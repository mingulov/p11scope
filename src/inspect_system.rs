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
use crate::discovery::confirm_shards::attribute_unselected_with_policy;
use crate::discovery::engine::{
    MAX_SCAN_PIDS, capture_manifest_object_key, parse_manifest_text, retarget_to_pins, scope_pids,
    select_excluding_kernel_threads, sweep_process_maps, unreadable_member_skip,
};
use crate::discovery::hooks::HookRegistry;
use crate::discovery::identity::{
    ExaminedObject, PinnedObjectId, PinnedObjects, ReconciledModule, bind_scanned_modules,
    canonicalize_scanned_overlays, pin_count_manifest_objects_in_views_with_prior,
    pin_scanned_view_objects,
};
use crate::discovery::kernel_identity::{EXAMINED_ANCHOR_CAP, ExaminedCustody};
use crate::discovery::noise::DiscoveryNoiseAggregator;
use crate::discovery::proof_stats::{ProofStatPool, proof_stat_threads};
use crate::discovery::scan::{
    CaptureWorkBudget, IO_CEILING_REASON, ScanOutcome, ScanRequest, ScannedModule, Skipped,
    scan_process_view_examined, scan_skip_truncates,
};
use crate::discovery::sweep_attribution::{
    AttributionLoss, IoResources, KnownKeyIndex, MatchedObject, ObjectChecks, OsConfirmIo,
    PreparationKind, ProofPools, RefusedObject, ReservationOwner, SegmentPolicy, SweepAttribution,
    SweptMember, is_caller_range, preparation_kind, retain_unchanged,
};
use crate::discovery::sweep_attribution::{MemberProbe, OsMemberProbe, attribute_unselected};
use crate::discovery::sweep_shards::{shard_count, shard_threads};
use crate::inspect_identity::{
    InspectApplicationResult, InspectIdentityUnknown, InspectImageReader, ProcessViewImageReader,
    application_detail, application_from_confirmed_member, application_json, application_label,
    begin_application, finish_application,
};
use crate::plan::{self, AdmissionPolicy, AdmissionScope};
use crate::process::{ProcessView, ProcessViewId, generation_gone};
use crate::timing::{StageKind, StageTimings};
use anyhow::{Context as _, Result, ensure};
use p11scope_manifest::manifest::Manifest;
use p11scope_manifest::maps::{MapEntry, ObjectKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub(crate) mod inventory_cgroup;

const DOC_ID: &str = "p11scope/inspect-system/v1";

/// The controller ruling, carried on every admission verdict and on the
/// plan recap: the catalog reports admission computed WITHOUT manifest
/// input, so an object whose admission could differ with a manifest says
/// so plainly instead of reading as a capture promise.
pub(crate) const SCAN_ONLY_NOTE: &str =
    "scan-only admission: manifest corroboration was not consulted";
/// The same disclaimer in TEXT words: names below come from the files
/// themselves. JSON keeps [`SCAN_ONLY_NOTE`] verbatim.
const TEXT_SCAN_ONLY_NOTE: &str = "scan only: names below come from the files themselves";
pub(crate) const COUNT_MANIFEST_NOTE: &str =
    "count admission includes explicit manifest targets validated against the mapped provider";

/// `p11scope inspect --system` — enumerate, sweep, deep-scan, pin, lower
/// admission scan-only, render. Exit 0 when the loop ran (even with zero
/// objects); a fully-unreadable machine renders a partial catalog with
/// per-process reasons, and only a failed `/proc` listing is a hard error.
pub fn run(
    hints: &[PathBuf],
    excludes: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
) -> Result<i32> {
    run_with_writer(
        hints,
        excludes,
        hooks,
        json,
        max_scan_pids,
        &mut std::io::stdout().lock(),
    )
}

fn run_with_writer(
    hints: &[PathBuf],
    excludes: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    out: &mut dyn std::io::Write,
) -> Result<i32> {
    let catalog = collect(
        hints,
        excludes,
        hooks,
        max_scan_pids,
        AdmissionPolicy::detailed(),
        // Single pass: no earlier scans, pure rarity selection.
        &BTreeSet::new(),
    )?;
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
/// "deep-scanning…"): verbose-only, so default and `--quiet` runs stay
/// silent. The interactive inventory dashboard turns them off while it
/// owns the terminal (C5.3): its own pass lines say the same, and one
/// line per scanned process would flood its bounded log tail.
static PROGRESS_LINES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Turns the scan progress lines on or off; returns the previous setting.
pub(crate) fn set_progress_lines(on: bool) -> bool {
    PROGRESS_LINES.swap(on, std::sync::atomic::Ordering::SeqCst)
}

/// Best-effort bounded stderr for a scan progress line. Formatting and
/// argument evaluation stay inside the enabled branch (see [`set_progress_lines`]).
macro_rules! progress {
    ($($arg:tt)*) => {
        if $crate::cli::text_is_verbose()
            && PROGRESS_LINES.load(std::sync::atomic::Ordering::SeqCst)
        {
            let line = format!($($arg)*);
            let _ = crate::sink::try_stderr_line(&crate::render::escape_controls(&line));
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

/// Private absence authority, minted by the scan producer and never serialized.
#[derive(Clone)]
pub(crate) struct CompleteMemberScan {
    generation: MemberGeneration,
    started_ns: u64,
    finished_ns: u64,
}

impl CompleteMemberScan {
    pub(crate) fn generation(&self) -> &MemberGeneration {
        &self.generation
    }
    pub(crate) fn started_ns(&self) -> u64 {
        self.started_ns
    }
    pub(crate) fn finished_ns(&self) -> u64 {
        self.finished_ns
    }
    #[cfg(test)]
    pub(crate) fn scripted(
        generation: MemberGeneration,
        started_ns: u64,
        finished_ns: u64,
    ) -> Self {
        Self {
            generation,
            started_ns,
            finished_ns,
        }
    }
}

/// One scope member's deep-scan result: its status, what it mapped, and
/// the pins the scan earned. Empty unless a scan ran.
struct MemberResult {
    pid: u32,
    view: ProcessViewId,
    status: MemberStatus,
    generation: Option<MemberGeneration>,
    complete_scan: Option<CompleteMemberScan>,
    /// Completed presentation receipt, separate from physical/absence authority.
    application: InspectApplicationResult,
    /// Scanner-owned presentation fact, never an absence receipt or render input.
    mapping_scan_completed: bool,
    /// Whether the scan reached its `--module` hint loop. Kernel threads
    /// and refused-initial scans never do; their silence is not a match.
    hints_examined: bool,
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
}

/// Enumerate the machine, sweep over the cap, deep-scan every selected
/// member fail-open, pin every view. Progress goes to stderr; stdout stays
/// empty until the final render, so `--json` stays parseable.
fn collect_members(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    timings: &mut StageTimings,
    budget: CaptureWorkBudget,
    scanned: &BTreeSet<u32>,
) -> Collection {
    collect_members_identity(
        hints,
        hooks,
        max_scan_pids,
        timings,
        false,
        budget,
        false,
        scanned,
    )
    .0
}

/// Explicit userspace never attempts the kernel pass (`decide_pass_attempt`
/// returns `Userspace` without consulting proof), so its identity scan takes
/// no anchor custody: held anchors would only cost censuses, CPU and
/// descriptors while shrinking the confirm allowance, and nothing under
/// explicit userspace consumes them. Auto and kernel keep full custody.
pub(crate) fn identity_takes_anchors(selection: crate::cli::IdentityBackendSelection) -> bool {
    !matches!(selection, crate::cli::IdentityBackendSelection::Userspace)
}

/// Build the identity scan's custody: full anchor capacity when the pass may
/// attempt the kernel, zero capacity (offers refuse before any census and
/// their files close on refusal) under explicit userspace. A failed strict
/// census still starts a closed custody phase in both cases: the normal
/// userspace scan still runs, but no partial anchor population forms.
pub(crate) fn build_identity_custody(
    callers: BTreeMap<ObjectKey, usize>,
    take_anchors: bool,
) -> ExaminedCustody {
    let cap = if take_anchors { EXAMINED_ANCHOR_CAP } else { 0 };
    match SegmentPolicy::try_snapshot(0, 0) {
        Ok(policy) => ExaminedCustody::new(ReservationOwner::for_examined(policy, cap), callers),
        Err(reason) => {
            let mut failed = ExaminedCustody::new(
                ReservationOwner::for_examined(SegmentPolicy::from_headroom(0, 0, 0), 0),
                callers,
            );
            let _ = failed.reconcile_census(Err(reason));
            failed
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_members_identity(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    timings: &mut StageTimings,
    identity: bool,
    mut budget: CaptureWorkBudget,
    take_anchors: bool,
    scanned: &BTreeSet<u32>,
) -> (Collection, Option<ExaminedCustody>) {
    debug_assert!(!take_anchors || identity);
    progress!("p11scope: enumerating processes...");
    let scope = Scope::System;
    let (pids, unlisted) = scope_pids(&scope);
    let proc_list_failed = unlisted
        .iter()
        .any(|skip| skip.reason.contains("no process was discovered"));
    let mut scope_gaps: Vec<PidGap> = unlisted.into_iter().map(PidGap::scope).collect();
    let cap = max_scan_pids.unwrap_or(MAX_SCAN_PIDS);
    let mut noise = DiscoveryNoiseAggregator::default();

    // Phase 1+2, exactly like capture discovery: the sweep and the
    // rarity selection run only over the cap; under it selection is the
    // identity (ascending pids). A non-empty scanned set tiers the
    // selection (never-scanned groups first) so multi-pass scans cannot
    // starve a newcomer; single passes pass an empty set. Past the cap
    // the sweep is kept: C1b attributes the unselected pids from it
    // after the deep scans, and the capped-or-complete record is decided
    // then, from its counts.
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
        // The stored sweep keeps every pid for maps attribution; only the
        // selection input drops the threads with no user memory.
        let selected = select_excluding_kernel_threads(
            &swept,
            &unavailable,
            Path::new("/proc"),
            cap,
            &mut budget,
            scanned,
        );
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

    let mut custody = identity.then(|| {
        let mut callers = BTreeMap::new();
        let selected_set: BTreeSet<_> = selected.iter().copied().collect();
        for (pid, entries) in &sweep {
            if selected_set.contains(pid) {
                continue;
            }
            let keys: BTreeSet<_> = entries
                .iter()
                .filter(|entry| is_caller_range(entry))
                .map(ObjectKey::of)
                .collect();
            for key in keys {
                *callers.entry(key).or_default() += 1;
            }
        }
        build_identity_custody(callers, take_anchors)
    });

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
        members.push(scan_member_identity(
            *pid,
            ProcessViewId(view_index),
            hints,
            hooks,
            &mut budget,
            &mut noise,
            custody.as_mut(),
        ));
    }
    timings.span(StageKind::Scan, "deep_scan", deep_start, monotonic_ns());
    noise.report();
    (
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
        },
        custody,
    )
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
    scan_member_identity(pid, view, hints, hooks, budget, noise, None)
}

fn scan_member_identity(
    pid: u32,
    view: ProcessViewId,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    budget: &mut CaptureWorkBudget,
    noise: &mut DiscoveryNoiseAggregator,
    custody: Option<&mut ExaminedCustody>,
) -> MemberResult {
    let started_ns = monotonic_ns();
    let budget_before = (budget.stopped_reason(), budget.refusal_counts());
    let opened = ProcessView::open_with_budget(view, pid, budget);
    let view_handle = match opened {
        Ok(view_handle) => view_handle,
        Err(error) => {
            return member_not_scanned(
                pid,
                view,
                &format!("the process generation could not be pinned: {error}"),
                noise,
                Vec::new(),
            );
        }
    };
    let mut reader = ProcessViewImageReader::new(&view_handle);
    scan_member_application_with(&mut reader, |reader| {
        scan_pinned_member_identity(
            reader.view(),
            hints,
            hooks,
            budget,
            noise,
            started_ns,
            budget_before,
            custody,
        )
    })
}

/// The existing physical scan/absence authority remains independent of naming.
fn scan_pinned_member(
    view_handle: &ProcessView,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    budget: &mut CaptureWorkBudget,
    noise: &mut DiscoveryNoiseAggregator,
    started_ns: Option<u64>,
    budget_before: (Option<&'static str>, (u64, u64)),
) -> MemberResult {
    scan_pinned_member_identity(
        view_handle,
        hints,
        hooks,
        budget,
        noise,
        started_ns,
        budget_before,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_pinned_member_identity(
    view_handle: &ProcessView,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    budget: &mut CaptureWorkBudget,
    noise: &mut DiscoveryNoiseAggregator,
    started_ns: Option<u64>,
    budget_before: (Option<&'static str>, (u64, u64)),
    mut custody: Option<&mut ExaminedCustody>,
) -> MemberResult {
    let scan = custody.as_mut().map(|held| held.begin_scan());
    let result = scan_pinned_member_inner(
        view_handle,
        hints,
        hooks,
        budget,
        noise,
        started_ns,
        budget_before,
        custody.as_deref_mut().zip(scan),
    );
    if (!result.mapping_scan_completed
        || !result.status.inventoried()
        || result.complete_scan.is_none())
        && let Some((custody, scan)) = custody.zip(scan)
    {
        custody.discard_scan(scan);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn scan_pinned_member_inner(
    view_handle: &ProcessView,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    budget: &mut CaptureWorkBudget,
    noise: &mut DiscoveryNoiseAggregator,
    started_ns: Option<u64>,
    budget_before: (Option<&'static str>, (u64, u64)),
    custody: Option<(&mut ExaminedCustody, u64)>,
) -> MemberResult {
    let pid = view_handle.pid();
    let view = view_handle.id();
    let mut gaps = Vec::new();
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
    let request = ScanRequest { pid, hints, hooks };
    let scanned = match custody {
        Some((custody, scan)) => crate::discovery::scan::scan_process_view_held(
            &request,
            view_handle,
            budget,
            custody,
            scan,
        ),
        None => scan_process_view_examined(&request, view_handle, budget),
    };
    let (outcome, examined, hints_examined) = match scanned {
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
    let (pins, pin_skips) = match pin_scanned_view_objects(view_handle, outcome.modules(), budget) {
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
    let generation_current = generation.start_time.is_some()
        && generation.exe.is_some()
        && generation.exe == read_exe_identity(pid)
        && generation.start_time == view_handle.start_time()
        && view_handle.still_the_same();
    let finished_ns = monotonic_ns();
    let complete_scan = if generation_current
        && retirement_scan_allows_absence(
            hints,
            &outcome,
            &pin_skips,
            budget_before,
            (budget.stopped_reason(), budget.refusal_counts()),
        ) {
        started_ns
            .zip(finished_ns)
            .filter(|(pre, post)| *pre > 0 && post > pre)
            .map(|(started_ns, finished_ns)| CompleteMemberScan {
                generation: generation.clone(),
                started_ns,
                finished_ns,
            })
    } else {
        None
    };
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
    let mapping_scan_completed = outcome.mapping_scan_completed();
    let (modules, status) = match outcome {
        ScanOutcome::Scanned { modules, .. } => (modules, MemberStatus::Scanned),
        ScanOutcome::Unavailable {
            reason, modules, ..
        } => (modules, MemberStatus::MemoryUnavailable { reason }),
    };
    MemberResult {
        mapping_scan_completed,
        application: InspectApplicationResult::Unknown(InspectIdentityUnknown::NotExamined),
        complete_scan,
        hints_examined,
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

/// Strict private omission vocabulary. Display completeness has a separate contract.
fn retirement_scan_allows_absence(
    hints: &[PathBuf],
    outcome: &ScanOutcome,
    pin_skips: &[Skipped],
    before: (Option<&'static str>, (u64, u64)),
    after: (Option<&'static str>, (u64, u64)),
) -> bool {
    hints.is_empty()
        && matches!(outcome, ScanOutcome::Scanned { .. })
        && pin_skips.is_empty()
        && before.0.is_none()
        && after.0.is_none()
        && before.1 == after.1
        && outcome.skipped().iter().all(|skip| {
            // With no hints the scan emits the unhinted no-table reason for
            // the skipped path, action suffix included; anything else is a
            // real gap, never an allowed absence.
            skip.reason == crate::discovery::scan::no_table_found_reason(&skip.subject, false)
        })
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
        mapping_scan_completed: false,
        application: InspectApplicationResult::Unknown(InspectIdentityUnknown::NotExamined),
        complete_scan: None,
        hints_examined: false,
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

/// The render rule (A3, ruling JK-22a), pure over the collection counts
/// so the branches are unit-testable: enumerated processes are rendered
/// however unreadable they are — each unreadability is a named, countable
/// gap with its per-process reason, and the catalog reads partial. Only a
/// failed `/proc` listing (no data source at all) is a hard error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemOutcome {
    Render,
    HardError,
}

#[derive(Debug, Clone, Copy)]
struct OutcomeStats {
    enumerated: usize,
    proc_list_failed: bool,
}

fn decide_system_outcome(stats: OutcomeStats) -> SystemOutcome {
    if stats.enumerated == 0 && stats.proc_list_failed {
        return SystemOutcome::HardError;
    }
    SystemOutcome::Render
}

fn proc_list_system_error(collection: &Collection) -> anyhow::Error {
    let first = collection
        .scope_gaps
        .iter()
        .map(|gap| gap.reason.as_str())
        .find(|reason| reason.contains("no process was discovered"))
        .or_else(|| collection.scope_gaps.first().map(|gap| gap.reason.as_str()))
        .unwrap_or("unknown reason");
    anyhow::anyhow!("cannot inspect system: {first}")
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
    /// A prefix-admitted (or growth-kept) object: some endpoints
    /// attached, the rest disclosed in the gap reason with counts.
    /// Partially covered, never refused.
    Partial {
        class: &'static str,
        endpoints: usize,
        reason: String,
    },
    Refused {
        class: &'static str,
        reason: String,
        /// The merge-time refusal kind. Display branches on this, never on
        /// the reason wording; JSON still carries only the reason.
        kind: crate::plan::RefusalKind,
    },
    Unresolved {
        reasons: Vec<String>,
    },
}

impl AdmissionRecord {
    pub(crate) const fn state(&self) -> &'static str {
        match self {
            Self::Admitted { .. } => "admitted",
            Self::Partial { .. } => "partial",
            Self::Refused { .. } => "refused",
            Self::Unresolved { .. } => "unresolved",
        }
    }

    pub(crate) fn class(&self) -> Option<&'static str> {
        match self {
            Self::Admitted { class, .. }
            | Self::Partial { class, .. }
            | Self::Refused { class, .. } => Some(class),
            Self::Unresolved { .. } => None,
        }
    }

    pub(crate) fn reasons(&self) -> Vec<String> {
        match self {
            Self::Admitted { .. } => Vec::new(),
            Self::Partial { reason, .. } | Self::Refused { reason, .. } => {
                vec![reason.clone()]
            }
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
    pub complete_scan: Option<CompleteMemberScan>,
    /// Scan-local presentation only; never use this as event naming authority.
    pub application: InspectApplicationResult,
    /// Whether the member's scan reached its `--module` hint loop.
    /// Internal collapse input only; never rendered (schema-safe).
    pub hints_examined: bool,
}

/// Both samples use the same retained reader and enclose the full physical
/// scan plus provider pinning. Naming rejection cannot discard those results.
fn scan_member_application_with<C: InspectImageReader>(
    context: &mut C,
    scan_and_pin: impl FnOnce(&mut C) -> MemberResult,
) -> MemberResult {
    let pending = begin_application(context);
    let mut member = scan_and_pin(context);
    member.application = if member.status.inventoried() && member.mapping_scan_completed {
        finish_application(pending, context)
    } else {
        InspectApplicationResult::Unknown(InspectIdentityUnknown::NotExamined)
    };
    member
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
    pub partial: usize,
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
    /// Files skipped by `--exclude-module` during this collection, one
    /// record per (file, process). Consumers aggregate and report these;
    /// an exclusion that matched nothing is reported from the inputs.
    pub excluded: Vec<crate::discovery::scan::ExcludedRecord>,
    /// The `--exclude-module` inputs this collection ran with, drained
    /// from the same pass budget as `excluded`. Renderers report inputs
    /// that matched nothing from these, never silently.
    pub exclude_inputs: Vec<PathBuf>,
    /// Per-stage wall time of this collection (sweep, select, deep scan,
    /// confirm, assemble): the system-scale cost measurement. Never
    /// rendered in the catalog document; `P11SCOPE_STAGE_TIMINGS=1` prints
    /// it to stderr.
    pub stage_timings: StageTimings,
}

/// The one scan-only lowering behind a catalog's admission verdicts: the
/// aggregate pins every reconciled module was bound against and the plan
/// built over them under the caller's policy. Plan object IDs index these
/// pins and nothing else. `modules` retains the reconciled scan
/// modules the plan was built from (DEMO-4): the coordinator stashes
/// them at absorb time so the no-manifest scan seal can mint over
/// current scanned tables instead of a creation-time snapshot.
pub(crate) struct CatalogLowering {
    pub plan: plan::AttachPlan,
    pub pins: PinnedObjects,
    pub modules: Vec<ReconciledModule>,
}

/// Collect the machine, lower scan-only admission under `policy`, assemble
/// the catalog. `inspect --system` lowers Detailed; the inventory command
/// lowers Inventory. The only `Err` is a failed `/proc` listing
/// (stdout stays empty); unreadable members render as gaps.
pub(crate) fn collect(
    hints: &[PathBuf],
    excludes: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    policy: AdmissionPolicy,
    scanned: &BTreeSet<u32>,
) -> Result<Catalog> {
    let mut budget = CaptureWorkBudget::default();
    budget.set_excludes(excludes.to_vec());
    collect_with_budget(hints, hooks, max_scan_pids, policy, budget, scanned)
}

pub(crate) fn collect_with_budget(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    policy: AdmissionPolicy,
    budget: CaptureWorkBudget,
    scanned: &BTreeSet<u32>,
) -> Result<Catalog> {
    collect_with_count_manifests(
        hints,
        hooks,
        max_scan_pids,
        policy,
        budget,
        scanned,
        &[],
        0,
        0,
    )
}

/// System collection with explicit count manifests. `prior_objects` /
/// `prior_bytes` are already-retained capture-level pins, charged against
/// the shared manifest+pre-arm budget (packet 6.13 round-3, finding 3).
/// `scanned` holds pids deep-scanned by earlier passes; a non-empty set
/// tiers selection (never-scanned groups first) so multi-pass scans cannot
/// starve a newcomer, while single passes pass an empty set for pure
/// rarity selection.
#[allow(clippy::too_many_arguments)]
pub(crate) fn collect_with_count_manifests(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    policy: AdmissionPolicy,
    budget: CaptureWorkBudget,
    scanned: &BTreeSet<u32>,
    manifests: &[PathBuf],
    prior_objects: usize,
    prior_bytes: u64,
) -> Result<Catalog> {
    collect_identity(
        hints,
        hooks,
        max_scan_pids,
        policy,
        false,
        budget,
        scanned,
        manifests,
        prior_objects,
        prior_bytes,
    )
    .map(|(catalog, _)| catalog)
}

/// Dormant opt-in collection seam for the inventory identity backend. The
/// catalog and its admitted pins own no references into the custody sidecar.
#[allow(dead_code)]
pub(crate) fn collect_inventory_identity(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    policy: AdmissionPolicy,
) -> Result<(Catalog, ExaminedCustody)> {
    if !matches!(policy, AdmissionPolicy::Inventory(_)) {
        return Err(anyhow::anyhow!(
            "physical identity collection requires inventory policy"
        ));
    }
    let (catalog, custody) = collect_identity(
        hints,
        hooks,
        max_scan_pids,
        policy,
        true,
        CaptureWorkBudget::default(),
        &BTreeSet::new(),
        &[],
        0,
        0,
    )?;
    Ok((catalog, custody.expect("opt-in collection owns custody")))
}

#[allow(clippy::too_many_arguments)]
fn collect_identity(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    policy: AdmissionPolicy,
    identity: bool,
    budget: CaptureWorkBudget,
    scanned: &BTreeSet<u32>,
    manifests: &[PathBuf],
    prior_objects: usize,
    prior_bytes: u64,
) -> Result<(Catalog, Option<ExaminedCustody>)> {
    let mut timings = StageTimings::new();
    let (mut collection, mut custody) = if identity {
        collect_members_identity(
            hints,
            hooks,
            max_scan_pids,
            &mut timings,
            true,
            budget,
            true,
            scanned,
        )
    } else {
        (
            collect_members(hints, hooks, max_scan_pids, &mut timings, budget, scanned),
            None,
        )
    };
    let stats = OutcomeStats {
        enumerated: collection.enumerated.len(),
        proc_list_failed: collection.proc_list_failed,
    };
    if decide_system_outcome(stats) == SystemOutcome::HardError {
        return Err(proc_list_system_error(&collection));
    }
    progress!("p11scope: lowering scan-only admission and rendering...");
    let bind_start = monotonic_ns();
    let mut bound = bind_collection(&mut collection);
    timings.span(StageKind::Bind, "assemble", bind_start, monotonic_ns());
    // The confirmation reads run here: after the deep scans, while the
    // aggregate pins (and their fds) are held, before the pure assembly.
    let confirm_start = monotonic_ns();
    // C7 A5: past the shard threshold the confirmation reads are sharded
    // by contiguous pid ranges (and replayed in pid order). Otherwise the
    // serial path runs, with the proof stats on a bounded pool that lives
    // for this confirmation stage only (DR-C1b-3); the shards never nest
    // that pool.
    let shards = shard_count(collection.sweep.len(), shard_threads());
    let (segment_policy, reservations) = if let Some(held) = &mut custody {
        let ready = !held.failed()
            && collection.budget.check_deadline_now().is_none()
            && collection.budget.poll_collection(0);
        let census = if ready {
            let census = SegmentPolicy::try_snapshot(shard_threads(), collection.sweep.len());
            if collection.budget.check_deadline_now().is_some()
                || !collection.budget.poll_collection(0)
            {
                Err(crate::discovery::sweep_attribution::FD_CENSUS_REASON.into())
            } else {
                census
            }
        } else {
            Err(crate::discovery::sweep_attribution::FD_CENSUS_REASON.into())
        };
        let segment_policy =
            identity_confirmation_policy(held, census).map_err(anyhow::Error::msg)?;
        (segment_policy, held.owner.clone())
    } else {
        let policy = SegmentPolicy::snapshot(shard_threads(), collection.sweep.len());
        (policy, ReservationOwner::new(policy))
    };
    let attribute = |pools: ProofPools<'_>| {
        attribute_sweep_with(
            &mut collection,
            &bound,
            &bound.aggregate,
            |sweep, unavailable, selected, index, budget| {
                attribute_unselected_with_policy(
                    sweep,
                    unavailable,
                    selected,
                    index,
                    budget,
                    segment_policy,
                    &reservations,
                    shards,
                    &|| OsConfirmIo::with_pools(pools),
                )
            },
        )
    };
    let attributed =
        with_confirmation_pools(shards, segment_policy, proof_stat_threads(), attribute);
    timings.span(StageKind::Scan, "confirm", confirm_start, monotonic_ns());
    prepare_count_manifests(
        &mut collection,
        &mut bound,
        manifests,
        prior_objects,
        prior_bytes,
    );
    let assemble_start = monotonic_ns();
    let mut catalog = assemble(
        collection,
        bound,
        attributed,
        policy,
        collector_admission_scope(hints, false),
    );
    timings.span(StageKind::Plan, "assemble", assemble_start, monotonic_ns());
    catalog.stage_timings = timings;
    Ok((catalog, custody))
}

/// The exact post-bind integration branch. A strict refusal closes custody
/// and permits only the bounded immediate fallback on the same owner. It
/// cannot trigger another census or restore batch workers.
fn identity_confirmation_policy(
    held: &mut ExaminedCustody,
    census: Result<SegmentPolicy, String>,
) -> Result<SegmentPolicy, String> {
    let strict_policy = census.as_ref().ok().copied();
    if held.reconcile_census(census).is_ok() {
        Ok(strict_policy.expect("successful reconciliation has a complete census"))
    } else {
        let policy = SegmentPolicy::from_headroom(3, 0, 0);
        held.owner.reconcile(policy)?;
        Ok(policy)
    }
}

/// Immediate work keeps its FD-free proof pool even when the population
/// selected shards. Parallel batch workers avoid nested range workers.
fn with_confirmation_pools<R>(
    shards: usize,
    policy: SegmentPolicy,
    threads: usize,
    body: impl FnOnce(ProofPools<'_>) -> R,
) -> R {
    ProofStatPool::scoped(threads, |pool| {
        body(ProofPools {
            batch: if shards > 1 && policy.workers > 1 {
                None
            } else {
                pool
            },
            immediate: pool,
        })
    })
}

/// Collect one pid through the same member scan and the same assembly:
/// the inventory scan lane's `--pid` pass. The only `Err` is a target no
/// scan inventoried — pid-inspect's hard failure, kept honest.
#[cfg(test)]
pub(crate) fn collect_pid(
    pid: u32,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    policy: AdmissionPolicy,
) -> Result<Catalog> {
    collect_pid_with_budget(pid, hints, hooks, policy, CaptureWorkBudget::default())
}

#[cfg(test)]
pub(crate) fn collect_pid_with_budget(
    pid: u32,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    policy: AdmissionPolicy,
    budget: CaptureWorkBudget,
) -> Result<Catalog> {
    collect_pid_with_count_manifests(pid, hints, hooks, policy, budget, &[], 0, 0)
}

/// Pid collection with explicit count manifests. `prior_objects` /
/// `prior_bytes` are already-retained capture-level pins, charged against
/// the shared manifest+pre-arm budget (packet 6.13 round-3, finding 3).
#[allow(clippy::too_many_arguments)]
pub(crate) fn collect_pid_with_count_manifests(
    pid: u32,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    policy: AdmissionPolicy,
    mut budget: CaptureWorkBudget,
    manifests: &[PathBuf],
    prior_objects: usize,
    prior_bytes: u64,
) -> Result<Catalog> {
    progress!("p11scope: deep-scanning pid {pid}...");
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
    let mut bound = bind_collection(&mut collection);
    prepare_count_manifests(
        &mut collection,
        &mut bound,
        manifests,
        prior_objects,
        prior_bytes,
    );
    Ok(assemble(
        collection,
        bound,
        None,
        policy,
        collector_admission_scope(hints, true),
    ))
}

/// The aggregate pin set and every module bound against it: the pure half
/// of assembly, run before the confirmation reads so they see exactly the
/// objects (and hold exactly the fds) the catalog will report.
struct Bound {
    aggregate: PinnedObjects,
    reconciled: Vec<(u32, ProcessViewId, ReconciledModule)>,
    unresolved: Vec<(u32, ProcessViewId, ScannedModule, Vec<String>)>,
    bind_gaps: Vec<PidGap>,
    count_manifests: Vec<Manifest>,
}

/// Aggregate every view's pins and bind every module.
fn bind_collection(collection: &mut Collection) -> Bound {
    // One aggregate pin set first: exact comparable identities merge and
    // equal raw keys with unequal full identity reject the group — the
    // same absorb semantics capture relies on.
    let mut aggregate = PinnedObjects::empty();
    let mut aggregate_lost = false;
    for member in &mut collection.members {
        let pins = std::mem::replace(&mut member.pins, PinnedObjects::empty());
        let losses = aggregate.absorb(pins);
        aggregate_lost |= !losses.is_empty();
        if !losses.is_empty() {
            member.complete_scan = None;
        }
        for skip in losses {
            member.gaps.push(PidGap::member(member.pid, skip));
        }
    }
    let (_collapsed, overlay_lost) = canonicalize_scanned_overlays(&mut aggregate);
    if aggregate_lost || !overlay_lost.is_empty() {
        for member in &mut collection.members {
            member.complete_scan = None;
        }
    }
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
    let affected: BTreeSet<u32> = bind_gaps.iter().filter_map(|gap| gap.pid).collect();
    let global_loss = collection.cap_hit
        || collection.proc_list_failed
        || !collection.scope_gaps.is_empty()
        || bind_gaps.iter().any(|gap| gap.pid.is_none());
    for member in &mut collection.members {
        if global_loss || affected.contains(&member.pid) {
            member.complete_scan = None;
        }
    }
    Bound {
        aggregate,
        reconciled,
        unresolved,
        bind_gaps,
        count_manifests: Vec::new(),
    }
}

/// Actual document reads share the collection's byte and work allowance.
struct CountManifestReader<'a> {
    file: std::fs::File,
    budget: &'a mut CaptureWorkBudget,
    operation_bytes: u64,
}

impl std::io::Read for CountManifestReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.budget.spend(1).map_err(std::io::Error::other)?;
        let allowed = self.budget.allowed_io(self.operation_bytes, bytes.len());
        if allowed == 0 {
            return Err(std::io::Error::other(IO_CEILING_REASON));
        }
        let read = std::io::Read::read(&mut self.file, &mut bytes[..allowed])?;
        self.budget.record_io(read);
        self.operation_bytes = self.operation_bytes.saturating_add(read as u64);
        Ok(read)
    }
}

fn read_count_manifest_file(path: &Path, budget: &mut CaptureWorkBudget) -> Result<Manifest> {
    let file = p11scope_manifest::identity::open_regular(path).map_err(anyhow::Error::msg)?;
    let length = file.metadata()?.len();
    let bytes = crate::manifest_input::read_bounded(
        CountManifestReader {
            file,
            budget,
            operation_bytes: 0,
        },
        length,
    )
    .map_err(anyhow::Error::msg)?;
    let text = String::from_utf8(bytes).context("manifest is not UTF-8")?;
    parse_manifest_text(&text, path)
}

/// Validate explicit count inputs while the collection still owns its read
/// allowance. Only an exact provider observed in this scope can contribute;
/// callbacks may live in other validated files. No table-completeness test
/// discards useful entries, and semantic/selection permissions stay elsewhere.
/// `prior_objects`/`prior_bytes` are already-retained capture-level pins
/// (packet 6.13 round-3, finding 3), charged against the shared
/// manifest+pre-arm object/byte budget.
fn prepare_count_manifests(
    collection: &mut Collection,
    bound: &mut Bound,
    paths: &[PathBuf],
    prior_objects: usize,
    prior_bytes: u64,
) {
    for path in paths {
        let accepted = (|| -> Result<Manifest> {
            collection.budget.spend(1).map_err(anyhow::Error::msg)?;
            let mut manifest = read_count_manifest_file(path, &mut collection.budget)?;
            let units = manifest
                .objects
                .len()
                .saturating_add(manifest.provenance_objects.len())
                .saturating_add(
                    manifest
                        .surfaces
                        .iter()
                        .map(|surface| surface.functions.len())
                        .chain(
                            manifest
                                .selection_evidence
                                .tables
                                .iter()
                                .map(|table| table.functions.len()),
                        )
                        .sum::<usize>(),
                )
                .saturating_add(1);
            collection
                .budget
                .spend(units as u64)
                .map_err(anyhow::Error::msg)?;

            // Proc-root locators must bind to the same collected generation,
            // rather than a PID that happens to exist when its path is opened.
            let pids: BTreeSet<u32> = manifest
                .objects
                .iter()
                .filter_map(|object| {
                    object
                        .path
                        .strip_prefix("/proc/")?
                        .split_once("/root/")?
                        .0
                        .parse()
                        .ok()
                })
                .collect();
            let mut views = Vec::new();
            for pid in pids {
                collection
                    .budget
                    .spend(collection.members.len() as u64 + 1)
                    .map_err(anyhow::Error::msg)?;
                let member = collection
                    .members
                    .iter()
                    .find(|member| member.pid == pid)
                    .context("manifest locator is outside the collected scope")?;
                let generation = member
                    .generation
                    .as_ref()
                    .context("manifest locator generation unavailable")?;
                let view = ProcessView::open_with_budget(member.view, pid, &mut collection.budget)
                    .map_err(anyhow::Error::msg)?;
                ensure!(
                    generation.start_time.is_some()
                        && generation.exe.is_some()
                        && view.start_time() == generation.start_time
                        && read_exe_identity(pid) == generation.exe,
                    "manifest locator generation changed"
                );
                views.push(view);
            }
            let pinning = pin_count_manifest_objects_in_views_with_prior(
                &manifest,
                &views,
                &mut collection.budget,
                prior_objects,
                prior_bytes,
            )
            .map_err(|error| anyhow::anyhow!("manifest pinning refused: {:?}", error.problems()))?;
            ensure!(
                pinning.stale.is_empty(),
                "manifest object identity is stale"
            );
            // Never-stop partial pinning returns per-object skips; inspect
            // keeps its strict refusal here (no silent loss) until its own
            // partial lane (F-07) relaxes it.
            ensure!(
                pinning.skipped.is_empty(),
                "manifest object unavailable: {}",
                pinning
                    .skipped
                    .first()
                    .map_or("unknown", |skip| skip.reason.as_str())
            );
            ensure!(
                pinning.pins.check_unchanged() == Ok(true),
                "manifest object identity changed"
            );
            for view in &views {
                collection
                    .budget
                    .spend(collection.members.len() as u64 + 1)
                    .map_err(anyhow::Error::msg)?;
                let generation = collection
                    .members
                    .iter()
                    .find(|member| member.pid == view.pid())
                    .and_then(|member| member.generation.as_ref())
                    .unwrap();
                ensure!(
                    view.still_the_same() && read_exe_identity(view.pid()) == generation.exe,
                    "manifest locator generation changed during validation"
                );
            }
            let own = pinning
                .pins
                .id_for_path(&manifest.module_path)
                .context("manifest provider pin unavailable")?;
            collection
                .budget
                .spend(bound.reconciled.len() as u64 + 1)
                .map_err(anyhow::Error::msg)?;
            let matching: Vec<_> = bound
                .reconciled
                .iter()
                .filter(|(_, _, module)| {
                    bound
                        .aggregate
                        .exactly_matches(module.object, &pinning.pins, own)
                })
                .map(|(_, _, module)| &module.scanned)
                .collect();
            ensure!(
                !matching.is_empty(),
                "manifest provider is not exactly mapped in the collected scope"
            );
            retarget_to_pins(&mut manifest, &matching, &bound.aggregate, &pinning.pins);
            let clone_units = bound
                .aggregate
                .pinned()
                .map(|pin| pin.path.len().div_ceil(16).saturating_add(8) as u64)
                .sum::<u64>();
            collection
                .budget
                .spend(clone_units)
                .map_err(anyhow::Error::msg)?;
            let mut candidate = bound.aggregate.clone();
            ensure!(
                candidate.absorb(pinning.pins).is_empty(),
                "manifest pin union disagrees with the collection"
            );
            for object in &manifest.objects {
                if let Some((key, path)) = capture_manifest_object_key(&manifest, object.id) {
                    candidate.refile_split_manifest_alias(
                        key,
                        path,
                        &mut collection.budget,
                        &crate::discovery::identity::KernelSelfMappingProbe,
                    );
                }
            }
            collection.budget.spend(1).map_err(anyhow::Error::msg)?;
            bound.aggregate = candidate;
            Ok(manifest)
        })();
        match accepted {
            Ok(manifest) => bound.count_manifests.push(manifest),
            Err(error) => collection.scope_gaps.push(PidGap::scope(Skipped {
                subject: path.display().to_string(),
                reason: format!("count manifest refused: {error:#}"),
            })),
        }
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
    attribute_sweep_with(
        collection,
        bound,
        checks,
        |sweep, unavailable, selected, index, budget| {
            attribute_unselected(sweep, unavailable, selected, index, probe, budget)
        },
    )
}

#[cfg(test)]
thread_local! {
    static REFUSED_SCAN_ENTRIES: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn count_refused_scans_for_test<R>(body: impl FnOnce() -> R) -> (R, usize) {
    struct Restore(Option<usize>);
    impl Drop for Restore {
        fn drop(&mut self) {
            REFUSED_SCAN_ENTRIES.set(self.0);
        }
    }
    let restore = Restore(REFUSED_SCAN_ENTRIES.replace(Some(0)));
    let result = body();
    let count = REFUSED_SCAN_ENTRIES
        .get()
        .expect("refused-scan counter is scoped");
    drop(restore);
    (result, count)
}

#[cfg(test)]
fn record_refused_scan_for_test() {
    REFUSED_SCAN_ENTRIES.set(REFUSED_SCAN_ENTRIES.get().map(|count| count + 1));
}

fn is_caller_range_counted(entry: &MapEntry) -> bool {
    #[cfg(test)]
    record_refused_scan_for_test();
    is_caller_range(entry)
}

/// Keep only refused objects an unselected process maps as a caller
/// would: executably (A6, the same rule as attribution). A refused
/// object is a loss only there; elsewhere it is not this pass's gap.
fn retain_refused_to_unselected(
    refused: &mut Vec<RefusedObject>,
    sweep: &[(u32, Vec<MapEntry>)],
    selected: &BTreeSet<u32>,
) {
    if refused.is_empty() {
        return;
    }
    let unselected_keys: BTreeSet<ObjectKey> = sweep
        .iter()
        .filter(|(pid, _)| !selected.contains(pid))
        .flat_map(|(_, entries)| {
            entries
                .iter()
                .filter(|entry| is_caller_range_counted(entry))
        })
        .map(ObjectKey::of)
        .collect();
    refused.retain(|object| unselected_keys.contains(&object.key));
}

/// The shared sweep-attribution prefix: this pass's key index, the
/// selected set, and the refused objects filtered to unselected caller
/// keys. Both attribution paths and the auto/kernel proof gate build
/// exactly this, so the gate sees the plan attribution would run.
fn sweep_proof_prefix(
    collection: &Collection,
    bound: &Bound,
    checks: &dyn ObjectChecks,
) -> (KnownKeyIndex, BTreeSet<u32>, Vec<RefusedObject>) {
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
    retain_refused_to_unselected(&mut refused, &collection.sweep, &selected);
    (index, selected, refused)
}

/// Whether this pass holds a nonempty admitted proof plan: the cap hit
/// with an unselected, available sweep PID whose preparation is not
/// settled. Slots-independent: preparation consults the snapshot and
/// the index only, never installed anchors. No-proof passes load and
/// record nothing.
fn sweep_has_proof_plan(collection: &Collection, bound: &Bound) -> bool {
    if !collection.cap_hit {
        return false;
    }
    let (index, selected, _) = sweep_proof_prefix(collection, bound, &bound.aggregate);
    collection.sweep.iter().any(|(pid, entries)| {
        !matches!(
            preparation_kind(
                *pid,
                entries,
                &collection.sweep_unavailable,
                &selected,
                &index
            ),
            PreparationKind::Settled
        )
    })
}

/// [`attribute_sweep`] with the attribution itself supplied: serial over
/// a probe, or sharded (C7 A5).
fn attribute_sweep_with(
    collection: &mut Collection,
    bound: &Bound,
    checks: &dyn ObjectChecks,
    attribute: impl FnOnce(
        &[(u32, Vec<MapEntry>)],
        &BTreeSet<u32>,
        &BTreeSet<u32>,
        &KnownKeyIndex,
        &mut CaptureWorkBudget,
    ) -> SweepAttribution,
) -> Option<Attributed> {
    if !collection.cap_hit {
        return None;
    }
    let (index, selected, refused) = sweep_proof_prefix(collection, bound, checks);
    progress!(
        "p11scope: attributing {} unselected processes by maps identity...",
        collection.sweep.len().saturating_sub(selected.len())
    );
    let mut attribution = attribute(
        &collection.sweep,
        &collection.sweep_unavailable,
        &selected,
        &index,
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

/// One pid's "maps shared objects no deep scan examined" gap, for a
/// matched member or an unmatched process alike: either way the pid
/// stays listed in the text instead of folding into the "N other
/// processes" line, which may only cover pids with nothing unexamined.
fn unexamined_maps_gap(pid: u32, count: usize) -> PidGap {
    PidGap::member(
        pid,
        Skipped {
            subject: "maps attribution".into(),
            reason: format!(
                "maps {count} shared object{} no deep scan examined this pass; {} may be \
                 an undiscovered provider",
                if count == 1 { "" } else { "s" },
                if count == 1 { "it" } else { "each" },
            ),
        },
    )
}

/// The GT-5 admission rule for a collected catalog, mirroring the engine: a
/// named process, or a capture the operator aimed with `--module`, admits
/// first-come; any other system capture admits in value order with a reserve
/// for late corroborated providers.
fn collector_admission_scope(hints: &[PathBuf], pid_scope: bool) -> AdmissionScope {
    if pid_scope || !hints.is_empty() {
        AdmissionScope::Named
    } else {
        AdmissionScope::Shared
    }
}

/// Lower one plan over collected evidence and validated inputs, and project
/// the catalog records — deep-scanned and maps-matched members alike.
/// Pure: no `/proc` reads. The scope comes from
/// [`collector_admission_scope`]: aimed captures admit first-come, unaimed
/// system captures keep the shared reserve.
fn assemble(
    mut collection: Collection,
    bound: Bound,
    attributed: Option<Attributed>,
    policy: AdmissionPolicy,
    admission_scope: AdmissionScope,
) -> Catalog {
    // `--exclude-module` records ride the pass budget, which `Collection`
    // owns end to end; drain them before the moves below consume it.
    let excluded = collection.budget.excluded().to_vec();
    let exclude_inputs = collection.budget.excludes().to_vec();
    let Bound {
        aggregate,
        reconciled,
        unresolved,
        bind_gaps,
        mut count_manifests,
    } = bound;
    let mut bind_gaps = bind_gaps;
    if attributed
        .as_ref()
        .is_some_and(|attributed| !attributed.changed.is_empty() || !attributed.refused.is_empty())
    {
        for member in &mut collection.members {
            member.complete_scan = None;
        }
    }

    // Inspect supplies scan evidence only. Inventory also supplies its validated
    // count manifests. Both lower once, before admission, with no history,
    // reserved slots, or attachment side effects.
    let inputs: Vec<ReconciledModule> = reconciled
        .iter()
        .map(|(_, _, module)| module.clone())
        .collect();
    let owners: Vec<(u32, ProcessViewId)> = reconciled
        .iter()
        .map(|(pid, view, _)| (*pid, *view))
        .collect();
    // Scoped collection may have removed members at its final permit cut.
    // Retained input pins alone never establish that a provider remains in it.
    count_manifests.retain(|manifest| {
        manifest
            .objects
            .iter()
            .find(|object| object.path == manifest.module_path)
            .and_then(|object| capture_manifest_object_key(manifest, object.id))
            .and_then(|(key, path)| aggregate.id_for_manifest(key, path))
            .is_some_and(|object| inputs.iter().any(|module| module.object == object))
    });
    let operators: BTreeSet<_> = count_manifests
        .iter()
        .filter_map(|manifest| {
            let own = manifest
                .objects
                .iter()
                .find(|object| object.path == manifest.module_path)?;
            let (key, path) = capture_manifest_object_key(manifest, own.id)?;
            aggregate.id_for_manifest(key, path)
        })
        .collect();
    let plan = plan::build_from_sources_for_policy_scoped(
        &inputs,
        &count_manifests,
        &aggregate,
        policy,
        admission_scope,
    );
    let refused: BTreeMap<PinnedObjectId, (&Skipped, crate::plan::RefusalKind)> = plan
        .refused_modules_typed()
        .map(|(object, skipped, kind)| (object, (skipped, kind)))
        .collect();
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
        let class = if operators.contains(&object) {
            "operator"
        } else {
            plan::classify_scanned_object(&group).0
        };
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
        // A prefix-admitted (or growth-kept) object has both slots
        // in the plan and a gap record: it files as partial with its
        // attached count, never as refused. A partial-kind gap with no
        // plan slots is a shape the merge never emits; it stays a
        // whole refusal rather than inventing coverage.
        let admission = match (refused.get(&object), admitted.get(&object)) {
            (Some((skip, _)), Some(endpoints))
                if crate::plan::is_partial_coverage(&skip.reason) =>
            {
                AdmissionRecord::Partial {
                    class,
                    endpoints: *endpoints,
                    reason: skip.reason.clone(),
                }
            }
            (Some((skip, kind)), _) => AdmissionRecord::Refused {
                class,
                reason: skip.reason.clone(),
                kind: *kind,
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
            application: if let Some(member) = members_by_pid.get(pid) {
                member.application.clone()
            } else if let Some(swept) = swept_by_pid.get(pid) {
                application_from_confirmed_member(swept)
            } else {
                InspectApplicationResult::Unknown(InspectIdentityUnknown::NotExamined)
            },
            complete_scan: members_by_pid
                .get(pid)
                .and_then(|member| member.complete_scan.clone()),
            hints_examined: members_by_pid
                .get(pid)
                .is_some_and(|member| member.hints_examined),
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
        // Every unselected pid with unexamined keys — matched member
        // or not — keeps its own gap, so only pids with nothing
        // unexamined can fold. The map holds exactly the nonzero
        // counts, members included, so this replaces the members loop
        // with identical text for members.
        for (pid, count) in &attributed.attribution.unexamined {
            gaps.push(unexamined_maps_gap(*pid, *count));
        }
        // Unselected pids whose phase-1 maps snapshot was unavailable:
        // nothing examined their mappings, so they stay listed too. A
        // selected pid keeps its own member record instead.
        let selected: BTreeSet<u32> = collection.selected.iter().copied().collect();
        for pid in collection.sweep_unavailable.difference(&selected) {
            gaps.push(PidGap::member(
                *pid,
                Skipped {
                    subject: "maps attribution".into(),
                    reason: "had no maps snapshot this pass; its mappings were never examined"
                        .into(),
                },
            ));
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
    // Kernel threads examined this pass: one counted note, never one gap
    // per thread.
    if let Some(note) = kernel_thread_absence_note(collection.budget.kernel_thread_absences()) {
        notes.push(note);
    }
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
        partial: objects
            .iter()
            .filter(|object| matches!(object.admission, AdmissionRecord::Partial { .. }))
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
            modules: inputs,
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
        excluded,
        exclude_inputs,
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

/// One pass-level note for processes examined and classified as kernel
/// threads with no user memory (verified absence, counted on the pass
/// budget), whether excluded before the deep-scan cap or classified by a
/// deep scan. `None` when none was classified, so deterministic runs see
/// no new record. A note, never a loss: kernel threads cannot load providers.
fn kernel_thread_absence_note(absences: u64) -> Option<PidGap> {
    if absences == 0 {
        return None;
    }
    let reason = if absences == 1 {
        "1 process examined is a kernel thread with no user memory to scan".to_string()
    } else {
        format!("{absences} processes examined are kernel threads with no user memory to scan")
    };
    Some(PidGap::scope(Skipped {
        subject: "kernel threads".into(),
        reason,
    }))
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
    let denied = collection.members.iter().any(|member| {
        matches!(&member.status, MemberStatus::Unreadable { reason }
            if reason.contains("Permission denied") || reason.contains("not permitted"))
    }) || collection
        .scope_gaps
        .iter()
        .any(|gap| gap.reason.contains("Permission denied"));
    if denied {
        parts.push(
            "some processes could not be read (permission denied); their modules are unknown, \
             not absent — rerun with `sudo p11scope inspect --system` for full coverage"
                .to_string(),
        );
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
            let application = application_json(&process.application);
            record["application"] = application["application"].clone();
            record["application_status"] = application["application_status"].clone();
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
            "partial": catalog.admission.partial,
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
    // Additive (v0.6.0): files skipped by `--exclude-module`, a declared
    // operator choice, never a loss. Omitted when empty.
    let (excluded_modules, unmatched_excludes) =
        crate::render::aggregate_excluded(&catalog.excluded, &catalog.exclude_inputs);
    if !excluded_modules.is_empty() {
        document["excluded_modules"] = serde_json::to_value(&excluded_modules).unwrap_or_default();
    }
    if !unmatched_excludes.is_empty() {
        document["unmatched_excludes"] =
            serde_json::to_value(&unmatched_excludes).unwrap_or_default();
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
        AdmissionRecord::Partial {
            class,
            endpoints,
            reason,
        } => serde_json::json!({
            "class": class,
            "endpoints": endpoints,
            "reason": reason,
            "scan_only": true,
            "note": SCAN_ONLY_NOTE,
        }),
        AdmissionRecord::Refused { class, reason, .. } => serde_json::json!({
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
/// Renders at the run-scoped verbosity; see [`render_text_with_verbosity`].
fn render_text(catalog: &Catalog) -> String {
    render_text_with_verbosity(catalog, crate::cli::text_verbosity())
}

/// [`render_text`] at an explicit verbosity: the tests' race-free
/// handle. Concise keeps the header, one short block per provider,
/// folded skips, coverage and the `-v` hint; verbose is the full
/// per-table listing; quiet keeps the header and coverage only.
fn render_text_with_verbosity(catalog: &Catalog, verbosity: crate::cli::TextVerbosity) -> String {
    use crate::cli::TextVerbosity;
    let verbose = verbosity == TextVerbosity::Verbose;
    let mut out = String::new();
    let files = if catalog.objects.len() == 1 {
        "provider file"
    } else {
        "provider files"
    };
    // The scan split in words, counted from the same process table the
    // `processes:` line below summarizes — so "checked in detail" is one
    // count in both places. Memory-unreadable members are named
    // separately, never folded into the deep-scanned total.
    let checked = catalog
        .processes
        .iter()
        .filter(|process| matches!(process.status, MemberStatus::Scanned))
        .count();
    let matched = catalog
        .processes
        .iter()
        .filter(|process| matches!(process.status, MemberStatus::MapsMatched))
        .count();
    let mem_unreadable = catalog
        .processes
        .iter()
        .filter(|process| matches!(process.status, MemberStatus::MemoryUnavailable { .. }))
        .count();
    let found = catalog.processes.len();
    let detail = if matched == 0 && mem_unreadable == 0 && checked == found {
        format!("all {found} checked in detail")
    } else if mem_unreadable == 0 {
        format!("{checked} checked in detail, {matched} matched from maps, of {found} found")
    } else {
        format!(
            "{checked} checked in detail, {matched} matched from maps, {mem_unreadable} memory \
             unreadable, of {found} found"
        )
    };
    let _ = writeln!(
        out,
        "system — {} {files} mapped in {} processes ({detail}; cap {}; deep scans {} ms; {})",
        catalog.objects.len(),
        catalog.processes.len(),
        catalog.cap,
        catalog.scan_ms,
        catalog.scan_status,
    );
    out.push_str(
        "Mapped provider files are scan evidence; activity was not captured by inspect.\n",
    );
    out.push('\n');
    if verbosity == TextVerbosity::Quiet {
        render_excluded(&mut out, catalog);
        if let Some(explanation) = &catalog.explanation {
            let _ = writeln!(out, "{explanation}");
        }
        render_coverage(&mut out, catalog);
        return out;
    }
    let processes: BTreeMap<u32, &ProcessRecord> = catalog
        .processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    for (index, object) in catalog.objects.iter().enumerate() {
        render_object(&mut out, index, object, &processes, verbosity);
        out.push('\n');
    }
    if verbose && !catalog.relationships.is_empty() {
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
    render_process_summary(&mut out, catalog, verbosity);
    render_gaps(&mut out, "skipped", &catalog.skipped, verbose);
    render_gaps(&mut out, "notes", &catalog.notes, verbose);
    render_excluded(&mut out, catalog);
    if let Some(explanation) = &catalog.explanation {
        let _ = writeln!(out, "{explanation}");
    }
    render_coverage(&mut out, catalog);
    if verbosity == crate::cli::TextVerbosity::Concise {
        let _ = writeln!(out, "{}", crate::cli::VERBOSE_HINT);
    }
    out
}

/// One coverage status line: complete only when collection finished
/// and nothing was skipped.
fn render_coverage(out: &mut String, catalog: &Catalog) {
    let mut parts: Vec<String> = Vec::new();
    if !catalog.skipped.is_empty() {
        parts.push(format!(
            "{} item{} skipped",
            catalog.skipped.len(),
            if catalog.skipped.len() == 1 { "" } else { "s" }
        ));
    }
    if catalog.scan_status != "complete" {
        parts.push("scan incomplete".to_string());
    }
    if parts.is_empty() {
        let _ = writeln!(out, "coverage: complete");
    } else {
        let _ = writeln!(
            out,
            "coverage: partial — {} (--json has every item)",
            parts.join("; ")
        );
    }
}

/// Whether a planner refusal is a probe-budget refusal: the module needs
/// more attach slots than remain. Concise folds these to one plain line;
/// verbose and JSON keep the full demand.
fn is_capacity_refusal(reason: &str) -> bool {
    reason.contains("attach slots are available")
}

fn render_object(
    out: &mut String,
    index: usize,
    object: &CatalogObject,
    processes: &BTreeMap<u32, &ProcessRecord>,
    verbosity: crate::cli::TextVerbosity,
) {
    let verbose = verbosity == crate::cli::TextVerbosity::Verbose;
    // Concise names the provider file like pid-inspect; the `object[N]`
    // index stays verbose-only for cross-references.
    if verbose {
        let _ = writeln!(
            out,
            "object[{index}]  {}",
            crate::render::escape_controls(&object.path)
        );
    } else {
        let _ = writeln!(
            out,
            "module  {}",
            crate::render::escape_controls(&object.path)
        );
    }
    if verbose {
        let _ = writeln!(
            out,
            "  identity   sha256 {}  build-id {}  dev {}:{}  ino {}",
            object.sha256.as_deref().unwrap_or("-"),
            object.build_id.as_deref().unwrap_or("-"),
            object.key.device.major,
            object.key.device.minor,
            object.key.inode,
        );
    }
    let mappings: Vec<String> = object
        .mappings
        .iter()
        .map(|(pid, view)| {
            let unknown = InspectApplicationResult::Unknown(InspectIdentityUnknown::NotExamined);
            let application = processes
                .get(pid)
                .map_or(&unknown, |process| &process.application);
            let label = application_label(application, *pid);
            match view {
                Some(view) if verbose => format!("{label} (view {})", view.0),
                // Concise names the process; the internal view id stays
                // verbose-only (JSON keeps every process).
                Some(_) => label,
                None => format!("{label} (maps match)"),
            }
        })
        .collect();
    if verbose || mappings.len() <= 3 {
        let _ = writeln!(out, "  mapped by  {}", mappings.join(", "));
    } else {
        let _ = writeln!(
            out,
            "  mapped by  {}, and {} more (--json lists every process)",
            mappings[..3].join(", "),
            mappings.len() - 3,
        );
    }
    match &object.admission {
        AdmissionRecord::Admitted { class, endpoints } => {
            // Inspect watches nothing: say what a capture aimed at this
            // file would watch. Concise has no per-table listing below,
            // so the scan-only note stays verbose-only. A zero-endpoint
            // record qualifies rather than predicts: an unscanned
            // module deep-scans on capture (admitting its real
            // functions), while a genuinely empty table admits nothing,
            // and this renderer cannot tell them apart.
            if *endpoints == 0 {
                if verbose {
                    let _ = writeln!(
                        out,
                        "  admission  0 functions admitted from this scan (class {class}; \
                         {TEXT_SCAN_ONLY_NOTE})"
                    );
                } else {
                    let _ = writeln!(out, "  admission  0 functions admitted from this scan");
                }
            } else {
                let noun = if *endpoints == 1 {
                    "function"
                } else {
                    "functions"
                };
                if verbose {
                    let _ = writeln!(
                        out,
                        "  admission  profile/run would watch {endpoints} {noun} (class {class}; \
                         {TEXT_SCAN_ONLY_NOTE})"
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "  admission  profile/run would watch {endpoints} {noun}"
                    );
                }
            }
        }
        AdmissionRecord::Partial { class, reason, .. } => {
            // The reason already carries the attached-vs-needed
            // counts; the line mirrors the refused shape.
            if verbose {
                let _ = writeln!(
                    out,
                    "  admission  partial ({class}): {} [{SCAN_ONLY_NOTE}]",
                    crate::render::escape_controls(reason),
                );
            } else {
                let _ = writeln!(
                    out,
                    "  admission  partial: {} [{SCAN_ONLY_NOTE}]",
                    crate::render::escape_controls(reason),
                );
            }
        }
        AdmissionRecord::Refused {
            class,
            reason,
            kind,
        } => {
            if *kind == crate::plan::RefusalKind::AwaitingPublication {
                // By-design refusal: the proxy alone admits nothing until
                // its providers publish. One plain line; verbose pairs
                // the machine class, JSON keeps the full planner reason.
                let proxy = if std::path::Path::new(&object.path)
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().contains("p11-kit"))
                {
                    "p11-kit proxy"
                } else {
                    "proxy closure array"
                };
                if verbose {
                    let _ = writeln!(
                        out,
                        "  admission  refused ({class}): {proxy} not attached by design; the providers \
                         it forwards to attach when they load (--json shows the full reason)"
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "  admission  refused (proxy): {proxy} not attached by design; the providers \
                         it forwards to attach when they load"
                    );
                }
            } else if verbose {
                let _ = writeln!(
                    out,
                    "  admission  refused ({class}): {} [{SCAN_ONLY_NOTE}]",
                    crate::render::escape_controls(reason),
                );
            } else if is_capacity_refusal(reason) {
                // A budget refusal names its demand in full under -v and
                // JSON; concise keeps the plain budget line with the fix.
                let _ = writeln!(
                    out,
                    "  admission  refused: too many functions for the remaining probe \
                     budget; name it with --module to capture it alone"
                );
            } else {
                let _ = writeln!(
                    out,
                    "  admission  refused: {} [{SCAN_ONLY_NOTE}]",
                    crate::render::escape_controls(reason),
                );
            }
        }
        AdmissionRecord::Unresolved { reasons } => {
            for reason in reasons {
                let _ = writeln!(
                    out,
                    "  admission  undecided: {}",
                    crate::render::escape_controls(reason),
                );
            }
        }
    }
    if !verbose {
        // Concise stops here: identity, per-process observations and
        // interfaces are verbose-only.
        return;
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
        let table_lines = observation.tables.iter().map(|table| {
            let count = table.entries.len();
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
            format!(
                "    table      {}.{}, {}{nulls}{unpinned}",
                table.version.0,
                table.version.1,
                crate::inspect::table_walk_words(table.walk, count)
            )
        });
        crate::inspect::push_collapsed_lines(out, table_lines);
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

/// One member status in plain words (text only; JSON keeps the
/// label). Unknown labels pass through verbatim.
fn member_status_words(status: &str) -> &str {
    match status {
        "scanned" => "checked in detail",
        "maps_matched" => "matched from maps",
        "exited" => "exited",
        "memory_unavailable" => "memory unreadable",
        "unreadable" => "unreadable",
        "not_selected" => "past the scan cap",
        other => other,
    }
}

fn render_process_summary(
    out: &mut String,
    catalog: &Catalog,
    verbosity: crate::cli::TextVerbosity,
) {
    let verbose = verbosity == crate::cli::TextVerbosity::Verbose;
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for process in &catalog.processes {
        *counts.entry(process.status.label()).or_default() += 1;
    }
    let parts: Vec<String> = counts
        .iter()
        .map(|(status, count)| {
            let plain = member_status_words(status);
            if verbose && plain != *status {
                format!("{count} {plain} ({status})")
            } else {
                format!("{count} {plain}")
            }
        })
        .collect();
    let _ = writeln!(out, "processes: {}", parts.join(", "));
    let mut unlisted = 0usize;
    let mut unlisted_scanned = 0usize;
    let mut unlisted_past_cap = 0usize;
    let mut unlisted_exited = 0usize;
    let with_gaps: BTreeSet<u32> = catalog
        .skipped
        .iter()
        .chain(catalog.notes.iter())
        .filter_map(|gap| gap.pid)
        .collect();
    for process in &catalog.processes {
        // Kernel threads and other processes with nothing to report are
        // counted below; listing each would bury the few that matter. A
        // process with an object, a reason or its own gap record
        // (skipped or note) is always listed in verbose text, so the
        // folded line may only claim no object was found or attributed,
        // never that a folded process maps none. Concise text folds
        // every process: the `processes:` line above carries the status
        // split, mapped-by previews name callers, and --json lists each.
        if process.objects.is_empty()
            && process.status.reason().is_none()
            && !with_gaps.contains(&process.pid)
            && matches!(
                process.status,
                MemberStatus::Scanned | MemberStatus::NotSelected { .. } | MemberStatus::Exited
            )
        {
            unlisted += 1;
            match process.status {
                MemberStatus::Scanned => unlisted_scanned += 1,
                MemberStatus::NotSelected { .. } => unlisted_past_cap += 1,
                MemberStatus::Exited => unlisted_exited += 1,
                _ => {}
            }
            continue;
        }
        if !verbose {
            unlisted += 1;
            continue;
        }
        let objects = process
            .objects
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "  {} — {}; objects [{}]",
            application_label(&process.application, process.pid),
            process.status.label(),
            objects,
        );
        if let Some(detail) = application_detail(&process.application) {
            out.push_str(&detail);
        }
        if let Some(reason) = process.status.reason() {
            let _ = writeln!(
                out,
                "  reason      {}",
                crate::render::escape_controls(reason)
            );
        }
    }
    if unlisted > 0 {
        if verbose {
            let _ = writeln!(
                out,
                "  {unlisted} other {} not listed: no PKCS#11 object found or attributed \
                 ({unlisted_scanned} checked in detail, {unlisted_past_cap} past the scan cap, \
                 {unlisted_exited} exited); --json lists every process",
                if unlisted == 1 {
                    "process is"
                } else {
                    "processes are"
                },
            );
        } else {
            let _ = writeln!(
                out,
                "  {unlisted} {} not listed individually; --json lists every process",
                if unlisted == 1 {
                    "process is"
                } else {
                    "processes are"
                },
            );
        }
    }
    render_admission_summary(out, catalog, verbose);
}

/// The admission totals in the JSON-aligned verdict terms
/// (admitted/partial/refused/unresolved), the
/// unconfirmed-function count with its ordinary-scan gloss, and the
/// scan-only disclaimer. Verbose pairs the machine counters.
fn render_admission_summary(out: &mut String, catalog: &Catalog, verbose: bool) {
    let uncorroborated = catalog.admission.uncorroborated_candidates;
    let ambiguous = catalog.admission.module_ambiguous;
    let mut parts: Vec<String> = Vec::new();
    if uncorroborated > 0 || verbose {
        let mut part =
            format!("{uncorroborated} possible functions not yet confirmed from a second source");
        if verbose {
            part.push_str(" (uncorroborated_candidates)");
        } else {
            part.push_str("; this is normal for a scan");
        }
        parts.push(part);
    }
    if ambiguous > 0 || verbose {
        let mut part = format!("{ambiguous} functions claimed by two providers");
        if verbose {
            part.push_str(" (module_ambiguous)");
        }
        parts.push(part);
    }
    parts.push(TEXT_SCAN_ONLY_NOTE.to_string());
    let _ = writeln!(
        out,
        "admission: {} admitted, {} partial, {} refused, {} unresolved ({})",
        catalog.admission.admitted,
        catalog.admission.partial,
        catalog.admission.refused,
        catalog.admission.unresolved,
        parts.join("; "),
    );
}

/// Whether a skip reason is an unexamined-maps gap (`unexamined_maps_gap`):
/// per-pid shared-object counts that would split concise groups by number.
fn is_unexamined_maps_reason(reason: &str) -> bool {
    reason.starts_with("maps ")
        && reason.contains("shared object")
        && reason.contains("no deep scan examined")
}

/// The per-object cap behind an over-capacity skip, for folding sizes
/// that would otherwise split concise groups. Handles both producer
/// formats (`too_large (SIZE bytes; per-object cap is CAP)` from the
/// scan budget and `object is SIZE bytes; limit is LIMIT` from the view
/// filesystem). `None` for any other reason or an unparsable cap.
fn too_large_cap(reason: &str) -> Option<u64> {
    if let Some(rest) = reason.strip_prefix("too_large (") {
        let (_, rest) = rest.split_once("per-object cap is ")?;
        return parse_leading_u64(rest);
    }
    if let Some(rest) = reason.strip_prefix("object is ") {
        let (_, rest) = rest.split_once("; limit is ")?;
        return parse_leading_u64(rest);
    }
    None
}

/// Leading ASCII digits as u64, for cap parsing with a graceful fallback.
fn parse_leading_u64(text: &str) -> Option<u64> {
    let digits: String = text.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Skipped records and notes in text. Verbose lists every record —
/// the full per-gap detail `-v` promises. Concise folds member records
/// by reason — a lone record keeps its pid and subject, a repeated
/// reason folds to one counted line — then scope-level records print
/// verbatim (the split already deduped them). JSON keeps every record;
/// see `render_json`.
fn render_gaps(out: &mut String, title: &str, gaps: &[PidGap], verbose: bool) {
    if verbose {
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
        return;
    }
    // Plain folds first: reasons with per-record numbers (unexamined-maps
    // counts, over-cap sizes) fold by kind with a process/file count,
    // instead of splitting one group per number.
    let mut plain_maps: Vec<&PidGap> = Vec::new();
    let mut plain_large: BTreeMap<u64, Vec<&PidGap>> = BTreeMap::new();
    let mut rest: Vec<&PidGap> = Vec::new();
    for gap in gaps.iter().filter(|gap| gap.pid.is_some()) {
        if is_unexamined_maps_reason(&gap.reason) {
            plain_maps.push(gap);
        } else if let Some(cap) = too_large_cap(&gap.reason) {
            plain_large.entry(cap).or_default().push(gap);
        } else {
            rest.push(gap);
        }
    }
    if !plain_maps.is_empty() {
        let processes: BTreeSet<u32> = plain_maps.iter().filter_map(|gap| gap.pid).collect();
        let count = processes.len();
        let noun = if count == 1 { "process" } else { "processes" };
        let verb = if count == 1 { "maps" } else { "map" };
        let _ = writeln!(
            out,
            "{title}: {count} {noun} {verb} libraries that were not deep-scanned (may hide \
             providers) (--json lists each)",
        );
    }
    for (cap, group) in &plain_large {
        let mib = cap / (1024 * 1024);
        let count = group.len();
        let noun = if count == 1 { "file" } else { "files" };
        let _ = writeln!(
            out,
            "{title}: {count} {noun} over {mib} MiB not read (--json lists each)",
        );
    }
    let mut by_reason: BTreeMap<&str, Vec<&PidGap>> = BTreeMap::new();
    for gap in rest {
        by_reason.entry(gap.reason.as_str()).or_default().push(gap);
    }
    for (reason, group) in &by_reason {
        if group.len() == 1 {
            let gap = group[0];
            let _ = writeln!(
                out,
                "{title}: pid {} {} — {}",
                gap.pid.expect("member gap carries its pid"),
                crate::render::escape_controls(&gap.subject),
                crate::render::escape_controls(&gap.reason),
            );
            continue;
        }
        let processes: BTreeSet<u32> = group.iter().filter_map(|gap| gap.pid).collect();
        let _ = writeln!(
            out,
            "{title} ({} gap{} in {} process{}): {} (--json lists each)",
            group.len(),
            if group.len() == 1 { "" } else { "s" },
            processes.len(),
            if processes.len() == 1 { "" } else { "es" },
            crate::render::escape_controls(reason),
        );
    }
    for gap in gaps.iter().filter(|gap| gap.pid.is_none()) {
        let _ = writeln!(
            out,
            "{title}: {} — {}",
            crate::render::escape_controls(&gap.subject),
            crate::render::escape_controls(&gap.reason)
        );
    }
}

/// Files skipped by `--exclude-module`, never silent: each with its path,
/// identity, and mapping process count, plus any inputs that matched
/// nothing. Same wording as `inspect --pid` and inventory.
fn render_excluded(out: &mut String, catalog: &Catalog) {
    let (excluded, unmatched) =
        crate::render::aggregate_excluded(&catalog.excluded, &catalog.exclude_inputs);
    if !excluded.is_empty() {
        let _ = writeln!(out, "Excluded by you ({} files):", excluded.len());
        for item in &excluded {
            let processes = if item.processes == 1 {
                "1 process mapped it".to_string()
            } else {
                format!("{} processes mapped it", item.processes)
            };
            let _ = writeln!(
                out,
                "  {}: excluded by you (device {} inode {}, {processes}); calls into this file were not observed",
                crate::render::escape_controls(&item.path),
                item.dev,
                item.ino,
            );
        }
    }
    if !unmatched.is_empty() {
        let _ = writeln!(
            out,
            "Unmatched exclusions ({}): {}",
            unmatched.len(),
            unmatched
                .iter()
                .map(|input| crate::render::escape_controls(input))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

// ---------------------------------------------------------------------------
// D3d: system sweep identity backend selection, sessions and disclosure.
// ---------------------------------------------------------------------------

/// Resolved system sweep identity backend (D3d): the approved
/// `observation.identity.backend` vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityBackend {
    Userspace,
    Kernel,
}

impl IdentityBackend {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Userspace => "userspace",
            Self::Kernel => "kernel",
        }
    }
}

/// Capture-level identity disclosure: the approved `{backend, fallback}`
/// shape. No coverage counters, no PIDs, paths or raw errors: `fallback`
/// is a finite label (or `label: detail` for the fixed target-run-limit
/// detail) or null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentitySummary {
    pub backend: IdentityBackend,
    pub fallback: Option<String>,
}

impl IdentitySummary {
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "backend": self.backend.label(),
            "fallback": self.fallback,
        })
    }
}

/// Finite kernel-selection failure cause (D3d): sanitized, no paths,
/// PIDs, verifier text or probe detail. Verifier rejection stays
/// `load_failed` even when its errno is EACCES; it is never a
/// capability skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityUnavailable {
    NoBtf,
    KernelFixMissing,
    NoTaskIterPidfd,
    NumberingMismatch,
    NumberingUnknown,
    PermissionDenied,
    LoadFailed,
    ProbeFailed,
    /// Lazy session setup refused before opening anything: the FD
    /// headroom cannot cover the setup/probe peak.
    FdHeadroom,
}

impl IdentityUnavailable {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NoBtf => "no_btf",
            Self::KernelFixMissing => "kernel_fix_missing",
            Self::NoTaskIterPidfd => "no_task_iter_pidfd",
            Self::NumberingMismatch => "numbering_mismatch",
            Self::NumberingUnknown => "numbering_unknown",
            Self::PermissionDenied => "permission_denied",
            Self::LoadFailed => "load_failed",
            Self::ProbeFailed => "probe_failed",
            Self::FdHeadroom => "fd_headroom",
        }
    }

    /// The sanitized deny: the label only, never the raw detail.
    pub(crate) fn from_kernel_deny(deny: crate::attach::identity_iter::KernelDeny) -> Self {
        match deny {
            crate::attach::identity_iter::KernelDeny::FixMissing => Self::KernelFixMissing,
            crate::attach::identity_iter::KernelDeny::NoTaskIterPidfd => Self::NoTaskIterPidfd,
            crate::attach::identity_iter::KernelDeny::NoBtf(_) => Self::NoBtf,
        }
    }
}

/// Typed PID-numbering outcome for identity eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityNumbering {
    Agree,
    Mismatch,
    Unknown,
}

/// Typed BTF eligibility outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityBtf {
    Ok,
    FixMissing,
    NoTaskIterPidfd,
    NoBtf,
}

/// Typed injected capability/probe source (D3d): every selection input
/// is a finite enum, never a raw string. Production reads the live host
/// (numbering, BTF, strict load, functional probe); tests inject each
/// arm deterministically without BPF.
pub(crate) trait IdentityChecks: Send {
    fn numbering(&self) -> IdentityNumbering;
    fn btf(&self) -> IdentityBtf;
    /// File-descriptor headroom above the census reserve, for the lazy
    /// session-setup reservation. Production runs the strict census;
    /// the injected test source answers from its canned headroom.
    fn setup_headroom(&self) -> Result<usize, String>;
    /// Full strict-load plus functional-probe validation, returning a
    /// fresh loaded session on success. Production loads BPF; the
    /// injected test source answers from its canned outcome.
    fn create_session(
        &self,
    ) -> Result<crate::discovery::kernel_identity::IdentitySession, IdentityUnavailable>;
}

/// The production capability source: live numbering, live BTF, real
/// strict loads and the real functional probe.
pub(crate) struct LiveIdentityChecks;

impl IdentityChecks for LiveIdentityChecks {
    fn numbering(&self) -> IdentityNumbering {
        let numbering = crate::pidns::numbering();
        if numbering.agrees() {
            return IdentityNumbering::Agree;
        }
        match (&numbering.observer, &numbering.proc_view) {
            (crate::pidns::ObserverPidNs::Unknown(_), _)
            | (_, crate::pidns::ProcView::Unserved(_)) => IdentityNumbering::Unknown,
            _ => IdentityNumbering::Mismatch,
        }
    }

    fn btf(&self) -> IdentityBtf {
        match crate::attach::identity_iter::ensure_kernel_identity_btf() {
            Ok(_) => IdentityBtf::Ok,
            Err(crate::attach::identity_iter::KernelDeny::FixMissing) => IdentityBtf::FixMissing,
            Err(crate::attach::identity_iter::KernelDeny::NoTaskIterPidfd) => {
                IdentityBtf::NoTaskIterPidfd
            }
            Err(crate::attach::identity_iter::KernelDeny::NoBtf(_)) => IdentityBtf::NoBtf,
        }
    }

    fn setup_headroom(&self) -> Result<usize, String> {
        SegmentPolicy::try_snapshot(0, 0).map(|policy| policy.headroom)
    }

    fn create_session(
        &self,
    ) -> Result<crate::discovery::kernel_identity::IdentitySession, IdentityUnavailable> {
        live_create_session()
    }
}

/// Whether a strict-load failure without a verifier log is a permission
/// refusal (EPERM/EACCES on the BPF syscalls) rather than a verifier or
/// object failure. Any non-empty verifier log means verifier rejection
/// (`load_failed`), even when its errno is EACCES.
fn load_error_is_permission(error: &crate::attach::identity_iter::LoadError) -> bool {
    use std::error::Error as _;
    if crate::attach::identity_iter::verifier_log_of(error).is_some_and(|log| !log.is_empty()) {
        return false;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = error.source();
    while let Some(error) = source {
        if let Some(io) = error.downcast_ref::<std::io::Error>()
            && matches!(io.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES))
        {
            return true;
        }
        source = error.source();
    }
    false
}

fn map_live_load_error(error: crate::attach::identity_iter::LoadError) -> IdentityUnavailable {
    if load_error_is_permission(&error) {
        IdentityUnavailable::PermissionDenied
    } else {
        IdentityUnavailable::LoadFailed
    }
}

/// Production session creation: BTF parse, full probe-and-load, with a
/// follow-up strict load only to distinguish a permission refusal from
/// a verifier/object failure when the session load fails.
/// A minimal RAII probe directory (std only: `tempfile` is a
/// dev-dependency): unique per call, removed on drop. Exclusive by
/// construction: atomic 0700 creation (never adopt a pre-existing
/// path), an owned-uid check, and cleanup restricted to the created
/// directory's identity (device + inode).
pub(crate) struct ProbeDir {
    path: std::path::PathBuf,
    uid: u32,
    dev: libc::dev_t,
    ino: libc::ino_t,
    /// The verified directory fd, held for the value's whole life so
    /// `Drop` unlinks the known fixture names through it (never the
    /// path): a post-check replacement is unreachable by fd.
    dirfd: std::os::fd::OwnedFd,
}

impl ProbeDir {
    /// A fresh unpredictable 0700 probe dir, named `{prefix}-…`, under
    /// the first exec-capable root: the temp dir, else `/var/tmp`. The
    /// probe child maps its fixtures `PROT_EXEC`, so a noexec root (a
    /// kind node mounts /tmp noexec) is unusable; a root that fails to
    /// create or to exec-map is dropped and the next is tried. The
    /// prefix is one plain segment: anything that could escape the
    /// root fails closed instead of joining.
    pub(crate) fn create(prefix: &str) -> Result<Self, IdentityUnavailable> {
        if prefix.is_empty() || prefix.contains('/') || prefix.contains('\0') {
            return Err(IdentityUnavailable::ProbeFailed);
        }
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let temp = std::env::temp_dir();
        let fallback = std::path::PathBuf::from("/var/tmp");
        let mut roots = vec![temp];
        if roots[0] != fallback {
            roots.push(fallback);
        }
        for root in roots.iter() {
            let id = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Unpredictable as well as unique: a local squatter cannot
            // precreate the probe path of a privileged run.
            let seed = std::collections::hash_map::RandomState::new();
            let random = {
                use std::hash::{BuildHasher as _, Hash as _, Hasher as _};
                let mut hasher = seed.build_hasher();
                std::process::id().hash(&mut hasher);
                id.hash(&mut hasher);
                hasher.finish()
            };
            let path = root.join(format!(
                "{prefix}-{pid}-{id}-{random:016x}",
                pid = std::process::id()
            ));
            let dir = match Self::create_at(&path) {
                Ok(dir) => dir,
                Err(_) => continue,
            };
            if dir.supports_exec_map() {
                // CLI-1: informational notes stay silent by default; the
                // `-v` lane resurfaces this fallback ("probe dir fell back
                // to {root} ({temp} is not exec-capable)") in verbose
                // output. A failed fallback still errors below.
                return Ok(dir);
            }
            // Not exec-capable: dropping removes the empty just-created
            // dir (the check unlinked its test file first), then the
            // next root is tried.
        }
        Err(IdentityUnavailable::ProbeFailed)
    }

    /// Whether a fresh file in this dir maps `PROT_EXEC` (the probe
    /// child's fixture shape). False on any failure; the test file is
    /// unlinked on every path so the dir stays empty for `Drop`.
    fn supports_exec_map(&self) -> bool {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        let name = c"probe-exec-check";
        // SAFETY: `openat` under the held verified directory fd;
        // `O_EXCL` fails on any pre-existing name instead of opening it.
        let raw = unsafe {
            libc::openat(
                self.dirfd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return false;
        }
        // SAFETY: the successful `openat` returned a new owned fd.
        let file = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        // SAFETY: `ftruncate` on a live fd with a plain length.
        let mut ok = unsafe { libc::ftruncate(file.as_raw_fd(), 4096) } == 0;
        if ok {
            // SAFETY: private executable mapping of the 4096-byte file
            // just created; unmapped below.
            let addr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            ok = addr != libc::MAP_FAILED;
            if ok {
                // SAFETY: the successful `mmap` above returned this range.
                ok = unsafe { libc::munmap(addr, 4096) } == 0;
            }
        }
        drop(file);
        // SAFETY: `unlinkat` of the static name on the live held dirfd;
        // flags 0 never unlinks directories.
        unsafe {
            libc::unlinkat(self.dirfd.as_raw_fd(), name.as_ptr(), 0);
        }
        ok
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn create_at(path: &std::path::Path) -> Result<Self, IdentityUnavailable> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStrExt as _;
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| IdentityUnavailable::ProbeFailed)?;
        // SAFETY: `mkdir` of a NUL-terminated path. Atomic: any
        // pre-existing name (dir, file or symlink) fails instead of
        // being adopted.
        if unsafe { libc::mkdir(cpath.as_ptr(), 0o700) } != 0 {
            return Err(IdentityUnavailable::ProbeFailed);
        }
        // Pin the fresh directory before verifying it: every check and
        // the mode fix below run against the open fd, never the path.
        // SAFETY: `open` of a NUL-terminated path; `O_NOFOLLOW` refuses
        // a swapped-in symlink instead of following it.
        let raw = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            // Best-effort cleanup of the directory mkdir just made.
            // `rmdir` removes empty dirs only, so a swapped-in foreign
            // path loses at most an empty dir — never contents.
            unsafe {
                libc::rmdir(cpath.as_ptr());
            }
            return Err(IdentityUnavailable::ProbeFailed);
        }
        // SAFETY: the successful `open` returned a new owned fd.
        let dirfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        // SAFETY: `fstat` on a live fd with a writable out-param.
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(dirfd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            drop(dirfd);
            // Best-effort cleanup of the directory mkdir just made.
            // `rmdir` removes empty dirs only, so a swapped-in foreign
            // path loses at most an empty dir — never contents.
            unsafe {
                libc::rmdir(cpath.as_ptr());
            }
            return Err(IdentityUnavailable::ProbeFailed);
        }
        // SAFETY: the successful `fstat` initialized `stat`.
        let stat = unsafe { stat.assume_init() };
        // SAFETY: `geteuid` takes no arguments and always succeeds.
        let uid = unsafe { libc::geteuid() };
        let owned = stat.st_mode & libc::S_IFMT == libc::S_IFDIR && stat.st_uid == uid;
        if !owned {
            drop(dirfd);
            // Best-effort cleanup of the directory mkdir just made.
            // `rmdir` removes empty dirs only, so a swapped-in foreign
            // path loses at most an empty dir — never contents.
            unsafe {
                libc::rmdir(cpath.as_ptr());
            }
            return Err(IdentityUnavailable::ProbeFailed);
        }
        // Only the verified-owned fd is modified: the mkdir mode honors
        // umask, so enforce 0700 exactly here.
        if unsafe { libc::fchmod(dirfd.as_raw_fd(), 0o700) } != 0 {
            drop(dirfd);
            // Best-effort cleanup of the directory mkdir just made.
            // `rmdir` removes empty dirs only, so a swapped-in foreign
            // path loses at most an empty dir — never contents.
            unsafe {
                libc::rmdir(cpath.as_ptr());
            }
            return Err(IdentityUnavailable::ProbeFailed);
        }
        let (dev, ino) = (stat.st_dev, stat.st_ino);
        Ok(Self {
            path: path.to_path_buf(),
            uid,
            dev,
            ino,
            dirfd,
        })
    }

    /// Whether `path` is still the directory this value created: the
    /// same device/inode directory owned by the creation uid (a
    /// swapped-in symlink, replacement dir, or foreign path is never
    /// ours).
    fn owns(path: &std::path::Path, uid: u32, dev: libc::dev_t, ino: libc::ino_t) -> bool {
        use std::os::unix::ffi::OsStrExt as _;
        let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `lstat` as in `create_at`.
        if unsafe { libc::lstat(cpath.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return false;
        }
        // SAFETY: the successful `lstat` initialized `stat`.
        let stat = unsafe { stat.assume_init() };
        stat.st_mode & libc::S_IFMT == libc::S_IFDIR
            && stat.st_uid == uid
            && stat.st_dev == dev
            && stat.st_ino == ino
    }
}

impl Drop for ProbeDir {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;
        if !Self::owns(&self.path, self.uid, self.dev, self.ino) {
            return;
        }
        // Bounded cleanup, not a recursive delete: only the four
        // fixture names the probe writes are unlinked, through the
        // held directory fd (never the path), so a replacement
        // swapped in after the check above loses nothing — its
        // unknown names are never touched, and the fd still points
        // at the created directory. Per-name errors are ignored: a
        // partial probe write leaves only a subset behind. The final
        // `rmdir` removes empty dirs only, so a swapped-in non-empty
        // dir survives with its contents intact; worst case a
        // swapped-in EMPTY dir is removed.
        for name in [c"probe-a", c"probe-b", c"probe-a-link", c"probe-a-copy"] {
            // SAFETY: `unlinkat` of a static NUL-terminated name on
            // the live held dirfd; flags 0 never unlinks directories.
            unsafe {
                libc::unlinkat(self.dirfd.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn live_create_session()
-> Result<crate::discovery::kernel_identity::IdentitySession, IdentityUnavailable> {
    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .map_err(IdentityUnavailable::from_kernel_deny)?;
    let parsed = aya::Btf::from_sys_fs().map_err(|_| IdentityUnavailable::NoBtf)?;
    let dir = ProbeDir::create("p11scope-identity-probe")?;
    match crate::discovery::kernel_identity::IdentitySession::probe_and_load(&parsed, &dir.path) {
        Ok(session) => Ok(session),
        Err("identity functional probe failed") => Err(IdentityUnavailable::ProbeFailed),
        Err(_) => {
            // The session load failed: distinguish permission from
            // verifier/object with one follow-up strict load carrying
            // the full error. A now-successful load means the session
            // failure was transient, still `load_failed`.
            match crate::attach::identity_iter::load_identity_object_strict(&parsed) {
                Ok(_) => Err(IdentityUnavailable::LoadFailed),
                Err(error) => Err(map_live_load_error(error)),
            }
        }
    }
}

/// Forced-kernel preflight (D3d): numbering, BTF, strict load and
/// functional probe, before capture or any sink exists. `Ok` returns the
/// fresh production session; the capture owns it and installs every proof
/// pass on it, so the eligibility probe runs once per capture.
pub(crate) fn preflight_forced_kernel(
    checks: &dyn IdentityChecks,
) -> Result<crate::discovery::kernel_identity::IdentitySession, IdentityUnavailable> {
    match checks.numbering() {
        IdentityNumbering::Agree => {}
        IdentityNumbering::Mismatch => return Err(IdentityUnavailable::NumberingMismatch),
        IdentityNumbering::Unknown => return Err(IdentityUnavailable::NumberingUnknown),
    }
    match checks.btf() {
        IdentityBtf::Ok => {}
        IdentityBtf::FixMissing => return Err(IdentityUnavailable::KernelFixMissing),
        IdentityBtf::NoTaskIterPidfd => return Err(IdentityUnavailable::NoTaskIterPidfd),
        IdentityBtf::NoBtf => return Err(IdentityUnavailable::NoBtf),
    }
    checks.create_session()
}

/// The forced-kernel refusal line: `--identity-backend kernel: kernel
/// identity is unavailable: <reason>`.
pub(crate) fn forced_kernel_refusal(reason: IdentityUnavailable) -> String {
    format!(
        "--identity-backend kernel: kernel identity is unavailable: {}",
        reason.label()
    )
}

/// Capture-owned identity state (D3d): selection, resolved backend, first
/// finite fallback, cost threshold, the injected checks, and the one
/// capture-owned kernel session. All fields are `Send`: each collection job
/// takes the session for its pass and returns it afterwards, so session
/// lifetime (loaded capability, generation, sticky status and counters)
/// survives across passes while pass lifetime (held files, arenas, scope,
/// pins, records) stays per-pass. No cross-pass identity cache beyond the
/// session itself: every pass installs fresh anchors under a fresh
/// generation.
pub(crate) struct IdentityRunShared {
    selection: crate::cli::IdentityBackendSelection,
    backend: IdentityBackend,
    fallback: Option<String>,
    threshold: Option<usize>,
    auto_ineligible: bool,
    loaded: bool,
    session_failed: bool,
    next_generation: u64,
    session: Option<crate::discovery::kernel_identity::IdentitySession>,
    checks: Box<dyn IdentityChecks>,
    sweep_witness_rotation: u64,
    sweep_witness_denominator: usize,
}

pub(crate) type IdentityShared = std::sync::Arc<std::sync::Mutex<IdentityRunShared>>;

// The capture-owned session crosses to the collection worker inside the
// shared handle: the whole state (including the loaded BPF object) is Send.
fn _identity_shared_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<IdentityShared>();
}

impl IdentityRunShared {
    /// New capture state. Forced kernel must have passed
    /// [`preflight_forced_kernel`] before sinks exist; auto starts
    /// unresolved (userspace until its first proof selects kernel).
    pub(crate) fn new(
        selection: crate::cli::IdentityBackendSelection,
        checks: Box<dyn IdentityChecks>,
    ) -> Self {
        let (backend, threshold) = match selection {
            crate::cli::IdentityBackendSelection::Userspace => (IdentityBackend::Userspace, None),
            crate::cli::IdentityBackendSelection::Kernel => (IdentityBackend::Kernel, None),
            crate::cli::IdentityBackendSelection::Auto => (
                IdentityBackend::Userspace,
                Some(crate::discovery::kernel_identity::AUTO_KERNEL_PROOF_PID_THRESHOLD),
            ),
        };
        Self {
            selection,
            backend,
            fallback: None,
            threshold,
            auto_ineligible: false,
            loaded: false,
            session_failed: false,
            next_generation: 1,
            session: None,
            checks,
            sweep_witness_rotation: 0,
            sweep_witness_denominator: 0,
        }
    }

    /// New capture state preloaded with the forced-kernel preflight session:
    /// the one eligibility probe already ran before sinks existed, so proof
    /// passes install on it without a second load.
    pub(crate) fn new_with_session(
        selection: crate::cli::IdentityBackendSelection,
        checks: Box<dyn IdentityChecks>,
        session: crate::discovery::kernel_identity::IdentitySession,
    ) -> Self {
        let mut shared = Self::new(selection, checks);
        shared.session = Some(session);
        shared
    }

    /// This pass's witness window over refused candidates: the
    /// start offset plus the previous pass's refused count (the
    /// modulo; 0 bootstraps to an order window on the first pass).
    fn witness_window(&self) -> (u64, usize) {
        (self.sweep_witness_rotation, self.sweep_witness_denominator)
    }

    /// Advance the witness window by this pass's spent queries, and
    /// record this pass's refused count as the next denominator
    /// (`None` when no witness scan ran, or a zero refused count, keeps
    /// the previous denominator: a pass that counts no candidates spends
    /// no queries, so the next pass continues past the spent queries
    /// instead of rebootstrapping; 0 spent leaves the start alone, so
    /// the next pass restarts from the same offset instead of skipping a
    /// candidate it never proved).
    fn advance_witness_rotation(&mut self, spent: u32, refused: Option<usize>) {
        self.sweep_witness_rotation = self.sweep_witness_rotation.wrapping_add(u64::from(spent));
        if let Some(refused) = refused.filter(|refused| *refused > 0) {
            self.sweep_witness_denominator = refused;
        }
    }

    #[cfg(test)]
    pub(crate) fn with_threshold(
        selection: crate::cli::IdentityBackendSelection,
        threshold: Option<usize>,
        checks: Box<dyn IdentityChecks>,
    ) -> Self {
        let mut shared = Self::new(selection, checks);
        shared.threshold = threshold;
        shared
    }

    pub(crate) fn summary(&self) -> IdentitySummary {
        IdentitySummary {
            backend: self.backend,
            fallback: self.fallback.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn loaded(&self) -> bool {
        self.loaded
    }

    fn note_fallback(&mut self, reason: &str) {
        if self.fallback.is_none() {
            self.fallback = Some(reason.to_string());
        }
    }

    fn note_selection_fallback(&mut self, reason: IdentityUnavailable) {
        self.note_fallback(reason.label());
    }
}

/// The finite runtime-fallback rendering: `label` alone, or
/// `label: detail` for the fixed target-run-limit detail.
fn runtime_fallback_label(
    reason: crate::discovery::kernel_identity::KernelFallbackReason,
) -> String {
    match reason.detail() {
        Some(detail) => format!("{}: {detail}", reason.label()),
        None => reason.label().to_string(),
    }
}

/// Scripted capability source for tests: canned outcomes plus call
/// counts proving load/probe ordering (userspace and auto-no-proof
/// never load; cheap failures never reach the session attempt).
#[cfg(test)]
pub(crate) struct ScriptedIdentityChecks {
    pub numbering: IdentityNumbering,
    pub btf: IdentityBtf,
    /// `setup_headroom` outcome: ample unless a test scripts scarcity.
    pub headroom: Result<usize, String>,
    /// `create_session` outcome: always `Err` in unit tests (a real
    /// session needs BPF; success is covered by privileged cells).
    /// `None` panics if called, proving no-load paths.
    pub session: Option<IdentityUnavailable>,
    pub numbering_calls: std::sync::atomic::AtomicUsize,
    pub btf_calls: std::sync::atomic::AtomicUsize,
    pub headroom_calls: std::sync::atomic::AtomicUsize,
    pub session_calls: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl ScriptedIdentityChecks {
    pub(crate) fn refuse(reason: IdentityUnavailable) -> Self {
        let (numbering, btf, session) = match reason {
            IdentityUnavailable::NumberingMismatch => {
                (IdentityNumbering::Mismatch, IdentityBtf::Ok, None)
            }
            IdentityUnavailable::NumberingUnknown => {
                (IdentityNumbering::Unknown, IdentityBtf::Ok, None)
            }
            IdentityUnavailable::KernelFixMissing => {
                (IdentityNumbering::Agree, IdentityBtf::FixMissing, None)
            }
            IdentityUnavailable::NoTaskIterPidfd => {
                (IdentityNumbering::Agree, IdentityBtf::NoTaskIterPidfd, None)
            }
            IdentityUnavailable::NoBtf => (IdentityNumbering::Agree, IdentityBtf::NoBtf, None),
            IdentityUnavailable::PermissionDenied
            | IdentityUnavailable::LoadFailed
            | IdentityUnavailable::ProbeFailed
            | IdentityUnavailable::FdHeadroom => {
                (IdentityNumbering::Agree, IdentityBtf::Ok, Some(reason))
            }
        };
        Self {
            numbering,
            btf,
            headroom: Ok(usize::MAX),
            session,
            numbering_calls: std::sync::atomic::AtomicUsize::new(0),
            btf_calls: std::sync::atomic::AtomicUsize::new(0),
            headroom_calls: std::sync::atomic::AtomicUsize::new(0),
            session_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Cheap checks pass; any session attempt answers `reason`.
    pub(crate) fn session_fails(reason: IdentityUnavailable) -> Self {
        Self {
            numbering: IdentityNumbering::Agree,
            btf: IdentityBtf::Ok,
            headroom: Ok(usize::MAX),
            session: Some(reason),
            numbering_calls: std::sync::atomic::AtomicUsize::new(0),
            btf_calls: std::sync::atomic::AtomicUsize::new(0),
            headroom_calls: std::sync::atomic::AtomicUsize::new(0),
            session_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Nothing may be consulted: any call panics (no-load proofs).
    pub(crate) fn must_not_load() -> Self {
        Self {
            numbering: IdentityNumbering::Agree,
            btf: IdentityBtf::Ok,
            headroom: Ok(usize::MAX),
            session: None,
            numbering_calls: std::sync::atomic::AtomicUsize::new(0),
            btf_calls: std::sync::atomic::AtomicUsize::new(0),
            headroom_calls: std::sync::atomic::AtomicUsize::new(0),
            session_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
impl IdentityChecks for ScriptedIdentityChecks {
    fn numbering(&self) -> IdentityNumbering {
        self.numbering_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.numbering
    }

    fn btf(&self) -> IdentityBtf {
        self.btf_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.btf
    }

    fn setup_headroom(&self) -> Result<usize, String> {
        self.headroom_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.headroom.clone()
    }

    fn create_session(
        &self,
    ) -> Result<crate::discovery::kernel_identity::IdentitySession, IdentityUnavailable> {
        self.session_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(self
            .session
            .expect("scripted checks: no session load on this path"))
    }
}

/// Observes batch-level userspace fallback inside kernel attribution:
/// delegates every batch to the kernel proof and records the first
/// finite fallback reason. Per-request `None` answers inside an
/// otherwise-kernel batch (unvisited/demoted/ineligible) stay in the
/// session ledger; this wrapper sees batch decisions only.
struct FallbackObservingProof<'a, P> {
    inner: &'a mut P,
    first_fallback:
        std::cell::Cell<Option<crate::discovery::kernel_identity::KernelFallbackReason>>,
}

impl<P> FallbackObservingProof<'_, P> {
    fn observed(&self) -> Option<crate::discovery::kernel_identity::KernelFallbackReason> {
        self.first_fallback.get()
    }
}

impl<P: crate::discovery::confirm_shards::SegmentProof>
    crate::discovery::confirm_shards::SegmentProof for FallbackObservingProof<'_, P>
{
    fn prove<'r>(
        &'r mut self,
        batch: &crate::discovery::confirm_shards::AcceptedBatch<'_>,
        budget: &mut CaptureWorkBudget,
        resources: &IoResources,
    ) -> crate::discovery::kernel_identity::ProofDecision<'r> {
        let decision = self.inner.prove(batch, budget, resources);
        let fallback = match &decision {
            crate::discovery::kernel_identity::ProofDecision::Userspace(reason)
            | crate::discovery::kernel_identity::ProofDecision::UserspaceExceptOverlay {
                reason,
                ..
            } => Some(crate::discovery::kernel_identity::KernelFallbackReason::from(*reason)),
            crate::discovery::kernel_identity::ProofDecision::Kernel(_) => None,
        };
        if let Some(reason) = fallback
            && self.first_fallback.get().is_none()
        {
            self.first_fallback.set(Some(reason));
        }
        decision
    }
}

/// Collect `--system` for inventory with D3d identity selection: custody
/// plus userspace or kernel sweep proof per the capture-owned shared
/// state, assembled under the Inventory policy. `inspect --system`
/// keeps using [`collect`] (userspace-only, frozen output).
/// `prior_objects` / `prior_bytes` are already-retained capture-level
/// pins, charged against the shared manifest+pre-arm budget (packet 6.13
/// round-3, finding 3).
#[allow(clippy::too_many_arguments)]
pub(crate) fn collect_system_with_identity(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    policy: AdmissionPolicy,
    shared: IdentityShared,
    budget: CaptureWorkBudget,
    scanned: &BTreeSet<u32>,
    manifests: &[PathBuf],
    prior_objects: usize,
    prior_bytes: u64,
) -> Result<Catalog> {
    if !matches!(policy, AdmissionPolicy::Inventory(_)) {
        return Err(anyhow::anyhow!(
            "physical identity collection requires inventory policy"
        ));
    }
    // The selection is fixed for the capture, so one read serves both the
    // custody cap below and the proof-index skip after the bind.
    let selection = shared
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .selection;
    let mut timings = StageTimings::new();
    let (mut collection, mut custody) = collect_members_identity(
        hints,
        hooks,
        max_scan_pids,
        &mut timings,
        true,
        budget,
        identity_takes_anchors(selection),
        scanned,
    );
    let stats = OutcomeStats {
        enumerated: collection.enumerated.len(),
        proc_list_failed: collection.proc_list_failed,
    };
    if decide_system_outcome(stats) == SystemOutcome::HardError {
        return Err(proc_list_system_error(&collection));
    }
    progress!("p11scope: lowering scan-only admission and rendering...");
    let bind_start = monotonic_ns();
    let mut bound = bind_collection(&mut collection);
    timings.span(StageKind::Bind, "assemble", bind_start, monotonic_ns());
    let confirm_start = monotonic_ns();
    // Per-pass kernel decision under the capture lock: userspace never
    // loads; auto without proof never loads; otherwise cheap checks
    // first, then at most one session attempt for this pass. Lazy
    // session init runs BEFORE the census: the setup peak is reserved
    // inside the takeout, and the census below counts the retained
    // session handles before the one-shot reconcile adopts the
    // allowance. Session FDs are unleased but counted, and no segment
    // worker or pin is live yet, so the reconcile boundary stays
    // quiescent.
    // Explicit userspace never attempts kernel, so its decision needs no
    // proof plan: skip the index build entirely (perf). The decide path
    // stays correct because userspace decides `Userspace` for either
    // `has_proof` value (see `d3d_userspace_selection_never_loads_or_probes`).
    let explicit_userspace = matches!(selection, crate::cli::IdentityBackendSelection::Userspace);
    let has_proof = if explicit_userspace {
        false
    } else {
        sweep_has_proof_plan(&collection, &bound)
    };
    let attempt = decide_pass_attempt(&shared, has_proof);
    let takeout = match &attempt {
        PassAttempt::Kernel { .. } => take_session_for_pass(&shared),
        PassAttempt::Userspace => None,
    };
    let shards = shard_count(collection.sweep.len(), shard_threads());
    let held = custody.as_mut().expect("identity scan owns custody");
    let ready = !held.failed()
        && collection.budget.check_deadline_now().is_none()
        && collection.budget.poll_collection(0);
    let census = if ready {
        let census = SegmentPolicy::try_snapshot(shard_threads(), collection.sweep.len());
        if collection.budget.check_deadline_now().is_some() || !collection.budget.poll_collection(0)
        {
            Err(crate::discovery::sweep_attribution::FD_CENSUS_REASON.into())
        } else {
            census
        }
    } else {
        Err(crate::discovery::sweep_attribution::FD_CENSUS_REASON.into())
    };
    let segment_policy = identity_confirmation_policy(held, census).map_err(anyhow::Error::msg)?;
    let reservations = held.owner.clone();
    let attributed = with_confirmation_pools(
        shards,
        segment_policy,
        proof_stat_threads(),
        |pools| match attempt {
            PassAttempt::Userspace => attribute_sweep_with(
                &mut collection,
                &bound,
                &bound.aggregate,
                |sweep, unavailable, selected, index, budget| {
                    crate::discovery::confirm_shards::attribute_unselected_with_policy(
                        sweep,
                        unavailable,
                        selected,
                        index,
                        budget,
                        segment_policy,
                        &reservations,
                        shards,
                        &|| OsConfirmIo::with_pools(pools),
                    )
                },
            ),
            PassAttempt::Kernel { threshold } => attribute_pass_with_kernel(
                &shared,
                takeout,
                &mut collection,
                &bound,
                custody.take().expect("identity scan owns custody"),
                segment_policy,
                &reservations,
                shards,
                pools,
                threshold,
            ),
        },
    );
    timings.span(StageKind::Scan, "confirm", confirm_start, monotonic_ns());
    prepare_count_manifests(
        &mut collection,
        &mut bound,
        manifests,
        prior_objects,
        prior_bytes,
    );
    let assemble_start = monotonic_ns();
    let mut catalog = assemble(
        collection,
        bound,
        attributed,
        policy,
        collector_admission_scope(hints, false),
    );
    timings.span(StageKind::Plan, "assemble", assemble_start, monotonic_ns());
    catalog.stage_timings = timings;
    Ok(catalog)
}

/// What this pass's attribution may attempt.
enum PassAttempt {
    Userspace,
    Kernel { threshold: Option<usize> },
}

/// Decide under the capture lock whether this pass attempts kernel
/// proof. Cheap checks (numbering/BTF) run here for auto's first
/// proof; session loads happen after the lock is dropped. No-request
/// passes add zero: they neither load nor record fallback.
fn decide_pass_attempt(shared: &IdentityShared, has_proof: bool) -> PassAttempt {
    let mut shared = shared.lock().unwrap_or_else(|poison| poison.into_inner());
    match shared.selection {
        crate::cli::IdentityBackendSelection::Userspace => PassAttempt::Userspace,
        crate::cli::IdentityBackendSelection::Kernel if !has_proof => PassAttempt::Userspace,
        crate::cli::IdentityBackendSelection::Kernel => PassAttempt::Kernel { threshold: None },
        crate::cli::IdentityBackendSelection::Auto if !has_proof => PassAttempt::Userspace,
        crate::cli::IdentityBackendSelection::Auto if shared.auto_ineligible => {
            PassAttempt::Userspace
        }
        crate::cli::IdentityBackendSelection::Auto => {
            match shared.checks.numbering() {
                IdentityNumbering::Agree => {}
                IdentityNumbering::Mismatch => {
                    shared.auto_ineligible = true;
                    shared.note_selection_fallback(IdentityUnavailable::NumberingMismatch);
                    return PassAttempt::Userspace;
                }
                IdentityNumbering::Unknown => {
                    shared.auto_ineligible = true;
                    shared.note_selection_fallback(IdentityUnavailable::NumberingUnknown);
                    return PassAttempt::Userspace;
                }
            }
            match shared.checks.btf() {
                IdentityBtf::Ok => {}
                IdentityBtf::FixMissing => {
                    shared.auto_ineligible = true;
                    shared.note_selection_fallback(IdentityUnavailable::KernelFixMissing);
                    return PassAttempt::Userspace;
                }
                IdentityBtf::NoTaskIterPidfd => {
                    shared.auto_ineligible = true;
                    shared.note_selection_fallback(IdentityUnavailable::NoTaskIterPidfd);
                    return PassAttempt::Userspace;
                }
                IdentityBtf::NoBtf => {
                    shared.auto_ineligible = true;
                    shared.note_selection_fallback(IdentityUnavailable::NoBtf);
                    return PassAttempt::Userspace;
                }
            }
            let threshold = shared.threshold;
            PassAttempt::Kernel { threshold }
        }
    }
}

/// One pass's exclusive session takeout: the capture-owned session plus
/// the generation this pass installs under. The pass returns the session
/// to the shared state when it ends; the generation is spent whether the
/// install succeeds or not.
struct SessionTakeout {
    session: crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
}

/// Whether the measured setup headroom covers the session setup/probe
/// peak. A failed census refuses: lazy init never opens handles it did
/// not reserve.
fn session_setup_admitted(headroom: Result<usize, String>) -> bool {
    headroom.is_ok_and(|headroom| headroom >= crate::attach::identity_iter::SESSION_SETUP_PEAK_FDS)
}

/// Record a sticky session-setup failure (refused reservation or failed
/// creation) with its first finite reason: auto's first failure is
/// failed selection (userspace, sticky); a later one keeps `kernel` as
/// a runtime fallback.
fn note_session_failure(shared: &mut IdentityRunShared, reason: IdentityUnavailable) {
    let selection = shared.selection;
    match selection {
        crate::cli::IdentityBackendSelection::Auto
            if shared.backend == IdentityBackend::Userspace =>
        {
            shared.auto_ineligible = true;
            shared.note_selection_fallback(reason);
        }
        _ => shared.note_selection_fallback(reason),
    }
}

/// Take this pass's kernel session from the capture-owned state: reuse
/// the live session when one is held, otherwise attempt the single
/// capture-level session creation. A failed creation is sticky with its
/// first finite reason (no per-pass re-probe); the caller installs exactly
/// one anchor pass under the takeout generation and returns the session
/// afterwards, so sticky status and counters survive across passes. The
/// generation is spent whether the install succeeds or not; before
/// generation exhaustion the object is retired and reloaded once rather
/// than wrapping into a parser-accepted old generation.
fn take_session_for_pass(shared: &IdentityShared) -> Option<SessionTakeout> {
    let mut shared = shared.lock().unwrap_or_else(|poison| poison.into_inner());
    if shared.next_generation >= u64::from(u32::MAX) {
        // Practically unreachable (one generation per pass): retire the
        // object before exhaustion; the creation below reloads it and the
        // counter restarts at 1.
        shared.session = None;
        shared.next_generation = 1;
    }
    let session = match shared.session.take() {
        Some(session) => session,
        None if shared.session_failed => return None,
        None => {
            // Reserve the setup/probe FD peak before opening anything.
            // A refused reservation is sticky with the finite reason,
            // like a failed creation — but nothing was loaded.
            if !session_setup_admitted(shared.checks.setup_headroom()) {
                shared.session_failed = true;
                note_session_failure(&mut shared, IdentityUnavailable::FdHeadroom);
                return None;
            }
            // The trait object cannot be cloned; create the session while
            // holding the lock (jobs run sequentially, the service tick
            // never takes it). Mark the load attempt first.
            shared.loaded = true;
            match shared.checks.create_session() {
                Ok(session) => session,
                Err(reason) => {
                    shared.session_failed = true;
                    note_session_failure(&mut shared, reason);
                    return None;
                }
            }
        }
    };
    let generation = shared.next_generation;
    shared.next_generation = shared.next_generation.saturating_add(1);
    Some(SessionTakeout {
        session,
        generation,
    })
}

/// Apply this pass's kernel fallback to the capture disclosure: the
/// session ledger's first reason (chronologically first across batch and
/// within-batch fallbacks) wins, then the batch wrapper's first
/// batch-level reason; an existing capture reason still wins over both.
fn apply_kernel_fallback(
    shared: &mut IdentityRunShared,
    observed: Option<crate::discovery::kernel_identity::KernelFallbackReason>,
    ledger_first: Option<crate::discovery::kernel_identity::KernelFallbackReason>,
) {
    if let Some(reason) = ledger_first {
        shared.note_fallback(&runtime_fallback_label(reason));
    }
    if let Some(reason) = observed {
        shared.note_fallback(&runtime_fallback_label(reason));
    }
}

fn note_anchor_setup_fallback(shared: &mut IdentityRunShared, capture_excluded: bool) {
    if !capture_excluded
        && shared.selection == crate::cli::IdentityBackendSelection::Auto
        && shared.backend == IdentityBackend::Userspace
    {
        shared.auto_ineligible = true;
    }
    shared.note_fallback("anchor_not_installed");
}

/// Run this pass's sweep attribution on the capture-owned kernel session,
/// falling back to userspace within the same pins on any setup failure.
/// The pass installs fresh anchors under its takeout generation and always
/// returns the session, so sticky status and counters survive across
/// passes. Forced kernel bypasses the cost threshold only (`threshold:
/// None`); resource and run caps still apply inside the proof. The
/// takeout is created before the census (see the caller), so a missing
/// one here is an already-recorded setup failure, never a fresh attempt.
#[allow(clippy::too_many_arguments)]
fn attribute_pass_with_kernel(
    shared: &IdentityShared,
    takeout: Option<SessionTakeout>,
    collection: &mut Collection,
    bound: &Bound,
    custody: ExaminedCustody,
    segment_policy: SegmentPolicy,
    reservations: &ReservationOwner,
    shards: usize,
    pools: ProofPools<'_>,
    threshold: Option<usize>,
) -> Option<Attributed> {
    // The witness budget covers a different candidate window each
    // kernel pass, so callers past the per-pass budget still prove
    // within a few passes instead of starving every pass. The pass
    // advances the window by the queries it actually spends and
    // reports its refused count as the next denominator.
    let (window_start, window_denominator) = {
        let shared = shared.lock().unwrap_or_else(|poison| poison.into_inner());
        shared.witness_window()
    };
    let Some(takeout) = takeout else {
        let out = attribute_sweep_with(
            collection,
            bound,
            &bound.aggregate,
            |sweep, unavailable, selected, index, budget| {
                crate::discovery::confirm_shards::attribute_unselected_with_policy(
                    sweep,
                    unavailable,
                    selected,
                    index,
                    budget,
                    segment_policy,
                    reservations,
                    shards,
                    &|| OsConfirmIo::with_pools(pools),
                )
            },
        );
        // No witness runs on the plain path: the window stays.
        {
            let mut shared = shared.lock().unwrap_or_else(|poison| poison.into_inner());
            shared.advance_witness_rotation(0, None);
        }
        return out;
    };
    let mut session = takeout.session;
    let generation = takeout.generation;
    // Admitted anchors: the aggregate's proven sweep keys; examined
    // anchors ride in custody. Held files only, never a pathname.
    let admitted: Vec<(ObjectKey, PinnedObjectId)> =
        bound.aggregate.sweep_match_keys().into_iter().collect();
    let pass = crate::discovery::kernel_identity::AnchorPass::prepare_excluding(
        &bound.aggregate,
        admitted,
        custody,
        collection.budget.kernel_anchor_exclusions(),
    );
    let capture_excluded = pass.only_capture_excluded();
    let install_deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    // The install borrows the session exclusively; its scope ends before
    // the common tail below touches the session again. `Some` carries the
    // proof outcome out (dropping the install rolls this pass's ledger —
    // batch and within-batch fallbacks — into the session totals);
    // `None` is a failed install, whose spent generation is never reused.
    let proved = {
        let installed = session
            .install_anchors(pass, generation, install_deadline)
            .ok();
        if let Some(mut installed) = installed {
            let probe_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut probe = crate::discovery::kernel_identity::KernelMemberProbe::new(
                &mut installed,
                OsConfirmIo::with_pools(pools),
                probe_deadline,
            );
            if let Some(threshold) = threshold {
                probe = probe.with_auto_threshold(threshold);
            }
            let (attributed, observed, witness_spent, witness_refused) =
                attribute_sweep_with_kernel(
                    collection,
                    bound,
                    segment_policy,
                    reservations,
                    shards,
                    &|| OsConfirmIo::with_pools(pools),
                    &mut probe,
                    window_start,
                    window_denominator,
                );
            drop(probe);
            drop(installed);
            Some((attributed, observed, witness_spent, witness_refused))
        } else {
            None
        }
    };
    let (out, spent, refused) = match proved {
        Some((attributed, observed, witness_spent, witness_refused)) => {
            // A fully proved pass adds zero to the totals.
            let ledger_first = session.fallback_totals().first_reason;
            {
                let mut shared = shared.lock().unwrap_or_else(|poison| poison.into_inner());
                if shared.backend == IdentityBackend::Userspace
                    && shared.selection == crate::cli::IdentityBackendSelection::Auto
                {
                    shared.backend = IdentityBackend::Kernel;
                }
                apply_kernel_fallback(&mut shared, observed, ledger_first);
                // Always return the session: later passes install on it and
                // its sticky status and counters persist across the capture.
                shared.session = Some(session);
            }
            let out = match attributed {
                Some(attributed) => Some(attributed),
                None => {
                    // Kernel expectations failed to install: same-pin
                    // userspace fallback with a finite reason.
                    {
                        let mut shared = shared.lock().unwrap_or_else(|poison| poison.into_inner());
                        shared.note_fallback("anchor_not_installed");
                    }
                    attribute_sweep_with(
                        collection,
                        bound,
                        &bound.aggregate,
                        |sweep, unavailable, selected, index, budget| {
                            crate::discovery::confirm_shards::attribute_unselected_with_policy(
                                sweep,
                                unavailable,
                                selected,
                                index,
                                budget,
                                segment_policy,
                                reservations,
                                shards,
                                &|| OsConfirmIo::with_pools(pools),
                            )
                        },
                    )
                }
            };
            (out, witness_spent, witness_refused)
        }
        None => {
            // The install failed but the session stays valid: return it
            // for later passes with the finite reason recorded.
            {
                let mut shared = shared.lock().unwrap_or_else(|poison| poison.into_inner());
                note_anchor_setup_fallback(&mut shared, capture_excluded);
                shared.session = Some(session);
            }
            let mut capture_excluded_window = (0u32, None);
            let out = attribute_sweep_with(
                collection,
                bound,
                &bound.aggregate,
                |sweep, unavailable, selected, index, budget| {
                    let mut witness = crate::discovery::overlay_witness::KernelSweepWitness::new();
                    let (out, refused) =
                        crate::discovery::confirm_shards::attribute_failed_install_sweep(
                            capture_excluded,
                            sweep,
                            unavailable,
                            selected,
                            index,
                            budget,
                            segment_policy,
                            reservations,
                            shards,
                            &|| OsConfirmIo::with_pools(pools),
                            &bound.aggregate,
                            &mut witness,
                            window_start,
                            window_denominator,
                        );
                    capture_excluded_window = (witness.used(), refused);
                    out
                },
            );
            let (spent, refused) = capture_excluded_window;
            (out, spent, refused)
        }
    };
    {
        let mut shared = shared.lock().unwrap_or_else(|poison| poison.into_inner());
        shared.advance_witness_rotation(spent, refused);
    }
    out
}

/// Kernel sweep attribution: the [`attribute_sweep_with`] prefix
/// (index, selection, refused filtering) plus kernel slot
/// expectations and the segment-proof hook. Setup failures return
/// `None` so the caller runs the same-pin userspace fallback. The
/// last returns are the witness queries this sweep spent and its
/// refused total (`None` when no sweep ran), so the caller can
/// advance the pass-wide window past them.
#[allow(clippy::too_many_arguments)]
fn attribute_sweep_with_kernel<Io, F>(
    collection: &mut Collection,
    bound: &Bound,
    policy: SegmentPolicy,
    owner: &ReservationOwner,
    threads: usize,
    make_io: &F,
    probe: &mut crate::discovery::kernel_identity::KernelMemberProbe<'_, '_, '_, Io>,
    window_start: u64,
    window_denominator: usize,
) -> (
    Option<Attributed>,
    Option<crate::discovery::kernel_identity::KernelFallbackReason>,
    u32,
    Option<usize>,
)
where
    Io: crate::discovery::confirm_shards::ShardableIo,
    Io::Pin: Send,
    F: Fn() -> Io + Sync,
{
    if !collection.cap_hit {
        return (None, None, 0, None);
    }
    let (mut index, selected, refused) = sweep_proof_prefix(collection, bound, &bound.aggregate);
    progress!(
        "p11scope: attributing {} unselected processes by maps identity...",
        collection.sweep.len().saturating_sub(selected.len())
    );
    if probe.install_expectations(&mut index).is_err() {
        return (None, None, 0, None);
    }
    let mut observing = FallbackObservingProof {
        inner: probe.segment_proof(),
        first_fallback: std::cell::Cell::new(None),
    };
    // K1-R2: watched overlay keys with no sweep route (live capture
    // attach-set exclusions) prove via the private witness session
    // under the D-P1 per-pass budget; exhaustion keeps the named loss.
    let mut witness = crate::discovery::overlay_witness::KernelSweepWitness::new();
    let (mut attribution, refused_total) =
        crate::discovery::confirm_shards::attribute_unselected_with_segment_proof_with_witness(
            &collection.sweep,
            &collection.sweep_unavailable,
            &selected,
            &index,
            &mut collection.budget,
            policy,
            owner,
            threads,
            make_io,
            &mut observing,
            &bound.aggregate,
            &mut witness,
            window_start,
            window_denominator,
        );
    let changed = retain_unchanged(&mut attribution, &bound.aggregate);
    let observed = observing.observed();
    let spent = witness.used();
    (
        Some(Attributed {
            attribution,
            refused,
            changed,
        }),
        observed,
        spent,
        Some(refused_total),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        IdentityNumbering, IdentityRunShared, IdentityShared, IdentityUnavailable,
        LiveIdentityChecks, ProbeDir, ScriptedIdentityChecks, apply_kernel_fallback,
        decide_pass_attempt, forced_kernel_refusal, preflight_forced_kernel,
        runtime_fallback_label, take_session_for_pass,
    };
    use crate::cli::IdentityBackendSelection;
    use std::sync::atomic::Ordering;

    #[test]
    fn aimed_system_capture_lowers_without_shared_reserve() {
        let hints = vec![std::path::PathBuf::from("/opt/provider.so")];
        assert_eq!(
            super::collector_admission_scope(&hints, false),
            crate::plan::AdmissionScope::Named
        );
    }

    #[test]
    fn unaimed_system_capture_keeps_shared_reserve() {
        assert_eq!(
            super::collector_admission_scope(&[], false),
            crate::plan::AdmissionScope::Shared
        );
    }

    #[test]
    fn pid_capture_is_always_named() {
        assert_eq!(
            super::collector_admission_scope(&[], true),
            crate::plan::AdmissionScope::Named
        );
    }

    fn shared_with(
        selection: IdentityBackendSelection,
        checks: ScriptedIdentityChecks,
    ) -> (IdentityShared, *const ScriptedIdentityChecks) {
        // The shared state owns the scripted checks; the raw pointer
        // reads back call counts (the Arc outlives the test).
        let checks = Box::new(checks);
        let ptr: *const ScriptedIdentityChecks = &*checks;
        let shared = std::sync::Arc::new(std::sync::Mutex::new(IdentityRunShared::new(
            selection, checks,
        )));
        (shared, ptr)
    }

    /// A 1-object count-manifest document over a real file, modeled on
    /// identity's `count_manifest_file` helper.
    fn count_manifest_doc() -> (tempfile::TempDir, std::path::PathBuf) {
        use p11scope_manifest::manifest::*;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("count-object.so");
        std::fs::copy("/bin/sh", &path).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
        let spelling = path.to_str().unwrap().to_string();
        let manifest = Manifest {
            schema: SCHEMA.into(),
            module_path: spelling.clone(),
            objects: vec![ObjectRecord {
                id: 0,
                path: spelling.clone(),
                identity: inspected.identity.clone(),
            }],
            provenance_objects: vec![ProvenanceObject {
                path: spelling,
                device_major: mapping.device_major,
                device_minor: mapping.device_minor,
                inode: mapping.inode,
                identity: inspected.identity,
            }],
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version {
                    major: 2,
                    minor: 40,
                }),
                walk: WalkOutcome::Full,
                functions: vec![FunctionRecord {
                    name: "C_Initialize".into(),
                    resolution: Resolution::NullPointer,
                }],
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
            selection_evidence: Default::default(),
        };
        assert!(crate::manifest_input::validate_structure(&manifest).is_empty());
        let doc = dir.path().join("count.json");
        std::fs::write(&doc, serde_json::to_vec(&manifest).unwrap()).unwrap();
        (dir, doc)
    }

    fn empty_collection() -> super::Collection {
        super::Collection {
            enumerated: Vec::new(),
            selected: Vec::new(),
            cap: 0,
            cap_hit: false,
            members: Vec::new(),
            scope_gaps: Vec::new(),
            proc_list_failed: false,
            sweep: Vec::new(),
            sweep_unavailable: std::collections::BTreeSet::new(),
            budget: crate::discovery::scan::CaptureWorkBudget::new(
                crate::discovery::scan::ScanLimits {
                    per_object_bytes: 8 << 20,
                    total_bytes: 64 << 20,
                },
            ),
        }
    }

    #[test]
    fn prepare_count_manifests_charges_retained_prearm_prior() {
        // Packet 6.13 round-3 (re-audit finding 3): per-pass count pins
        // charge already-retained pre-arm usage against the shared cap —
        // a full retained set refuses one more count object by budget.
        let (_dir, doc) = count_manifest_doc();
        let mut collection = empty_collection();
        let mut bound = super::bind_collection(&mut collection);
        super::prepare_count_manifests(
            &mut collection,
            &mut bound,
            std::slice::from_ref(&doc),
            512,
            0,
        );
        assert!(bound.count_manifests.is_empty());
        assert_eq!(collection.scope_gaps.len(), 1);
        assert!(
            collection.scope_gaps[0].reason.contains("512-object limit"),
            "over-budget count pin refuses by budget: {:?}",
            collection.scope_gaps[0].reason
        );
        // Control: the same document without retained usage pins — it is
        // refused later for scope reasons (nothing collected), not budget.
        let mut collection = empty_collection();
        let mut bound = super::bind_collection(&mut collection);
        super::prepare_count_manifests(
            &mut collection,
            &mut bound,
            std::slice::from_ref(&doc),
            0,
            0,
        );
        assert!(bound.count_manifests.is_empty());
        assert_eq!(collection.scope_gaps.len(), 1);
        let reason = &collection.scope_gaps[0].reason;
        assert!(reason.contains("not exactly mapped"), "{reason}");
        assert!(!reason.contains("object limit"), "{reason}");
    }

    /// D3d: forced preflight refuses each arm with its finite label,
    /// and cheap failures never reach the session attempt.
    #[test]
    fn d3d_preflight_refuses_each_arm_with_its_finite_label() {
        for reason in [
            IdentityUnavailable::NumberingMismatch,
            IdentityUnavailable::NumberingUnknown,
            IdentityUnavailable::KernelFixMissing,
            IdentityUnavailable::NoTaskIterPidfd,
            IdentityUnavailable::NoBtf,
            IdentityUnavailable::PermissionDenied,
            IdentityUnavailable::LoadFailed,
            IdentityUnavailable::ProbeFailed,
            IdentityUnavailable::FdHeadroom,
        ] {
            let checks = ScriptedIdentityChecks::refuse(reason);
            match preflight_forced_kernel(&checks) {
                Err(got) => assert_eq!(got, reason, "arm {}", reason.label()),
                Ok(_) => panic!("arm {} must refuse", reason.label()),
            }
            assert_eq!(
                forced_kernel_refusal(reason),
                format!(
                    "--identity-backend kernel: kernel identity is unavailable: {}",
                    reason.label()
                )
            );
            // Cheap arms never load; session arms load exactly once.
            let expect_session = matches!(
                reason,
                IdentityUnavailable::PermissionDenied
                    | IdentityUnavailable::LoadFailed
                    | IdentityUnavailable::ProbeFailed
                    | IdentityUnavailable::FdHeadroom
            );
            assert_eq!(
                checks.session_calls.load(Ordering::SeqCst),
                usize::from(expect_session),
                "arm {}",
                reason.label()
            );
            assert!(
                checks.numbering_calls.load(Ordering::SeqCst) >= 1,
                "arm {}",
                reason.label()
            );
        }
    }

    /// D3d: userspace never consults capability or probe sources.
    #[test]
    fn d3d_userspace_selection_never_loads_or_probes() {
        let checks = ScriptedIdentityChecks::must_not_load();
        // decide_pass_attempt must not call anything for userspace,
        // with or without proof. checked via counts below using a
        // shared handle (must_not_load panics only on session).
        let (shared, ptr) = shared_with(IdentityBackendSelection::Userspace, checks);
        for has_proof in [false, true] {
            assert!(matches!(
                decide_pass_attempt(&shared, has_proof),
                super::PassAttempt::Userspace
            ));
        }
        let checks = unsafe { &*ptr };
        assert_eq!(checks.numbering_calls.load(Ordering::SeqCst), 0);
        assert_eq!(checks.btf_calls.load(Ordering::SeqCst), 0);
        assert_eq!(checks.session_calls.load(Ordering::SeqCst), 0);
        let shared = shared.lock().unwrap();
        assert_eq!(shared.summary().backend, super::IdentityBackend::Userspace);
        assert_eq!(shared.summary().fallback, None);
        assert!(!shared.loaded());
    }

    /// D3d: auto without proof never loads and stays userspace/null.
    #[test]
    fn d3d_auto_without_proof_never_loads() {
        let (shared, ptr) = shared_with(
            IdentityBackendSelection::Auto,
            ScriptedIdentityChecks::must_not_load(),
        );
        assert!(matches!(
            decide_pass_attempt(&shared, false),
            super::PassAttempt::Userspace
        ));
        let checks = unsafe { &*ptr };
        assert_eq!(checks.numbering_calls.load(Ordering::SeqCst), 0);
        assert_eq!(checks.btf_calls.load(Ordering::SeqCst), 0);
        assert_eq!(checks.session_calls.load(Ordering::SeqCst), 0);
        let shared = shared.lock().unwrap();
        assert_eq!(shared.summary().backend, super::IdentityBackend::Userspace);
        assert_eq!(shared.summary().fallback, None);
        assert!(!shared.loaded());
    }

    /// D3d: auto's first proof with cheap failures stays userspace
    /// with the finite reason, sticky, without a session attempt.
    #[test]
    fn d3d_auto_cheap_failure_stays_userspace_sticky_without_session() {
        for reason in [
            IdentityUnavailable::NumberingMismatch,
            IdentityUnavailable::NumberingUnknown,
            IdentityUnavailable::KernelFixMissing,
            IdentityUnavailable::NoTaskIterPidfd,
            IdentityUnavailable::NoBtf,
        ] {
            let (shared, ptr) = shared_with(
                IdentityBackendSelection::Auto,
                ScriptedIdentityChecks::refuse(reason),
            );
            assert!(matches!(
                decide_pass_attempt(&shared, true),
                super::PassAttempt::Userspace
            ));
            // Sticky: a second proof pass consults nothing further.
            assert!(matches!(
                decide_pass_attempt(&shared, true),
                super::PassAttempt::Userspace
            ));
            let checks = unsafe { &*ptr };
            assert_eq!(
                checks.session_calls.load(Ordering::SeqCst),
                0,
                "{}",
                reason.label()
            );
            let shared = shared.lock().unwrap();
            assert_eq!(shared.summary().backend, super::IdentityBackend::Userspace);
            assert_eq!(shared.summary().fallback.as_deref(), Some(reason.label()));
            assert!(!shared.loaded());
        }
    }

    /// D3d: auto with passing cheap checks attempts kernel once per
    /// pass decision (the session attempt itself is the eligibility
    /// probe); the threshold rides along for the proof.
    #[test]
    fn d3d_auto_cheap_pass_attempts_kernel_with_threshold() {
        let (shared, ptr) = shared_with(
            IdentityBackendSelection::Auto,
            ScriptedIdentityChecks::session_fails(IdentityUnavailable::ProbeFailed),
        );
        match decide_pass_attempt(&shared, true) {
            super::PassAttempt::Kernel { threshold } => assert_eq!(
                threshold,
                Some(crate::discovery::kernel_identity::AUTO_KERNEL_PROOF_PID_THRESHOLD)
            ),
            super::PassAttempt::Userspace => panic!("cheap pass must attempt kernel"),
        }
        let checks = unsafe { &*ptr };
        assert_eq!(checks.numbering_calls.load(Ordering::SeqCst), 1);
        assert_eq!(checks.btf_calls.load(Ordering::SeqCst), 1);
        assert_eq!(checks.session_calls.load(Ordering::SeqCst), 0);
    }

    /// D3d: forced kernel attempts every proof pass with no cost
    /// threshold and skips no-proof passes without loading.
    #[test]
    fn d3d_forced_kernel_bypasses_threshold_only() {
        let (shared, _) = shared_with(
            IdentityBackendSelection::Kernel,
            ScriptedIdentityChecks::session_fails(IdentityUnavailable::ProbeFailed),
        );
        assert!(matches!(
            decide_pass_attempt(&shared, false),
            super::PassAttempt::Userspace
        ));
        match decide_pass_attempt(&shared, true) {
            super::PassAttempt::Kernel { threshold } => assert_eq!(threshold, None),
            super::PassAttempt::Userspace => panic!("forced proof must attempt kernel"),
        }
    }

    /// A precreated dir, symlink or file at the probe path is refused,
    /// never adopted: exclusive creation fails and the squatter survives.
    #[test]
    fn probe_dir_rejects_precreated_dir() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let scratch = tempfile::tempdir().expect("probe scratch");
        // A precreated directory with a sentinel inside.
        let taken = scratch.path().join("taken");
        std::fs::create_dir(&taken).expect("precreate dir");
        std::fs::write(taken.join("sentinel"), b"sentinel").expect("write sentinel");
        assert!(
            ProbeDir::create_at(&taken).is_err(),
            "a precreated probe dir must be refused, not adopted"
        );
        assert_eq!(
            std::fs::read(taken.join("sentinel")).expect("read sentinel"),
            b"sentinel"
        );
        // A precreated symlink to a victim dir.
        let victim = scratch.path().join("victim");
        std::fs::create_dir(&victim).expect("create victim");
        let link = scratch.path().join("linked");
        std::os::unix::fs::symlink(&victim, &link).expect("plant link");
        assert!(
            ProbeDir::create_at(&link).is_err(),
            "a symlinked probe path must be refused, not followed"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("stat link")
                .is_symlink()
        );
        // A precreated regular file.
        let file = scratch.path().join("file");
        std::fs::write(&file, b"squatter").expect("write squatter");
        assert!(
            ProbeDir::create_at(&file).is_err(),
            "a precreated probe file must be refused"
        );
        // The happy path is an owned 0700 dir, removed on drop.
        let fresh = scratch.path().join("fresh");
        let dir = ProbeDir::create_at(&fresh).expect("fresh probe dir");
        let meta = std::fs::symlink_metadata(&fresh).expect("stat fresh");
        assert!(meta.is_dir());
        assert_eq!(meta.uid(), unsafe { libc::geteuid() });
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        drop(dir);
        assert!(!fresh.exists(), "drop removes the owned probe dir");
    }

    /// `Drop` removes only the directory this value created: a swapped-in
    /// symlink is left alone and its target keeps its bytes.
    #[test]
    fn probe_dir_drop_skips_swapped_symlink() {
        let scratch = tempfile::tempdir().expect("probe scratch");
        let path = scratch.path().join("probe");
        let dir = ProbeDir::create_at(&path).expect("fresh probe dir");
        std::fs::remove_dir(&path).expect("remove probe dir");
        let victim = scratch.path().join("victim");
        std::fs::create_dir(&victim).expect("create victim");
        std::fs::write(victim.join("keep"), b"keep").expect("write keep");
        std::os::unix::fs::symlink(&victim, &path).expect("swap in link");
        drop(dir);
        assert_eq!(
            std::fs::read(victim.join("keep")).expect("read keep"),
            b"keep",
            "drop deleted through a swapped-in symlink"
        );
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("stat link")
                .is_symlink(),
            "drop removed the swapped-in symlink"
        );
    }

    /// `Drop` removes only the directory this value created: a swapped-in
    /// same-uid replacement directory is left alone, and the renamed-away
    /// original is left alone too — neither is deleted.
    #[test]
    fn probe_dir_drop_skips_swapped_dir() {
        let scratch = tempfile::tempdir().expect("probe scratch");
        let path = scratch.path().join("probe");
        let dir = ProbeDir::create_at(&path).expect("fresh probe dir");
        std::fs::write(path.join("orig"), b"orig").expect("write orig");
        let moved = scratch.path().join("original-away");
        std::fs::rename(&path, &moved).expect("rename original away");
        std::fs::create_dir(&path).expect("plant replacement dir");
        std::fs::write(path.join("replacement"), b"replacement").expect("write replacement");
        drop(dir);
        assert_eq!(
            std::fs::read(moved.join("orig")).expect("read orig"),
            b"orig",
            "drop deleted the renamed-away original"
        );
        assert_eq!(
            std::fs::read(path.join("replacement")).expect("read replacement"),
            b"replacement",
            "drop deleted a swapped-in replacement dir"
        );
    }

    /// `Drop` deletes at most the four known fixture names plus the
    /// directory itself when empty: unknown contents in the owned dir
    /// survive with their bytes intact, and the still-non-empty dir
    /// survives too. Fully-swapped paths are already skipped by the
    /// identity pre-check (see the tests above); this pins the deletion
    /// bound, so a replacement swapped in after the check can lose
    /// nothing but an empty dir.
    #[test]
    fn probe_dir_drop_preserves_unknown_contents() {
        let scratch = tempfile::tempdir().expect("probe scratch");
        let path = scratch.path().join("probe");
        let dir = ProbeDir::create_at(&path).expect("fresh probe dir");
        for name in ["probe-a", "probe-b", "probe-a-link", "probe-a-copy"] {
            std::fs::write(path.join(name), b"fixture").expect("write fixture");
        }
        std::fs::write(path.join("foreign"), b"foreign").expect("write foreign");
        drop(dir);
        assert_eq!(
            std::fs::read(path.join("foreign")).expect("read foreign"),
            b"foreign",
            "drop deleted unknown contents of the probe dir"
        );
        assert!(path.is_dir(), "drop removed a non-empty probe dir");
        for name in ["probe-a", "probe-b", "probe-a-link", "probe-a-copy"] {
            assert!(!path.join(name).exists(), "drop left fixture {name} behind");
        }
    }

    /// Whether a fresh file under `dir` maps `PROT_EXEC` (the probe
    /// child's fixture shape: it maps each fixture `PROT_READ|PROT_EXEC`
    /// `MAP_PRIVATE`). Test-only; the product carries its own check, so
    /// this asserts the behavior, not the implementation.
    fn exec_map_smoke(dir: &std::path::Path) -> bool {
        use std::os::fd::AsRawFd as _;
        let path = dir.join(format!("probe-smoke-{}", std::process::id()));
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        else {
            return false;
        };
        if file.set_len(4096).is_err() {
            let _ = std::fs::remove_file(&path);
            return false;
        }
        // SAFETY: anonymous-length private executable mapping of a
        // 4096-byte file we just created; unmapped and unlinked below.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        let mapped = addr != libc::MAP_FAILED;
        if mapped {
            // SAFETY: the successful `mmap` above returned this range.
            unsafe {
                libc::munmap(addr, 4096);
            }
        }
        drop(file);
        let _ = std::fs::remove_file(&path);
        mapped
    }

    /// The created probe dir exec-maps: the probe child maps its
    /// fixtures `PROT_EXEC`, so a noexec dir is unusable. Also the
    /// inner driver of `probe_dir_falls_back_when_temp_is_noexec`,
    /// which re-execs this binary to run exactly this cell with
    /// TMPDIR pointed at a noexec tmpfs. Run as root with `--ignored`.
    #[test]
    #[ignore = "privileged: created probe dir exec-maps"]
    fn probe_dir_created_dir_exec_maps() {
        let dir = ProbeDir::create("p11scope-identity-probe").expect("probe dir");
        assert!(
            exec_map_smoke(dir.path()),
            "probe dir is not exec-capable: {}",
            dir.path().display()
        );
    }

    /// The probe dir under a noexec temp root (kind nodes mount /tmp
    /// noexec): creation falls back to an exec-capable root instead of
    /// handing back a dir the probe cannot use. Forks, mounts a noexec
    /// tmpfs over a scratch dir in a private mount namespace, re-execs
    /// this binary to run the exec-map cell with TMPDIR pointed at it,
    /// and asserts the inner positive ran (exit 0 plus `1 passed`,
    /// never a zero-match pass). Run as root with `--ignored`.
    #[test]
    #[ignore = "privileged: probe dir falls back when temp is noexec"]
    fn probe_dir_falls_back_when_temp_is_noexec() {
        use std::ffi::CString;
        use std::io::Read as _;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::io::FromRawFd as _;
        let scratch = tempfile::tempdir().expect("noexec mountpoint");
        let mountpoint =
            CString::new(scratch.path().as_os_str().as_bytes()).expect("mountpoint has no nul");
        let exe = std::env::current_exe().expect("own test binary");
        let args = [
            CString::new(exe.as_os_str().as_bytes()).expect("exe has no nul"),
            CString::new("--exact").unwrap(),
            CString::new("inspect_system::tests::probe_dir_created_dir_exec_maps").unwrap(),
            CString::new("--ignored").unwrap(),
            CString::new("--test-threads=1").unwrap(),
            CString::new("--nocapture").unwrap(),
        ];
        let argv: Vec<*const libc::c_char> = args
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        // The re-exec environment: this process's own with TMPDIR
        // pointed at the noexec mount. Built pre-fork; the child only
        // passes the pointers to `execve`.
        let tmpdir = CString::new(format!("TMPDIR={}", scratch.path().to_string_lossy()))
            .expect("TMPDIR has no nul");
        let mut env: Vec<CString> = std::env::vars_os()
            .filter(|(key, _)| key != "TMPDIR")
            .map(|(key, value)| {
                let mut pair = key.into_encoded_bytes();
                pair.push(b'=');
                pair.extend_from_slice(&value.into_encoded_bytes());
                CString::new(pair).expect("env pair has no nul")
            })
            .collect();
        env.push(tmpdir);
        let envp: Vec<*const libc::c_char> = env
            .iter()
            .map(|var| var.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let mut pipe = [0 as libc::c_int; 2];
        // SAFETY: out-param pipe pair; the parent closes the write end
        // after forking and reads the read end to EOF.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0, "pipe works");
        // SAFETY: the child only calls async-signal-safe libc, then
        // re-execs or exits with a distinct status; all CStrings were
        // built before forking. The parent waits below.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork for the noexec probe runner");
        if pid == 0 {
            noexec_probe_child(&mountpoint, pipe[1], &argv, &envp);
        }
        // SAFETY: our own pipe write end; closing first lets EOF arrive
        // when the re-exec'd child exits.
        assert_eq!(unsafe { libc::close(pipe[1]) }, 0, "close our write end");
        // SAFETY: our own pipe read end, owned from here to EOF.
        let mut reader = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
        let mut output = Vec::new();
        reader.read_to_end(&mut output).expect("read inner output");
        let mut status: libc::c_int = 0;
        // SAFETY: waiting for our own forked child.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "reap the noexec probe runner");
        let text = String::from_utf8_lossy(&output);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "inner exec-map cell passed under noexec TMPDIR (runner status {status}): {text}"
        );
        assert!(
            text.contains("test result: ok. 1 passed; 0 failed"),
            "the inner positive ran (not a zero-match pass): {text}"
        );
    }

    /// Child side of the noexec probe runner: a private mount namespace
    /// with a noexec tmpfs over `mountpoint`, then re-exec with the
    /// prebuilt argv/envp. Async-signal-safe only: no allocation, no
    /// locks, `_exit` on every path. Call only in the post-fork child.
    fn noexec_probe_child(
        mountpoint: &std::ffi::CString,
        write_fd: libc::c_int,
        argv: &[*const libc::c_char],
        envp: &[*const libc::c_char],
    ) -> ! {
        unsafe {
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                libc::_exit(70);
            }
            // Private first: without this the tmpfs mount below would
            // propagate to the host through the shared mount tree.
            if libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                libc::_exit(70);
            }
            if libc::mount(
                c"tmpfs".as_ptr(),
                mountpoint.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOEXEC,
                std::ptr::null(),
            ) != 0
            {
                libc::_exit(70);
            }
            if libc::dup2(write_fd, libc::STDOUT_FILENO) < 0
                || libc::dup2(write_fd, libc::STDERR_FILENO) < 0
            {
                libc::_exit(70);
            }
            libc::execve(argv[0], argv.as_ptr(), envp.as_ptr());
            libc::_exit(70);
        }
    }

    /// Inner driver of `probe_dir_fallback_prints_no_notice_by_default`:
    /// creates one probe dir and proves it usable. Re-exec-only
    /// meaningful under a TMPDIR that forces the fallback; harmless
    /// (drop removes the dir) as an ordinary passing cell.
    #[test]
    fn probe_dir_create_smoke() {
        let dir = ProbeDir::create("p11scope-identity-probe").expect("probe dir");
        assert!(dir.path().is_dir(), "probe dir exists");
    }

    /// CLI-1 suppresses informational stderr notes by default: a temp
    /// fallback must not print. Re-execs this binary to run exactly
    /// the smoke cell with TMPDIR pointed at a missing dir (creation
    /// there fails, so `/var/tmp` is tried), and asserts the inner
    /// positive ran (exit 0 plus `1 passed`, never a zero-match pass)
    /// with no fallback notice on either stream.
    #[test]
    fn probe_dir_fallback_prints_no_notice_by_default() {
        let scratch = tempfile::tempdir().expect("scratch");
        let missing = scratch.path().join("missing-temp-root");
        let exe = std::env::current_exe().expect("own test binary");
        let output = std::process::Command::new(exe)
            .arg("--exact")
            .arg("inspect_system::tests::probe_dir_create_smoke")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("TMPDIR", &missing)
            .output()
            .expect("re-exec the smoke cell");
        assert!(output.status.success(), "inner exit: {}", output.status);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.contains("test result: ok. 1 passed; 0 failed"),
            "inner positive missing: {stdout}"
        );
        assert!(
            !stdout.contains("fell back") && !stderr.contains("fell back"),
            "fallback notice printed: {stdout}{stderr}"
        );
    }

    /// Fresh probe dirs are unique per call.
    #[test]
    fn probe_dir_names_are_unique() {
        let first = ProbeDir::create("p11scope-identity-probe").expect("first probe dir");
        let second = ProbeDir::create("p11scope-identity-probe").expect("second probe dir");
        assert_ne!(first.path, second.path, "probe dir names collided");
        assert!(
            first.path().file_name().is_some_and(|name| name
                .to_string_lossy()
                .starts_with("p11scope-identity-probe-")),
            "probe dir name lost its prefix: {}",
            first.path().display()
        );
        assert!(
            ProbeDir::create("../escape").is_err() && ProbeDir::create("").is_err(),
            "a hostile prefix must fail closed"
        );
    }

    /// D3d: sanitization — raw deny/probe detail never reaches labels;
    /// verifier EACCES stays `load_failed`, never permission.
    #[test]
    fn d3d_selection_reasons_are_finite_and_sanitized() {
        use crate::attach::identity_iter::KernelDeny;
        // NoBtf carries a path-bearing detail; the label drops it.
        let deny =
            KernelDeny::NoBtf("/sys/kernel/btf/vmlinux: Permission denied (os error 13)".into());
        assert_eq!(
            IdentityUnavailable::from_kernel_deny(deny).label(),
            "no_btf"
        );
        for (deny, label) in [
            (KernelDeny::FixMissing, "kernel_fix_missing"),
            (KernelDeny::NoTaskIterPidfd, "no_task_iter_pidfd"),
        ] {
            assert_eq!(IdentityUnavailable::from_kernel_deny(deny).label(), label);
        }
        // Every label is finite: lowercase, digits, underscores only.
        for reason in [
            IdentityUnavailable::NoBtf,
            IdentityUnavailable::KernelFixMissing,
            IdentityUnavailable::NoTaskIterPidfd,
            IdentityUnavailable::NumberingMismatch,
            IdentityUnavailable::NumberingUnknown,
            IdentityUnavailable::PermissionDenied,
            IdentityUnavailable::LoadFailed,
            IdentityUnavailable::ProbeFailed,
            IdentityUnavailable::FdHeadroom,
        ] {
            let label = reason.label();
            assert!(
                label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{label}"
            );
            assert!(!label.contains('/'), "{label}");
            assert!(
                !label
                    .bytes()
                    .any(|b| b.is_ascii_digit() && label.len() > 20),
                "{label}"
            );
        }
        // Verifier rejection with EACCES is load, not permission.
        let verifier = crate::attach::identity_iter::LoadError::Program(
            aya::programs::ProgramError::LoadError {
                io_error: std::io::Error::from_raw_os_error(libc::EACCES),
                verifier_log: aya_obj::VerifierLog::new("rejected: unbounded\n".to_string()),
            },
        );
        assert!(!super::load_error_is_permission(&verifier));
        assert_eq!(
            super::map_live_load_error(verifier),
            IdentityUnavailable::LoadFailed
        );
        // A bare EPERM without a verifier log is permission.
        let denied = crate::attach::identity_iter::LoadError::Program(
            aya::programs::ProgramError::LoadError {
                io_error: std::io::Error::from_raw_os_error(libc::EPERM),
                verifier_log: aya_obj::VerifierLog::new(String::new()),
            },
        );
        assert!(super::load_error_is_permission(&denied));
        assert_eq!(
            super::map_live_load_error(denied),
            IdentityUnavailable::PermissionDenied
        );
    }

    #[test]
    fn capture_watched_all_excluded_pass_keeps_later_auto_kernel_eligible() {
        assert_capture_exclusion_selection(false);
    }

    #[test]
    fn capture_watched_mixed_setup_failure_keeps_auto_failure_sticky() {
        assert_capture_exclusion_selection(true);
    }

    fn assert_capture_exclusion_selection(missing_anchor: bool) {
        use crate::discovery::kernel_identity::{
            AnchorPass, ExaminedCustody, KernelAnchorExclusions,
        };
        use crate::discovery::sweep_attribution::{ReservationOwner, SegmentPolicy};
        use std::collections::BTreeMap;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watched.so");
        std::fs::write(&path, [0u8; 4096]).unwrap();
        let pins =
            crate::discovery::identity::test_fixture::real_scan_pin(&path, None, 1, "watched");
        let id = pins.pinned().next().unwrap().id;
        let target = pins.retain_inventory_target(id).unwrap();
        for excluded in [false, true] {
            let (shared, _) = shared_with(
                IdentityBackendSelection::Auto,
                ScriptedIdentityChecks::must_not_load(),
            );
            let custody = ExaminedCustody::new(
                ReservationOwner::for_examined(SegmentPolicy::from_headroom(16, 0, 0), 0),
                BTreeMap::new(),
            );
            let exclusions = KernelAnchorExclusions::from_targets([&target]);
            let mut admitted: Vec<_> = excluded
                .then_some((target.object_key(), id))
                .into_iter()
                .collect();
            if missing_anchor {
                let mut absent = target.object_key();
                absent.inode += 1;
                admitted.push((absent, crate::discovery::identity::PinnedObjectId(u32::MAX)));
            }
            let pass = AnchorPass::prepare_excluding(&pins, admitted, custody, &exclusions);
            assert_eq!(pass.only_capture_excluded(), excluded && !missing_anchor);
            super::note_anchor_setup_fallback(
                &mut shared.lock().unwrap(),
                pass.only_capture_excluded(),
            );
            assert_eq!(
                matches!(
                    decide_pass_attempt(&shared, true),
                    super::PassAttempt::Kernel { .. }
                ),
                excluded && !missing_anchor,
                "intentional exclusion disabled future unrelated kernel proof"
            );
            assert_eq!(
                shared.lock().unwrap().summary().fallback.as_deref(),
                Some("anchor_not_installed")
            );
        }
    }

    /// D3d: runtime fallback rendering — label alone, except the fixed
    /// target-run-limit detail.
    #[test]
    fn d3d_runtime_fallback_labels_are_finite() {
        use crate::discovery::kernel_identity::KernelFallbackReason;
        assert_eq!(
            runtime_fallback_label(KernelFallbackReason::TargetLimit),
            "fd_headroom: target_run_limit"
        );
        for (reason, label) in [
            (KernelFallbackReason::BelowThreshold, "below_threshold"),
            (KernelFallbackReason::FdHeadroom, "fd_headroom"),
            (KernelFallbackReason::StreamInvalid, "stream_invalid"),
            (KernelFallbackReason::Deadline, "deadline"),
        ] {
            assert_eq!(runtime_fallback_label(reason), label);
        }
    }

    /// D3d: live numbering mapping — agree/mismatch/unknown are typed.
    #[test]
    fn d3d_live_numbering_maps_agree_mismatch_unknown() {
        let live = LiveIdentityChecks;
        // The live answer depends on this host; it must be one typed
        // variant and must agree with PidNumbering::agrees.
        let numbering = live.numbering();
        let agrees = crate::pidns::numbering().agrees();
        assert_eq!(numbering == IdentityNumbering::Agree, agrees);
        // Injected mismatch/unknown map distinctly.
        let _ = (IdentityNumbering::Mismatch, IdentityNumbering::Unknown);
    }

    /// D3d: auto's injected-threshold contract — a test threshold
    /// rides to the kernel attempt unchanged (production uses 2,400;
    /// forced kernel uses none).
    #[test]
    fn d3d_auto_injected_threshold_rides_to_kernel_attempt() {
        for threshold in [Some(1), Some(7), None] {
            let shared =
                std::sync::Arc::new(std::sync::Mutex::new(IdentityRunShared::with_threshold(
                    IdentityBackendSelection::Auto,
                    threshold,
                    Box::new(ScriptedIdentityChecks::session_fails(
                        IdentityUnavailable::ProbeFailed,
                    )),
                )));
            match decide_pass_attempt(&shared, true) {
                super::PassAttempt::Kernel { threshold: got } => {
                    assert_eq!(got, threshold, "injected threshold rides along")
                }
                super::PassAttempt::Userspace => panic!("cheap pass must attempt kernel"),
            }
        }
    }

    /// D3d fix (I2/I3): the eligibility probe (BTF+load+probe) runs once
    /// per capture, never once per pass: three production takes attempt a
    /// single session creation for both auto and forced kernel, so the one
    /// capture-owned session (with its sticky status and counters) serves
    /// every pass.
    #[test]
    fn d3d_capture_session_created_once_per_capture() {
        for selection in [
            IdentityBackendSelection::Auto,
            IdentityBackendSelection::Kernel,
        ] {
            let (shared, ptr) = shared_with(
                selection,
                ScriptedIdentityChecks::session_fails(IdentityUnavailable::ProbeFailed),
            );
            for take in 0..3 {
                assert!(
                    take_session_for_pass(&shared).is_none(),
                    "{selection:?} take {take} fails its session creation"
                );
            }
            let checks = unsafe { &*ptr };
            assert_eq!(
                checks.session_calls.load(Ordering::SeqCst),
                1,
                "{selection:?} probes once per capture, not once per pass"
            );
        }
    }

    /// D3d fix (I2/I3): a failed session creation is sticky with its first
    /// finite reason: later passes attempt nothing further, the load is
    /// recorded, and auto never consults cheap checks again.
    #[test]
    fn d3d_session_creation_failure_is_sticky_with_first_reason() {
        for selection in [
            IdentityBackendSelection::Auto,
            IdentityBackendSelection::Kernel,
        ] {
            let (shared, ptr) = shared_with(
                selection,
                ScriptedIdentityChecks::session_fails(IdentityUnavailable::LoadFailed),
            );
            assert!(take_session_for_pass(&shared).is_none());
            assert!(take_session_for_pass(&shared).is_none());
            let checks = unsafe { &*ptr };
            assert_eq!(checks.session_calls.load(Ordering::SeqCst), 1);
            {
                let shared = shared.lock().unwrap();
                assert_eq!(shared.summary().fallback.as_deref(), Some("load_failed"));
                assert!(shared.loaded());
            }
            if selection == IdentityBackendSelection::Auto {
                let numbering = checks.numbering_calls.load(Ordering::SeqCst);
                let btf = checks.btf_calls.load(Ordering::SeqCst);
                assert!(matches!(
                    decide_pass_attempt(&shared, true),
                    super::PassAttempt::Userspace
                ));
                assert_eq!(checks.numbering_calls.load(Ordering::SeqCst), numbering);
                assert_eq!(checks.btf_calls.load(Ordering::SeqCst), btf);
            }
        }
    }

    /// The witness window advances by the queries a pass actually
    /// spends (a full 8-query budget moves the window by 8, not 1; a
    /// pass with no witness leaves it), wrapping at `u64::MAX`, and
    /// records the pass's refused count as the next denominator
    /// (`None` keeps the previous one).
    #[test]
    fn witness_rotation_advances_by_queries_spent() {
        let (shared, _) = shared_with(
            IdentityBackendSelection::Auto,
            ScriptedIdentityChecks::session_fails(IdentityUnavailable::LoadFailed),
        );
        let mut guard = shared.lock().unwrap();
        assert_eq!(guard.witness_window(), (0, 0));
        guard.advance_witness_rotation(8, Some(10));
        assert_eq!(guard.witness_window(), (8, 10));
        guard.advance_witness_rotation(0, None);
        assert_eq!(guard.witness_window(), (8, 10));
        guard.sweep_witness_rotation = u64::MAX;
        guard.advance_witness_rotation(1, Some(9));
        assert_eq!(guard.witness_window(), (0, 9));
    }

    /// A completed sweep that counts zero refused candidates leaves the
    /// denominator alone, like a pass with no witness run: it spends no
    /// queries, so the next pass continues past the spent queries
    /// instead of rebootstrapping to the first window and starving the
    /// tail whenever zero-count passes interleave with counted ones.
    #[test]
    fn witness_rotation_keeps_denominator_on_zero_count_pass() {
        let (shared, _) = shared_with(
            IdentityBackendSelection::Auto,
            ScriptedIdentityChecks::session_fails(IdentityUnavailable::LoadFailed),
        );
        let mut guard = shared.lock().unwrap();
        guard.advance_witness_rotation(8, Some(10));
        assert_eq!(guard.witness_window(), (8, 10));
        guard.advance_witness_rotation(0, Some(0));
        assert_eq!(guard.witness_window(), (8, 10));
    }

    /// A pass with no witness run (sticky setup failure: no takeout,
    /// plain userspace path) leaves the rotation alone, so the next
    /// kernel pass restarts from the same offset instead of skipping
    /// a candidate it never proved.
    #[test]
    fn witness_rotation_stays_when_no_witness_runs() {
        let (shared, _) = shared_with(
            IdentityBackendSelection::Auto,
            ScriptedIdentityChecks::session_fails(IdentityUnavailable::LoadFailed),
        );
        {
            let mut guard = shared.lock().unwrap();
            guard.sweep_witness_rotation = 5;
        }
        assert!(take_session_for_pass(&shared).is_none());
        assert!(take_session_for_pass(&shared).is_none());
        let mut collection = empty_collection();
        let bound = super::bind_collection(&mut collection);
        let policy = crate::discovery::sweep_attribution::SegmentPolicy::from_headroom(16, 1, 1);
        let reservations = crate::discovery::sweep_attribution::ReservationOwner::new(policy);
        let custody = crate::discovery::kernel_identity::ExaminedCustody::new(
            reservations.clone(),
            std::collections::BTreeMap::new(),
        );
        let out = super::attribute_pass_with_kernel(
            &shared,
            None,
            &mut collection,
            &bound,
            custody,
            policy,
            &reservations,
            1,
            crate::discovery::sweep_attribution::ProofPools {
                batch: None,
                immediate: None,
            },
            None,
        );
        assert!(out.is_none());
        assert_eq!(shared.lock().unwrap().sweep_witness_rotation, 5);
    }

    /// D3d: first-use session setup under scarce FDs refuses before
    /// opening anything: no session attempt, nothing loaded, the finite
    /// `fd_headroom` reason recorded, sticky across later passes.
    #[test]
    fn d3d_first_use_low_fd_refuses_before_session_proof() {
        use crate::attach::identity_iter::SESSION_SETUP_PEAK_FDS;
        for headroom in [
            Ok(SESSION_SETUP_PEAK_FDS - 1),
            Ok(0),
            Err("identity file-descriptor census is unavailable".to_string()),
        ] {
            for selection in [
                IdentityBackendSelection::Auto,
                IdentityBackendSelection::Kernel,
            ] {
                let mut checks =
                    ScriptedIdentityChecks::session_fails(IdentityUnavailable::ProbeFailed);
                checks.headroom = headroom.clone();
                let (shared, ptr) = shared_with(selection, checks);
                assert!(
                    take_session_for_pass(&shared).is_none(),
                    "{selection:?} low-FD first use must refuse: {headroom:?}"
                );
                // A second pass retries nothing.
                assert!(take_session_for_pass(&shared).is_none());
                let checks = unsafe { &*ptr };
                assert_eq!(
                    checks.session_calls.load(Ordering::SeqCst),
                    0,
                    "{selection:?} refused setup must not reach the session attempt"
                );
                assert_eq!(
                    checks.headroom_calls.load(Ordering::SeqCst),
                    1,
                    "{selection:?} reserves once per capture, not once per pass"
                );
                let shared = shared.lock().unwrap();
                assert_eq!(shared.summary().fallback.as_deref(), Some("fd_headroom"));
                assert!(!shared.loaded(), "refused setup loads nothing");
            }
        }
    }

    /// D3d: the setup reservation admits exactly the peak and above, and
    /// refuses scarcity plus census failure.
    #[test]
    fn d3d_session_setup_reservation_is_exact_at_the_peak() {
        use crate::attach::identity_iter::SESSION_SETUP_PEAK_FDS;
        assert!(!super::session_setup_admitted(Ok(
            SESSION_SETUP_PEAK_FDS - 1
        )));
        assert!(!super::session_setup_admitted(Ok(0)));
        assert!(!super::session_setup_admitted(Err(
            "census failed".to_string()
        )));
        assert!(super::session_setup_admitted(Ok(SESSION_SETUP_PEAK_FDS)));
        assert!(super::session_setup_admitted(Ok(usize::MAX)));
    }

    /// D3d: the live setup headroom is the strict census headroom (a
    /// measured value, never the scripted ample default).
    #[test]
    fn d3d_live_setup_headroom_reports_the_strict_census() {
        let live = LiveIdentityChecks.setup_headroom();
        let headroom = live.expect("a healthy host censuses its FDs");
        assert!(
            headroom < usize::MAX,
            "live headroom is measured, not scripted-ample"
        );
    }

    /// D3d fix (I1): a within-batch fallback recorded in the session ledger
    /// (unvisited, anchor-not-installed, conflicting-duplicate) is disclosed
    /// in the capture fallback slot with the kernel backend kept, even when
    /// no batch fell back.
    #[test]
    fn d3d_within_batch_fallback_disclosed_with_kernel_backend() {
        use crate::discovery::kernel_identity::KernelFallbackReason;
        let (shared, _) = shared_with(
            IdentityBackendSelection::Auto,
            ScriptedIdentityChecks::must_not_load(),
        );
        for reason in [
            KernelFallbackReason::Unvisited,
            KernelFallbackReason::AnchorNotInstalled,
            KernelFallbackReason::ConflictingDuplicate,
        ] {
            let mut shared = shared.lock().unwrap();
            shared.backend = super::IdentityBackend::Kernel;
            shared.fallback = None;
            apply_kernel_fallback(&mut shared, None, Some(reason));
            assert_eq!(shared.summary().backend, super::IdentityBackend::Kernel);
            assert_eq!(
                shared.summary().fallback.as_deref(),
                Some(reason.label()),
                "ledger {reason:?} reaches the disclosure slot"
            );
        }
    }

    /// D3d fix (I1): the ledger's first reason is chronologically first, so
    /// it wins over a later batch-level reason; an existing capture reason
    /// still wins over both.
    #[test]
    fn d3d_ledger_first_reason_wins_over_later_batch_reason() {
        use crate::discovery::kernel_identity::KernelFallbackReason;
        let (shared, _) = shared_with(
            IdentityBackendSelection::Auto,
            ScriptedIdentityChecks::must_not_load(),
        );
        let mut shared = shared.lock().unwrap();
        shared.backend = super::IdentityBackend::Kernel;
        apply_kernel_fallback(
            &mut shared,
            Some(KernelFallbackReason::Deadline),
            Some(KernelFallbackReason::Unvisited),
        );
        assert_eq!(shared.summary().fallback.as_deref(), Some("unvisited"));
        apply_kernel_fallback(
            &mut shared,
            Some(KernelFallbackReason::StreamInvalid),
            Some(KernelFallbackReason::ConflictingDuplicate),
        );
        assert_eq!(shared.summary().fallback.as_deref(), Some("unvisited"));
    }

    #[test]
    fn d3b_failed_strict_census_never_reenumerates_or_restores_batch() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        for refusal in ["timeout", "entry cap", "stopped budget"] {
            let owner = ReservationOwner::for_examined(SegmentPolicy::from_headroom(16, 0, 0), 2);
            let mut custody = ExaminedCustody::new(owner.clone(), BTreeMap::new());
            let file = tempfile::tempfile().unwrap();
            let fd = file.as_raw_fd();
            let meta = file.metadata().unwrap();
            let key = ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: libc::major(meta.dev()) as u64,
                    minor: libc::minor(meta.dev()) as u64,
                },
                inode: meta.ino(),
            };
            let scan = custody.begin_scan();
            assert!(custody.offer_for_test(
                scan,
                ExaminedObject {
                    key,
                    identity: crate::discovery::identity::FileIdentity {
                        dev: meta.dev(),
                        ino: meta.ino(),
                    },
                    key_is_identity: false,
                },
                file
            ));
            let (policy, calls) =
                crate::discovery::sweep_attribution::count_censuses_for_test(|| {
                    identity_confirmation_policy(&mut custody, Err(format!("injected {refusal}")))
                        .unwrap()
                });
            assert_eq!(calls, 0, "strict refusal retried a census after {refusal}");
            assert_eq!(
                (policy.headroom, policy.workers, policy.retained),
                (3, 0, 0)
            );
            assert!(custody.failed());
            assert_eq!(owner.examined_for_test().0, 0);
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstat observes a possibly closed descriptor; matching
            // metadata only guards against FD-number reuse by other tests.
            let still_held = unsafe { libc::fstat(fd, stat.as_mut_ptr()) } == 0 && {
                // SAFETY: successful fstat initialized stat.
                let stat = unsafe { stat.assume_init() };
                stat.st_dev == meta.dev() && stat.st_ino == meta.ino()
            };
            assert!(!still_held, "strict refusal leaked its examined File");
            assert_eq!(owner.examined_capacity(), 0);
            assert!(owner.examined().is_err());
        }
    }

    use super::*;
    use crate::discovery::scan::{ScannedEntry, ScannedInterface, ScannedTable};

    mod application {
        use super::*;
        use crate::fixture_guard::DieWithParent as _;
        use crate::inspect_identity::{
            InspectApplicationResult, InspectIdentityUnknown, InspectImageReader,
            ProcessViewImageReader, application_from_confirmed_member, application_json,
        };
        use std::io::{BufRead, Write};
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        struct OwnedExec(Child);
        impl OwnedExec {
            fn new() -> Self {
                let mut child = Command::new("/bin/sh")
                    .args(["-c", "printf 'ready\\n'; read trigger; exec /bin/sleep 30"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .die_with_parent()
                    .spawn()
                    .unwrap();
                let mut ready = String::new();
                std::io::BufReader::new(child.stdout.take().unwrap())
                    .read_line(&mut ready)
                    .unwrap();
                assert_eq!(ready, "ready\n");
                Self(child)
            }
            fn exec(&mut self, before: &ExeIdentity) {
                self.0.stdin.as_mut().unwrap().write_all(b"go\n").unwrap();
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    if read_exe_identity(self.0.id()).is_some_and(|exe| exe != *before) {
                        break;
                    }
                    assert!(Instant::now() < deadline, "owned child did not exec");
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        impl Drop for OwnedExec {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        struct OsReader<'a> {
            os: ProcessViewImageReader<'a>,
            unreadable: bool,
        }
        impl InspectImageReader for OsReader<'_> {
            fn exe_identity(&mut self) -> Option<ExeIdentity> {
                if self.unreadable {
                    None
                } else {
                    self.os.exe_identity()
                }
            }
            fn start_time(&mut self) -> Option<u64> {
                self.os.start_time()
            }
            fn still_same(&mut self) -> bool {
                self.os.still_same()
            }
            fn validate_generation(&mut self) -> Result<(), InspectIdentityUnknown> {
                self.os.validate_generation()
            }
        }

        fn member(pid: u32) -> MemberResult {
            MemberResult {
                mapping_scan_completed: true,
                hints_examined: true,
                pid,
                view: ProcessViewId(0),
                status: MemberStatus::Scanned,
                generation: None,
                complete_scan: None,
                application: InspectApplicationResult::Unknown(InspectIdentityUnknown::NotExamined),
                modules: Vec::new(),
                examined: Vec::new(),
                pins: PinnedObjects::empty(),
                gaps: Vec::new(),
                scan_ms: 0,
            }
        }

        fn catalog_for(member: MemberResult) -> Catalog {
            let mut catalog = super::catalog_with(vec![super::object(
                "/opt/vendor/libprovider.so",
                42,
                None,
                member.pid,
                AdmissionRecord::Unresolved {
                    reasons: vec!["fixture".into()],
                },
            )]);
            let pid = member.pid;
            catalog.objects[0].mappings = vec![(pid, Some(member.view))];
            catalog.objects[0].observations[0].pid = pid;
            catalog.processes = vec![ProcessRecord {
                pid,
                status: member.status,
                objects: vec![0],
                generation: member.generation,
                complete_scan: member.complete_scan,
                application: member.application,
                hints_examined: member.hints_examined,
            }];
            catalog.skipped = member.gaps;
            catalog
        }

        fn os_diagnosis(
            exec_before_scan: bool,
            exec_during_pin: bool,
            unreadable: bool,
        ) -> (serde_json::Value, String, String) {
            let mut child = OwnedExec::new();
            let pid = child.0.id();
            let pin = crate::process::PidPin::open(pid).unwrap();
            assert!(pin.pidfd().is_ok(), "live pidfd control is required");
            let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
            let before = read_exe_identity(pid).unwrap();
            let birth = crate::process::process_start_time(pid).unwrap();
            let mut reader = OsReader {
                os: ProcessViewImageReader::new(&view),
                unreadable: false,
            };
            let member = scan_member_application_with(&mut reader, |reader| {
                if exec_before_scan {
                    child.exec(&before);
                }
                assert!(view.still_the_same());
                // The production closure scans mappings, then pins providers.
                let scanned = member(pid);
                if exec_during_pin {
                    child.exec(&before);
                }
                reader.unreadable = unreadable;
                assert!(view.still_the_same());
                scanned
            });
            assert_eq!(crate::process::process_start_time(pid).unwrap(), birth);
            assert!(view.still_the_same(), "exec kept the original pin live");
            let catalog = catalog_for(member);
            (
                render_json(&catalog),
                render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose),
                before.path.unwrap(),
            )
        }

        fn assert_unknown(json: &serde_json::Value, text: &str, initial_path: &str, reason: &str) {
            let process = &json["processes"][0];
            assert!(process["application"].is_null());
            assert_eq!(process["application_status"], reason);
            assert!(text.contains(&format!("Unknown executable (PID {})", process["pid"])));
            assert!(!text.contains(initial_path));
            assert_eq!(json["objects"][0]["path"], "/opt/vendor/libprovider.so");
            assert!(text.contains("libprovider.so"));
        }

        #[test]
        fn system_inspect_exec_before_scan_with_live_pin_is_unknown() {
            let (json, text, initial) = os_diagnosis(true, false, false);
            assert_unknown(&json, &text, &initial, "changed");
        }
        #[test]
        fn system_inspect_exec_during_pin_is_unknown() {
            let (json, text, initial) = os_diagnosis(false, true, false);
            assert_unknown(&json, &text, &initial, "changed");
        }
        #[test]
        fn system_inspect_final_exe_unreadable_is_unknown() {
            let (json, text, initial) = os_diagnosis(false, false, true);
            assert_unknown(&json, &text, &initial, "unavailable");
        }
        #[test]
        fn system_inspect_unchanged_executable_is_named_in_text_and_json() {
            let (json, text, initial) = os_diagnosis(false, false, false);
            assert_eq!(json["processes"][0]["application_status"], "observed");
            assert_eq!(json["processes"][0]["application"]["path"], initial);
            assert!(text.contains(&initial));
            let basename = std::path::Path::new(&initial)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();
            assert!(text.contains(&format!("{basename} (PID ")));
            assert!(text.contains("activity was not captured by inspect"));
            assert!(json["objects"][0].get("calls").is_none());
        }
        #[test]
        fn system_inspect_os_scan_adapter_retains_the_owned_executable() {
            let pid = std::process::id();
            let result = scan_member(
                pid,
                ProcessViewId(0),
                &[],
                &HookRegistry::builtin(),
                &mut CaptureWorkBudget::default(),
                &mut DiscoveryNoiseAggregator::default(),
            );
            assert!(result.status.inventoried());
            let json = application_json(&result.application);
            assert_eq!(json["application_status"], "observed");
            assert_eq!(
                json["application"]["path"],
                read_exe_identity(pid).unwrap().path.unwrap()
            );
        }
        #[test]
        fn system_inspect_memory_unavailable_can_retain_a_valid_receipt() {
            let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
            let result =
                scan_member_application_with(&mut ProcessViewImageReader::new(&view), |_| {
                    let mut row = member(view.pid());
                    row.mapping_scan_completed = ScanOutcome::Unavailable {
                        reason: "ptrace",
                        modules: Vec::new(),
                        skipped: Vec::new(),
                    }
                    .mapping_scan_completed();
                    row.status = MemberStatus::MemoryUnavailable { reason: "ptrace" };
                    row
                });
            assert_eq!(
                application_json(&result.application)["application_status"],
                "observed"
            );
        }

        #[test]
        fn system_inspect_final_mapping_failure_with_stable_exe_withholds_identity() {
            let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
            for read_failure in [false, true] {
                let result = scan_member_application_with(
                    &mut ProcessViewImageReader::new(&view),
                    |reader| {
                        let mut budget = CaptureWorkBudget::default();
                        let outcome = crate::discovery::scan::final_maps_refusal_for_test(
                            reader.view(),
                            &mut budget,
                            read_failure,
                        );
                        assert!(outcome.modules().is_empty());
                        let (pins, skips) =
                            pin_scanned_view_objects(reader.view(), outcome.modules(), &mut budget)
                                .unwrap();
                        assert!(skips.is_empty());
                        assert!(!retirement_scan_allows_absence(
                            &[],
                            &outcome,
                            &skips,
                            (None, (0, 0)),
                            (budget.stopped_reason(), budget.refusal_counts())
                        ));
                        let mut row = member(view.pid());
                        row.mapping_scan_completed = outcome.mapping_scan_completed();
                        row.modules = outcome.modules().to_vec();
                        row.gaps = outcome
                            .skipped()
                            .iter()
                            .cloned()
                            .map(|skip| PidGap::member(view.pid(), skip))
                            .collect();
                        row.status = match outcome {
                            ScanOutcome::Scanned { .. } => MemberStatus::Scanned,
                            ScanOutcome::Unavailable { reason, .. } => {
                                MemberStatus::MemoryUnavailable { reason }
                            }
                        };
                        row.pins = pins;
                        row
                    },
                );
                assert!(view.still_the_same());
                assert!(result.complete_scan.is_none());
                let mut catalog = catalog_for(result);
                catalog.objects.clear();
                catalog.processes[0].objects.clear();
                let json = render_json(&catalog);
                let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
                assert_eq!(json["processes"][0]["application_status"], "not_examined");
                assert!(json["processes"][0]["application"].is_null());
                assert!(text.contains(&format!("Unknown executable (PID {})", view.pid())));
                assert!(text.contains("final mapping validation unavailable"));
                assert!(
                    catalog
                        .skipped
                        .iter()
                        .any(|gap| gap.reason.contains("final mapping validation unavailable"))
                );
            }
        }
        #[test]
        fn retirement_scan_allows_absence_for_new_no_table_reason() {
            let allows = |reason: String| {
                let outcome = ScanOutcome::Scanned {
                    modules: Vec::new(),
                    skipped: vec![Skipped {
                        subject: "/opt/p11.so".into(),
                        reason,
                    }],
                    scan_ms: 0,
                };
                retirement_scan_allows_absence(&[], &outcome, &[], (None, (0, 0)), (None, (0, 0)))
            };
            assert!(
                allows(crate::discovery::scan::no_table_found_reason(
                    "/opt/p11.so",
                    false
                )),
                "the scan-side reason and the matcher must agree"
            );
            assert!(
                !allows(
                    "no function table was found in its file-backed data; a table built at run \
                     time in .bss or on the heap is outside the memory scan's reach"
                        .into()
                ),
                "the bare pre-suffix reason must stay a real gap"
            );
        }
        #[test]
        fn system_inspect_failed_or_unexamined_rows_never_gain_names() {
            let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
            for status in [
                MemberStatus::Exited,
                MemberStatus::Unreadable {
                    reason: "denied".into(),
                },
                MemberStatus::NotSelected { loss: None },
            ] {
                let result =
                    scan_member_application_with(&mut ProcessViewImageReader::new(&view), |_| {
                        let mut row = member(view.pid());
                        row.status = status;
                        row
                    });
                assert_eq!(
                    application_json(&result.application)["application_status"],
                    "not_examined"
                );
            }
            let result =
                scan_member_application_with(&mut ProcessViewImageReader::new(&view), |_| {
                    let mut row = member(view.pid());
                    let skipped = Skipped {
                        subject: "capture discovery".into(),
                        reason:
                            "memory scan refused: initial mapping validation unavailable: denied"
                                .into(),
                    };
                    row.mapping_scan_completed = ScanOutcome::Scanned {
                        modules: Vec::new(),
                        skipped: vec![skipped.clone()],
                        scan_ms: 0,
                    }
                    .mapping_scan_completed();
                    row.gaps.push(PidGap::member(view.pid(), skipped));
                    row
                });
            assert_eq!(
                application_json(&result.application)["application_status"],
                "not_examined"
            );
        }
        #[test]
        fn system_inspect_confirmed_maps_match_requires_a_retained_path() {
            let member = SweptMember {
                pid: 7,
                start_time: 11,
                exe: ExeIdentity {
                    dev: 1,
                    ino: 2,
                    mtime_secs: 3,
                    mtime_nanos: 4,
                    path: None,
                },
                objects: Vec::new(),
                unexamined: 0,
            };
            assert_eq!(
                application_json(&application_from_confirmed_member(&member))["application_status"],
                "unavailable"
            );
        }

        #[test]
        fn system_inspect_colliding_basenames_and_provider_paths_stay_separate() {
            let confirmed = |path: &str, ino: u64| {
                application_from_confirmed_member(&SweptMember {
                    pid: 7,
                    start_time: 11,
                    exe: ExeIdentity {
                        dev: 1,
                        ino,
                        mtime_secs: 3,
                        mtime_nanos: 4,
                        path: Some(path.into()),
                    },
                    objects: Vec::new(),
                    unexamined: 0,
                })
            };
            let mut catalog = super::catalog_with(vec![
                super::object(
                    "/opt/libprovider.so",
                    42,
                    None,
                    100,
                    AdmissionRecord::Unresolved {
                        reasons: Vec::new(),
                    },
                ),
                super::object(
                    "/opt/libprovider.so",
                    43,
                    None,
                    200,
                    AdmissionRecord::Unresolved {
                        reasons: Vec::new(),
                    },
                ),
            ]);
            catalog.processes[0].application = confirmed("/opt/a/app", 2);
            catalog.processes[1].application = confirmed("/opt/b/app", 3);
            let json = render_json(&catalog);
            let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
            assert_eq!(json["processes"][0]["application"]["path"], "/opt/a/app");
            assert_eq!(json["processes"][1]["application"]["path"], "/opt/b/app");
            assert_eq!(json["objects"].as_array().unwrap().len(), 2);
            assert_ne!(json["objects"][0]["inode"], json["objects"][1]["inode"]);
            assert!(text.contains("app (PID 100)"));
            assert!(text.contains("app (PID 200)"));
            assert!(text.contains("/opt/a/app"));
            assert!(text.contains("/opt/b/app"));
        }
    }
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
            extension_impossible: false,
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
        let partial = objects
            .iter()
            .filter(|object| matches!(object.admission, AdmissionRecord::Partial { .. }))
            .count();
        let refused = objects
            .iter()
            .filter(|object| matches!(object.admission, AdmissionRecord::Refused { .. }))
            .count();
        let unresolved = objects.len() - admitted - partial - refused;
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
                    application: InspectApplicationResult::Unknown(
                        InspectIdentityUnknown::NotExamined,
                    ),
                    complete_scan: None,
                    hints_examined: true,
                    pid: 100,
                    status: MemberStatus::Scanned,
                    objects: vec![0],
                    generation: None,
                },
                ProcessRecord {
                    application: InspectApplicationResult::Unknown(
                        InspectIdentityUnknown::NotExamined,
                    ),
                    complete_scan: None,
                    hints_examined: true,
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
                partial,
                refused,
                unresolved,
            },
            skipped: Vec::new(),
            notes: Vec::new(),
            excluded: Vec::new(),
            exclude_inputs: Vec::new(),
            explanation: None,
            stage_timings: StageTimings::new(),
        }
    }

    #[test]
    fn system_catalog_reports_excluded_files_and_unmatched_inputs() {
        let mut catalog = catalog_with(Vec::new());
        catalog.excluded = vec![crate::discovery::scan::ExcludedRecord {
            pid: 100,
            path: "/opt/libp11-kit.so.0.4.8".into(),
            dev: 42,
            ino: 1001,
            via: PathBuf::from("libp11-kit.so.0"),
        }];
        catalog.exclude_inputs = vec![
            PathBuf::from("libp11-kit.so.0"),
            PathBuf::from("libnothing.so"),
        ];
        let text = render_text(&catalog);
        assert!(text.contains("Excluded by you (1 files):"), "{text}");
        assert!(
            text.contains(
                "/opt/libp11-kit.so.0.4.8: excluded by you (device 42 inode 1001, 1 process mapped it)"
            ),
            "{text}"
        );
        assert!(
            text.contains("Unmatched exclusions (1): libnothing.so"),
            "{text}"
        );
        let document = render_json(&catalog);
        assert_eq!(
            document["excluded_modules"][0]["path"],
            "/opt/libp11-kit.so.0.4.8"
        );
        assert_eq!(document["excluded_modules"][0]["processes"], 1);
        assert_eq!(document["unmatched_excludes"][0], "libnothing.so");
        // Silent when no exclusions ran: no empty sections.
        let bare = catalog_with(Vec::new());
        assert!(!render_text(&bare).contains("Excluded by you"));
        assert!(render_json(&bare).get("excluded_modules").is_none());
        assert!(render_json(&bare).get("unmatched_excludes").is_none());
    }

    mod c1b {
        use super::super::*;
        use crate::discovery::identity::test_fixture::{PATH, SHA, module, view_pin};
        use crate::discovery::identity::{FileIdentity, MappedFile};
        use crate::discovery::sweep_attribution::{
            Confirmation, ConfirmedRead, MappedIdentities, RangeProof,
        };
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
                    .map(|entry| {
                        (
                            (entry.start, entry.end),
                            RangeProof::MapFiles(vm_file(entry)),
                        )
                    })
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
                            .map(|entry| (*range, RangeProof::MapFiles(vm_file(entry))))
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
                    fs_magic: Some(0x01021994),
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
                mapping_scan_completed: true,
                application: InspectApplicationResult::Unknown(InspectIdentityUnknown::NotExamined),
                complete_scan: None,
                hints_examined: true,
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
            assemble(
                collection,
                bound,
                attributed,
                AdmissionPolicy::detailed(),
                crate::plan::AdmissionScope::Shared,
            )
        }

        fn catalog_with(mut collection: Collection, checks: &Checks) -> Catalog {
            let snapshots: HashMap<u32, Vec<MapEntry>> = collection.sweep.iter().cloned().collect();
            let bound = bind_collection(&mut collection);
            let mut probe = Probe(snapshots, HashMap::new());
            let attributed = attribute_sweep(&mut collection, &bound, &mut probe, checks);
            assemble(
                collection,
                bound,
                attributed,
                AdmissionPolicy::detailed(),
                crate::plan::AdmissionScope::Shared,
            )
        }

        /// A provider with `tables` bare heuristic tables of
        /// `entries_per_table` endpoints each, for admission-wiring twins.
        fn heuristic_provider(tables: usize, entries_per_table: usize) -> ScannedModule {
            use crate::discovery::scan::{ScannedEntry, ScannedTable};
            let mut provider = module(PROVIDER);
            provider.view = ProcessViewId(0);
            provider.tables = (0..tables)
                .map(|table| ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: (0..entries_per_table)
                        .map(|entry| ScannedEntry {
                            name: "C_Initialize",
                            object: PROVIDER,
                            object_path: PATH.into(),
                            file_offset: 0x1000 + (table * entries_per_table + entry) as u64 * 8,
                        })
                        .collect(),
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000 + table as u64 * 0x1000,
                    file_offset: Some(table as u64 * 0x1000),
                    live_return: false,
                    manifest_supported: false,
                    extension_impossible: false,
                })
                .collect();
            provider
        }

        /// Lower `provider` over the standard over-cap collection under a
        /// 32-endpoint Inventory budget, with the scope the collector
        /// derives from `hints`.
        /// Lower `provider` over the standard over-cap collection under
        /// `policy`, with the scope the collector derives from `hints`.
        fn scoped_catalog(
            provider: ScannedModule,
            policy: AdmissionPolicy,
            hints: &[PathBuf],
        ) -> Catalog {
            let mut collection = over_cap(&[]);
            collection.members[0].modules = vec![provider];
            let snapshots: HashMap<u32, Vec<MapEntry>> = collection.sweep.iter().cloned().collect();
            let bound = bind_collection(&mut collection);
            let mut probe = Probe(snapshots, HashMap::new());
            let checks = Checks {
                changed: false,
                nonunique: None,
            };
            let attributed = attribute_sweep(&mut collection, &bound, &mut probe, &checks);
            assemble(
                collection,
                bound,
                attributed,
                policy,
                collector_admission_scope(hints, false),
            )
        }

        fn inventory_catalog(provider: ScannedModule, hints: &[PathBuf]) -> Catalog {
            scoped_catalog(
                provider,
                AdmissionPolicy::Inventory(crate::capacity::InventoryBudget::new(32, 256).unwrap()),
                hints,
            )
        }

        fn catalog_admission(catalog: &Catalog) -> &AdmissionRecord {
            &catalog
                .objects
                .iter()
                .find(|object| object.path == PATH)
                .expect("the provider object")
                .admission
        }

        #[test]
        fn unaimed_inventory_capture_refuses_heuristic_module_at_the_reserve() {
            // No hints: Shared scope, so a 32 budget reserves all 32 and
            // the 32-endpoint heuristic module is refused whole.
            let catalog = inventory_catalog(heuristic_provider(1, 32), &[]);
            match catalog_admission(&catalog) {
                AdmissionRecord::Refused { class, reason, .. } => {
                    assert_eq!(*class, "heuristic");
                    assert!(reason.contains("reserved"), "{reason}");
                }
                other => panic!("the reserve must refuse the module, got {other:?}"),
            }
        }

        #[test]
        fn aimed_inventory_capture_admits_heuristic_module_first_come() {
            // One hint: Named scope, first-come with no reserve, so the
            // same 32 endpoints admit.
            let hints = [PathBuf::from(PATH)];
            let catalog = inventory_catalog(heuristic_provider(1, 32), &hints);
            match catalog_admission(&catalog) {
                AdmissionRecord::Admitted { class, endpoints } => {
                    assert_eq!(*class, "heuristic");
                    assert_eq!(*endpoints, 32);
                }
                other => panic!("an aimed module must admit first-come, got {other:?}"),
            }
        }

        #[test]
        fn inspect_aimed_system_capture_admits_heuristic_prefix_first_come() {
            // `inspect --system` lowers under the Detailed policy with the
            // same aim rule the capture engine keeps: an aimed capture
            // admits first-come with no reserve, so a 600-endpoint
            // heuristic provider admits its strongest 450-endpoint prefix
            // and discloses the spilled table. JK-22a: the unaimed capture
            // admits the reserve-capped 300-endpoint prefix with a named
            // provider-prefix gap instead of refusing the module whole; the
            // catalog files that gapped prefix as partial with its
            // attached count, carrying the prefix reason.
            let aimed = scoped_catalog(
                heuristic_provider(4, 150),
                AdmissionPolicy::detailed(),
                &[PathBuf::from(PATH)],
            );
            match catalog_admission(&aimed) {
                AdmissionRecord::Admitted { class, endpoints } => {
                    assert_eq!(*class, "heuristic");
                    assert_eq!(*endpoints, 450);
                }
                other => panic!("an aimed inspect must admit the prefix, got {other:?}"),
            }
            assert_eq!(
                aimed.admission.uncorroborated_candidates, 1,
                "the spilled table stays disclosed"
            );
            let unaimed =
                scoped_catalog(heuristic_provider(4, 150), AdmissionPolicy::detailed(), &[]);
            match catalog_admission(&unaimed) {
                AdmissionRecord::Partial {
                    class,
                    endpoints,
                    reason,
                } => {
                    assert_eq!(*class, "heuristic");
                    assert_eq!(*endpoints, 300);
                    assert!(reason.contains("reserved"), "{reason}");
                    assert!(
                        reason.contains("300 of 600 endpoints attached")
                            && reason.contains("(provider_prefix)"),
                        "the unaimed inspect carries the prefix gap: {reason}"
                    );
                }
                other => panic!("the unaimed inspect must file the gapped prefix, got {other:?}"),
            }
        }

        #[test]
        fn prefix_admitted_provider_reports_partial_state_with_counts() {
            // A prefix-admitted object is partially covered, never
            // refused: JSON and text must agree on the partial state
            // and carry the attached-vs-needed counts.
            let unaimed =
                scoped_catalog(heuristic_provider(4, 150), AdmissionPolicy::detailed(), &[]);
            let json = render_json(&unaimed);
            let admission = json["objects"]
                .as_array()
                .unwrap()
                .iter()
                .find(|object| object["path"] == PATH)
                .unwrap()["admission"]
                .clone();
            assert_eq!(admission["state"], "partial");
            assert_eq!(admission["class"], "heuristic");
            assert_eq!(admission["endpoints"], 300);
            let reason = admission["reason"].as_str().unwrap();
            assert!(
                reason.contains("300 of 600 endpoints attached")
                    && reason.contains("(provider_prefix)"),
                "the partial record keeps the prefix counts: {reason}"
            );
            let text = render_text(&unaimed);
            let line = text
                .lines()
                .find(|line| line.contains("admission") && line.contains("(provider_prefix)"))
                .expect("the text catalog names the prefix gap");
            assert!(
                line.contains("partial (heuristic)"),
                "the text verdict must read partial, got: {line}"
            );
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

        #[test]
        fn assemble_discloses_kernel_thread_absences_once() {
            let mut collection = over_cap(&[]);
            collection.budget.note_kernel_thread_absence();
            collection.budget.note_kernel_thread_absence();
            let catalog = catalog_with(
                collection,
                &Checks {
                    changed: false,
                    nonunique: None,
                },
            );
            let notes: Vec<&PidGap> = catalog
                .notes
                .iter()
                .filter(|note| note.subject == "kernel threads")
                .collect();
            assert_eq!(notes.len(), 1, "{:?}", catalog.notes);
            assert_eq!(notes[0].pid, None);
            assert_eq!(
                notes[0].reason,
                "2 processes examined are kernel threads with no user memory to scan"
            );
            assert!(
                catalog
                    .skipped
                    .iter()
                    .all(|gap| gap.subject != "kernel threads"),
                "verified absence is a note, never a loss: {:?}",
                catalog.skipped
            );
        }

        #[test]
        fn assemble_omits_kernel_thread_note_without_absences() {
            let catalog = catalog_with(
                over_cap(&[]),
                &Checks {
                    changed: false,
                    nonunique: None,
                },
            );
            assert!(
                catalog
                    .notes
                    .iter()
                    .all(|note| note.subject != "kernel threads"),
                "{:?}",
                catalog.notes
            );
            assert!(
                catalog
                    .skipped
                    .iter()
                    .all(|gap| gap.subject != "kernel threads"),
                "{:?}",
                catalog.skipped
            );
        }

        /// Capped with zero charged ranges (an unexamined-only snapshot,
        /// an empty snapshot, and an unavailable caller): the old cap-hit
        /// proxy claims proof, but the proof-plan gate must refuse it —
        /// while the unmodified over-cap cell keeps its plan. The computed
        /// zero-proof gate feeds the pass decision with must-not-load checks
        /// (`session: None` panics if called): no session attempt, no
        /// capability consultation, no fallback recorded.
        #[test]
        fn no_proof_gate_refuses_capped_zero_proof_plan() {
            let mut collection = over_cap(&[]);
            let unknown = vec![
                entry(0x3000_0000, b"r--p", 0x9999, "/usr/lib/libunknown.so"),
                entry(0x3000_1000, b"r-xp", 0x9999, "/usr/lib/libunknown.so"),
            ];
            collection.sweep = vec![(30_001, unknown), (30_002, Vec::new()), (30_003, caller())];
            collection.sweep_unavailable = BTreeSet::from([30_003]);
            let bound = bind_collection(&mut collection);
            assert!(
                collection.cap_hit && !collection.sweep.is_empty(),
                "fixture must trip the old cap-hit proxy"
            );
            let gate = sweep_has_proof_plan(&collection, &bound);
            assert!(!gate, "capped-but-zero-proof must hold no proof plan");
            for selection in [
                crate::cli::IdentityBackendSelection::Auto,
                crate::cli::IdentityBackendSelection::Kernel,
            ] {
                let (shared, ptr) =
                    super::shared_with(selection, ScriptedIdentityChecks::must_not_load());
                assert!(
                    matches!(decide_pass_attempt(&shared, gate), PassAttempt::Userspace),
                    "{selection:?} zero-proof must stay userspace"
                );
                let checks = unsafe { &*ptr };
                assert_eq!(
                    checks
                        .numbering_calls
                        .load(std::sync::atomic::Ordering::SeqCst),
                    0,
                    "{selection:?} zero-proof consults no numbering"
                );
                assert_eq!(
                    checks.btf_calls.load(std::sync::atomic::Ordering::SeqCst),
                    0,
                    "{selection:?} zero-proof consults no BTF"
                );
                assert_eq!(
                    checks
                        .session_calls
                        .load(std::sync::atomic::Ordering::SeqCst),
                    0,
                    "{selection:?} zero-proof attempts no session"
                );
                let shared = shared.lock().unwrap();
                assert_eq!(shared.summary().fallback, None);
                assert!(!shared.loaded());
            }
            let mut full = over_cap(&[]);
            let full_bound = bind_collection(&mut full);
            assert!(
                sweep_has_proof_plan(&full, &full_bound),
                "the charged over-cap cell keeps its proof plan"
            );
        }

        #[test]
        fn system_inspect_confirmed_maps_match_identity() {
            let catalog = catalog_of(over_cap(&[]), HashMap::new(), false);
            let matched = catalog
                .processes
                .iter()
                .find(|row| row.pid == 10_001)
                .unwrap();
            assert_eq!(matched.status, MemberStatus::MapsMatched);
            let json = render_json(&catalog);
            let row = json["processes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["pid"] == 10_001)
                .unwrap();
            assert_eq!(row["application_status"], "observed");
            assert_eq!(row["application"]["path"], exe().path.unwrap());
            assert_eq!(row["application"]["start_time"], 19_001);
            assert!(!matched.objects.is_empty());
            assert!(render_text(&catalog).contains("(PID 10001) (maps match)"));

            let refused = catalog_of(
                over_cap(&[]),
                HashMap::from([(
                    10_001,
                    Confirmation::Lost(AttributionLoss::ExecChanged, "exec changed".into()),
                )]),
                false,
            );
            let row = refused
                .processes
                .iter()
                .find(|row| row.pid == 10_001)
                .unwrap();
            assert!(matches!(row.status, MemberStatus::NotSelected { .. }));
            assert!(
                crate::inspect_identity::application_json(&row.application)["application"]
                    .is_null()
            );
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

        /// A6 (exec-only proof ranges), end to end over the catalog: a
        /// process past the cap that maps the provider and an unknown
        /// library only without `x` (a scanner reading files) is neither
        /// maps-matched nor a loss nor a coverage gap — the pass stays
        /// complete with the same 299 callers.
        #[test]
        fn a_data_only_mapper_past_the_cap_is_neither_a_caller_nor_a_gap() {
            let data_only = vec![
                entry(0x6000_0000, b"r--p", PROVIDER.inode, PATH),
                entry(0x6000_1000, b"rw-p", PROVIDER.inode, PATH),
                entry(0x7000_0000, b"r--p", 77, "/opt/vendor/libunknown.so"),
            ];
            let mut collection = over_cap(&[]);
            collection.sweep.push((30_000, data_only));
            collection.enumerated.push(30_000);
            let catalog = catalog_of(collection, HashMap::new(), false);
            assert_eq!(
                statuses(&catalog),
                BTreeMap::from([("maps_matched", 299), ("not_selected", 148), ("scanned", 2)])
            );
            let scanner = catalog
                .processes
                .iter()
                .find(|process| process.pid == 30_000)
                .unwrap();
            assert_eq!(scanner.status.label(), "not_selected");
            assert_eq!(scanner.status.reason(), None);
            assert!(scanner.objects.is_empty());
            assert_eq!((catalog.unexamined, catalog.unexamined_objects), (0, 0));
            assert!(
                catalog.attribution_losses.values().all(|count| *count == 0),
                "{:?}",
                catalog.attribution_losses
            );
            assert_eq!(catalog.scan_status, "complete", "{:?}", catalog.skipped);
            assert!(attribution_complete(&catalog));
        }

        /// A6: an object refused for non-unique inodes is a gap only where
        /// a process past the cap maps it executable — the same rule as the
        /// `inode_not_unique` loss it stands for.
        #[test]
        fn a_refused_object_mapped_only_data_only_past_the_cap_is_not_a_gap() {
            let fuse = Checks {
                changed: false,
                nonunique: Some("fuse"),
            };
            let mut alone = over_cap(&[]);
            alone
                .sweep
                .retain(|(pid, _)| !(10_001..10_300).contains(pid));
            alone
                .enumerated
                .retain(|pid| !(10_001..10_300).contains(pid));
            alone.sweep.push((
                30_000,
                vec![entry(0x6000_0000, b"r--p", PROVIDER.inode, PATH)],
            ));
            alone.enumerated.push(30_000);
            let catalog = catalog_with(alone, &fuse);
            assert!(
                !catalog
                    .skipped
                    .iter()
                    .any(|gap| gap.reason.starts_with("on a fuse filesystem")),
                "{:?}",
                catalog.skipped
            );
            assert!(
                catalog.attribution_losses.values().all(|count| *count == 0),
                "{:?}",
                catalog.attribution_losses
            );
            assert_eq!(catalog.scan_status, "complete", "{:?}", catalog.skipped);
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
            let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
            assert!(
                text.contains("2 checked in detail, 299 matched from maps, of 448 found"),
                "{text}"
            );
            assert!(
                text.contains("299 matched from maps (maps_matched)"),
                "{text}"
            );
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

        /// An unmatched process past the cap that maps a shared object no
        /// deep scan examined keeps its own per-pid gap and stays listed:
        /// folding it into "N other processes" would claim it maps no
        /// PKCS#11 object when none examined what it maps.
        #[test]
        fn unexamined_unmatched_process_stays_listed_with_its_own_gap() {
            let other = vec![
                entry(0x5000_0000, b"r--p", 77, "/opt/vendor/libunknown.so"),
                entry(0x5000_1000, b"r-xp", 77, "/opt/vendor/libunknown.so"),
            ];
            let catalog = catalog_of(
                over_cap(&[(10_001, other.clone()), (20_005, other)]),
                HashMap::new(),
                false,
            );
            assert!(
                catalog
                    .skipped
                    .iter()
                    .any(|gap| gap.pid == Some(10_001) && gap.subject == "maps attribution"),
                "the matched member keeps its per-pid gap: {:?}",
                catalog.skipped
            );
            let gap = catalog
                .skipped
                .iter()
                .find(|gap| gap.pid == Some(20_005))
                .expect("the unmatched unexamined pid keeps its own gap");
            assert_eq!(gap.subject, "maps attribution");
            assert!(
                gap.reason.contains("no deep scan examined"),
                "unexpected gap reason: {gap:?}"
            );
            let process = catalog
                .processes
                .iter()
                .find(|process| process.pid == 20_005)
                .unwrap();
            assert_eq!(process.status, MemberStatus::NotSelected { loss: None });
            let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
            assert!(
                text.contains("(PID 20005) — not_selected"),
                "unexamined unmatched pid must stay listed: {text}"
            );
        }

        /// An unselected pid whose phase-1 maps snapshot was unavailable
        /// keeps its own per-pid gap and stays listed: nothing examined
        /// its mappings, so the fold must not claim it maps no object.
        #[test]
        fn unavailable_snapshot_past_the_cap_stays_listed_with_its_own_gap() {
            let mut collection = over_cap(&[]);
            let found = collection
                .sweep
                .iter_mut()
                .find(|(pid, _)| *pid == 20_006)
                .map(|(_, entries)| entries.clear());
            assert!(found.is_some(), "fixture must contain pid 20006");
            collection.sweep_unavailable.insert(20_006);
            let catalog = catalog_with(
                collection,
                &Checks {
                    changed: false,
                    nonunique: None,
                },
            );
            assert_eq!(catalog.snapshots_unavailable, 1);
            let gap = catalog
                .skipped
                .iter()
                .find(|gap| gap.pid == Some(20_006))
                .expect("the unavailable pid keeps its own gap");
            assert_eq!(gap.subject, "maps attribution");
            assert!(
                gap.reason.contains("no maps snapshot"),
                "unexpected gap reason: {gap:?}"
            );
            let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
            assert!(
                text.contains("(PID 20006) — not_selected"),
                "unavailable pid must stay listed: {text}"
            );
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
                .find(|gap| gap.subject == "maps attribution" && gap.pid.is_none())
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

        fn unreadable(pid: u32, view: u32, detail: &str) -> MemberResult {
            let mut noise = DiscoveryNoiseAggregator::default();
            let skip = unreadable_member_skip(pid, false, detail, &mut noise)
                .expect("a live pid earns a gap");
            MemberResult {
                mapping_scan_completed: false,
                application: InspectApplicationResult::Unknown(InspectIdentityUnknown::NotExamined),
                complete_scan: None,
                hints_examined: false,
                pid,
                view: ProcessViewId(view),
                status: MemberStatus::Unreadable {
                    reason: detail.to_string(),
                },
                generation: None,
                modules: Vec::new(),
                examined: Vec::new(),
                pins: PinnedObjects::empty(),
                gaps: vec![PidGap::generic_member(pid, skip)],
                scan_ms: 0,
            }
        }

        #[test]
        fn fully_unreadable_collection_assembles_zero_objects_with_sudo_hint() {
            let denied =
                "the process generation could not be pinned: Permission denied (os error 13)";
            let collection = Collection {
                enumerated: vec![7, 9],
                selected: vec![7, 9],
                cap: MAX_SCAN_PIDS,
                cap_hit: false,
                members: vec![unreadable(7, 0, denied), unreadable(9, 1, denied)],
                scope_gaps: Vec::new(),
                proc_list_failed: false,
                sweep: Vec::new(),
                sweep_unavailable: BTreeSet::new(),
                budget: CaptureWorkBudget::default(),
            };
            let catalog = catalog_of(collection, HashMap::new(), false);
            assert!(catalog.objects.is_empty(), "no object was proven");
            assert_eq!(catalog.scan_status, "partial");
            assert!(
                !catalog.skipped.is_empty(),
                "the unreadable loss is a skipped gap"
            );
            assert!(
                catalog
                    .processes
                    .iter()
                    .all(|process| process.status.label() == "unreadable"
                        && process.status.reason().is_some()),
                "every process keeps its own reason"
            );
            let explanation = catalog
                .explanation
                .as_deref()
                .expect("the empty catalog explains itself");
            assert!(
                explanation.contains("sudo p11scope inspect --system"),
                "an unprivileged user is told to rerun with sudo: {explanation}"
            );
            let document = render_json(&catalog);
            assert_eq!(document["scan"]["status"], "partial");
            assert_eq!(document["objects"].as_array().map(Vec::len), Some(0));
            assert!(
                document["explanation"]
                    .as_str()
                    .is_some_and(|text| text.contains("sudo p11scope inspect --system")),
                "the JSON carries the same hint: {document}"
            );
        }

        #[test]
        fn fully_scanned_empty_machine_stays_complete_without_sudo_hint() {
            let collection = Collection {
                enumerated: vec![7],
                selected: vec![7],
                cap: MAX_SCAN_PIDS,
                cap_hit: false,
                members: vec![scanned(7, 0, Vec::new(), PinnedObjects::empty())],
                scope_gaps: Vec::new(),
                proc_list_failed: false,
                sweep: Vec::new(),
                sweep_unavailable: BTreeSet::new(),
                budget: CaptureWorkBudget::default(),
            };
            let catalog = catalog_of(collection, HashMap::new(), false);
            assert!(catalog.objects.is_empty(), "no provider was mapped");
            assert_eq!(catalog.scan_status, "complete");
            assert!(catalog.skipped.is_empty(), "{:?}", catalog.skipped);
            let explanation = catalog
                .explanation
                .as_deref()
                .expect("the empty catalog explains itself");
            assert!(
                !explanation.contains("sudo"),
                "full coverage needs no sudo hint: {explanation}"
            );
        }
    }

    #[test]
    fn system_outcome_renders_unless_the_proc_listing_failed() {
        // Nothing enumerated and the listing itself failed: hard error.
        assert_eq!(
            decide_system_outcome(OutcomeStats {
                enumerated: 0,
                proc_list_failed: true,
            }),
            SystemOutcome::HardError
        );
        // Nothing enumerated, listing fine: a vacuously empty machine.
        assert_eq!(
            decide_system_outcome(OutcomeStats {
                enumerated: 0,
                proc_list_failed: false,
            }),
            SystemOutcome::Render
        );
        // Enumerated, nothing inventoried: gaps with per-process reasons,
        // not a stop — ruling JK-22a.
        assert_eq!(
            decide_system_outcome(OutcomeStats {
                enumerated: 9,
                proc_list_failed: false,
            }),
            SystemOutcome::Render
        );
    }

    #[test]
    fn fully_unreadable_machine_renders_a_partial_catalog() {
        // Ruling JK-22a: enumerated but unreadable processes are gaps with
        // per-process reasons, not a stop. Only a failed /proc listing
        // (no data source at all) stays a hard error.
        assert_eq!(
            decide_system_outcome(OutcomeStats {
                enumerated: 9,
                proc_list_failed: false,
            }),
            SystemOutcome::Render
        );
    }

    #[test]
    fn proc_list_error_names_the_failed_listing() {
        // The only remaining hard error: /proc could not be listed, so no
        // data source exists. Unreadable members render as gaps instead
        // (see fully_unreadable_collection_assembles_zero_objects_with_sudo_hint).
        let collection = Collection {
            enumerated: Vec::new(),
            selected: Vec::new(),
            cap: MAX_SCAN_PIDS,
            cap_hit: false,
            members: Vec::new(),
            scope_gaps: vec![PidGap::scope(Skipped {
                subject: "system".into(),
                reason: "/proc could not be listed (os error 5); no process was discovered".into(),
            })],
            proc_list_failed: true,
            sweep: Vec::new(),
            sweep_unavailable: BTreeSet::new(),
            budget: CaptureWorkBudget::default(),
        };
        let error = format!("{:#}", proc_list_system_error(&collection));
        assert!(error.contains("cannot inspect system"), "{error}");
        assert!(error.contains("no process was discovered"), "{error}");
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
    fn kernel_thread_absence_note_counts_once_per_pass() {
        assert_eq!(kernel_thread_absence_note(0), None);
        let one = kernel_thread_absence_note(1).expect("one absence is noted");
        assert_eq!(one.pid, None);
        assert_eq!(one.subject, "kernel threads");
        assert_eq!(
            one.reason,
            "1 process examined is a kernel thread with no user memory to scan"
        );
        let many = kernel_thread_absence_note(117).expect("many absences are noted");
        assert_eq!(many.pid, None);
        assert_eq!(many.subject, "kernel threads");
        assert_eq!(
            many.reason,
            "117 processes examined are kernel threads with no user memory to scan"
        );
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
                    kind: crate::plan::RefusalKind::CapacityWhole,
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
                    kind: crate::plan::RefusalKind::CapacityWhole,
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
        assert!(text.contains("0 provider files"), "{text}");
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
                kind: crate::plan::RefusalKind::CapacityWhole,
            },
        )]);
        let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(text.contains("system — 1 provider file"), "{text}");
        assert!(text.contains("/opt/provider.so"), "{text}");
        assert!(text.contains("sha256 aa"), "{text}");
        assert!(
            text.contains("Unknown executable (PID 100) (view 0)"),
            "{text}"
        );
        assert!(
            text.contains("refused (closure_array): module needs 388 more"),
            "{text}"
        );
        assert!(text.contains(TEXT_SCAN_ONLY_NOTE), "{text}");
        assert!(text.contains("2.40"), "{text}");
        assert!(text.contains("PKCS 11"), "{text}");
        assert!(
            text.contains("processes: 2 checked in detail (scanned)"),
            "{text}"
        );
        assert!(
            text.contains("0 admitted, 0 partial, 1 refused, 0 unresolved"),
            "{text}"
        );
    }

    /// An unpublished proxy closure array (the p11-kit proxy alone) refuses
    /// by design: the text says so in one plain line, while JSON keeps the
    /// full planner reason.
    #[test]
    fn text_folds_unpublished_closure_refusal_to_one_plain_line() {
        let reason = "a proxy closure array alone in the capture's first plan, or mapped during \
             the capture, attaches only its published tables, and none of its 67 lookalike \
             function tables is published yet, so calls through it are not counted \
             (a proxy closure array is admitted whole, as a prefix when mapped before the \
             capture's first plan beside a provider or named by the operator, or as published \
             tables); the providers it forwards to attach when they load";
        let catalog = catalog_with(vec![object(
            "/usr/lib64/libp11-kit.so.0.4.11",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: reason.into(),
                kind: crate::plan::RefusalKind::AwaitingPublication,
            },
        )]);
        let text = render_text(&catalog);
        assert!(
            text.contains(
                "refused (proxy): p11-kit proxy not attached by design; the providers it forwards \
                 to attach when they load"
            ),
            "{text}"
        );
        assert!(!text.contains("lookalike"), "{text}");
        assert!(!text.contains("closure_array"), "{text}");
        let document = render_json(&catalog);
        assert_eq!(
            document["objects"][0]["admission"]["reason"].as_str(),
            Some(reason),
            "{document}"
        );
    }

    /// Same by-design fold for a closure array outside p11-kit: the generic
    /// proxy name replaces the p11-kit one.
    #[test]
    fn text_folds_unpublished_closure_refusal_without_proxy_name() {
        let catalog = catalog_with(vec![object(
            "/opt/proxy.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: "a proxy closure array alone in the capture's first plan, or mapped \
                     during the capture, attaches only its published tables, and none of \
                     its 3 lookalike function tables is published yet, so calls through it \
                     are not counted (a proxy closure array is admitted whole, as a prefix \
                     when mapped before the capture's first plan beside a provider or named \
                     by the operator, or as published tables); the providers it forwards to \
                     attach when they load"
                    .into(),
                kind: crate::plan::RefusalKind::AwaitingPublication,
            },
        )]);
        let text = render_text(&catalog);
        assert!(
            text.contains(
                "refused (proxy): proxy closure array not attached by design; the providers it \
                 forwards to attach when they load"
            ),
            "{text}"
        );
        assert!(!text.contains("closure_array"), "{text}");
    }

    /// A capacity closure refusal keeps its full text under `-v`: the demand
    /// it states is actionable, not a by-design constant. Concise folds it
    /// to the plain budget line (see
    /// `concise_capacity_refusal_is_plain_budget_line`).
    #[test]
    fn text_keeps_capacity_closure_refusal_verbatim() {
        let reason = "module needs 388 more; only 512 attach slots are available; 480 are in \
             use — refusing to attach a prefix of its 67 lookalike function tables \
             (a proxy closure array is admitted whole, as a prefix when mapped before the \
             capture's first plan beside a provider or named by the operator, or as published \
             tables)";
        let catalog = catalog_with(vec![object(
            "/usr/lib64/libp11-kit.so.0.4.11",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: reason.into(),
                kind: crate::plan::RefusalKind::CapacityWhole,
            },
        )]);
        let verbose = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(
            verbose.contains(&format!(
                "refused (closure_array): {reason} [{SCAN_ONLY_NOTE}]"
            )),
            "{verbose}"
        );
        let document = render_json(&catalog);
        assert_eq!(
            document["objects"][0]["admission"]["reason"].as_str(),
            Some(reason),
            "{document}"
        );
    }

    /// Item 11: the header and the processes line use one count for
    /// "checked in detail" (deep-scanned members only; memory-unreadable
    /// members are named separately, never folded in).
    #[test]
    fn header_and_processes_line_agree_on_checked_in_detail() {
        let mut catalog = catalog_with(Vec::new());
        catalog.processes[1].status = MemberStatus::MemoryUnavailable { reason: "denied" };
        // Stale inventoried total: the header must count processes, not it.
        catalog.scanned = 2;
        catalog.maps_matched = 0;
        let concise = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(
            concise.contains("1 checked in detail, 0 matched from maps, 1 memory unreadable"),
            "{concise}"
        );
        assert!(
            concise.contains("processes: 1 memory unreadable, 1 checked in detail"),
            "{concise}"
        );
        assert!(!concise.contains("2 checked in detail"), "{concise}");
    }

    /// Item 11: the header labels the summed deep-scan time as deep scans,
    /// never "scan took" (the command's wall time is longer).
    #[test]
    fn header_labels_deep_scan_time_not_scan_took() {
        let catalog = catalog_with(Vec::new());
        let concise = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(concise.contains("deep scans 7 ms"), "{concise}");
        assert!(!concise.contains("scan took"), "{concise}");
    }

    /// Item 31: concise object headers name the provider file without an
    /// index; verbose keeps `object[N]` for cross-references.
    #[test]
    fn concise_object_header_has_no_index() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Admitted {
                class: "standard",
                endpoints: 68,
            },
        )]);
        let concise = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(!concise.contains("object[0]"), "{concise}");
        assert!(concise.contains("/opt/provider.so"), "{concise}");
        let verbose = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(verbose.contains("object[0]"), "{verbose}");
    }

    /// Item 12: concise admitted text says what profile/run would watch;
    /// inspect itself watches nothing.
    #[test]
    fn concise_admitted_says_profile_run_would_watch() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Admitted {
                class: "standard",
                endpoints: 68,
            },
        )]);
        let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(
            text.contains("profile/run would watch 68 functions"),
            "{text}"
        );
        assert!(!text.contains("admission  watched"), "{text}");
    }

    /// Item 12: verbose admitted text also avoids claiming inspect watches.
    #[test]
    fn verbose_admitted_says_profile_run_would_watch() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Admitted {
                class: "standard",
                endpoints: 68,
            },
        )]);
        let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(
            text.contains("profile/run would watch 68 functions"),
            "{text}"
        );
        assert!(!text.contains("admission  watched"), "{text}");
    }

    /// Item 12: the admission summary uses the JSON-aligned verdict
    /// terms (admitted/refused/unresolved), never "watched": inspect
    /// watches nothing.
    #[test]
    fn admission_summary_uses_json_aligned_terms() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Admitted {
                class: "standard",
                endpoints: 68,
            },
        )]);
        for (verbosity, summary) in [
            (
                crate::cli::TextVerbosity::Concise,
                "admission: 1 admitted, 0 refused, 0 unresolved (scan only: names below come \
                 from the files themselves)",
            ),
            (
                crate::cli::TextVerbosity::Verbose,
                "admission: 1 admitted, 0 refused, 0 unresolved (0 possible functions not yet \
                 confirmed from a second source (uncorroborated_candidates); 0 functions \
                 claimed by two providers (module_ambiguous); scan only: names below come \
                 from the files themselves)",
            ),
        ] {
            let text = render_text_with_verbosity(&catalog, verbosity);
            let line = text.lines().find(|line| line.starts_with("admission: "));
            assert_eq!(line, Some(summary), "{text}");
            for line in text.lines() {
                for (at, _) in line.match_indices("watch") {
                    let context = &line[at.saturating_sub(6)..];
                    assert!(
                        context.starts_with("would watch"),
                        "every watch claim is a would-watch prediction: {line}"
                    );
                }
            }
        }
    }

    /// Item 12 adjacent: an admitted record with zero endpoints from
    /// this scan qualifies the prediction instead of asserting
    /// "would watch 0 functions" (an unscanned module deep-scans on
    /// capture; a genuinely empty table admits nothing).
    #[test]
    fn admitted_zero_endpoints_qualifies_scan_prediction() {
        let catalog = catalog_with(vec![object(
            "/opt/unreadable.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Admitted {
                class: "heuristic",
                endpoints: 0,
            },
        )]);
        let concise = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(
            concise.contains("admission  0 functions admitted from this scan"),
            "{concise}"
        );
        assert!(!concise.contains("would watch 0"), "{concise}");
        let verbose = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(
            verbose.contains("admission  0 functions admitted from this scan (class heuristic;"),
            "{verbose}"
        );
        assert!(!verbose.contains("would watch 0"), "{verbose}");
    }

    /// Item 10: concise capacity refusal is one plain budget line; verbose
    /// keeps the full planner reason.
    #[test]
    fn concise_capacity_refusal_is_plain_budget_line() {
        let reason = "module needs 388 more; only 512 attach slots are available; 480 are in \
             use — refusing to attach a prefix of its 67 lookalike function tables \
             (a proxy closure array is admitted whole, as a prefix when mapped before the \
             capture's first plan beside a provider or named by the operator, or as published \
             tables)";
        let catalog = catalog_with(vec![object(
            "/usr/lib64/libp11-kit.so.0.4.11",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: reason.into(),
                kind: crate::plan::RefusalKind::CapacityWhole,
            },
        )]);
        let concise = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(
            concise.contains(
                "refused: too many functions for the remaining probe budget; name it \
                 with --module to capture it alone"
            ),
            "{concise}"
        );
        assert!(!concise.contains("lookalike"), "{concise}");
        assert!(!concise.contains("closure_prefix"), "{concise}");
        let verbose = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(verbose.contains("module needs 388 more"), "{verbose}");
    }

    /// Item 10: unexamined-maps skips with different counts fold to one
    /// plain concise line; verbose lists each pid record.
    #[test]
    fn concise_folds_unexamined_maps_gaps_to_one_plain_line() {
        let mut catalog = catalog_with(Vec::new());
        for (pid, count) in [(11u32, 13usize), (12, 14), (13, 9)] {
            catalog.skipped.push(unexamined_maps_gap(pid, count));
        }
        let concise = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(
            concise.contains(
                "3 processes map libraries that were not deep-scanned (may hide providers)"
            ),
            "{concise}"
        );
        assert_eq!(
            concise
                .lines()
                .filter(|line| line.starts_with("skipped"))
                .count(),
            1,
            "{concise}"
        );
        let verbose = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(verbose.contains("maps 13 shared objects"), "{verbose}");
        assert!(verbose.contains("maps 14 shared objects"), "{verbose}");
    }

    /// Item 10: over-capacity file skips with different sizes fold to one
    /// plain concise line; verbose lists each record. Both producer
    /// formats fold together.
    #[test]
    fn concise_folds_too_large_gaps_to_one_plain_line() {
        let mut catalog = catalog_with(Vec::new());
        for (pid, size) in [(21u32, 319346888u64), (22, 300000000)] {
            catalog.skipped.push(PidGap::member(
                pid,
                Skipped {
                    subject: format!("/proc/{pid}/root/usr/lib/big.so"),
                    reason: format!("too_large ({size} bytes; per-object cap is 268435456)"),
                },
            ));
        }
        catalog.skipped.push(PidGap::member(
            23,
            Skipped {
                subject: "/proc/23/root/usr/lib/huge.so".into(),
                reason: "object is 407976096 bytes; limit is 268435456".into(),
            },
        ));
        let concise = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(
            concise.contains("3 files over 256 MiB not read"),
            "{concise}"
        );
        assert_eq!(
            concise
                .lines()
                .filter(|line| line.starts_with("skipped"))
                .count(),
            1,
            "{concise}"
        );
        let verbose = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(verbose.contains("too_large (319346888 bytes"), "{verbose}");
        assert!(
            verbose.contains("object is 407976096 bytes; limit is 268435456"),
            "{verbose}"
        );
    }

    /// Twenty identical pin-loss skips across two processes fold to one
    /// counted line in text; JSON still lists every record.
    #[test]
    fn text_folds_repeated_skipped_gaps_to_one_counted_line() {
        let mut catalog = catalog_with(Vec::new());
        for pid in [639, 640] {
            for index in 0..10 {
                catalog.skipped.push(PidGap::member(
                    pid,
                    Skipped {
                        subject: format!("/proc/{pid}/root/usr/lib/object{index}.so"),
                        reason: "opening object within retained target root: No such file or \
                             directory (os error 2)"
                            .into(),
                    },
                ));
            }
        }
        let text = render_text(&catalog);
        assert!(
            text.contains(
                "skipped (20 gaps in 2 processes): opening object within retained target \
                 root: No such file or directory (os error 2) (--json lists each)"
            ),
            "{text}"
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("skipped"))
                .count(),
            1,
            "{text}"
        );
        let document = render_json(&catalog);
        assert_eq!(
            document["skipped"].as_array().map(Vec::len),
            Some(20),
            "{document}"
        );
    }

    /// Verbose lists every skipped record: `-v` is the full per-gap
    /// detail, never a fold.
    #[test]
    fn text_lists_every_skipped_gap_in_verbose() {
        let mut catalog = catalog_with(Vec::new());
        for pid in [639, 640] {
            for index in 0..10 {
                catalog.skipped.push(PidGap::member(
                    pid,
                    Skipped {
                        subject: format!("/proc/{pid}/root/usr/lib/object{index}.so"),
                        reason: "opening object within retained target root: No such file or \\
                             directory (os error 2)"
                            .into(),
                    },
                ));
            }
        }
        let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("skipped: pid"))
                .count(),
            20,
            "{text}"
        );
        assert!(
            !text.lines().any(|line| line.starts_with("skipped (")),
            "verbose never folds: {text}"
        );
    }

    /// Repeated per-pid notes fold to one counted line in concise
    /// text, like skipped gaps; JSON still lists every record.
    #[test]
    fn text_folds_repeated_notes_to_one_counted_line() {
        let mut catalog = catalog_with(Vec::new());
        for pid in [639, 640] {
            for index in 0..5 {
                catalog.notes.push(PidGap::member(
                    pid,
                    Skipped {
                        subject: format!("/usr/lib/object{index}.so (deleted)"),
                        reason: "deleted mapping".into(),
                    },
                ));
            }
        }
        let text = render_text(&catalog);
        assert!(
            text.contains("notes (10 gaps in 2 processes): deleted mapping (--json lists each)"),
            "{text}"
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("notes"))
                .count(),
            1,
            "{text}"
        );
        let document = render_json(&catalog);
        assert_eq!(
            document["notes"].as_array().map(Vec::len),
            Some(10),
            "{document}"
        );
    }

    /// CLI-1: concise system inspect keeps the plain header, one
    /// short block per provider, the folded lines, coverage and the
    /// `-v` hint; per-table observations are verbose-only.
    #[test]
    fn concise_system_inspect_keeps_providers_coverage_and_hint() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: "module needs 388 more".into(),
                kind: crate::plan::RefusalKind::CapacityWhole,
            },
        )]);
        let out = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(out.contains("1 provider file"), "{out}");
        assert!(out.contains("/opt/provider.so"), "{out}");
        assert!(out.contains("coverage: complete"), "{out}");
        assert!(!out.contains("observed   pid"), "{out}");
        assert!(!out.contains("PKCS 11"), "{out}");
        assert!(!out.contains("closure_array"), "{out}");
        assert!(!out.contains("uncorroborated"), "{out}");
        assert!(out.contains(crate::cli::VERBOSE_HINT), "{out}");
    }

    /// F7: concise system inspect omits internal `(view N)` ids from
    /// the mapped-by lines (first-timers need names, not view ids);
    /// verbose keeps them beside the names, JSON keeps every process.
    #[test]
    fn concise_system_inspect_omits_view_ids_verbose_keeps_them() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: "module needs 388 more".into(),
                kind: crate::plan::RefusalKind::CapacityWhole,
            },
        )]);
        let concise = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Concise);
        assert!(
            concise.contains("Unknown executable (PID 100)"),
            "{concise}"
        );
        assert!(
            !concise.contains("(view "),
            "concise leaks view ids: {concise}"
        );
        let verbose = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(
            verbose.contains("Unknown executable (PID 100) (view 0)"),
            "{verbose}"
        );
    }

    /// CLI-1: verbose system inspect pairs machine names with the plain
    /// words and keeps the per-table observations.
    #[test]
    fn verbose_system_inspect_pairs_machine_names_with_plain_words() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: "module needs 388 more".into(),
                kind: crate::plan::RefusalKind::CapacityWhole,
            },
        )]);
        let out = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(out.contains("observed   pid"), "{out}");
        assert!(out.contains("PKCS 11"), "{out}");
        assert!(out.contains("closure_array"), "{out}");
        assert!(!out.contains(crate::cli::VERBOSE_HINT), "{out}");
    }

    /// CLI-1: quiet system inspect is the header and coverage only.
    #[test]
    fn quiet_system_inspect_keeps_header_and_coverage_only() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: "module needs 388 more".into(),
                kind: crate::plan::RefusalKind::CapacityWhole,
            },
        )]);
        let out = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Quiet);
        assert!(out.contains("1 provider file"), "{out}");
        assert!(out.contains("coverage: complete"), "{out}");
        assert!(!out.contains("/opt/provider.so"), "{out}");
        assert!(!out.contains(crate::cli::VERBOSE_HINT), "{out}");
    }

    /// A lone skip keeps its pid and subject: there is nothing to fold.
    #[test]
    fn text_keeps_a_single_skipped_gap_verbatim() {
        let mut catalog = catalog_with(Vec::new());
        catalog.skipped.push(PidGap::member(
            7,
            Skipped {
                subject: "/opt/a.so".into(),
                reason: "identity_mismatch: mapping (8:1, 5) != opened (8:1, 6)".into(),
            },
        ));
        let text = render_text(&catalog);
        assert!(
            text.contains(
                "skipped: pid 7 /opt/a.so — identity_mismatch: mapping (8:1, 5) != opened (8:1, 6)"
            ),
            "{text}"
        );
    }

    /// A proxy such as p11-kit carries dozens of identical closure tables:
    /// the text names each consecutive run once with its count, in the
    /// original order, while JSON keeps every table.
    #[test]
    fn text_collapses_consecutive_identical_tables_and_json_keeps_each() {
        let mut proxy = object(
            "/opt/proxy.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: "module needs 6734 more".into(),
                kind: crate::plan::RefusalKind::CapacityWhole,
            },
        );
        let mut prefix = table((3, 2), 68);
        prefix.walk = "known_prefix";
        let mut tables = vec![prefix.clone()];
        tables.extend(std::iter::repeat_n(table((3, 2), 104), 65));
        tables.extend([prefix.clone(), prefix]);
        proxy.observations[0].tables = tables;
        let catalog = catalog_with(vec![proxy]);

        let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| line.trim_start().starts_with("table "))
            .collect();
        assert_eq!(
            lines,
            [
                "    table      3.2, 68 known functions (newer functions unknown)",
                "    table      3.2, 104 functions (fully walked)  (×65 identical)",
                "    table      3.2, 68 known functions (newer functions unknown)  (×2 identical)",
            ],
            "{text}"
        );
        let document = render_json(&catalog);
        assert_eq!(
            document["objects"][0]["observations"][0]["tables"]
                .as_array()
                .map(Vec::len),
            Some(68),
            "{document}"
        );
    }

    /// Kernel threads and other processes that map no provider are counted
    /// on the summary line; the text lists only processes that map an
    /// object, carry a reason, or carry their own gap record (skipped or
    /// note). JSON still lists every process.
    #[test]
    fn text_lists_only_processes_with_objects_or_reasons() {
        let mut catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Admitted {
                class: "corroborated",
                endpoints: 68,
            },
        )]);
        let plain = |pid: u32, status: MemberStatus| ProcessRecord {
            application: InspectApplicationResult::Unknown(InspectIdentityUnknown::NotExamined),
            complete_scan: None,
            hints_examined: false,
            pid,
            status,
            objects: Vec::new(),
            generation: None,
        };
        catalog.skipped.push(PidGap::member(
            700,
            Skipped {
                subject: "/opt/lib.so".into(),
                reason: "opening object within retained target root: No such process".into(),
            },
        ));
        catalog.notes.push(PidGap::member(
            800,
            Skipped {
                subject: "/opt/lib.so".into(),
                reason: "deleted mapping".into(),
            },
        ));
        catalog.processes.extend([
            plain(700, MemberStatus::Scanned),
            plain(800, MemberStatus::Scanned),
            plain(300, MemberStatus::NotSelected { loss: None }),
            plain(400, MemberStatus::Exited),
            plain(
                500,
                MemberStatus::Unreadable {
                    reason: "permission denied".into(),
                },
            ),
            plain(
                600,
                MemberStatus::NotSelected {
                    loss: Some("maps changed".into()),
                },
            ),
        ]);

        let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(
            text.contains("Unknown executable (PID 100) — scanned"),
            "{text}"
        );
        for hidden in [200, 300, 400] {
            assert!(
                !text.contains(&format!("(PID {hidden}) —")),
                "pid {hidden} maps nothing and has no reason: {text}"
            );
        }
        assert!(text.contains("(PID 500) — unreadable"), "{text}");
        assert!(text.contains("permission denied"), "{text}");
        assert!(text.contains("(PID 600) — not_selected"), "{text}");
        assert!(
            text.contains("(PID 700) — scanned"),
            "a process with its own skipped record stays listed: {text}"
        );
        assert!(
            text.contains("(PID 800) — scanned"),
            "a process with only a per-pid note stays listed: {text}"
        );
        assert!(text.contains("maps changed"), "{text}");
        assert!(
            text.contains(
                "  3 other processes are not listed: no PKCS#11 object found or attributed \
                 (1 checked in detail, 1 past the scan cap, 1 exited); --json lists every process"
            ),
            "{text}"
        );
        let document = render_json(&catalog);
        assert_eq!(
            document["processes"].as_array().map(Vec::len),
            Some(8),
            "{document}"
        );
    }

    /// The fold line keeps singular grammar for one hidden process and
    /// still names all three buckets, so a zero bucket reads as counted
    /// rather than forgotten.
    #[test]
    fn fold_line_counts_one_hidden_process_by_status() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Admitted {
                class: "corroborated",
                endpoints: 68,
            },
        )]);
        let text = render_text_with_verbosity(&catalog, crate::cli::TextVerbosity::Verbose);
        assert!(
            text.contains(
                "  1 other process is not listed: no PKCS#11 object found or attributed \
                 (1 checked in detail, 0 past the scan cap, 0 exited); --json lists every process"
            ),
            "{text}"
        );
    }
}

#[cfg(test)]
pub(crate) mod demotion_retirement_producer_tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    pub(crate) struct OwnedStoppedChild(Option<Child>);

    impl OwnedStoppedChild {
        pub(crate) fn new() -> Self {
            Self::with_command("kill -STOP $$; exit 99")
        }

        pub(crate) fn with_command(command: &str) -> Self {
            Self::spawn_stopped(Command::new("/bin/sh").args(["-c", command]), |_| {})
        }

        /// Abort-proof an explicitly-owned fixture spawn: the child dies
        /// with its observer even while SIGSTOPped, and keeps no
        /// inherited fd past stdio.
        ///
        /// Drop reaps on every unwind path, but an aborted observer
        /// (SIGABRT/SIGKILL) runs no teardown, orphaning its stopped
        /// child with every inherited fd — including the cargo-lane
        /// lock, which flock(1) holds without CLOEXEC by design and
        /// which the orphan then wedges via the shared open file
        /// description. The hook therefore arms a parent-death SIGKILL
        /// (a parent already gone exits before exec) and scrubs every
        /// fd past stdio that would survive the exec. Async-signal-safe
        /// syscalls only; the bounded loop costs milliseconds.
        pub(crate) fn harden_spawn(command: &mut Command) {
            use std::os::unix::process::CommandExt;
            // The orphan check compares against the owner at fork: a
            // live subreaper may adopt the child before the hook runs,
            // so testing for init alone misses live adoption, and the
            // death signal never fires for a death that predates it.
            let owner = std::process::id();
            // SAFETY: the hook runs after fork before exec; its body
            // uses async-signal-safe syscalls only (prctl, getppid,
            // close_range, fcntl, close, _exit), closes child fds only,
            // allocates nothing and touches no parent memory. stdio is
            // already dup2ed onto 0..3 before hooks run, so the sweep
            // cannot break redirection; CLOEXEC-marked fds stay open
            // because that set carries Rust's spawn-error channel, whose
            // EOF the parent reads as exec success — closing it would
            // turn an exec failure into a bogus Ok child. CLOEXEC fds
            // vanish at exec anyway, so keeping them leaks nothing.
            unsafe {
                command.pre_exec(move || {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
                    if libc::getppid() != owner as libc::pid_t {
                        libc::_exit(127);
                    }
                    // Existing fds survive RLIMIT_NOFILE lowering,
                    // so an rlimit-bounded sweep misses descriptors
                    // above a lowered soft limit. close_range covers
                    // the whole table; CLOEXEC (not close) keeps
                    // Rust's already-CLOEXEC spawn-error channel
                    // intact, and every marked fd vanishes at exec.
                    // The raw syscall keeps the static musl build,
                    // whose libc has no close_range wrapper.
                    if libc::syscall(
                        libc::SYS_close_range,
                        3,
                        libc::c_uint::MAX,
                        libc::CLOSE_RANGE_CLOEXEC,
                    ) != 0
                    {
                        // Pre-5.9 kernels: sweep a fixed cap
                        // regardless of the limit, still preserving
                        // CLOEXEC fds (test fixtures never approach
                        // a million fds).
                        for fd in 3..(1 << 20) {
                            let flags = libc::fcntl(fd, libc::F_GETFD);
                            if flags >= 0 && (flags & libc::FD_CLOEXEC) == 0 {
                                libc::close(fd);
                            }
                        }
                    }
                    Ok(())
                });
            }
        }

        pub(crate) fn spawn_stopped(command: &mut Command, after_spawn: impl FnOnce(u32)) -> Self {
            // The child reaches its readiness handshake after dynamic startup.
            // A confirmed SIGSTOP then holds its maps stable during the scan.
            Self::harden_spawn(command);
            let mut owned = Self(Some(command.spawn().unwrap()));
            after_spawn(owned.id());
            let pid = owned.id() as libc::pid_t;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                assert!(
                    Instant::now() < deadline,
                    "owned positive-control child did not stop after startup"
                );
                let mut status = 0;
                // SAFETY: pid names only this retained owned child; WNOHANG
                // prevents a blocking wait and WUNTRACED reports its stop.
                let waited =
                    unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WNOHANG) };
                if waited == pid {
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        // waitpid already reaped it: never kill that pid again.
                        owned.0 = None;
                    }
                    assert!(
                        libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP,
                        "owned positive-control child ended before readiness: {status}"
                    );
                    return owned;
                }
                if waited < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        // Another wait has already consumed this child.
                        owned.0 = None;
                    }
                    assert_eq!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted,
                        "cannot observe owned positive-control child readiness: {error}"
                    );
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        pub(crate) fn id(&self) -> u32 {
            self.0.as_ref().expect("retained owned child").id()
        }
    }

    impl Drop for OwnedStoppedChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    // The scanner must expose each real unusable mapping before pinning.
    #[test]
    fn demotion_retirement_mapped_unlinked_or_unusable_owner_never_retires() {
        for name in [
            std::ffi::OsString::from("deleted.so"),
            std::ffi::OsString::from("ambiguous\n.so"),
            std::ffi::OsString::from_vec(vec![b'b', 0xff, b'.', b's', b'o']),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(&name);
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.set_len(4096).unwrap();
            use std::os::fd::AsRawFd;
            // SAFETY: a retained 4096-byte file is mapped read/execute, never called, and released below.
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            let expected = if name == std::ffi::OsStr::new("deleted.so") {
                std::fs::remove_file(&path).unwrap();
                "deleted mapping"
            } else if name.as_encoded_bytes().contains(&b'\n') {
                "ambiguous \\012 pathname"
            } else {
                "non-UTF-8 pathname"
            };
            let mut budget = CaptureWorkBudget::default();
            let mut noise = DiscoveryNoiseAggregator::default();
            let member = scan_member(
                std::process::id(),
                ProcessViewId(0),
                &[],
                &HookRegistry::builtin(),
                &mut budget,
                &mut noise,
            );
            // SAFETY: the exact owned mapping is no longer used by the scanner.
            assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);
            assert!(
                member.gaps.iter().any(|gap| gap.reason == expected),
                "actual omission must be observed: {expected}"
            );
            assert!(
                !crate::discovery::scan::scan_skip_truncates(expected),
                "public completeness remains unchanged"
            );
            assert!(
                member.complete_scan.is_none(),
                "omitted file may still contain a current owner"
            );
        }
    }

    #[test]
    fn demotion_retirement_hint_selection_never_proves_physical_absence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replaced.so");
        let original = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        original.set_len(4096).unwrap();
        use std::os::fd::AsRawFd;
        // SAFETY: the owned executable mapping remains retained but is never invoked.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                original.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        std::fs::rename(&path, dir.path().join("still-mapped.so")).unwrap();
        std::fs::write(&path, b"replacement physical file").unwrap();
        let mut budget = CaptureWorkBudget::default();
        let mut noise = DiscoveryNoiseAggregator::default();
        let member = scan_member(
            std::process::id(),
            ProcessViewId(0),
            &[path],
            &HookRegistry::builtin(),
            &mut budget,
            &mut noise,
        );
        // SAFETY: scanning completed; this is the exact owned 4096-byte mapping.
        assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);
        assert!(
            member
                .gaps
                .iter()
                .any(|gap| gap.reason == crate::discovery::scan::HINT_NOT_MAPPED_REASON)
        );
        assert!(
            member.complete_scan.is_none(),
            "hint absence supplies no physical absence authority"
        );
        let child = OwnedStoppedChild::new();
        let mut positive_budget = CaptureWorkBudget::default();
        let member = scan_member(
            child.id(),
            ProcessViewId(0),
            &[],
            &HookRegistry::builtin(),
            &mut positive_budget,
            &mut noise,
        );
        drop(child);
        assert!(
            member.complete_scan.is_some(),
            "unrestricted complete scan is the positive control: status={:?}, \
             generation={:?}, mapping_scan_completed={}, gaps={:?}, \
             budget_stop={:?}, refusals={:?}",
            member.status,
            member.generation,
            member.mapping_scan_completed,
            member.gaps,
            positive_budget.stopped_reason(),
            positive_budget.refusal_counts(),
        );
    }
}

#[cfg(test)]
mod d3a_adapter_tests {
    use super::with_confirmation_pools;
    use crate::discovery::caller_registry::ExeIdentity;
    use crate::discovery::confirm_shards::{ShardableIo, attribute_unselected_with_policy};
    use crate::discovery::identity::{FileIdentity, MappedFile, PinnedObjectId};
    use crate::discovery::proof_stats::MIN_PARALLEL_BATCH;
    use crate::discovery::scan::{CaptureWorkBudget, read_maps_or_refuse};
    use crate::discovery::sweep_attribution::{
        AttributionLoss, ConfirmIo, FdLease, KnownKeyIndex, ObjectChecks, OsConfirmIo, ProofTrace,
        ReservationOwner, SegmentPolicy,
    };
    use crate::fixture_guard::DieWithParent as _;
    use p11scope_manifest::maps::{Device, MapEntry, ObjectKey};
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::sync::{Arc, Mutex};

    struct AdapterIo<'p> {
        os: OsConfirmIo<'p>,
        text: Arc<Vec<u8>>,
        trace: Arc<Mutex<ProofTrace>>,
        owner: ReservationOwner,
    }

    impl ConfirmIo for AdapterIo<'_> {
        type Pin = std::fs::File;
        fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
            self.os.mapped_file(pid, start, end)
        }
        fn mapped_files_reserved(
            &mut self,
            pid: u32,
            ranges: &[(u64, u64)],
            lease: Option<FdLease>,
        ) -> Vec<Result<FileIdentity, String>> {
            let results = self.os.mapped_files_reserved(pid, ranges, lease);
            // The actual OS directory has closed and returned its immediate
            // transient lease before final checks or the next PID can reuse it.
            assert_eq!(self.owner.state_for_test().0[3], 0);
            let trace = self.trace.lock().unwrap();
            assert_eq!(trace.opened, trace.closed);
            results
        }
        fn open(&mut self, _pid: u32) -> Result<Self::Pin, String> {
            std::fs::File::open("/dev/null").map_err(|error| error.to_string())
        }
        fn start_time(&self, _pin: &Self::Pin) -> Option<u64> {
            Some(1)
        }
        fn still_the_same(&self, _pin: &Self::Pin) -> bool {
            true
        }
        fn exe(&self, _pid: u32) -> Option<ExeIdentity> {
            Some(ExeIdentity {
                dev: 1,
                ino: 2,
                mtime_secs: 3,
                mtime_nanos: 0,
                path: None,
            })
        }
        fn maps(
            &mut self,
            pid: u32,
            budget: &mut CaptureWorkBudget,
        ) -> Result<Vec<MapEntry>, String> {
            read_maps_or_refuse(self.open_maps(pid).unwrap(), budget, || self.maps_now())
        }
        fn gone(&self, _pid: u32) -> bool {
            false
        }
    }

    impl ShardableIo for AdapterIo<'_> {
        type Maps = std::io::Cursor<Vec<u8>>;
        fn open_maps(&mut self, _pid: u32) -> std::io::Result<Self::Maps> {
            Ok(std::io::Cursor::new(self.text.as_ref().clone()))
        }
        fn maps_now(&self) -> Option<u64> {
            Some(1)
        }
    }

    struct Held;
    impl ObjectChecks for Held {
        fn nonunique_inodes(&self, _: PinnedObjectId) -> Result<Option<&'static str>, String> {
            Ok(None)
        }
        fn unchanged(&self, _: PinnedObjectId) -> Result<bool, String> {
            Ok(true)
        }
        fn mapped_identity(&self, _: PinnedObjectId) -> Result<MappedFile, String> {
            Ok(MappedFile {
                identity: FileIdentity { dev: 37, ino: 7001 },
                fs_magic: Some(0x01021994),
            })
        }
    }

    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn d3a_r2_immediate_adapter_preserves_proof_pool() {
        let child = Child(
            std::process::Command::new("sleep")
                .arg("30")
                .die_with_parent()
                .spawn()
                .unwrap(),
        );
        let mut pids = [std::process::id(), child.0.id()];
        pids.sort_unstable();
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 7001,
        };
        let object = PinnedObjectId(1);
        let (index, refused) = KnownKeyIndex::build(
            [(key, Some(object))],
            &BTreeMap::from([(key, object)]),
            [],
            &Held,
        );
        assert!(refused.is_empty());
        for (headroom, oversized) in [(3, false), (4, false), (5, false), (9, true)] {
            for count in [
                MIN_PARALLEL_BATCH - 1,
                MIN_PARALLEL_BATCH,
                MIN_PARALLEL_BATCH + 1,
            ] {
                // Odd range ends cannot name a Linux VMA. The production OS
                // proof reads therefore return exact ENOENT negatives without
                // privilege or reliance on any provider's installed behavior.
                let text: Vec<u8> = (0..count)
                    .map(|i| {
                        let start = 0x6000_0000_0000u64 + (i as u64) * 0x2000;
                        format!(
                            "{start:x}-{:x} r-xp 00000000 08:01 7001 /usr/lib/provider.so\n",
                            start + 0x1001
                        )
                    })
                    .collect::<String>()
                    .into_bytes();
                let text = Arc::new(text);
                let entries = p11scope_manifest::maps::parse_maps(text.as_slice()).unwrap();
                let sweep: Vec<_> = pids.iter().map(|&pid| (pid, entries.clone())).collect();
                let mut policy = SegmentPolicy::from_headroom(headroom, 4, sweep.len());
                if oversized {
                    assert_eq!((policy.workers, policy.retained), (2, 2));
                    policy.max_ranges = 0;
                } else {
                    assert_eq!((policy.workers, policy.retained), (0, 0));
                }
                let mut oracle = None;
                for proof_threads in [1, 4] {
                    let owner = ReservationOwner::new(policy);
                    let trace = Arc::new(Mutex::new(ProofTrace::default()));
                    let mut budget = CaptureWorkBudget::default();
                    let out = with_confirmation_pools(4, policy, proof_threads, |pools| {
                        if oversized {
                            assert!(
                                pools.batch.is_none(),
                                "parallel batch must not nest a range pool"
                            );
                        }
                        let make_io = || {
                            assert_eq!(
                                owner.state_for_test().0,
                                [0; 4],
                                "previous immediate envelope still held"
                            );
                            let trace_state = trace.lock().unwrap();
                            assert_eq!(trace_state.opened, trace_state.closed);
                            drop(trace_state);
                            AdapterIo {
                                os: OsConfirmIo::with_pools(pools).observing(trace.clone()),
                                text: text.clone(),
                                trace: trace.clone(),
                                owner: owner.clone(),
                            }
                        };
                        // Serial preparation makes the rejected oversized
                        // record's destruction fence directly observable.
                        attribute_unselected_with_policy(
                            &sweep,
                            &BTreeSet::new(),
                            &BTreeSet::new(),
                            &index,
                            &mut budget,
                            policy,
                            &owner,
                            if oversized { 1 } else { 4 },
                            &make_io,
                        )
                    });
                    assert!(out.members.is_empty());
                    assert_eq!(out.probed, 2);
                    assert_eq!(out.member_losses.keys().copied().collect::<Vec<_>>(), pids);
                    assert!(
                        out.member_losses
                            .values()
                            .all(|(loss, _)| *loss == AttributionLoss::MappingChanged)
                    );
                    assert!(out.unexamined_objects.is_empty());
                    let state = budget.confirm_state_for_test();
                    assert_eq!(state.1, (2 * count) as u64);
                    assert_eq!(state.0.attempted_io_bytes, (2 * text.len()) as u64);
                    assert_eq!(state.0.stop, None);
                    assert!(!state.0.stop_reported);
                    if let Some((expected, expected_state)) = &oracle {
                        assert_eq!(&out, expected);
                        assert_eq!(&state, expected_state);
                    } else {
                        oracle = Some((out, state));
                    }
                    let trace = trace.lock().unwrap();
                    assert_eq!(trace.opened, 2);
                    assert_eq!(trace.closed, 2);
                    let mut requests: Vec<_> = trace
                        .reads
                        .iter()
                        .map(|&(pid, start, end, _, _)| (pid, start, end))
                        .collect();
                    requests.sort_unstable();
                    let expected: Vec<_> = pids
                        .iter()
                        .flat_map(|&pid| {
                            entries
                                .iter()
                                .map(move |entry| (pid, entry.start, entry.end))
                        })
                        .collect();
                    assert_eq!(requests, expected);
                    let threads: HashSet<_> = trace.reads.iter().map(|read| read.3).collect();
                    if proof_threads > 1 && count >= MIN_PARALLEL_BATCH {
                        assert!(
                            threads.len() > 1,
                            "H={headroom}: population shards discarded the immediate proof pool"
                        );
                        assert!(trace.reads.iter().any(|read| {
                            read.4
                                .as_deref()
                                .is_some_and(|name| name.starts_with("p11scope-proof-"))
                        }));
                    } else {
                        assert_eq!(threads, HashSet::from([std::thread::current().id()]));
                    }
                    assert_eq!(owner.state_for_test().0, [0; 4]);
                    assert_eq!(owner.state_for_test().1[2], 1);
                    assert_eq!(owner.state_for_test().1[3], 2);
                    assert_eq!(owner.state_for_test().2, 3);
                }
            }
        }
    }
}

/// Privileged kernel-identity cells: real production checks against
/// the running kernel (never fixtures), classified per release lane.
#[cfg(test)]
mod privileged_tests {
    use super::{
        IdentityBackend, IdentityBtf, IdentityChecks, IdentityNumbering, IdentityRunShared,
        IdentityShared, IdentitySummary, IdentityUnavailable, LiveIdentityChecks, PassAttempt,
        decide_pass_attempt,
    };
    use crate::attach::identity_iter::{
        self, BTF_KIND_ENUM, BTF_KIND_FUNC, TASK_ITER_ATTACH_FUNC, TASK_ITER_TYPE_ENUM,
        TASK_VMA_INFO_MM_MEMBER, TASK_VMA_INFO_STRUCT,
    };
    use crate::cli::IdentityBackendSelection;
    use std::os::fd::AsFd as _;

    /// The 5.15 identity-denial cell: the real BTF named-fix refusal,
    /// disclosed through the production sink with zero `bpf()` calls through
    /// the instrumented identity-iterator wrapper (that counter covers only
    /// the wrapper, not aya or other raw `bpf()` sites).
    ///
    /// Dual-outcome by running kernel, never vacuous: on a kernel whose
    /// BTF lacks the `mm` fix (the 5.15 guest) the direct scan AND the
    /// live sink must agree on `FixMissing`, the production auto-selection
    /// path must stay userspace with `fallback: kernel_fix_missing`, and
    /// the instrumented wrapper on the path must see zero `bpf()` calls. On an eligible
    /// kernel the scan AND the sink must agree on success with the same
    /// zero-call instrumented selection. Any scan/sink disagreement, any unexpected
    /// deny arm, or any missing BTF fails loudly: a fabricated or partial
    /// denial can never print the marker. The release contract classifies
    /// the marker per lane (denial required on 5.15, eligible elsewhere).
    /// Run as root with `--ignored`, one test per process.
    #[test]
    #[ignore = "privileged: real kernel BTF identity-denial disclosure; lane-classified"]
    fn privileged_identity_515_denial_is_disclosed() {
        // Real BTF of the RUNNING kernel: no fixtures, no release strings.
        let raw = identity_iter::read_vmlinux_btf()
            .expect("the denial cell needs the running kernel's BTF");
        let scan_bytes = raw.len();
        assert!(scan_bytes > 0, "empty BTF proves nothing");
        let mm_present = identity_iter::btf_has_struct_member(
            &raw,
            TASK_VMA_INFO_STRUCT,
            TASK_VMA_INFO_MM_MEMBER,
        )
        .expect("the named-fix fact must scan, not error");
        let attach = identity_iter::btf_has_named_type(&raw, BTF_KIND_FUNC, TASK_ITER_ATTACH_FUNC)
            .expect("the attach-func witness must scan, not error");
        let tasktype = identity_iter::btf_has_named_type(&raw, BTF_KIND_ENUM, TASK_ITER_TYPE_ENUM)
            .expect("the task-type witness must scan, not error");
        let direct = identity_iter::check_kernel_identity_btf(&raw);

        // The production auto-selection path with live checks. Numbering
        // must agree: the cell needs an un-namespaced lane, and a
        // numbering refusal must never masquerade as the BTF denial.
        let before = identity_iter::test_bpf_call_count();
        assert_eq!(
            LiveIdentityChecks.numbering(),
            IdentityNumbering::Agree,
            "the cell needs an un-namespaced lane (numbering must agree)"
        );
        let sink = LiveIdentityChecks.btf();
        let shared: IdentityShared = std::sync::Arc::new(std::sync::Mutex::new(
            IdentityRunShared::new(IdentityBackendSelection::Auto, Box::new(LiveIdentityChecks)),
        ));
        let attempt = decide_pass_attempt(&shared, true);
        let summary = shared
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .summary();
        assert_eq!(
            identity_iter::test_bpf_call_count() - before,
            0,
            "selection must issue zero instrumented bpf() calls (identity-iterator wrapper only)"
        );

        match (&direct, sink) {
            (Err(identity_iter::KernelDeny::FixMissing), IdentityBtf::FixMissing) => {
                assert!(
                    !mm_present,
                    "a FixMissing denial requires the mm member absent"
                );
                assert!(
                    matches!(attempt, PassAttempt::Userspace),
                    "denial must stay on the userspace attempt"
                );
                assert_eq!(
                    summary,
                    IdentitySummary {
                        backend: IdentityBackend::Userspace,
                        fallback: Some("kernel_fix_missing".to_string()),
                    },
                    "denial must disclose the finite fallback label"
                );
                assert_eq!(
                    IdentityUnavailable::from_kernel_deny(identity_iter::KernelDeny::FixMissing)
                        .label(),
                    "kernel_fix_missing"
                );
                assert_eq!(
                    summary.json(),
                    serde_json::json!({
                        "backend": "userspace",
                        "fallback": "kernel_fix_missing",
                    }),
                    "observation.identity carries backend + fallback only"
                );
                eprintln!(
                    "IDENTITY_515_DENIAL outcome=denied reason=kernel_fix_missing \
                     mm_present=false attach={attach} tasktype={tasktype} \
                     bpf_delta=0 scan_bytes={scan_bytes} fallback=kernel_fix_missing"
                );
                eprintln!("P11SCOPE_CELL_BRANCH=denied");
            }
            (Ok(_), IdentityBtf::Ok) => {
                assert!(
                    mm_present,
                    "an eligible scan requires the mm member present"
                );
                assert!(
                    matches!(attempt, PassAttempt::Kernel { .. }),
                    "eligibility must reach the kernel attempt"
                );
                assert_eq!(
                    summary,
                    IdentitySummary {
                        backend: IdentityBackend::Userspace,
                        fallback: None,
                    },
                    "unresolved auto selection discloses no fallback"
                );
                eprintln!(
                    "IDENTITY_515_DENIAL outcome=eligible mm_present=true \
                     attach={attach} tasktype={tasktype} bpf_delta=0 \
                     scan_bytes={scan_bytes} sink=ok"
                );
                eprintln!("P11SCOPE_CELL_BRANCH=eligible");
            }
            (direct, sink) => {
                let direct = match direct {
                    Ok(_) => "eligible".to_string(),
                    Err(deny) => format!("denied:{}", deny.label()),
                };
                panic!(
                    "unexpected 5.15-cell arms (direct scan: {direct}, live sink: {sink:?}): \
                     only agreed FixMissing denial or agreed eligible may print the marker; \
                     fabricated or partial denial"
                );
            }
        }

        // Seam-liveness control: one real failing probe advances the
        // counter by exactly one (single-test process, no concurrency).
        let null = std::fs::File::open("/dev/null").expect("open /dev/null");
        assert!(
            identity_iter::link_create_task_vma(null.as_fd(), None).is_err(),
            "link create on /dev/null must fail"
        );
        assert_eq!(
            identity_iter::test_bpf_call_count() - before,
            1,
            "the seam must observe exactly one attempted syscall"
        );
    }
}

#[cfg(test)]
mod refused_filter_tests {
    use super::{count_refused_scans_for_test, retain_refused_to_unselected};
    use crate::discovery::identity::PinnedObjectId;
    use crate::discovery::sweep_attribution::RefusedObject;
    use p11scope_manifest::maps::{Device, MapEntry, ObjectKey};
    use std::collections::BTreeSet;

    fn caller_entry(device: Device, inode: u64) -> MapEntry {
        MapEntry {
            start: 0x1000,
            end: 0x2000,
            file_offset: 0,
            permissions: *b"r-xp",
            device,
            inode,
            raw_path: Some(b"/lib/libfake.so".to_vec()),
        }
    }

    fn noncaller_entry(device: Device, inode: u64) -> MapEntry {
        MapEntry {
            permissions: *b"r--p",
            ..caller_entry(device, inode)
        }
    }

    fn refused_object(object: u32, key: ObjectKey) -> RefusedObject {
        RefusedObject {
            object: PinnedObjectId(object),
            key,
            filesystem: "fuse",
        }
    }

    #[test]
    fn empty_refused_scans_no_sweep_entries() {
        let dev = Device { major: 7, minor: 7 };
        let sweep: Vec<(u32, Vec<MapEntry>)> = vec![
            (1001, vec![caller_entry(dev, 42), caller_entry(dev, 43)]),
            (1002, vec![caller_entry(dev, 42), noncaller_entry(dev, 44)]),
        ];
        let selected = BTreeSet::new();
        let mut refused = Vec::new();
        let ((), scans) = count_refused_scans_for_test(|| {
            retain_refused_to_unselected(&mut refused, &sweep, &selected);
        });
        assert_eq!(scans, 0, "empty refused must skip the sweep scan");
        assert!(refused.is_empty());
    }

    #[test]
    fn nonempty_refused_scans_and_filters_to_unselected_caller_keys() {
        let dev = Device { major: 7, minor: 7 };
        let key = |inode| ObjectKey { device: dev, inode };
        let sweep: Vec<(u32, Vec<MapEntry>)> = vec![
            (1001, vec![caller_entry(dev, 42), caller_entry(dev, 43)]),
            (1002, vec![caller_entry(dev, 42)]),
        ];
        let selected = BTreeSet::new();
        let mut refused = vec![refused_object(1, key(42)), refused_object(2, key(99))];
        let ((), scans) = count_refused_scans_for_test(|| {
            retain_refused_to_unselected(&mut refused, &sweep, &selected);
        });
        assert_eq!(scans, 3, "nonempty refused must scan every entry");
        assert_eq!(refused, vec![refused_object(1, key(42))]);
    }

    #[test]
    fn refused_scan_skips_selected_pids() {
        let dev = Device { major: 7, minor: 7 };
        let key = |inode| ObjectKey { device: dev, inode };
        let sweep: Vec<(u32, Vec<MapEntry>)> = vec![
            (1001, vec![caller_entry(dev, 42), caller_entry(dev, 43)]),
            (1002, vec![caller_entry(dev, 42), noncaller_entry(dev, 44)]),
        ];
        let selected: BTreeSet<u32> = BTreeSet::from([1001]);
        let mut refused = vec![refused_object(1, key(42))];
        let ((), scans) = count_refused_scans_for_test(|| {
            retain_refused_to_unselected(&mut refused, &sweep, &selected);
        });
        assert_eq!(scans, 2, "only unselected entries are scanned");
        assert_eq!(refused, vec![refused_object(1, key(42))]);
    }
}

/// Pins the `take_anchors` flag -> builder wiring at the nearest testable
/// seam: `collect_members_identity` must forward its flag to
/// `build_identity_custody`, so explicit userspace (`false`) gets
/// zero-capacity custody and auto/kernel (`true`) gets full capacity.
/// Capacity is fixed at construction, so the asserts hold unprivileged
/// with zero deep scans (`max_scan_pids = Some(0)`): map_files EPERM can
/// only affect offers, of which there are none. The selection -> flag
/// line in `collect_system_with_identity` still needs the Fedora
/// 2-census/pass floor as its last-mile proof.
#[cfg(test)]
mod take_anchors_wiring_tests {
    use super::{
        CaptureWorkBudget, EXAMINED_ANCHOR_CAP, HookRegistry, StageTimings,
        collect_members_identity,
    };

    #[test]
    fn collect_members_identity_forwards_take_anchors_to_custody_capacity() {
        for take_anchors in [false, true] {
            let mut timings = StageTimings::new();
            let (collection, custody) = collect_members_identity(
                &[],
                &HookRegistry::builtin(),
                Some(0),
                &mut timings,
                true,
                CaptureWorkBudget::default(),
                take_anchors,
                // Cap 0 selects nothing; freshness is moot.
                &std::collections::BTreeSet::new(),
            );
            assert!(
                collection.selected.is_empty(),
                "cap 0 must select nothing (take_anchors={take_anchors})"
            );
            let held = custody.expect("identity scan owns custody");
            assert!(
                !held.failed(),
                "creation census must succeed unprivileged (take_anchors={take_anchors})"
            );
            let expected = if take_anchors { EXAMINED_ANCHOR_CAP } else { 0 };
            assert_eq!(
                held.owner.examined_capacity(),
                expected,
                "take_anchors={take_anchors} must build capacity {expected}"
            );
        }
    }
}
