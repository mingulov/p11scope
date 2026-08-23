//! Initial and incremental provider discovery ownership.

use crate::attach::{
    CapturePolicy, CounterSnapshot, DynamicExportIdentity, OwnedPauseGeneration, Scope, Session,
};
use crate::cli::CaptureArgs;
use crate::discovery::hooks::{HookAbi, HookRegistry};
use crate::discovery::identity::{
    ManifestStaleReason, PinnedObjectId, PinnedObjects, PinnedTimingKey, ReconciledModule,
    StaleManifestObject, bind_scanned_modules, canonicalize_scanned_overlays,
    pin_manifest_objects_deferred_in_views, pin_scanned_view_objects, target_paths_equal,
};
use crate::discovery::loader::{LoaderContextId, LoaderContextSpec, LoaderRegistry};
use crate::discovery::scan::{
    CaptureWorkBudget, ScanOutcome, ScanRequest, ScannedEntry, ScannedInterface, ScannedModule,
    ScannedTable, Skipped, scan_process_view, spans_for,
};
use crate::manifest_input::{read_manifest, validate_structure};
use crate::process::{self, ProcessView, ProcessViewId};
use crate::run::OwnedChild;
use crate::{plan, render};
use anyhow::{Context as _, Result, anyhow, bail};
use p11scope_ebpf_common::{
    DISCOVERY_INTERFACES, DISCOVERY_KIND_EXEC, DISCOVERY_KIND_FUNCTION_LIST_RETURN,
    DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN, DISCOVERY_KIND_INTERFACE_RETURN,
    DISCOVERY_KIND_LEADER_EXIT, DISCOVERY_KIND_LOADER, DISCOVERY_NAME_EXACT_STANDARD,
    DISCOVERY_NAME_NULL, DISCOVERY_NAME_OTHER, DISCOVERY_STATUS_LOADER_CONTEXT_INVALID,
    DiscoveryRecord, valid_discovery_record,
};
use p11scope_manifest::elf::ElfSnapshot;
use p11scope_manifest::manifest::{Manifest, Resolution, SCHEMA};
use p11scope_manifest::maps::{
    Device, MapEntry, MappedPath, ObjectKey, Resolved, parse_maps, resolve,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub struct Engine {
    plan: plan::AttachPlan,
    pinned: PinnedObjects,
    discovery: render::DiscoveryEvidence,
    views: Vec<ProcessView>,
    modules: Vec<ReconciledModule>,
    manifests: Vec<Manifest>,
    counters: DiscoveryCounters,
    identity_mismatches: usize,
    scan_inputs: BTreeMap<ProcessViewId, ScanInput>,
    manifest_inputs: Vec<ManifestInput>,
    base_counters: DiscoveryCounters,
    budget: CaptureWorkBudget,
    next_view_id: u32,
    loader_registry: LoaderRegistry,
    scope: Scope,
    hooks: HookRegistry,
    module_hints: Vec<PathBuf>,
    counter_snapshot: CounterSnapshot,
    malformed_discovery: u64,
    refresh_requested: BTreeSet<u32>,
    loader_records_accepted: u64,
    timings: CausalTimings,
    discovery_truncated: u64,
    pending_rejected_keys: BTreeSet<ObjectKey>,
    pending_retirements: BTreeSet<ProcessViewId>,
}

struct ScanInput {
    modules: Vec<ScannedModule>,
    pins: PinnedObjects,
    counters: DiscoveryCounters,
}

type InventoryScan = (ProcessViewId, Vec<ScannedModule>, PinnedObjects);
type InventoryScanOutcome = (Vec<InventoryScan>, BTreeSet<u32>, Vec<Skipped>);
type PendingViewRetirements = BTreeMap<ProcessViewId, bool>;
type DiscoveryCollector<'a> = dyn FnMut(&mut Session) -> Result<(Vec<DiscoveryRecord>, u64)> + 'a;

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
}

#[derive(Default)]
struct ApplyOutcome {
    committed: bool,
    changed: bool,
    stale_views: BTreeSet<ProcessViewId>,
    missing_contexts: Vec<LoaderContextId>,
    static_completions: Vec<(BTreeSet<PinnedTimingKey>, Option<u64>)>,
    static_failures: BTreeSet<PinnedTimingKey>,
    newly_rejected_keys: BTreeSet<ObjectKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiscoveryBatchOutcome {
    pub(crate) changed: bool,
    pub(crate) required_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordRejection {
    ExportNoRetainedView,
    ExportNoLowerableOwner,
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
            Self::Rejected(_) => false,
        }
    }

    fn required_complete(self) -> bool {
        matches!(
            self,
            Self::Applied {
                required_complete: true,
                ..
            }
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
    fn required_complete(&self) -> bool {
        self.committed
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
}

#[derive(Clone)]
struct QueuedDiscoveryRecord {
    record: DiscoveryRecord,
    terminal_owner: Option<LoaderContextId>,
    terminal_exports: Vec<DynamicExportIdentity>,
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
const MAX_SCAN_PIDS: usize = 256;

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

fn scope_pids(scope: &Scope) -> (Vec<u32>, Vec<Skipped>) {
    let path = match scope {
        Scope::Pid(pid) => return (vec![*pid], Vec::new()),
        Scope::Cgroup { path, .. } => path,
    };
    let mut pids = Vec::new();
    let mut lost = Vec::new();
    let mut stack = vec![path.clone()];
    while let Some(dir) = stack.pop() {
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
                subject: dir.display().to_string(),
                reason: format!(
                    "cgroup.procs could not be read ({error}); no process of this cgroup \
                     was scanned"
                ),
            }),
        }
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                        stack.push(entry.path());
                    }
                }
            }
            // Gone, not hidden — the same rule as above, and the container
            // cgroups this walks churn constantly. A cgroup is only removable
            // once it is empty, so a directory that vanished between its
            // parent's listing and this read held no process to lose.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => lost.push(Skipped {
                subject: dir.display().to_string(),
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

/// What a scope-wide loss is filed under: the cgroup path, or the pid.
fn scope_label(scope: &Scope) -> String {
    match scope {
        Scope::Pid(pid) => format!("pid {pid}"),
        Scope::Cgroup { path, .. } => path.display().to_string(),
    }
}

/// Reads, parses and schema-checks one `--manifest`.
fn read_manifest_file(path: &Path) -> Result<Manifest> {
    let text = read_manifest(path)
        .map_err(|error| anyhow!("reading manifest {}: {error}", path.display()))?;
    let manifest: Manifest = serde_json::from_str(&text)
        .with_context(|| format!("parsing manifest {}", path.display()))?;
    if manifest.schema != SCHEMA {
        bail!(
            "manifest schema mismatch: got {:?}, this build expects {SCHEMA:?}; \
             rerun `p11scope-discover` to rediscover the module",
            manifest.schema
        );
    }
    Ok(manifest)
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
) -> Result<(Vec<ScannedModule>, PinnedObjects)> {
    let outcome = scan_process_view(
        &ScanRequest {
            pid: view.pid(),
            hints,
            hooks,
        },
        view,
        budget,
    )
    .map_err(|error| anyhow!("scanning process view {:?}: {error}", view.id()))?;
    counters.scan_unavailable = counters.scan_unavailable.or(outcome.unavailable_reason());
    let (pinned, pin_skips) = pin_scanned_view_objects(view, outcome.modules(), budget)
        .map_err(|error| anyhow!("pinning process view {:?}: {error}", view.id()))?;
    // Printed *and* kept: an object discovery could not read is a provider that
    // may never have been observed, and a report that only prints it leaves the
    // document claiming a clean capture.
    for skipped in outcome.skipped().iter().chain(&pin_skips) {
        eprintln!(
            "p11scope: discovery skipped {} — {}",
            skipped.subject, skipped.reason
        );
        counters.object_skips.push(skipped.clone());
    }
    let modules = match outcome {
        ScanOutcome::Scanned {
            modules, scan_ms, ..
        } => {
            counters.scan_ms += scan_ms;
            modules
        }
        ScanOutcome::Unavailable { modules, .. } => modules,
    };
    Ok((modules, pinned))
}

/// Discovery for one capture: scan the scope, read and corroborate any manifests,
/// merge into one plan, pin every object, and record how all of it was found.
fn discover_plan(
    a: &CaptureArgs,
    scope: &Scope,
    mut named_view: Option<ProcessView>,
) -> Result<Engine> {
    let mut discovered = Engine::empty();
    discovered.scope = scope.clone();
    discovered.hooks = a.hooks.clone();
    discovered.module_hints = a.modules.clone();
    let (pids, unlisted) = scope_pids(scope);
    discovered.base_counters.object_skips.extend(unlisted);
    // The pid the operator named is the capture; a cgroup's processes are many,
    // however few happen to be in it right now.
    let named = matches!(scope, Scope::Pid(_));
    if pids.len() > MAX_SCAN_PIDS {
        // Published, not just noted: a provider mapped only by a process past the
        // cap is undiscovered, unprobed, and has nothing else to show for it.
        discovered.base_counters.object_skips.push(Skipped {
            subject: scope_label(scope),
            reason: format!(
                "{} processes in scope; discovery scanned the first {MAX_SCAN_PIDS} — a \
                 provider mapped only by one of the rest was never discovered",
                pids.len()
            ),
        });
    }
    for pid in pids.iter().take(MAX_SCAN_PIDS) {
        let opened = if named {
            named_view
                .take()
                .filter(|view| view.pid() == *pid)
                .ok_or_else(|| "named process view was not retained from scope resolution".into())
        } else {
            ProcessView::open(discovered.allocate_view_id()?, *pid)
        };
        let view = match opened {
            Ok(view) => view,
            Err(error) if named => return Err(anyhow!(error)),
            Err(error) => {
                discovered.base_counters.object_skips.push(Skipped {
                    subject: "process view".into(),
                    reason: format!("the process generation could not be pinned: {error}"),
                });
                continue;
            }
        };
        discovered.retain_view_id(view.id())?;
        let mut counters = DiscoveryCounters::default();
        match scan_and_pin(
            &view,
            &a.modules,
            &a.hooks,
            &mut discovered.budget,
            &mut counters,
        ) {
            Ok((found, pins)) => {
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
                eprintln!("p11scope: discovery skipped pid {pid}: {error:#}");
                discovered.base_counters.scan_unavailable = discovered
                    .base_counters
                    .scan_unavailable
                    .or(counters.scan_unavailable);
                discovered.base_counters.scan_ms += counters.scan_ms;
                discovered
                    .base_counters
                    .object_skips
                    .extend(counters.object_skips);
                discovered.base_counters.object_skips.push(Skipped {
                    subject: format!("pid {pid}"),
                    reason: format!("the process could not be scanned: {error:#}"),
                });
            }
        }
    }

    for path in &a.manifests {
        let manifest =
            read_manifest_file(path).inspect_err(|_| discovered.base_counters.report_notes())?;
        let pinning = pin_manifest_objects_deferred_in_views(&manifest, &discovered.views)
            .map_err(|error| {
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
    for refused in &discovered.plan.modules_skipped {
        eprintln!(
            "p11scope: module refused: {} — {}",
            refused.subject, refused.reason
        );
    }
    discovered.counters.report(&discovered.plan);
    Ok(discovered)
}

fn build_current_plan(
    modules: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
    counters: &mut DiscoveryCounters,
    corroborated: &BTreeSet<PinnedObjectId>,
    identity_mismatches: usize,
    manifest_fallbacks: usize,
) -> Result<plan::AttachPlan> {
    // Every plan reference is a capture-local pinned ID. Raw mapping keys remain
    // evidence only and cannot select an attach fd.
    let mut plan = plan::build_from_sources(modules, manifests, pinned);
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
    if let Some(error) = refusal_error(&plan) {
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
    for skip in skips {
        if !plan.skipped.contains(skip) {
            plan.skipped.push(skip.clone());
        }
    }
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
                .filter(|s| s.module_ids.contains(&m.id) && seen.insert(s.object))
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
    let mut counters = discovered.base_counters.clone();
    let mut scan_modules = Vec::new();
    for input in discovered.scan_inputs.values() {
        counters.scan_unavailable = counters
            .scan_unavailable
            .or(input.counters.scan_unavailable);
        counters.scan_ms += input.counters.scan_ms;
        counters
            .object_skips
            .extend(input.counters.object_skips.clone());
        scan_modules.extend(input.modules.clone());
    }
    let (mut pinned, aggregation_skips) =
        PinnedObjects::aggregate_views(discovered.scan_inputs.values().map(|input| &input.pins));
    counters.object_skips.extend(aggregation_skips);
    let (collapsed, overlay_skips) = canonicalize_scanned_overlays(&mut pinned);
    if collapsed > 0 {
        eprintln!(
            "p11scope: discovery: {collapsed} matching overlay mapping(s) were collapsed \
             onto one attach target; physical identity is not provable, so published \
             uncertainty makes this capture PARTIAL"
        );
    }
    counters.object_skips.extend(overlay_skips);
    let mut accepted = Vec::new();
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
            if pending_fallbacks.len() >= p11scope_ebpf_common::MAX_SLOTS as usize {
                bail!(
                    "more than {} stale manifest objects require fallback",
                    p11scope_ebpf_common::MAX_SLOTS
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
                counters
                    .object_skips
                    .extend(pinned.absorb(manifest_pins.clone()));
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
                counters
                    .object_skips
                    .extend(pinned.absorb(manifest_pins.clone()));
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
                counters
                    .object_skips
                    .extend(pinned.absorb(manifest_pins.clone()));
            }
            Corroboration::Uncorroborated => {
                retarget_to_pins(&mut manifest, &[], &pinned, manifest_pins);
                accepted.push(manifest);
                counters
                    .object_skips
                    .extend(pinned.absorb(manifest_pins.clone()));
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

    let (modules, differed) = bind_scanned_modules(&scan_modules, &mut pinned);
    counters.object_skips.extend(differed);
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
    let manifest_fallbacks = counters.manifest_fallbacks.len();
    let plan = build_current_plan(
        &modules,
        &accepted,
        &pinned,
        &mut counters,
        &corroborated,
        identity_mismatches,
        manifest_fallbacks,
    )
    .inspect_err(|_| counters.report_notes())?;
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
    let discovery = discovery_evidence(&plan, &pinned, &counters);
    discovered.plan = plan;
    discovered.pinned = pinned;
    discovered.discovery = discovery;
    discovered.modules = modules;
    discovered.manifests = accepted;
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
    let before = discovered.views.len();
    discovered.views.retain(|view| !stale.contains(&view.id()));
    let removed = before - discovered.views.len();
    if removed == 0 {
        bail!("lifecycle check did not identify an accepted process view");
    }
    for view in stale {
        discovered.scan_inputs.remove(&view);
        discovered.base_counters.object_skips.push(Skipped {
            subject: "process view".into(),
            reason: STALE_VIEW_REASON.into(),
        });
        eprintln!("p11scope: discovery skipped process view — {STALE_VIEW_REASON}");
    }
    rebuild_discovered(discovered)?;
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
    loop {
        let stale = stale_views(&discovered.views);
        if !stale.is_empty() {
            if named {
                bail!("the named process generation changed before attach");
            }
            remove_stale_views(discovered, &stale)?;
            continue;
        }

        let session = start(&discovered.plan, &discovered.pinned)?;
        let stale = stale_views(&discovered.views);
        if stale.is_empty() {
            return Ok(session);
        }
        // No event/map consumer can see this session. Dropping it first tears down
        // every just-created link before stale ownership changes or a retry begins.
        drop(session);
        if named {
            bail!("the named process generation changed while attaching");
        }
        remove_stale_views(discovered, &stale)?;
    }
}

fn export_abi(kind: u8) -> Option<HookAbi> {
    match kind {
        DISCOVERY_KIND_FUNCTION_LIST_RETURN => Some(HookAbi::FunctionList),
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN => Some(HookAbi::InterfaceList),
        DISCOVERY_KIND_INTERFACE_RETURN => Some(HookAbi::Interface),
        _ => None,
    }
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

/// Lowers one already-decoded export record through the same table-layout and
/// mapping authority as the memory scanner. Runtime addresses and custom hook
/// names remain private inputs to the candidate transaction.
fn lower_export_record(
    view: &ProcessView,
    maps: &[MapEntry],
    hooks: &HookRegistry,
    record: &DiscoveryRecord,
    budget: &mut CaptureWorkBudget,
) -> Result<Option<ScannedModule>, String> {
    if !valid_discovery_record(record) {
        return Err("malformed discovery record reached export lowering".into());
    }
    let Some(expected_abi) = export_abi(record.kind) else {
        return Err("non-export discovery record reached export lowering".into());
    };
    let Some((hook_name, abi)) = hooks.by_id(record.symbol_id) else {
        return Err("export record names an unknown private hook ID".into());
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

    let Resolved::File {
        path: MappedPath::Usable(owner_path),
        device: owner_device,
        inode: owner_inode,
        permissions: owner_permissions,
        ..
    } = resolve(maps, record.table_ptr)
    else {
        return Ok(None);
    };
    if owner_inode == 0 || owner_permissions[0] != b'r' {
        return Ok(None);
    }

    let word = u64::from(record.version_major) | (u64::from(record.version_minor) << 8);
    let Some((version, spans, walk)) = spans_for(word) else {
        return Ok(None);
    };
    let usable = usize::from(record.usable_n);
    if usable > spans.iter().map(|span| span.fields().len()).sum() {
        return Ok(None);
    }
    if !budget.admit_table(usable)
        || (matches!(
            record.kind,
            DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN | DISCOVERY_KIND_INTERFACE_RETURN
        ) && !budget.admit_interface())
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
        let Resolved::File {
            path: MappedPath::Usable(path),
            file_offset,
            device,
            inode,
            permissions,
            ..
        } = resolve(maps, pointer)
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
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN | DISCOVERY_KIND_INTERFACE_RETURN => {
            vec![ScannedInterface {
                index: usize::from(record.interface_index),
                name_class: name_class(record.name_class),
                name_lossy: None,
                flags: record.interface_flags,
                table: Some(0),
            }]
        }
        _ => Vec::new(),
    };
    let module = ScannedModule {
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key: ObjectKey {
            device: owner_device,
            inode: owner_inode,
        },
        path: owner_path.display().to_string(),
        exports: vec![hook_name.to_string()],
        tables: vec![ScannedTable {
            version,
            walk,
            entries,
            null_entries,
            unpinned: Vec::new(),
            address: record.table_ptr,
        }],
        interfaces,
    };
    if !view.still_the_same() {
        return Err("process generation changed during export lowering".into());
    }
    Ok(Some(module))
}

fn merge_scanned_module(modules: &mut Vec<ScannedModule>, mut incoming: ScannedModule) {
    let Some(existing) = modules.iter_mut().find(|module| {
        module.view == incoming.view
            && module.mount_namespace == incoming.mount_namespace
            && module.key == incoming.key
            && module.path == incoming.path
    }) else {
        modules.push(incoming);
        return;
    };
    for export in incoming.exports.drain(..) {
        if !existing.exports.contains(&export) {
            existing.exports.push(export);
        }
    }
    let mut table_indices = Vec::new();
    for table in incoming.tables.drain(..) {
        let index = existing.tables.iter().position(|known| *known == table);
        table_indices.push(index.unwrap_or_else(|| {
            existing.tables.push(table);
            existing.tables.len() - 1
        }));
    }
    for mut interface in incoming.interfaces.drain(..) {
        interface.table = interface
            .table
            .and_then(|index| table_indices.get(index).copied());
        if !existing.interfaces.contains(&interface) {
            existing.interfaces.push(interface);
        }
    }
}

fn usable_path(maps: &[MapEntry], mapping: &MapEntry) -> Option<PathBuf> {
    match resolve(maps, mapping.start) {
        Resolved::File {
            path: MappedPath::Usable(path),
            inode,
            ..
        } if inode != 0 => Some(path),
        _ => None,
    }
}

fn exact_executable_mapping(
    maps: &[MapEntry],
    identity: ObjectKey,
) -> Option<(&MapEntry, PathBuf)> {
    maps.iter()
        .filter(|mapping| mapping.permissions[2] == b'x' && ObjectKey::of(mapping) == identity)
        .find_map(|mapping| usable_path(maps, mapping).map(|path| (mapping, path)))
}

fn metadata_object_key(metadata: &std::fs::Metadata) -> ObjectKey {
    use std::os::unix::fs::MetadataExt as _;

    let device = metadata.dev();
    ObjectKey {
        device: Device {
            major: u64::from(libc::major(device)),
            minor: u64::from(libc::minor(device)),
        },
        inode: metadata.ino(),
    }
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
        if !work.already_attached {
            if let Some(module) = &work.module {
                timings.lose(module);
            }
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
    attach: GenerationMutation<Result<bool>>,
) -> OwnedPrearmAttachDisposition {
    match attach {
        GenerationMutation::Committed(Ok(true)) => OwnedPrearmAttachDisposition::Attached,
        GenerationMutation::Committed(Err(error)) => OwnedPrearmAttachDisposition::Unavailable {
            reason: error.to_string(),
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
    OrdinaryFailure,
    GenerationLost {
        changed: bool,
        failure: Option<LoaderArmFailure>,
    },
    Invariant(anyhow::Error),
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
        Err(LoaderArmFailure::Ordinary(_)) => LoaderArmOutcome::OrdinaryFailure,
        Err(LoaderArmFailure::Invariant(error)) => LoaderArmOutcome::Invariant(error),
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

fn terminal_record_for(
    terminal_owner: LoaderContextId,
    terminal_exports: &[DynamicExportIdentity],
    record: DiscoveryRecord,
) -> QueuedDiscoveryRecord {
    let owns_record = record.kind == DISCOVERY_KIND_LOADER
        && LoaderContextId::from_case_id(record.case_id) == terminal_owner;
    QueuedDiscoveryRecord {
        record,
        terminal_owner: owns_record.then_some(terminal_owner),
        terminal_exports: if owns_record {
            terminal_exports.to_vec()
        } else {
            Vec::new()
        },
    }
}

fn mapped_object(view: &ProcessView, mapping: &MapEntry, path: &Path) -> ScannedModule {
    ScannedModule {
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key: ObjectKey::of(mapping),
        path: path.display().to_string(),
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
            views: Vec::new(),
            modules: Vec::new(),
            manifests: Vec::new(),
            counters: DiscoveryCounters::default(),
            identity_mismatches: 0,
            scan_inputs: BTreeMap::new(),
            manifest_inputs: Vec::new(),
            base_counters: DiscoveryCounters::default(),
            budget: CaptureWorkBudget::default(),
            next_view_id: 0,
            loader_registry: LoaderRegistry::default(),
            scope: Scope::Pid(std::process::id()),
            hooks: HookRegistry::builtin(),
            module_hints: Vec::new(),
            counter_snapshot: CounterSnapshot::default(),
            malformed_discovery: 0,
            refresh_requested: BTreeSet::new(),
            loader_records_accepted: 0,
            timings: CausalTimings::default(),
            discovery_truncated: 0,
            pending_rejected_keys: BTreeSet::new(),
            pending_retirements: BTreeSet::new(),
        }
    }

    fn allocate_view_id(&mut self) -> Result<ProcessViewId> {
        if self.next_view_id as usize >= MAX_SCAN_PIDS {
            bail!("capture process-view capacity {MAX_SCAN_PIDS} is exhausted");
        }
        let id = ProcessViewId(self.next_view_id);
        self.next_view_id = self
            .next_view_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("process view ID space exhausted"))?;
        Ok(id)
    }

    fn retain_view_id(&mut self, id: ProcessViewId) -> Result<()> {
        if id.0 as usize >= MAX_SCAN_PIDS {
            bail!("capture process-view capacity {MAX_SCAN_PIDS} is exhausted");
        }
        let next =
            id.0.checked_add(1)
                .ok_or_else(|| anyhow!("process view ID space exhausted"))?;
        self.next_view_id = self.next_view_id.max(next);
        Ok(())
    }

    fn mark_partial(&mut self, subject: &str, reason: &str) {
        let skipped = Skipped {
            subject: subject.into(),
            reason: reason.into(),
        };
        if !self.counters.object_skips.contains(&skipped) {
            self.counters.object_skips.push(skipped);
        }
    }

    fn mark_live_loss(&mut self, subject: &str, reason: &str) {
        self.invalidate_causal_timing();
        self.mark_partial(subject, reason);
    }

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

    fn read_maps(view: &ProcessView) -> Result<Vec<MapEntry>> {
        let pid = view.pid();
        let bytes = view
            .run_while_same(|| std::fs::read(format!("/proc/{pid}/maps")))
            .map_err(anyhow::Error::msg)??;
        parse_maps(&bytes).map_err(anyhow::Error::msg)
    }

    fn collect_discovery_records(session: &mut Session) -> Result<(Vec<DiscoveryRecord>, u64)> {
        let mut records = Vec::new();
        let mut malformed = 0u64;
        while let Some(item) = session.discovery_dequeue()? {
            match item {
                crate::events::DiscoveryItem::Record(record) => records.push(record),
                crate::events::DiscoveryItem::Malformed => {
                    malformed = malformed.saturating_add(1);
                }
            }
        }
        Ok((records, malformed))
    }

    fn record_malformed_discovery(&mut self, malformed: u64) {
        if malformed == 0 {
            return;
        }
        self.malformed_discovery = self.malformed_discovery.saturating_add(malformed);
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
    ) -> Result<(Vec<ScannedModule>, PinnedObjects, DiscoveryCounters)> {
        let mut counters = DiscoveryCounters::default();
        let (modules, pins) = scan_and_pin(view, module_hints, hooks, budget, &mut counters)?;
        Ok((modules, pins, counters))
    }

    fn absorb_scan_counters(&mut self, counters: DiscoveryCounters) -> Vec<Skipped> {
        self.counters.scan_unavailable =
            self.counters.scan_unavailable.or(counters.scan_unavailable);
        self.counters.scan_ms = self.counters.scan_ms.saturating_add(counters.scan_ms);
        counters.object_skips
    }

    fn live_candidate(
        &mut self,
        mut pinned: PinnedObjects,
        mut raw_modules: Vec<ScannedModule>,
        mut skipped: Vec<Skipped>,
    ) -> Result<LiveCandidate> {
        self.pending_rejected_keys
            .extend(pinned.newly_rejected_keys(&self.pinned));
        let (_, overlay_skips) = canonicalize_scanned_overlays(&mut pinned);
        skipped.extend(overlay_skips);
        if self.pinned.has_overlay_uncertainty() || pinned.has_overlay_uncertainty() {
            self.invalidate_causal_timing();
        }
        for skip in skipped {
            if !self.counters.object_skips.contains(&skip) {
                self.counters.object_skips.push(skip);
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
        let (modules, binding_skips) = bind_scanned_modules(&raw_modules, &mut pinned);
        for skip in binding_skips {
            if !self.counters.object_skips.contains(&skip) {
                self.counters.object_skips.push(skip);
            }
        }
        let mut rebuilt = self
            .plan
            .rebuild_from_sources(&modules, &self.manifests, &pinned);
        record_object_skips(&mut rebuilt, &self.counters.object_skips);
        let mut candidate_plan = self.plan.clone();
        let delta = candidate_plan
            .extend_exact(rebuilt)
            .map_err(anyhow::Error::msg)?;
        if !candidate_identity_is_complete(&candidate_plan, &modules, &pinned) {
            bail!("live candidate retained an active module or slot without exact pinned identity");
        }
        let module_objects: BTreeSet<_> = candidate_plan
            .modules
            .iter()
            .map(|module| module.object)
            .collect();
        let mut corroboration = self.counters.corroboration.clone();
        let corroboration_before = corroboration.len();
        corroboration.retain(|(objects, _)| {
            !objects.is_empty()
                && objects.iter().all(|object| {
                    module_objects.contains(object) && pinned.summary(*object).is_some()
                })
        });
        let mut manifest_fallbacks = self.counters.manifest_fallbacks.clone();
        let fallback_before = manifest_fallbacks.len();
        manifest_fallbacks.retain(|fallback| {
            pinned.summary(fallback.replacement).is_some()
                && fallback_proof_in_plan(&fallback.proof, &candidate_plan)
        });
        if corroboration.len() != corroboration_before
            || manifest_fallbacks.len() != fallback_before
        {
            self.mark_partial(
                "live discovery evidence",
                "a late identity collision invalidated prior exact fallback or corroboration evidence",
            );
            record_object_skips(&mut candidate_plan, &self.counters.object_skips);
        }
        let views = modules.iter().map(|module| module.scanned.view).collect();
        Ok(LiveCandidate {
            pinned,
            modules,
            plan: candidate_plan,
            delta,
            views,
            corroboration,
            manifest_fallbacks,
        })
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
        let raw_modules = self
            .modules
            .iter()
            .map(|module| module.scanned.clone())
            .collect();
        let mut candidate = self.live_candidate(candidate_pins, raw_modules, skipped)?;
        candidate.views.insert(view);
        let loader = candidate
            .pinned
            .id_for_scanned(loader_module, loader_module.key, &loader_module.path)
            .filter(|candidate_loader| {
                loader_pins.exactly_matches(local_loader, &candidate.pinned, *candidate_loader)
            });
        Ok((candidate, loader))
    }

    fn conservative_candidate(
        &mut self,
        retirements: &BTreeSet<ProcessViewId>,
        keys: &BTreeSet<ObjectKey>,
    ) -> Result<LiveCandidate> {
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
        self.live_candidate(pinned, raw_modules, skipped)
    }

    fn apply_candidate(
        &mut self,
        session: &mut Session,
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
        let targets_ok = preflighted
            || session
                .preflight_targets(&targets, &candidate.pinned)
                .is_ok();
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

        let selected: Vec<_> = candidate
            .delta
            .retire
            .iter()
            .chain(&candidate.delta.replace)
            .cloned()
            .collect();
        let detach_failed = session.detach_slots(&selected).is_err();
        if detach_failed {
            *additions_allowed = false;
            outcome
                .static_failures
                .extend(target_modules.iter().cloned());
        }
        let may_add = *additions_allowed;
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
            let attach = generation_checked_mutation(
                || process_views_are_current(&self.views, extra_views, &candidate_views),
                || session.attach_targets(&candidate.delta.new, &candidate.pinned),
            );
            let (attach, attach_stale) = match attach {
                GenerationMutation::PrecheckFailed => (None, true),
                GenerationMutation::Committed(result) => (Some(result), false),
                GenerationMutation::PostcheckFailed(result) => (Some(result), true),
            };
            generation_lost |= attach_stale;
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
                        if session.detach_slots(&failed_slots).is_err() {
                            *additions_allowed = false;
                            self.mark_partial(
                                "live discovery detach",
                                "a partial new-slot detach failed once and was not retried",
                            );
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
                let (replacement, replacement_stale) = match replacement {
                    GenerationMutation::PrecheckFailed => (None, true),
                    GenerationMutation::Committed(result) => (Some(result), false),
                    GenerationMutation::PostcheckFailed(result) => (Some(result), true),
                };
                generation_lost |= replacement_stale;
                match replacement {
                    Some(Ok((completed, failed_detach))) => {
                        outcome.record_completions(
                            &candidate.delta.replace,
                            &timing_owners,
                            completed,
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
                    None => {}
                }
            } else {
                for slot in &candidate.delta.replace {
                    outcome
                        .static_failures
                        .extend(slot_timing_keys(slot, &timing_owners));
                    candidate.plan.deactivate(slot.index);
                }
            }
            if generation_lost {
                *additions_allowed = false;
            }
        }
        outcome.stale_views = stale_process_views(&self.views, extra_views, &candidate.views);
        if !outcome.stale_views.is_empty() {
            *additions_allowed = false;
            outcome.static_failures.extend(target_modules);
            let mut cleaned_pins = candidate.pinned.clone();
            for view in &outcome.stale_views {
                cleaned_pins.remove_view(*view);
            }
            let cleaned_modules: Vec<_> = candidate
                .modules
                .iter()
                .filter(|module| !outcome.stale_views.contains(&module.scanned.view))
                .cloned()
                .collect();
            let rebuilt = candidate.plan.rebuild_from_sources(
                &cleaned_modules,
                &self.manifests,
                &cleaned_pins,
            );
            let cleanup = candidate
                .plan
                .extend_exact(rebuilt)
                .map_err(anyhow::Error::msg)?;
            let cleanup_slots: Vec<_> = cleanup
                .retire
                .iter()
                .chain(&cleanup.replace)
                .cloned()
                .collect();
            if session.detach_slots(&cleanup_slots).is_err() {
                self.mark_partial(
                    "live discovery detach",
                    "generation loss cleanup had a one-shot detach failure",
                );
            }
            for slot in &cleanup.replace {
                candidate.plan.deactivate(slot.index);
            }
            self.mark_partial(
                "live discovery generation",
                "a process generation changed after link mutation; its targets were retired before context cleanup",
            );
        }
        if !candidate_identity_is_complete(&candidate.plan, &candidate.modules, &candidate.pinned) {
            bail!(
                "live candidate postcheck left an active module or slot without exact pinned identity"
            );
        }
        record_object_skips(&mut candidate.plan, &self.counters.object_skips);
        outcome.changed |= candidate.plan != self.plan;
        self.pinned = candidate.pinned;
        self.modules = candidate.modules;
        self.plan = candidate.plan;
        self.counters.corroboration = candidate.corroboration;
        self.counters.manifest_fallbacks = candidate.manifest_fallbacks;
        self.discovery = discovery_evidence(&self.plan, &self.pinned, &self.counters);
        outcome.committed = true;
        Ok(outcome)
    }

    fn latch_candidate_ambiguity(&mut self, candidate: &plan::AttachPlan) -> bool {
        if !self.plan.latch_ambiguity_from(candidate) {
            return false;
        }
        self.discovery.module_ambiguous = self.plan.module_ambiguous as u64;
        true
    }

    fn update_counter_snapshot(&mut self, session: &Session) -> Result<()> {
        let next = session.counter_snapshot()?;
        if !self.counter_snapshot.replace_with(next) {
            self.invalidate_causal_timing();
            self.mark_partial(
                "live discovery counters",
                "a producer counter decreased; the prior absolute snapshot was retained",
            );
            return Ok(());
        }
        if self.counter_snapshot.ring_loss > 0 {
            self.invalidate_causal_timing();
            self.mark_partial(
                "live discovery transport",
                "the kernel could not reserve one or more private discovery records",
            );
        }
        if self.counter_snapshot.export_state_failures > 0
            || self.counter_snapshot.export_bounded_read_failures > 0
        {
            self.invalidate_causal_timing();
            self.mark_partial(
                "live export discovery",
                "the kernel reported export state or bounded-read failures",
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
        session: &mut Session,
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
            self.refresh_requested.insert(pid);
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
            let maps = Self::read_maps(view)?;
            lower_export_record(view, &maps, &self.hooks, record, &mut self.budget)
        };
        let Some(lowered) = lowered.map_err(|error| anyhow!(error))? else {
            self.mark_live_loss(
                "live export discovery",
                "an export table had no usable exact file-backed owner and prefix",
            );
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::ExportNoLowerableOwner,
            ));
        };
        let (pins, pin_skips) = {
            let view = &self.views[position];
            pin_scanned_view_objects(view, std::slice::from_ref(&lowered), &mut self.budget)
                .map_err(anyhow::Error::msg)?
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
        merge_scanned_module(&mut raw_modules, lowered);
        let mut candidate = self.live_candidate(candidate_pins, raw_modules, skipped)?;
        candidate.views.insert(self.views[position].id());
        let observed = candidate_timing_keys(&candidate, std::slice::from_ref(&observed_module));
        self.observe_causal_timing(&observed, record.hook_ts_ns);
        let outcome = self.apply_candidate(session, candidate, additions_allowed, false, &[])?;
        self.record_apply_timing(&outcome);
        self.queue_apply_outcome(&outcome, pending_views);
        Ok(DiscoveryRecordOutcome::applied(
            outcome.changed,
            outcome.required_complete(),
        ))
    }

    fn process_loader_record(
        &mut self,
        queued: QueuedDiscoveryRecord,
        session: &mut Session,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
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
            self.refresh_requested.insert(pid);
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
        let maps = Self::read_maps(&self.views[position])?;
        let Some(mapping) = maps
            .iter()
            .find(|mapping| (mapping.start..mapping.end).contains(&record.table_ptr))
        else {
            self.reject_loader_record("a loader hook address no longer resolved to a mapping");
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::LoaderMissingMapping,
            ));
        };
        if context.spec.view != self.views[position].id()
            || context
                .spec
                .mapping
                .as_ref()
                .is_some_and(|expected| expected != mapping)
        {
            self.reject_loader_record(
                "a loader hit failed generation, mapping, identity, or hook-IP validation",
            );
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

        let (found, fresh_pins, scan_counters) = Self::scan_retained_view(
            &self.views[position],
            &self.module_hints,
            &self.hooks,
            &mut self.budget,
        )?;
        let mut skipped = self.absorb_scan_counters(scan_counters);
        let export_modules = found.clone();
        let mut candidate_pins = self.pinned.clone();
        skipped.extend(candidate_pins.replace_view_pins(
            self.views[position].id(),
            fresh_pins,
            &[loader],
        ));
        let mut raw_modules: Vec<_> = self
            .modules
            .iter()
            .filter(|module| module.scanned.view != self.views[position].id())
            .map(|module| module.scanned.clone())
            .collect();
        for module in found {
            merge_scanned_module(&mut raw_modules, module);
        }
        let mut candidate = self.live_candidate(candidate_pins, raw_modules, skipped)?;
        candidate.views.insert(self.views[position].id());
        let observed = candidate_timing_keys(&candidate, &export_modules);
        self.observe_causal_timing(&observed, record.hook_ts_ns);
        let dynamic_work = self.collect_dynamic_export_work(
            context_id,
            &export_modules,
            &candidate,
            session,
            terminal_owner.is_some(),
            &terminal_exports,
        );
        let outcome = self.apply_candidate(session, candidate, additions_allowed, false, &[])?;
        self.record_apply_timing(&outcome);
        self.queue_apply_outcome(&outcome, pending_views);
        let changed = outcome.changed;
        let mut required_complete = outcome.required_complete();
        if terminal_owner.is_none() && outcome.committed && outcome.stale_views.is_empty() {
            let (retire, dynamic_complete) = self.attach_export_work(
                self.views[position].id(),
                &dynamic_work,
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
        } else {
            lose_unperformed_dynamic_work(&mut self.timings, &dynamic_work);
        }
        Ok(DiscoveryRecordOutcome::applied(changed, required_complete))
    }

    fn collect_dynamic_export_work(
        &mut self,
        context: LoaderContextId,
        modules: &[ScannedModule],
        candidate: &LiveCandidate,
        session: &Session,
        terminal: bool,
        terminal_exports: &[DynamicExportIdentity],
    ) -> Vec<DynamicExportWork> {
        let mut work = Vec::new();
        for module in modules {
            let Some(object) = candidate
                .pinned
                .id_for_scanned(module, module.key, &module.path)
            else {
                continue;
            };
            let timing_key = candidate.pinned.owned_timing_key(object);
            let snapshot = candidate
                .pinned
                .file_for(object)
                .and_then(|file| ElfSnapshot::read(file).ok());
            for name in &module.exports {
                let Some(abi) = self.hooks.abi(name) else {
                    continue;
                };
                let Some(cookie) = self.hooks.export_cookie(name) else {
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
                work.push(DynamicExportWork {
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
                });
            }
        }
        work
    }

    fn attach_export_work(
        &mut self,
        view: ProcessViewId,
        work: &[DynamicExportWork],
        session: &mut Session,
        additions_allowed: &mut bool,
    ) -> (bool, bool) {
        let Some(pid) = self
            .views
            .iter()
            .find(|candidate| candidate.id() == view)
            .map(ProcessView::pid)
        else {
            lose_unperformed_dynamic_work(&mut self.timings, work);
            return (true, false);
        };
        let mut retire = false;
        let mut complete = true;
        for work in work {
            if work.already_attached {
                continue;
            }
            if !*additions_allowed {
                complete = false;
                if let Some(module) = &work.module {
                    self.timings.lose(module);
                }
                continue;
            }
            let detach_failures = session.detach_failures().len();
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
            match attach {
                GenerationMutation::Committed(Ok((added, completed))) => {
                    if added {
                        if let Some(module) = &work.module {
                            self.complete_causal_timing(
                                &[module.clone()].into_iter().collect(),
                                completed,
                            );
                        }
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
                GenerationMutation::PrecheckFailed | GenerationMutation::PostcheckFailed(_) => {
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
        (retire, complete)
    }

    fn arm_loader_for_view(
        &mut self,
        position: usize,
        session: &mut Session,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> std::result::Result<bool, LoaderArmFailure> {
        let view_id = self.views[position].id();
        if !self.loader_registry.ids_for_view(view_id).is_empty() {
            return Ok(false);
        }
        let maps = Self::read_maps(&self.views[position])?;
        let pid = self.views[position].pid();
        let executable_metadata = self.views[position]
            .run_while_same(|| std::fs::metadata(format!("/proc/{pid}/exe")))
            .map_err(anyhow::Error::msg)?
            .map_err(anyhow::Error::from)?;
        let Some((executable_mapping, executable_path)) =
            exact_executable_mapping(&maps, metadata_object_key(&executable_metadata))
        else {
            self.mark_partial(
                "live loader arming",
                "the retained executable had no fresh matching file-backed executable mapping",
            );
            return Ok(false);
        };
        let executable_module =
            mapped_object(&self.views[position], executable_mapping, &executable_path);
        let (executable_pins, mut skipped) = pin_scanned_view_objects(
            &self.views[position],
            std::slice::from_ref(&executable_module),
            &mut self.budget,
        )
        .map_err(anyhow::Error::msg)?;
        let Some(executable_id) = executable_pins.id_for_scanned(
            &executable_module,
            executable_module.key,
            &executable_module.path,
        ) else {
            self.mark_partial(
                "live loader arming",
                "the retained executable could not be pinned exactly",
            );
            return Ok(false);
        };
        let executable_snapshot = ElfSnapshot::read(
            executable_pins
                .file_for(executable_id)
                .expect("the just-pinned executable has its retained file"),
        )
        .map_err(anyhow::Error::msg)?;
        let Some(interpreter) = executable_snapshot.interpreter() else {
            return Ok(false);
        };
        let interpreter = PathBuf::from(
            std::str::from_utf8(interpreter)
                .map_err(|_| anyhow!("retained executable PT_INTERP is not UTF-8"))?,
        );
        if !interpreter.is_absolute() {
            self.mark_partial(
                "live loader arming",
                "the retained executable PT_INTERP was not an absolute path",
            );
            return Ok(false);
        }
        let interpreter_metadata = self.views[position]
            .run_while_same(|| {
                std::fs::metadata(format!("/proc/{}/root{}", pid, interpreter.display()))
            })
            .map_err(anyhow::Error::msg)?
            .map_err(anyhow::Error::from)?;
        let loader_identity = metadata_object_key(&interpreter_metadata);
        let Some((first_loader_mapping, loader_path)) =
            exact_executable_mapping(&maps, loader_identity)
        else {
            self.mark_partial(
                "live loader arming",
                "PT_INTERP had no fresh matching file-backed executable loader mapping",
            );
            return Ok(false);
        };
        let loader_module =
            mapped_object(&self.views[position], first_loader_mapping, &loader_path);
        let (loader_pins, loader_skips) = pin_scanned_view_objects(
            &self.views[position],
            std::slice::from_ref(&loader_module),
            &mut self.budget,
        )
        .map_err(anyhow::Error::msg)?;
        skipped.extend(loader_skips);
        let Some(local_loader_id) =
            loader_pins.id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        else {
            self.mark_partial(
                "live loader arming",
                "the exact loader mapping could not be pinned",
            );
            return Ok(false);
        };
        let loader_snapshot = ElfSnapshot::read(
            loader_pins
                .file_for(local_loader_id)
                .expect("the just-pinned loader has its retained file"),
        )
        .map_err(anyhow::Error::msg)?;
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
        let Some(loader_mapping) = maps.iter().find(|mapping| {
            if ObjectKey::of(mapping) != loader_identity || mapping.permissions[2] != b'x' {
                return false;
            }
            let len = mapping.end.saturating_sub(mapping.start);
            (mapping.file_offset..mapping.file_offset.saturating_add(len))
                .contains(&hook.file_offset)
        }) else {
            self.mark_partial(
                "live loader arming",
                "_dl_debug_state did not resolve inside the exact executable loader mapping",
            );
            return Ok(false);
        };
        let loader_mapping = loader_mapping.clone();
        let state = loader_snapshot
            .defined_symbol("_r_debug")
            .map_err(anyhow::Error::msg)?;

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
            state,
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
        if !outcome.committed || !outcome.stale_views.is_empty() || !*additions_allowed {
            return Ok(changed);
        }
        let context = self
            .loader_registry
            .prepare(prepared)
            .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
        let attach = generation_checked_mutation(
            || {
                self.views[position].still_the_same()
                    && self.pinned.check_unchanged().unwrap_or(false)
                    && Self::read_maps(&self.views[position])
                        .is_ok_and(|maps| maps.contains(&loader_mapping))
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
            GenerationMutation::Committed(Err(_)) => {
                self.loader_registry
                    .cancel_prepared(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                self.loader_registry
                    .remove(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                self.mark_partial(
                    "live loader arming",
                    "the fixed-purpose loader attachment failed",
                );
                false
            }
            GenerationMutation::PrecheckFailed | GenerationMutation::PostcheckFailed(Err(_)) => {
                self.loader_registry
                    .cancel_prepared(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                self.loader_registry
                    .remove(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                true
            }
        };
        if generation_lost {
            self.mark_live_loss(
                "live loader arming",
                "loader generation, mapping, or pinned identity changed during attach",
            );
            self.queue_stale_views(&[view_id].into_iter().collect(), pending_views);
            if matches!(self.scope, Scope::Pid(_)) {
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
        session: &mut Session,
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
        let loader_metadata = prepared_executable.interpreter_file().metadata()?;
        let loader_module = ScannedModule {
            view: view_id,
            mount_namespace: self.views[position].mount_namespace(),
            key: metadata_object_key(&loader_metadata),
            path: prepared_executable.interpreter().display().to_string(),
            exports: Vec::new(),
            tables: Vec::new(),
            interfaces: Vec::new(),
        };
        let (loader_pins, skipped) = pin_scanned_view_objects(
            &self.views[position],
            std::slice::from_ref(&loader_module),
            &mut self.budget,
        )
        .map_err(anyhow::Error::msg)?;
        let Some(local_loader) =
            loader_pins.id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        else {
            self.mark_partial(
                "owned initial-set discovery",
                "the exact PT_INTERP could not be pinned through the owned child root",
            );
            return Ok(OwnedLoaderPrearmOutcome::Unavailable);
        };
        let loader_snapshot = ElfSnapshot::read(
            loader_pins
                .file_for(local_loader)
                .expect("the just-pinned pre-exec loader has its retained file"),
        )
        .map_err(anyhow::Error::msg)?;
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
        let state = loader_snapshot
            .defined_symbol("_r_debug")
            .map_err(anyhow::Error::msg)?;
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
            state,
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
        if !outcome.committed || !*additions_allowed {
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
        session: &mut Session,
        pending_views: &mut PendingViewRetirements,
        initiating_error: String,
    ) -> Result<OwnedLoaderPrearmOutcome> {
        let mut errors = vec![initiating_error];
        let (terminal_exports, detach_failed) = session.detach_dynamic_context(context);
        if detach_failed {
            errors.push("dynamic loader detach failed".into());
        }
        let drained = begin_owned_prearm_retirement_with(
            &mut self.loader_registry,
            context,
            registry_attached,
            &mut errors,
            || Self::collect_discovery_records(session),
        );
        if let Some((records, malformed)) = drained {
            if malformed != 0 {
                errors.push("malformed discovery record during pre-arm retirement".into());
            }
            self.record_malformed_discovery(malformed);
            if let Err(error) = self.update_counter_snapshot(session) {
                errors.push(format!("post-detach producer snapshot failed: {error:#}"));
            }
            let mut no_additions = false;
            for record in records {
                let queued = terminal_record_for(context, &terminal_exports, record);
                if let Err(error) = self.dispatch_discovery_record(
                    queued,
                    session,
                    &mut no_additions,
                    pending_views,
                ) {
                    errors.push(format!("pre-arm retirement accounting failed: {error:#}"));
                }
            }
        }
        if let Err(error) = self.loader_registry.remove(context) {
            errors.push(error);
        }
        bail!(errors.join("; "))
    }

    fn arm_loader_or_partial(
        &mut self,
        position: usize,
        session: &mut Session,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<bool> {
        let named = matches!(self.scope, Scope::Pid(_));
        let view_id = self.views[position].id();
        let result = self.arm_loader_for_view(position, session, additions_allowed, pending_views);
        let generation_valid = self
            .views
            .get(position)
            .is_some_and(|view| view.id() == view_id && view.still_the_same());
        match loader_arm_outcome(generation_valid, result) {
            LoaderArmOutcome::Changed(changed) => Ok(changed),
            LoaderArmOutcome::OrdinaryFailure => {
                self.invalidate_causal_timing();
                self.mark_partial(
                    "live loader arming",
                    "an existing retained view could not be armed exactly",
                );
                Ok(false)
            }
            LoaderArmOutcome::Invariant(error) => Err(error),
            LoaderArmOutcome::GenerationLost { changed, failure } => {
                self.queue_stale_views(&[view_id].into_iter().collect(), pending_views);
                self.mark_live_loss(
                    "live loader arming",
                    "the process generation changed before the loader-arm postcheck",
                );
                match failure {
                    Some(LoaderArmFailure::Invariant(error)) => Err(error),
                    Some(LoaderArmFailure::Ordinary(error)) if named => Err(error),
                    _ if named => {
                        bail!("the named process generation changed during loader arming")
                    }
                    _ => Ok(changed),
                }
            }
        }
    }

    fn retire_loader_contexts(
        &mut self,
        view: ProcessViewId,
        session: &mut Session,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
    ) -> Result<(bool, bool)> {
        let mut changed = false;
        for context_id in self.loader_registry.ids_for_view(view) {
            let Some(context) = self.loader_registry.context(context_id).cloned() else {
                continue;
            };
            if self.loader_registry.is_tombstoned(context_id) {
                // A prior one-shot retirement reached its terminal state but
                // could not remove the registry entry. Never detach it twice.
            } else if context.was_attached {
                let (terminal_exports, detach_failed) = session.detach_dynamic_context(context_id);
                if detach_failed {
                    closure.fail();
                    *additions_allowed = false;
                    self.mark_partial(
                        "live loader detach",
                        "a one-shot dynamic detach failed; replacement was blocked for this cycle",
                    );
                }
                match begin_attached_retirement_with(&mut self.loader_registry, context_id, || {
                    collect(session)
                }) {
                    Ok(Ok((owned, malformed))) => {
                        if malformed != 0 {
                            closure.fail();
                        }
                        self.record_malformed_discovery(malformed);
                        if self.update_counter_snapshot(session).is_err() {
                            closure.fail();
                            self.mark_live_loss(
                                "live discovery counters",
                                "the post-detach producer snapshot could not be read",
                            );
                        }
                        for record in owned {
                            let queued = terminal_record_for(context_id, &terminal_exports, record);
                            match self.dispatch_discovery_record(
                                queued,
                                session,
                                additions_allowed,
                                pending_views,
                            ) {
                                Ok(outcome) => {
                                    changed |= outcome.changed();
                                    if !outcome.required_complete() {
                                        closure.fail();
                                    }
                                }
                                Err(_) => {
                                    closure.fail();
                                    self.mark_live_loss(
                                        "live discovery record",
                                        "a structurally valid private terminal record failed exact live resolution",
                                    );
                                }
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        closure.fail();
                        self.mark_live_loss(
                            "live loader retirement",
                            "the post-detach private discovery drain failed",
                        );
                    }
                    Err(_) => {
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
            if self.loader_registry.remove(context_id).is_err() {
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

    fn queue_stale_views(
        &mut self,
        stale: &BTreeSet<ProcessViewId>,
        pending_views: &mut PendingViewRetirements,
    ) {
        for view in stale {
            let newly_generation_lost = !*pending_views.entry(*view).or_default();
            pending_views.insert(*view, true);
            if let Some(pid) = self
                .views
                .iter()
                .find(|candidate| candidate.id() == *view)
                .map(ProcessView::pid)
            {
                self.refresh_requested.insert(pid);
            }
            if newly_generation_lost {
                self.mark_live_loss(
                    "live discovery generation",
                    "a retained process generation changed and was scheduled for conservative cleanup",
                );
            }
        }
    }

    fn queue_apply_outcome(
        &mut self,
        outcome: &ApplyOutcome,
        pending_views: &mut PendingViewRetirements,
    ) {
        if outcome.committed {
            self.pending_rejected_keys
                .retain(|key| !outcome.newly_rejected_keys.contains(key));
        } else {
            self.pending_rejected_keys
                .extend(outcome.newly_rejected_keys.iter().copied());
        }
        for context_id in &outcome.missing_contexts {
            let Some(context) = self.loader_registry.context(*context_id) else {
                continue;
            };
            let view = context.spec.view;
            pending_views.entry(view).or_default();
            if let Some(pid) = self
                .views
                .iter()
                .find(|candidate| candidate.id() == view)
                .map(ProcessView::pid)
            {
                self.refresh_requested.insert(pid);
            }
        }
        self.queue_stale_views(&outcome.stale_views, pending_views);
    }

    fn queue_conservative_outcome(
        &mut self,
        outcome: &ApplyOutcome,
        retirements: &BTreeSet<ProcessViewId>,
        rejected_keys: &BTreeSet<ObjectKey>,
        pending_views: &mut PendingViewRetirements,
    ) -> bool {
        self.queue_apply_outcome(outcome, pending_views);
        if outcome.committed {
            self.pending_retirements
                .retain(|view| !retirements.contains(view));
            self.pending_rejected_keys
                .retain(|key| !rejected_keys.contains(key));
        }
        outcome.changed
    }

    fn replay_pending_conservative(
        &mut self,
        session: &mut Session,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> ApplyOutcome {
        let retirements = self.pending_retirements.clone();
        let keys = self.pending_rejected_keys.clone();
        *additions_allowed = false;
        let candidate = match self.conservative_candidate(&retirements, &keys) {
            Ok(candidate) => candidate,
            Err(_) => {
                self.mark_partial(
                    "live discovery transaction",
                    "a pending conservative candidate could not be rebuilt and remains queued",
                );
                return ApplyOutcome::default();
            }
        };
        let outcome = match self.apply_candidate(session, candidate, additions_allowed, false, &[])
        {
            Ok(outcome) => outcome,
            Err(_) => {
                self.mark_partial(
                    "live discovery transaction",
                    "a pending conservative candidate could not be applied and remains queued",
                );
                return ApplyOutcome::default();
            }
        };
        self.record_apply_timing(&outcome);
        self.queue_conservative_outcome(&outcome, &retirements, &keys, pending_views);
        outcome
    }

    fn dispatch_discovery_record(
        &mut self,
        queued: QueuedDiscoveryRecord,
        session: &mut Session,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<DiscoveryRecordOutcome> {
        let record = queued.record;
        match record.kind {
            DISCOVERY_KIND_FUNCTION_LIST_RETURN
            | DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN
            | DISCOVERY_KIND_INTERFACE_RETURN => {
                self.process_export_record(&record, session, additions_allowed, pending_views)
            }
            DISCOVERY_KIND_LOADER => {
                self.process_loader_record(queued, session, additions_allowed, pending_views)
            }
            DISCOVERY_KIND_EXEC | DISCOVERY_KIND_LEADER_EXIT => {
                let pid = (record.pid_tgid >> 32) as u32;
                self.refresh_requested.insert(pid);
                if let Some(view) = self
                    .views
                    .iter()
                    .find(|view| view.pid() == pid)
                    .map(ProcessView::id)
                {
                    self.queue_stale_views(&[view].into_iter().collect(), pending_views);
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

    fn process_discovery_records(
        &mut self,
        session: &mut Session,
        records: &mut Vec<QueuedDiscoveryRecord>,
        pending_views: &mut PendingViewRetirements,
        additions_allowed: &mut bool,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
    ) -> Result<bool> {
        let mut changed = false;
        let mut named_generation_lost = false;
        let mut conservative_replay_attempted = false;
        loop {
            for queued in std::mem::take(records) {
                match self.dispatch_discovery_record(
                    queued,
                    session,
                    additions_allowed,
                    pending_views,
                ) {
                    Ok(outcome) => {
                        changed |= outcome.changed();
                        if !outcome.required_complete() {
                            closure.fail();
                        }
                    }
                    Err(_) => {
                        closure.fail();
                        self.mark_live_loss(
                            "live discovery record",
                            "a structurally valid private record failed exact live resolution",
                        );
                    }
                }
            }
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
                changed |= outcome.changed;
                if !outcome.committed && pending_views.is_empty() {
                    break;
                }
            }
            for (view, mut generation_lost) in std::mem::take(pending_views) {
                generation_lost |= pending_views.remove(&view).unwrap_or(false);
                let (retirement_changed, complete) = self.retire_loader_contexts(
                    view,
                    session,
                    additions_allowed,
                    pending_views,
                    collect,
                    closure,
                )?;
                generation_lost |= pending_views.remove(&view).unwrap_or(false);
                named_generation_lost |= generation_lost && matches!(self.scope, Scope::Pid(_));
                changed |= retirement_changed;
                if !complete {
                    continue;
                }
                self.pending_retirements.insert(view);
                conservative_replay_attempted = false;
            }
        }
        if named_generation_lost {
            bail!("the named process generation changed during live discovery");
        }
        Ok(changed)
    }

    fn scan_inventory_views(
        &mut self,
        views: &BTreeSet<ProcessViewId>,
        failure: &str,
    ) -> InventoryScanOutcome {
        let mut scans = Vec::new();
        let mut failed_pids = BTreeSet::new();
        let mut skipped = Vec::new();
        for view_id in views {
            let position = self
                .views
                .iter()
                .position(|view| view.id() == *view_id)
                .expect("inventory view remains retained");
            match Self::scan_retained_view(
                &self.views[position],
                &self.module_hints,
                &self.hooks,
                &mut self.budget,
            ) {
                Ok((modules, pins, counters)) => {
                    skipped.extend(self.absorb_scan_counters(counters));
                    scans.push((*view_id, modules, pins));
                }
                Err(error) => {
                    failed_pids.insert(self.views[position].pid());
                    skipped.push(Skipped {
                        subject: "process view".into(),
                        reason: format!("{failure}: {error:#}"),
                    });
                }
            }
        }
        (scans, failed_pids, skipped)
    }

    fn inventory_candidate(
        &mut self,
        removed: &BTreeSet<ProcessViewId>,
        refreshed: &[(ProcessViewId, Vec<ScannedModule>, PinnedObjects)],
        new_views: &[(ProcessView, Vec<ScannedModule>, PinnedObjects)],
        mut skipped: Vec<Skipped>,
    ) -> Result<LiveCandidate> {
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
        let mut candidate = self.live_candidate(candidate_pins, raw_modules, skipped)?;
        candidate
            .views
            .extend(new_views.iter().map(|(view, _, _)| view.id()));
        Ok(candidate)
    }

    fn inventory_candidate_admission(
        &self,
        session: &Session,
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

    fn refresh_inventory(
        &mut self,
        session: &mut Session,
        additions_allowed: &mut bool,
        records: &mut Vec<QueuedDiscoveryRecord>,
        pending_views: &mut PendingViewRetirements,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
    ) -> Result<bool> {
        if matches!(self.scope, Scope::Pid(_)) {
            let stale: BTreeSet<_> = self
                .views
                .iter()
                .filter(|view| !view.still_the_same())
                .map(ProcessView::id)
                .collect();
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
        let (pids, mut skipped) = scope_pids(&self.scope);
        if pids.len() > MAX_SCAN_PIDS {
            skipped.push(Skipped {
                subject: scope_label(&self.scope),
                reason: format!(
                    "{} processes in scope; live discovery scanned the first {MAX_SCAN_PIDS}",
                    pids.len()
                ),
            });
        }
        let desired: BTreeSet<_> = pids.into_iter().take(MAX_SCAN_PIDS).collect();
        let mut removed: BTreeSet<_> = self
            .views
            .iter()
            .filter(|view| {
                !view.still_the_same()
                    || (matches!(self.scope, Scope::Cgroup { .. })
                        && !desired.contains(&view.pid()))
            })
            .map(ProcessView::id)
            .collect();
        let refreshed: BTreeSet<_> = self
            .views
            .iter()
            .filter(|view| {
                !removed.contains(&view.id()) && self.refresh_requested.contains(&view.pid())
            })
            .map(ProcessView::id)
            .collect();
        let known_pids: BTreeSet<_> = self
            .views
            .iter()
            .filter(|view| !removed.contains(&view.id()))
            .map(ProcessView::pid)
            .collect();
        let new_pids: Vec<_> = desired.difference(&known_pids).copied().collect();
        if removed.is_empty() && refreshed.is_empty() && new_pids.is_empty() {
            self.refresh_requested.clear();
            for skip in skipped {
                self.mark_partial(&skip.subject, &skip.reason);
            }
            return Ok(false);
        }

        let (mut refreshed_scans, mut failed_refresh_pids, refresh_skips) =
            self.scan_inventory_views(&refreshed, "a requested inventory refresh failed");
        skipped.extend(refresh_skips);

        let mut new_views = Vec::new();
        for pid in new_pids {
            let id = match self.allocate_view_id() {
                Ok(id) => id,
                Err(_) => {
                    skipped.push(Skipped {
                        subject: "process view".into(),
                        reason: format!(
                            "capture process-view capacity {MAX_SCAN_PIDS} was exhausted; remaining generations were not scanned"
                        ),
                    });
                    break;
                }
            };
            let view = match ProcessView::open(id, pid) {
                Ok(view) => view,
                Err(error) => {
                    failed_refresh_pids.insert(pid);
                    skipped.push(Skipped {
                        subject: format!("pid {pid}"),
                        reason: format!("the process generation could not be retained: {error}"),
                    });
                    continue;
                }
            };
            match Self::scan_retained_view(&view, &self.module_hints, &self.hooks, &mut self.budget)
            {
                Ok((modules, pins, counters)) => {
                    skipped.extend(self.absorb_scan_counters(counters));
                    new_views.push((view, modules, pins));
                }
                Err(error) => {
                    failed_refresh_pids.insert(pid);
                    skipped.push(Skipped {
                        subject: format!("pid {pid}"),
                        reason: format!("the process generation could not be scanned: {error:#}"),
                    });
                }
            }
        }

        for (view, _, _) in &new_views {
            if !view.still_the_same() {
                skipped.push(Skipped {
                    subject: "process view".into(),
                    reason: STALE_VIEW_REASON.into(),
                });
            }
        }
        let mut refreshed_ok: BTreeSet<_> =
            refreshed_scans.iter().map(|(view, _, _)| *view).collect();
        let candidate =
            self.inventory_candidate(&removed, &refreshed_scans, &new_views, skipped.clone())?;
        let admission =
            self.inventory_candidate_admission(session, &candidate, &removed, &new_views);
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
            self.queue_stale_views(&retained_stale, pending_views);
            for (view, _, _) in &new_views {
                if admission.stale_views.contains(&view.id()) {
                    self.refresh_requested.insert(view.pid());
                    failed_refresh_pids.insert(view.pid());
                }
            }
            self.mark_live_loss(
                "live inventory generation",
                "an exact retained or newly opened process generation changed during inventory preflight",
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
                self.refresh_requested.insert(pid);
            }
        }

        let mut mutation_started = false;
        let mut failed_retirements = BTreeSet::new();
        let mut context_retirements = BTreeSet::new();
        let retirement_views: BTreeSet<_> = removed.union(&refreshed_ok).copied().collect();
        for view in &retirement_views {
            if !self.loader_registry.ids_for_view(*view).is_empty() {
                mutation_started = true;
                context_retirements.insert(*view);
            }
            let (retirement_changed, complete) = self.retire_loader_contexts(
                *view,
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
                    self.refresh_requested.insert(pid);
                }
            }
        }
        removed.retain(|view| !failed_retirements.contains(view));
        refreshed_ok.retain(|view| !failed_retirements.contains(view));
        let completed_retirements =
            completed_retirement_intent(&removed, &context_retirements, &failed_retirements);
        self.pending_retirements
            .extend(completed_retirements.iter().copied());
        changed |= self.process_discovery_records(
            session,
            records,
            pending_views,
            additions_allowed,
            collect,
            closure,
        )?;
        if !self.pending_retirements.is_empty() || !self.pending_rejected_keys.is_empty() {
            self.mark_partial(
                "live inventory transaction",
                "completed conservative retirement remains queued for a later current-state rebuild",
            );
            return Ok(changed);
        }

        let (rescanned, failed_rescan_pids, rescan_skips) =
            self.scan_inventory_views(&refreshed_ok, "a post-retirement inventory refresh failed");
        failed_refresh_pids.extend(failed_rescan_pids);
        skipped.extend(rescan_skips);
        refreshed_scans = rescanned;
        refreshed_ok = refreshed_scans.iter().map(|(view, _, _)| *view).collect();
        refreshed_ok.retain(|view| !failed_retirements.contains(view));
        refreshed_scans.retain(|(view, _, _)| refreshed_ok.contains(view));
        let candidate =
            self.inventory_candidate(&removed, &refreshed_scans, &new_views, skipped)?;
        let admission =
            self.inventory_candidate_admission(session, &candidate, &removed, &new_views);
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
            for (view, _, _) in &new_views {
                if admission.stale_views.contains(&view.id()) {
                    self.refresh_requested.insert(view.pid());
                    failed_refresh_pids.insert(view.pid());
                }
            }
            if !admission.stale_views.is_empty() {
                self.mark_live_loss(
                    "live inventory generation",
                    "an exact retained or newly opened process generation changed during post-retirement preflight",
                );
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
            self.views.retain(|view| !removed.contains(&view.id()));
            for view in removed.iter().chain(&refreshed_ok) {
                self.scan_inputs.remove(view);
            }
            if matches!(self.scope, Scope::Pid(_)) && !outcome.stale_views.is_empty() {
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
        for view in &outcome.stale_views {
            if let Some(pid) = new_views
                .iter()
                .find(|(candidate, _, _)| candidate.id() == *view)
                .map(|(view, _, _)| view.pid())
            {
                self.refresh_requested.insert(pid);
            }
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
        if !outcome.committed || !outcome.stale_views.is_empty() {
            return Ok(changed);
        }

        if conservative_only || !*additions_allowed {
            failed_refresh_pids.extend(retirement_views.iter().filter_map(|view| {
                self.views
                    .iter()
                    .find(|candidate| candidate.id() == *view)
                    .map(ProcessView::pid)
            }));
            failed_refresh_pids.extend(new_views.iter().map(|(view, _, _)| view.pid()));
        }
        self.refresh_requested
            .retain(|pid| failed_refresh_pids.contains(pid));
        let new_view_ids: BTreeSet<_> = if conservative_only {
            BTreeSet::new()
        } else {
            new_views.iter().map(|(view, _, _)| view.id()).collect()
        };
        self.views.retain(|view| !removed.contains(&view.id()));
        if !conservative_only {
            for (view, _, _) in new_views {
                self.views.push(view);
            }
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
                self.arm_loader_or_partial(position, session, additions_allowed, pending_views)
            })
        } else {
            Ok(false)
        };
        let fatal = match arm_result {
            Ok(arm_changed) => {
                changed |= arm_changed;
                None
            }
            Err(error) => Some(error),
        };
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
        Ok(changed)
    }

    /// Drains private discovery records into owned storage, drops the map
    /// borrow, then applies identity/link transactions. Callers synchronize
    /// semantic consumers immediately when this reports a plan change, before
    /// draining the ordinary event ring.
    pub fn drain_discovery(&mut self, session: &mut Session) -> Result<bool> {
        let (records, malformed) = Self::collect_discovery_records(session)?;
        self.apply_discovery_batch(session, records, malformed)
    }

    pub(crate) fn apply_discovery_batch(
        &mut self,
        session: &mut Session,
        records: Vec<DiscoveryRecord>,
        malformed: u64,
    ) -> Result<bool> {
        let mut collect = Self::collect_discovery_records;
        self.apply_discovery_batch_with(session, records, malformed, true, &mut collect)
            .map(|outcome| outcome.changed)
    }

    pub(crate) fn apply_discovery_batch_with(
        &mut self,
        session: &mut Session,
        records: Vec<DiscoveryRecord>,
        malformed: u64,
        additions_allowed: bool,
        collect: &mut DiscoveryCollector<'_>,
    ) -> Result<DiscoveryBatchOutcome> {
        let mut records: Vec<_> = records
            .into_iter()
            .map(|record| QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            })
            .collect();
        self.record_malformed_discovery(malformed);
        self.update_counter_snapshot(session)?;

        let mut additions_allowed = additions_allowed;
        let mut closure = PauseClosure::new(additions_allowed && malformed == 0);
        let mut pending_views = PendingViewRetirements::new();
        let mut changed = self.process_discovery_records(
            session,
            &mut records,
            &mut pending_views,
            &mut additions_allowed,
            collect,
            &mut closure,
        )?;
        if self.pending_retirements.is_empty() && self.pending_rejected_keys.is_empty() {
            changed |= self.refresh_inventory(
                session,
                &mut additions_allowed,
                &mut records,
                &mut pending_views,
                collect,
                &mut closure,
            )?;
        }
        record_object_skips(&mut self.plan, &self.counters.object_skips);
        self.discovery = discovery_evidence(&self.plan, &self.pinned, &self.counters);
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

    /// Private-loader transport failures as finite aggregate counters only.
    pub fn loader_failures(&self) -> (u64, u64) {
        (
            self.loader_registry.discovery_truncated(),
            self.loader_registry.context_failures(),
        )
    }

    pub fn start_session(&mut self, policy: CapturePolicy) -> Result<Session> {
        self.start_session_with(policy, None, None)
    }

    #[allow(dead_code)] // Task 8 invokes this reviewed library-internal route.
    pub(crate) fn start_owned_session(
        &mut self,
        policy: CapturePolicy,
        child: &mut OwnedChild,
    ) -> Result<Session> {
        let generation = OwnedPauseGeneration::from_owned_child(child);
        self.start_session_with(policy, Some(generation), Some(child))
    }

    /// Task 8 calls this only after its coordinator armed the pause epoch and
    /// released the barrier. A changed direct target, shebang, or later exec
    /// chain retires the speculative pre-exec context and uses the ordinary
    /// exact mapped-loader route without upgrading empty-catalog evidence.
    #[allow(dead_code)] // Task 8 invokes this after its pause arm and barrier release.
    pub(crate) fn revalidate_owned_session_with(
        &mut self,
        child: &OwnedChild,
        session: &mut Session,
        collect: &mut DiscoveryCollector<'_>,
    ) -> Result<DiscoveryBatchOutcome> {
        let Some(view) = self
            .views
            .iter()
            .find(|view| view.pid() == child.pid())
            .map(ProcessView::id)
        else {
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
        if direct_stable && !self.loader_registry.ids_for_view(view).is_empty() {
            return Ok(DiscoveryBatchOutcome {
                changed: false,
                required_complete: true,
            });
        }
        if !self.loader_registry.ids_for_view(view).is_empty() {
            let (_, complete) = self.retire_loader_contexts(
                view,
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
        record_object_skips(&mut self.plan, &self.counters.object_skips);
        self.discovery = discovery_evidence(&self.plan, &self.pinned, &self.counters);
        Ok(DiscoveryBatchOutcome {
            changed,
            required_complete: closure.required_complete() && additions_allowed,
        })
    }

    fn start_session_with(
        &mut self,
        policy: CapturePolicy,
        mut pause_generation: Option<OwnedPauseGeneration>,
        owned_child: Option<&OwnedChild>,
    ) -> Result<Session> {
        let retained_scope = self.scope.clone();
        let named = matches!(retained_scope, Scope::Pid(_));
        let scope = &retained_scope;
        let mut session =
            start_retained_with(self, named, process::stale_view_ids, |plan, pinned| {
                Session::start(plan, scope, pinned, policy, pause_generation.take())
            })?;
        let mut additions_allowed = true;
        let mut records = Vec::new();
        let mut pending_views = PendingViewRetirements::new();
        let mut collect = Self::collect_discovery_records;
        let mut closure = PauseClosure::new(true);
        let mut fatal = None;
        if let Some(child) = owned_child {
            let _ = self.arm_owned_loader_before_release(
                child,
                &mut session,
                &mut additions_allowed,
                &mut pending_views,
            )?;
            self.mark_partial(
                "owned initial-set discovery",
                "the empty timing catalog leaves initial-set capture unproven",
            );
        } else {
            for position in 0..self.views.len() {
                if !self.views[position].still_the_same() {
                    continue;
                }
                match self.arm_loader_or_partial(
                    position,
                    &mut session,
                    &mut additions_allowed,
                    &mut pending_views,
                ) {
                    Ok(_) => {}
                    Err(error) => {
                        fatal = Some(error);
                        break;
                    }
                }
            }
        }
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
        self.discovery = discovery_evidence(&self.plan, &self.pinned, &self.counters);
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::identity::test_fixture::{
        SHA as OVERLAY_SHA, module as overlay_module, overlay as overlay_key, pins as overlay_pins,
        view_pin as overlay_view_pin,
    };
    use crate::discovery::identity::{
        ManifestPinError, ManifestStaleReason, PinnedObjectId, ReconciledModule,
        pin_manifest_objects, pin_manifest_objects_deferred, pin_scanned_objects,
        reconcile_scanned_modules,
    };
    use crate::discovery::loader::LoaderContextSpec;
    use crate::discovery::scan::{ScanLimits, ScannedEntry, ScannedTable, scan_pid};
    use crate::{semantics, trace};
    use p11scope_manifest::manifest::{
        Acquisition, AliasEntry, AliasGroup, FunctionRecord, InterfaceClassification,
        SurfaceRecord, SurfaceSource, Version, WalkOutcome,
    };
    use std::cell::Cell;
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;

    fn dynamic_export_work(module: PinnedTimingKey, already_attached: bool) -> DynamicExportWork {
        DynamicExportWork {
            context: LoaderContextId::from_case_id(0),
            module: Some(module),
            object: PinnedObjectId(7),
            file_offset: 0x10,
            cookie: 1,
            abi: HookAbi::FunctionList,
            already_attached,
        }
    }

    fn timing_key(index: usize) -> PinnedTimingKey {
        static KEYS: std::sync::OnceLock<Vec<PinnedTimingKey>> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            let view = ProcessView::open(ProcessViewId(99), std::process::id()).unwrap();
            let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
            let mut keys = Vec::new();
            for mapping in maps
                .iter()
                .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
            {
                let Resolved::File {
                    path: MappedPath::Usable(path),
                    ..
                } = resolve(&maps, mapping.start)
                else {
                    continue;
                };
                let module = mapped_object(&view, mapping, &path);
                let pins = pin_test_module(&view, &module);
                let object = pins
                    .id_for_scanned(&module, module.key, &module.path)
                    .unwrap();
                let key = pins.owned_timing_key(object).unwrap();
                if !keys.contains(&key) {
                    keys.push(key);
                }
                if keys.len() == 3 {
                    break;
                }
            }
            assert_eq!(
                keys.len(),
                3,
                "the test process has three executable objects"
            );
            keys
        })[index]
            .clone()
    }

    #[test]
    fn pause_closure_preserves_real_required_attachment_failure() {
        let failed = timing_key(0);
        let outcome = ApplyOutcome {
            committed: true,
            static_failures: [failed].into_iter().collect(),
            ..ApplyOutcome::default()
        };
        let mut closure = PauseClosure::new(true);

        closure.observe_apply(&outcome);

        assert!(!closure.required_complete());
    }

    #[test]
    fn every_rejected_discovery_record_fails_the_pause_closure() {
        let rejections = [
            RecordRejection::ExportNoRetainedView,
            RecordRejection::ExportNoLowerableOwner,
            RecordRejection::LoaderMissingCounterAuthority,
            RecordRejection::LoaderInvalidContext,
            RecordRejection::LoaderNoRetainedView,
            RecordRejection::LoaderUnknownContext,
            RecordRejection::LoaderMissingMapping,
            RecordRejection::LoaderMismatchedMapping,
            RecordRejection::LoaderPinnedIdentityMismatch,
            RecordRejection::LoaderValidationFailure,
            RecordRejection::UnknownKind,
        ];

        for rejection in rejections {
            let outcome = DiscoveryRecordOutcome::Rejected(rejection);
            assert!(
                !outcome.required_complete(),
                "{rejection:?} must make a pause batch non-confirmable"
            );
        }
    }

    #[test]
    fn loader_retirement_never_owns_an_untimed_session_dequeue() {
        let source = include_str!("engine.rs");
        let retirement = source
            .split_once("    fn retire_loader_contexts(")
            .unwrap()
            .1
            .split_once("    fn queue_stale_views(")
            .unwrap()
            .0;
        assert!(!retirement.contains("Self::collect_discovery_records(session)"));
        assert!(retirement.contains("collect(session)"));
    }

    #[test]
    fn owned_session_prearms_while_exclusively_borrowing_the_unreleased_child() {
        let source = include_str!("engine.rs");
        let owned_entry = source
            .split_once("    pub(crate) fn start_owned_session(")
            .unwrap()
            .1
            .split_once("    pub(crate) fn revalidate_owned_session_with(")
            .unwrap()
            .0;
        assert!(owned_entry.contains("child: &mut OwnedChild"));
        let route = source
            .split_once("    fn start_session_with(")
            .unwrap()
            .1
            .split_once("\n    }\n}")
            .unwrap()
            .0;
        assert!(route.contains("arm_owned_loader_before_release("));
        assert!(!route.contains("child.release()"));
        assert!(source.contains("child.revalidate_after_exec()"));
    }

    fn prepared_loader_registry() -> (LoaderRegistry, LoaderContextId) {
        use p11scope_manifest::elf::SymbolFact;

        let mut registry = LoaderRegistry::default();
        let prepared = registry
            .preflight(LoaderContextSpec {
                view: ProcessViewId(3),
                loader: PinnedObjectId(9),
                mapping: None,
                hook: SymbolFact {
                    virtual_address: 0x2100,
                    file_offset: 0x2100,
                },
                state: None,
            })
            .unwrap();
        let context = registry.prepare(prepared).unwrap();
        (registry, context)
    }

    #[test]
    fn prearm_mark_attached_failure_retires_and_drains_before_reporting() {
        let (mut registry, context) = prepared_loader_registry();
        let order = std::cell::RefCell::new(vec!["detach"]);
        let mut errors = vec!["loader registry mark-attached failed".to_string()];

        let drained =
            begin_owned_prearm_retirement_with(&mut registry, context, false, &mut errors, || {
                order.borrow_mut().push("drain");
                Ok("accounted")
            });

        assert_eq!(*order.borrow(), ["detach", "drain"]);
        assert_eq!(drained, Some("accounted"));
        assert!(registry.is_tombstoned(context));
        assert!(errors.iter().any(|error| error.contains("mark-attached")));
    }

    #[test]
    fn prearm_detach_failure_still_drains_and_remains_lifecycle_fatal() {
        let (mut registry, context) = prepared_loader_registry();
        registry.mark_attached(context).unwrap();
        let mut errors = vec!["dynamic loader detach failed".to_string()];

        let drained =
            begin_owned_prearm_retirement_with(&mut registry, context, true, &mut errors, || {
                Ok("accounted")
            });

        assert_eq!(drained, Some("accounted"));
        assert!(registry.is_tombstoned(context));
        assert!(errors.iter().any(|error| error.contains("detach failed")));
    }

    #[test]
    fn ordinary_prearm_attach_unavailability_is_the_only_fallback() {
        assert!(matches!(
            classify_owned_prearm_attach(GenerationMutation::Committed(Err(anyhow!(
                "kernel loader attach unavailable"
            )))),
            OwnedPrearmAttachDisposition::Unavailable { .. }
        ));
        assert!(matches!(
            classify_owned_prearm_attach(GenerationMutation::PrecheckFailed),
            OwnedPrearmAttachDisposition::Lifecycle {
                producer_exists: false,
                ..
            }
        ));
        assert!(matches!(
            classify_owned_prearm_attach(GenerationMutation::PostcheckFailed(Ok(true))),
            OwnedPrearmAttachDisposition::Lifecycle {
                producer_exists: true,
                ..
            }
        ));
    }

    fn engine_with_overlay(minor: u64) -> (Engine, ScannedModule, PinnedObjectId, PinnedTimingKey) {
        let module = overlay_module(overlay_key(minor));
        let mut pins = overlay_pins(&[(module.key, OVERLAY_SHA, 1)]);
        let object = pins
            .id_for_scanned(&module, module.key, &module.path)
            .unwrap();
        let timing = pins.owned_timing_key(object).unwrap();
        let (modules, skipped) = bind_scanned_modules(std::slice::from_ref(&module), &mut pins);
        assert!(skipped.is_empty(), "{skipped:?}");
        let mut engine = Engine::empty();
        engine.plan = plan::build_from_reconciled_modules(&modules);
        engine.pinned = pins;
        engine.modules = modules;
        (engine, module, object, timing)
    }

    #[test]
    fn interface_truncation_is_recorded_once_for_a_17_entry_invocation() {
        use p11scope_ebpf_common::DISCOVERY_INTERFACES;

        let records: Vec<DiscoveryRecord> = (0..DISCOVERY_INTERFACES)
            .map(|index| {
                let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
                record.kind = DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN;
                record.interface_index = index;
                record.announced_count = u32::from(DISCOVERY_INTERFACES) + 1;
                record
            })
            .collect();

        assert_eq!(
            records
                .iter()
                .filter(|record| interface_list_is_truncated(record))
                .count(),
            1,
            "only index zero owns the finite userspace truncation contribution"
        );
    }

    #[test]
    fn causal_gap_stays_none_after_loss_then_later_record() {
        let module = timing_key(0);
        let mut timings = CausalTimings::default();
        timings.invalidate();
        timings.observe(&module, 20);
        timings.complete(&module, 50);
        assert_eq!(timings.gap_ns(&module), None);

        let mut intact = CausalTimings::default();
        intact.observe(&module, 20);
        intact.observe(&module, 40);
        intact.complete(&module, 50);
        assert_eq!(
            intact.gap_ns(&module),
            Some(30),
            "a later hit cannot replace the first accepted causal timestamp"
        );
    }

    #[test]
    fn causal_timing_does_not_follow_a_reused_candidate_module_id() {
        let first = timing_key(0);
        let second = timing_key(1);
        assert_ne!(first, second);

        let mut timings = CausalTimings::default();
        timings.observe(&first, 10);
        timings.lose(&first);
        timings.observe(&second, 20);
        timings.complete(&second, 30);
        timings.observe(&first, 40);
        timings.complete(&first, 50);

        assert_eq!(timings.gap_ns(&second), Some(10));
        assert_eq!(
            timings.gap_ns(&first),
            None,
            "the refused physical module keeps its loss after reappearance"
        );
    }

    #[test]
    fn live_overlay_peer_keeps_one_stable_slot_without_new_attach_work() {
        let (mut engine, first, original, _) = engine_with_overlay(104);
        let second = overlay_module(overlay_key(102));
        let mut candidate_pins = engine.pinned.clone();
        let skipped = candidate_pins.absorb(overlay_pins(&[(second.key, OVERLAY_SHA, 1)]));

        let candidate = engine
            .live_candidate(candidate_pins, vec![first.clone(), second.clone()], skipped)
            .unwrap();

        assert_eq!(
            candidate
                .pinned
                .id_for_scanned(&first, first.key, &first.path),
            Some(original)
        );
        assert_eq!(
            candidate
                .pinned
                .id_for_scanned(&second, second.key, &second.path),
            Some(original),
            "the later overlay peer must use the already committed canonical ID"
        );
        assert_eq!(candidate.plan.modules.len(), 1);
        assert_eq!(candidate.plan.slots.len(), 1);
        assert!(candidate.delta.new.is_empty());
        assert_eq!(engine.counters.object_skips.len(), 1);
    }

    #[test]
    fn same_key_overlay_uncertainty_keeps_causal_timing_null() {
        let (mut engine, module, _, kept_timing) = engine_with_overlay(102);
        engine.timings.observe(&kept_timing, 10);
        engine.timings.complete(&kept_timing, 20);
        assert_eq!(engine.timings.gap_ns(&kept_timing), Some(10));

        let incoming = overlay_view_pin(&module, 999, OVERLAY_SHA, 1, true);
        let incoming_object = incoming
            .id_for_scanned(&module, module.key, &module.path)
            .unwrap();
        let incoming_timing = incoming.owned_timing_key(incoming_object).unwrap();
        assert_ne!(kept_timing, incoming_timing);
        let mut candidate_pins = engine.pinned.clone();
        let skipped = candidate_pins.absorb(incoming);
        assert_eq!(skipped.len(), 1, "the accepted heuristic stays explicit");

        let candidate = engine
            .live_candidate(candidate_pins, vec![module.clone()], skipped)
            .unwrap();
        let observed = candidate_timing_keys(&candidate, std::slice::from_ref(&module));
        engine.observe_causal_timing(&observed, 30);
        engine.complete_causal_timing(&observed, Some(40));
        engine.timings.observe(&incoming_timing, 35);
        engine.timings.complete(&incoming_timing, 45);

        assert_eq!(engine.timings.gap_ns(&kept_timing), None);
        assert_eq!(engine.timings.gap_ns(&incoming_timing), None);
    }

    #[test]
    fn causal_completion_tracks_the_last_new_required_attachment() {
        let module = timing_key(0);
        let mut timings = CausalTimings::default();
        timings.observe(&module, 10);
        timings.complete(&module, 12);
        timings.observe(&module, 20);
        timings.complete(&module, 25);

        assert_eq!(
            timings.gap_ns(&module),
            Some(15),
            "completion advances after later genuinely new required work"
        );
    }

    #[test]
    fn accepted_causal_observation_is_independent_from_candidate_work() {
        let (raw_modules, mut pinned) = pinned_self();
        let modules = reconcile_for_test(&raw_modules, &mut pinned);
        let mut engine = Engine::empty();
        engine.plan = plan::build_from_reconciled_modules(&modules);
        engine.pinned = pinned;
        engine.modules = modules;
        let candidate = engine
            .live_candidate(engine.pinned.clone(), raw_modules.clone(), Vec::new())
            .unwrap();

        assert!(candidate.delta.new.is_empty());
        assert!(candidate.delta.replace.is_empty());
        let observed = candidate_timing_keys(&candidate, &raw_modules);
        assert_eq!(observed.len(), 1, "the stable duplicate still has an owner");
        engine.observe_causal_timing(&observed, 10);
        assert_eq!(engine.timings.gap_ns(observed.first().unwrap()), None);

        engine.observe_causal_timing(&observed, 30);
        engine.record_apply_timing(&ApplyOutcome {
            static_completions: vec![(observed.clone(), Some(40))],
            ..ApplyOutcome::default()
        });
        assert_eq!(
            engine.timings.gap_ns(observed.first().unwrap()),
            Some(30),
            "later work keeps the earlier accepted observation"
        );
        engine.observe_causal_timing(&observed, 50);
        assert_eq!(engine.timings.gap_ns(observed.first().unwrap()), Some(30));
        engine.invalidate_causal_timing();
        engine.observe_causal_timing(&observed, 60);
        engine.complete_causal_timing(&observed, Some(70));
        assert_eq!(engine.timings.gap_ns(observed.first().unwrap()), None);
    }

    #[test]
    fn each_module_uses_its_own_immediate_attach_completion() {
        let first = timing_key(0);
        let second = timing_key(1);
        let mut engine = Engine::empty();
        engine.timings.observe(&first, 10);
        engine.timings.observe(&second, 10);
        engine.complete_causal_timing(&[first.clone()].into_iter().collect(), Some(20));
        engine.complete_causal_timing(&[second.clone()].into_iter().collect(), Some(35));

        assert_eq!(engine.timings.gap_ns(&first), Some(10));
        assert_eq!(engine.timings.gap_ns(&second), Some(25));
    }

    #[test]
    fn generation_precheck_reports_exact_missing_view_ids() {
        let current = ProcessView::open(ProcessViewId(2), std::process::id()).unwrap();
        let expected: BTreeSet<_> = [ProcessViewId(9)].into_iter().collect();
        let requested: BTreeSet<_> = [current.id(), ProcessViewId(9)].into_iter().collect();

        assert_eq!(
            stale_process_views(&[current], &[], &requested),
            expected,
            "callers need the exact stale identity for terminal cleanup and refresh"
        );
    }

    #[test]
    fn apply_outcome_keeps_static_timing_and_generation_loss_ownership() {
        let completed = timing_key(0);
        let failed = timing_key(1);
        let stale = ProcessViewId(9);
        let mut engine = Engine::empty();
        engine.timings.observe(&completed, 10);
        engine.timings.observe(&failed, 10);
        let outcome = ApplyOutcome {
            committed: true,
            changed: true,
            stale_views: [stale].into_iter().collect(),
            missing_contexts: Vec::new(),
            static_completions: vec![([completed.clone()].into_iter().collect(), Some(20))],
            static_failures: [failed.clone()].into_iter().collect(),
            newly_rejected_keys: BTreeSet::new(),
        };

        engine.record_apply_timing(&outcome);

        assert_eq!(engine.timings.gap_ns(&completed), Some(10));
        assert_eq!(engine.timings.gap_ns(&failed), None);
        assert_eq!(outcome.stale_views, [stale].into_iter().collect());
        assert!(outcome.committed && outcome.changed);
    }

    #[test]
    fn closed_additions_gate_loses_every_unperformed_exact_owner() {
        let first_id = plan::ModuleId(3);
        let second_id = plan::ModuleId(4);
        let first = timing_key(0);
        let second = timing_key(1);
        let duplicate = timing_key(2);
        let slots = vec![
            plan::Slot {
                index: 0,
                descriptor_index: 0,
                object: PinnedObjectId(7),
                object_path: "/opt/first.so".into(),
                file_offset: 0x10,
                names: vec!["C_Sign".into()],
                aliased: false,
                semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
                semantic_authorized: false,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![first_id],
            },
            plan::Slot {
                index: 1,
                descriptor_index: 0,
                object: PinnedObjectId(8),
                object_path: "/opt/second.so".into(),
                file_offset: 0x20,
                names: vec!["C_Verify".into()],
                aliased: false,
                semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
                semantic_authorized: false,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![second_id],
            },
        ];
        let delta = plan::AttachDelta {
            new: vec![slots[0].clone()],
            replace: vec![slots[1].clone()],
            retire: Vec::new(),
        };
        let mut candidate_plan = plan::AttachPlan::from_slots(slots);
        let mut outcome = ApplyOutcome::default();
        let owners = [(first_id, first.clone()), (second_id, second.clone())]
            .into_iter()
            .collect();
        block_unperformed_static(&mut candidate_plan, &delta, &owners, &mut outcome);

        assert_eq!(
            outcome.static_failures,
            [first.clone(), second.clone()].into_iter().collect(),
            "an already-closed gate owns every skipped new/replacement slot"
        );
        assert!(!candidate_plan.is_active(0));
        assert!(!candidate_plan.is_active(1));

        let mut timings = CausalTimings::default();
        for module in [&first, &second, &duplicate] {
            timings.observe(module, 10);
        }
        timings.complete(&duplicate, 15);
        lose_unperformed_dynamic_work(
            &mut timings,
            &[
                dynamic_export_work(first.clone(), false),
                dynamic_export_work(second.clone(), false),
                dynamic_export_work(duplicate.clone(), true),
            ],
        );
        for module in [&first, &second] {
            timings.complete(module, 30);
            assert_eq!(
                timings.gap_ns(module),
                None,
                "later work cannot substitute for required work skipped by the closed gate"
            );
        }
        assert_eq!(
            timings.gap_ns(&duplicate),
            Some(5),
            "an already-attached dynamic pair is not unperformed work"
        );
    }

    #[test]
    fn refused_dynamic_only_candidate_loses_its_exact_owner() {
        let module = timing_key(0);
        let mut timings = CausalTimings::default();
        timings.observe(&module, 10);
        let refused = ApplyOutcome {
            missing_contexts: vec![LoaderContextId::from_case_id(0)],
            ..ApplyOutcome::default()
        };
        let work = [dynamic_export_work(module.clone(), false)];

        if refused.committed && refused.stale_views.is_empty() {
            timings.complete(&module, 20);
        } else {
            lose_unperformed_dynamic_work(&mut timings, &work);
        }
        timings.complete(&module, 30);

        assert_eq!(
            timings.gap_ns(&module),
            None,
            "a later attach cannot substitute for dynamic work skipped by candidate refusal"
        );
    }

    #[test]
    fn tagged_terminal_export_snapshot_preserves_only_the_exact_duplicate() {
        let object = PinnedObjectId(7);
        let module = timing_key(0);
        let context = LoaderContextId::from_case_id(0);
        let exact = crate::attach::DynamicExportIdentity {
            object,
            file_offset: 0x10,
            cookie: 1,
            abi: HookAbi::FunctionList,
        };
        let snapshot = vec![exact];
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_LOADER;
        record.case_id = 0;
        let queued = terminal_record_for(context, &snapshot, record);
        assert_eq!(queued.terminal_owner, Some(context));
        assert_eq!(queued.terminal_exports, snapshot);

        let mut timings = CausalTimings::default();
        timings.observe(&module, 10);
        timings.complete(&module, 20);
        let duplicate = DynamicExportWork {
            context,
            module: Some(module.clone()),
            object,
            file_offset: exact.file_offset,
            cookie: exact.cookie,
            abi: exact.abi,
            already_attached: queued.terminal_exports.contains(&exact),
        };
        lose_unperformed_dynamic_work(&mut timings, std::slice::from_ref(&duplicate));
        assert_eq!(timings.gap_ns(&module), Some(10));

        let absent = DynamicExportWork {
            file_offset: 0x20,
            already_attached: queued.terminal_exports.contains(
                &crate::attach::DynamicExportIdentity {
                    file_offset: 0x20,
                    ..exact
                },
            ),
            ..duplicate.clone()
        };
        lose_unperformed_dynamic_work(&mut timings, std::slice::from_ref(&absent));
        assert_eq!(timings.gap_ns(&module), None);

        record.case_id = 1;
        let other = terminal_record_for(context, &snapshot, record);
        assert_eq!(other.terminal_owner, None);
        assert!(other.terminal_exports.is_empty());
    }

    #[test]
    fn pt_interp_alias_binds_the_mapped_dev_inode_and_mapping_path() {
        use p11scope_manifest::maps::Device;

        let interpreter = PathBuf::from("/lib64/ld-linux-x86-64.so.2");
        let mapped = PathBuf::from("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
        let key = ObjectKey {
            device: Device {
                major: 0,
                minor: 32,
            },
            inode: 35_110_329,
        };
        let maps = vec![
            MapEntry {
                start: 0x1000,
                end: 0x2000,
                file_offset: 0,
                permissions: *b"r-xp",
                device: Device {
                    major: 8,
                    minor: 32,
                },
                inode: key.inode,
                raw_path: Some(interpreter.as_os_str().as_encoded_bytes().to_vec()),
            },
            MapEntry {
                start: 0x3000,
                end: 0x4000,
                file_offset: 0,
                permissions: *b"r-xp",
                device: key.device,
                inode: key.inode,
                raw_path: Some(mapped.as_os_str().as_encoded_bytes().to_vec()),
            },
        ];

        let (mapping, path) = exact_executable_mapping(&maps, key).unwrap();
        assert_eq!(mapping.start, 0x3000, "inode alone is not full identity");
        assert_eq!(path, mapped, "pin through the mapping's usable alias");
        assert_ne!(path, interpreter, "PT_INTERP spelling is not map authority");
    }

    #[test]
    fn loader_pin_collision_cannot_commit_a_plan_with_missing_pin_id() {
        let (plan, pins) = plan_with_pins(1, 0);
        assert!(candidate_identity_is_complete(&plan, &[], &pins));
        assert!(
            !candidate_identity_is_complete(&plan, &[], &PinnedObjects::empty()),
            "a collision-rejected ID cannot remain in an active plan"
        );
    }

    fn pin_test_module(view: &ProcessView, module: &ScannedModule) -> PinnedObjects {
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        });
        let (pins, skipped) =
            pin_scanned_view_objects(view, std::slice::from_ref(module), &mut budget).unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        pins
    }

    #[test]
    fn exact_loader_pin_is_view_owned_but_not_a_provider_module() {
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let (raw_modules, mut provider_pins) = pinned_self();
        let provider_modules = reconcile_for_test(&raw_modules, &mut provider_pins);
        let mut engine = Engine::empty();
        engine.plan = plan::build_from_reconciled_modules(&provider_modules);
        engine.pinned = provider_pins;
        engine.modules = provider_modules;

        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        let executable = std::env::current_exe().unwrap();
        let (loader_mapping, loader_path) = maps
            .iter()
            .filter(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
            .find_map(|mapping| match resolve(&maps, mapping.start) {
                Resolved::File {
                    path: MappedPath::Usable(path),
                    ..
                } if path != executable => Some((mapping, path)),
                _ => None,
            })
            .expect("the test process has a mapped executable dependency");
        let loader_module = mapped_object(&view, loader_mapping, &loader_path);
        let loader_pins = pin_test_module(&view, &loader_module);
        let local_loader = loader_pins
            .id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
            .unwrap();
        let (candidate, loader) = engine
            .loader_candidate(
                view.id(),
                &loader_module,
                &loader_pins,
                local_loader,
                Vec::new(),
            )
            .unwrap();
        let loader = loader.expect("the exact loader pin survives reconciliation");

        assert!(candidate.pinned.summary(loader).is_some());
        assert!(
            candidate
                .plan
                .modules
                .iter()
                .all(|module| module.object != loader),
            "a loader-only pin is not a provider module"
        );
        let evidence = discovery_evidence(
            &candidate.plan,
            &candidate.pinned,
            &DiscoveryCounters::default(),
        );
        assert!(
            evidence
                .modules
                .iter()
                .all(|module| module.path != loader_module.path),
            "public discovery has no linker-only module"
        );
    }

    #[test]
    fn loader_collision_candidate_keeps_provider_retirement_without_loader_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider-and-loader.so");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let len = file.metadata().unwrap().len() as usize;
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED);
        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        let mapping = maps
            .iter()
            .find(|mapping| (mapping.start..mapping.end).contains(&(address as u64)))
            .unwrap();
        let mut provider = mapped_object(&view, mapping, &path);
        provider.tables.push(ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name: "C_Sign",
                object: provider.key,
                object_path: provider.path.clone(),
                file_offset: 0x10,
            }],
            null_entries: Vec::new(),
            unpinned: Vec::new(),
            address: 0x7000,
        });
        let mut provider_pins = pin_test_module(&view, &provider);
        let provider_modules =
            reconcile_for_test(std::slice::from_ref(&provider), &mut provider_pins);
        let mut engine = Engine::empty();
        engine.plan = plan::build_from_reconciled_modules(&provider_modules);
        engine.pinned = provider_pins;
        engine.modules = provider_modules;
        let rejected_loader = engine.plan.modules[0].object;

        let context_spec = |view| LoaderContextSpec {
            view,
            loader: rejected_loader,
            mapping: Some(MapEntry {
                start: 0x4000,
                end: 0x5000,
                file_offset: 0x2000,
                permissions: *b"r-xp",
                device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
                inode: 7,
                raw_path: Some(b"/lib/ld.so".to_vec()),
            }),
            hook: p11scope_manifest::elf::SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state: None,
        };
        let prepared = engine
            .loader_registry
            .preflight(context_spec(ProcessViewId(80)))
            .unwrap();
        let prepared = engine.loader_registry.prepare(prepared).unwrap();
        let attached = engine
            .loader_registry
            .preflight(context_spec(ProcessViewId(81)))
            .unwrap();
        let attached = engine.loader_registry.prepare(attached).unwrap();
        engine.loader_registry.mark_attached(attached).unwrap();
        let tombstoned = engine
            .loader_registry
            .preflight(context_spec(ProcessViewId(82)))
            .unwrap();
        let tombstoned = engine.loader_registry.prepare(tombstoned).unwrap();
        engine.loader_registry.mark_attached(tombstoned).unwrap();
        engine.loader_registry.tombstone(tombstoned).unwrap();

        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        let loader_module = mapped_object(&view, mapping, &path);
        let loader_pins = pin_test_module(&view, &loader_module);
        let local_loader = loader_pins
            .id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
            .unwrap();
        let (candidate, loader) = engine
            .loader_candidate(
                view.id(),
                &loader_module,
                &loader_pins,
                local_loader,
                Vec::new(),
            )
            .unwrap();

        assert!(loader.is_none(), "the conflicting loader has no authority");
        assert_eq!(candidate.delta.retire.len(), 1);
        assert!(
            candidate
                .plan
                .slots
                .iter()
                .all(|slot| !candidate.plan.is_active(slot.index))
        );
        assert!(candidate_identity_is_complete(
            &candidate.plan,
            &candidate.modules,
            &candidate.pinned
        ));
        let admission = candidate_admission(
            &engine.views,
            &[],
            &candidate.views,
            &engine.loader_registry,
            &candidate.pinned,
            &engine.pinned,
            true,
        );
        assert_eq!(
            admission.missing_contexts,
            vec![prepared, attached, tombstoned],
            "Prepared, Attached, and Tombstoned loader pins are all candidate evidence"
        );

        assert!(candidate.pinned.rejects(loader_module.key));
        let rejected_keys = candidate.pinned.newly_rejected_keys(&engine.pinned);
        let outcome = ApplyOutcome {
            missing_contexts: admission.missing_contexts.clone(),
            newly_rejected_keys: rejected_keys.clone(),
            ..ApplyOutcome::default()
        };
        let mut pending_views = PendingViewRetirements::new();
        engine.queue_apply_outcome(&outcome, &mut pending_views);
        assert_eq!(engine.pending_rejected_keys, rejected_keys);
        drop(candidate);
        engine.loader_registry.cancel_prepared(prepared).unwrap();
        engine.loader_registry.remove(prepared).unwrap();
        engine.loader_registry.tombstone(attached).unwrap();
        engine.loader_registry.remove(attached).unwrap();
        engine.loader_registry.remove(tombstoned).unwrap();
        let keys = engine.pending_rejected_keys.clone();
        let replay = engine
            .conservative_candidate(&BTreeSet::new(), &keys)
            .unwrap();
        assert!(
            replay.pinned.rejects(loader_module.key),
            "serial context cleanup cannot discard the collision that selected it"
        );
        assert_eq!(
            replay.delta.retire.len(),
            1,
            "the fresh post-cleanup candidate must retain the affected provider retirement"
        );
        assert_eq!(unsafe { libc::munmap(address, len) }, 0);
    }

    #[test]
    fn live_candidate_captures_rejected_keys_before_fallible_plan_extension() {
        let (_, raw_modules, mut pins, _) = same_object_scan_and_manifest(0x10);
        let modules = reconcile_for_test(&raw_modules, &mut pins);
        let mut engine = Engine::empty();
        engine.plan = plan::build_from_reconciled_modules(&modules);
        assert_eq!(engine.plan.slots.len(), 1);
        engine.plan.slots[0].descriptor_index += 1;
        engine.plan.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        engine.plan.slots[0].semantic_ambiguous = true;
        engine.pinned = pins;
        engine.modules = modules;

        let rejected = ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: 254,
                minor: 1,
            },
            inode: u64::MAX - 1,
        };
        let mut candidate_pins = engine.pinned.clone();
        assert!(
            candidate_pins
                .reapply_rejected_keys(&[rejected].into_iter().collect())
                .is_empty()
        );

        assert!(
            engine
                .live_candidate(candidate_pins, raw_modules, Vec::new())
                .is_err(),
            "the fixture reaches the fallible plan-extension boundary"
        );

        assert_eq!(
            engine.pending_rejected_keys,
            [rejected].into_iter().collect(),
            "later plan construction cannot erase the already-proved rejection"
        );
    }

    #[test]
    fn conservative_intent_survives_refusal_until_current_candidate_commits() {
        let (_, raw_modules, mut pins, _) = same_object_scan_and_manifest(0x10);
        let modules = reconcile_for_test(&raw_modules, &mut pins);
        let retired = raw_modules[0].view;
        let rejected = pins.pinned().next().unwrap().key;
        let mut engine = Engine::empty();
        engine.plan = plan::build_from_reconciled_modules(&modules);
        engine.pinned = pins;
        engine.modules = modules;
        engine.pending_retirements.insert(retired);
        engine.pending_rejected_keys.insert(rejected);

        let retirements = engine.pending_retirements.clone();
        let rejected_keys = engine.pending_rejected_keys.clone();
        let candidate = engine
            .conservative_candidate(&retirements, &rejected_keys)
            .unwrap();
        assert!(candidate.delta.new.is_empty());
        assert!(candidate.delta.replace.is_empty());
        assert!(candidate.plan.modules.is_empty());
        assert!(candidate.pinned.rejects(rejected));

        let mut pending_views = PendingViewRetirements::new();
        let refused = ApplyOutcome {
            stale_views: [ProcessViewId(91)].into_iter().collect(),
            newly_rejected_keys: rejected_keys.clone(),
            ..ApplyOutcome::default()
        };
        assert!(!engine.queue_conservative_outcome(
            &refused,
            &retirements,
            &rejected_keys,
            &mut pending_views,
        ));
        assert_eq!(engine.pending_retirements, retirements);
        assert_eq!(engine.pending_rejected_keys, rejected_keys);

        let committed = ApplyOutcome {
            committed: true,
            changed: true,
            newly_rejected_keys: rejected_keys.clone(),
            ..ApplyOutcome::default()
        };
        assert!(engine.queue_conservative_outcome(
            &committed,
            &retirements,
            &rejected_keys,
            &mut pending_views,
        ));
        assert!(engine.pending_retirements.is_empty());
        assert!(engine.pending_rejected_keys.is_empty());
    }

    #[test]
    fn candidate_admission_keeps_exact_retained_and_local_stale_view_ids() {
        fn exited_view(id: ProcessViewId) -> ProcessView {
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let view = ProcessView::open(id, child.id()).unwrap();
            child.kill().unwrap();
            child.wait().unwrap();
            assert!(!view.still_the_same());
            view
        }

        let retained = exited_view(ProcessViewId(90));
        let local_new = exited_view(ProcessViewId(91));
        let candidate_views = [retained.id(), local_new.id()].into_iter().collect();
        let admission = candidate_admission(
            std::slice::from_ref(&retained),
            &[&local_new],
            &candidate_views,
            &LoaderRegistry::default(),
            &PinnedObjects::empty(),
            &PinnedObjects::empty(),
            false,
        );

        assert_eq!(admission.stale_views, candidate_views);
        assert!(!admission.targets_ok);
    }

    #[test]
    fn post_retirement_target_failure_requires_conservative_apply() {
        let failed = CandidateAdmission {
            targets_ok: false,
            ..CandidateAdmission::default()
        };

        assert!(
            !failed.requires_conservative_apply(false),
            "a pure preflight failure leaves the transaction unchanged"
        );
        assert!(
            failed.requires_conservative_apply(true),
            "after dynamic retirement the same failure must commit conservative subtraction"
        );
    }

    #[test]
    fn every_pre_mutation_refusal_latches_shared_active_slot_provenance() {
        fn plans() -> (plan::AttachPlan, plan::AttachPlan, u32) {
            let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
            let mut current = plan_with(1, 0);
            current.slots[0].descriptor_index = descriptor;
            current.slots[0].semantics = crate::kinds::DESCRIPTORS[descriptor as usize];
            let mut rebuilt = current.clone();
            let mut second = rebuilt.modules[0].clone();
            second.id = plan::ModuleId(1);
            second.object = PinnedObjectId(43);
            second.key.inode = 43;
            second.path = "/opt/peer.so".into();
            rebuilt.modules.push(second);
            rebuilt.slots[0].descriptor_index = 0;
            rebuilt.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
            rebuilt.slots[0].semantic_ambiguous = true;
            rebuilt.slots[0].module_ids.push(plan::ModuleId(1));
            let mut candidate = current.clone();
            let delta = candidate.extend_exact(rebuilt).unwrap();
            assert_eq!(delta.replace.len(), 1);
            (current, candidate, descriptor)
        }

        let refusals = [
            (
                "target preflight",
                CandidateAdmission {
                    targets_ok: false,
                    ..CandidateAdmission::default()
                },
            ),
            (
                "stale generation",
                CandidateAdmission {
                    stale_views: [ProcessViewId(91)].into_iter().collect(),
                    targets_ok: true,
                    ..CandidateAdmission::default()
                },
            ),
            (
                "missing loader context",
                CandidateAdmission {
                    missing_contexts: vec![LoaderContextId::from_case_id(7)],
                    targets_ok: true,
                    ..CandidateAdmission::default()
                },
            ),
        ];

        for (label, admission) in refusals {
            let (current, candidate, descriptor) = plans();
            let mut engine = Engine::empty();
            engine.plan = current;

            assert!(admission.refuses_candidate(), "{label}");
            assert!(
                engine.latch_candidate_ambiguity(&candidate),
                "{label} must report a canonical semantic change"
            );
            assert_eq!(engine.plan.slots[0].descriptor_index, descriptor, "{label}");
            assert_eq!(
                engine.plan.slots[0].module_ids,
                [plan::ModuleId(0)],
                "{label}"
            );
            assert_eq!(engine.plan.module_of_slot(0), None, "{label}");
            assert_eq!(engine.plan.module_ambiguous, 1, "{label}");
            assert_eq!(engine.discovery.module_ambiguous, 1, "{label}");
            assert!(
                !engine.latch_candidate_ambiguity(&candidate),
                "{label} must be idempotent"
            );
        }
    }

    #[test]
    fn context_free_refresh_does_not_create_retirement_intent() {
        let removed = [ProcessViewId(1)].into_iter().collect();
        let context_views = [ProcessViewId(2)].into_iter().collect();
        let failed = [ProcessViewId(3)].into_iter().collect();

        assert_eq!(
            completed_retirement_intent(&removed, &context_views, &failed),
            [ProcessViewId(1), ProcessViewId(2)].into_iter().collect(),
            "removed views and successful context retirements persist; a context-free refresh does not"
        );
    }

    #[test]
    fn post_retirement_local_new_stale_requires_conservative_apply() {
        let stale = CandidateAdmission {
            stale_views: [ProcessViewId(91)].into_iter().collect(),
            targets_ok: true,
            ..CandidateAdmission::default()
        };

        assert!(
            !stale.requires_conservative_apply(false),
            "a pre-mutation local generation loss leaves canonical topology unchanged"
        );
        assert!(
            stale.requires_conservative_apply(true),
            "after dynamic retirement local-only staleness still requires static subtraction"
        );
    }

    #[test]
    fn post_attach_generation_loss_detaches_and_cannot_commit_stale_candidate() {
        let view = ProcessView::open(ProcessViewId(91), std::process::id()).unwrap();
        let checks = Cell::new(0usize);
        let outcome = generation_checked_mutation(
            || {
                let call = checks.get();
                checks.set(call + 1);
                view.still_the_same() && call == 0
            },
            || "attached",
        );
        let mut detached = 0;
        let mut retired_views = 0;
        let mut committed = false;
        match outcome {
            GenerationMutation::PostcheckFailed(value) => {
                assert_eq!(value, "attached");
                detached += 1;
                retired_views += 1;
            }
            GenerationMutation::Committed(_) => committed = true,
            GenerationMutation::PrecheckFailed => {}
        }

        assert_eq!(checks.get(), 2, "generation is checked on both sides");
        assert_eq!(detached, 1, "post-attach loss triggers one cleanup");
        assert_eq!(retired_views, 1, "the stale candidate view is retired now");
        assert!(!committed, "stale ownership is never committed");

        let (raw_modules, mut pins) = pinned_self();
        let stale = raw_modules[0].view;
        let (modules, skipped) = bind_scanned_modules(&raw_modules, &mut pins);
        assert!(skipped.is_empty());
        let (remaining_pins, remaining_modules) =
            candidate_sources_without_view(&pins, &modules, stale);
        assert!(
            remaining_modules.is_empty(),
            "stale module ownership is removed"
        );
        assert_eq!(
            remaining_pins.pinned().count(),
            0,
            "stale pins are removed before the candidate can commit"
        );
    }

    #[test]
    fn attached_context_is_processed_and_removed_before_same_view_rearm() {
        use p11scope_manifest::elf::SymbolFact;
        use p11scope_manifest::maps::Device;

        let mapping = MapEntry {
            start: 0x4000,
            end: 0x5000,
            file_offset: 0x2000,
            permissions: *b"r-xp",
            device: Device { major: 8, minor: 1 },
            inode: 7,
            raw_path: Some(b"/lib/ld.so".to_vec()),
        };
        let mut registry = LoaderRegistry::default();
        let prepared = registry
            .preflight(LoaderContextSpec {
                view: ProcessViewId(3),
                loader: PinnedObjectId(9),
                mapping: Some(mapping.clone()),
                hook: SymbolFact {
                    virtual_address: 0x2100,
                    file_offset: 0x2100,
                },
                state: None,
            })
            .unwrap();
        let context = registry.prepare(prepared).unwrap();
        registry.mark_attached(context).unwrap();
        let mut queued: DiscoveryRecord = unsafe { std::mem::zeroed() };
        queued.kind = DISCOVERY_KIND_LOADER;
        queued.case_id = (context.get() - 1) as u8;
        queued.table_ptr = 0x4100;
        queued.hook_ts_ns = 10;
        let order = std::cell::RefCell::new(Vec::new());

        order.borrow_mut().push("detach");
        let drained = begin_attached_retirement_with(&mut registry, context, || {
            order.borrow_mut().push("drain");
            Ok((
                vec![queued],
                CounterSnapshot {
                    loader_hits: 1,
                    ..CounterSnapshot::default()
                },
            ))
        })
        .unwrap();
        let (drained, post_drain_snapshot) = drained.unwrap();
        let mut authority = CounterSnapshot::default();
        assert!(authority.replace_with(post_drain_snapshot));

        assert_eq!(*order.borrow(), ["detach", "drain"]);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].case_id, queued.case_id);
        assert_eq!(drained[0].hook_ts_ns, queued.hook_ts_ns);
        assert_eq!(
            authority.loader_hits, 1,
            "the owned hit has fresh authority"
        );
        let ordinary = QueuedDiscoveryRecord {
            record: queued,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        };
        assert!(
            validate_loader_record_context(
                &mut registry,
                ordinary.terminal_owner,
                &ordinary.record,
                ProcessViewId(3),
                PinnedObjectId(9),
                &mapping,
            )
            .is_err(),
            "ordinary dispatch cannot revive a tombstone"
        );
        let wrong_owner = Some(LoaderContextId::from_case_id(
            queued.case_id.wrapping_add(1),
        ));
        assert!(
            validate_loader_record_context(
                &mut registry,
                wrong_owner,
                &queued,
                ProcessViewId(3),
                PinnedObjectId(9),
                &mapping,
            )
            .is_err(),
            "another drain's tag cannot authorize this tombstone"
        );
        let failures = registry.context_failures();
        let terminal = QueuedDiscoveryRecord {
            record: queued,
            terminal_owner: Some(context),
            terminal_exports: Vec::new(),
        };
        validate_loader_record_context(
            &mut registry,
            terminal.terminal_owner,
            &terminal.record,
            ProcessViewId(3),
            PinnedObjectId(9),
            &mapping,
        )
        .expect("the exact owned terminal drain can resolve its live tombstone");
        assert_eq!(
            registry.context_failures(),
            failures,
            "the tagged terminal hit adds no context failure"
        );
        order.borrow_mut().push("process");
        let mut engine = Engine::empty();
        engine.loader_registry = registry;
        engine.loader_registry.remove(context).unwrap();
        order.borrow_mut().push("remove");
        assert!(
            engine
                .loader_registry
                .ids_for_view(ProcessViewId(3))
                .is_empty(),
            "the tombstone cannot block same-view replacement arming"
        );
        let prepared = engine
            .loader_registry
            .preflight(LoaderContextSpec {
                view: ProcessViewId(3),
                loader: PinnedObjectId(9),
                mapping: Some(mapping),
                hook: SymbolFact {
                    virtual_address: 0x2100,
                    file_offset: 0x2100,
                },
                state: None,
            })
            .unwrap();
        let replacement = engine.loader_registry.prepare(prepared).unwrap();
        order.borrow_mut().push("arm");
        assert_ne!(replacement, context, "context IDs are never reused");
        assert_eq!(
            *order.borrow(),
            ["detach", "drain", "process", "remove", "arm"]
        );
    }

    #[test]
    fn serial_terminal_drain_never_claims_another_attached_context() {
        use p11scope_manifest::elf::SymbolFact;
        use p11scope_manifest::maps::Device;

        let mapping = MapEntry {
            start: 0x4000,
            end: 0x5000,
            file_offset: 0x2000,
            permissions: *b"r-xp",
            device: Device { major: 8, minor: 1 },
            inode: 7,
            raw_path: Some(b"/lib/ld.so".to_vec()),
        };
        let mut registry = LoaderRegistry::default();
        let mut prepare = |view, loader| {
            let prepared = registry
                .preflight(LoaderContextSpec {
                    view,
                    loader,
                    mapping: Some(mapping.clone()),
                    hook: SymbolFact {
                        virtual_address: 0x2100,
                        file_offset: 0x2100,
                    },
                    state: None,
                })
                .unwrap();
            let context = registry.prepare(prepared).unwrap();
            registry.mark_attached(context).unwrap();
            context
        };
        let first = prepare(ProcessViewId(3), PinnedObjectId(9));
        let second = prepare(ProcessViewId(4), PinnedObjectId(10));

        registry.tombstone(first).unwrap();
        let mut second_hit: DiscoveryRecord = unsafe { std::mem::zeroed() };
        second_hit.kind = DISCOVERY_KIND_LOADER;
        second_hit.case_id = (second.get() - 1) as u8;
        second_hit.table_ptr = 0x4100;
        second_hit.hook_ts_ns = 10;
        let queued = terminal_record_for(first, &[], second_hit);
        assert_eq!(
            queued.terminal_owner, None,
            "A's global drain cannot grant terminal authority to B's record"
        );
        let failures = registry.context_failures();
        validate_loader_record_context(
            &mut registry,
            queued.terminal_owner,
            &queued.record,
            ProcessViewId(4),
            PinnedObjectId(10),
            &mapping,
        )
        .expect("B remains Attached while A's drained batch is dispatched");
        assert_eq!(registry.context_failures(), failures);
        registry.remove(first).unwrap();

        registry.tombstone(second).unwrap();
        let queued = terminal_record_for(second, &[], second_hit);
        assert_eq!(queued.terminal_owner, Some(second));
        validate_loader_record_context(
            &mut registry,
            queued.terminal_owner,
            &queued.record,
            ProcessViewId(4),
            PinnedObjectId(10),
            &mapping,
        )
        .expect("B receives terminal authority only from B's own drain");
        registry.remove(second).unwrap();
        assert!(registry.ids_for_view(ProcessViewId(3)).is_empty());
        assert!(registry.ids_for_view(ProcessViewId(4)).is_empty());
    }

    #[test]
    fn refresh_preserves_a_loader_arm_plan_change() {
        let mut attempted = Vec::new();
        let changed = arm_refreshed_views_with(&[4, 7], |position| {
            attempted.push(position);
            Ok(position == 7)
        })
        .unwrap();

        assert_eq!(attempted, [4, 7]);
        assert!(changed, "refresh must report a loader-arm plan mutation");
    }

    #[test]
    fn refresh_continues_second_view_after_first_loader_arm_error() {
        let mut attempted = Vec::new();
        let mut partial = 0;
        let changed = arm_refreshed_views_with(&[0, 1], |position| {
            attempted.push(position);
            let result = if position == 0 {
                Err(LoaderArmFailure::ordinary(anyhow!(
                    "ordinary per-view map failure"
                )))
            } else {
                Ok(false)
            };
            match loader_arm_outcome(true, result) {
                LoaderArmOutcome::OrdinaryFailure => {
                    partial += 1;
                    Ok(false)
                }
                LoaderArmOutcome::Changed(changed) => Ok(changed),
                _ => unreachable!(),
            }
        })
        .unwrap();

        assert_eq!(attempted, [0, 1]);
        assert_eq!(partial, 1);
        assert!(!changed);
        assert!(
            matches!(
                loader_arm_outcome(
                    true,
                    Err(LoaderArmFailure::invariant(anyhow!(
                        "registry state transition failed"
                    )))
                ),
                LoaderArmOutcome::Invariant(_)
            ),
            "a true loader-arm invariant remains capture-fatal"
        );

        for changed in [false, true] {
            assert!(
                matches!(
                    loader_arm_outcome(false, Ok(changed)),
                    LoaderArmOutcome::GenerationLost {
                        changed: retained,
                        failure: None,
                    } if retained == changed
                ),
                "a successful or early-return arm must enter cleanup and retain its change bit"
            );
        }
    }

    #[test]
    fn engine_lowers_export_table_owner_and_prefix() {
        use p11scope_ebpf_common::{
            DISCOVERY_KIND_FUNCTION_LIST_RETURN, DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN,
            DISCOVERY_STATUS_READ_FAILURE, DiscoveryRecord,
        };
        use p11scope_manifest::maps::{MappedPath, Resolved, parse_maps, resolve};

        let view = ProcessView::open(ProcessViewId(41), std::process::id()).unwrap();
        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        let executable = std::env::current_exe().unwrap();
        let executable = executable.canonicalize().unwrap_or(executable);
        let owner = maps
            .iter()
            .find(|mapping| {
                mapping.inode != 0
                    && mapping.permissions[0] == b'r'
                    && mapping.permissions[2] != b'x'
                    && matches!(
                        resolve(&maps, mapping.start),
                        Resolved::File {
                            path: MappedPath::Usable(ref path),
                            ..
                        } if path == &executable
                    )
            })
            .expect("the test executable has a file-backed data mapping");
        let code = maps
            .iter()
            .find(|mapping| {
                mapping.inode == owner.inode
                    && mapping.device == owner.device
                    && mapping.permissions[2] == b'x'
            })
            .expect("the test executable has a matching code mapping");

        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_FUNCTION_LIST_RETURN;
        record.symbol_id = 1;
        record.table_ptr = owner.start;
        record.version_major = 2;
        record.version_minor = 40;
        record.pointers[0] = code.start;
        record.pointers_attempted = 1;
        record.completed_prefix = 1;
        record.usable_n = 1;

        let hooks = crate::discovery::hooks::HookRegistry::builtin();
        let limits = ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        };
        let mut budget = CaptureWorkBudget::new(limits);
        let lowered = lower_export_record(&view, &maps, &hooks, &record, &mut budget)
            .expect("the structurally valid record lowers")
            .expect("one usable pointer gives one table");
        assert_eq!(lowered.view, view.id());
        assert_eq!(lowered.key, ObjectKey::of(owner));
        assert_eq!(lowered.tables.len(), 1);
        assert_eq!(lowered.tables[0].entries.len(), 1);
        assert_eq!(lowered.tables[0].entries[0].object, ObjectKey::of(code));

        let mut interface_record = record;
        interface_record.kind = DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN;
        interface_record.symbol_id = 2;
        interface_record.table_ptr += 8;
        interface_record.interface_index = 3;
        interface_record.announced_count = 4;
        interface_record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        let interface = lower_export_record(&view, &maps, &hooks, &interface_record, &mut budget)
            .unwrap()
            .unwrap();
        let mut merged = vec![lowered.clone()];
        merge_scanned_module(&mut merged, interface);
        assert_eq!(merged[0].interfaces[0].table, Some(1));

        let mut wrong_hook = record;
        wrong_hook.symbol_id = 2;
        assert!(
            lower_export_record(&view, &maps, &hooks, &wrong_hook, &mut budget).is_err(),
            "the retained symbol ABI must agree with the record kind"
        );
        wrong_hook.symbol_id = u32::MAX;
        assert!(
            lower_export_record(&view, &maps, &hooks, &wrong_hook, &mut budget).is_err(),
            "unknown private symbol IDs have no hook authority"
        );

        let (mut pins, skipped) =
            pin_scanned_objects(view.pid(), std::slice::from_ref(&lowered), &mut budget).unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let reconciled = reconcile_for_test(&[lowered], &mut pins);
        assert_eq!(
            plan::build_from_reconciled_modules(&reconciled).slots.len(),
            1
        );

        record.status_flags = DISCOVERY_STATUS_READ_FAILURE;
        record.usable_n = 0;
        assert!(
            lower_export_record(&view, &maps, &hooks, &record, &mut budget)
                .expect("the completed raw prefix is structurally valid")
                .is_none(),
            "a read-failed completed prefix is not target authority"
        );

        record.status_flags = 0;
        record.usable_n = 1;
        record.table_ptr = maps
            .iter()
            .find(|mapping| mapping.inode == 0 && mapping.permissions[0] == b'r')
            .expect("this process has an anonymous readable mapping")
            .start;
        assert!(
            lower_export_record(&view, &maps, &hooks, &record, &mut budget)
                .expect("an anonymous table owner is a count-only outcome")
                .is_none(),
            "an anonymous mapping cannot own a live table"
        );
    }

    #[test]
    fn post_session_rebuild_preserves_canonical_ids() {
        let (modules, canonical) = pinned_self();
        let original = canonical
            .id_for_scanned(&modules[0], modules[0].key, &modules[0].path)
            .unwrap();
        let (_, incoming) = pinned_self();
        let mut engine = Engine::empty();
        engine.pinned = canonical;
        let mut candidate_pins = engine.pinned.clone();
        let skipped = candidate_pins.absorb(incoming);
        assert!(skipped.is_empty(), "{skipped:?}");
        let candidate = engine
            .live_candidate(candidate_pins, modules.clone(), skipped)
            .unwrap();
        assert_eq!(
            candidate
                .pinned
                .id_for_scanned(&modules[0], modules[0].key, &modules[0].path)
                .unwrap(),
            original,
            "an exact post-session observation reuses the canonical object ID"
        );
        assert_eq!(
            engine.pinned.pinned().count(),
            candidate.pinned.pinned().count()
        );

        let mut preserved = engine.pinned.clone();
        assert!(
            preserved
                .replace_view_pins(modules[0].view, PinnedObjects::empty(), &[original])
                .is_empty()
        );
        assert_eq!(
            preserved.id_for_scanned(&modules[0], modules[0].key, &modules[0].path),
            Some(original),
            "an active loader context can retain its exact pin across a view rescan"
        );
    }

    #[test]
    fn manifest_pins_are_not_rehashed_by_event() {
        use std::io::{Read as _, Seek as _, SeekFrom};
        use std::os::fd::AsRawFd as _;

        let exe = std::env::current_exe().unwrap();
        let pins = pin_as_manifest_object(exe.to_str().unwrap());
        let id = pins.pinned().next().unwrap().id;
        let file = pins
            .file_for(id)
            .expect("the manifest pin retains its opened file");
        let before = file.metadata().unwrap().ino();
        let mut borrowed = file;
        borrowed.seek(SeekFrom::Start(0)).unwrap();
        let mut magic = [0; 4];
        borrowed.read_exact(&mut magic).unwrap();
        assert_eq!(&magic, b"\x7fELF");
        assert_eq!(file.metadata().unwrap().ino(), before);
        let retained_fd = file.as_raw_fd();
        assert!(pins.check_unchanged().unwrap());

        let mut engine = Engine::empty();
        engine.pinned = pins;
        let candidate = engine
            .live_candidate(engine.pinned.clone(), Vec::new(), Vec::new())
            .unwrap();
        assert_eq!(
            candidate.pinned.file_for(id).unwrap().as_raw_fd(),
            retained_fd,
            "an event candidate shares the retained manifest descriptor"
        );
    }

    #[test]
    fn scope_refresh_uses_engine_owned_scope_and_monotonic_view_ids() {
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(std::process::id());
        let first = engine.allocate_view_id().unwrap();
        let second = engine.allocate_view_id().unwrap();
        assert_eq!((first, second), (ProcessViewId(0), ProcessViewId(1)));
        assert_eq!(scope_pids(&engine.scope).0, vec![std::process::id()]);

        engine.next_view_id = MAX_SCAN_PIDS as u32;
        assert!(engine.allocate_view_id().is_err());
        assert_eq!(engine.next_view_id, MAX_SCAN_PIDS as u32);
    }

    fn current_mount_namespace() -> crate::process::MountNamespaceId {
        let metadata = std::fs::metadata("/proc/self/ns/mnt").unwrap();
        crate::process::MountNamespaceId {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn reconcile_for_test(
        modules: &[ScannedModule],
        pinned: &mut PinnedObjects,
    ) -> Vec<ReconciledModule> {
        let (modules, _, skipped) = reconcile_scanned_modules(modules, pinned);
        assert!(skipped.is_empty(), "{skipped:?}");
        modules
    }

    fn lifecycle_discovered(views: Vec<ProcessView>) -> Engine {
        let mut discovered = Engine::empty();
        for view in &views {
            discovered.retain_view_id(view.id()).unwrap();
        }
        discovered.views = views;
        discovered
    }

    fn discovered_from_inputs(
        views: Vec<ProcessView>,
        scan_modules: Vec<ScannedModule>,
        scan_pins: PinnedObjects,
        manifest_inputs: Vec<ManifestInput>,
    ) -> Engine {
        let mut discovered = lifecycle_discovered(views);
        let view = scan_modules
            .first()
            .expect("test scan input has one process view")
            .view;
        discovered.scan_inputs.insert(
            view,
            ScanInput {
                modules: scan_modules,
                pins: scan_pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs = manifest_inputs;
        rebuild_discovered(&mut discovered).unwrap();
        discovered
    }

    fn same_object_scan_and_manifest(
        scan_offset: u64,
    ) -> (
        ProcessView,
        Vec<ScannedModule>,
        PinnedObjects,
        ManifestInput,
    ) {
        let (mut modules, pins) = pinned_self();
        assert_eq!(modules.len(), 1);
        let summary = pins.pinned().next().unwrap();
        let (path, key, sha256) = (
            summary.path.to_string(),
            summary.key,
            summary.sha256.to_string(),
        );
        modules[0].tables.push(ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name: "C_Sign",
                object: key,
                object_path: path.clone(),
                file_offset: scan_offset,
            }],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7000,
        });
        let manifest = manifest_naming(&path, Some(sha256));
        let input = ManifestInput {
            path: PathBuf::from("manifest.json"),
            pins: pin_as_manifest_object(&path),
            manifest,
            stale: Vec::new(),
        };
        (
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
            modules,
            pins,
            input,
        )
    }

    fn object_facts(path: &Path) -> (ObjectKey, p11scope_manifest::identity::ObjectIdentity, u64) {
        let file = p11scope_manifest::identity::open_object(path).unwrap();
        let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
        (
            ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            },
            inspected.identity,
            inspected.executable_ranges[0].0,
        )
    }

    fn valid_manifest_for(paths: &[PathBuf], targets: &[u32]) -> Manifest {
        use p11scope_manifest::manifest::*;

        assert_eq!(targets.len(), 67);
        let facts: Vec<_> = paths.iter().map(|path| object_facts(path)).collect();
        Manifest {
            schema: SCHEMA.to_string(),
            module_path: paths[0].display().to_string(),
            objects: paths
                .iter()
                .zip(&facts)
                .enumerate()
                .map(|(id, (path, (_, identity, _)))| ObjectRecord {
                    id: id as u32,
                    path: path.display().to_string(),
                    identity: identity.clone(),
                })
                .collect(),
            provenance_objects: paths
                .iter()
                .zip(&facts)
                .map(|(path, (key, identity, _))| ProvenanceObject {
                    path: path.display().to_string(),
                    device_major: key.device.major,
                    device_minor: key.device.minor,
                    inode: key.inode,
                    identity: identity.clone(),
                })
                .collect(),
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version { major: 2, minor: 0 }),
                walk: WalkOutcome::Full,
                functions: pkcs11_module::FUNCTION_LIST_FIELDS[..67]
                    .iter()
                    .zip(targets)
                    .map(|(field, object)| FunctionRecord {
                        name: field.name.into(),
                        resolution: Resolution::Resolved {
                            object: *object,
                            file_offset: facts[*object as usize].2,
                        },
                    })
                    .collect(),
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        }
    }

    fn scanned_manifest_replacement(paths: &[PathBuf], targets: &[u32]) -> ScannedModule {
        let facts: Vec<_> = paths.iter().map(|path| object_facts(path)).collect();
        ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
            key: facts[0].0,
            path: paths[0].display().to_string(),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 0),
                walk: "full",
                entries: pkcs11_module::FUNCTION_LIST_FIELDS[..67]
                    .iter()
                    .zip(targets)
                    .map(|(field, object)| ScannedEntry {
                        name: field.name,
                        object: facts[*object as usize].0,
                        object_path: paths[*object as usize].display().to_string(),
                        file_offset: facts[*object as usize].2,
                    })
                    .collect(),
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
            }],
            interfaces: vec![],
        }
    }

    fn manifest_input_from_pinning(path: &str, manifest: Manifest) -> ManifestInput {
        let pinning = pin_manifest_objects_deferred(&manifest).unwrap();
        ManifestInput {
            path: PathBuf::from(path),
            manifest,
            pins: pinning.pins,
            stale: pinning.stale,
        }
    }

    fn pin_scan(module: &ScannedModule) -> PinnedObjects {
        let (pins, skipped) = pin_scanned_objects(
            std::process::id(),
            std::slice::from_ref(module),
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        pins
    }

    #[test]
    fn discovery_open_stale_manifest_object_uses_only_the_exact_scanned_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let manifest = valid_manifest_for(&paths, &targets);
        let scan = scanned_manifest_replacement(&paths, &targets);
        let scan_offset = scan.tables[0].entries[0].file_offset;
        let scan_pins = pin_scan(&scan);
        std::fs::remove_file(&provider).unwrap();
        let input = manifest_input_from_pinning("open-stale.json", manifest);
        assert_eq!(input.stale[0].reason, ManifestStaleReason::OpenStale);

        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stale_view = view.id();
        let mut discovered = discovered_from_inputs(vec![view], vec![scan], scan_pins, vec![input]);

        assert_eq!(discovered.plan.modules[0].source, "scan");
        assert_eq!(discovered.plan.slots.len(), 1);
        assert_eq!(discovered.plan.slots[0].file_offset, scan_offset);
        assert!(!discovered.plan.slots[0].semantic_authorized);
        assert_eq!(
            discovered.plan.slots[0].semantics,
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        assert_eq!(discovered.counters.manifest_fallbacks.len(), 1);
        assert_eq!(discovered.counters.uncorroborated, 1);
        assert_eq!(discovered.discovery.manifest_object_fallbacks.len(), 1);

        let error = remove_stale_views(&mut discovered, &[stale_view])
            .expect_err("fallback must be recomputed from the surviving pristine views");
        assert!(
            error.to_string().contains("stale manifest object"),
            "{error:#}"
        );
    }

    #[test]
    fn discovery_identity_stale_object_with_invalid_offset_is_fatal_before_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let mut manifest = valid_manifest_for(&paths, &targets);
        for function in &mut manifest.surfaces[0].functions {
            let Resolution::Resolved { file_offset, .. } = &mut function.resolution else {
                unreachable!()
            };
            *file_offset = 0xdead_beef;
        }
        std::fs::copy("/bin/true", &provider).unwrap();
        let error = pin_manifest_objects_deferred(&manifest)
            .expect_err("invalid executable offsets stay fatal before stale fallback");
        assert!(
            matches!(
                &error,
                ManifestPinError::Fatal(problems)
                    if problems.iter().any(|problem| problem.contains("outside every executable"))
            ),
            "{error:?}"
        );
    }

    #[test]
    fn discovery_complementary_partial_tables_do_not_cover_one_stale_surface() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let manifest = valid_manifest_for(&paths, &targets);
        std::fs::copy("/bin/ls", &provider).unwrap();
        let mut scan = scanned_manifest_replacement(&paths, &targets);
        let mut second = scan.tables[0].clone();
        let midpoint = scan.tables[0].entries.len() / 2;
        second.entries = scan.tables[0].entries.split_off(midpoint);
        second.address += 0x1000;
        scan.tables.push(second);
        let pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("partial-tables.json", manifest);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules: vec![scan],
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("two partial tables cannot manufacture one complete proof");
        assert!(error.to_string().contains("object 0"), "{error:#}");
    }

    #[test]
    fn discovery_one_duplicate_table_cannot_prove_two_manifest_surfaces() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let mut manifest = valid_manifest_for(&paths, &targets);
        manifest.interface_list = Acquisition::Ok;
        manifest.surfaces[0] = SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Absent,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        };
        let functions: Vec<_> = pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
            .map(|field| FunctionRecord {
                name: field.name.into(),
                resolution: Resolution::Resolved {
                    object: 0,
                    file_offset: object_facts(&provider).2,
                },
            })
            .collect();
        let interface = |index| SurfaceRecord {
            source: SurfaceSource::Interface {
                index,
                raw_name_hex: Some("504b4353203131".into()),
                name_lossy: Some("PKCS 11".into()),
                name_error: None,
                flags: 0,
                classification: InterfaceClassification::ExactStandard,
            },
            acquisition: Acquisition::Ok,
            version: Some(Version { major: 3, minor: 0 }),
            walk: WalkOutcome::Full,
            functions: functions.clone(),
        };
        manifest.surfaces.extend([interface(0), interface(1)]);
        std::fs::copy("/bin/ls", &provider).unwrap();
        let mut scan = scanned_manifest_replacement(&paths, &targets);
        let (key, _, offset) = object_facts(&provider);
        scan.tables[0].version = (3, 0);
        scan.tables[0].entries = pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
            .flat_map(|field| {
                std::iter::repeat_n(
                    ScannedEntry {
                        name: field.name,
                        object: key,
                        object_path: provider.display().to_string(),
                        file_offset: offset,
                    },
                    2,
                )
            })
            .collect();
        let pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("duplicate-table.json", manifest);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules: vec![scan],
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("one table cannot be reused for two manifest surfaces");
        assert!(error.to_string().contains("object 0"), "{error:#}");
    }

    #[test]
    fn discovery_stale_module_requires_coverage_for_unresolved_claims() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let mut manifest = valid_manifest_for(&paths, &targets);
        manifest.surfaces[0].functions[66].resolution = Resolution::NullPointer;
        std::fs::copy("/bin/ls", &provider).unwrap();
        let mut scan = scanned_manifest_replacement(&paths, &targets);
        scan.tables[0].entries.pop();
        let pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("unresolved-claim.json", manifest);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules: vec![scan],
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("discarded unresolved records still require table coverage");
        assert!(error.to_string().contains("object 0"), "{error:#}");
    }

    #[test]
    fn discovery_mixed_manifest_drops_only_the_stale_dependency_claims() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let replaced = dir.path().join("replaced.so");
        let fresh = dir.path().join("fresh.so");
        for path in [&provider, &replaced, &fresh] {
            std::fs::copy("/bin/sh", path).unwrap();
        }
        let paths = vec![provider.clone(), replaced.clone(), fresh.clone()];
        let mut targets = vec![0; 67];
        targets[0] = 1;
        targets[1] = 2;
        targets[2] = 2;
        targets[3] = 1;
        let mut manifest = valid_manifest_for(&paths, &targets);
        let stale_offset = object_facts(&replaced).2;
        let fresh_offset = object_facts(&fresh).2;
        manifest.alias_groups = vec![
            AliasGroup {
                object: 1,
                file_offset: stale_offset,
                entries: vec![
                    AliasEntry {
                        surface: 0,
                        name: manifest.surfaces[0].functions[0].name.clone(),
                    },
                    AliasEntry {
                        surface: 0,
                        name: manifest.surfaces[0].functions[3].name.clone(),
                    },
                ],
            },
            AliasGroup {
                object: 2,
                file_offset: fresh_offset,
                entries: vec![
                    AliasEntry {
                        surface: 0,
                        name: manifest.surfaces[0].functions[1].name.clone(),
                    },
                    AliasEntry {
                        surface: 0,
                        name: manifest.surfaces[0].functions[2].name.clone(),
                    },
                ],
            },
        ];

        std::fs::copy("/bin/ls", &replaced).unwrap();
        let mut scan_targets = targets.clone();
        scan_targets[1] = 0;
        scan_targets[2] = 0;
        let mut scan = scanned_manifest_replacement(&paths, &scan_targets);
        scan.tables[0].entries[4].file_offset += 1;
        let scan_pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("mixed-valid.json", manifest);
        assert_eq!(input.stale.len(), 1);
        assert_eq!(input.stale[0].object, 1);

        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let discovered = discovered_from_inputs(vec![view], vec![scan], scan_pins, vec![input]);

        assert_eq!(discovered.counters.manifest_fallbacks.len(), 1);
        assert_eq!(discovered.discovery.manifest_object_fallbacks.len(), 1);
        assert_eq!(discovered.manifests.len(), 1);
        let filtered = &discovered.manifests[0];
        assert_eq!(filtered.surfaces.len(), 1);
        assert_eq!(filtered.surfaces[0].walk, WalkOutcome::Full);
        assert_eq!(filtered.surfaces[0].functions.len(), 67);
        for index in [0, 3] {
            assert!(matches!(
                &filtered.surfaces[0].functions[index].resolution,
                Resolution::UnusableFile { reason, path_hex }
                    if reason == "superseded by exact scan fallback" && path_hex.is_empty()
            ));
        }
        for index in [1, 2] {
            assert!(matches!(
                filtered.surfaces[0].functions[index].resolution,
                Resolution::Resolved { object: 1, file_offset } if file_offset == fresh_offset
            ));
        }
        assert_eq!(
            filtered
                .objects
                .iter()
                .map(|object| (object.id, object.path.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (0, provider.to_str().unwrap()),
                (1, fresh.to_str().unwrap())
            ]
        );
        assert_eq!(
            filtered
                .provenance_objects
                .iter()
                .map(|object| object.path.as_str())
                .collect::<Vec<_>>(),
            vec![provider.to_str().unwrap(), fresh.to_str().unwrap()]
        );
        assert_eq!(filtered.alias_groups.len(), 1);
        assert_eq!(filtered.alias_groups[0].object, 1);
        assert_eq!(filtered.alias_groups[0].entries.len(), 2);
        let module_objects = &discovered.discovery.modules[0].objects;
        let sources_for = |path: &Path| {
            let key = object_facts(path).0;
            module_objects
                .iter()
                .find(|object| {
                    object.dev == (key.device.major, key.device.minor) && object.ino == key.inode
                })
                .map(|object| object.sources.as_slice())
        };
        assert_eq!(
            sources_for(&provider),
            Some(["scan", "manifest"].as_slice())
        );
        assert_eq!(sources_for(&replaced), Some(["scan"].as_slice()));
        assert_eq!(sources_for(&fresh), Some(["manifest"].as_slice()));
        assert_eq!(
            discovered.plan.entries_seen, 72,
            "62 exact scan/manifest claims count once; distinct claims remain"
        );
        assert_eq!(discovered.plan.surfaces.len(), 2);
        assert_eq!(
            discovered.plan.modules[0]
                .tables
                .iter()
                .map(|table| (table.source, table.entries))
                .collect::<Vec<_>>(),
            vec![("scan", 67), ("manifest", 67)]
        );
        assert_eq!(
            discovered
                .plan
                .skipped
                .iter()
                .filter(|skip| skip.reason == "superseded by exact scan fallback")
                .count(),
            2
        );
    }

    #[test]
    fn discovery_dependency_fallback_rejects_an_unrelated_modules_table() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let replaced = dir.path().join("replaced.so");
        let unrelated = dir.path().join("unrelated.so");
        for path in [&provider, &replaced, &unrelated] {
            std::fs::copy("/bin/sh", path).unwrap();
        }
        let paths = vec![provider.clone(), replaced.clone()];
        let mut manifest_targets = vec![0; 67];
        manifest_targets[0] = 1;
        let manifest = valid_manifest_for(&paths, &manifest_targets);

        std::fs::copy("/bin/ls", &replaced).unwrap();
        let owner_scan = scanned_manifest_replacement(&paths, &vec![0; 67]);
        let unrelated_scan =
            scanned_manifest_replacement(&[unrelated, replaced], &manifest_targets);
        let modules = vec![owner_scan, unrelated_scan];
        let (pins, skipped) = pin_scanned_objects(
            std::process::id(),
            &modules,
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let input = manifest_input_from_pinning("unrelated.json", manifest);
        assert_eq!(input.stale.len(), 1);

        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules,
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("only the exact manifest module's scan view may replace its dependency");
        assert!(error.to_string().contains("object 1"), "{error:#}");
    }

    #[test]
    fn discovery_fallback_fails_when_the_proof_module_is_refused_at_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let replaced = dir.path().join("replaced.so");
        let unrelated = dir.path().join("unrelated.so");
        for path in [&provider, &replaced, &unrelated] {
            std::fs::copy("/bin/sh", path).unwrap();
        }
        let paths = vec![provider.clone(), replaced.clone()];
        let mut targets = vec![0; 67];
        targets[0] = 1;
        let manifest = valid_manifest_for(&paths, &targets);
        std::fs::copy("/bin/ls", &replaced).unwrap();

        let mut proof_module = scanned_manifest_replacement(&paths, &targets);
        let (provider_key, _, _) = object_facts(&provider);
        proof_module.tables[0]
            .entries
            .extend(
                (0..p11scope_ebpf_common::MAX_SLOTS).map(|index| ScannedEntry {
                    name: "C_Initialize",
                    object: provider_key,
                    object_path: provider.display().to_string(),
                    file_offset: 0x1000_0000 + u64::from(index),
                }),
            );
        let unrelated_module = scanned_manifest_replacement(&[unrelated, replaced], &targets);
        let modules = vec![proof_module, unrelated_module];
        let (pins, skipped) = pin_scanned_objects(
            std::process::id(),
            &modules,
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let input = manifest_input_from_pinning("capacity-proof.json", manifest);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules,
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered).expect_err(
            "an unrelated admitted module using the dependency cannot preserve the proof",
        );
        assert!(error.to_string().contains("proof"), "{error:#}");
    }

    #[test]
    fn discovery_fallback_binding_rejects_a_proof_table_lost_during_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let manifest = valid_manifest_for(&paths, &targets);
        std::fs::copy("/bin/ls", &provider).unwrap();
        let scan = scanned_manifest_replacement(&paths, &targets);
        let mut pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("reconciliation-loss.json", manifest);
        let proof = scanned_replacement(
            &input.manifest,
            &input.stale[0],
            std::slice::from_ref(&scan),
            &pins,
            &input.pins,
        )
        .expect("the pristine scan table proves the pending fallback");
        let (mut reconciled, _, _) =
            reconcile_scanned_modules(std::slice::from_ref(&scan), &mut pins);
        reconciled[0].scanned.tables.clear();
        reconciled[0].entry_objects.clear();

        assert!(
            bind_fallback_proof(&proof, &reconciled).is_none(),
            "a candidate locator is not proof after its exact table is gone"
        );
    }

    #[test]
    fn discovery_open_stale_sole_source_is_fatal_after_scan_availability_is_known() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let manifest = valid_manifest_for(&[provider.clone()], &vec![0; 67]);
        std::fs::remove_file(&provider).unwrap();
        let input = manifest_input_from_pinning("sole-source.json", manifest);
        let mut discovered = lifecycle_discovered(Vec::new());
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered).expect_err("no scan replacement is fatal");
        assert!(
            error.to_string().contains("stale manifest object"),
            "{error:#}"
        );
    }

    #[test]
    fn discovery_mixed_manifest_cannot_hide_a_stale_sole_source_object() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let replaced = dir.path().join("replaced.so");
        let sole = dir.path().join("sole.so");
        for path in [&provider, &replaced, &sole] {
            std::fs::copy("/bin/sh", path).unwrap();
        }
        let mut targets = vec![0; 67];
        targets[0] = 1;
        targets[1] = 2;
        let manifest = valid_manifest_for(
            &[provider.clone(), replaced.clone(), sole.clone()],
            &targets,
        );
        std::fs::copy("/bin/ls", &replaced).unwrap();
        std::fs::remove_file(&sole).unwrap();

        let mut scan_targets = targets.clone();
        scan_targets[1] = 0;
        let scan = scanned_manifest_replacement(&[provider, replaced], &scan_targets);
        let scan_pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("mixed.json", manifest);
        assert_eq!(input.stale.len(), 2);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules: vec![scan],
                pins: scan_pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("the second stale object has no scanned replacement");
        assert!(error.to_string().contains("object 2"), "{error:#}");
    }

    #[derive(Debug)]
    struct FakeSession(std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>);

    impl Drop for FakeSession {
        fn drop(&mut self) {
            self.0.borrow_mut().push("drop");
        }
    }

    /// Mutation caught: starting before the precheck would attach against a raw,
    /// potentially recycled named PID.
    #[test]
    fn named_generation_change_before_attach_never_starts_a_session() {
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stale = view.id();
        let mut discovered = lifecycle_discovered(vec![view]);
        let starts = Cell::new(0);
        let error = start_retained_with(
            &mut discovered,
            true,
            |_| vec![stale],
            |_, _| {
                starts.set(starts.get() + 1);
                Ok(FakeSession(Default::default()))
            },
        )
        .expect_err("a named generation change is fatal");

        assert!(error.to_string().contains("before attach"), "{error:#}");
        assert_eq!(starts.get(), 0, "no attach action may follow the mismatch");
    }

    /// Mutation caught: returning the new session before the postcheck would make its
    /// ring/maps consumable; failing without dropping it would leave its links live.
    #[test]
    fn named_generation_change_during_attach_drops_before_event_consumption() {
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stale = view.id();
        let mut discovered = lifecycle_discovered(vec![view]);
        let checks = Cell::new(0);
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let error = start_retained_with(
            &mut discovered,
            true,
            |_| {
                checks.set(checks.get() + 1);
                (checks.get() == 2).then_some(stale).into_iter().collect()
            },
            |_, _| {
                log.borrow_mut().push("start");
                Ok(FakeSession(std::rc::Rc::clone(&log)))
            },
        )
        .expect_err("a named generation change is fatal");

        assert!(error.to_string().contains("while attaching"), "{error:#}");
        assert_eq!(*log.borrow(), ["start", "drop"]);
        assert!(!log.borrow().contains(&"consume"));
    }

    /// Mutation caught: retrying without subtracting an originally accepted stale
    /// view can spin forever under cgroup churn. Three accepted views permit only
    /// three stale-session retries, followed by the final stable start.
    #[test]
    fn cgroup_retries_retire_one_original_view_each_time_and_publish_partial() {
        let views: Vec<_> = (0..3)
            .map(|id| ProcessView::open(ProcessViewId(id), std::process::id()).unwrap())
            .collect();
        let original: Vec<_> = views.iter().map(ProcessView::id).collect();
        let mut discovered = lifecycle_discovered(views);
        let checks = Cell::new(0usize);
        let starts = Cell::new(0usize);
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let session = start_retained_with(
            &mut discovered,
            false,
            |_| {
                checks.set(checks.get() + 1);
                if checks.get() % 2 == 0 {
                    original
                        .get(checks.get() / 2 - 1)
                        .copied()
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                }
            },
            |_, _| {
                starts.set(starts.get() + 1);
                log.borrow_mut().push("start");
                Ok(FakeSession(std::rc::Rc::clone(&log)))
            },
        )
        .unwrap();

        assert_eq!(starts.get(), original.len() + 1);
        assert!(discovered.views.is_empty());
        assert_eq!(
            discovered
                .counters
                .object_skips
                .iter()
                .filter(|skip| skip.reason == STALE_VIEW_REASON)
                .count(),
            original.len(),
            "each retired accepted view remains accounted internally"
        );
        assert_eq!(
            discovered.plan.skipped.len(),
            1,
            "identical public cgroup losses use the existing bounded deduplication"
        );
        assert!(
            discovered
                .plan
                .skipped
                .iter()
                .map(render::capture_skipped_out)
                .all(|skip| skip.name == "discovery subject"
                    && skip.reason == "discovery unavailable")
        );
        assert_eq!(
            log.borrow()
                .iter()
                .filter(|event| **event == "drop")
                .count(),
            original.len(),
            "every stale post-start pass tears down its whole session"
        );
        drop(session);
    }

    /// Mutation caught: retaining only the initial `Agreed` outcome drops the
    /// manifest's valid offsets when its sole agreeing scan owner is retired.
    #[test]
    fn stale_sole_owner_agreement_falls_back_to_the_retained_manifest() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
        let stale = view.id();
        let mut discovered = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        assert_eq!(discovered.plan.slots.len(), 1);
        assert_eq!(discovered.plan.modules[0].source, "scan+manifest");
        assert!(
            discovered.plan.slots[0].semantic_authorized,
            "an agreed explicit manifest remains an exact plan claim"
        );
        assert_eq!(
            discovered.plan.slots[0].semantics,
            crate::kinds::descriptor("C_Sign").unwrap()
        );
        assert_eq!(discovered.plan.entries_seen, 1);

        remove_stale_views(&mut discovered, &[stale]).unwrap();

        assert_eq!(discovered.plan.slots.len(), 1);
        assert_eq!(discovered.plan.slots[0].names, ["C_Sign"]);
        assert_eq!(discovered.plan.slots[0].file_offset, 0x40);
        assert!(discovered.plan.slots[0].semantic_authorized);
        assert_eq!(discovered.plan.modules[0].source, "manifest");
        assert_eq!(discovered.counters.uncorroborated, 1);
        assert_eq!(discovered.identity_mismatches, 0);
    }

    /// Mutation caught: a stale path-matching view's mismatch must not remain
    /// latched and abort the rebuild after that view's scan slot is subtracted.
    #[test]
    fn stale_only_identity_mismatch_becomes_manifest_fallback_for_stable_scope() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let path = provider.display().to_string();
        let own = pin_as_manifest_object(&path);
        let old_sha = own.pinned().next().unwrap().sha256.to_string();
        let manifest = manifest_naming(&path, Some(old_sha));

        let replacement = dir.path().join("replacement.so");
        std::fs::copy("/bin/true", &replacement).unwrap();
        std::fs::rename(&replacement, &provider).unwrap();
        let file = p11scope_manifest::identity::open_object(&provider).unwrap();
        let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let key = ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: mapping.device_major,
                minor: mapping.device_minor,
            },
            inode: mapping.inode,
        };
        let module = ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
            key,
            path: path.clone(),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: path.clone(),
                    file_offset: 0x80,
                }],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
            }],
            interfaces: vec![],
        };
        let (scan_pins, skipped) = pin_scanned_objects(
            std::process::id(),
            std::slice::from_ref(&module),
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let stale = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stable = ProcessView::open(ProcessViewId(1), std::process::id()).unwrap();
        let stale_id = stale.id();
        let input = ManifestInput {
            path: PathBuf::from("stale-manifest.json"),
            manifest,
            pins: own,
            stale: Vec::new(),
        };
        let mut discovered =
            discovered_from_inputs(vec![stale, stable], vec![module], scan_pins, vec![input]);
        assert_eq!(discovered.identity_mismatches, 1);
        assert_eq!(
            discovered.plan.slots.len(),
            1,
            "the scan initially keeps capture viable"
        );

        remove_stale_views(&mut discovered, &[stale_id]).unwrap();

        assert_eq!(
            discovered.views.len(),
            1,
            "the unrelated stable view remains"
        );
        assert_eq!(discovered.identity_mismatches, 0);
        assert_eq!(discovered.plan.modules[0].source, "manifest");
        assert_eq!(discovered.plan.slots[0].names, ["C_Sign"]);
    }

    /// Mutation caught: subtracting the only conflicting scan owner must recompute
    /// the manifest as uncorroborated instead of preserving stale conflict evidence.
    #[test]
    fn stale_conflict_owner_is_removed_from_final_counter_and_corroboration() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
        let stale = view.id();
        let mut discovered = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        assert_eq!(discovered.counters.conflicts, 1);
        assert_eq!(discovered.plan.slots.len(), 2);

        remove_stale_views(&mut discovered, &[stale]).unwrap();

        assert_eq!(discovered.counters.conflicts, 0);
        assert_eq!(discovered.plan.slots.len(), 1);
        assert_eq!(discovered.plan.modules[0].source, "manifest");
        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["uncorroborated"]
        );
    }

    #[test]
    fn repeated_manifest_only_outcomes_preserve_order_and_multiplicity() {
        let (_, pins) = pinned_self();
        let summary = pins.pinned().next().unwrap();
        let path = summary.path.to_string();
        let sha256 = summary.sha256.to_string();
        let input = |name| ManifestInput {
            path: PathBuf::from(name),
            manifest: manifest_naming(&path, Some(sha256.clone())),
            pins: pin_as_manifest_object(&path),
            stale: Vec::new(),
        };
        let mut discovered = lifecycle_discovered(Vec::new());
        discovered.manifest_inputs = vec![input("first.json"), input("second.json")];

        rebuild_discovered(&mut discovered).unwrap();

        assert_eq!(discovered.plan.modules.len(), 1);
        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["uncorroborated", "uncorroborated"],
            "one accepted outcome must remain visible for each repeated --manifest input"
        );
    }

    #[test]
    fn repeated_manifest_outcomes_recompute_after_the_scan_owner_is_removed() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
        let stale = view.id();
        let mut duplicate = ManifestInput {
            path: PathBuf::from("duplicate-manifest.json"),
            manifest: input.manifest.clone(),
            pins: pin_as_manifest_object(&input.manifest.module_path),
            stale: Vec::new(),
        };
        let Resolution::Resolved { file_offset, .. } =
            &mut duplicate.manifest.surfaces[0].functions[0].resolution
        else {
            unreachable!()
        };
        *file_offset = 0x80;
        let mut discovered =
            discovered_from_inputs(vec![view], modules, pins, vec![input, duplicate]);

        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["agreed", "conflict"],
            "outcomes retain repeated manifest input order"
        );

        remove_stale_views(&mut discovered, &[stale]).unwrap();

        assert_eq!(discovered.plan.modules.len(), 1);
        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["uncorroborated", "uncorroborated"],
            "rebuilds must retain each accepted manifest outcome, not synthesize one"
        );
    }

    #[test]
    fn later_manifest_identity_collision_drops_stale_scan_ids_before_planning() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let dependency = dir.path().join("dependency.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        std::fs::copy("/bin/sh", &dependency).unwrap();
        let paths = vec![provider.clone(), dependency.clone()];
        let targets = vec![1; 67];
        let scan = scanned_manifest_replacement(&paths, &targets);
        let dependency_key = scan.tables[0].entries[0].object;
        let scan_pins = pin_scan(&scan);

        // `copy` truncates the existing file: its raw map key remains the same,
        // while its opened pin and hash become incomparable to the scan's pin.
        std::fs::copy("/bin/true", &dependency).unwrap();
        let input = manifest_input_from_pinning(
            "later-collision.json",
            valid_manifest_for(&paths, &targets),
        );
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stale = view.id();
        let mut discovered = lifecycle_discovered(vec![view]);
        discovered.scan_inputs.insert(
            stale,
            ScanInput {
                modules: vec![scan],
                pins: scan_pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        rebuild_discovered(&mut discovered).unwrap();

        assert!(
            discovered
                .plan
                .modules
                .iter()
                .all(|module| discovered.pinned.summary(module.object).is_some()),
            "no pre-absorption module ID may reach the final plan"
        );
        assert!(
            discovered
                .plan
                .slots
                .iter()
                .all(|slot| discovered.pinned.summary(slot.object).is_some()),
            "no pre-absorption dependency ID may reach the final plan"
        );
        assert!(
            discovered.plan.slots.iter().all(|slot| {
                discovered
                    .pinned
                    .summary(slot.object)
                    .is_none_or(|summary| summary.key != dependency_key)
            }),
            "the rejected collision group cannot lend its old dependency offsets"
        );
        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["conflict"],
            "the surviving exact provider owns the conflict outcome"
        );

        remove_stale_views(&mut discovered, &[stale]).unwrap();
        assert!(
            discovered
                .plan
                .slots
                .iter()
                .all(|slot| discovered.pinned.summary(slot.object).is_some()),
            "a stable-view rebuild resolves fresh final IDs from pristine inputs"
        );
    }

    #[test]
    fn corroboration_marks_the_exact_reconciled_object_not_the_raw_key_peer() {
        let key = ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 42,
        };
        let module = |view, object, path: &str, offset| ReconciledModule {
            object,
            entry_objects: vec![vec![object]],
            scanned: ScannedModule {
                view,
                mount_namespace: current_mount_namespace(),
                key,
                path: path.into(),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: vec![ScannedEntry {
                        name: "C_Sign",
                        object: key,
                        object_path: path.into(),
                        file_offset: offset,
                    }],
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000 + offset,
                }],
                interfaces: vec![],
            },
        };
        let first = module(ProcessViewId(0), PinnedObjectId(100), "/first.so", 0x10);
        let second = module(ProcessViewId(0), PinnedObjectId(200), "/second.so", 0x20);
        let mut counters = DiscoveryCounters::default();
        let plan = build_current_plan(
            &[first, second],
            &[],
            &PinnedObjects::empty(),
            &mut counters,
            // The exact final object, not its equal-key peer, owns the outcome.
            &[PinnedObjectId(200)].into_iter().collect(),
            0,
            0,
        )
        .unwrap();

        let first = plan
            .modules
            .iter()
            .find(|module| module.object == PinnedObjectId(100))
            .unwrap();
        let second = plan
            .modules
            .iter()
            .find(|module| module.object == PinnedObjectId(200))
            .unwrap();
        assert!(!first.corroborated);
        assert_eq!(first.source, "scan");
        assert!(second.corroborated);
        assert_eq!(second.source, "scan+manifest");

        counters
            .corroboration
            .push(([PinnedObjectId(200)].into_iter().collect(), "conflict"));
        assert_eq!(
            corroboration_of(&counters, first),
            ["single_source"],
            "a raw-key peer must not contribute public outcome evidence"
        );
        assert_eq!(
            corroboration_of(&counters, second),
            ["conflict"],
            "the exact reconciled module retains its outcome array"
        );
    }

    #[test]
    fn pending_fallback_outcome_follows_the_final_overlay_canonical_id_without_authority() {
        let key = ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: 0,
                minor: 102,
            },
            inode: 42,
        };
        let module = |view: ProcessViewId, path: &str| ReconciledModule {
            object: PinnedObjectId(200),
            entry_objects: vec![vec![PinnedObjectId(200)]],
            scanned: ScannedModule {
                view,
                mount_namespace: current_mount_namespace(),
                key,
                path: path.into(),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: vec![ScannedEntry {
                        name: "C_Sign",
                        object: key,
                        object_path: path.into(),
                        file_offset: 0x10,
                    }],
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000,
                }],
                interfaces: vec![],
            },
        };
        let first = module(ProcessViewId(0), "/overlay/first.so");
        let second = module(ProcessViewId(1), "/overlay/second.so");
        let mut counters = DiscoveryCounters::default();
        let corroborated = bind_pending_corroboration(
            vec![PendingCorroboration {
                owners: vec![OutcomeOwner::Scan(ScanOutcomeLocator::module(
                    &second.scanned,
                ))],
                label: "object_fallback",
            }],
            &[first, second],
            &PinnedObjects::empty(),
            &mut counters,
        )
        .unwrap();

        assert!(
            corroborated.is_empty(),
            "a scan-only overlay collapse can bind fallback evidence but never semantic authority"
        );
        assert_eq!(
            counters.corroboration,
            vec![(
                [PinnedObjectId(200)].into_iter().collect(),
                "object_fallback"
            )],
            "the overlay peer's fallback locator binds to its final canonical ID, never a stale pre-remap ID"
        );
    }

    #[test]
    fn pending_corroboration_rebuild_resolves_the_current_final_id() {
        let key = ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 42,
        };
        let module = |object| ReconciledModule {
            object,
            entry_objects: vec![vec![object]],
            scanned: ScannedModule {
                view: ProcessViewId(0),
                mount_namespace: current_mount_namespace(),
                key,
                path: "/stable-view.so".into(),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: vec![ScannedEntry {
                        name: "C_Sign",
                        object: key,
                        object_path: "/stable-view.so".into(),
                        file_offset: 0x10,
                    }],
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000,
                }],
                interfaces: vec![],
            },
        };
        let first = module(PinnedObjectId(10));
        let owner = OutcomeOwner::Scan(ScanOutcomeLocator::module(&first.scanned));
        let second = module(PinnedObjectId(20));
        let mut counters = DiscoveryCounters::default();
        let corroborated = bind_pending_corroboration(
            vec![PendingCorroboration {
                owners: vec![owner],
                label: "conflict",
            }],
            &[second],
            &PinnedObjects::empty(),
            &mut counters,
        )
        .unwrap();

        assert_eq!(corroborated, [PinnedObjectId(20)].into_iter().collect());
        assert_eq!(
            counters.corroboration,
            vec![([PinnedObjectId(20)].into_iter().collect(), "conflict")],
            "a rebuild cannot retain an earlier capture-local numeric ID"
        );
    }

    #[test]
    fn manifest_v1_and_v2_are_rejected_with_rediscovery_instruction() {
        for schema in ["p11scope-manifest/1", "p11scope-manifest/2"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("m.json");
            std::fs::write(
                &path,
                format!(
                    r#"{{"schema":"{schema}","module_path":"/opt/p.so","objects":[],"interface_list":{{"status":"absent"}},"surfaces":[],"vendor_interfaces":[],"alias_groups":[]}}"#
                ),
            )
            .unwrap();
            let err = read_manifest_file(&path).unwrap_err().to_string();
            assert!(err.contains("rediscover"), "{err}");
        }
    }

    /// Our own executable, scanned and pinned the way a capture pins a provider:
    /// a real `PinnedObjects` with one key in it, with no privileges needed.
    fn pinned_self() -> (Vec<ScannedModule>, PinnedObjects) {
        let hooks = crate::discovery::hooks::HookRegistry::builtin();
        let exe = std::env::current_exe().unwrap();
        // Unbounded on purpose: `pin_scanned_object` caps on the whole file size, and
        // this test binary is already at 96% of the 64 MiB default. The byte caps are
        // not what these tests are about, and a silent skip would fail them with
        // "the hinted executable is pinned", which names the symptom, not the cause.
        let limits = ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        };
        let mut budget = CaptureWorkBudget::new(limits);
        let outcome = scan_pid(
            &ScanRequest {
                pid: std::process::id(),
                hints: &[exe],
                hooks: &hooks,
            },
            &mut budget,
        )
        .unwrap();
        let modules = outcome.modules().to_vec();
        let (pinned, _) = pin_scanned_objects(std::process::id(), &modules, &mut budget).unwrap();
        assert_eq!(
            pinned.pinned().count(),
            1,
            "the hinted executable is pinned"
        );
        (modules, pinned)
    }

    #[test]
    fn coordinator_reuses_one_budget_across_process_scans_and_hashes() {
        use std::os::unix::fs::MetadataExt as _;

        let exe = std::env::current_exe().unwrap();
        let inode = std::fs::metadata(&exe).unwrap().ino();
        let maps = p11scope_manifest::maps::parse_maps(&std::fs::read("/proc/self/maps").unwrap())
            .unwrap();
        let scan_bytes: u64 = maps
            .iter()
            .filter(|m| m.inode == inode && m.permissions[0] == b'r' && m.permissions[2] != b'x')
            .map(|m| m.end - m.start)
            .sum();
        let hash_bytes = std::fs::metadata(&exe).unwrap().len();
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: scan_bytes.max(hash_bytes),
            total_bytes: scan_bytes + hash_bytes,
        });
        let hints = vec![exe];
        let hooks = HookRegistry::builtin();
        let mut counters = DiscoveryCounters::default();
        let first_view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let (_, first) =
            scan_and_pin(&first_view, &hints, &hooks, &mut budget, &mut counters).unwrap();
        let second_view = ProcessView::open(ProcessViewId(1), std::process::id()).unwrap();
        let (_, second) =
            scan_and_pin(&second_view, &hints, &hooks, &mut budget, &mut counters).unwrap();
        assert_eq!(first.pinned().count(), 1);
        assert_eq!(
            second.pinned().count(),
            0,
            "the later scan cannot renew bytes"
        );
        assert!(
            counters
                .object_skips
                .iter()
                .any(|skip| skip.reason.contains("capture attempted-I/O ceiling")),
            "budget exhaustion must remain explicit: {:?}",
            counters.object_skips
        );
    }

    /// The pin `pin_manifest_objects` produces for one manifest object: filed under
    /// the path the manifest names (`ObjectRecord.path`, which it opens), keyed by the
    /// identity that path resolves to right now.
    fn pin_as_manifest_object(object_path: &str) -> PinnedObjects {
        let file = p11scope_manifest::identity::open_object(Path::new(object_path)).unwrap();
        let found = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let identity = p11scope_manifest::identity::inspect_file(&file)
            .unwrap()
            .identity;
        let mut manifest = manifest_naming(object_path, identity.sha256.clone());
        manifest.objects[0].identity = identity.clone();
        manifest.provenance_objects[0] = p11scope_manifest::manifest::ProvenanceObject {
            path: object_path.to_string(),
            device_major: found.device_major,
            device_minor: found.device_minor,
            inode: found.inode,
            identity,
        };
        manifest.surfaces[0].acquisition = p11scope_manifest::manifest::Acquisition::Absent;
        manifest.surfaces[0].walk = p11scope_manifest::manifest::WalkOutcome::NotWalked;
        manifest.surfaces[0].functions.clear();
        pin_manifest_objects(&manifest).unwrap()
    }

    fn entry(name: &'static str, object: ObjectKey, file_offset: u64) -> ScannedEntry {
        ScannedEntry {
            name,
            object,
            object_path: format!("/opt/{}.so", object.inode),
            file_offset,
        }
    }

    /// An entry whose object could not be pinned has no attach path of its own. Left
    /// in the plan it either kills the whole capture (§4.10 says one unusable
    /// dependency must not) or, once a manifest is in the same plan, falls back to
    /// the *observer's* file at the target's pathname — a different file, silently
    /// probed at scan-derived offsets.
    #[test]
    fn a_table_entry_whose_object_was_not_pinned_never_becomes_a_slot() {
        let (mut modules, mut pinned) = pinned_self();
        let pinned_key = pinned.pinned().next().unwrap().key;
        let unpinned_key = ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: 0xffff,
                minor: 0xffff,
            },
            inode: u64::MAX,
        };
        modules[0]
            .tables
            .push(crate::discovery::scan::ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![
                    entry("C_Sign", pinned_key, 0x10),
                    entry("C_Verify", unpinned_key, 0x20),
                ],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
            });
        modules[0].tables.last_mut().unwrap().entries[0].object_path = modules[0].path.clone();

        let (reconciled, _, dropped) = reconcile_scanned_modules(&modules, &mut pinned);
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(dropped[0].subject, "C_Verify");
        assert!(
            dropped[0]
                .reason
                .contains("could not be reconciled to a comparable pinned object"),
            "{dropped:?}"
        );

        let plan = plan::build_from_reconciled_modules(&reconciled);
        assert_eq!(plan.slots.len(), 1, "only the pinned target attaches");
        for slot in &plan.slots {
            assert!(
                pinned.attach_path_for(slot.object).is_ok(),
                "every scanned slot must have a pinned object of its own: {slot:?}"
            );
        }
        // A record the scan decoded and could not use is still a record it saw:
        // dropping it from `entries_seen` would make `slots` vs `table_entries`
        // read as "everything seen was attached". It is reported as a skip too,
        // the same way a NULL entry is, and attributed to its own module.
        assert_eq!(plan.entries_seen, 2, "the dropped entry stays counted");
        assert_eq!(plan.skipped.len(), 1, "{:?}", plan.skipped);
        assert_eq!(plan.skipped[0].subject, "C_Verify");
        assert_eq!(plan.modules[0].skipped, plan.skipped);
        // The reason the drop is recorded on the table rather than added to the
        // total afterwards: per-surface counts and the total stay one number.
        assert_eq!(
            plan.surfaces.iter().map(|s| s.functions).sum::<usize>(),
            plan.entries_seen,
            "every record counted in table_entries belongs to a surface"
        );
    }

    #[test]
    fn an_unpinned_entry_skip_is_bounded_in_every_capture_output() {
        let raw = Skipped {
            subject: "C_Sign".into(),
            reason: "/private/ROUND4_OBJECT_PATH_SENTINEL.so was not pinned: \
                     ROUND4_ERROR_CHAIN_SENTINEL"
                .into(),
        };
        let (mut modules, mut pinned) = pinned_self();
        modules[0]
            .tables
            .push(crate::discovery::scan::ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![],
                null_entries: vec![],
                unpinned: vec![raw.clone()],
                address: 0x7000,
            });
        let reconciled = reconcile_for_test(&modules, &mut pinned);
        let plan = plan::build_from_reconciled_modules(&reconciled);
        assert_eq!(plan.skipped, vec![raw.clone()]);
        assert_eq!(plan.modules[0].skipped, vec![raw]);

        let discovery = discovery_evidence(&plan, &pinned, &DiscoveryCounters::default());
        let mut evidence = render::Evidence {
            table_entries: plan.entries_seen,
            slots: plan.slots.len(),
            attached_probes: 0,
            attach_failures: vec![],
            aliased: vec![],
            skipped: plan
                .skipped
                .iter()
                .map(render::capture_skipped_out)
                .collect(),
            semantic_unverified_slots: 0,
            in_flight_at_end: 0,
            surfaces: plan.surfaces.clone(),
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            event_loss: 0,
            start_insert_failures: 0,
            unmatched_returns: 0,
            rv_update_failures: 0,
            cgroup_scope_failures: 0,
            semantic_capture_failures: 0,
            unregistered_mechanisms: 0,
            template_tail_failures: 0,
            process_tracking_fallbacks: 0,
            process_tracking_failures: 0,
            process_tracking_evictions: 0,
            state_reconciliations: 0,
            session_cancel_ambiguities: 0,
            session_cancel_unknown_flags: 0,
            operation_state_imports: 0,
            auth_state_ambiguities: 0,
            async_target_failures: 0,
            async_orphans: 0,
            async_duplicates: 0,
            async_evictions: 0,
            fork_state_ambiguities: 0,
            semantic_state_drops: 0,
            pending_at_end: 0,
            malformed_records: 0,
            orphan_ops: 0,
            unmatched_closes: 0,
            shape_decode_failures: 0,
            shape_decode_total_failures: 0,
            templates_truncated: false,
            provider_changed: false,
            discovery,
            completeness: "UNKNOWN",
        };
        evidence.verdict();
        let profile_capture = render::CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "test",
            policy: CapturePolicy::Allowlisted,
        };
        let state = semantics::State::with_policy(&plan, CapturePolicy::Allowlisted);
        let profile = render::profile_json(&[], &evidence, &state, &profile_capture);
        let metrics_capture = render::CaptureMeta {
            policy: CapturePolicy::AggregateOnly,
            ..profile_capture
        };
        let metrics = render::json(&[], &evidence, &metrics_capture);
        let trace = trace::evidence_line(&evidence, CapturePolicy::Allowlisted);

        for rendered in [
            serde_json::to_string(&profile).unwrap(),
            serde_json::to_string(&metrics).unwrap(),
            trace,
        ] {
            for sentinel in ["ROUND4_OBJECT_PATH_SENTINEL", "ROUND4_ERROR_CHAIN_SENTINEL"] {
                assert!(
                    !rendered.contains(sentinel),
                    "leaked {sentinel}: {rendered}"
                );
            }
        }
        for document in [profile, metrics] {
            assert_eq!(document["evidence"]["completeness"], "PARTIAL");
            assert_eq!(document["evidence"]["skipped"].as_array().unwrap().len(), 1);
            assert_eq!(
                document["evidence"]["discovery"][0]["skipped"],
                document["evidence"]["skipped"]
            );
            assert_eq!(
                document["evidence"]["skipped"][0],
                serde_json::json!({
                    "name": "C_Sign",
                    "reason": "function entry unavailable",
                })
            );
        }
    }

    /// An object the scan could not read at all is the loss `discovery[]` cannot
    /// show: the module it belonged to contributes no table, so it produces no
    /// entry to skip, no attach to fail and no counter to raise. Printed and
    /// dropped, it leaves a document whose every field says the capture was
    /// clean while a provider went unobserved.
    #[test]
    fn an_object_the_scan_could_not_read_is_published_not_only_printed() {
        let (modules, _) = pinned_self();
        // The same objects, pinned under a cap they cannot fit: every one is
        // skipped, exactly as a memfd, a deleted file or an unreadable mapping
        // would be — without needing one.
        let tiny = ScanLimits {
            per_object_bytes: 1024,
            total_bytes: 1024,
        };
        let (mut pinned, skips) = pin_scanned_objects(
            std::process::id(),
            &modules,
            &mut CaptureWorkBudget::new(tiny),
        )
        .unwrap();
        assert_eq!(pinned.pinned().count(), 0, "nothing could be pinned");
        assert!(!skips.is_empty(), "the scan reported the loss");

        let (reconciled, _, _) = reconcile_scanned_modules(&modules, &mut pinned);
        let mut plan = plan::build_from_reconciled_modules(&reconciled);
        assert!(
            plan.skipped.is_empty(),
            "the module published no table, so nothing else records the loss: {:?}",
            plan.skipped
        );

        record_object_skips(&mut plan, &skips);
        assert_eq!(plan.skipped.len(), skips.len(), "{:?}", plan.skipped);
        assert!(
            plan.skipped.iter().any(|s| s.reason.contains("too_large")),
            "{:?}",
            plan.skipped
        );

        // A cgroup scans many processes mapping the same provider; one loss is
        // one line however many processes hit it — and two *different* losses
        // are still two, which a dedupe that collapsed by subject would lose.
        let other = Skipped {
            subject: skips[0].subject.clone(),
            reason: "a second, different loss of the same object".into(),
        };
        let mixed: Vec<Skipped> = skips
            .iter()
            .chain(skips.iter())
            .cloned()
            .chain([other.clone()])
            .collect();
        let mut plan = plan::build_from_reconciled_modules(&reconciled);
        record_object_skips(&mut plan, &mixed);
        assert_eq!(plan.skipped.len(), skips.len() + 1, "{:?}", plan.skipped);
        assert!(plan.skipped.contains(&other), "{:?}", plan.skipped);
    }

    fn plan_with(slots: usize, refused: usize) -> plan::AttachPlan {
        let mut plan = plan::AttachPlan::from_slots(
            (0..slots)
                .map(|index| plan::Slot {
                    index: index as u32,
                    descriptor_index: 0,
                    object: PinnedObjectId(42),
                    object_path: "/opt/p11.so".into(),
                    file_offset: index as u64 * 8,
                    names: vec!["C_Sign".into()],
                    aliased: false,
                    semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
                    semantic_authorized: true,
                    semantic_ambiguous: false,
                    fork_safe: false,
                    module_ids: vec![plan::ModuleId(0)],
                })
                .collect(),
        );
        plan.modules = vec![plan::ModuleSummary {
            id: plan::ModuleId(0),
            object: PinnedObjectId(42),
            key: ObjectKey {
                device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
                inode: 42,
            },
            path: "/opt/p11.so".into(),
            tables: vec![],
            interfaces: 0,
            source: "scan",
            corroborated: false,
            skipped: vec![],
        }];
        plan.modules_skipped = (0..refused)
            .map(|i| Skipped {
                subject: format!("/opt/big{i}.so"),
                reason: "module needs 600 more of the 512 attach slots".into(),
            })
            .collect();
        plan.entries_seen = slots;
        plan
    }

    fn plan_with_pins(slots: usize, refused: usize) -> (plan::AttachPlan, PinnedObjects) {
        let (_, pins) = pinned_self();
        let pin = pins.pinned().next().unwrap();
        let mut plan = plan_with(slots, refused);
        for slot in &mut plan.slots {
            slot.object = pin.id;
            slot.object_path = pin.path.to_string();
        }
        plan.modules[0].object = pin.id;
        plan.modules[0].key = pin.key;
        plan.modules[0].path = pin.path.to_string();
        (plan, pins)
    }

    /// One provider over the slot ceiling must not cost the capture the other
    /// providers could still have shared: the refusal is evidence (and forces
    /// PARTIAL), not an abort. It stays an error only when nothing is left.
    #[test]
    fn a_partial_capacity_refusal_is_reported_and_only_an_empty_one_is_fatal() {
        assert_eq!(refusal_error(&plan_with(4, 0)), None, "nothing refused");
        assert_eq!(
            refusal_error(&plan_with(4, 1)),
            None,
            "one refused module must not lose the four slots that fit"
        );
        assert_eq!(refusal_error(&plan_with(0, 0)), None, "§4.10: not an error");
        let error = refusal_error(&plan_with(0, 1)).expect("a refusal with nothing left is fatal");
        assert!(error.contains("nothing to attach"), "{error}");
        assert!(error.contains("/opt/big0.so"), "{error}");

        // …and the refusal reaches evidence, which is what makes reporting it
        // instead of aborting honest: `render::Evidence::verdict` turns a
        // non-empty `modules_skipped` into PARTIAL (see `render`'s own tests).
        let (plan, pins) = plan_with_pins(4, 1);
        let evidence = discovery_evidence(&plan, &pins, &DiscoveryCounters::default());
        assert_eq!(evidence.modules_skipped.len(), 1);
        assert_eq!(evidence.modules_skipped[0].name, "/opt/big0.so");
        assert!(
            evidence.modules_skipped[0].reason.contains("attach slots"),
            "{:?}",
            evidence.modules_skipped[0]
        );
    }

    /// A manifest ignored as stale is the one §4.12 outcome with no module of
    /// its own in the plan — and the one most likely to be covering a provider
    /// the scan cannot read, which is then observed by nobody.
    #[test]
    fn an_ignored_stale_manifest_is_counted_as_uncorroborated() {
        let mut plan = plan_with(1, 0);
        assert_eq!(
            uncorroborated_count(&plan, 0, 0),
            0,
            "a scanned module is not"
        );
        assert_eq!(
            uncorroborated_count(&plan, 1, 0),
            1,
            "an ignored manifest must reach a counter, or it reaches none"
        );
        plan.modules[0].source = "manifest";
        assert_eq!(uncorroborated_count(&plan, 1, 0), 2, "both are counted");
        plan.modules[0].corroborated = true;
        assert_eq!(uncorroborated_count(&plan, 0, 0), 0);
        assert_eq!(uncorroborated_count(&plan, 0, 1), 1);
    }

    /// Both §4.12 outcomes that attach a union mark the module corroborated, so
    /// without the outcome itself an agreement and a conflict are the same
    /// record — and `discovery_conflicts` would have nothing explaining it.
    #[test]
    fn the_module_record_says_which_corroboration_outcome_it_got() {
        let (plan, pins) = plan_with_pins(1, 0);
        let object = plan.modules[0].object;
        for (outcome, label) in [
            (Corroboration::Agreed, "agreed"),
            (Corroboration::Conflict, "conflict"),
            (Corroboration::ScanEmpty, "scan_empty"),
            (Corroboration::IdentityMismatch, "identity_mismatch"),
        ] {
            let counters = DiscoveryCounters {
                corroboration: vec![([object].into_iter().collect(), corroboration_label(outcome))],
                ..DiscoveryCounters::default()
            };
            let evidence = discovery_evidence(&plan, &pins, &counters);
            assert_eq!(evidence.modules[0].corroboration, vec![label]);
        }
        // Nothing recorded: one source described it, and the record says so
        // rather than implying a second source failed to.
        let evidence = discovery_evidence(&plan, &pins, &DiscoveryCounters::default());
        assert_eq!(evidence.modules[0].corroboration, vec!["single_source"]);
        assert_eq!(evidence.modules[0].sources, vec!["scan"]);
    }

    #[test]
    fn late_collision_invalidates_fallback_evidence_without_discovery_evidence_panic() {
        let (plan, pins) = plan_with_pins(1, 0);
        let mut counters = DiscoveryCounters::default();
        counters.manifest_fallbacks.push(ManifestFallback {
            manifest: 0,
            object: 0,
            reason: ManifestStaleReason::IdentityMismatch,
            replacement: PinnedObjectId(u32::MAX),
            proof: BoundFallbackProof {
                module: PinnedObjectId(u32::MAX),
                tables: vec![],
                required_targets: BTreeMap::new(),
            },
        });

        let evidence = discovery_evidence(&plan, &pins, &counters);

        assert!(
            evidence.manifest_object_fallbacks.is_empty(),
            "a fallback whose exact replacement was rejected must not survive"
        );
    }

    /// A manifest records the `{device, inode}` its provider had on the host it was
    /// made on. Inode reuse after a rebuild is enough for that pair to collide with a
    /// *live* pin of an unrelated file — and the by-key lookup in `Session::start` is
    /// consulted first, so the collision wins and the manifest's offsets are applied
    /// to the wrong file. The mirror of the unpinned-entry hazard above.
    #[test]
    fn a_stale_recorded_identity_never_resolves_to_another_objects_pin() {
        let (_, mut pins) = pinned_self();
        let collision = pins.pinned().next().unwrap().key;

        // A second, unrelated file.
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let path = provider.display().to_string();
        let own = pin_as_manifest_object(&path);

        let mut m = manifest_naming(&path, Some("11".repeat(32)));
        // The stale pair, here colliding with the live pin of a different file.
        m.provenance_objects[0].device_major = collision.device.major;
        m.provenance_objects[0].device_minor = collision.device.minor;
        m.provenance_objects[0].inode = collision.inode;

        retarget_to_pins(&mut m, &[], &pins, &own);
        pins.absorb(own);

        let plan = plan::build_from_sources(&[], std::slice::from_ref(&m), &pins);
        let attach = pins.attach_path_for(plan.slots[0].object).unwrap();
        assert_eq!(
            std::fs::metadata(&attach).unwrap().ino(),
            std::fs::metadata(&provider).unwrap().ino(),
            "a manifest slot must attach into its own object, never into whatever \
             live pin happens to share the identity it recorded"
        );
    }

    /// `p11scope-discover` writes `objects[].path` as the `--module` argument was
    /// spelled and `provenance_objects[].path` as `/proc/self/maps` renders it — the
    /// resolved target. Any provider named through a symlink (`libykcs11.so` →
    /// `.so.2.x`, usrmerge `/lib` → `/usr/lib`) therefore has two different pathnames
    /// in one manifest, and a retarget that looked the pin up by the provenance path
    /// would find none: the recorded pair would survive into the plan, which either
    /// resolves to an unrelated file that shares it or fails to resolve at all.
    #[test]
    fn a_manifest_naming_its_object_and_its_provenance_differently_is_still_retargeted() {
        let (_, mut pins) = pinned_self();
        let collision = pins.pinned().next().unwrap().key;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("provider.so.2.4");
        std::fs::copy("/bin/sh", &real).unwrap();
        let link = dir.path().join("provider.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let (link_path, real_path) = (link.display().to_string(), real.display().to_string());

        let own = pin_as_manifest_object(&link_path);
        pins.absorb(pin_as_manifest_object(&link_path));

        // A pair nothing pins (a manifest reused after a rebuild — the case pinning
        // exists to support), then one colliding with a live pin of another file.
        for recorded in [
            ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: 0xffff,
                    minor: 0xffff,
                },
                inode: u64::MAX,
            },
            collision,
        ] {
            let mut m = manifest_naming(&link_path, Some("11".repeat(32)));
            m.provenance_objects[0].path = real_path.clone();
            m.provenance_objects[0].device_major = recorded.device.major;
            m.provenance_objects[0].device_minor = recorded.device.minor;
            m.provenance_objects[0].inode = recorded.inode;

            retarget_to_pins(&mut m, &[], &pins, &own);

            let plan = plan::build_from_sources(&[], std::slice::from_ref(&m), &pins);
            let attach = pins.attach_path_for(plan.slots[0].object).expect(
                "a manifest whose recorded identity is not the live one must still \
                 resolve — that reuse is what pinning by build-id and sha256 is for",
            );
            assert_eq!(
                std::fs::metadata(&attach).unwrap().ino(),
                std::fs::metadata(&real).unwrap().ino(),
                "recorded {recorded:?} must not decide what gets attached"
            );
        }
    }

    /// The glue that picks among the four §4.12 outcomes: which scanned module a
    /// manifest is talking about, and whether the bytes agree.
    #[test]
    fn scan_view_matches_by_hash_then_path_and_needs_a_pin() {
        let (modules, pinned) = pinned_self();
        let summary = pinned.pinned().next().unwrap();
        let (path, sha) = (summary.path.to_string(), summary.sha256.to_string());

        let m = manifest_naming(&path, Some(sha.clone()));
        let own = pin_as_manifest_object(&path);
        let view = scan_view(&m, &modules, &pinned, &own).expect("mapped and pinned");
        assert_eq!(view.modules[0].key, summary.key);
        assert!(view.agrees, "the recorded sha256 is the pinned one");
        let manifest_target = manifest_targets(&m, &own).unwrap();
        assert_eq!(manifest_target.len(), 1);
        let (manifest_target, manifest_offset) = manifest_target.iter().next().unwrap();
        assert_eq!(*manifest_offset, 0x40);
        assert_eq!(
            own.summary(*manifest_target).unwrap().path,
            path,
            "manifest targets resolve through their exact opened pin"
        );
        assert_eq!(
            scanned_targets(&view.modules, &pinned),
            Some(BTreeSet::new()),
            "our own executable publishes no PKCS#11 table"
        );

        // Same path, different bytes: §4.12's identity mismatch.
        let stale = manifest_naming(&path, Some("22".repeat(32)));
        assert_eq!(
            scan_view(&stale, &modules, &pinned, &own).map(|view| view.agrees),
            Some(false)
        );

        // Mapped but never pinned: nothing to compare against, so nothing corroborates
        // it — the trigger condition for the unpinned-slot bug above.
        let unpinned = manifest_naming(&path, Some(sha));
        assert!(
            scan_view(&unpinned, &modules, &PinnedObjects::empty(), &own).is_none(),
            "a module with no pin has no hash to agree or disagree with"
        );

        // A manifest for something the target does not map at all.
        let elsewhere = manifest_naming("/opt/not-mapped.so", Some("33".repeat(32)));
        assert!(scan_view(&elsewhere, &modules, &pinned, &PinnedObjects::empty()).is_none());
    }

    #[test]
    fn scan_view_does_not_choose_the_first_byte_identical_ordinary_file() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.so");
        let intended = dir.path().join("intended.so");
        std::fs::copy("/bin/sh", &first).unwrap();
        std::fs::copy("/bin/sh", &intended).unwrap();
        let as_module = |path: &Path| {
            let file = p11scope_manifest::identity::open_object(path).unwrap();
            let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
            ScannedModule {
                view: ProcessViewId(0),
                mount_namespace: current_mount_namespace(),
                key: ObjectKey {
                    device: p11scope_manifest::maps::Device {
                        major: key.device_major,
                        minor: key.device_minor,
                    },
                    inode: key.inode,
                },
                path: path.display().to_string(),
                exports: vec![],
                tables: vec![],
                interfaces: vec![],
            }
        };
        let modules = vec![as_module(&first), as_module(&intended)];
        let (pinned, skipped) = pin_scanned_objects(
            std::process::id(),
            &modules,
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let intended_sha = pinned
            .pinned()
            .find(|pin| pin.key == modules[1].key)
            .unwrap()
            .sha256
            .to_string();
        let intended_path = intended.display().to_string();
        let manifest = manifest_naming(&intended_path, Some(intended_sha));
        let own = pin_as_manifest_object(&intended_path);

        let view = scan_view(&manifest, &modules, &pinned, &own).expect("mapped object");
        assert!(view.agrees);
        assert_eq!(
            view.modules[0].path, modules[1].path,
            "digest equality selected the first distinct ordinary file"
        );
    }

    #[test]
    fn byte_identical_distinct_entry_objects_conflict_and_attach_the_union() {
        use crate::discovery::scan::ScannedTable;
        use p11scope_manifest::manifest::{
            Acquisition, FunctionRecord, ObjectRecord, ProvenanceObject, SurfaceRecord,
            SurfaceSource, Version, WalkOutcome,
        };

        let dir = tempfile::tempdir().unwrap();
        let module_path = dir.path().join("module.so");
        let scanned_target_path = dir.path().join("scanned-target.so");
        let manifest_target_path = dir.path().join("manifest-target.so");
        for path in [&module_path, &scanned_target_path, &manifest_target_path] {
            std::fs::copy("/bin/sh", path).unwrap();
        }

        let opened = |path: &Path| {
            let file = p11scope_manifest::identity::open_object(path).unwrap();
            let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
            let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
            (mapping, inspected)
        };
        let (module_mapping, module_inspected) = opened(&module_path);
        let (scanned_mapping, scanned_inspected) = opened(&scanned_target_path);
        let (manifest_mapping, manifest_inspected) = opened(&manifest_target_path);
        assert_eq!(
            scanned_inspected.identity.sha256, manifest_inspected.identity.sha256,
            "the witness requires equal bytes"
        );
        assert_ne!(
            scanned_mapping.inode, manifest_mapping.inode,
            "the witness requires distinct opened objects"
        );
        let offset = scanned_inspected.executable_ranges[0].0;
        let key = |mapping: p11scope_manifest::identity::MappingFileKey| ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: mapping.device_major,
                minor: mapping.device_minor,
            },
            inode: mapping.inode,
        };
        let module = ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
            key: key(module_mapping),
            path: module_path.display().to_string(),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![ScannedEntry {
                    name: "C_Initialize",
                    object: key(scanned_mapping),
                    object_path: scanned_target_path.display().to_string(),
                    file_offset: offset,
                }],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
            }],
            interfaces: vec![],
        };
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        });
        let (mut scan_pins, skipped) = pin_scanned_objects(
            std::process::id(),
            std::slice::from_ref(&module),
            &mut budget,
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");

        let object = |id, path: &Path, identity| ObjectRecord {
            id,
            path: path.display().to_string(),
            identity,
        };
        let provenance = |path: &Path,
                          mapping: p11scope_manifest::identity::MappingFileKey,
                          identity| ProvenanceObject {
            path: path.display().to_string(),
            device_major: mapping.device_major,
            device_minor: mapping.device_minor,
            inode: mapping.inode,
            identity,
        };
        let mut manifest = Manifest {
            schema: SCHEMA.into(),
            module_path: module_path.display().to_string(),
            objects: vec![
                object(0, &module_path, module_inspected.identity.clone()),
                object(
                    1,
                    &manifest_target_path,
                    manifest_inspected.identity.clone(),
                ),
            ],
            provenance_objects: vec![
                provenance(&module_path, module_mapping, module_inspected.identity),
                provenance(
                    &manifest_target_path,
                    manifest_mapping,
                    manifest_inspected.identity,
                ),
            ],
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version {
                    major: 2,
                    minor: 40,
                }),
                walk: WalkOutcome::Full,
                functions: pkcs11_module::FUNCTION_LIST_FIELDS
                    .iter()
                    .map(|field| FunctionRecord {
                        name: field.name.into(),
                        resolution: Resolution::Resolved {
                            object: 1,
                            file_offset: offset,
                        },
                    })
                    .collect(),
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        };
        let manifest_pins = pin_manifest_objects(&manifest).unwrap();
        let view = scan_view(
            &manifest,
            std::slice::from_ref(&module),
            &scan_pins,
            &manifest_pins,
        )
        .expect("the module itself exact-matches");
        let scanned_targets = scanned_targets(&view.modules, &scan_pins).unwrap();
        let manifest_targets = manifest_targets(&manifest, &manifest_pins).unwrap();
        let outcome = corroborate(
            false,
            Some(view.agrees),
            scan_pins.exactly_same_targets(&scanned_targets, &manifest_pins, &manifest_targets),
            scanned_targets.is_empty(),
        );
        assert_eq!(
            outcome,
            Corroboration::Conflict,
            "equal digest/offset must not suppress a distinct opened target"
        );

        retarget_to_pins(&mut manifest, &view.modules, &scan_pins, &manifest_pins);
        assert!(scan_pins.absorb(manifest_pins).is_empty());
        let (modules, _, uncertainty) =
            reconcile_scanned_modules(std::slice::from_ref(&module), &mut scan_pins);
        assert!(uncertainty.is_empty(), "{uncertainty:?}");
        let plan = plan::build_from_sources(&modules, &[manifest], &scan_pins);
        assert_eq!(plan.slots.len(), 2, "both exact opened targets must attach");
        assert_eq!(
            plan.slots
                .iter()
                .map(|slot| slot.object)
                .collect::<BTreeSet<_>>()
                .len(),
            2,
            "the union must retain two distinct capture-local identities"
        );
        let mut counters = DiscoveryCounters {
            conflicts: 1,
            ..DiscoveryCounters::default()
        };
        counters
            .corroboration
            .push(([modules[0].object].into_iter().collect(), "conflict"));
        assert_eq!(
            discovery_evidence(&plan, &scan_pins, &counters).conflicts,
            1,
            "the conflict is the bounded evidence that forces PARTIAL"
        );
    }

    /// Retargeting adopts the identity of the object the scan matched — never some
    /// other pin that happens to hash the same (an earlier manifest's copy of the
    /// same bytes, which the target may not map at all).
    #[test]
    fn retargeting_only_adopts_the_matched_scanned_object() {
        let (modules, pinned) = pinned_self();
        let summary = pinned.pinned().next().unwrap();
        let (path, sha) = (summary.path.to_string(), summary.sha256.to_string());
        let mut m = manifest_naming(&path, Some(sha.clone()));
        m.provenance_objects[0].inode = 1;
        m.provenance_objects[0].device_major = 99;

        let own = pin_as_manifest_object(&path);
        retarget_to_pins(&mut m, &[&modules[0]], &pinned, &own);
        assert_eq!(m.provenance_objects[0].inode, summary.key.inode);
        assert_eq!(
            m.provenance_objects[0].device_major,
            summary.key.device.major
        );

        // The same bytes pinned under an identity the scan did not see must not be
        // adopted: a decoy module the matched scan never named.
        let decoy = ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
            key: ObjectKey {
                device: p11scope_manifest::maps::Device { major: 0, minor: 0 },
                inode: 7,
            },
            path: "/opt/decoy.so".into(),
            exports: vec![],
            tables: vec![],
            interfaces: vec![],
        };
        let mut m = manifest_naming(&path, Some(sha));
        m.provenance_objects[0].inode = 1;
        retarget_to_pins(&mut m, &[&decoy], &pinned, &own);
        assert_eq!(
            m.provenance_objects[0].inode, summary.key.inode,
            "no pin of the decoy exists, so the manifest's own exact pin is retained"
        );
    }

    /// A minimal schema-current manifest naming one object with one resolved function.
    fn manifest_naming(path: &str, sha256: Option<String>) -> Manifest {
        use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
        use p11scope_manifest::manifest::*;
        let identity = ObjectIdentity {
            kind: IdentityKind::GnuBuildId,
            value: Some("aa".into()),
            sha256,
            reusable: true,
            note: None,
        };
        Manifest {
            schema: SCHEMA.to_string(),
            module_path: path.to_string(),
            objects: vec![ObjectRecord {
                id: 0,
                path: path.to_string(),
                identity: identity.clone(),
            }],
            provenance_objects: vec![ProvenanceObject {
                path: path.to_string(),
                device_major: 8,
                device_minor: 1,
                inode: 42,
                identity,
            }],
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: None,
                walk: WalkOutcome::Full,
                functions: vec![FunctionRecord {
                    name: "C_Sign".into(),
                    resolution: Resolution::Resolved {
                        object: 0,
                        file_offset: 0x40,
                    },
                }],
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        }
    }

    /// The outcomes of spec §4.12, which decide whether `--manifest` is a safe
    /// fallback or a trapdoor. Each one changes what is attached and what the
    /// capture claims about it.
    #[test]
    fn the_corroboration_outcomes() {
        // 1. Not mapped in scope: the manifest stands on its own.
        assert_eq!(
            corroborate(false, None, false, true),
            Corroboration::Uncorroborated
        );
        // 2. Mapped, same {object, offset} set: corroborated.
        assert_eq!(
            corroborate(false, Some(true), true, false),
            Corroboration::Agreed
        );
        // 3. Mapped, the sets differ: a conflict (the caller attaches the union).
        assert_eq!(
            corroborate(false, Some(true), false, false),
            Corroboration::Conflict
        );
        // 3b. Mapped and identity-matched, but the scan decoded no table at all:
        // the documented use of `--manifest`, not two sources contradicting each
        // other. Reported as uncorroborated, never as a disagreement.
        assert_eq!(
            corroborate(false, Some(true), false, true),
            Corroboration::ScanEmpty
        );
        // Two empty sets are not a scan-empty case: nothing was recorded either.
        assert_eq!(
            corroborate(false, Some(true), true, true),
            Corroboration::Agreed
        );
        // 4. Mapped, but the bytes are not the ones the manifest recorded.
        assert_eq!(
            corroborate(false, Some(false), true, false),
            Corroboration::IdentityMismatch
        );
        // A scan that could not read memory found no tables to disagree with, so it
        // never turns a usable manifest into a conflict or a mismatch.
        for identity in [None, Some(true), Some(false)] {
            assert_eq!(
                corroborate(true, identity, false, true),
                Corroboration::Uncorroborated,
                "{identity:?}"
            );
        }
    }

    /// A pod's processes live in the container cgroups below the pod directory;
    /// capture scope already includes every descendant, so discovery must too.
    #[test]
    fn cgroup_scope_collects_pids_from_every_descendant() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("kubepods.slice").join("container.scope");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(root.path().join("cgroup.procs"), "11\n").unwrap();
        std::fs::write(leaf.join("cgroup.procs"), "22\n33\n\n22\n").unwrap();
        let (pids, lost) = scope_pids(&Scope::Cgroup {
            id: 0,
            path: root.path().to_path_buf(),
        });
        assert_eq!(pids, vec![11, 22, 33], "deduplicated, descendants included");
        assert_eq!(lost, vec![], "every directory was readable");
        assert_eq!(scope_pids(&Scope::Pid(7)).0, vec![7]);

        // A cgroup that is gone by the time the walk reaches it — container
        // cgroups churn constantly, and one is removable only when empty — held
        // no process to lose, on either read. Claiming otherwise would publish a
        // false loss and force PARTIAL on ordinary pod turnover.
        let (pids, lost) = scope_pids(&Scope::Cgroup {
            id: 0,
            path: root.path().join("vanished.scope"),
        });
        assert_eq!(pids, Vec::<u32>::new());
        assert_eq!(lost, vec![], "a cgroup that no longer exists is not a loss");

        // A subtree the observer cannot read is not an empty subtree: the
        // processes in it were never listed, so their providers were never
        // discovered, and nothing else in the document would say so. An *absent*
        // cgroup.procs (the intermediate directory above) is not a loss — it is
        // not a cgroup — which is why the first assertion above sees none.
        //
        // Root reads a mode-000 directory, so the denial is not reproducible
        // there. Both configurations assert — a test that steps aside under the
        // very privilege level the gates run at is a green that proves nothing.
        // Which claim applies is decided by what this process can actually do
        // rather than by its uid: root with CAP_DAC_OVERRIDE dropped is denied
        // like anyone else, and would fail a uid-based branch for the wrong
        // reason.
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&leaf).unwrap().permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&leaf, permissions).unwrap();
        let denied = std::fs::read_dir(&leaf).is_err();
        let (pids, lost) = scope_pids(&Scope::Cgroup {
            id: 0,
            path: root.path().to_path_buf(),
        });
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !denied {
            assert_eq!(
                pids,
                vec![11, 22, 33],
                "the mode change denied this observer nothing, so nothing is missed"
            );
            assert_eq!(lost, vec![], "nothing was denied, so nothing is a loss");
            return;
        }
        assert_eq!(pids, vec![11], "only the readable cgroup's process");
        assert_eq!(
            lost.len(),
            2,
            "the file and the listing both failed: {lost:?}"
        );
        assert!(
            lost.iter().all(|s| s.subject.ends_with("container.scope")),
            "{lost:?}"
        );
        assert!(
            lost.iter().any(|s| s.reason.contains("cgroup.procs"))
                && lost.iter().any(|s| s.reason.contains("never discovered")),
            "{lost:?}"
        );
    }
}
