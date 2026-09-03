//! Initial and incremental provider discovery ownership.

use crate::attach::{
    CapturePolicy, CounterSnapshot, DynamicExportIdentity, DynamicLoaderAttachFailure,
    OwnedPauseGeneration, Scope, Session,
};
use crate::cli::CaptureArgs;
use crate::discovery::attribution;
use crate::discovery::hooks::{HookAbi, HookRegistry};
use crate::discovery::identity::{
    ManifestStaleReason, PinnedObjectId, PinnedObjects, PinnedTimingKey, ReconciledModule,
    StaleManifestObject, bind_scanned_modules, canonicalize_scanned_overlays, open_view_object,
    pin_manifest_objects_deferred_in_views, pin_scanned_view_objects, retained_object_key,
    target_paths_equal, view_object_key,
};
use crate::discovery::loader::{LoaderContextId, LoaderContextSpec, LoaderRegistry};
use crate::discovery::scan::{
    CaptureWorkBudget, ScanOutcome, ScanRequest, ScannedEntry, ScannedInterface, ScannedModule,
    ScannedTable, Skipped, decode_exact_table, exact_table_addresses, exact_table_bytes,
    index_maps_or_refuse, read_maps_or_refuse, scan_process_view, spans_for,
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
    DISCOVERY_NAME_NULL, DISCOVERY_NAME_OTHER, DISCOVERY_NAME_UNREADABLE,
    DISCOVERY_STATUS_LOADER_CONTEXT_INVALID, DISCOVERY_VERSION_NULL, DISCOVERY_VERSION_OTHER,
    DISCOVERY_VERSION_UNREADABLE, DISCOVERY_VERSION_V2_40, DISCOVERY_VERSION_V3_0,
    DISCOVERY_VERSION_V3_1, DISCOVERY_VERSION_V3_2, DiscoveryRecord, valid_discovery_record,
};
use p11scope_manifest::elf::ElfSnapshot;
use p11scope_manifest::manifest::{
    Acquisition, Manifest, Resolution, SCHEMA, SelectionAuthority, SelectionNameClass,
    SelectionRequest, SelectionVersionClass, WalkOutcome,
};
use p11scope_manifest::maps::{Device, MapEntry, MapIndex, MappedPath, ObjectKey, Resolved};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::num::NonZeroU64;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

pub struct Engine {
    plan: plan::AttachPlan,
    pinned: PinnedObjects,
    discovery: render::DiscoveryEvidence,
    capture_facts: CaptureFacts,
    views: Vec<ProcessView>,
    modules: Vec<ReconciledModule>,
    manifests: Vec<Manifest>,
    manifest_ordinals: Vec<u32>,
    counters: DiscoveryCounters,
    identity_mismatches: usize,
    scan_inputs: BTreeMap<ProcessViewId, ScanInput>,
    manifest_inputs: Vec<ManifestInput>,
    base_counters: DiscoveryCounters,
    budget: CaptureWorkBudget,
    next_view_id: u32,
    loader_registry: LoaderRegistry,
    terminal_batch: Option<TerminalBatch>,
    terminal_journal: Option<TerminalJournal>,
    pending_discovery_records: Vec<QueuedDiscoveryRecord>,
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
    retirement_intents: PendingViewRetirements,
    ready_expected_removals: BTreeSet<ProcessViewId>,
    expected_target_exit_pending: Option<ProcessViewId>,
    expected_target_exit: bool,
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
    selection_claims: BTreeMap<SelectionClaimKey, SelectionClaim>,
    selection_tables: BTreeMap<SelectionTableKey, SelectionTableFact>,
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
    scan_unavailable: Option<String>,
    scan_ms: u64,
    vendor_interfaces: usize,
    interface_list: String,
    selection_inventory: BTreeMap<ExactSelectionTable, Vec<InventorySurfaceKey>>,
    selection_surfaces: BTreeSet<InventorySurfaceKey>,
    selections: Vec<LiveSelectionTuple>,
    selection_truncated: bool,
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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct InventorySurfaceKey {
    base: InventorySurfaceBase,
    duplicate: u16,
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
    let skipped = Skipped {
        subject: "live interface selection".into(),
        reason: reason.into(),
    };
    history
        .losses
        .entry((skipped.subject.clone(), skipped.reason.clone()))
        .or_insert(skipped);
}

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
    let index_a = MapIndex::new(&maps_a).ok_or(())?;
    let mapping_a = index_a.containing(table_ptr).cloned();
    let resolved_a = index_a.resolve(table_ptr);
    let maps_b = read_maps()?;
    let index_b = MapIndex::new(&maps_b).ok_or(())?;
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
        let reachable: BTreeSet<_> = manifest
            .selection_evidence
            .queries
            .iter()
            .filter(|query| matches!(query.authority, SelectionAuthority::SelectionCountOnly))
            .filter_map(|query| query.selection_table)
            .collect();
        for table in manifest
            .selection_evidence
            .tables
            .iter()
            .filter(|table| reachable.contains(&table.id))
        {
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
            match plan.add_selection_table(allocated, module, targets.clone()) {
                Ok(()) => admissions.push(ManifestSelectionAdmission {
                    source: (*ordinal, table.id),
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
    fn record_selection(&mut self, mut tuple: LiveSelectionTuple, matches_truncated: bool) -> bool {
        let history = self.visible_history_mut();
        let was_truncated = history.selection_truncated;
        let existing = history.selections.iter_mut().find(|known| {
            known.module == tuple.module
                && known.request == tuple.request
                && known.rv == tuple.rv
                && known.result == tuple.result
                && known.inventory_matches == tuple.inventory_matches
        });
        if let Some(existing) = existing {
            existing.count = existing.count.saturating_add(1);
        } else if history
            .selections
            .iter()
            .filter(|known| known.module == tuple.module)
            .count()
            < MAX_LIVE_SELECTION_TUPLES
        {
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

    fn merge_current(
        &mut self,
        plan: &plan::AttachPlan,
        pinned: &PinnedObjects,
        modules: &[ReconciledModule],
        manifests: &[Manifest],
        manifest_ordinals: &[u32],
        counters: &DiscoveryCounters,
    ) -> Result<()> {
        if manifests.len() != manifest_ordinals.len() {
            bail!("accepted manifest history lost its source ordinals");
        }
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
                history
                    .tables
                    .entry(TableOccurrence::Scan {
                        module: owner,
                        version: table_fact.0,
                        entries: table_fact.1,
                        occurrence: *table_occurrence,
                    })
                    .or_insert(plan::TableSummary {
                        version: table_fact.0,
                        entries: table_fact.1,
                        source: "scan",
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
            history
                .refusals
                .entry(id)
                .or_insert_with(|| refused.clone());
        }
        for fallback in current.manifest_object_fallbacks {
            let key = (fallback.manifest, fallback.object);
            if !history.fallback_tombstones.contains(&key) {
                history.fallbacks.entry(key).or_insert(fallback);
            }
        }
        // Both stay pure high-water marks of what the plan reports. What the
        // capture-end re-derivation adds or removes is held in
        // `recorroborated`, and `discovery` combines the two once — a latch
        // that could drop below `current` would let one module's re-derivation
        // absorb another module's tombstone gap.
        history.conflicts = history.conflicts.max(current.conflicts);
        history.uncorroborated = history.uncorroborated.max(current.uncorroborated);
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
type InventoryScanOutcome = (Vec<InventoryScan>, BTreeSet<u32>, Vec<Skipped>);
type PendingViewRetirements = BTreeMap<ProcessViewId, RetirementCause>;
type DiscoveryCollector<'a> =
    dyn FnMut(&mut dyn EngineSession) -> Result<(Vec<DiscoveryRecord>, u64)> + 'a;
type SlotCompletion = (u32, Option<u64>);
type TargetAttachResult = (Vec<u32>, Vec<SlotCompletion>);
type ReplacementAttachResult = (Vec<SlotCompletion>, bool);

/// Exactly the `Session` surface the discovery/pause path already uses. It
/// exists so the Engine/coordinator lifecycle can be driven without loading a
/// BPF object; `Session` is the only production implementation and every method
/// is a plain delegation to the existing inherent one.
pub(crate) trait EngineSession {
    fn capture_policy(&self) -> CapturePolicy;
    fn discovery_dequeue(&mut self) -> Result<Option<crate::events::DiscoveryItem>>;
    fn counter_snapshot(&self) -> Result<CounterSnapshot>;
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
    ) -> Result<ReplacementAttachResult>;
    fn detach_slots(&mut self, slots: &[plan::Slot]) -> Result<()>;
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
    fn detach_producers(&mut self) -> Result<()>;
}

impl EngineSession for Session {
    fn capture_policy(&self) -> CapturePolicy {
        Session::capture_policy(self)
    }

    fn discovery_dequeue(&mut self) -> Result<Option<crate::events::DiscoveryItem>> {
        Session::discovery_dequeue(self)
    }

    fn counter_snapshot(&self) -> Result<CounterSnapshot> {
        Session::counter_snapshot(self)
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
    ) -> Result<ReplacementAttachResult> {
        Session::replace_targets(self, plan, replace, objects)
    }

    fn detach_slots(&mut self, slots: &[plan::Slot]) -> Result<()> {
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

    fn detach_producers(&mut self) -> Result<()> {
        Session::detach_producers(self)
    }
}

#[derive(Clone)]
pub(crate) struct IncompleteTerminalDrain {
    pub(crate) records: Vec<DiscoveryRecord>,
    pub(crate) malformed: u64,
    pub(crate) unvalidated_records: u64,
    /// The drain stopped at its work quantum, not on a failure: the prefix is
    /// exact and the rest is still queued on the ring for the next drain.
    pub(crate) backlog: bool,
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
            cause: cause.to_string(),
        }
    }

    fn backlog(records: Vec<DiscoveryRecord>, malformed: u64) -> Self {
        Self {
            records,
            malformed,
            unvalidated_records: 0,
            backlog: true,
            cause: DISCOVERY_DRAIN_BACKLOG_REASON.into(),
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
            .field("cause", &self.cause)
            .finish()
    }
}

impl std::fmt::Display for IncompleteTerminalDrain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; {} terminal record{} retained for retry",
            self.cause,
            self.records.len(),
            if self.records.len() == 1 { "" } else { "s" },
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiscoveryBatchOutcome {
    pub(crate) changed: bool,
    pub(crate) required_complete: bool,
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
#[allow(dead_code)] // Task 4 consumes this crate-private reducer contract.
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

    #[allow(dead_code)] // Used by the Task-4-facing reducer below.
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

#[derive(Clone)]
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
/// cannot accidentally consume it.
#[derive(Clone)]
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

fn scope_pids(scope: &Scope) -> (Vec<u32>, Vec<Skipped>) {
    let (path, io_root) = match scope {
        Scope::Pid(pid) => return (vec![*pid], Vec::new()),
        Scope::Cgroup { path, dir, .. } => (
            path.as_path(),
            PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())),
        ),
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
            "{}",
            format_discovery_skip(&skipped.subject, &skipped.reason)
        );
        attribution::note(skipped);
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
    attribution::note_all(&unlisted);
    discovered.base_counters.object_skips.extend(unlisted);
    // The pid the operator named is the capture; a cgroup's processes are many,
    // however few happen to be in it right now.
    let named = matches!(scope, Scope::Pid(_));
    if pids.len() > MAX_SCAN_PIDS {
        // Published, not just noted: a provider mapped only by a process past the
        // cap is undiscovered, unprobed, and has nothing else to show for it.
        let skipped = Skipped {
            subject: scope_label(scope),
            reason: format!(
                "{} processes in scope; discovery scanned the first {MAX_SCAN_PIDS} — a \
                 provider mapped only by one of the rest was never discovered",
                pids.len()
            ),
        };
        attribution::note(&skipped);
        discovered.base_counters.object_skips.push(skipped);
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
                if let Some(skipped) = unreadable_member_skip(
                    *pid,
                    process::generation_gone(*pid),
                    &format!("the process generation could not be pinned: {error}"),
                ) {
                    attribution::note(&skipped);
                    discovered.base_counters.object_skips.push(skipped);
                }
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
                discovered.base_counters.scan_unavailable = discovered
                    .base_counters
                    .scan_unavailable
                    .or(counters.scan_unavailable);
                discovered.base_counters.scan_ms += counters.scan_ms;
                discovered
                    .base_counters
                    .object_skips
                    .extend(counters.object_skips);
                if let Some(skipped) = unreadable_member_skip(
                    *pid,
                    view.original_exited() == Ok(true),
                    &format!("the process could not be scanned: {error:#}"),
                ) {
                    attribution::note(&skipped);
                    discovered.base_counters.object_skips.push(skipped);
                }
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
            "{}",
            format_module_refusal(&refused.subject, &refused.reason)
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
const DISCOVERY_DRAIN_BACKLOG_REASON: &str =
    "the live discovery drain stopped at its work quantum with records still queued";
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

fn format_discovery_skip(subject: &str, reason: &str) -> String {
    format!(
        "p11scope: discovery skipped {} — {}",
        render::escape_controls(subject),
        render::escape_controls(reason)
    )
}

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
/// and loud, whenever the end cannot be proven.
fn unreadable_member_skip(pid: u32, gone: bool, detail: &str) -> Option<Skipped> {
    if gone {
        return None;
    }
    eprintln!("{}", format_unreadable_member(pid, detail));
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

    let (modules, differed) = bind_scanned_modules(&scan_modules, &mut pinned);
    attribution::note_all(&differed);
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
    let mut plan = build_current_plan(
        &modules,
        &accepted,
        &pinned,
        &mut counters,
        &corroborated,
        identity_mismatches,
        manifest_fallbacks,
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
    let discovery = discovery_evidence(&plan, &pinned, &counters);
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
    let before = discovered.views.len();
    discovered.views.retain(|view| !stale.contains(&view.id()));
    let removed = before - discovered.views.len();
    if removed == 0 {
        bail!("lifecycle check did not identify an accepted process view");
    }
    for view in stale {
        discovered.scan_inputs.remove(&view);
        let skipped = Skipped {
            subject: "process view".into(),
            reason: STALE_VIEW_REASON.into(),
        };
        attribution::note(&skipped);
        discovered.base_counters.object_skips.push(skipped);
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
    maps: &MapIndex<'_>,
    hooks: &HookRegistry,
    record: &DiscoveryRecord,
    budget: &mut CaptureWorkBudget,
) -> Result<Option<ScannedModule>, String> {
    if record.kind == DISCOVERY_KIND_INTERFACE_RETURN {
        return Err("selection record reached export lowering".into());
    }
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
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN | DISCOVERY_KIND_INTERFACE_RETURN => {
            vec![ScannedInterface {
                index: usize::from(record.interface_index),
                name_class: name_class(record.name_class),
                name_lossy: None,
                name_private: None,
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
            file_offset: Some(table_file_offset),
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

const ELF_HEADER_BYTES: usize = 64;
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
) -> std::result::Result<Option<PathBuf>, String> {
    let mut header = [0u8; ELF_HEADER_BYTES];
    read_exact_at(file, &mut header, 0)?;
    if &header[..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(little_u16(&header[16..18]), 2 | 3)
        || little_u16(&header[18..20]) != 62
        || little_u32(&header[20..24]) != 1
        || little_u16(&header[52..54]) as usize != ELF_HEADER_BYTES
        || little_u16(&header[54..56]) as usize != ELF_PROGRAM_HEADER_BYTES
    {
        return Err("retained executable is not a supported x86-64 ELF".into());
    }
    let table_offset = little_u64(&header[32..40]);
    let count = little_u16(&header[56..58]);
    if count == 0 || count == 0xffff {
        return Err("retained executable has no bounded ordinary program-header table".into());
    }
    let table_len = usize::from(count)
        .checked_mul(ELF_PROGRAM_HEADER_BYTES)
        .filter(|length| *length <= MAX_PROGRAM_HEADER_TABLE_BYTES)
        .ok_or_else(|| "retained executable program-header table is too large".to_string())?;
    table_offset
        .checked_add(table_len as u64)
        .filter(|end| *end <= size)
        .ok_or_else(|| "retained executable program-header table is out of bounds".to_string())?;
    let mut table = vec![0u8; table_len];
    read_exact_at(file, &mut table, table_offset)?;

    let mut interpreter = None;
    for program in table.chunks_exact(ELF_PROGRAM_HEADER_BYTES) {
        if little_u32(&program[..4]) != 3 {
            continue;
        }
        if interpreter.is_some() {
            return Err("retained executable has more than one PT_INTERP".into());
        }
        let offset = little_u64(&program[8..16]);
        let length: usize = little_u64(&program[32..40])
            .try_into()
            .map_err(|_| "PT_INTERP length does not fit usize".to_string())?;
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
    Ok(interpreter)
}

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
        return Err("retained executable has no usable executable mapping".into());
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
        return Err("PT_INTERP has no usable executable loader mapping".into());
    };
    if by_path.next().is_some() {
        return Err("PT_INTERP mapping identity has more than one usable path".into());
    }
    Ok(loader)
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

fn commit_cleaned_candidate_identity(
    candidate: &mut LiveCandidate,
    pinned: PinnedObjects,
    modules: Vec<ReconciledModule>,
    stale_views: &BTreeSet<ProcessViewId>,
) {
    candidate.pinned = pinned;
    candidate.modules = modules;
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
            capture_facts: CaptureFacts::default(),
            views: Vec::new(),
            modules: Vec::new(),
            manifests: Vec::new(),
            manifest_ordinals: Vec::new(),
            counters: DiscoveryCounters::default(),
            identity_mismatches: 0,
            scan_inputs: BTreeMap::new(),
            manifest_inputs: Vec::new(),
            base_counters: DiscoveryCounters::default(),
            budget: CaptureWorkBudget::default(),
            next_view_id: 0,
            loader_registry: LoaderRegistry::default(),
            terminal_batch: None,
            terminal_journal: None,
            pending_discovery_records: Vec::new(),
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
            retirement_intents: PendingViewRetirements::new(),
            ready_expected_removals: BTreeSet::new(),
            expected_target_exit_pending: None,
            expected_target_exit: false,
            next_selection_binding_id: Some(1),
            selection_bindings: BTreeMap::new(),
            selection_claims: BTreeMap::new(),
            selection_tables: BTreeMap::new(),
            loader_contexts: BTreeMap::new(),
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
        for class in self.loader_contexts.values() {
            let timing = if class.initial_set {
                // Exactly one initial-set context per owned run, and the empty
                // catalog can never make it eligible (D3 amendment §3).
                aggregate.initial_set_capture.none =
                    aggregate.initial_set_capture.none.saturating_add(1);
                &mut aggregate.initial_set_timing
            } else {
                &mut aggregate.dlopen_timing
            };
            if class.bound {
                timing.unproven = timing.unproven.saturating_add(1);
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

    /// True once a named target's expected exit has been fully finalized:
    /// its view, links, and pending work are all released. Never true for a
    /// cgroup capture, which continues when one member exits.
    pub fn expected_target_exit(&self) -> bool {
        self.expected_target_exit
    }

    /// The one immutable public view of capture-lifetime facts (plan Task 8
    /// Step 2). Every field is boundary-safe: no pins, views, files, timing
    /// keys, or loader/pause identity crosses it. Most fields are the
    /// projected discovery evidence and finite aggregates, but `table_entries`
    /// and `slots` are the exception — they are counts read live off the
    /// engine's own `plan`, not sourced from `self.discovery`.
    pub fn capture_facts(&self) -> render::CaptureFacts {
        render::CaptureFacts {
            discovery: self.discovery.clone(),
            table_entries: self.plan.entries_seen,
            slots: self.plan.slots.len(),
            attach_gap_ms: self.timings.max_gap_ms(),
            loader_discovery: self.loader_discovery(),
            discovery_ring_loss: self.counter_snapshot.ring_loss,
            discovery_state_failures: self.counter_snapshot.export_state_failures,
            discovery_read_failures: self.counter_snapshot.export_bounded_read_failures,
            // One accumulator, each source feeding it once (design §9.1).
            discovery_truncated: self
                .discovery_truncated
                .saturating_add(self.malformed_discovery)
                .saturating_add(self.loader_registry.discovery_truncated())
                .saturating_add(self.loader_registry.context_failures()),
        }
    }

    pub(crate) fn account_unvalidated_discovery(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        self.discovery_truncated = self.discovery_truncated.saturating_add(count);
        self.invalidate_silent_selection_coverage();
        self.invalidate_causal_timing();
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
    }

    #[allow(dead_code)] // Task 4 consumes this crate-private reducer accessor.
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
        if let Some(binding) = self.selection_bindings.get_mut(&id) {
            if binding.attached && !binding.retired {
                binding.coverage.open();
            }
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
            None => self.refresh_requested.contains(&pid),
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
        let before_maps = Self::read_maps(view, budget)?;
        let executable_path = PathBuf::from(format!("/proc/{pid}/exe"));
        let before_executable =
            view_object_key(view, &executable_path).map_err(anyhow::Error::msg)?;
        let executable = view
            .run_while_same(|| std::fs::File::open(&executable_path))
            .map_err(anyhow::Error::msg)??;
        let before_file = FileSnapshot::read(&executable).map_err(anyhow::Error::msg)?;
        let interpreter =
            read_bounded_interpreter(&executable, before_file.size).map_err(anyhow::Error::msg)?;
        let after_file = FileSnapshot::read(&executable).map_err(anyhow::Error::msg)?;
        if before_file != after_file {
            bail!("retained executable changed during bounded PT_INTERP discovery");
        }
        let retained_executable =
            retained_object_key(view, &executable).map_err(anyhow::Error::msg)?;

        let interpreter_file = if let Some(interpreter) = &interpreter {
            let path = PathBuf::from(format!("/proc/{pid}/root")).join(
                interpreter
                    .strip_prefix("/")
                    .expect("bounded PT_INTERP paths are absolute"),
            );
            let (file, key) = open_view_object(view, &path).map_err(anyhow::Error::msg)?;
            let snapshot = FileSnapshot::read(&file).map_err(anyhow::Error::msg)?;
            Some((snapshot, key))
        } else {
            None
        };

        let after_maps = Self::read_maps(view, budget)?;
        let after_executable =
            view_object_key(view, &executable_path).map_err(anyhow::Error::msg)?;
        if before_executable != retained_executable || retained_executable != after_executable {
            bail!("retained executable identity changed during PT_INTERP discovery");
        }
        let before_index =
            index_maps_or_refuse(&before_maps, budget).map_err(anyhow::Error::msg)?;
        let after_index = index_maps_or_refuse(&after_maps, budget).map_err(anyhow::Error::msg)?;
        let before_executable_maps =
            executable_map_snapshot(&before_index, retained_executable, budget)
                .map_err(anyhow::Error::msg)?;
        let after_executable_maps =
            executable_map_snapshot(&after_index, retained_executable, budget)
                .map_err(anyhow::Error::msg)?;
        if before_executable_maps != after_executable_maps {
            bail!("retained executable mappings changed during PT_INTERP discovery");
        }
        let Some(interpreter) = interpreter else {
            return Ok(None);
        };
        let (interpreter_file, loader_key) =
            interpreter_file.expect("a PT_INTERP snapshot has its retained file identity");
        let (before_loader_path, before_loader_maps) =
            loader_map_snapshot(&before_index, loader_key, budget).map_err(anyhow::Error::msg)?;
        let (loader_path, loader_maps) =
            loader_map_snapshot(&after_index, loader_key, budget).map_err(anyhow::Error::msg)?;
        if before_loader_path != loader_path || before_loader_maps != loader_maps {
            bail!("retained loader mappings changed during PT_INTERP discovery");
        }
        Ok(Some(LoaderLocator {
            authority: LoaderAuthority {
                executable_file: before_file,
                executable_key: retained_executable,
                executable_maps: after_executable_maps,
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

    fn publish_current_capture_facts(&mut self) -> Result<()> {
        self.capture_facts.merge_current(
            &self.plan,
            &self.pinned,
            &self.modules,
            &self.manifests,
            &self.manifest_ordinals,
            &self.counters,
        )?;
        if self.capture_facts.staged.is_some() {
            return Ok(());
        }
        self.project_capture_facts();
        Ok(())
    }

    fn project_capture_facts(&mut self) {
        self.capture_facts.apply_to_plan(&mut self.plan);
        self.discovery = self.capture_facts.discovery(&self.plan);
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
                Ok(value)
            }
            Err(error) => {
                self.capture_facts.rollback_stage();
                self.restore_start_publication(snapshot);
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
        attribution::note_all(&binding_skips);
        for skip in binding_skips {
            if !self.counters.object_skips.contains(&skip) {
                self.counters.object_skips.push(skip);
            }
        }
        let mut rebuilt = self
            .plan
            .rebuild_from_sources(&modules, &self.manifests, &pinned);
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
            if self.capture_facts.staged.is_none() {
                self.project_capture_facts();
            }
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
        let had_exact_loader = candidate_pins
            .id_for_scanned(loader_module, loader_module.key, &loader_module.path)
            .is_some_and(|candidate_loader| {
                loader_pins.exactly_matches(local_loader, &candidate_pins, candidate_loader)
            });
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
        self.finalize_candidate(
            session,
            candidate,
            extra_views,
            target_modules,
            additions_allowed,
            &mut outcome,
        );
        Ok(outcome)
    }

    /// Everything a candidate can fail at, proven before its first link
    /// mutation. Post-mutation cleanup only ever drops sources, so a candidate
    /// that passes here still publishes after a conservative retirement.
    fn preflight_candidate_publication(&self, candidate: &LiveCandidate) -> Result<()> {
        if !candidate_identity_is_complete(&candidate.plan, &candidate.modules, &candidate.pinned) {
            bail!("live candidate lost exact pinned identity before link mutation");
        }
        // ponytail: proves the publication on a throwaway copy of the fact
        // store, so the fallible surface is exact by construction rather than
        // a second list that can drift. Swap for a dedicated preflight walk if
        // the doubled history merge ever shows up in capture cost.
        self.capture_facts.clone().merge_current(
            &candidate.plan,
            &candidate.pinned,
            &candidate.modules,
            &self.manifests,
            &self.manifest_ordinals,
            &self.counters,
        )
    }

    /// The one complete finalization for a candidate whose links were already
    /// mutated. It never short-circuits and never returns: a lost generation
    /// downgrades the disposition and cleans up, it does not unwind.
    fn finalize_candidate(
        &mut self,
        session: &mut dyn EngineSession,
        mut candidate: LiveCandidate,
        extra_views: &[&ProcessView],
        target_modules: BTreeSet<PinnedTimingKey>,
        additions_allowed: &mut bool,
        outcome: &mut ApplyOutcome,
    ) {
        let selection_pending = candidate.selection_admission.take();
        outcome.stale_views = stale_process_views(&self.views, extra_views, &candidate.views);
        let retired = !outcome.stale_views.is_empty();
        if retired {
            *additions_allowed = false;
            outcome.static_failures.extend(target_modules);
            self.retire_stale_candidate_sources(session, &mut candidate, &outcome.stale_views);
            self.mark_partial(
                "live discovery generation",
                "a process generation changed after link mutation; its targets were retired before context cleanup",
            );
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
                if session.detach_slots(&detach).is_err() {
                    self.mark_partial(
                        "live interface selection",
                        "a refused selection table could not detach one-shot additions",
                    );
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
                    *slot = inventory.clone();
                } else {
                    slot.names.clear();
                    slot.aliased = false;
                    slot.semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
                    slot.semantic_authorized = false;
                    slot.semantic_ambiguous = false;
                    slot.fork_safe = false;
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
            if session.detach_slots(&rollback).is_err() {
                self.mark_partial(
                    "offline interface selection",
                    "a failed manifest selection table could not detach its successful prefix",
                );
            }
            for slot in rollback {
                candidate.plan.deactivate(slot.index);
            }
            self.mark_partial(
                "offline interface selection",
                "a manifest selection table failed indivisible attachment and was rolled back",
            );
        }
        record_object_skips(&mut candidate.plan, &self.counters.object_skips);
        outcome.changed |= candidate.plan != self.plan;
        self.pinned = candidate.pinned;
        self.modules = candidate.modules;
        self.plan = candidate.plan;
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
        outcome.selection_authorized &= outcome.disposition == ApplyDisposition::Accepted;
    }

    /// Drops the pins, modules, proofs, and live endpoints a lost process
    /// generation owned. Infallible on purpose: it runs after link mutation.
    fn retire_stale_candidate_sources(
        &mut self,
        session: &mut dyn EngineSession,
        candidate: &mut LiveCandidate,
        stale_views: &BTreeSet<ProcessViewId>,
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
        let inventory_plan =
            self.plan
                .rebuild_from_sources(&cleaned_modules, &self.manifests, &cleaned_pins);
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
        if !orphaned_selection.is_empty() && session.detach_slots(&orphaned_selection).is_err() {
            self.mark_partial(
                "live discovery detach",
                "stale selection claims lost their final owner but one link detach failed",
            );
        }
        for slot in orphaned_selection {
            candidate.plan.deactivate(slot.index);
        }
        let retired = candidate
            .plan
            .retire_unpinned_targets(&cleaned_pins, self.plan.slots.len());
        if session.detach_slots(&retired).is_err() {
            self.mark_partial(
                "live discovery detach",
                "generation loss cleanup had a one-shot detach failure",
            );
        }
        commit_cleaned_candidate_identity(candidate, cleaned_pins, cleaned_modules, stale_views);
    }

    fn latch_candidate_ambiguity(&mut self, candidate: &plan::AttachPlan) -> bool {
        if !self.plan.latch_ambiguity_from(candidate) {
            return false;
        }
        self.discovery.module_ambiguous = self.plan.module_ambiguous as u64;
        true
    }

    fn update_counter_snapshot(&mut self, session: &dyn EngineSession) -> Result<()> {
        let next = session.counter_snapshot()?;
        if !self.counter_snapshot.replace_with(next) {
            self.invalidate_silent_selection_coverage();
            self.invalidate_causal_timing();
            self.mark_partial(
                "live discovery counters",
                "a producer counter decreased; the prior absolute snapshot was retained",
            );
            return Ok(());
        }
        if self.counter_snapshot.ring_loss > 0 {
            self.invalidate_silent_selection_coverage();
            self.invalidate_causal_timing();
            self.mark_partial(
                "live discovery transport",
                "the kernel could not reserve one or more private discovery records",
            );
        }
        if self.counter_snapshot.export_state_failures > 0
            || self.counter_snapshot.export_bounded_read_failures > 0
        {
            self.invalidate_silent_selection_coverage();
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
            let maps = Self::read_maps(view, &mut self.budget)?;
            let index =
                index_maps_or_refuse(&maps, &mut self.budget).map_err(|error| anyhow!(error))?;
            lower_export_record(view, &index, &self.hooks, record, &mut self.budget)
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
        let collected = self.collect_dynamic_export_work(
            context_id,
            &export_modules,
            &candidate.pinned,
            session,
            terminal_owner.is_some(),
            &terminal_exports,
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
            let (retire, dynamic_complete) = self.attach_export_work(
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
        transaction: Option<(
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
        let authorized = if let Some(owner) = queued.terminal_owner {
            binding.attached
                && hook_matches
                && owner == binding.context
                && queued.terminal_exports.contains(&identity)
        } else {
            binding.attached
                && !binding.retired
                && hook_matches
                && !self.loader_registry.is_tombstoned(binding.context)
                && self
                    .loader_registry
                    .context(binding.context)
                    .is_some_and(|context| context.spec.view == binding.view)
                && self.views.iter().any(|view| {
                    view.id() == binding.view && view.pid() == pid && view.still_the_same()
                })
        };
        if !authorized {
            self.mark_live_loss(
                "live interface selection",
                "a selection record failed binding, context, or process-generation attribution",
            );
            self.invalidate_selection_coverage(binding.id);
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::SelectionUnattributed,
            ));
        }

        let Some(request_name) = selection_name_class(record.case_id) else {
            self.mark_live_loss(
                "live interface selection",
                "a selection record carried an unknown request-name class",
            );
            self.invalidate_selection_coverage(binding.id);
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::SelectionUnattributed,
            ));
        };
        let Some(request_version) = selection_version_class(record.interface_index) else {
            self.mark_live_loss(
                "live interface selection",
                "a selection record carried an unknown request-version class",
            );
            self.invalidate_selection_coverage(binding.id);
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::SelectionUnattributed,
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
                self.mark_live_loss(
                    "live interface selection",
                    "a selection binding had no stable provider module",
                );
                self.invalidate_selection_coverage(binding.id);
                return Ok(DiscoveryRecordOutcome::Rejected(
                    RecordRejection::SelectionUnattributed,
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
                self.mark_live_loss(
                    "live interface selection",
                    "a selection record carried an unknown result-name class",
                );
                self.invalidate_selection_coverage(binding.id);
                return Ok(DiscoveryRecordOutcome::Rejected(
                    RecordRejection::SelectionUnattributed,
                ));
            };
            let Some(result_version) = selection_version_class(record.selection_version_class)
            else {
                self.mark_live_loss(
                    "live interface selection",
                    "a selection record carried an unknown result-version class",
                );
                self.invalidate_selection_coverage(binding.id);
                return Ok(DiscoveryRecordOutcome::Rejected(
                    RecordRejection::SelectionUnattributed,
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
                    let (mapping, table) =
                        Self::read_selection_table(view, record.table_ptr, &mut self.budget)?;
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

        let selection_became_truncated = self.capture_facts.record_selection(
            LiveSelectionTuple {
                module,
                request,
                rv: record.return_rv,
                result,
                inventory_matches: inventory_matches.clone(),
                count: 1,
            },
            matches_truncated,
        );
        if selection_became_truncated {
            self.invalidate_silent_selection_coverage();
        }
        let unmatched = result.is_some() && inventory_matches.is_empty() && !assessment_loss;
        let mut claim_authorized = false;
        if unmatched
            && can_attach
            && queued.terminal_owner.is_none()
            && !selection_became_truncated
            && !read_loss
            && !matches_truncated
            && self.counter_snapshot.ring_loss == 0
            && self.counter_snapshot.export_state_failures == 0
            && self.counter_snapshot.export_bounded_read_failures == 0
            && !self.capture_facts.visible_history().selection_truncated
            && authority_shape
            && result.as_ref().is_some_and(|result| {
                decoded_table.as_ref().is_some_and(|table| {
                    table.walk == "full" && inventory_version_class(table.version) == result.version
                })
            })
        {
            if let (Some(table), Some(result), Some(provider)) = (
                decoded_table.as_ref(),
                result.as_ref(),
                self.pinned.owned_timing_key(binding.object),
            ) {
                if let Some((claims, tables, pending)) =
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
                        let outcome = self.apply_candidate(
                            session,
                            candidate,
                            additions_allowed,
                            false,
                            &[],
                        )?;
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
            }
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
        budget: &mut CaptureWorkBudget,
    ) -> std::result::Result<(MapEntry, ScannedTable), ()> {
        let maps_a = Self::read_maps(view, budget).map_err(|_| ())?;
        let index_a = index_maps_or_refuse(&maps_a, budget).map_err(|_| ())?;
        let mapping_a = index_a.containing(address).cloned().ok_or(())?;
        if mapping_a.permissions[0] != b'r' {
            return Err(());
        }
        let mem = view
            .run_while_same(|| File::open(format!("/proc/{}/mem", view.pid())))
            .map_err(|_| ())?
            .map_err(|_| ())?;
        let mut bytes = vec![0; std::mem::size_of::<u64>()];
        let mut operation_bytes = 0u64;
        let mut read_exact = |bytes: &mut [u8], base: u64| -> Result<(), ()> {
            let mut done = 0usize;
            while done < bytes.len() {
                if budget.check_deadline_now().is_some() {
                    return Err(());
                }
                let allowed = budget.allowed_io(operation_bytes, bytes.len() - done);
                if allowed == 0 {
                    return Err(());
                }
                let at = base.checked_add(done as u64).ok_or(())?;
                let read = mem
                    .read_at(&mut bytes[done..done + allowed], at)
                    .map_err(|_| ())?;
                if read == 0 {
                    return Err(());
                }
                budget.record_io(read);
                operation_bytes = operation_bytes.saturating_add(read as u64);
                done += read;
            }
            Ok(())
        };
        read_exact(&mut bytes, address)?;
        let table_bytes = exact_table_bytes(&bytes).ok_or(())?;
        let table_end = address.checked_add(table_bytes as u64).ok_or(())?;
        if table_end > mapping_a.end {
            return Err(());
        }
        bytes.resize(table_bytes, 0);
        if table_bytes > std::mem::size_of::<u64>() {
            read_exact(
                &mut bytes[std::mem::size_of::<u64>()..],
                address
                    .checked_add(std::mem::size_of::<u64>() as u64)
                    .ok_or(())?,
            )?;
        }
        let raw_addresses = exact_table_addresses(&bytes).ok_or(())?;
        let mut addresses = Vec::with_capacity(raw_addresses.len() + 1);
        addresses.push(address);
        addresses.extend(raw_addresses);
        let mappings_a: Vec<_> = addresses
            .iter()
            .map(|address| index_a.containing(*address).cloned().ok_or(()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let table = decode_exact_table(&bytes, address, &index_a, budget)
            .map_err(|_| ())?
            .ok_or(())?;
        let maps_b = Self::read_maps(view, budget).map_err(|_| ())?;
        let index_b = index_maps_or_refuse(&maps_b, budget).map_err(|_| ())?;
        if !mappings_a
            .iter()
            .zip(&addresses)
            .all(|(mapping, address)| index_b.containing(*address) == Some(mapping))
            || !view.still_the_same()
        {
            return Err(());
        }
        Ok((mapping_a, table))
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
            let snapshot = pinned
                .file_for(object)
                .and_then(|file| ElfSnapshot::read(file).ok());
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
                let cookie = selection_binding
                    .map(|binding| binding.id)
                    .unwrap_or(u64::from(hook_id));
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

    fn attach_export_work(
        &mut self,
        view: ProcessViewId,
        work: &[DynamicExportWork],
        session: &mut dyn EngineSession,
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
                    if let Some(mut binding) = work.selection_binding {
                        binding.attached = true;
                        self.selection_bindings.insert(binding.id, binding);
                    }
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
        (retire, complete)
    }

    fn attach_refreshed_exports(
        &mut self,
        view: ProcessViewId,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
    ) -> (bool, bool) {
        let modules: Vec<_> = self
            .modules
            .iter()
            .filter(|module| module.scanned.view == view && !module.scanned.exports.is_empty())
            .map(|module| module.scanned.clone())
            .collect();
        if modules.is_empty() {
            return (false, true);
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
            return (false, false);
        };
        let pinned = self.pinned.clone();
        let collected =
            self.collect_dynamic_export_work(*context, &modules, &pinned, session, false, &[]);
        let (retire, complete) =
            self.attach_export_work(view, &collected.dynamic, session, additions_allowed);
        (retire, complete && collected.required_seed_complete)
    }

    fn attach_initial_exports(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        closure: &mut PauseClosure,
    ) {
        let views: Vec<_> = self.views.iter().map(ProcessView::id).collect();
        for view in views {
            let (retire, complete) =
                self.attach_refreshed_exports(view, session, additions_allowed);
            if retire {
                self.queue_stale_views(&[view].into_iter().collect(), pending_views);
            }
            if !complete {
                closure.fail();
            }
        }
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
        let Some(locator) = Self::loader_locator(&self.views[position], &mut self.budget)? else {
            return Ok(false);
        };
        let loader_path = locator.authority.loader_path.clone();
        let loader_module = mapped_object(
            &self.views[position],
            &locator.authority.loader_maps[0],
            &loader_path,
        );
        let (loader_pins, loader_skips) = pin_scanned_view_objects(
            &self.views[position],
            std::slice::from_ref(&loader_module),
            &mut self.budget,
        )
        .map_err(anyhow::Error::msg)?;
        let skipped = loader_skips;
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
        let pinned_loader_file = FileSnapshot::read(
            loader_pins
                .file_for(local_loader_id)
                .expect("the just-pinned loader has its retained file"),
        )
        .map_err(anyhow::Error::msg)?;
        if pinned_loader_file != locator.authority.interpreter_file {
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
        if !outcome.accepted() || !*additions_allowed {
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
                    && Self::loader_locator(&self.views[position], &mut self.budget).is_ok_and(
                        |current| {
                            current.is_some_and(|current| {
                                current.authority == locator.authority
                                    && current.maps.contains(&loader_mapping)
                            })
                        },
                    )
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
            self.mark_generation_change(
                view_id,
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
        let loader_identity = retained_object_key(
            &self.views[position],
            prepared_executable.interpreter_file(),
        )
        .map_err(anyhow::Error::msg)?;
        let loader_module = ScannedModule {
            view: view_id,
            mount_namespace: self.views[position].mount_namespace(),
            key: loader_identity,
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
        session: &mut dyn EngineSession,
        pending_views: &mut PendingViewRetirements,
        initiating_error: String,
    ) -> Result<OwnedLoaderPrearmOutcome> {
        let mut errors = vec![initiating_error];
        let (terminal_exports, detach_failed) = session.detach_dynamic_context(context);
        if detach_failed {
            errors.push("dynamic loader detach failed".into());
        }
        let mut complete = true;
        let mut unvalidated_records = 0;
        let drained = begin_owned_prearm_retirement_with(
            &mut self.loader_registry,
            context,
            registry_attached,
            &mut errors,
            || match Self::collect_discovery_records(session) {
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

    fn arm_loader_or_partial(
        &mut self,
        position: usize,
        session: &mut dyn EngineSession,
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
        self.record_loader_arm(view_id, false);
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
                self.mark_generation_change(
                    view_id,
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
            Err(error) => match error.downcast::<IncompleteTerminalDrain>() {
                Ok(incomplete) => {
                    self.account_unvalidated_discovery(incomplete.unvalidated_records);
                    self.retain_terminal_batch(
                        incomplete.records.clone(),
                        false,
                        incomplete.malformed,
                    )?;
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

    fn retire_loader_contexts(
        &mut self,
        view: ProcessViewId,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
    ) -> Result<(bool, bool)> {
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
                let (terminal_exports, detach_failed) = session.detach_dynamic_context(context_id);
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
                match self.begin_terminal_drain(context_id, terminal_exports, || collect(session)) {
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
        let previous = self.retirement_intents.get(&view).copied();
        let cause = if cause == RetirementCause::GenerationLost && self.original_exited(view) {
            RetirementCause::ExpectedRemoval
        } else {
            cause
        };
        let cause = previous.map_or(cause, |current| current.merge(cause));
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
                    self.refresh_requested.remove(&pid);
                }
                RetirementCause::ExecRefresh | RetirementCause::GenerationLost => {
                    self.refresh_requested.insert(pid);
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

    fn replay_pending_conservative(
        &mut self,
        session: &mut dyn EngineSession,
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

    fn dispatch_lifecycle_record(
        &mut self,
        record: &DiscoveryRecord,
        pending_views: &mut PendingViewRetirements,
    ) -> Option<ProcessViewId> {
        let pid = (record.pid_tgid >> 32) as u32;
        if let Some((view, cause)) =
            lifecycle_retirement(&self.views, pid, record.hook_ts_ns, record.kind)
        {
            self.queue_retirement(view, cause, pending_views);
            (cause == RetirementCause::ExecRefresh).then_some(view)
        } else if record.kind == DISCOVERY_KIND_EXEC
            && unmatched_exec_requests_refresh(&self.views, pid)
        {
            self.refresh_requested.insert(pid);
            None
        } else {
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
            DISCOVERY_KIND_INTERFACE_RETURN => self.process_selection_record_with_session(
                &queued,
                session,
                additions_allowed,
                pending_views,
            ),
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

    fn process_discovery_records(
        &mut self,
        session: &mut dyn EngineSession,
        records: &mut Vec<QueuedDiscoveryRecord>,
        pending_views: &mut PendingViewRetirements,
        additions_allowed: &mut bool,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
    ) -> Result<bool> {
        let mut changed = false;
        let mut named_generation_lost = false;
        let mut conservative_replay_attempted = false;
        for (view, cause) in self.retirement_intents.clone() {
            pending_views
                .entry(view)
                .and_modify(|current| *current = current.merge(cause))
                .or_insert(cause);
        }
        loop {
            let mut exec_refresh_views = BTreeSet::new();
            let mut deferred_mismatches = Vec::new();
            for queued in std::mem::take(records) {
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
                                "a structurally valid private record failed exact live resolution",
                            );
                        }
                    }
                }
            }
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
                    continue;
                };
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
                // The conservative replay this queues drops every pin the view
                // owns. That is right for a generation that is gone, and wrong
                // for an `ExecRefresh`, which keeps its view and rescans the
                // same live generation: dropping its pins re-pins the same
                // provider under a fresh ID, so a second full slot set is
                // allocated for targets that already have one and the replay's
                // `additions_allowed = false` stops the replacement attaching.
                if cause != RetirementCause::ExecRefresh {
                    self.pending_retirements.insert(view);
                }
                self.retirement_intents.remove(&view);
                self.ready_expected_removals.remove(&view);
                if cause == RetirementCause::ExpectedRemoval {
                    self.views.retain(|candidate| candidate.id() != view);
                    self.scan_inputs.remove(&view);
                    self.arm_expected_target_exit(view);
                }
                conservative_replay_attempted = false;
            }
        }
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
                    let view = &self.views[position];
                    failed_pids.insert(view.pid());
                    skipped.extend(unreadable_member_skip(
                        view.pid(),
                        view.original_exited() == Ok(true),
                        &format!("{failure}: {error:#}"),
                    ));
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

    fn refresh_inventory(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        records: &mut Vec<QueuedDiscoveryRecord>,
        pending_views: &mut PendingViewRetirements,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
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
        let (pids, mut skipped) = scope_pids(&self.scope);
        let membership_complete = skipped.is_empty() && pids.len() <= MAX_SCAN_PIDS;
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
        let membership_authoritative =
            membership_complete && matches!(self.scope, Scope::Cgroup { .. });
        let retirement_causes: BTreeMap<_, _> = self
            .views
            .iter()
            .filter_map(|view| {
                inventory_retirement_cause(
                    view.still_the_same(),
                    membership_authoritative,
                    desired.contains(&view.pid()),
                    self.refresh_requested.contains(&view.pid()),
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
                    skipped.extend(unreadable_member_skip(
                        pid,
                        process::generation_gone(pid),
                        &format!("the process generation could not be retained: {error}"),
                    ));
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
                    skipped.extend(unreadable_member_skip(
                        pid,
                        view.original_exited() == Ok(true),
                        &format!("the process generation could not be scanned: {error:#}"),
                    ));
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
        self.queue_inventory_retirements(&retirement_views, &stale, &departed, pending_views);
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
                for view in refreshed_ok.union(&new_view_ids).copied() {
                    let (retire, complete) =
                        self.attach_refreshed_exports(view, session, additions_allowed);
                    if retire {
                        self.queue_stale_views(&[view].into_iter().collect(), pending_views);
                    }
                    if !complete {
                        closure.fail();
                    }
                }
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
        self.drain_discovery_from(session)
    }

    /// A quantum stop is backlog, not failure: the exact prefix is applied now
    /// and the rest stays on the ring for the next tick, which the run loop's
    /// duration/signal checks precede. Overflow in between is the producer's
    /// `ring_loss`, read with every batch.
    pub(crate) fn drain_discovery_from(&mut self, session: &mut dyn EngineSession) -> Result<bool> {
        let (records, malformed) = match Self::collect_discovery_records(session) {
            Ok(drained) => drained,
            Err(error) => match error.downcast::<IncompleteTerminalDrain>() {
                Ok(incomplete) if incomplete.backlog => (incomplete.records, incomplete.malformed),
                Ok(incomplete) => return Err(Self::generic_drain_error(incomplete.into())),
                Err(error) => return Err(error),
            },
        };
        self.apply_discovery_batch(session, records, malformed)
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

    pub(crate) fn apply_discovery_batch(
        &mut self,
        session: &mut dyn EngineSession,
        records: Vec<DiscoveryRecord>,
        malformed: u64,
    ) -> Result<bool> {
        let mut collect = Self::collect_discovery_records;
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
        let mut records = queued;

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
        self.publish_current_capture_facts()?;
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
        session: &mut dyn EngineSession,
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
        self.publish_current_capture_facts()?;
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
        let snapshot = self.begin_start_capture_attempt()?;
        let retained_scope = self.scope.clone();
        let named = matches!(retained_scope, Scope::Pid(_));
        let scope = &retained_scope;
        let mut session =
            match start_retained_with(self, named, process::stale_view_ids, |plan, pinned| {
                Session::start(plan, scope, pinned, policy, pause_generation.take())
            }) {
                Ok(session) => session,
                Err(error) => {
                    return self.finish_start_capture_attempt(snapshot, Err(error));
                }
            };
        self.record_session_lifecycle_tracking(&session);
        let result = (|| {
            let mut additions_allowed = true;
            let mut records = Vec::new();
            let mut pending_views = PendingViewRetirements::new();
            let mut collect = Self::collect_discovery_records;
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
            if fatal.is_none() {
                self.attach_initial_exports(
                    &mut session,
                    &mut additions_allowed,
                    &mut pending_views,
                    &mut closure,
                );
                if owned_prearmed && let Some(generation) = owned_generation {
                    self.mark_owned_selection_pending(generation);
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
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    #[derive(Default)]
    pub(crate) struct ScriptedSession {
        pub(crate) capture_policy: Option<CapturePolicy>,
        pub(crate) dequeues: VecDeque<Result<Option<crate::events::DiscoveryItem>>>,
        pub(crate) counters: CounterSnapshot,
        /// One entry per upcoming `counter_snapshot` call; `true` fails it.
        counter_script: RefCell<VecDeque<bool>>,
        counter_reads: Cell<u64>,
        pub(crate) detach_exports: Vec<DynamicExportIdentity>,
        pub(crate) detach_failed: bool,
        pub(crate) lifecycle_tracking_unavailable: Option<&'static str>,
        pub(crate) detached: Vec<LoaderContextId>,
        /// Slot counts of every `detach_slots` call, in order.
        pub(crate) detached_slots: Vec<usize>,
        /// One entry per upcoming `detach_slots` call; `true` fails it.
        detach_slot_script: VecDeque<bool>,
        /// Static target slot indices that the next attach reports as failed.
        fail_target_slots: BTreeSet<u32>,
        /// Slot counts of every `attach_targets` call, in order.
        pub(crate) attached_slots: Vec<usize>,
        /// Dynamic exports requested by the Engine, in order.
        pub(crate) dynamic_attach_calls: Vec<DynamicExportIdentity>,
        pub(crate) dynamic_attach_reports_added: bool,
        /// Killed and reaped from inside `attach_targets`, i.e. exactly between
        /// a generation precheck and its postcheck.
        kill_on_attach: Option<u32>,
        /// Killed and reaped after one dynamic link mutation, before its
        /// generation postcheck.
        kill_on_dynamic_attach: Option<u32>,
        /// Refuses every `preflight_targets`, i.e. a pure preflight refusal.
        refuse_preflight: bool,
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

        /// A session whose target preflight refuses every candidate.
        pub(crate) fn refusing_preflight() -> Self {
            Self {
                refuse_preflight: true,
                ..Self::default()
            }
        }

        /// Schedules the outcome of the next one-shot slot detaches; `true`
        /// fails that call. Later calls succeed.
        pub(crate) fn fail_slot_detaches(&mut self, script: impl IntoIterator<Item = bool>) {
            self.detach_slot_script = script.into_iter().collect();
        }

        pub(crate) fn fail_target_slots(&mut self, slots: impl IntoIterator<Item = u32>) {
            self.fail_target_slots = slots.into_iter().collect();
        }

        pub(crate) fn lose_generation_at_dynamic_attach(&mut self, pid: u32) {
            self.kill_on_dynamic_attach = Some(pid);
        }
    }

    impl EngineSession for ScriptedSession {
        fn capture_policy(&self) -> CapturePolicy {
            self.capture_policy.unwrap_or(CapturePolicy::Allowlisted)
        }

        fn discovery_dequeue(&mut self) -> Result<Option<crate::events::DiscoveryItem>> {
            self.dequeues.pop_front().unwrap_or(Ok(None))
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

        fn detach_failures(&self) -> &[String] {
            &[]
        }

        fn lifecycle_tracking_unavailable(&self) -> Option<&str> {
            self.lifecycle_tracking_unavailable
        }

        fn preflight_targets(&self, _: &[plan::Slot], _: &PinnedObjects) -> Result<()> {
            if self.refuse_preflight {
                bail!("scripted target preflight refused the candidate");
            }
            Ok(())
        }

        fn attach_targets(
            &mut self,
            slots: &[plan::Slot],
            _: &PinnedObjects,
        ) -> Result<TargetAttachResult> {
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
            _: &[plan::Slot],
            _: &PinnedObjects,
        ) -> Result<ReplacementAttachResult> {
            Ok((Vec::new(), false))
        }

        fn detach_slots(&mut self, slots: &[plan::Slot]) -> Result<()> {
            self.detached_slots.push(slots.len());
            if self.detach_slot_script.pop_front().unwrap_or(false) {
                bail!("scripted one-shot slot detach failed");
            }
            Ok(())
        }

        fn has_dynamic_export(
            &self,
            _: LoaderContextId,
            target: (PinnedObjectId, u64),
            cookie: u64,
            abi: HookAbi,
        ) -> bool {
            self.dynamic_attach_calls.iter().any(|export| {
                export.object == target.0
                    && export.file_offset == target.1
                    && export.cookie == cookie
                    && export.abi == abi
            })
        }

        fn attach_dynamic_export(
            &mut self,
            _: LoaderContextId,
            pid: u32,
            target: (PinnedObjectId, u64),
            cookie: u64,
            abi: HookAbi,
            _: &PinnedObjects,
        ) -> Result<(bool, Option<u64>)> {
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
            _: LoaderContextId,
            _: u32,
            _: PinnedObjectId,
            _: u64,
            _: u64,
            _: &PinnedObjects,
        ) -> std::result::Result<bool, DynamicLoaderAttachFailure> {
            Ok(false)
        }

        fn detach_dynamic_context(
            &mut self,
            context: LoaderContextId,
        ) -> (Vec<DynamicExportIdentity>, bool) {
            self.detached.push(context);
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

        fn detach_producers(&mut self) -> Result<()> {
            Ok(())
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
                state: None,
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
mod tests {
    use super::session_fixture::ScriptedSession;
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
    use crate::discovery::scan::{
        SCAN_DEADLINE_REASON, ScanLimits, ScannedEntry, ScannedTable, WORK_CEILING_REASON, scan_pid,
    };
    use crate::{semantics, trace};
    use p11scope_manifest::manifest::{
        Acquisition, AliasEntry, AliasGroup, FunctionRecord, InterfaceClassification,
        SurfaceRecord, SurfaceSource, Version, WalkOutcome,
    };
    use p11scope_manifest::maps::{parse_maps, resolve};
    use std::cell::Cell;
    use std::io::Write as _;
    use std::path::PathBuf;

    /// Task 11 fix round 2 (csf_ce5962b root closure): the live per-record
    /// snapshot read charges the capture budget and honors the installed
    /// batch deadline on the real `/proc` path, refusing before a byte is read.
    #[test]
    fn live_maps_snapshot_charges_the_budget_and_honors_the_installed_deadline() {
        use crate::discovery::scan::SCAN_DEADLINE_REASON;

        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let mut budget = CaptureWorkBudget::default();
        assert!(!Engine::read_maps(&view, &mut budget).unwrap().is_empty());
        assert!(
            budget.attempted_io_bytes() > 0,
            "the snapshot read is charged to the capture budget"
        );

        let mut budget = CaptureWorkBudget::default();
        budget.set_deadline(Some(0));
        let error = Engine::read_maps(&view, &mut budget)
            .err()
            .map(|error| error.to_string());
        assert_eq!(error.as_deref(), Some(SCAN_DEADLINE_REASON));
        assert_eq!(
            budget.attempted_io_bytes(),
            0,
            "an expired deadline refuses before a byte is read"
        );
    }

    #[test]
    fn lifecycle_tier_gap_uses_existing_public_discovery_evidence() {
        let mut engine = Engine::empty();
        let mut session = ScriptedSession::default();
        session.lifecycle_tracking_unavailable =
            Some("live lifecycle tracking unavailable: tracefs not found");
        engine.record_session_lifecycle_tracking(&session);
        record_object_skips(&mut engine.plan, &engine.counters.object_skips);
        engine.publish_current_capture_facts().unwrap();

        assert_eq!(engine.plan.skipped.len(), 1);
        assert_eq!(
            render::capture_skipped_out(&engine.plan.skipped[0]),
            render::SkippedOut {
                name: "discovery subject".into(),
                reason: "discovery unavailable".into(),
            }
        );
        assert!(
            !engine.plan.skipped.is_empty(),
            "the final engine plan supplies the existing public PARTIAL projection"
        );
    }

    #[test]
    fn unvalidated_discovery_accounting_changes_only_bounded_loss_evidence() {
        let (mut engine, owner) = Engine::retiring_loader_context(std::process::id());
        let view = ProcessViewId(0);
        let timing = timing_key(0);
        engine.timings.observe(&timing, 1_000_000);
        engine.timings.complete(&timing, 2_000_000);
        engine.discovery_truncated = 1;
        engine.refresh_requested.insert(std::process::id());
        engine.pending_retirements.insert(view);
        engine.ready_expected_removals.insert(view);
        engine.expected_target_exit_pending = Some(view);
        engine.loader_records_accepted = 7;
        engine.counter_snapshot.loader_hits = 11;
        engine.terminal_journal = Some(TerminalJournal {
            owner,
            dispatch_started: true,
            retry_used: false,
        });
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_LOADER;
        engine
            .pending_discovery_records
            .push(QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            });
        let confirmation = PauseClosure::new(true);

        let before_plan = engine.plan.clone();
        let before_discovery = engine.discovery.clone();
        let before_views: Vec<_> = engine.views.iter().map(ProcessView::id).collect();
        let before_refresh = engine.refresh_requested.clone();
        let before_retirements = engine.pending_retirements.clone();
        let before_ready = engine.ready_expected_removals.clone();
        let before_facts = engine.capture_facts();
        let before_journal = engine.terminal_journal_for_test();

        engine.account_unvalidated_discovery(0);
        assert_eq!(engine.timings.gap_ns(&timing), Some(1_000_000));
        engine.account_unvalidated_discovery(u64::MAX);
        engine.account_unvalidated_discovery(1);

        assert_eq!(engine.discovery_truncated, u64::MAX);
        assert_eq!(engine.capture_facts().discovery_truncated, u64::MAX);
        assert_eq!(engine.capture_facts().attach_gap_ms(), None);
        assert_eq!(engine.plan, before_plan);
        assert_eq!(engine.discovery, before_discovery);
        assert_eq!(
            engine.views.iter().map(ProcessView::id).collect::<Vec<_>>(),
            before_views
        );
        assert_eq!(engine.refresh_requested, before_refresh);
        assert_eq!(engine.loader_records_accepted, 7);
        assert_eq!(engine.counter_snapshot.loader_hits, 11);
        assert_eq!(engine.loader_context_state_for_test(owner), Some("live"));
        assert_eq!(engine.pending_retirements, before_retirements);
        assert_eq!(engine.ready_expected_removals, before_ready);
        assert_eq!(engine.expected_target_exit_pending, Some(view));
        assert_eq!(engine.terminal_journal_for_test(), before_journal);
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.pending_discovery_records.len(), 1);
        assert!(confirmation.required_complete());
        assert_eq!(
            engine.capture_facts().table_entries,
            before_facts.table_entries
        );
        assert_eq!(engine.capture_facts().slots, before_facts.slots);
    }

    fn dynamic_export_work(module: PinnedTimingKey, already_attached: bool) -> DynamicExportWork {
        DynamicExportWork {
            context: LoaderContextId::from_case_id(0),
            module: Some(module),
            object: PinnedObjectId(7),
            file_offset: 0x10,
            cookie: 1,
            abi: HookAbi::FunctionList,
            already_attached,
            selection_binding: None,
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
            disposition: ApplyDisposition::Accepted,
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
            RecordRejection::SelectionUnattributed,
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

    /// The generic (non-terminal) drain never retries: `drain_discovery_tick`
    /// aborts the run on `?` (src/run.rs) instead of retaining and replaying
    /// anything. Its error text must not claim retention the terminal routes
    /// actually perform.
    #[test]
    fn generic_drain_failure_states_no_retention_claim() {
        let record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        let retained =
            IncompleteTerminalDrain::new(vec![record], 0, 0, anyhow!("scripted ring read failed"));

        let error = Engine::generic_drain_error(retained.into());

        assert_eq!(error.to_string(), "scripted ring read failed");
        assert!(
            !error.to_string().contains("retained"),
            "the generic drain retains nothing across ticks: {error:#}"
        );
    }

    fn malformed_dequeues(count: usize) -> Vec<Result<Option<crate::events::DiscoveryItem>>> {
        (0..count)
            .map(|_| Ok(Some(crate::events::DiscoveryItem::Malformed)))
            .collect()
    }

    /// One record past the quantum, then a dequeue that must never be reached:
    /// a producer that keeps the live ring nonempty must not keep the shared
    /// collector from returning to its caller's deadline and signal checks.
    #[test]
    fn live_collector_stops_at_its_quantum_with_the_backlog_still_queued() {
        let record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        let mut session = ScriptedSession::default();
        session.dequeues.extend(
            (0..=LIVE_DISCOVERY_DRAIN_QUANTUM)
                .map(|_| Ok(Some(crate::events::DiscoveryItem::Record(record)))),
        );
        session
            .dequeues
            .push_back(Err(anyhow!("dequeued past the quantum")));

        let incomplete = match Engine::collect_discovery_records(&mut session) {
            Ok((records, malformed)) => panic!(
                "a quantum stop is an incomplete drain, never an empty ring: {} records, {malformed} malformed",
                records.len()
            ),
            Err(error) => error
                .downcast::<IncompleteTerminalDrain>()
                .expect("the exact prefix travels with the stop"),
        };

        assert!(incomplete.backlog, "{incomplete:?}");
        assert_eq!(incomplete.records.len(), LIVE_DISCOVERY_DRAIN_QUANTUM);
        assert_eq!(incomplete.malformed, 0);
        assert_eq!(
            session.dequeues.len(),
            2,
            "the record past the quantum and the sentinel stay queued"
        );
    }

    /// The generic tick route applies a quantum's exact prefix and returns;
    /// the backlog waits on the ring for the next tick, behind the run loop's
    /// duration/signal checks, and is never a batch error.
    #[test]
    fn the_live_drain_applies_the_quantum_prefix_and_leaves_the_backlog_queued() {
        let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
        let mut session = ScriptedSession::default();
        session
            .dequeues
            .extend(malformed_dequeues(LIVE_DISCOVERY_DRAIN_QUANTUM + 1));
        session
            .dequeues
            .push_back(Err(anyhow!("dequeued past the quantum")));

        engine
            .drain_discovery_from(&mut session)
            .expect("a backlog is not a drain failure");

        assert_eq!(
            engine.malformed_discovery,
            LIVE_DISCOVERY_DRAIN_QUANTUM as u64
        );
        assert_eq!(session.dequeues.len(), 2);

        session.dequeues.pop_back();
        engine.drain_discovery_from(&mut session).unwrap();

        assert_eq!(
            engine.malformed_discovery,
            LIVE_DISCOVERY_DRAIN_QUANTUM as u64 + 1
        );
        assert!(session.dequeues.is_empty());
    }

    #[test]
    fn a_real_dequeue_failure_still_aborts_the_generic_route() {
        let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
        let mut session = ScriptedSession::default();
        session
            .dequeues
            .push_back(Err(anyhow!("scripted ring read failed")));

        let error = engine.drain_discovery_from(&mut session).unwrap_err();

        assert_eq!(error.to_string(), "scripted ring read failed");
    }

    /// Every dequeue is capture-wide work, charged at the sink the records
    /// enter so the one work ceiling counts ring traffic too. The budget has
    /// no unit accessor and `DEFAULT_WORK_CEILING` is private to scan.rs, so
    /// the charge is observed exactly through the ceiling itself.
    #[test]
    fn dequeued_discovery_work_is_charged_to_the_capture_budget() {
        const WORK_CEILING: u64 = 16 * 1024 * 1024;
        let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
        assert!(engine.budget.charge(WORK_CEILING - 3));
        let mut session = ScriptedSession::default();
        session.dequeues.extend(malformed_dequeues(3));
        engine.drain_discovery_from(&mut session).unwrap();
        assert!(
            !engine.budget.charge(1),
            "three dequeues must have consumed the last three work units"
        );

        let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
        assert!(engine.budget.charge(WORK_CEILING - 4));
        let mut session = ScriptedSession::default();
        session.dequeues.extend(malformed_dequeues(3));
        engine.drain_discovery_from(&mut session).unwrap();
        assert!(engine.budget.charge(1), "exactly one unit per dequeue");
        assert!(!engine.budget.charge(1));
    }

    /// Past the ceiling the records are already off the ring, so they are
    /// still applied — dropping them would be silent loss — and the sticky
    /// stop the refused charge leaves is what the lowering and the next scan
    /// refuse on and publish.
    #[test]
    fn a_drain_past_the_work_ceiling_still_applies_the_dequeued_records() {
        let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
        assert!(engine.budget.charge(16 * 1024 * 1024));
        let mut session = ScriptedSession::default();
        session.dequeues.extend(malformed_dequeues(2));
        engine.drain_discovery_from(&mut session).unwrap();
        session.dequeues.extend(malformed_dequeues(1));
        engine.drain_discovery_from(&mut session).unwrap();

        assert_eq!(
            engine.malformed_discovery, 3,
            "dequeued records are never dropped"
        );
        assert!(!engine.budget.charge(1), "the ceiling stays sticky");
    }

    /// Task 11 fix round 3 (writer A1 follow-ups 1 and 2). A1's drain quantum
    /// returns to the caller at this sink, so the sink is where the live
    /// collector path polls the clock: a batch deadline that expired during the
    /// drain stops the capture at the quantum boundary instead of one whole
    /// batch later. A refused charge is published there exactly once, under
    /// whichever ceiling actually stopped it — the work ceiling and the
    /// deadline are never labelled as each other.
    #[test]
    fn a_drained_quantum_polls_the_batch_deadline_and_publishes_its_own_stop() {
        let drain_skip = |engine: &Engine| -> Vec<Skipped> {
            engine
                .counters
                .object_skips
                .iter()
                .filter(|skip| skip.subject == "live discovery drain")
                .cloned()
                .collect()
        };

        let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
        let mut session = ScriptedSession::default();
        let mut collect = Engine::collect_discovery_records;
        engine
            .apply_discovery_batch_with(
                &mut session,
                Vec::new(),
                2,
                true,
                false,
                &mut collect,
                Some(0),
            )
            .unwrap();
        assert_eq!(
            drain_skip(&engine),
            vec![Skipped {
                subject: "live discovery drain".into(),
                reason: SCAN_DEADLINE_REASON.into(),
            }],
            "an expired batch deadline stops the drain at its quantum, once"
        );

        let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
        assert!(engine.budget.charge(16 * 1024 * 1024));
        let mut session = ScriptedSession::default();
        let mut collect = Engine::collect_discovery_records;
        engine
            .apply_discovery_batch_with(
                &mut session,
                Vec::new(),
                2,
                true,
                false,
                &mut collect,
                None,
            )
            .unwrap();
        assert_eq!(
            drain_skip(&engine),
            vec![Skipped {
                subject: "live discovery drain".into(),
                reason: WORK_CEILING_REASON.into(),
            }],
            "a refused charge is the work ceiling, never mislabelled as the deadline"
        );

        // An ordinary drain inside its deadline publishes nothing at all.
        let (mut engine, _scope) = engine_over_cgroup_naming(&[]);
        let mut session = ScriptedSession::default();
        let mut collect = Engine::collect_discovery_records;
        engine
            .apply_discovery_batch_with(
                &mut session,
                Vec::new(),
                2,
                true,
                false,
                &mut collect,
                Some(u64::MAX),
            )
            .unwrap();
        assert!(drain_skip(&engine).is_empty());
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
        let prearm = route.find("self.arm_owned_loader_before_release(").unwrap();
        let exports = route.find("self.attach_initial_exports(").unwrap();
        let coverage = route.find("self.mark_owned_selection_pending(").unwrap();
        let ready = route.rfind("Ok(session)").unwrap();
        assert!(prearm < exports && exports < coverage && coverage < ready);
        assert!(route.contains("if owned_prearmed && let Some(generation)"));

        let run = include_str!("../run.rs");
        let owned_run = run
            .split_once("fn run_owned_inner(")
            .unwrap()
            .1
            .split_once("\nfn no_modules_hint(")
            .unwrap()
            .0;
        assert!(
            owned_run.find(".start_owned_session(").unwrap()
                < owned_run.find(".release()").unwrap()
        );
        let finish = run
            .split_once("    fn finish(\n")
            .unwrap()
            .1
            .split_once("\n    }\n}")
            .unwrap()
            .0;
        assert!(
            finish.find("finish_owned_selection_coverage(").unwrap()
                < finish.find("self.coordinator.cleanup(").unwrap()
        );
    }

    #[test]
    fn initial_provider_exports_are_attached_before_session_readiness() {
        let source = include_str!("engine.rs");
        let route = source
            .split_once("    fn start_session_with(")
            .unwrap()
            .1
            .split_once("\n    }\n}")
            .unwrap()
            .0;
        let external_loader = route.find("self.arm_loader_or_partial(").unwrap();
        let exports = route.find("self.attach_initial_exports(").unwrap();
        let drain = route
            .find("let cleanup = self.process_discovery_records(")
            .unwrap();
        let ready = route.rfind("Ok(session)").unwrap();

        assert!(external_loader < exports);
        assert!(exports < drain);
        assert!(drain < ready);
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
    fn typed_prearm_attach_unavailability_is_the_only_fallback() {
        use crate::attach::DynamicLoaderAttachFailure;

        assert!(matches!(
            classify_owned_prearm_attach(GenerationMutation::Committed(Err(
                DynamicLoaderAttachFailure::KernelUnavailable(anyhow!(
                    "kernel loader attach unavailable"
                ))
            ))),
            OwnedPrearmAttachDisposition::Unavailable { .. }
        ));
        for failure in [
            DynamicLoaderAttachFailure::Provenance(anyhow!("pinned identity changed")),
            DynamicLoaderAttachFailure::Registry(anyhow!("attach path unavailable")),
            DynamicLoaderAttachFailure::ProgramMissing,
            DynamicLoaderAttachFailure::ProgramType(anyhow!("wrong Aya program type")),
            DynamicLoaderAttachFailure::InvalidPid,
        ] {
            assert!(matches!(
                classify_owned_prearm_attach(GenerationMutation::Committed(Err(failure))),
                OwnedPrearmAttachDisposition::Lifecycle {
                    producer_exists: false,
                    ..
                }
            ));
        }
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
    fn capture_facts_reuses_only_the_same_exact_module_id() {
        let first = timing_key(0);
        let second = timing_key(1);
        let mut facts = CaptureFacts::default();

        assert_eq!(facts.resolve_module_id(&first).unwrap(), plan::ModuleId(0));
        assert_eq!(facts.resolve_module_id(&first).unwrap(), plan::ModuleId(0));
        assert_eq!(facts.resolve_module_id(&second).unwrap(), plan::ModuleId(1));
        assert_eq!(facts.module_key(plan::ModuleId(0)), Some(&first));
        assert_eq!(facts.module_key(plan::ModuleId(1)), Some(&second));
    }

    #[test]
    fn capture_facts_bind_candidate_plan_ids_before_extension() {
        let (first, _, _, first_key) = engine_with_overlay(20);
        let mut facts = CaptureFacts::default();
        let mut initial = first.plan.clone();
        facts
            .bind_plan_module_ids(&mut initial, &first.modules, &[], &first.pinned)
            .unwrap();
        let stable = initial.modules[0].id;
        assert_eq!(stable, plan::ModuleId(0));
        assert_eq!(initial.slots[0].module_ids, [stable]);

        let mut reload = first.plan.clone();
        facts
            .bind_plan_module_ids(&mut reload, &first.modules, &[], &first.pinned)
            .unwrap();
        assert_eq!(reload.modules[0].id, stable);
        assert_eq!(facts.module_key(stable), Some(&first_key));

        let (different, _, _, different_key) = engine_with_overlay(21);
        let mut different_plan = different.plan.clone();
        facts
            .bind_plan_module_ids(
                &mut different_plan,
                &different.modules,
                &[],
                &different.pinned,
            )
            .unwrap();
        assert_eq!(different_plan.modules[0].id, plan::ModuleId(1));
        assert_eq!(different_plan.slots[0].module_ids, [plan::ModuleId(1)]);
        assert_eq!(facts.module_key(plan::ModuleId(1)), Some(&different_key));
    }

    /// Task 9.2b defect F. A capture-stable module ID is not the plan-local
    /// one: any provider discovered ahead of this one takes the lower ID — a
    /// capacity-*refused* provider included, since it is still a discovered
    /// module with an exact identity. Binding renames the plan's modules and
    /// its slots' owners; the aggregate cells name the same modules and must be
    /// renamed with them. Leaving them on the pre-bind ID makes the next
    /// extension read one provider under two IDs as two rivals and latch
    /// `module_ambiguous` on every one of its cells — lane 03's 68 ambiguous
    /// slots with no competing co-owner anywhere.
    #[test]
    fn rebinding_a_provider_to_its_stable_id_is_not_a_second_rival_owner() {
        let (engine, _, _, _) = engine_with_overlay(50);
        let mut facts = CaptureFacts::default();
        // Another provider this capture discovered first holds ModuleId(0).
        facts.resolve_module_id(&timing_key(0)).unwrap();

        let mut committed = engine.plan.clone();
        assert_eq!(committed.modules[0].id, plan::ModuleId(0));
        facts
            .bind_plan_module_ids(&mut committed, &engine.modules, &[], &engine.pinned)
            .unwrap();
        assert_eq!(committed.modules[0].id, plan::ModuleId(1));

        let mut rebuilt = engine.plan.clone();
        facts
            .bind_plan_module_ids(&mut rebuilt, &engine.modules, &[], &engine.pinned)
            .unwrap();
        committed
            .extend_exact_with_stable_module_ids(rebuilt)
            .unwrap();

        assert_eq!(
            committed.module_ambiguous, 0,
            "one provider under one stable ID is one owner, not two rivals"
        );
    }

    #[test]
    fn live_candidate_reuses_an_exact_provider_id_after_an_empty_interval() {
        let (mut engine, first_raw, _, _) = engine_with_overlay(30);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        let first_pins = engine.pinned.clone();

        let empty = engine
            .live_candidate(PinnedObjects::empty(), Vec::new(), Vec::new())
            .unwrap();
        engine.plan = empty.plan;
        engine.pinned = empty.pinned;
        engine.modules = empty.modules;

        let reload = engine
            .live_candidate(first_pins, vec![first_raw], Vec::new())
            .unwrap();
        assert_eq!(reload.plan.modules[0].id, plan::ModuleId(0));

        let (different, different_raw, _, _) = engine_with_overlay(31);
        let new_identity = engine
            .live_candidate(different.pinned, vec![different_raw], Vec::new())
            .unwrap();
        assert_eq!(new_identity.plan.modules[0].id, plan::ModuleId(1));
    }

    #[test]
    fn accepted_capture_facts_survive_empty_and_deduplicate_exact_reload() {
        let (mut engine, _, _, _) = engine_with_overlay(40);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        let first_plan = engine.plan.clone();
        let first_pins = engine.pinned.clone();
        let first_modules = engine.modules.clone();

        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.plan.entries_seen, 1);
        assert_eq!(engine.plan.surfaces.len(), 1);
        assert_eq!(engine.discovery.modules.len(), 1);

        let empty = engine
            .live_candidate(PinnedObjects::empty(), Vec::new(), Vec::new())
            .unwrap();
        engine.plan = empty.plan;
        engine.pinned = empty.pinned;
        engine.modules = empty.modules;
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.plan.entries_seen, 1);
        assert_eq!(engine.plan.surfaces.len(), 1);
        assert_eq!(engine.discovery.modules.len(), 1);

        engine.plan = first_plan;
        engine.pinned = first_pins;
        engine.modules = first_modules;
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.plan.entries_seen, 1, "exact reload is not recounted");
        assert_eq!(engine.plan.surfaces.len(), 1, "surface is not duplicated");
        assert_eq!(engine.discovery.modules.len(), 1);

        let (different, _, _, _) = engine_with_overlay(41);
        engine.plan = different.plan;
        engine.pinned = different.pinned;
        engine.modules = different.modules;
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.plan.entries_seen, 2);
        assert_eq!(engine.plan.surfaces.len(), 2);
        assert_eq!(engine.discovery.modules.len(), 2);
    }

    #[test]
    fn accepted_capture_facts_publish_scanned_interface_surfaces() {
        let (mut engine, _, _, _) = engine_with_overlay(45);
        engine.modules[0].scanned.interfaces.push(ScannedInterface {
            index: 0,
            name_class: "exact_standard",
            name_lossy: None,
            name_private: None,
            flags: 0,
            table: Some(0),
        });
        engine.plan = plan::build_from_reconciled_modules(&engine.modules);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();

        engine.publish_current_capture_facts().unwrap();

        assert_eq!(engine.plan.surfaces.len(), 2);
        assert_eq!(
            engine.plan.surfaces[1].source,
            "interface[0] exact_standard"
        );

        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.plan.surfaces.len(), 2, "surface is not duplicated");
    }

    #[test]
    fn accepted_capture_facts_retain_a_changed_table_at_the_same_position() {
        let (mut engine, _, _, _) = engine_with_overlay(42);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        engine.publish_current_capture_facts().unwrap();

        engine.modules[0].scanned.tables[0].version = (3, 0);
        engine.plan.modules[0].tables[0].version = (3, 0);
        engine.publish_current_capture_facts().unwrap();

        assert_eq!(
            engine.discovery.modules[0]
                .tables
                .iter()
                .map(|table| table.version)
                .collect::<Vec<_>>(),
            [(2, 40), (3, 0)]
        );

        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.discovery.modules[0].tables.len(), 2);
    }

    #[test]
    fn later_same_path_table_retires_pre_attachment_scan_losses() {
        let (mut engine, _, _, _) = engine_with_overlay(43);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        let attached_plan = engine.plan.clone();
        let attached_pinned = engine.pinned.clone();
        let attached_modules = engine.modules.clone();
        let path = attached_modules[0].scanned.path.clone();
        let not_mapped = Skipped {
            subject: path.clone(),
            reason: "not mapped in the target".into(),
        };
        let empty_scan = Skipped {
            subject: path,
            reason: "no function table was found in its file-backed data".into(),
        };
        let same_path_other = Skipped {
            subject: attached_modules[0].scanned.path.clone(),
            reason: "provider identity changed".into(),
        };
        let initial_set_timing = Skipped {
            subject: "owned initial-set discovery".into(),
            reason: "the empty timing catalog leaves initial-set capture unproven".into(),
        };
        let unmatched = Skipped {
            subject: "/opt/other-p11.so".into(),
            reason: "not mapped in the target".into(),
        };
        engine.counters.object_skips = vec![
            not_mapped.clone(),
            empty_scan.clone(),
            same_path_other.clone(),
            initial_set_timing.clone(),
            unmatched.clone(),
        ];
        engine.plan = plan::build_from_reconciled_modules(&[]);
        engine.pinned = PinnedObjects::empty();
        engine.modules.clear();
        engine.publish_current_capture_facts().unwrap();

        engine.plan = attached_plan;
        engine.pinned = attached_pinned;
        engine.modules = attached_modules;
        engine.publish_current_capture_facts().unwrap();

        assert_eq!(
            engine.plan.skipped,
            vec![
                unmatched.clone(),
                same_path_other.clone(),
                initial_set_timing.clone()
            ],
            "only non-scan-gap losses remain"
        );
        assert!(!engine.plan.skipped.contains(&not_mapped));
        assert!(!engine.plan.skipped.contains(&empty_scan));

        engine.plan = plan::build_from_reconciled_modules(&[]);
        engine.pinned = PinnedObjects::empty();
        engine.modules.clear();
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(
            engine.plan.skipped,
            vec![unmatched, same_path_other, initial_set_timing],
            "a later empty publication does not resurrect retired scan gaps"
        );
        let rendered = engine
            .plan
            .skipped
            .iter()
            .map(render::capture_skipped_out)
            .collect::<Vec<_>>();
        assert_eq!(rendered.len(), 3);
        assert!(rendered.iter().all(|skip| {
            skip.name == "discovery subject" && skip.reason == "discovery unavailable"
        }));
    }

    #[test]
    fn capture_fact_stage_publishes_once_or_rolls_back_whole() {
        let (mut engine, _, _, _) = engine_with_overlay(50);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.discovery.modules.len(), 1);

        let (different, _, _, _) = engine_with_overlay(51);
        engine.capture_facts.begin_stage().unwrap();
        engine.plan = different.plan.clone();
        engine.pinned = different.pinned.clone();
        engine.modules = different.modules.clone();
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(
            engine.discovery.modules.len(),
            1,
            "the stage is not published before successful return"
        );
        engine.capture_facts.rollback_stage();
        engine.capture_facts.apply_to_plan(&mut engine.plan);
        engine.discovery = engine.capture_facts.discovery(&engine.plan);
        assert_eq!(
            engine.discovery.modules.len(),
            1,
            "late failure publishes nothing"
        );
        assert_eq!(engine.plan.entries_seen, 1);

        engine.capture_facts.begin_stage().unwrap();
        engine.publish_current_capture_facts().unwrap();
        engine.capture_facts.commit_stage().unwrap();
        engine.project_capture_facts();
        assert_eq!(engine.discovery.modules.len(), 2);
        assert_eq!(engine.plan.entries_seen, 2);
    }

    /// `table_entries` counts an exact target occurrence once however many
    /// sources decoded it (`docs/schema/observed-profile-v2.md`: "A `--manifest`
    /// overlapping a scanned module does not add a second count for the same
    /// exact target occurrence; distinct claims and true repeated occurrences
    /// remain separate"). The planner already merges that way; publication must
    /// not undo it by counting the scan's target and the manifest's function as
    /// two entries.
    #[test]
    fn capture_facts_count_a_corroborated_entry_once_across_both_surfaces() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
        let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        assert_eq!(engine.plan.entries_seen, 1, "the planner counts it once");
        assert_eq!(engine.plan.surfaces.len(), 2, "one scan and one manifest");

        engine.publish_current_capture_facts().unwrap();

        assert_eq!(
            engine.plan.entries_seen, 1,
            "the corroborating manifest must not add a second count"
        );
        assert_eq!(
            engine.plan.surfaces.len(),
            2,
            "each source keeps its own surface record"
        );

        // The other direction: a manifest claim the scan did not decode is a
        // distinct entry, not a duplicate of the one it did.
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
        let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        assert_eq!(engine.plan.entries_seen, 2);
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(
            engine.plan.entries_seen, 2,
            "a distinct claim stays a distinct entry"
        );
    }

    /// The attach-time reconciliation is the only thing that ever derives a
    /// §4.12 outcome, and on a target held on a barrier it runs before the
    /// provider is mapped: it sees no scan, records `uncorroborated`, and the
    /// live path never revisits it. Rewinds the recorded counters to exactly
    /// that blind state and leaves the scan facts the capture ended up with.
    fn blinded_attach_time_corroboration(engine: &mut Engine) {
        engine.counters.conflicts = 0;
        engine.counters.uncorroborated = 1;
        engine.counters.corroboration = vec![(
            engine.plan.modules.iter().map(|m| m.object).collect(),
            "uncorroborated",
        )];
        for module in &mut engine.plan.modules {
            module.corroborated = false;
        }
    }

    /// §4.12 is judged by capture end, not by what the attach-time scan
    /// happened to see (design §4.12: corroboration happens "whenever the
    /// object is mapped in scope — scan **or a live export record**"; schema:
    /// `uncorroborated` means "not mapped in scope, or no scan"). A provider
    /// the target only maps after the observer attached is corroborated by the
    /// end, and the blind attach-time outcome is stale.
    #[test]
    fn a_manifest_the_scan_only_reaches_later_is_corroborated_by_capture_end() {
        // Differing targets: the manifest records 0x40, the scan decodes 0x80.
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
        let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        blinded_attach_time_corroboration(&mut engine);

        engine.publish_current_capture_facts().unwrap();

        assert_eq!(
            engine.discovery.conflicts, 1,
            "both sources decoded targets in one object and they differ"
        );
        assert_eq!(
            engine.discovery.uncorroborated, 0,
            "nothing is uncorroborated: the scan reached this object by capture end"
        );
        let module = &engine.discovery.modules[0];
        assert!(module.corroborated, "{module:?}");
        assert_eq!(module.corroboration, vec!["conflict"], "{module:?}");
    }

    /// Same seam, agreeing sources: the re-derivation must report the outcome
    /// it actually derives, not "corroborated somehow".
    #[test]
    fn a_late_scan_that_agrees_is_recorded_as_agreed_not_as_a_conflict() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
        let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        blinded_attach_time_corroboration(&mut engine);

        engine.publish_current_capture_facts().unwrap();

        assert_eq!(engine.discovery.conflicts, 0);
        assert_eq!(engine.discovery.uncorroborated, 0);
        let module = &engine.discovery.modules[0];
        assert!(module.corroborated, "{module:?}");
        assert_eq!(module.corroboration, vec!["agreed"], "{module:?}");
    }

    /// Corroboration is a capture-*lifetime* fact, so it survives the ordinary
    /// churn of a `--cgroup` capture: `pkcs11-check --isolation file` retires a
    /// view per exiting subprocess, and a publication whose pin set no longer
    /// holds the scan's decoded tables is less informed, not newer evidence
    /// that nothing corroborated the manifest. Observed live before this was
    /// held: `corroboration: ["agreed", "uncorroborated"]` beside
    /// `corroborated: true` and `discovery_uncorroborated: 1`.
    #[test]
    fn a_derived_corroboration_survives_a_later_less_informed_publication() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
        let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        blinded_attach_time_corroboration(&mut engine);
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.discovery.modules[0].corroboration, vec!["conflict"]);

        // The scan's view is gone; the manifest still describes the object.
        engine.modules.clear();
        engine.publish_current_capture_facts().unwrap();

        let module = &engine.discovery.modules[0];
        assert_eq!(module.corroboration, vec!["conflict"], "{module:?}");
        assert!(module.corroborated, "{module:?}");
        assert_eq!(engine.discovery.conflicts, 1);
        assert_eq!(engine.discovery.uncorroborated, 0);
    }

    /// A corroboration tombstone is a gap of its own, and it must survive every
    /// later publication however many *other* modules hold a derived
    /// corroboration. Also the only cover for the tombstone-revokes-derived
    /// path: a derived corroboration is already inside the blind attach-time
    /// count, so revoking it restores that contribution rather than adding a
    /// second one.
    #[test]
    fn a_tombstone_gap_survives_another_modules_derived_corroboration() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
        let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        blinded_attach_time_corroboration(&mut engine);
        engine.publish_current_capture_facts().unwrap();
        let derived = engine.discovery.modules[0].id;
        assert_eq!(
            engine.discovery.uncorroborated, 0,
            "the blind attach-time outcome is re-derived at capture end"
        );
        assert_eq!(
            engine.discovery.conflicts, 1,
            "the two sources decoded different targets in one object"
        );

        // A second provider, corroborated when the plan was built: it is not in
        // the blind attach-time count, so revoking its proof is a new gap.
        let second = plan::ModuleId(derived.0 + 1);
        let mut attach_corroborated = merged_module(vec!["scan", "manifest"]);
        attach_corroborated.id = second;
        attach_corroborated.corroborated = true;
        attach_corroborated.corroboration = vec!["agreed"];
        engine
            .capture_facts
            .history
            .modules
            .insert(second, attach_corroborated);

        engine
            .capture_facts
            .invalidate_discovery_proofs([second], []);
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(
            engine.discovery.uncorroborated, 1,
            "the revoked proof is a gap the document must report"
        );
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(
            engine.discovery.uncorroborated, 1,
            "a tombstone gap is not absorbed by another module's re-derivation"
        );

        // Revoking the derived module's own proof restores exactly its blind
        // attach-time contribution — it must not be counted twice.
        engine
            .capture_facts
            .invalidate_discovery_proofs([derived], []);
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(
            engine.discovery.uncorroborated, 2,
            "both providers are uncorroborated now, and neither is double-counted"
        );
        // Corroboration is revocable; a disagreement is not. The two sources
        // did decode different targets, and no later retirement unsays it —
        // an attach-derived conflict survives its module's tombstone through
        // the high-water base, and a capture-end-derived one must too.
        assert_eq!(
            engine.discovery.conflicts, 1,
            "a derived conflict is sticky: revoking the proof cannot lower it"
        );
    }

    /// The other way a derived conflict can be replaced rather than revoked.
    /// Only three of the version-matrix provider's thirteen tables live in
    /// file-backed data; the other ten are built at run time in `.bss`, so a
    /// scan that differs early and agrees once more of the object is decoded
    /// is reachable. The later agreement is the better reading of the module,
    /// but it does not unsay that the two sources once decoded different
    /// targets.
    #[test]
    fn a_derived_conflict_stays_counted_when_a_later_scan_agrees() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
        let mut engine = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        blinded_attach_time_corroboration(&mut engine);
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.discovery.conflicts, 1);
        assert_eq!(engine.discovery.modules[0].corroboration, vec!["conflict"]);

        // The same object, decoded again with the targets now agreeing.
        let (_, agreeing, agreeing_pins, agreeing_input) = same_object_scan_and_manifest(0x40);
        let agreed = discovered_from_inputs(
            vec![ProcessView::open(ProcessViewId(0), std::process::id()).unwrap()],
            agreeing,
            agreeing_pins,
            vec![agreeing_input],
        );
        engine.plan = agreed.plan;
        engine.pinned = agreed.pinned;
        engine.modules = agreed.modules;
        engine.manifests = agreed.manifests;
        engine.manifest_ordinals = agreed.manifest_ordinals;
        blinded_attach_time_corroboration(&mut engine);
        engine
            .capture_facts
            .bind_plan_module_ids(
                &mut engine.plan,
                &engine.modules,
                &engine.manifests,
                &engine.pinned,
            )
            .unwrap();
        engine.publish_current_capture_facts().unwrap();

        assert_eq!(
            engine.discovery.modules[0].corroboration,
            vec!["agreed"],
            "the better-informed reading wins the module's own record"
        );
        assert_eq!(
            engine.discovery.conflicts, 1,
            "a disagreement the capture really observed is never decremented"
        );
        assert_eq!(engine.discovery.uncorroborated, 0);
    }

    /// The guard the re-derivation turns on: a provider the scan never reached
    /// — the only source that ever described it is the manifest — is still
    /// uncorroborated at capture end, and must stay that way.
    #[test]
    fn a_provider_the_scan_never_reached_stays_uncorroborated() {
        let (_, modules, pins, input) = same_object_scan_and_manifest(0x80);
        let object = pins.pinned().next().unwrap();
        let manifest_only = pin_as_manifest_object(object.path);
        let owned = manifest_only.pinned().next().unwrap().id;
        assert_eq!(
            manifest_only.sources(owned),
            ["manifest"],
            "the fixture must have no scan alias"
        );

        let counters = DiscoveryCounters {
            uncorroborated: 1,
            corroboration: vec![([owned].into_iter().collect(), "uncorroborated")],
            ..DiscoveryCounters::default()
        };
        let reconciled = bind_scanned_modules(&modules, &mut pins.clone()).0;
        assert!(
            recorroborate_at_capture_end(
                &manifest_only,
                &reconciled,
                std::slice::from_ref(&input.manifest),
                &counters,
            )
            .is_empty(),
            "nothing is mapped in scope to corroborate against"
        );
    }

    #[test]
    fn capture_facts_keep_each_accepted_manifest_ordinal_once() {
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
        let mut engine = lifecycle_discovered(Vec::new());
        engine.manifest_inputs = vec![input("first.json"), input("second.json")];
        rebuild_discovered(&mut engine).unwrap();

        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.plan.entries_seen, 2);
        assert_eq!(engine.plan.surfaces.len(), 2);

        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.plan.entries_seen, 2, "one refresh does not recount");
        assert_eq!(
            engine.plan.surfaces.len(),
            2,
            "one refresh does not duplicate"
        );
    }

    #[test]
    fn capture_fact_proof_tombstones_block_later_positive_refresh() {
        let (mut engine, _, object, _) = engine_with_overlay(52);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        let module = engine.plan.modules[0].id;
        engine.plan.modules[0].corroborated = true;
        engine.counters.corroboration = vec![([object].into_iter().collect(), "agreed")];
        engine.counters.manifest_fallbacks.push(ManifestFallback {
            manifest: 0,
            object: 0,
            reason: ManifestStaleReason::IdentityMismatch,
            replacement: object,
            proof: BoundFallbackProof {
                module: object,
                tables: Vec::new(),
                required_targets: BTreeMap::new(),
            },
        });
        engine.publish_current_capture_facts().unwrap();
        assert!(engine.discovery.modules[0].corroborated);
        assert_eq!(engine.discovery.manifest_object_fallbacks.len(), 1);

        engine
            .capture_facts
            .invalidate_discovery_proofs([module], [(0, 0)]);
        engine.publish_current_capture_facts().unwrap();

        assert!(!engine.discovery.modules[0].corroborated);
        assert_eq!(
            engine.discovery.modules[0].corroboration,
            ["uncorroborated"]
        );
        assert!(engine.discovery.manifest_object_fallbacks.is_empty());
    }

    #[test]
    fn current_discovery_never_reads_an_inactive_slots_retired_pin() {
        let (mut plan, pins) = plan_with_pins(2, 0);
        plan.slots[1].object = PinnedObjectId(u32::MAX);
        plan.deactivate(1);

        let evidence = discovery_evidence(&plan, &pins, &DiscoveryCounters::default());

        assert_eq!(evidence.modules[0].objects.len(), 1);
    }

    #[test]
    fn capture_facts_keep_all_decoded_occurrences_for_a_capacity_refusal() {
        let mut raw = overlay_module(overlay_key(53));
        raw.tables[0].entries = (0..=p11scope_ebpf_common::MAX_SLOTS)
            .map(|index| ScannedEntry {
                name: "C_Sign",
                object: raw.key,
                object_path: raw.path.clone(),
                file_offset: 8 * u64::from(index),
            })
            .collect();
        let mut pins = overlay_pins(&[(raw.key, OVERLAY_SHA, 1)]);
        let (modules, skipped) = bind_scanned_modules(std::slice::from_ref(&raw), &mut pins);
        assert!(skipped.is_empty(), "{skipped:?}");
        let mut engine = Engine::empty();
        engine.plan = plan::build_from_reconciled_modules(&modules);
        engine.pinned = pins;
        engine.modules = modules;
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();

        engine.publish_current_capture_facts().unwrap();

        assert_eq!(engine.plan.entries_seen, 513);
        assert!(engine.plan.slots.is_empty());
        assert_eq!(engine.plan.modules_skipped.len(), 1);
        assert!(engine.discovery.modules.is_empty());
        assert_eq!(engine.discovery.modules_skipped.len(), 1);

        engine.plan = plan::build_from_reconciled_modules(&[]);
        engine.pinned = PinnedObjects::empty();
        engine.modules.clear();
        engine.publish_current_capture_facts().unwrap();
        assert_eq!(engine.plan.entries_seen, 513);
        assert_eq!(engine.discovery.modules_skipped.len(), 1);
    }

    #[test]
    fn capture_facts_keep_a_manifest_only_capacity_refusal() {
        let (_, pins) = pinned_self();
        let summary = pins.pinned().next().unwrap();
        let path = summary.path.to_string();
        let mut manifest = manifest_naming(&path, Some(summary.sha256.to_string()));
        let function = manifest.surfaces[0].functions[0].clone();
        manifest.surfaces[0].functions = (0..=p11scope_ebpf_common::MAX_SLOTS)
            .map(|index| {
                let mut function = function.clone();
                function.resolution = Resolution::Resolved {
                    object: 0,
                    file_offset: 8 * u64::from(index),
                };
                function
            })
            .collect();
        let manifest_pins = pin_as_manifest_object(&path);
        retarget_to_pins(&mut manifest, &[], &PinnedObjects::empty(), &manifest_pins);
        let (mut engine, _, _, _) = engine_with_overlay(55);
        assert!(engine.pinned.absorb(manifest_pins).is_empty());
        engine.manifests = vec![manifest];
        engine.manifest_ordinals = vec![0];
        let mut counters = DiscoveryCounters::default();
        engine.plan = build_current_plan(
            &engine.modules,
            &engine.manifests,
            &engine.pinned,
            &mut counters,
            &BTreeSet::new(),
            0,
            0,
        )
        .unwrap();
        engine.counters = counters;
        engine
            .capture_facts
            .bind_plan_module_ids(
                &mut engine.plan,
                &engine.modules,
                &engine.manifests,
                &engine.pinned,
            )
            .unwrap();
        assert_eq!(engine.plan.modules_skipped.len(), 1);

        engine.publish_current_capture_facts().unwrap();

        assert_eq!(engine.plan.entries_seen, 514);
        assert_eq!(engine.plan.slots.len(), 1);
        assert_eq!(engine.plan.modules_skipped.len(), 1);
        assert_eq!(engine.discovery.modules_skipped.len(), 1);
        assert_eq!(engine.discovery.modules.len(), 1);
    }

    #[test]
    fn start_attempt_stages_initial_facts_before_active_cleanup() {
        let (mut engine, _, _, _) = engine_with_overlay(56);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        assert!(engine.capture_facts.history.modules.is_empty());
        let snapshot = engine.begin_start_capture_attempt().unwrap();

        engine.plan = plan::build_from_reconciled_modules(&[]);
        engine.pinned = PinnedObjects::empty();
        engine.modules.clear();
        engine.publish_current_capture_facts().unwrap();
        engine
            .finish_start_capture_attempt(snapshot, Ok(()))
            .unwrap();

        assert_eq!(engine.discovery.modules.len(), 1);
        assert_eq!(engine.plan.entries_seen, 1);
    }

    #[test]
    fn failed_start_restores_prior_aggregate_owner_after_cleanup() {
        let (mut engine, _, _, _) = engine_with_overlay(54);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        engine.publish_current_capture_facts().unwrap();
        let owner = engine.plan.module_of_slot(0);
        let snapshot = engine.begin_start_capture_attempt().unwrap();

        let mut shared = engine.plan.slots[0].clone();
        shared.module_ids.push(plan::ModuleId(99));
        let candidate = plan::AttachPlan::from_slots(vec![shared]);
        assert!(engine.latch_candidate_ambiguity(&candidate));
        assert_eq!(engine.plan.module_of_slot(0), None);
        let cleanup_ran = Cell::new(false);
        cleanup_ran.set(true);

        let result: Result<()> =
            engine.finish_start_capture_attempt(snapshot, Err(anyhow!("late loader failure")));

        assert!(result.is_err());
        assert!(cleanup_ran.get());
        assert_eq!(engine.plan.module_of_slot(0), owner);
        assert_eq!(engine.plan.module_ambiguous, 0);
        assert_eq!(engine.discovery.modules.len(), 1);
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
    fn lifecycle_records_bind_once_to_the_admitted_process_view() {
        let view = ProcessView::open(ProcessViewId(12), std::process::id()).unwrap();
        let admitted = view.admitted_ns();
        let pid = view.pid();

        assert_eq!(
            lifecycle_retirement(
                &[view],
                pid,
                admitted.saturating_sub(1),
                DISCOVERY_KIND_LEADER_EXIT,
            ),
            None,
            "a delayed record from before this retained generation cannot retire it"
        );

        let view = ProcessView::open(ProcessViewId(13), std::process::id()).unwrap();
        assert_eq!(
            lifecycle_retirement(&[view], pid, u64::MAX, DISCOVERY_KIND_EXEC),
            Some((ProcessViewId(13), RetirementCause::ExecRefresh))
        );
        let view = ProcessView::open(ProcessViewId(14), std::process::id()).unwrap();
        assert_eq!(
            lifecycle_retirement(&[view], pid, u64::MAX, DISCOVERY_KIND_LEADER_EXIT),
            Some((ProcessViewId(14), RetirementCause::ExpectedRemoval))
        );
    }

    #[test]
    fn retirement_cause_merge_never_downgrades_real_loss() {
        assert_eq!(
            RetirementCause::ExecRefresh.merge(RetirementCause::ExpectedRemoval),
            RetirementCause::ExpectedRemoval
        );
        assert_eq!(
            RetirementCause::ExpectedRemoval.merge(RetirementCause::GenerationLost),
            RetirementCause::GenerationLost
        );
        assert_eq!(
            RetirementCause::GenerationLost.merge(RetirementCause::ExecRefresh),
            RetirementCause::GenerationLost
        );
    }

    #[test]
    fn batch_exit_dominates_exec_before_dead_pin_promotion() {
        let record = |kind, pid, hook_ts_ns| {
            let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
            record.kind = kind;
            record.pid_tgid = u64::from(pid) << 32;
            record.hook_ts_ns = hook_ts_ns;
            record
        };
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let view = ProcessView::open(ProcessViewId(18), child.id()).unwrap();
        let hook_ts_ns = view.admitted_ns();
        let mut engine = Engine::empty();
        engine.views.push(view);
        child.kill().unwrap();
        child.wait().unwrap();
        let mut pending = PendingViewRetirements::new();

        for record in [
            record(DISCOVERY_KIND_EXEC, child.id(), hook_ts_ns),
            record(DISCOVERY_KIND_LEADER_EXIT, child.id(), hook_ts_ns),
        ] {
            engine.dispatch_lifecycle_record(&record, &mut pending);
        }
        engine.promote_stale_execs(&mut pending);

        assert_eq!(
            pending.get(&ProcessViewId(18)),
            Some(&RetirementCause::ExpectedRemoval)
        );
        assert!(!engine.refresh_requested.contains(&child.id()));
        assert!(
            engine
                .counters
                .object_skips
                .iter()
                .all(|skip| skip.subject != "live discovery generation")
        );

        // An exec with no exit *record* still gets its matching exit from the
        // stronger authority: the retained original pin. Task 9.2 defect B —
        // the exit record is still in the ring while the pidfd is already
        // readable, and calling that proven exit a lost generation failed
        // `p11scope run` on every short-lived child.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let view = ProcessView::open(ProcessViewId(19), child.id()).unwrap();
        let exec = record(DISCOVERY_KIND_EXEC, child.id(), view.admitted_ns());
        let mut engine = Engine::empty();
        engine.views.push(view);
        child.kill().unwrap();
        child.wait().unwrap();
        let mut pending = PendingViewRetirements::new();
        engine.dispatch_lifecycle_record(&exec, &mut pending);
        engine.promote_stale_execs(&mut pending);
        assert_eq!(
            pending.get(&ProcessViewId(19)),
            Some(&RetirementCause::ExpectedRemoval),
            "a pin that proves the original exited names the leader-exit transition"
        );
        assert!(
            engine
                .counters
                .object_skips
                .iter()
                .all(|skip| skip.subject != "live discovery generation"),
            "a proven exit is not a loss"
        );

        // Loss that cannot be proven an exit stays loss: the live-loader attach
        // postcheck route on a generation that is still running.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let view = ProcessView::open(ProcessViewId(20), child.id()).unwrap();
        let mut engine = Engine::empty();
        engine.views.push(view);
        let mut pending = PendingViewRetirements::new();
        engine.queue_stale_views(&[ProcessViewId(20)].into_iter().collect(), &mut pending);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(
            pending.get(&ProcessViewId(20)),
            Some(&RetirementCause::GenerationLost),
            "a live generation that changed under us is genuine loss"
        );
        assert!(
            engine
                .counters
                .object_skips
                .iter()
                .any(|skip| skip.subject == "live discovery generation"),
            "genuine loss stays sticky and PARTIAL"
        );
    }

    /// Task 9.2 defect B, through the real batch route. A named target that
    /// exits while live discovery is working on it is an expected removal —
    /// the retained pin proves it — and the capture ends the ordinary way.
    /// Only the `LEADER_EXIT` record used to say so, and it is still in the
    /// ring when the pidfd is already readable, so `p11scope run` on a
    /// short-lived child failed with a false `the named process generation
    /// changed during live discovery` and discarded the whole capture.
    #[test]
    fn a_named_target_that_provably_exited_ends_the_capture_rather_than_failing_it() {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let view = ProcessView::open(ProcessViewId(0), child.id()).unwrap();
        record.kind = DISCOVERY_KIND_EXEC;
        record.pid_tgid = u64::from(child.id()) << 32;
        record.hook_ts_ns = view.admitted_ns();
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(child.id());
        engine.views.push(view);
        child.kill().unwrap();
        child.wait().unwrap();

        let mut session = ScriptedSession::default();
        apply_ordinary_batch(&mut engine, &mut session, vec![record])
            .expect("a named target's provable exit is not a live-discovery failure");

        assert!(
            engine.expected_target_exit(),
            "the capture ends the ordinary way: {:?}",
            engine.counters.object_skips
        );
        assert!(engine.views.is_empty());
        assert!(
            engine
                .counters
                .object_skips
                .iter()
                .all(|skip| skip.subject != "live discovery generation"),
            "a proven exit is not a lost generation: {:?}",
            engine.counters.object_skips
        );
    }

    #[test]
    fn expected_exit_requires_a_definitive_original_pin_result() {
        assert!(!retirement_ready_with(RetirementCause::ExpectedRemoval, || Ok(false)).unwrap());
        assert!(retirement_ready_with(RetirementCause::ExpectedRemoval, || Ok(true)).unwrap());
        assert!(
            retirement_ready_with(RetirementCause::ExpectedRemoval, || {
                Err("original pidfd poll failed".to_string())
            })
            .is_err(),
            "a transport error is loss, never exit evidence"
        );
        assert!(
            retirement_ready_with(RetirementCause::ExecRefresh, || {
                Err("must not poll".to_string())
            })
            .unwrap()
        );
    }

    /// Task 9.2 defect A. An ordinary dynamically linked target binds its live
    /// loader context through the real arming path, so no capture publishes a
    /// `discovery unavailable` skip for a loader that is plainly there. The
    /// loader is located by reading only the retained executable's bounded
    /// PT_INTERP metadata and matching `/proc/<pid>/maps`; `stat`'s `st_dev` is not
    /// that representation: on a btrfs rootfs it is the subvolume's anonymous device,
    /// so every comparison failed and every capture on such a host reported unavailable.
    #[test]
    fn an_ordinary_dynamic_target_binds_its_live_loader_context() {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let mut child = ChildGuard(
            std::process::Command::new("sh")
                .args(["-c", "printf R; kill -STOP $$"])
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut ready = [0_u8; 1];
        std::io::Read::read_exact(child.0.stdout.as_mut().unwrap(), &mut ready).unwrap();
        assert_eq!(ready, *b"R");
        let view = ProcessView::open(ProcessViewId(0), child.0.id()).unwrap();
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(child.0.id());
        engine.views.push(view);

        let mut session = ScriptedSession::default();
        let armed = engine.arm_loader_or_partial(
            0,
            &mut session,
            &mut true,
            &mut PendingViewRetirements::new(),
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        armed.expect("arming an ordinary dynamic target is not a failure");

        let skips = engine.counters.object_skips.clone();
        let aggregate = engine.loader_discovery();
        assert_eq!(
            aggregate.strategies.debug_state_every_hit, 1,
            "the loader context must bind: {skips:?}"
        );
        assert_eq!(aggregate.strategies.unavailable, 0, "{skips:?}");
        assert_eq!(aggregate.dlopen_timing.none, 0, "{skips:?}");
        assert!(
            skips
                .iter()
                .all(|skip| render::capture_skipped_out(skip).reason != "discovery unavailable"),
            "an available loader never publishes a refused discovery skip: {skips:?}"
        );
    }

    #[test]
    fn two_gib_dynamic_executable_arms_without_hashing_the_executable() {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let source_path = std::path::Path::new("/bin/sh");
        let source_file = std::fs::File::open(source_path).unwrap();
        let source_size = source_file.metadata().unwrap().len();
        assert!(
            read_bounded_interpreter(&source_file, source_size)
                .unwrap()
                .is_some(),
            "the copied source must be a dynamic executable with one PT_INTERP"
        );

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("large-sh");
        std::fs::copy(source_path, &executable).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&executable)
            .unwrap()
            .set_len(2 * 1024 * 1024 * 1024 + 11 * 1024 * 1024)
            .unwrap();
        assert_eq!(
            std::fs::metadata(&executable).unwrap().len(),
            2 * 1024 * 1024 * 1024 + 11 * 1024 * 1024
        );
        let mut child = ChildGuard(
            std::process::Command::new(&executable)
                .args(["-c", "printf R; kill -STOP $$"])
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut ready = [0_u8; 1];
        std::io::Read::read_exact(child.0.stdout.as_mut().unwrap(), &mut ready).unwrap();
        assert_eq!(ready, *b"R");
        let pid = child.0.id() as libc::pid_t;
        let mut status = 0;
        // SAFETY: this process is the parent of the exact unreaped child.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) },
            pid
        );
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        let process_executable = std::fs::metadata(format!("/proc/{}/exe", child.0.id())).unwrap();
        let fixture_executable = std::fs::metadata(&executable).unwrap();
        assert_eq!(
            (process_executable.dev(), process_executable.ino()),
            (fixture_executable.dev(), fixture_executable.ino()),
            "the stopped child must execute the enlarged fixture"
        );
        let view = ProcessView::open(ProcessViewId(0), child.0.id()).unwrap();
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(child.0.id());
        engine.views.push(view);

        let mut session = ScriptedSession::default();
        let armed = engine.arm_loader_or_partial(
            0,
            &mut session,
            &mut true,
            &mut PendingViewRetirements::new(),
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        armed.expect("a large dynamic executable locates its separately bounded loader");

        let skips = engine.counters.object_skips.clone();
        let aggregate = engine.loader_discovery();
        assert_eq!(aggregate.strategies.debug_state_every_hit, 1, "{skips:?}");
        assert_eq!(aggregate.strategies.unavailable, 0, "{skips:?}");
        assert!(
            skips.iter().all(|skip| !skip.reason.contains("too_large")),
            "the executable itself is never hashed: {skips:?}"
        );
    }

    /// Task 9.2 defect A, second half, through the real batch route. A loader
    /// context that retires cleanly publishes nothing. Its terminal dispatch
    /// removes the context it retired, so the view retirement that follows must
    /// not report that same context as one it could not remove — a second
    /// false `discovery unavailable`, reachable only once a loader actually
    /// binds, which is why the broken binding hid it.
    #[test]
    fn a_cleanly_retired_loader_context_publishes_no_skip() {
        let (mut engine, owner) = Engine::retiring_loader_context(std::process::id());
        let mut session = ScriptedSession::with_records([], 0);
        apply_ordinary_batch(&mut engine, &mut session, Vec::new())
            .expect("an ordinary retirement batch");

        assert!(engine.loader_registry.context(owner).is_none());
        let skips = engine.counters.object_skips.clone();
        assert!(
            skips
                .iter()
                .all(|skip| skip.subject != "live loader retirement"),
            "a context removed exactly once is not a removal failure: {skips:?}"
        );
        assert!(
            skips
                .iter()
                .all(|skip| render::capture_skipped_out(skip).reason != "discovery unavailable"),
            "{skips:?}"
        );
    }

    /// One retained live view for this process, one *attached* loader context
    /// frozen on `mapping`, and an `ExecRefresh` already queued for that view:
    /// the state every capture whose target execs passes through between the
    /// exec record and the refresh it queues.
    fn engine_with_exec_refreshed_loader(
        mapping: MapEntry,
    ) -> (Engine, LoaderContextId, ProcessViewId) {
        use p11scope_manifest::elf::SymbolFact;

        let pid = std::process::id();
        let view = ProcessView::open(ProcessViewId(0), pid).expect("a live process view");
        let view_id = view.id();
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(pid);
        engine.views.push(view);
        engine.next_view_id = 1;
        let prepared = engine
            .loader_registry
            .preflight(LoaderContextSpec {
                view: view_id,
                loader: PinnedObjectId(9),
                hook: SymbolFact {
                    virtual_address: mapping.file_offset + 0x10,
                    file_offset: mapping.file_offset + 0x10,
                },
                mapping: Some(mapping),
                state: None,
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
        (engine, context, view_id)
    }

    /// A pending retirement intent is not evidence that this dispatched batch
    /// contains the matching exec record.
    #[test]
    fn a_loader_hit_remapped_by_a_preexisting_exec_refresh_is_a_discovery_loss() {
        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        let observed = maps
            .iter()
            .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
            .expect("this process maps its own executable text")
            .clone();
        // The same object at the load base it had before the exec: identity,
        // file offset and protection unchanged, only the address moved.
        let mut armed = observed.clone();
        armed.start -= 0x1000_0000;
        armed.end -= 0x1000_0000;

        let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
        let mut record = loader_record_for(context, std::process::id());
        record.table_ptr = observed.start + 0x10;
        let mut session = ScriptedSession::with_records([], 1);
        apply_ordinary_batch(&mut engine, &mut session, vec![record])
            .expect("an ordinary batch carrying one remapped loader hit");

        let skips = engine.counters.object_skips.clone();
        assert!(
            skips
                .iter()
                .any(|skip| skip.subject == "live loader discovery"),
            "an intent without an actual same-batch exec cannot explain the moved \
             mapping: {skips:?}"
        );
        // ...and "not a loss" has to mean the loss-class counter too. It is the
        // one contributor that publishes no skip, so a nonzero value here is a
        // gap no reader can attribute to anything.
        let [_, _, _, truncated] = engine.capture_facts().discovery_losses();
        assert_eq!(
            truncated, 1,
            "without an actual same-batch exec, the rejected hit remains one loss"
        );
    }

    /// A loader hit may precede its matching EXEC record in one dispatched
    /// batch. The hit remains rejected and fails pause completeness, but the
    /// exact same-batch lifecycle match explains its moved mapping.
    #[test]
    fn a_loader_hit_remapped_by_a_same_batch_exec_is_not_a_discovery_loss() {
        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        let observed = maps
            .iter()
            .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
            .expect("this process maps its own executable text")
            .clone();
        let mut armed = observed.clone();
        armed.start -= 0x1000_0000;
        armed.end -= 0x1000_0000;

        let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
        engine.retirement_intents.clear();
        engine.refresh_requested.clear();
        let mut loader = loader_record_for(context, std::process::id());
        loader.table_ptr = observed.start + 0x10;
        let mut exec: DiscoveryRecord = unsafe { std::mem::zeroed() };
        exec.kind = DISCOVERY_KIND_EXEC;
        exec.pid_tgid = u64::from(std::process::id()) << 32;
        exec.hook_ts_ns = engine.views[0].admitted_ns();
        let mut session = ScriptedSession::with_records([], 1);
        let outcome = apply_ordinary_batch(&mut engine, &mut session, vec![loader, exec])
            .expect("an ordinary batch carrying a remapped hit before its exec");

        assert!(
            !outcome.required_complete,
            "the loader hit remains rejected even when its loss is explained"
        );
        let skips = engine.counters.object_skips.clone();
        assert!(
            skips
                .iter()
                .all(|skip| skip.subject != "live loader discovery"),
            "the exact same-batch exec explains the moved mapping: {skips:?}"
        );
        let [_, _, _, truncated] = engine.capture_facts().discovery_losses();
        assert_eq!(
            truncated, 0,
            "the explained rejection is counted by nothing"
        );
    }

    /// Task 9.2-fix5 item A. A retained generation that changes under an
    /// operation needing it is loss — unless the retained original pin proves
    /// the process simply ended. Arming a loader context for one of
    /// pkcs11-check's per-file subprocesses loses the generation every time
    /// one finishes, and that is the ordinary end of a process, on the same
    /// authority `queue_retirement` already uses.
    #[test]
    fn a_generation_change_a_pin_proves_was_an_exit_is_not_a_loss() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut engine = Engine::empty();
        engine
            .views
            .push(ProcessView::open(ProcessViewId(0), child.id()).unwrap());
        engine.next_view_id = 1;

        engine.mark_generation_change(ProcessViewId(0), "live loader arming", "scripted");
        assert_eq!(
            engine.counters.object_skips.len(),
            1,
            "a live generation that changed under an arm is a real loss"
        );

        child.kill().unwrap();
        child.wait().unwrap();
        engine.counters.object_skips.clear();
        engine.mark_generation_change(ProcessViewId(0), "live loader arming", "scripted");
        assert!(
            engine.counters.object_skips.is_empty(),
            "a generation the retained pin proves ended is not a lost one: {:?}",
            engine.counters.object_skips
        );
    }

    /// Task 9.2-fix5 item C. The scan owes an empty module an answer, but by
    /// capture end the same object can have a full table: SoftHSM2 builds its
    /// `CK_FUNCTION_LIST` at run time, and whether one scan pass of a live
    /// target sees it is a race. Measured on the healthy lane-16 shape
    /// (`run --pause auto -- hammer`): one run in eight published a second
    /// record, `function table unavailable in file-backed data`, beside 68
    /// table entries, 68 slots and 136/136 probes for that very object — every
    /// other counter identical to the seven clean runs.
    #[test]
    fn an_empty_scan_pass_is_not_a_loss_once_the_capture_attaches_that_table() {
        let mut plan = plan::build_from_reconciled_modules(&[]);
        plan.modules = vec![plan::ModuleSummary {
            id: plan::ModuleId(0),
            object: PinnedObjectId(42),
            key: ObjectKey {
                device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
                inode: 42,
            },
            path: "/opt/p11.so".into(),
            tables: vec![plan::TableSummary {
                version: (2, 40),
                entries: 68,
                source: "scan",
            }],
            interfaces: 0,
            source: "scan",
            corroborated: false,
            skipped: vec![],
        }];
        let empty_scan = |path: &str| Skipped {
            subject: path.into(),
            reason: "no function table was found in its file-backed data; a table built at \
                     run time in .bss or on the heap is outside the memory scan's reach"
                .into(),
        };
        let attached = empty_scan("/opt/p11.so");
        let never_attached = empty_scan("/opt/other.so");

        record_object_skips(&mut plan, &[attached.clone(), never_attached.clone()]);
        assert_eq!(
            plan.skipped,
            vec![never_attached.clone()],
            "a module this capture attached a table in has no empty scan to show; \
             one it never attached still does"
        );

        // …and the plan's skip list is only rebuilt when its sources are, so a
        // record an earlier batch made while the module was still empty has to
        // be re-judged, not just kept out.
        plan.skipped = vec![attached, never_attached.clone()];
        record_object_skips(&mut plan, &[]);
        assert_eq!(plan.skipped, vec![never_attached]);
    }

    /// A cgroup whose `cgroup.procs` names one process that no longer exists —
    /// what every inventory tick of a workload that forks per unit of work
    /// sees. `scope_pids` only reads the file, so a plain directory holding one
    /// is the whole scope.
    fn engine_over_cgroup_naming(pids: &[u32]) -> (Engine, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("a scope directory");
        let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
        std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
        let mut engine = Engine::empty();
        engine.scope = crate::scope::cgroup(dir.path()).expect("open scope directory");
        (engine, dir)
    }

    fn refresh_inventory_once(engine: &mut Engine) {
        let mut session = ScriptedSession::with_records([], 0);
        let mut collect: Box<DiscoveryCollector<'_>> = Box::new(Engine::collect_discovery_records);
        engine
            .refresh_inventory(
                &mut session,
                &mut true,
                &mut Vec::new(),
                &mut PendingViewRetirements::new(),
                &mut *collect,
                &mut PauseClosure::new(true),
            )
            .expect("an inventory refresh over a cgroup scope");
    }

    /// Task 9.2-fix5 item A. A `--cgroup` capture re-enumerates its members
    /// every tick, and a workload that forks one short-lived subprocess per
    /// unit of work leaves some of them gone before discovery can open or scan
    /// them. That is the ordinary end of a process, on the same authority
    /// `queue_retirement` and the fix4 record rule already use — not a
    /// discovery loss. Measured on the pkcs11-check `--isolation file` shape:
    /// five public `discovery unavailable` records, one per vanished pid.
    #[test]
    fn a_scope_member_that_ended_before_discovery_reached_it_is_not_a_loss() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        child.kill().unwrap();
        child.wait().unwrap();

        let (mut engine, _dir) = engine_over_cgroup_naming(&[pid]);
        refresh_inventory_once(&mut engine);

        let skips = engine.counters.object_skips.clone();
        assert!(
            skips.is_empty(),
            "a generation that is provably gone is not a discovery loss: {skips:?}"
        );
    }

    /// …and when its fate is *not* proven the loss stays loud — but as one
    /// record for the whole capture, not one per pid. The pid, the view and the
    /// error belong in the diagnostic; carrying them in the deduplicated
    /// `(subject, reason)` pair defeated `record_object_skips`'s own stated
    /// deduplication and made the published count track the workload's fork
    /// rate. Lane 11 published eleven of these on a capture an independent
    /// oracle proved complete.
    #[test]
    fn unreadable_scope_members_stay_loud_as_one_deduplicated_record() {
        let published: Vec<_> = [7u32, 9, 4242]
            .into_iter()
            .filter_map(|pid| unreadable_member_skip(pid, false, "scripted, unproven"))
            .collect();
        assert_eq!(published.len(), 3, "an unproven fate is never silent");

        let mut engine = Engine::empty();
        for skip in &published {
            engine.mark_partial(&skip.subject, &skip.reason);
        }
        assert_eq!(
            engine.counters.object_skips.len(),
            1,
            "three unreadable members are one loss, not three: {:?}",
            engine.counters.object_skips
        );
        assert_eq!(
            render::capture_skipped_out(&engine.counters.object_skips[0]).reason,
            "discovery unavailable"
        );
        assert!(
            unreadable_member_skip(11, true, "scripted, proven gone").is_none(),
            "a generation that is provably gone is the ordinary end of a process"
        );
    }

    #[test]
    fn scan_pin_diagnostics_escape_target_controls() {
        let message =
            format_discovery_skip("/opt/p\u{1b}[2Jevil\r.so", "scan failed: \u{1b}[31mboom\r");
        assert_eq!(
            message,
            r"p11scope: discovery skipped /opt/p\u{1b}[2Jevil\r.so — scan failed: \u{1b}[31mboom\r"
        );
        assert!(!message.contains('\u{1b}') && !message.contains('\r'));
    }

    #[test]
    fn unreadable_member_diagnostics_escape_target_controls() {
        let message = format_unreadable_member(4242, "detail: \u{1b}[2Jevil\r");
        assert_eq!(
            message,
            r"p11scope: discovery skipped pid 4242: detail: \u{1b}[2Jevil\r"
        );
        assert!(!message.contains('\u{1b}') && !message.contains('\r'));
    }

    #[test]
    fn module_refusal_diagnostics_escape_target_controls() {
        let message =
            format_module_refusal("/opt/p\u{1b}[2Jevil\r.so", "capacity: \u{1b}[31mboom\r");
        assert_eq!(
            message,
            r"p11scope: module refused: /opt/p\u{1b}[2Jevil\r.so — capacity: \u{1b}[31mboom\r"
        );
        assert!(!message.contains('\u{1b}') && !message.contains('\r'));
    }

    /// Task 9.2-fix5 item B, first half. The same `exec` transition, one step
    /// earlier: when the whole image is replaced the moved hook address often
    /// resolves to *no* mapping at all rather than to a moved one, so the
    /// record is rejected here instead of at the identity check — and this
    /// branch never learned what the identity branch already knows. Measured
    /// on `run --pause never -- env LD_PRELOAD=<provider> harness`: a second
    /// public `discovery unavailable` on a capture with 136/136 probes, 68
    /// slots and every counter clean, attributed to this exact site.
    #[test]
    fn a_loader_hit_unmapped_by_a_queued_exec_refresh_is_not_a_discovery_loss() {
        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        let armed = maps
            .iter()
            .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
            .expect("this process maps its own executable text")
            .clone();
        // Below `mmap_min_addr`: never mapped, so the hook address resolves to
        // nothing at all rather than to a moved mapping.
        let unmapped = 0x1000;
        assert!(
            !maps
                .iter()
                .any(|mapping| (mapping.start..mapping.end).contains(&unmapped)),
            "the null page is not mapped"
        );

        let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
        let mut record = loader_record_for(context, std::process::id());
        record.table_ptr = unmapped;
        let mut session = ScriptedSession::with_records([], 1);
        apply_ordinary_batch(&mut engine, &mut session, vec![record])
            .expect("an ordinary batch carrying one unmapped loader hit");

        let skips = engine.counters.object_skips.clone();
        assert!(
            skips
                .iter()
                .all(|skip| skip.subject != "live loader discovery"),
            "an exec this capture already queued a refresh for explains the vanished \
             mapping; the hit is rejected, not lost: {skips:?}"
        );
        let [_, _, _, truncated] = engine.capture_facts().discovery_losses();
        assert_eq!(
            truncated, 0,
            "the queued refresh rescans the view whole, so this rejection is \
             counted by nothing"
        );
    }

    /// …and the exec record does not have to have been *seen* yet. Measured on
    /// `run --pause auto -- env LD_PRELOAD=<provider> harness`: two loader hits
    /// sit ahead of the exec record in the same ring batch, so neither
    /// `pending_views` nor `refresh_requested` knows about the exec when they
    /// are resolved. The armed mapping being gone from a live image is proof
    /// enough on its own — only `exec` replaces an address space wholesale,
    /// and `sched_process_exec` is attached unconditionally.
    #[test]
    fn a_loader_hit_whose_armed_image_is_gone_is_not_a_discovery_loss() {
        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        let observed = maps
            .iter()
            .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
            .expect("this process maps its own executable text")
            .clone();
        let mut armed = observed.clone();
        armed.start -= 0x1000_0000;
        armed.end -= 0x1000_0000;

        let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
        // Neither channel knows about the exec yet: the record is still behind
        // this hit in the ring.
        engine.retirement_intents.clear();
        engine.refresh_requested.clear();
        let mut record = loader_record_for(context, std::process::id());
        record.table_ptr = 0x1000;
        let mut session = ScriptedSession::with_records([], 1);
        apply_ordinary_batch(&mut engine, &mut session, vec![record])
            .expect("an ordinary batch carrying one hit from a replaced image");

        let skips = engine.counters.object_skips.clone();
        assert!(
            skips
                .iter()
                .all(|skip| skip.subject != "live loader discovery"),
            "the armed mapping is gone from a live image, which only exec does: {skips:?}"
        );
    }

    /// fix5 review, finding 1. `refresh_requested` is not exec evidence: it is
    /// also filled by `GenerationLost`, and `refresh_inventory` *retains* it
    /// for every pid whose refresh failed, so on a live target whose refresh
    /// keeps failing it is sticky for the rest of the capture. Silencing a
    /// hit on it claims "the refresh rescans that view whole and re-arms it",
    /// which is exactly what did not happen. Only a context armed before its
    /// child exec'd has no mapping of its own to judge by.
    #[test]
    fn a_sticky_refresh_request_does_not_excuse_a_live_armed_mapping() {
        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        // Armed on a mapping this live image still holds: nothing about it says
        // `exec`.
        let armed = maps
            .iter()
            .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
            .expect("this process maps its own executable text")
            .clone();
        let pid = std::process::id();

        let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
        engine.retirement_intents.clear();
        engine.refresh_requested.insert(pid);
        let mut record = loader_record_for(context, pid);
        record.table_ptr = 0x1000;
        let mut session = ScriptedSession::with_records([], 1);
        apply_ordinary_batch(&mut engine, &mut session, vec![record])
            .expect("an ordinary batch carrying one unresolvable hit");

        let skips = engine.counters.object_skips.clone();
        assert!(
            skips
                .iter()
                .any(|skip| skip.subject == "live loader discovery"),
            "a stale refresh request is not proof that an exec replaced this image: {skips:?}"
        );
    }

    /// fix5 review, finding 2. fix4's identity branch excuses a moved mapping
    /// only while the exec that moved it is queued as this view's
    /// `ExecRefresh`. `same_object_remapped` already requires the mapping to
    /// have moved, so "the armed mapping is absent from the live image" is
    /// implied there and must not stand in for the queued refresh — that would
    /// make fix4's precondition vacuous. The controller's ruling is that fix4's
    /// decision stands.
    #[test]
    fn the_identity_branch_still_requires_a_queued_exec_refresh() {
        let maps = parse_maps(&std::fs::read("/proc/self/maps").unwrap()).unwrap();
        let observed = maps
            .iter()
            .find(|mapping| mapping.permissions[2] == b'x' && mapping.inode != 0)
            .expect("this process maps its own executable text")
            .clone();
        let mut armed = observed.clone();
        armed.start -= 0x1000_0000;
        armed.end -= 0x1000_0000;

        let (mut engine, context, _) = engine_with_exec_refreshed_loader(armed);
        // No exec queued and no request outstanding: the mapping moved for a
        // reason this capture cannot name.
        engine.retirement_intents.clear();
        engine.refresh_requested.clear();
        let mut record = loader_record_for(context, std::process::id());
        record.table_ptr = observed.start + 0x10;
        let mut session = ScriptedSession::with_records([], 1);
        apply_ordinary_batch(&mut engine, &mut session, vec![record])
            .expect("an ordinary batch carrying one remapped hit");

        let skips = engine.counters.object_skips.clone();
        assert!(
            skips
                .iter()
                .any(|skip| skip.subject == "live loader discovery"),
            "without a queued exec refresh a moved mapping is loss, as fix4 left it: {skips:?}"
        );
    }

    /// fix5 review, finding 3. The initial discovery pass has the same two
    /// producers `refresh_inventory` does, and they were left carrying the pid
    /// in their deduplication key and consulting no exit proof — so a
    /// `--cgroup` capture attached to an already-churning workload reproduces
    /// lane 11's multiplicity at capture start, before the live path ever runs.
    #[test]
    fn capture_start_members_that_ended_are_not_losses() {
        let pids: Vec<_> = (0..3)
            .map(|_| {
                let mut child = std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap();
                let pid = child.id();
                child.kill().unwrap();
                child.wait().unwrap();
                pid
            })
            .collect();
        let dir = tempfile::tempdir().expect("a scope directory");
        let listing: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
        std::fs::write(dir.path().join("cgroup.procs"), listing).expect("a cgroup.procs");
        let args = CaptureArgs {
            kind: crate::cli::Kind::Profile,
            modules: vec![],
            manifests: vec![],
            hooks: HookRegistry::builtin(),
            scope: crate::cli::ScopeArg::Cgroup(dir.path().to_path_buf()),
            metrics: false,
            duration: None,
            out: None,
            max_events: None,
            unsafe_requested: false,
        };
        let scope = crate::scope::cgroup(dir.path()).expect("open scope directory");

        let engine = Engine::discover(&args, &scope, None).expect("an empty cgroup still captures");

        assert!(
            engine.plan().skipped.is_empty(),
            "three members that ended before capture start are not three losses: {:?}",
            engine.plan().skipped
        );
    }

    /// Task 9.2b defect D, second half. A discovery record can only be resolved
    /// against the address space it came from, and a `--cgroup` capture's
    /// forked children make their calls and exit while their records are still
    /// queued. Every one of those then fails resolution with "process
    /// generation changed before target access" and publishes one public
    /// `discovery unavailable` — for the ordinary end of a process whose calls
    /// the attached probes already counted exactly.
    #[test]
    fn a_record_from_a_proven_exited_generation_is_not_a_discovery_loss() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let (mut engine, context) = Engine::retiring_loader_context(pid);
        // A cgroup capture continues when one member exits; the record its
        // exited member already queued is what this is about.
        let scope_dir = tempfile::tempdir().expect("a scope directory");
        engine.scope = crate::scope::cgroup(scope_dir.path()).expect("open scope directory");
        engine.retirement_intents.clear();
        child.kill().unwrap();
        child.wait().unwrap();

        // A loader record whose context is fine but whose address space is
        // gone: resolution reads `/proc/<pid>/maps` behind the retained pin.
        let mut session = ScriptedSession::with_records([], 1);
        apply_ordinary_batch(
            &mut engine,
            &mut session,
            vec![loader_record_for(context, pid)],
        )
        .expect("an ordinary batch carrying one unresolvable record");

        let skips = engine.counters.object_skips.clone();
        assert!(
            skips
                .iter()
                .all(|skip| skip.subject != "live discovery record"),
            "a generation the retained pin proves ended is not a lost one: {skips:?}"
        );
    }

    /// Task 9.2b defect E, first half. An `ExecRefresh` *keeps* its view: the
    /// refresh rescans that same live generation. Queuing it for the
    /// conservative retirement replay drops the view's pins, so the same
    /// provider is re-pinned under a fresh `PinnedObjectId`, a second full slot
    /// set is allocated for targets that already have one, and `additions
    /// allowed` is cleared so the replacement never attaches — 136 slots for a
    /// 68-entry table, and probes that count nothing.
    #[test]
    fn an_exec_refresh_never_queues_its_live_view_for_conservative_retirement() {
        let (mut engine, module, object, _) = engine_with_overlay(7);
        let pid = std::process::id();
        engine.scope = Scope::Pid(pid);
        engine
            .views
            .push(ProcessView::open(module.view, pid).unwrap());
        engine.next_view_id = module.view.0 + 1;
        engine
            .retirement_intents
            .insert(module.view, RetirementCause::ExecRefresh);
        assert_eq!(engine.plan.slots.len(), 1);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        let mut session = ScriptedSession::with_records([], 0);

        apply_ordinary_batch(&mut engine, &mut session, Vec::new())
            .expect("an ordinary retirement batch");

        assert!(
            engine
                .views
                .iter()
                .any(|retained| retained.id() == module.view),
            "an exec refresh keeps its process view"
        );
        assert!(
            engine.pinned.summary(object).is_some(),
            "a retained view keeps its pins; re-pinning the same object under a \
             fresh ID allocates a second slot set for targets that already have one"
        );
        assert_eq!(engine.plan.modules.len(), 1);
    }

    /// Task 9.2b defect E, second half, in the *capture* path this time.
    /// `fix1` taught `queue_retirement` that the retained original pin, not
    /// `still_the_same()`, decides whether a generation was lost or merely
    /// ended. `refresh_inventory` asks a weaker question — whether an
    /// `ExpectedRemoval` intent was already *recorded* — so a `run` child that
    /// exits before its `LEADER_EXIT` record is drained fails the whole
    /// capture with "the named process generation changed during capture".
    #[test]
    fn a_capture_refresh_ends_on_a_proven_exit_instead_of_failing() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let view = ProcessView::open(ProcessViewId(0), pid).unwrap();
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(pid);
        engine.views.push(view);
        engine.next_view_id = 1;
        child.kill().unwrap();
        child.wait().unwrap();

        let mut session = ScriptedSession::with_records([], 0);
        let mut collect: Box<DiscoveryCollector<'_>> = Box::new(Engine::collect_discovery_records);
        let outcome = engine.refresh_inventory(
            &mut session,
            &mut true,
            &mut Vec::new(),
            &mut PendingViewRetirements::new(),
            &mut *collect,
            &mut PauseClosure::new(true),
        );

        assert!(
            outcome.is_ok(),
            "a proven exit ends the capture, it does not discard it: {:?}",
            outcome.err()
        );
        assert!(engine.expected_target_exit());
    }

    /// Plan Task 8 Step 1 checkbox 8, deferred to Step 2 because it needs the
    /// crate-private `DiscoveryItem`/record path: strategy, timing, and
    /// capture counts deduplicate the exact internal
    /// `{process generation, optional bound tuple}` once, while `hits` and
    /// `state_read_failures` come only from their BPF counters and never from
    /// received-record counts.
    #[test]
    fn loader_counts_deduplicate_one_context_and_take_hits_only_from_bpf_counters() {
        let view = ProcessViewId(3);
        let mut engine = Engine::empty();

        // Same context, recorded on every tick of a live capture: one context,
        // one strategy count, one timing count, one capture count.
        for _ in 0..5 {
            engine.record_loader_arm(view, true);
        }
        let aggregate = engine.loader_discovery();
        assert_eq!(aggregate.strategies.unavailable, 1);
        assert_eq!(aggregate.initial_set_timing.none, 1);
        assert_eq!(aggregate.initial_set_capture.none, 1);
        assert_eq!(aggregate.initial_set_capture.eligible, 0);
        assert_eq!(aggregate.dlopen_timing, render::LoaderTiming::default());

        // A second exact process generation is a second context.
        engine.record_loader_arm(ProcessViewId(4), false);
        let aggregate = engine.loader_discovery();
        assert_eq!(aggregate.strategies.unavailable, 2);
        assert_eq!(aggregate.dlopen_timing.none, 1);
        assert_eq!(
            aggregate.initial_set_capture.none, 1,
            "an ordinary dlopen context is not a second initial-set capture"
        );

        // Records are not counts. Dispatching loader records moves neither
        // `hits` nor `state_read_failures`; only the BPF producer counters do.
        engine.loader_records_accepted = 9;
        assert_eq!(engine.loader_discovery().hits, 0);
        assert_eq!(engine.loader_discovery().state_read_failures, 0);
        engine.counter_snapshot.loader_hits = 7;
        engine.counter_snapshot.loader_state_read_failures = 2;
        let aggregate = engine.loader_discovery();
        assert_eq!(aggregate.hits, 7);
        assert_eq!(aggregate.state_read_failures, 2);
        assert_eq!(
            aggregate.strategies.unavailable, 2,
            "a producer counter is not a classification"
        );

        // `capture_facts()` publishes the BPF-owned discovery losses verbatim
        // and derives the truncation accumulator, never a second copy of the
        // loader state-read counter.
        engine.counter_snapshot.ring_loss = 4;
        engine.counter_snapshot.export_state_failures = 5;
        engine.counter_snapshot.export_bounded_read_failures = 6;
        engine.discovery_truncated = 1;
        engine.malformed_discovery = 2;
        let facts = engine.capture_facts();
        assert_eq!(facts.discovery_losses(), [4, 5, 6, 3]);
        assert_eq!(
            facts.attach_gap_ms(),
            None,
            "an unmeasured gap is never zero"
        );
    }

    #[test]
    fn loader_counts_deduplicate_replaced_context_by_stable_bound_tuple() {
        use p11scope_manifest::elf::SymbolFact;

        let view = ProcessViewId(5);
        let module = overlay_module(overlay_key(105));
        let pins = overlay_pins(&[(module.key, OVERLAY_SHA, 1)]);
        let loader = pins
            .id_for_scanned(&module, module.key, &module.path)
            .unwrap();
        let mut engine = Engine::empty();
        engine.pinned = pins;
        let spec = LoaderContextSpec {
            view,
            loader,
            mapping: Some(MapEntry {
                start: 0x4000,
                end: 0x5000,
                file_offset: 0x2000,
                permissions: *b"r-xp",
                device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
                inode: 7,
                raw_path: Some(b"/lib/ld.so".to_vec()),
            }),
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state: None,
        };

        let first = engine.loader_registry.preflight(spec.clone()).unwrap();
        let first = engine.loader_registry.prepare(first).unwrap();
        engine.loader_registry.mark_attached(first).unwrap();
        engine.record_loader_arm(view, false);
        engine.loader_registry.tombstone(first).unwrap();
        engine.loader_registry.remove(first).unwrap();

        let replacement = engine.loader_registry.preflight(spec.clone()).unwrap();
        let replacement = engine.loader_registry.prepare(replacement).unwrap();
        engine.loader_registry.mark_attached(replacement).unwrap();
        engine.record_loader_arm(view, false);

        let aggregate = engine.loader_discovery();
        assert_eq!(aggregate.strategies.debug_state_every_hit, 1);
        assert_eq!(aggregate.dlopen_timing.unproven, 1);
        assert_eq!(
            aggregate.initial_set_timing,
            render::LoaderTiming::default()
        );
        assert_eq!(
            aggregate.initial_set_capture,
            render::InitialSetCapture::default()
        );

        engine.loader_registry.tombstone(replacement).unwrap();
        engine.loader_registry.remove(replacement).unwrap();
        let initial_set = engine.loader_registry.preflight(spec).unwrap();
        let initial_set = engine.loader_registry.prepare(initial_set).unwrap();
        engine.loader_registry.mark_attached(initial_set).unwrap();
        engine.record_loader_arm(view, true);

        let aggregate = engine.loader_discovery();
        assert_eq!(aggregate.strategies.debug_state_every_hit, 2);
        assert_eq!(aggregate.dlopen_timing.unproven, 1);
        assert_eq!(aggregate.initial_set_timing.unproven, 1);
        assert_eq!(aggregate.initial_set_capture.none, 1);
    }

    #[test]
    fn loader_counts_distinguish_unbound_and_unkeyed_contexts() {
        use p11scope_manifest::elf::SymbolFact;

        let view = ProcessViewId(6);
        let mut engine = Engine::empty();
        engine.record_loader_arm(view, false);
        let spec = LoaderContextSpec {
            view,
            loader: PinnedObjectId(9),
            mapping: Some(MapEntry {
                start: 0x4000,
                end: 0x5000,
                file_offset: 0x2000,
                permissions: *b"r-xp",
                device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
                inode: 7,
                raw_path: Some(b"/lib/ld.so".to_vec()),
            }),
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            state: None,
        };
        let first = engine.loader_registry.preflight(spec.clone()).unwrap();
        let first = engine.loader_registry.prepare(first).unwrap();
        engine.loader_registry.mark_attached(first).unwrap();
        engine.record_loader_arm(view, false);
        engine.record_loader_arm(view, false);

        let aggregate = engine.loader_discovery();
        assert_eq!(aggregate.strategies.unavailable, 1);
        assert_eq!(aggregate.strategies.debug_state_every_hit, 1);
        assert_eq!(aggregate.dlopen_timing.unproven, 1);
        assert_eq!(engine.counters.object_skips.len(), 1);
        assert_eq!(
            render::capture_skipped_out(&engine.counters.object_skips[0]).reason,
            "discovery unavailable"
        );

        engine.loader_registry.tombstone(first).unwrap();
        engine.loader_registry.remove(first).unwrap();
        let replacement = engine.loader_registry.preflight(spec).unwrap();
        let replacement = engine.loader_registry.prepare(replacement).unwrap();
        engine.loader_registry.mark_attached(replacement).unwrap();
        engine.record_loader_arm(view, false);

        let aggregate = engine.loader_discovery();
        assert_eq!(aggregate.strategies.unavailable, 1);
        assert_eq!(aggregate.strategies.debug_state_every_hit, 2);
        assert_eq!(aggregate.dlopen_timing.unproven, 2);
        assert_eq!(engine.counters.object_skips.len(), 1);
    }

    /// Plan Task 8 Step 2: a named target's expected exit is what ends the
    /// capture the ordinary way, with no interrupt and no `--duration`. A
    /// cgroup capture never reaches that state when one member exits — it
    /// stops only by its normal capture policy — and the asymmetry lives in
    /// exactly one place: only `Scope::Pid` arms the pending marker.
    #[test]
    fn only_a_named_targets_expected_exit_finishes_the_capture() {
        let view = ProcessViewId(21);

        let mut named = Engine::empty();
        named.scope = Scope::Pid(1);
        assert!(!named.expected_target_exit(), "nothing has exited yet");
        named.arm_expected_target_exit(view);
        named.finalize_expected_target_exit();
        assert!(
            named.expected_target_exit(),
            "a named target's expected exit must end the capture"
        );

        let mut cgroup = Engine::empty();
        let cgroup_dir = tempfile::tempdir().expect("a scope directory");
        cgroup.scope = crate::scope::cgroup(cgroup_dir.path()).expect("open scope directory");
        cgroup.arm_expected_target_exit(view);
        cgroup.finalize_expected_target_exit();
        assert!(
            !cgroup.expected_target_exit(),
            "one cgroup member exiting must not end a cgroup capture"
        );
    }

    #[test]
    fn expected_target_exit_completes_only_after_conservative_cleanup() {
        let view = ProcessViewId(17);
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(1);
        engine.expected_target_exit_pending = Some(view);
        engine.pending_retirements.insert(view);

        engine.finalize_expected_target_exit();
        assert!(!engine.expected_target_exit);
        assert_eq!(engine.expected_target_exit_pending, Some(view));

        engine.pending_retirements.clear();
        let owner = LoaderContextId::from_case_id(1);
        let journal = TerminalJournal {
            owner,
            dispatch_started: false,
            retry_used: false,
        };
        let batch = TerminalBatch::empty(TerminalAuthority {
            owner,
            exports: Vec::new(),
        });

        // Every terminal-journal state blocks finalization on its own: an
        // undispatched batch, a started journal with no batch, and both.
        for (pending_journal, pending_batch) in [
            (Some(journal), None),
            (
                None,
                Some(TerminalBatch::empty(TerminalAuthority {
                    owner,
                    exports: Vec::new(),
                })),
            ),
            (Some(journal), Some(batch)),
            (
                Some(TerminalJournal {
                    dispatch_started: true,
                    ..journal
                }),
                None,
            ),
        ] {
            engine.terminal_journal = pending_journal;
            engine.terminal_batch = pending_batch;
            engine.finalize_expected_target_exit();
            assert!(
                !engine.expected_target_exit,
                "a pending terminal lifecycle state cannot prove expected exit"
            );
            assert_eq!(engine.expected_target_exit_pending, Some(view));
        }

        engine.terminal_batch = None;
        engine.terminal_journal = None;
        engine.finalize_expected_target_exit();
        assert!(engine.expected_target_exit);
        assert_eq!(engine.expected_target_exit_pending, None);
    }

    /// The tombstoned registry context a real terminal drain leaves behind is
    /// carried through detach and return: finalization stays blocked until the
    /// continuation removes it.
    #[test]
    fn a_real_terminal_drain_blocks_expected_exit_until_its_journal_clears() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let view = engine.views[0].id();
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        start_failed_terminal_drain(&mut engine, &mut session, owner);

        let retained = std::mem::take(&mut engine.views);
        let intents = std::mem::take(&mut engine.retirement_intents);
        engine.expected_target_exit_pending = Some(view);
        engine.finalize_expected_target_exit();

        assert!(
            !engine.expected_target_exit,
            "a tombstoned context with an undispatched batch is not a clean exit"
        );
        assert_eq!(
            engine.loader_context_state_for_test(owner),
            Some("tombstoned")
        );

        engine.views = retained;
        engine.retirement_intents = intents;
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert!(engine.terminal_journal.is_none());
        assert!(engine.loader_registry.context(owner).is_none());
        engine.views.clear();
        engine.retirement_intents.clear();
        engine.pending_retirements.clear();
        engine.finalize_expected_target_exit();
        assert!(engine.expected_target_exit);
    }

    #[test]
    fn delayed_pre_admission_exec_cannot_refresh_a_reused_pid() {
        let view = ProcessView::open(ProcessViewId(16), std::process::id()).unwrap();
        let mut delayed: DiscoveryRecord = unsafe { std::mem::zeroed() };
        delayed.kind = DISCOVERY_KIND_EXEC;
        delayed.pid_tgid = u64::from(view.pid()) << 32;
        delayed.hook_ts_ns = view.admitted_ns().saturating_sub(1);
        let mut engine = Engine::empty();
        engine.views.push(view);
        let mut pending = PendingViewRetirements::new();

        engine.dispatch_lifecycle_record(&delayed, &mut pending);

        assert!(pending.is_empty());
        assert!(!engine.refresh_requested.contains(&std::process::id()));
    }

    #[test]
    fn only_complete_cgroup_enumeration_authorizes_absence() {
        assert_eq!(
            inventory_retirement_cause(true, true, false, false),
            Some((RetirementCause::ExpectedRemoval, true))
        );
        assert_eq!(
            inventory_retirement_cause(false, true, false, false),
            Some((RetirementCause::ExpectedRemoval, true)),
            "authoritative absence proves clean departure even after the process exited"
        );
        assert_eq!(
            inventory_retirement_cause(true, false, false, false),
            None,
            "unreadable or truncated membership cannot prove departure"
        );
        assert_eq!(
            inventory_retirement_cause(false, false, false, false),
            Some((RetirementCause::GenerationLost, false)),
            "an independently stale retained pin remains genuine loss"
        );
        assert_eq!(
            inventory_retirement_cause(true, false, true, true),
            Some((RetirementCause::ExecRefresh, false))
        );
    }

    #[test]
    fn cgroup_departure_is_journaled_before_fallible_retirement() {
        let view = ProcessView::open(ProcessViewId(20), std::process::id()).unwrap();
        let mut engine = Engine::empty();
        engine.views.push(view);
        let retirement_views = [ProcessViewId(20)].into_iter().collect();
        let departed = [ProcessViewId(20)].into_iter().collect();
        let mut pending = PendingViewRetirements::new();

        engine.queue_inventory_retirements(
            &retirement_views,
            &BTreeSet::new(),
            &departed,
            &mut pending,
        );

        assert_eq!(
            engine.retirement_intents.get(&ProcessViewId(20)),
            Some(&RetirementCause::ExpectedRemoval)
        );
        assert!(engine.ready_expected_removals.contains(&ProcessViewId(20)));
        assert!(!engine.refresh_requested.contains(&std::process::id()));
        pending.clear();
        assert_eq!(
            engine.retirement_intents.get(&ProcessViewId(20)),
            Some(&RetirementCause::ExpectedRemoval),
            "an unconsumed drain retry keeps the selected exact view"
        );

        let source = include_str!("engine.rs");
        let refresh = source
            .split_once("    fn refresh_inventory(")
            .unwrap()
            .1
            .split_once("    /// Drains private discovery records")
            .unwrap()
            .0;
        assert!(
            refresh.find("self.queue_inventory_retirements(").unwrap()
                < refresh.find("self.retire_loader_contexts(").unwrap()
        );
    }

    #[test]
    fn cgroup_walk_does_not_silently_drop_directory_entry_errors() {
        let source = include_str!("engine.rs");
        let walk = source
            .split_once("fn scope_pids(")
            .unwrap()
            .1
            .split_once("fn scope_label(")
            .unwrap()
            .0;

        assert!(!walk.contains("entries.flatten()"));
        assert!(!walk.contains("file_type().is_ok_and"));
        assert!(walk.contains("membership absence is not authoritative"));
    }

    #[test]
    fn retirement_intent_is_persistent_and_generation_loss_is_sticky() {
        let view = ProcessView::open(ProcessViewId(15), std::process::id()).unwrap();
        let mut engine = lifecycle_discovered(vec![view]);
        let mut pending = PendingViewRetirements::new();

        engine.queue_retirement(
            ProcessViewId(15),
            RetirementCause::ExecRefresh,
            &mut pending,
        );
        engine.queue_retirement(
            ProcessViewId(15),
            RetirementCause::ExpectedRemoval,
            &mut pending,
        );
        engine.queue_retirement(
            ProcessViewId(15),
            RetirementCause::GenerationLost,
            &mut pending,
        );

        assert_eq!(
            engine.retirement_intents.get(&ProcessViewId(15)),
            Some(&RetirementCause::GenerationLost)
        );
        assert_eq!(
            pending.get(&ProcessViewId(15)),
            Some(&RetirementCause::GenerationLost)
        );
        assert!(engine.refresh_requested.contains(&std::process::id()));
        assert_eq!(
            engine
                .counters
                .object_skips
                .iter()
                .filter(|skip| skip.subject == "live discovery generation")
                .count(),
            1,
            "the sticky loss is published once"
        );
    }

    #[test]
    fn expected_exit_waits_for_the_original_process_pin() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let view = ProcessView::open(ProcessViewId(16), child.id()).unwrap();
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_LEADER_EXIT;
        record.pid_tgid = u64::from(child.id()) << 32;
        record.hook_ts_ns = view.admitted_ns();
        let mut engine = Engine::empty();
        engine.views.push(view);
        let mut pending = PendingViewRetirements::new();
        engine.dispatch_lifecycle_record(&record, &mut pending);

        assert_eq!(
            pending.get(&ProcessViewId(16)),
            Some(&RetirementCause::ExpectedRemoval)
        );
        assert!(!retirement_ready(RetirementCause::ExpectedRemoval, &engine.views[0]).unwrap());

        child.kill().unwrap();
        child.wait().unwrap();
        assert!(retirement_ready(RetirementCause::ExpectedRemoval, &engine.views[0]).unwrap());
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
            disposition: ApplyDisposition::Accepted,
            changed: true,
            stale_views: [stale].into_iter().collect(),
            missing_contexts: Vec::new(),
            static_completions: vec![([completed.clone()].into_iter().collect(), Some(20))],
            static_failures: [failed.clone()].into_iter().collect(),
            newly_rejected_keys: BTreeSet::new(),
            selection_authorized: false,
        };

        engine.record_apply_timing(&outcome);

        assert_eq!(engine.timings.gap_ns(&completed), Some(10));
        assert_eq!(engine.timings.gap_ns(&failed), None);
        assert_eq!(outcome.stale_views, [stale].into_iter().collect());
        assert!(outcome.accepted() && outcome.changed);
    }

    /// One provider module over a real file-backed mapping of `view`. The
    /// table is synthetic; the identity, the pin, and the process view are all
    /// real, which is what the transaction path is about.
    fn provider_module(
        view: &ProcessView,
        mapping: &MapEntry,
        path: &Path,
        offset: u64,
    ) -> ScannedModule {
        let mut module = mapped_object(view, mapping, path);
        module.exports = vec!["C_GetFunctionList".into()];
        module.tables = vec![ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name: "C_Initialize",
                object: module.key,
                object_path: module.path.clone(),
                file_offset: offset,
            }],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7000,
            file_offset: Some(0),
        }];
        module
    }

    struct LoadedSeedProvider {
        child: std::process::Child,
        peers: Vec<std::process::Child>,
        _dir: tempfile::TempDir,
    }

    impl Drop for LoadedSeedProvider {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            for peer in &mut self.peers {
                let _ = peer.kill();
                let _ = peer.wait();
            }
        }
    }

    impl LoadedSeedProvider {
        fn spawn_peer(&mut self) -> u32 {
            let child = std::process::Command::new(self._dir.path().join("seed-runner"))
                .arg(self._dir.path().join("seed-provider.so"))
                .spawn()
                .unwrap();
            let pid = child.id();
            self.peers.push(child);
            pid
        }
    }

    fn loaded_seed_provider() -> (
        LoadedSeedProvider,
        ProcessView,
        ScannedModule,
        PinnedObjects,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let library = dir.path().join("seed-provider.so");
        let source = dir.path().join("seed-provider.c");
        let runner_source = dir.path().join("seed-runner.c");
        let runner = dir.path().join("seed-runner");
        std::fs::write(
            &source,
            r#"
#include <stddef.h>
__attribute__((visibility("default"), noinline))
int C_GetFunctionList(void **out) {
    if (out != NULL) *out = NULL;
    return 0;
}
__attribute__((visibility("default"), noinline))
int C_GetInterfaceList(void *out, unsigned long *count) {
    if (out != NULL) *(void **)out = NULL;
    if (count != NULL) *count = 0;
    return 0;
}
__attribute__((visibility("default"), noinline))
int C_GetInterface(const char *name, void *version, void **out, unsigned long flags) {
    (void)name;
    (void)version;
    (void)flags;
    if (out != NULL) *out = NULL;
    return 0;
}
"#,
        )
        .unwrap();
        assert!(
            std::process::Command::new("gcc")
                .args(["-shared", "-fPIC", "-o"])
                .arg(&library)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(
            &runner_source,
            r#"
#include <dlfcn.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) return 3;
    sleep(30);
    dlclose(handle);
    return 0;
}
"#,
        )
        .unwrap();
        assert!(
            std::process::Command::new("gcc")
                .args(["-o"])
                .arg(&runner)
                .arg(&runner_source)
                .arg("-ldl")
                .status()
                .unwrap()
                .success()
        );
        let child = std::process::Command::new(&runner)
            .arg(&library)
            .spawn()
            .unwrap();
        let fixture = LoadedSeedProvider {
            child,
            peers: Vec::new(),
            _dir: dir,
        };
        let view = ProcessView::open(ProcessViewId(0), fixture.child.id()).unwrap();
        let mut mapped = None;
        for _ in 0..200 {
            let maps =
                parse_maps(&std::fs::read(format!("/proc/{}/maps", fixture.child.id())).unwrap())
                    .unwrap();
            mapped = maps
                .iter()
                .find_map(|mapping| match resolve(&maps, mapping.start) {
                    Resolved::File {
                        path: MappedPath::Usable(path),
                        ..
                    } if path == library => Some((mapping.clone(), path)),
                    _ => None,
                });
            if mapped.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let (mapping, mapped_path) = mapped.expect("the loaded seed provider is mapped");
        let mut module = mapped_object(&view, &mapping, &mapped_path);
        module.exports = vec!["C_GetFunctionList".into()];
        let pins = pin_test_module(&view, &module);
        (fixture, view, module, pins)
    }

    fn initial_export_route() -> (LoadedSeedProvider, Engine, ScriptedSession) {
        let (fixture, view, mut module, pins) = loaded_seed_provider();
        let pid = view.pid();
        module.exports = vec![
            "C_GetFunctionList".into(),
            "C_GetInterfaceList".into(),
            "C_GetInterface".into(),
        ];
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(pid);
        engine.next_view_id = 1;
        engine.views.push(view);
        let candidate = engine
            .live_candidate(pins, vec![module], Vec::new())
            .unwrap();
        let mut session = ScriptedSession::default();
        let mut additions_allowed = true;
        let outcome = engine
            .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
            .unwrap();
        assert!(outcome.accepted());
        engine
            .arm_loader_or_partial(
                0,
                &mut session,
                &mut additions_allowed,
                &mut PendingViewRetirements::new(),
            )
            .unwrap();
        assert!(additions_allowed);
        (fixture, engine, session)
    }

    fn attached_selection_route() -> (
        LoadedSeedProvider,
        Engine,
        ScriptedSession,
        SelectionBindingFact,
    ) {
        let (fixture, mut engine, mut session) = initial_export_route();
        session.dynamic_attach_reports_added = true;
        engine.attach_initial_exports(
            &mut session,
            &mut true,
            &mut PendingViewRetirements::new(),
            &mut PauseClosure::new(true),
        );
        let binding = *engine.selection_bindings.values().next().unwrap();
        (fixture, engine, session, binding)
    }

    fn selection_only_table(
        engine: &Engine,
        binding: SelectionBindingFact,
        table_file_offset: u64,
        entries: &[(&'static str, u64)],
        null_entries: Vec<&'static str>,
    ) -> ScannedTable {
        let summary = engine.pinned.summary(binding.object).unwrap();
        let path = engine
            .modules
            .iter()
            .find(|module| module.object == binding.object)
            .unwrap()
            .scanned
            .path
            .clone();
        ScannedTable {
            version: (3, 0),
            walk: "full",
            entries: entries
                .iter()
                .map(|(name, file_offset)| ScannedEntry {
                    name,
                    object: summary.key,
                    object_path: path.clone(),
                    file_offset: *file_offset,
                })
                .collect(),
            null_entries,
            unpinned: Vec::new(),
            address: 0,
            file_offset: Some(table_file_offset),
        }
    }

    fn manifest_selection_evidence(
        version: Version,
        resolved: &[(&str, u64)],
    ) -> p11scope_manifest::manifest::SelectionEvidence {
        use p11scope_manifest::manifest::{
            SelectionAcquisition, SelectionAuthority, SelectionEvidence, SelectionNameClass,
            SelectionQuery, SelectionRequest, SelectionTable, SelectionVersionClass,
        };

        let functions = pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
            .chain(
                (version.minor == 2)
                    .then_some(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
                    .into_iter()
                    .flatten(),
            )
            .map(|field| FunctionRecord {
                name: field.name.into(),
                resolution: resolved
                    .iter()
                    .find(|(name, _)| *name == field.name)
                    .map_or(Resolution::NullPointer, |(_, file_offset)| {
                        Resolution::Resolved {
                            object: 0,
                            file_offset: *file_offset,
                        }
                    }),
            })
            .collect();
        let mut queries = Vec::new();
        for selector in 0..5 {
            for flags in 0..=1 {
                let (name, result_version) = match selector {
                    0 => (SelectionNameClass::Null, SelectionVersionClass::Null),
                    1 => (
                        SelectionNameClass::ExactStandard,
                        SelectionVersionClass::Null,
                    ),
                    2 => (
                        SelectionNameClass::ExactStandard,
                        SelectionVersionClass::V3_0,
                    ),
                    3 => (
                        SelectionNameClass::ExactStandard,
                        SelectionVersionClass::V3_1,
                    ),
                    _ => (
                        SelectionNameClass::ExactStandard,
                        SelectionVersionClass::V3_2,
                    ),
                };
                let request = SelectionRequest {
                    name,
                    version: result_version,
                    flags,
                };
                queries.push(
                    if selector == version.minor.saturating_add(2) && flags == 0 {
                        SelectionQuery {
                            selector,
                            request,
                            rv: 0,
                            result: Some(request),
                            inventory_matches: Vec::new(),
                            selection_table: Some(0),
                            authority: SelectionAuthority::SelectionCountOnly,
                            helper_failure: None,
                        }
                    } else {
                        SelectionQuery {
                            selector,
                            request,
                            rv: 1,
                            result: None,
                            inventory_matches: Vec::new(),
                            selection_table: None,
                            authority: SelectionAuthority::None,
                            helper_failure: None,
                        }
                    },
                );
            }
        }
        SelectionEvidence {
            acquisition: SelectionAcquisition::Queried,
            queries,
            tables: vec![SelectionTable {
                id: 0,
                version,
                walk: WalkOutcome::Full,
                functions,
                semantic_authorized: false,
            }],
            selection_truncated: false,
        }
    }

    fn evidence_verdict(
        plan: &plan::AttachPlan,
        pinned: &PinnedObjects,
        counters: &DiscoveryCounters,
    ) -> render::Evidence {
        let mut evidence = render::Evidence {
            table_entries: plan.entries_seen,
            slots: plan.slots.len(),
            attached_probes: 0,
            attach_failures: Vec::new(),
            aliased: plan
                .slots
                .iter()
                .filter(|slot| slot.aliased)
                .map(|slot| slot.names.clone())
                .collect(),
            skipped: plan
                .skipped
                .iter()
                .map(render::capture_skipped_out)
                .collect(),
            semantic_unverified_slots: plan
                .slots
                .iter()
                .filter(|slot| !slot.semantic_authorized)
                .count(),
            in_flight_at_end: 0,
            surfaces: plan.surfaces.clone(),
            vendor_interfaces: plan.vendor_interfaces,
            interface_list: plan.interface_list.clone(),
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
            attach_gap_ms: None,
            pause: "none",
            pause_attempts: 0,
            pause_confirmed: 0,
            pause_partial: 0,
            child_still_running: None,
            discovery_ring_loss: 0,
            discovery_state_failures: 0,
            discovery_read_failures: 0,
            discovery_truncated: 0,
            loader_discovery: render::LoaderDiscovery::default(),
            unprotected_live_windows: 0,
            module_unresolved_slots: 0,
            provider_changed: false,
            discovery: discovery_evidence(plan, pinned, counters),
            completeness: "UNKNOWN",
        };
        evidence.verdict();
        evidence
    }

    #[test]
    fn manifest_selection_tables_enter_the_attach_transaction() {
        let (_fixture, view, mut module, mut pins) = loaded_seed_provider();
        let provider = pins.pinned().next().unwrap();
        let path = provider.path.to_string();
        let base = object_facts(Path::new(&path)).2;
        module.tables.push(ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name: "C_Initialize",
                object: provider.key,
                object_path: path.clone(),
                file_offset: base,
            }],
            null_entries: Vec::new(),
            unpinned: Vec::new(),
            address: 0,
            file_offset: Some(base),
        });

        let mut manifest = valid_manifest_for(&[PathBuf::from(&path)], &[0; 67]);
        for (index, function) in manifest.surfaces[0].functions.iter_mut().enumerate() {
            function.resolution = Resolution::Resolved {
                object: 0,
                file_offset: base + index as u64,
            };
        }
        let manifest_pins = pin_manifest_objects(&manifest).unwrap();
        assert!(pins.absorb(manifest_pins).is_empty());

        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(view.pid());
        engine.next_view_id = 1;
        engine.views.push(view);
        engine.manifests.push(manifest.clone());
        engine.manifest_ordinals.push(0);
        let mut session = ScriptedSession::default();
        let initial = engine
            .live_candidate(pins, vec![module.clone()], Vec::new())
            .unwrap();
        engine
            .apply_candidate(&mut session, initial, &mut true, false, &[])
            .unwrap();
        let inventory = engine
            .plan
            .slots
            .iter()
            .find(|slot| slot.file_offset == base)
            .unwrap()
            .clone();
        let inventory_tables = engine.plan.modules[0].tables.clone();
        let extra = base + 80;

        let mut selection = manifest_selection_evidence(
            Version { major: 3, minor: 0 },
            &[
                ("C_Finalize", base),
                ("C_GetInfo", extra),
                ("C_GetSlotList", extra + 1),
                ("C_GetMechanismList", extra + 2),
            ],
        );
        let mut survivor = manifest_selection_evidence(
            Version { major: 3, minor: 1 },
            &[("C_GetInfo", base), ("C_GetSlotList", extra)],
        );
        survivor.tables[0].id = 1;
        for query in &mut survivor.queries {
            if query.selection_table.is_some() {
                query.selection_table = Some(1);
            }
        }
        let survivor_query = survivor
            .queries
            .into_iter()
            .find(|query| query.selection_table == Some(1))
            .unwrap();
        let survivor_key = (survivor_query.selector, survivor_query.request.flags);
        *selection
            .queries
            .iter_mut()
            .find(|query| (query.selector, query.request.flags) == survivor_key)
            .unwrap() = survivor_query;
        selection.tables.push(survivor.tables.pop().unwrap());
        manifest.selection_evidence = selection;
        let problems = crate::manifest_input::validate_structure(&manifest);
        assert!(problems.is_empty(), "{problems:?}");
        engine.manifests[0] = manifest;
        let candidate = engine
            .live_candidate(engine.pinned.clone(), vec![module], Vec::new())
            .unwrap();

        assert_eq!(candidate.delta.new.len(), 3, "null entries do not attach");
        assert_eq!(
            candidate
                .plan
                .slots
                .iter()
                .filter(|slot| slot.file_offset == base)
                .count(),
            1,
            "inventory and selection share one physical slot"
        );
        for slot in candidate.plan.slots.iter().filter(
            |slot| matches!(slot.file_offset, offset if offset >= extra && offset <= extra + 2),
        ) {
            assert_eq!(
                slot.semantics,
                p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
            );
            assert!(!slot.semantic_authorized);
        }
        assert_eq!(candidate.plan.modules[0].tables, inventory_tables);
        let evidence = evidence_verdict(&candidate.plan, &candidate.pinned, &engine.counters);
        assert!(evidence.semantic_unverified_slots > 0);
        assert_eq!(
            serde_json::to_value(&evidence).unwrap()["completeness"],
            "PARTIAL"
        );

        let earlier = candidate
            .delta
            .new
            .iter()
            .find(|slot| slot.file_offset == extra + 1)
            .unwrap()
            .index;
        let later = candidate
            .delta
            .new
            .iter()
            .find(|slot| slot.file_offset == extra + 2)
            .unwrap()
            .index;
        assert_ne!(earlier, later);
        session.fail_target_slots([later]);
        engine
            .apply_candidate(&mut session, candidate, &mut true, false, &[])
            .unwrap();

        assert_eq!(
            engine
                .plan
                .slots
                .iter()
                .find(|slot| slot.file_offset == base)
                .unwrap(),
            &plan::Slot {
                names: vec!["C_GetInfo".into(), "C_Initialize".into()],
                aliased: true,
                ..inventory
            },
            "rollback removes only the failed manifest alias from inventory"
        );
        let shared = engine
            .plan
            .slots
            .iter()
            .find(|slot| slot.file_offset == extra)
            .unwrap();
        assert!(engine.plan.is_active(shared.index));
        assert_eq!(shared.names, ["C_GetSlotList"]);
        assert!(
            engine
                .plan
                .slots
                .iter()
                .filter(|slot| matches!(slot.file_offset, offset if offset == extra + 1 || offset == extra + 2))
                .all(|slot| !engine.plan.is_active(slot.index)),
            "a later failure rolls back the successful selection-only prefix"
        );
        assert_eq!(session.detached_slots.last(), Some(&1));
        assert_eq!(session.attached_slots.last(), Some(&3));
        let evidence = evidence_verdict(&engine.plan, &engine.pinned, &engine.counters);
        assert_eq!(
            serde_json::to_value(&evidence).unwrap()["completeness"],
            "PARTIAL"
        );
        assert!(
            engine
                .plan
                .skipped
                .iter()
                .any(|skip| skip.subject == "offline interface selection")
        );
    }

    #[test]
    fn manifest_selection_tables_lower_during_initial_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let base = object_facts(&provider).2;
        let mut manifest = valid_manifest_for(std::slice::from_ref(&provider), &[0; 67]);
        manifest.selection_evidence = manifest_selection_evidence(
            Version { major: 3, minor: 0 },
            &[("C_GetInfo", base + 80)],
        );
        let problems = crate::manifest_input::validate_structure(&manifest);
        assert!(problems.is_empty(), "{problems:?}");

        let mut discovered = lifecycle_discovered(Vec::new());
        discovered
            .manifest_inputs
            .push(manifest_input_from_pinning("initial.json", manifest));
        rebuild_discovered(&mut discovered).unwrap();

        let slot = discovered
            .plan
            .slots
            .iter()
            .find(|slot| slot.file_offset == base + 80)
            .expect("initial manifest selection target enters the starting plan");
        assert_eq!(
            slot.semantics,
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        assert!(!slot.semantic_authorized);
        assert_eq!(discovered.plan.modules[0].tables.len(), 1);
    }

    #[test]
    fn manifest_selection_table_without_a_candidate_provider_adds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let base = object_facts(&provider).2;
        let mut manifest = valid_manifest_for(std::slice::from_ref(&provider), &[0; 67]);
        manifest.selection_evidence = manifest_selection_evidence(
            Version { major: 3, minor: 0 },
            &[("C_GetInfo", base + 80)],
        );
        let problems = crate::manifest_input::validate_structure(&manifest);
        assert!(problems.is_empty(), "{problems:?}");
        let pins = pin_manifest_objects(&manifest).unwrap();
        let mut plan = plan::build_from_reconciled_modules(&[]);
        let allocated = plan.clone();

        let (admissions, refused) = lower_manifest_selection_tables(
            &mut plan,
            &allocated,
            std::slice::from_ref(&manifest),
            &[0],
            &pins,
        );

        assert!(admissions.is_empty());
        assert!(refused.is_empty());
        assert!(plan.slots.is_empty());
    }

    #[test]
    fn stale_manifest_selection_does_not_transfer_to_scan_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let base = object_facts(&provider).2;
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let mut manifest = valid_manifest_for(&paths, &targets);
        manifest.selection_evidence = manifest_selection_evidence(
            Version { major: 3, minor: 0 },
            &[("C_GetInfo", base + 80)],
        );
        let problems = crate::manifest_input::validate_structure(&manifest);
        assert!(problems.is_empty(), "{problems:?}");
        let scan = scanned_manifest_replacement(&paths, &targets);
        let scan_pins = pin_scan(&scan);
        std::fs::remove_file(&provider).unwrap();
        let input = manifest_input_from_pinning("stale-selection.json", manifest);
        assert_eq!(input.stale[0].reason, ManifestStaleReason::OpenStale);
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let mut discovered = lifecycle_discovered(vec![view]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules: vec![scan],
                pins: scan_pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        rebuild_discovered(&mut discovered).unwrap();

        assert!(discovered.manifests.is_empty());
        assert!(
            discovered
                .plan
                .slots
                .iter()
                .all(|slot| slot.file_offset != base + 80),
            "the scan replacement cannot inherit stale offline selection authority"
        );
    }

    fn selection_provider_address(engine: &Engine, binding: SelectionBindingFact) -> u64 {
        let provider = engine.pinned.summary(binding.object).unwrap().key;
        parse_maps(&std::fs::read(format!("/proc/{}/maps", engine.views[0].pid())).unwrap())
            .unwrap()
            .into_iter()
            .find(|mapping| ObjectKey::of(mapping) == provider)
            .unwrap()
            .start
    }

    fn armed_seed_route(
        loader_hits: u64,
    ) -> (
        LoadedSeedProvider,
        Engine,
        LoaderContextId,
        DiscoveryRecord,
        ScriptedSession,
    ) {
        let (fixture, view, _module, _pins) = loaded_seed_provider();
        let pid = view.pid();
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(pid);
        engine.next_view_id = 1;
        engine.views.push(view);
        let mut session = ScriptedSession::default();
        session.counters.loader_hits = loader_hits;
        engine
            .arm_loader_or_partial(
                0,
                &mut session,
                &mut true,
                &mut PendingViewRetirements::new(),
            )
            .unwrap();
        let context = engine.loader_registry.ids_for_view(ProcessViewId(0))[0];
        let spec = engine
            .loader_registry
            .context(context)
            .unwrap()
            .spec
            .clone();
        let mapping = spec.mapping.as_ref().unwrap();
        let mut record = loader_record_for(context, pid);
        record.table_ptr = mapping.start + (spec.hook.file_offset - mapping.file_offset);
        record.hook_ts_ns = engine.views[0].admitted_ns();
        (fixture, engine, context, record, session)
    }

    #[test]
    fn exec_refresh_attaches_provider_exports_before_readiness() {
        let (fixture, view, _module, _pins) = loaded_seed_provider();
        let pid = view.pid();
        let view_id = view.id();
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(pid);
        engine.next_view_id = 1;
        engine.module_hints = vec![fixture._dir.path().join("seed-provider.so")];
        engine.views.push(view);
        let mut session = ScriptedSession::default();
        engine
            .arm_loader_or_partial(
                0,
                &mut session,
                &mut true,
                &mut PendingViewRetirements::new(),
            )
            .unwrap();
        let retired = engine.loader_registry.ids_for_view(view_id)[0];
        let mut exec: DiscoveryRecord = unsafe { std::mem::zeroed() };
        exec.kind = DISCOVERY_KIND_EXEC;
        exec.pid_tgid = u64::from(pid) << 32;
        exec.hook_ts_ns = engine.views[0].admitted_ns();

        let outcome = apply_ordinary_batch(&mut engine, &mut session, vec![exec]).unwrap();

        assert!(outcome.required_complete);
        let contexts = engine.loader_registry.ids_for_view(view_id);
        assert_eq!(contexts.len(), 1);
        assert_ne!(contexts[0], retired);
        assert_eq!(session.dynamic_attach_calls.len(), 3);
        assert_eq!(
            session
                .dynamic_attach_calls
                .iter()
                .map(|export| export.cookie)
                .collect::<BTreeSet<_>>(),
            [1, 2].into_iter().collect(),
            "readiness requires all configured exports from the refreshed provider"
        );
    }

    #[test]
    fn selection_bindings_reuse_existing_physical_attachments() {
        let (_fixture, mut engine, mut session) = initial_export_route();
        engine.modules[0]
            .scanned
            .exports
            .push("C_GetInterface".into());
        session.dynamic_attach_reports_added = true;
        let mut additions_allowed = true;
        let mut pending = PendingViewRetirements::new();
        let mut closure = PauseClosure::new(true);

        engine.attach_initial_exports(
            &mut session,
            &mut additions_allowed,
            &mut pending,
            &mut closure,
        );
        assert_eq!(session.dynamic_attach_calls.len(), 3);
        assert_eq!(
            session
                .dynamic_attach_calls
                .iter()
                .map(|export| export.cookie)
                .collect::<BTreeSet<_>>(),
            [1, 2].into_iter().collect()
        );
        assert_eq!(engine.selection_bindings.len(), 1);
        assert!(engine.selection_bindings[&1].attached);
        assert_eq!(
            session
                .dynamic_attach_calls
                .iter()
                .find(|export| export.abi == HookAbi::FunctionList)
                .unwrap()
                .cookie,
            u64::from(engine.hooks.id("C_GetFunctionList").unwrap())
        );
        assert_eq!(
            session
                .dynamic_attach_calls
                .iter()
                .find(|export| export.abi == HookAbi::InterfaceList)
                .unwrap()
                .cookie,
            u64::from(engine.hooks.id("C_GetInterfaceList").unwrap())
        );
        assert_eq!(
            session
                .dynamic_attach_calls
                .iter()
                .find(|export| export.abi == HookAbi::Interface)
                .unwrap()
                .cookie,
            engine.selection_bindings[&1].id
        );
        assert!(additions_allowed && pending.is_empty() && closure.required_complete());

        engine.attach_initial_exports(
            &mut session,
            &mut additions_allowed,
            &mut pending,
            &mut closure,
        );
        assert_eq!(session.dynamic_attach_calls.len(), 3);
        assert_eq!(engine.selection_bindings.len(), 1);
    }

    #[test]
    fn two_view_selection_claims_retire_independently() {
        let (mut fixture, mut engine, mut session, first_binding) = attached_selection_route();
        let provider_path = PathBuf::from(&engine.modules[0].scanned.path);
        let peer_pid = fixture.spawn_peer();
        let second_view = ProcessView::open(ProcessViewId(1), peer_pid).unwrap();
        let second_view_id = second_view.id();
        let (cgroup_engine, _scope_dir) =
            engine_over_cgroup_naming(&[engine.views[0].pid(), peer_pid]);
        engine.scope = cgroup_engine.scope;
        let provider = engine
            .pinned
            .owned_timing_key(first_binding.object)
            .unwrap();
        let first_table = selection_only_table(
            &engine,
            first_binding,
            0x20,
            &[("C_Initialize", 0x100)],
            Vec::new(),
        );
        let result = SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        };
        let (claims, tables, pending) = engine
            .propose_selection_claim(&first_binding, provider, &first_table, &result)
            .unwrap();
        let candidate = engine
            .live_candidate_with_selection(
                engine.pinned.clone(),
                engine
                    .modules
                    .iter()
                    .map(|module| module.scanned.clone())
                    .collect(),
                claims,
                tables,
                pending,
            )
            .unwrap();
        engine
            .apply_candidate(&mut session, candidate, &mut true, false, &[])
            .unwrap();

        let mut mapped = None;
        for _ in 0..200 {
            let maps =
                parse_maps(&std::fs::read(format!("/proc/{peer_pid}/maps")).unwrap()).unwrap();
            mapped = maps.iter().find_map(|mapping| {
                matches!(
                    resolve(&maps, mapping.start),
                    Resolved::File {
                        path: MappedPath::Usable(ref path),
                        ..
                    } if path == &provider_path
                )
                .then(|| mapping.clone())
            });
            if mapped.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut second_module = mapped_object(
            &second_view,
            &mapped.expect("the peer seed provider is mapped"),
            &provider_path,
        );
        second_module.exports = vec![
            "C_GetFunctionList".into(),
            "C_GetInterfaceList".into(),
            "C_GetInterface".into(),
        ];
        let mut candidate_pinned = engine.pinned.clone();
        assert!(
            candidate_pinned
                .absorb(pin_test_module(&second_view, &second_module))
                .is_empty()
        );
        engine.next_view_id = 2;
        let raw_modules = engine
            .modules
            .iter()
            .map(|module| module.scanned.clone())
            .chain([second_module.clone()])
            .collect();
        let candidate = engine
            .live_candidate(candidate_pinned, raw_modules, Vec::new())
            .unwrap();
        assert!(
            engine
                .apply_candidate(&mut session, candidate, &mut true, false, &[&second_view],)
                .unwrap()
                .accepted()
        );
        engine.views.push(second_view);
        engine
            .arm_loader_or_partial(
                1,
                &mut session,
                &mut true,
                &mut PendingViewRetirements::new(),
            )
            .unwrap();
        let (retire, complete) =
            engine.attach_refreshed_exports(second_view_id, &mut session, &mut true);
        assert!(!retire && complete);
        let second_binding = *engine
            .selection_bindings
            .values()
            .find(|binding| binding.view == second_view_id)
            .unwrap();
        let second_table = selection_only_table(
            &engine,
            second_binding,
            0x20,
            &[("C_Initialize", 0x100)],
            Vec::new(),
        );
        let (claims, tables, pending) = engine
            .propose_selection_claim(
                &second_binding,
                engine
                    .pinned
                    .owned_timing_key(second_binding.object)
                    .unwrap(),
                &second_table,
                &result,
            )
            .unwrap();
        let raw_modules = engine
            .modules
            .iter()
            .map(|module| module.scanned.clone())
            .collect();
        let candidate = engine
            .live_candidate_with_selection(
                engine.pinned.clone(),
                raw_modules,
                claims,
                tables,
                pending,
            )
            .unwrap();
        assert!(
            engine
                .apply_candidate(&mut session, candidate, &mut true, false, &[])
                .unwrap()
                .accepted()
        );

        let selection_slot = engine
            .plan
            .slots
            .iter()
            .find(|slot| slot.file_offset == 0x100)
            .map(|slot| slot.index)
            .unwrap();
        assert_eq!(engine.selection_claims.len(), 2);
        assert_eq!(
            engine
                .plan
                .slots
                .iter()
                .filter(|slot| slot.file_offset == 0x100 && engine.plan.is_active(slot.index))
                .count(),
            1
        );
        let raw_modules = engine
            .modules
            .iter()
            .map(|module| module.scanned.clone())
            .collect();
        let candidate = engine
            .live_candidate(engine.pinned.clone(), raw_modules, Vec::new())
            .unwrap();
        let mut first_retirement =
            ScriptedSession::losing_generation_at_attach(engine.views[0].pid());
        let first_outcome = engine
            .apply_candidate(&mut first_retirement, candidate, &mut true, false, &[])
            .unwrap();

        assert!(!first_outcome.accepted());
        assert!(
            engine.selection_bindings[&first_binding.id].retired,
            "retiring the first view must retire its binding ID"
        );
        assert!(!engine.selection_bindings[&second_binding.id].retired);
        assert_eq!(engine.selection_claims.len(), 1);
        assert_eq!(
            engine.selection_claims.keys().next().unwrap().binding_id,
            second_binding.id
        );
        assert!(engine.plan.is_active(selection_slot));
        assert_eq!(first_retirement.detached_slots.iter().sum::<usize>(), 0);

        let mut delayed: DiscoveryRecord = unsafe { std::mem::zeroed() };
        delayed.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        delayed.pid_tgid = u64::from(engine.views[0].pid()) << 32;
        delayed.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        delayed.interface_index = DISCOVERY_VERSION_V3_0;
        delayed.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        delayed.selection_version_class = DISCOVERY_VERSION_V3_0;
        delayed.binding_id = first_binding.id;
        assert_eq!(
            engine.process_selection_record(&QueuedDiscoveryRecord {
                record: delayed,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }),
            DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed)
        );

        let mut usable: DiscoveryRecord = unsafe { std::mem::zeroed() };
        usable.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        usable.pid_tgid = u64::from(engine.views[1].pid()) << 32;
        usable.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        usable.interface_index = DISCOVERY_VERSION_V3_0;
        usable.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        usable.selection_version_class = DISCOVERY_VERSION_V3_0;
        usable.return_rv = 1;
        usable.binding_id = second_binding.id;
        assert_eq!(
            engine.process_selection_record(&QueuedDiscoveryRecord {
                record: usable,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }),
            DiscoveryRecordOutcome::applied(false, true)
        );

        let raw_modules = engine
            .modules
            .iter()
            .map(|module| module.scanned.clone())
            .collect();
        let candidate = engine
            .live_candidate(engine.pinned.clone(), raw_modules, Vec::new())
            .unwrap();
        let mut second_retirement = ScriptedSession::losing_generation_at_attach(peer_pid);
        let second_outcome = engine
            .apply_candidate(&mut second_retirement, candidate, &mut true, false, &[])
            .unwrap();
        assert!(!second_outcome.accepted());
        assert_eq!(second_retirement.detached_slots.iter().sum::<usize>(), 1);
        assert!(!engine.plan.is_active(selection_slot));
        assert!(engine.selection_bindings[&second_binding.id].retired);
        assert!(engine.selection_claims.is_empty());
        assert!(engine.selection_tables.is_empty());
    }

    #[test]
    fn aggregate_policy_creates_no_selection_bindings() {
        let (_fixture, mut engine, mut session) = initial_export_route();
        engine.modules[0].scanned.exports = vec!["C_GetInterface".into()];
        session.capture_policy = Some(CapturePolicy::AggregateOnly);
        session.dynamic_attach_reports_added = true;
        let mut additions_allowed = true;
        let mut pending = PendingViewRetirements::new();
        let mut closure = PauseClosure::new(true);

        engine.attach_initial_exports(
            &mut session,
            &mut additions_allowed,
            &mut pending,
            &mut closure,
        );

        assert!(session.dynamic_attach_calls.is_empty());
        assert!(engine.selection_bindings.is_empty());
        assert_eq!(engine.next_selection_binding_id, Some(1));
        assert!(closure.required_complete());
        assert!(!engine.counters.object_skips.iter().any(|skip| {
            skip.subject.contains("selection") || skip.reason.contains("selection")
        }));
    }

    #[test]
    fn selection_binding_ids_never_reuse() {
        let mut engine = Engine::empty();
        let context = LoaderContextId::from_case_id(0);
        engine.next_selection_binding_id = Some(u64::MAX);

        let last = engine
            .selection_binding_candidate(
                context,
                ProcessViewId(1),
                PinnedObjectId(2),
                0x10,
                3,
                plan::ModuleId(0),
            )
            .unwrap();
        assert_eq!(last.id, u64::MAX);
        engine.selection_bindings.insert(last.id, last);
        assert_eq!(
            engine
                .selection_binding_candidate(
                    context,
                    ProcessViewId(1),
                    PinnedObjectId(2),
                    0x10,
                    3,
                    plan::ModuleId(0),
                )
                .unwrap()
                .id,
            u64::MAX,
            "the same physical attachment reuses its retained ID"
        );
        assert!(
            engine
                .selection_binding_candidate(
                    context,
                    ProcessViewId(1),
                    PinnedObjectId(2),
                    0x20,
                    3,
                    plan::ModuleId(0),
                )
                .is_none(),
            "exhaustion refuses rather than wrapping to zero"
        );
        assert_eq!(engine.next_selection_binding_id, None);
    }

    #[test]
    fn selection_binding_start_failure_restores_capture_state() {
        let mut engine = Engine::empty();
        let binding = engine
            .selection_binding_candidate(
                LoaderContextId::from_case_id(0),
                ProcessViewId(1),
                PinnedObjectId(2),
                0x10,
                3,
                plan::ModuleId(0),
            )
            .unwrap();
        engine.selection_bindings.insert(binding.id, binding);
        let snapshot = engine.begin_start_capture_attempt().unwrap();
        assert!(engine.selection_bindings.is_empty());
        assert_eq!(engine.next_selection_binding_id, Some(1));
        let attempted = engine
            .selection_binding_candidate(
                LoaderContextId::from_case_id(1),
                ProcessViewId(4),
                PinnedObjectId(5),
                0x20,
                3,
                plan::ModuleId(0),
            )
            .unwrap();
        engine.selection_bindings.insert(attempted.id, attempted);

        let error = engine
            .finish_start_capture_attempt::<()>(snapshot, Err(anyhow!("late start failure")))
            .unwrap_err();

        assert_eq!(error.to_string(), "late start failure");
        assert_eq!(
            engine.selection_bindings,
            [(1, binding)].into_iter().collect()
        );
        assert_eq!(engine.next_selection_binding_id, Some(2));
    }

    #[test]
    fn selection_postcheck_failure_retains_attached_binding() {
        let (_fixture, mut engine, mut session) = initial_export_route();
        engine.modules[0].scanned.exports = vec!["C_GetInterface".into()];
        let view = engine.views[0].id();
        session.dynamic_attach_reports_added = true;
        session.lose_generation_at_dynamic_attach(engine.views[0].pid());
        let mut additions_allowed = true;
        let mut pending = PendingViewRetirements::new();
        let mut closure = PauseClosure::new(true);

        engine.attach_initial_exports(
            &mut session,
            &mut additions_allowed,
            &mut pending,
            &mut closure,
        );

        assert_eq!(engine.selection_bindings.len(), 1);
        let binding = *engine.selection_bindings.values().next().unwrap();
        assert!(binding.attached);
        assert_eq!(binding.coverage, SelectionCoverageState::Uncovered);
        assert!(
            session
                .dynamic_attach_calls
                .contains(&DynamicExportIdentity {
                    object: binding.object,
                    file_offset: binding.file_offset,
                    cookie: binding.id,
                    abi: binding.abi,
                })
        );
        assert!(!additions_allowed);
        assert!(pending.contains_key(&view));
        assert!(!closure.required_complete());
    }

    #[test]
    fn owned_run_selection_coverage() {
        let (_fixture, mut engine, _session, binding) = attached_selection_route();
        let provider = binding.provider;
        assert_eq!(binding.coverage, SelectionCoverageState::Uncovered);
        assert_eq!(engine.selection_coverage(plan::ModuleId(u32::MAX)), None);
        assert_eq!(
            engine.selection_coverage(provider),
            Some(SelectionCoverageVerdict::AbsentUncovered)
        );
        engine
            .selection_bindings
            .get_mut(&binding.id)
            .unwrap()
            .observed = true;
        assert_eq!(
            engine.selection_coverage(provider),
            Some(SelectionCoverageVerdict::Observed)
        );
        engine
            .selection_bindings
            .get_mut(&binding.id)
            .unwrap()
            .observed = false;

        let generation = std::num::NonZeroU64::new(7).unwrap();
        engine.mark_owned_selection_pending(generation);
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::OwnedPending(generation)
        );
        assert_eq!(
            engine.selection_coverage(provider),
            Some(SelectionCoverageVerdict::AbsentUncovered)
        );
        engine.open_owned_selection(binding.id);
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::OwnedOpen(generation)
        );

        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
        record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        record.interface_index = DISCOVERY_VERSION_V3_0;
        record.return_rv = 7;
        record.binding_id = binding.id;
        assert_eq!(
            engine.process_selection_record(&QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }),
            DiscoveryRecordOutcome::applied(false, true)
        );
        assert!(engine.selection_bindings[&binding.id].observed);
        assert_eq!(
            engine.selection_coverage(provider),
            Some(SelectionCoverageVerdict::Observed)
        );
        let uncovered = SelectionBindingFact {
            id: binding.id + 1,
            observed: false,
            coverage: SelectionCoverageState::Uncovered,
            ..binding
        };
        engine.selection_bindings.insert(uncovered.id, uncovered);
        assert_eq!(
            engine.selection_coverage(provider),
            Some(SelectionCoverageVerdict::ObservedUncovered)
        );
        engine.selection_bindings.remove(&uncovered.id);

        engine.close_owned_selection(binding.id);
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::OwnedClosed(generation)
        );

        engine
            .selection_bindings
            .get_mut(&binding.id)
            .unwrap()
            .observed = false;
        engine
            .selection_bindings
            .get_mut(&binding.id)
            .unwrap()
            .coverage = SelectionCoverageState::OwnedOpen(generation);
        engine.finish_owned_selection_coverage(true);
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::OwnedClosed(generation)
        );
        assert_eq!(
            engine.selection_coverage(provider),
            Some(SelectionCoverageVerdict::AbsentCovered)
        );

        engine
            .selection_bindings
            .get_mut(&binding.id)
            .unwrap()
            .coverage = SelectionCoverageState::OwnedOpen(generation);
        engine.finish_owned_selection_coverage(false);
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::Uncovered
        );
        assert_eq!(
            engine.selection_coverage(provider),
            Some(SelectionCoverageVerdict::AbsentUncovered)
        );
    }

    #[test]
    fn selection_ring_loss_invalidates_silent_coverage() {
        let (_fixture, mut engine, mut session, binding) = attached_selection_route();
        let generation = std::num::NonZeroU64::new(9).unwrap();
        engine.mark_owned_selection_pending(generation);
        engine.open_owned_selection(binding.id);
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::OwnedOpen(generation)
        );

        session.counters.ring_loss = 1;
        engine.update_counter_snapshot(&session).unwrap();
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::Uncovered
        );
        assert_eq!(
            engine.selection_coverage(binding.provider),
            Some(SelectionCoverageVerdict::AbsentUncovered)
        );

        engine.mark_owned_selection_pending(generation);
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::Uncovered,
            "a loss known before prearm cannot mint covered silence"
        );

        engine.counter_snapshot.ring_loss = 0;
        session.counters.ring_loss = 0;
        engine.mark_owned_selection_pending(generation);
        engine.open_owned_selection(binding.id);
        engine.finish_owned_selection_coverage(true);
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::OwnedClosed(generation)
        );
        session.counters.ring_loss = 1;
        engine.update_counter_snapshot(&session).unwrap();
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::Uncovered,
            "loss discovered after closure invalidates the historical proof"
        );
    }

    #[test]
    fn selection_counter_regression_invalidates_silent_coverage() {
        let (_fixture, mut engine, mut session, binding) = attached_selection_route();
        let generation = NonZeroU64::new(13).unwrap();
        engine.mark_owned_selection_pending(generation);
        engine.open_owned_selection(binding.id);
        engine.counter_snapshot.loader_hits = 2;
        session.counters.loader_hits = 1;
        session.counters.ring_loss = 1;

        engine.update_counter_snapshot(&session).unwrap();

        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::Uncovered
        );
    }

    #[test]
    fn selection_table_refusal_isolates_provider_coverage() {
        let (child, mut engine, modules) = engine_with_one_accepted_provider();
        let mut session = ScriptedSession::default();
        let mut additions_allowed = true;
        engine
            .arm_loader_or_partial(
                0,
                &mut session,
                &mut additions_allowed,
                &mut PendingViewRetirements::new(),
            )
            .unwrap();
        let context = engine.loader_registry.ids_for_view(engine.views[0].id())[0];
        let candidate = peer_candidate(&mut engine, &modules);
        assert!(
            engine
                .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
                .unwrap()
                .accepted()
        );
        let first = engine
            .modules
            .iter()
            .find(|module| module.object == engine.plan.modules[0].object)
            .unwrap()
            .object;
        let second = engine
            .modules
            .iter()
            .find(|module| module.object != first)
            .unwrap()
            .object;
        let first_provider = engine.pinned.owned_timing_key(first).unwrap();
        let first_id = engine
            .plan
            .modules
            .iter()
            .find(|module| module.object == first)
            .unwrap()
            .id;
        let second_id = engine
            .plan
            .modules
            .iter()
            .find(|module| module.object == second)
            .unwrap()
            .id;
        let generation = NonZeroU64::new(17).unwrap();
        let first_binding = SelectionBindingFact {
            id: 1,
            context,
            view: engine.views[0].id(),
            object: first,
            file_offset: 0x10,
            hook_id: 0,
            abi: HookAbi::Interface,
            attached: true,
            retired: false,
            provider: first_id,
            observed: false,
            coverage: SelectionCoverageState::OwnedOpen(generation),
        };
        let second_binding = SelectionBindingFact {
            id: 2,
            object: second,
            provider: second_id,
            coverage: SelectionCoverageState::OwnedOpen(generation),
            ..first_binding
        };
        engine
            .selection_bindings
            .extend([(1, first_binding), (2, second_binding)]);
        let table_key = SelectionTableKey {
            view: engine.views[0].id(),
            provider: first_provider.clone(),
            version: SelectionVersionClass::V3_0,
            flags: 0,
        };
        let claim = SelectionClaim {
            target: plan::AttachKey {
                object: first,
                file_offset: 0x100,
            },
            object_path: String::new(),
        };
        let mut key = SelectionClaimKey {
            binding_id: 1,
            view: table_key.view,
            context: context.get(),
            hook_owner: first,
            provider: first_provider,
            selected_object: first,
            table_file_offset: 0x20,
            version: table_key.version,
            flags: table_key.flags,
            name: "C_Initialize",
            file_offset: 0x100,
        };
        let mut claims: BTreeMap<SelectionClaimKey, SelectionClaim> =
            [(key.clone(), claim.clone())].into_iter().collect();
        key.table_file_offset = 0x28;
        claims.insert(key, claim);
        let table = SelectionTableFact {
            object: first,
            file_offset: 0x20,
            targets: vec![plan::SelectionTableTarget {
                object: first,
                object_path: String::new(),
                file_offset: 0x100,
                name: "C_Initialize",
            }],
        };
        let pending = PendingSelectionAdmission {
            key: table_key.clone(),
            table: table.clone(),
            previous_claims: BTreeMap::new(),
            previous_tables: BTreeMap::new(),
        };
        let candidate = engine
            .live_candidate_with_selection(
                engine.pinned.clone(),
                engine
                    .modules
                    .iter()
                    .map(|module| module.scanned.clone())
                    .collect(),
                claims,
                [(table_key, table)].into_iter().collect(),
                pending,
            )
            .unwrap();
        assert!(candidate.plan.slots.len() >= engine.plan.slots.len());
        assert_eq!(
            engine.selection_bindings[&1].coverage,
            SelectionCoverageState::Uncovered
        );
        assert_eq!(
            engine.selection_bindings[&2].coverage,
            SelectionCoverageState::OwnedOpen(generation)
        );
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn interface_list_truncation_preserves_selection_coverage() {
        let (_fixture, mut engine, mut session, binding) = attached_selection_route();
        let generation = NonZeroU64::new(19).unwrap();
        engine.mark_owned_selection_pending(generation);
        engine.open_owned_selection(binding.id);
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN;
        record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
        record.interface_index = 0;
        record.announced_count = u32::from(DISCOVERY_INTERFACES) + 1;
        let mut additions_allowed = true;
        let mut pending = PendingViewRetirements::new();
        let _ = engine.process_export_record(
            &record,
            &mut session,
            &mut additions_allowed,
            &mut pending,
        );

        assert_eq!(engine.discovery_truncated, 1);
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::OwnedOpen(generation)
        );
    }

    #[test]
    fn attributed_selection_loss_does_not_poison_another_provider() {
        let (_fixture, mut engine, _session, binding) = attached_selection_route();
        let generation = NonZeroU64::new(11).unwrap();
        engine.mark_owned_selection_pending(generation);
        engine.open_owned_selection(binding.id);
        let unrelated = SelectionBindingFact {
            id: binding.id + 1,
            provider: plan::ModuleId(binding.provider.0 + 1),
            coverage: SelectionCoverageState::OwnedOpen(generation),
            ..binding
        };
        engine.selection_bindings.insert(unrelated.id, unrelated);

        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
        record.case_id = u8::MAX;
        record.binding_id = binding.id;
        assert_eq!(
            engine.process_selection_record(&QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }),
            DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed)
        );
        assert_eq!(
            engine.selection_bindings[&binding.id].coverage,
            SelectionCoverageState::Uncovered
        );
        assert_eq!(
            engine.selection_bindings[&unrelated.id].coverage,
            SelectionCoverageState::OwnedOpen(generation)
        );
    }

    #[test]
    fn c_get_interface_selection_never_mutates_inventory() {
        let (_fixture, mut engine, mut session) = initial_export_route();
        session.dynamic_attach_reports_added = true;
        let mut additions_allowed = true;
        let mut pending = PendingViewRetirements::new();
        let mut closure = PauseClosure::new(true);
        engine.attach_initial_exports(
            &mut session,
            &mut additions_allowed,
            &mut pending,
            &mut closure,
        );
        let binding = *engine.selection_bindings.values().next().unwrap();
        let before_plan = engine.plan.clone();
        let before_modules = engine.modules.clone();
        let before_discovery = engine.discovery.clone();
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
        record.case_id = DISCOVERY_NAME_NULL;
        record.return_rv = 1;
        record.binding_id = binding.id;
        assert!(valid_discovery_record(&record));

        let outcome = engine
            .dispatch_discovery_record(
                QueuedDiscoveryRecord {
                    record,
                    terminal_owner: None,
                    terminal_exports: Vec::new(),
                },
                &mut session,
                &mut additions_allowed,
                &mut pending,
                &mut BTreeSet::new(),
                &mut Vec::new(),
            )
            .unwrap();

        assert_eq!(outcome, DiscoveryRecordOutcome::applied(false, true));
        assert_eq!(engine.plan, before_plan);
        assert_eq!(engine.modules, before_modules);
        assert_eq!(engine.discovery, before_discovery);

        engine
            .selection_bindings
            .get_mut(&binding.id)
            .unwrap()
            .retired = true;
        engine.loader_registry.tombstone(binding.context).unwrap();
        let identity = DynamicExportIdentity {
            object: binding.object,
            file_offset: binding.file_offset,
            cookie: binding.id,
            abi: binding.abi,
        };
        assert_eq!(
            engine.process_selection_record(&tagged_by_authority(
                binding.context,
                &[identity],
                record,
            )),
            DiscoveryRecordOutcome::applied(false, true),
            "the exact terminal export snapshot remains historical authority"
        );
        let skips = engine.counters.object_skips.len();
        let ordinary = engine.process_selection_record(&QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        });
        assert_eq!(
            ordinary,
            DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed),
            "a delayed ordinary record fails closed after retirement"
        );
        assert_eq!(engine.counters.object_skips.len(), skips + 1);
    }

    #[test]
    fn c_get_interface_selection_tuples_are_capture_bounded_and_counted() {
        let (_fixture, mut engine, _session, binding) = attached_selection_route();
        let before_plan = engine.plan.clone();
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
        record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        record.interface_index = DISCOVERY_VERSION_V3_0;
        record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        record.selection_version_class = DISCOVERY_VERSION_V3_0;
        record.table_ptr = selection_provider_address(&engine, binding);
        record.binding_id = binding.id;
        let queued = |record| QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        };

        for flags in 0..16 {
            record.request_flags = flags;
            assert_eq!(
                engine.process_selection_record(&queued(record)),
                DiscoveryRecordOutcome::applied(false, true)
            );
        }
        assert_eq!(engine.capture_facts.history.selections.len(), 16);
        assert!(engine.capture_facts.history.selections[0].result.is_some());
        assert!(
            engine.capture_facts.history.selections[0]
                .inventory_matches
                .is_empty()
        );
        record.request_flags = 0;
        engine.process_selection_record(&queued(record));
        assert_eq!(engine.capture_facts.history.selections[0].count, 2);
        engine.capture_facts.history.selections[0].count = u64::MAX;
        engine.process_selection_record(&queued(record));
        assert_eq!(engine.capture_facts.history.selections[0].count, u64::MAX);

        record.request_flags = 16;
        engine.process_selection_record(&queued(record));
        assert_eq!(engine.capture_facts.history.selections.len(), 16);
        assert!(engine.capture_facts.history.selection_truncated);
        assert_eq!(
            engine.plan, before_plan,
            "selection tuples never mutate inventory"
        );
        assert!(engine.selection_claims.is_empty());
        assert!(engine.selection_tables.is_empty());
    }

    #[test]
    fn selection_unknown_result_flags_remain_factual_without_authority() {
        let (_fixture, mut engine, _session, binding) = attached_selection_route();
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        record.pid_tgid = u64::from(engine.views[0].pid()) << 32;
        record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        record.interface_index = DISCOVERY_VERSION_V3_0;
        record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        record.selection_version_class = DISCOVERY_VERSION_V3_0;
        record.interface_flags = 1 << 63;
        record.table_ptr = selection_provider_address(&engine, binding);
        record.binding_id = binding.id;

        assert_eq!(
            engine.process_selection_record(&QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }),
            DiscoveryRecordOutcome::applied(false, true)
        );
        assert_eq!(
            engine.capture_facts.history.selections[0]
                .result
                .as_ref()
                .unwrap()
                .flags,
            1 << 63
        );
        assert!(engine.selection_claims.is_empty());
        assert!(engine.selection_tables.is_empty());
        assert!(!engine.capture_facts.history.selection_truncated);
    }

    #[test]
    fn c_get_interface_selection_exact_match_keeps_inventory_aliases() {
        let (_fixture, mut engine, _session, binding) = attached_selection_route();
        let pid = engine.views[0].pid();
        let provider = engine.pinned.summary(binding.object).unwrap().key;
        let maps = parse_maps(&std::fs::read(format!("/proc/{pid}/maps")).unwrap()).unwrap();
        let address = maps
            .iter()
            .find(|mapping| ObjectKey::of(mapping) == provider)
            .unwrap()
            .start;
        let table_file_offset = match resolve(&maps, address) {
            Resolved::File { file_offset, .. } => file_offset,
            _ => unreachable!(),
        };
        engine.modules[0].scanned.tables.push(ScannedTable {
            version: (3, 0),
            walk: "full",
            entries: Vec::new(),
            null_entries: vec!["C_Initialize"],
            unpinned: Vec::new(),
            address,
            file_offset: Some(table_file_offset),
        });
        engine.modules[0].entry_objects.push(Vec::new());
        engine.modules[0].scanned.interfaces.extend([
            ScannedInterface {
                index: 0,
                name_class: "exact_standard",
                name_lossy: None,
                name_private: Some(b"PKCS 11".to_vec()),
                flags: 0,
                table: Some(0),
            },
            ScannedInterface {
                index: 1,
                name_class: "exact_standard",
                name_lossy: None,
                name_private: Some(b"PKCS 11".to_vec()),
                flags: 1,
                table: Some(0),
            },
        ]);
        engine.publish_current_capture_facts().unwrap();
        let before_plan = engine.plan.clone();

        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        record.pid_tgid = u64::from(pid) << 32;
        record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        record.interface_index = DISCOVERY_VERSION_V3_0;
        record.request_flags = 1;
        record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        record.selection_version_class = DISCOVERY_VERSION_V3_0;
        record.interface_flags = 1;
        record.table_ptr = address;
        record.binding_id = binding.id;
        assert_eq!(
            engine.process_selection_record(&QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }),
            DiscoveryRecordOutcome::applied(false, true)
        );

        let tuple = engine.capture_facts.history.selections.last().unwrap();
        assert_eq!(tuple.inventory_matches.len(), 3);
        assert_eq!(
            tuple
                .inventory_matches
                .iter()
                .filter(|matched| matched.name_agrees)
                .count(),
            2,
            "legacy has no name while both interface aliases remain distinct"
        );
        assert!(
            tuple
                .inventory_matches
                .iter()
                .all(|matched| matched.version_agrees)
        );
        let provider_module = tuple.module;
        assert_eq!(engine.plan, before_plan);

        record.name_class = DISCOVERY_NAME_UNREADABLE;
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        });
        assert!(
            engine.capture_facts.history.selections[1]
                .inventory_matches
                .iter()
                .all(|matched| !matched.name_agrees),
            "unreadable classifications never agree"
        );

        record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        let losses = engine.capture_facts.history.losses.len();
        record.table_ptr = maps
            .iter()
            .find(|mapping| ObjectKey::of(mapping) != provider)
            .unwrap()
            .start;
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        });
        let foreign = engine.capture_facts.history.selections.last().unwrap();
        assert_eq!(
            foreign.module, provider_module,
            "the hook owner stays the provider"
        );
        assert!(
            foreign.inventory_matches.is_empty(),
            "a returned pointer in another object never becomes an inventory match"
        );
        assert_eq!(engine.capture_facts.history.losses.len(), losses + 1);
        assert!(engine.capture_facts.history.losses.values().any(|loss| {
            loss.reason == "a successful selection result matched no inventory table"
        }));

        record.table_ptr = address;
        let original_key = engine
            .capture_facts
            .history
            .selection_inventory
            .keys()
            .next()
            .unwrap()
            .clone();
        let surfaces = engine
            .capture_facts
            .history
            .selection_inventory
            .remove(&original_key)
            .unwrap();
        let mut wrong_offset = original_key;
        wrong_offset.file_offset = wrong_offset.file_offset.saturating_add(1);
        engine
            .capture_facts
            .history
            .selection_inventory
            .insert(wrong_offset, surfaces);
        engine.process_selection_record(&QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        });
        let unmatched = engine
            .capture_facts
            .history
            .selections
            .iter()
            .find(|tuple| {
                tuple.result.is_some()
                    && tuple.inventory_matches.is_empty()
                    && tuple.request.flags == record.request_flags
            })
            .unwrap();
        assert_eq!(
            unmatched.count, 2,
            "the same inode and address cannot recover a stale table offset"
        );
    }

    #[test]
    fn selection_facts_follow_capture_stage_commit_and_rollback() {
        let tuple = LiveSelectionTuple {
            module: plan::ModuleId(7),
            request: SelectionRequest {
                name: SelectionNameClass::Null,
                version: SelectionVersionClass::Null,
                flags: 0,
            },
            rv: 1,
            result: None,
            inventory_matches: Vec::new(),
            count: 1,
        };
        let mut facts = CaptureFacts::default();
        let provider = timing_key(0);
        let selection_surfaces = |start: usize, count: usize| {
            canonical_inventory_keys(
                (start..start + count)
                    .map(|offset| InventorySurfaceBase {
                        provider: provider.clone(),
                        table_file_offset: offset as u64,
                        kind: InventorySurfaceKind::Interface,
                        name: PrivateSelectionName::ExactStandard,
                        version: SelectionVersionClass::V3_0,
                        flags: 0,
                    })
                    .collect(),
            )
        };
        let baseline_surfaces = facts.history.selection_surfaces.clone();
        let baseline_inventory = facts.history.selection_inventory.clone();
        let baseline_losses = facts.history.losses.clone();
        facts.begin_stage().unwrap();
        assert_eq!(
            admit_inventory_keys(
                facts.visible_history_mut(),
                selection_surfaces(0, MAX_LIVE_SELECTION_SURFACES),
            )
            .len(),
            MAX_LIVE_SELECTION_SURFACES
        );
        assert!(
            admit_inventory_keys(
                facts.visible_history_mut(),
                selection_surfaces(MAX_LIVE_SELECTION_SURFACES, 1),
            )
            .is_empty()
        );
        for flags in 0..17 {
            let mut distinct = tuple.clone();
            distinct.request.flags = flags;
            facts.record_selection(distinct, false);
        }
        let mut other_provider = tuple.clone();
        other_provider.module = plan::ModuleId(8);
        facts.record_selection(other_provider, false);
        assert_eq!(facts.visible_history().selections.len(), 17);
        assert!(facts.visible_history().selection_truncated);
        assert_eq!(facts.visible_history().losses.len(), 1);
        facts.rollback_stage();
        assert!(facts.history.selections.is_empty());
        assert_eq!(facts.history.selection_surfaces, baseline_surfaces);
        assert_eq!(facts.history.selection_inventory, baseline_inventory);
        assert_eq!(facts.history.losses, baseline_losses);
        assert!(!facts.history.selection_truncated);

        facts.begin_stage().unwrap();
        assert_eq!(
            admit_inventory_keys(
                facts.visible_history_mut(),
                selection_surfaces(0, MAX_LIVE_SELECTION_SURFACES),
            )
            .len(),
            MAX_LIVE_SELECTION_SURFACES
        );
        assert!(
            admit_inventory_keys(
                facts.visible_history_mut(),
                selection_surfaces(MAX_LIVE_SELECTION_SURFACES, 1),
            )
            .is_empty()
        );
        for flags in 0..17 {
            let mut distinct = tuple.clone();
            distinct.request.flags = flags;
            facts.record_selection(distinct, false);
        }
        let mut other_provider = tuple;
        other_provider.module = plan::ModuleId(8);
        facts.record_selection(other_provider, false);
        facts.commit_stage().unwrap();
        assert_eq!(
            facts.history.selection_surfaces.len(),
            MAX_LIVE_SELECTION_SURFACES
        );
        assert_eq!(facts.history.selections.len(), 17);
        assert!(facts.history.selection_truncated);
        assert_eq!(facts.history.losses.len(), 1);
    }

    #[test]
    fn terminal_selection_success_survives_view_loss_as_unmatched_fact() {
        let (_fixture, mut engine, _session, binding) = attached_selection_route();
        engine
            .selection_bindings
            .get_mut(&binding.id)
            .unwrap()
            .retired = true;
        engine.loader_registry.tombstone(binding.context).unwrap();
        engine.views.clear();
        let identity = DynamicExportIdentity {
            object: binding.object,
            file_offset: binding.file_offset,
            cookie: binding.id,
            abi: binding.abi,
        };
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        record.interface_index = DISCOVERY_VERSION_V3_0;
        record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        record.selection_version_class = DISCOVERY_VERSION_V3_0;
        record.table_ptr = 0x1000;
        record.binding_id = binding.id;

        assert_eq!(
            engine.process_selection_record(&tagged_by_authority(
                binding.context,
                &[identity],
                record,
            )),
            DiscoveryRecordOutcome::applied(false, true)
        );
        let tuple = engine.capture_facts.history.selections.last().unwrap();
        assert!(tuple.result.is_some());
        assert!(tuple.inventory_matches.is_empty());
        assert!(engine.capture_facts.history.losses.values().any(|loss| {
            loss.reason == "a terminal selection result had no stable live table assessment"
        }));
        assert!(engine.selection_claims.is_empty());
        assert!(engine.selection_tables.is_empty());
    }

    #[test]
    fn selection_occurrences_keep_canonical_null_and_alias_ordinals() {
        let mut engine = Engine::empty();
        let provider = timing_key(0);
        let table = ScannedTable {
            version: (3, 0),
            walk: "full",
            entries: vec![
                ScannedEntry {
                    name: "C_Finalize",
                    object: plan::TEST_OBJECT,
                    object_path: "/provider.so".into(),
                    file_offset: 0x40,
                },
                ScannedEntry {
                    name: "C_GetInfo",
                    object: plan::TEST_OBJECT,
                    object_path: "/provider.so".into(),
                    file_offset: 0x40,
                },
            ],
            null_entries: vec!["C_Initialize"],
            unpinned: Vec::new(),
            address: 0,
            file_offset: Some(0x20),
        };

        engine.record_selection_occurrences(plan::ModuleId(7), provider, &table);

        let occurrences: Vec<_> = engine
            .capture_facts
            .history
            .decoded
            .iter()
            .filter_map(|occurrence| match occurrence {
                DecodedOccurrence::Selection {
                    ordinal,
                    name,
                    object,
                    ..
                } => Some((*ordinal, *name, object.is_some())),
                _ => None,
            })
            .collect();
        assert_eq!(occurrences.len(), 3);
        assert!(occurrences.contains(&(
            crate::kinds::function_id("C_Initialize").unwrap() as u16,
            "C_Initialize",
            false,
        )));
        assert!(occurrences.contains(&(
            crate::kinds::function_id("C_Finalize").unwrap() as u16,
            "C_Finalize",
            true,
        )));
        assert!(occurrences.contains(&(
            crate::kinds::function_id("C_GetInfo").unwrap() as u16,
            "C_GetInfo",
            true,
        )));
    }

    #[test]
    fn selection_semantic_key_reuses_same_table_and_refuses_changed_targets() {
        let (_fixture, mut engine, _session, binding) = attached_selection_route();
        let provider = engine.pinned.owned_timing_key(binding.object).unwrap();
        let result = SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        };
        let first = selection_only_table(
            &engine,
            binding,
            0x20,
            &[("C_Initialize", 0x100), ("C_Finalize", 0x108)],
            Vec::new(),
        );
        let (claims, tables, _) = engine
            .propose_selection_claim(&binding, provider.clone(), &first, &result)
            .unwrap();
        engine.selection_claims = claims.clone();
        engine.selection_tables = tables.clone();

        let (same_claims, same_tables, _) = engine
            .propose_selection_claim(&binding, provider.clone(), &first, &result)
            .unwrap();
        assert_eq!(same_claims, claims);
        assert_eq!(same_tables, tables);

        engine.selection_claims.clear();
        assert_eq!(engine.selection_tables, tables);

        let changed = selection_only_table(
            &engine,
            binding,
            0x20,
            &[("C_Initialize", 0x100), ("C_Finalize", 0x110)],
            Vec::new(),
        );
        assert!(
            engine
                .propose_selection_claim(&binding, provider, &changed, &result)
                .is_none()
        );
        assert!(engine.selection_claims.is_empty());
        assert_eq!(engine.selection_tables, tables);
        assert!(engine.capture_facts.history.selection_truncated);
    }

    #[test]
    fn selection_table_partial_attach_rolls_back_the_successful_prefix() {
        let (_fixture, mut engine, mut session, binding) = attached_selection_route();
        let provider = engine.pinned.owned_timing_key(binding.object).unwrap();
        let table = selection_only_table(
            &engine,
            binding,
            0x20,
            &[("C_Initialize", 0x100), ("C_Finalize", 0x108)],
            Vec::new(),
        );
        let result = SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        };
        let (claims, tables, pending) = engine
            .propose_selection_claim(&binding, provider, &table, &result)
            .unwrap();
        let raw_modules = engine
            .modules
            .iter()
            .map(|module| module.scanned.clone())
            .collect();
        let candidate = engine
            .live_candidate_with_selection(
                engine.pinned.clone(),
                raw_modules,
                claims,
                tables,
                pending,
            )
            .unwrap();
        assert_eq!(candidate.delta.new.len(), 2);
        session.fail_target_slots([candidate.delta.new[1].index]);

        let outcome = engine
            .apply_candidate(&mut session, candidate, &mut true, false, &[])
            .unwrap();

        assert!(!outcome.selection_authorized);
        assert!(engine.selection_claims.is_empty());
        assert!(engine.selection_tables.is_empty());
        assert!(
            engine
                .plan
                .slots
                .iter()
                .filter(|slot| matches!(slot.file_offset, 0x100 | 0x108))
                .all(|slot| !engine.plan.is_active(slot.index))
        );
        assert_eq!(session.attached_slots.last(), Some(&2));
        assert_eq!(
            session.detached_slots.iter().rev().take(2).sum::<usize>(),
            2
        );
    }

    #[test]
    fn selection_candidate_preflight_refusal_keeps_claims_and_latch_unchanged() {
        let (_fixture, mut engine, _session, binding) = attached_selection_route();
        let table = selection_only_table(
            &engine,
            binding,
            0x20,
            &[("C_Initialize", 0x100)],
            Vec::new(),
        );
        let result = SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        };
        let (claims, tables, pending) = engine
            .propose_selection_claim(
                &binding,
                engine.pinned.owned_timing_key(binding.object).unwrap(),
                &table,
                &result,
            )
            .unwrap();
        let candidate = engine
            .live_candidate_with_selection(
                engine.pinned.clone(),
                engine
                    .modules
                    .iter()
                    .map(|module| module.scanned.clone())
                    .collect(),
                claims,
                tables,
                pending,
            )
            .unwrap();
        let before_plan = engine.plan.clone();
        let mut session = ScriptedSession::refusing_preflight();

        let outcome = engine
            .apply_candidate(&mut session, candidate, &mut true, false, &[])
            .unwrap();

        assert!(!outcome.selection_authorized);
        assert_eq!(engine.plan, before_plan);
        assert!(engine.selection_claims.is_empty());
        assert!(engine.selection_tables.is_empty());
        assert!(session.attached_slots.is_empty());
    }

    #[test]
    fn selection_rollback_does_not_restore_a_latch_after_generation_loss() {
        let (_fixture, mut engine, _session, binding) = attached_selection_route();
        let table = selection_only_table(
            &engine,
            binding,
            0x20,
            &[("C_Initialize", 0x100)],
            Vec::new(),
        );
        let result = SelectionRequest {
            name: SelectionNameClass::ExactStandard,
            version: SelectionVersionClass::V3_0,
            flags: 0,
        };
        let provider = engine.pinned.owned_timing_key(binding.object).unwrap();
        let (_, latched, _) = engine
            .propose_selection_claim(&binding, provider.clone(), &table, &result)
            .unwrap();
        engine.selection_tables = latched;
        let (claims, tables, pending) = engine
            .propose_selection_claim(&binding, provider, &table, &result)
            .unwrap();
        let candidate = engine
            .live_candidate_with_selection(
                engine.pinned.clone(),
                engine
                    .modules
                    .iter()
                    .map(|module| module.scanned.clone())
                    .collect(),
                claims,
                tables,
                pending,
            )
            .unwrap();
        let mut session = ScriptedSession::losing_generation_at_attach(engine.views[0].pid());

        let outcome = engine
            .apply_candidate(&mut session, candidate, &mut true, false, &[])
            .unwrap();

        assert!(!outcome.selection_authorized);
        assert!(engine.selection_claims.is_empty());
        assert!(engine.selection_tables.is_empty());
    }

    #[test]
    fn selection_inventory_keys_are_canonical_bounded_and_pruned() {
        let (_fixture, engine, _session, binding) = attached_selection_route();
        let provider = engine.pinned.owned_timing_key(binding.object).unwrap();
        let base = |table_file_offset, name, flags| InventorySurfaceBase {
            provider: provider.clone(),
            table_file_offset,
            kind: InventorySurfaceKind::Interface,
            name,
            version: SelectionVersionClass::V3_0,
            flags,
        };
        let first = base(0x20, PrivateSelectionName::Other(b"alpha".to_vec()), 0);
        let second = base(0x20, PrivateSelectionName::Other(b"beta".to_vec()), 1);
        assert_eq!(
            canonical_inventory_keys(vec![first.clone(), second.clone()]),
            canonical_inventory_keys(vec![second.clone(), first.clone()]),
            "enumeration order does not change canonical aliases"
        );
        assert_ne!(
            canonical_inventory_keys(vec![first.clone()]),
            canonical_inventory_keys(vec![second.clone()]),
            "private names and flags remain part of alias identity"
        );
        assert_ne!(
            canonical_inventory_keys(vec![first.clone()]),
            canonical_inventory_keys(vec![base(
                0x28,
                PrivateSelectionName::Other(b"alpha".to_vec()),
                0,
            )]),
            "the same apparent alias at another table offset stays distinct"
        );
        let duplicates = canonical_inventory_keys(vec![first.clone(), first]);
        assert_eq!(duplicates[0].duplicate, 0);
        assert_eq!(duplicates[1].duplicate, 1);

        let mut history = CaptureHistory::default();
        let first_512 = (0..MAX_LIVE_SELECTION_SURFACES)
            .map(|offset| base(offset as u64, PrivateSelectionName::ExactStandard, 0))
            .collect();
        assert_eq!(
            admit_inventory_keys(&mut history, canonical_inventory_keys(first_512)).len(),
            MAX_LIVE_SELECTION_SURFACES
        );
        let overflow = canonical_inventory_keys(vec![base(
            MAX_LIVE_SELECTION_SURFACES as u64,
            PrivateSelectionName::ExactStandard,
            0,
        )]);
        assert!(admit_inventory_keys(&mut history, overflow).is_empty());
        assert_eq!(
            history.selection_surfaces.len(),
            MAX_LIVE_SELECTION_SURFACES
        );
        assert!(history.selection_truncated);
        assert_eq!(history.losses.len(), 1);

        let surface = history.selection_surfaces.iter().next().unwrap().clone();
        for view in [ProcessViewId(1), ProcessViewId(2)] {
            history.selection_inventory.insert(
                ExactSelectionTable {
                    view,
                    provider: provider.clone(),
                    address: 0x1000,
                    file_offset: 0,
                },
                vec![surface.clone()],
            );
        }
        prune_selection_inventory(&mut history, &[ProcessViewId(2)].into_iter().collect());
        assert_eq!(history.selection_inventory.len(), 1);
        assert!(
            history
                .selection_inventory
                .keys()
                .all(|table| table.view == ProcessViewId(2))
        );

        let before =
            parse_maps(b"00001000-00002000 r--p 00000000 08:01 9 /opt/provider.so\n").unwrap();
        let remapped =
            parse_maps(b"00001000-00002000 r--p 00001000 08:01 9 /opt/provider.so\n").unwrap();
        assert!(!stable_selection_mapping(before.first(), remapped.first()));
    }

    #[test]
    fn selection_assessment_rejects_remap_view_loss_and_pin_change() {
        fn assess(
            before: Vec<MapEntry>,
            after: Vec<MapEntry>,
            view_same: bool,
            pin_same: bool,
        ) -> (Result<(), ()>, Vec<&'static str>) {
            let mut snapshots = [before, after].into_iter();
            let events = std::cell::RefCell::new(Vec::new());
            let result = selection_mapping_bracket(
                0x1000,
                || {
                    events.borrow_mut().push("maps");
                    snapshots.next().ok_or(())
                },
                || {
                    events.borrow_mut().push("view");
                    view_same
                },
                || {
                    events.borrow_mut().push("pin");
                    pin_same
                },
            )
            .map(|_| ());
            (result, events.into_inner())
        }

        let stable =
            parse_maps(b"00001000-00002000 r--p 00000000 08:01 9 /opt/provider.so\n").unwrap();
        let remapped =
            parse_maps(b"00001000-00002000 r--p 00001000 08:01 9 /opt/provider.so\n").unwrap();
        let (result, events) = assess(stable.clone(), remapped, true, true);
        assert!(result.is_err());
        assert_eq!(events, ["maps", "maps", "view", "pin"]);
        assert!(
            assess(stable.clone(), stable.clone(), false, true)
                .0
                .is_err()
        );
        assert!(assess(stable.clone(), stable, true, false).0.is_err());
    }

    #[test]
    fn initial_export_generation_loss_queues_retirement_before_readiness() {
        let (_fixture, mut engine, mut session) = initial_export_route();
        let view = engine.views[0].id();
        session.lose_generation_at_dynamic_attach(engine.views[0].pid());
        let mut additions_allowed = true;
        let mut pending = PendingViewRetirements::new();
        let mut closure = PauseClosure::new(true);

        engine.attach_initial_exports(
            &mut session,
            &mut additions_allowed,
            &mut pending,
            &mut closure,
        );

        assert!(!additions_allowed);
        assert!(pending.contains_key(&view));
        assert!(!closure.required_complete());
    }

    #[test]
    fn loader_batch_route_adds_one_count_only_seed_without_table_surface() {
        let (_dir, mut engine, _context, record, mut session) = armed_seed_route(2);
        engine.capture_facts.next_module_id = 7;
        let first = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

        assert!(first.required_complete);
        assert_eq!(
            session
                .attached_slots
                .iter()
                .filter(|count| **count > 0)
                .count(),
            1
        );
        assert_eq!(engine.plan.entries_seen, 0);
        assert!(engine.plan.surfaces.is_empty());
        let binding = engine
            .selection_bindings
            .values()
            .next()
            .expect("the newly loader-discovered provider has a selection binding");
        let provider = engine
            .plan
            .modules
            .iter()
            .find(|module| module.object == binding.object)
            .expect("the selection hook owner has a committed provider module");
        assert_eq!(binding.provider, provider.id);
        assert_eq!(binding.provider, plan::ModuleId(7));
        assert_eq!(
            engine
                .plan
                .slots
                .iter()
                .filter(|slot| engine.plan.is_active(slot.index))
                .count(),
            1
        );
        assert_eq!(
            engine.plan.slots[0].names,
            ["C_GetFunctionList"],
            "the seed owns descriptor zero"
        );

        let second = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();
        assert!(second.required_complete);
        assert_eq!(
            session
                .attached_slots
                .iter()
                .filter(|count| **count > 0)
                .count(),
            1,
            "an exact repeated loader record does not reattach the seed"
        );
        assert_eq!(
            session.dynamic_attach_calls.len(),
            3,
            "an exact repeated loader record does not reattach the exports"
        );
        assert_eq!(
            engine
                .plan
                .slots
                .iter()
                .filter(|slot| engine.plan.is_active(slot.index))
                .count(),
            1
        );
    }

    #[test]
    fn terminal_loader_batch_route_seeds_without_dynamic_attach() {
        let (_fixture, mut engine, context, record, mut session) = armed_seed_route(1);
        engine
            .begin_terminal_drain(context, Vec::new(), || Ok::<(), anyhow::Error>(()))
            .unwrap()
            .unwrap();
        engine.retain_terminal_batch([record], true, 0).unwrap();
        let mut collect = Engine::collect_discovery_records;
        let terminal = engine
            .apply_discovery_batch_with(&mut session, Vec::new(), 0, true, true, &mut collect, None)
            .unwrap();

        assert!(terminal.required_complete);
        assert!(engine.loader_registry.context(context).is_none());
        assert!(session.dynamic_attach_calls.is_empty());
        assert_eq!(
            session
                .attached_slots
                .iter()
                .filter(|count| **count > 0)
                .count(),
            1,
            "the terminal replay does not attach a duplicate static seed"
        );
        assert_eq!(
            engine
                .plan
                .slots
                .iter()
                .filter(|slot| engine.plan.is_active(slot.index))
                .count(),
            1
        );
    }

    #[test]
    fn loader_batch_route_seed_target_failure_deactivates_slot() {
        let (_fixture, mut engine, _context, record, mut session) = armed_seed_route(1);
        session.fail_target_slots([0]);

        let outcome = apply_ordinary_batch(&mut engine, &mut session, vec![record]).unwrap();

        assert!(!outcome.required_complete);
        assert!(!engine.plan.is_active(0));
        assert_eq!(engine.plan.slots[0].descriptor_index, 0);
        assert_eq!(engine.plan.slots[0].names, ["C_GetFunctionList"]);
        assert_eq!(engine.plan.entries_seen, 0);
        assert!(engine.plan.surfaces.is_empty());
        assert_eq!(
            session
                .attached_slots
                .iter()
                .filter(|count| **count > 0)
                .count(),
            1
        );
        assert!(session.detached_slots.contains(&1));
    }

    #[test]
    fn exact_pinned_executable_export_collects_one_count_only_seed() {
        let (_fixture, view, module, pins) = loaded_seed_provider();
        let mut engine = Engine::empty();
        let candidate = engine
            .live_candidate(pins, vec![module.clone()], Vec::new())
            .unwrap();
        let object = candidate
            .pinned
            .id_for_scanned(&module, module.key, &module.path)
            .unwrap();
        let collected = engine.collect_dynamic_export_work(
            LoaderContextId::from_case_id(0),
            std::slice::from_ref(&module),
            &candidate.pinned,
            &ScriptedSession::default(),
            false,
            &[],
        );

        assert!(collected.required_seed_complete);
        assert_eq!(collected.count_only_seeds.len(), 1);
        assert_eq!(collected.count_only_seeds[0].object, object);
        assert_eq!(collected.count_only_seeds[0].object_path, module.path);
        assert_eq!(collected.dynamic.len(), 1);
        assert_eq!(collected.dynamic[0].object, object);
        assert!(
            candidate
                .plan
                .modules
                .iter()
                .any(|summary| summary.object == object)
        );
        assert_eq!(view.id(), module.view);
    }

    #[test]
    fn absent_pinned_export_marks_seed_incomplete_without_allocating_a_slot() {
        let (mut modules, pins) = pinned_self();
        let mut module = modules.pop().unwrap();
        module.exports = vec!["C_GetFunctionList".into()];
        let mut engine = Engine::empty();
        let candidate = engine
            .live_candidate(pins, vec![module.clone()], Vec::new())
            .unwrap();
        let collected = engine.collect_dynamic_export_work(
            LoaderContextId::from_case_id(0),
            std::slice::from_ref(&module),
            &candidate.pinned,
            &ScriptedSession::default(),
            false,
            &[],
        );

        assert!(!collected.required_seed_complete);
        assert!(collected.count_only_seeds.is_empty());
        assert!(collected.dynamic.is_empty());
        assert!(engine.counters.object_skips.iter().any(|skip| {
            skip.subject == "live export hook"
                && !skip.reason.contains(&module.path)
                && !skip.reason.contains("offset")
        }));
    }

    #[test]
    fn static_seed_attach_failure_detaches_and_deactivates_seed_slot() {
        let (_fixture, view, module, pins) = loaded_seed_provider();
        let mut engine = Engine::empty();
        engine.views.push(view);
        let mut candidate = engine
            .live_candidate(pins, vec![module.clone()], Vec::new())
            .unwrap();
        let object = candidate
            .pinned
            .id_for_scanned(&module, module.key, &module.path)
            .unwrap();
        let collected = engine.collect_dynamic_export_work(
            LoaderContextId::from_case_id(0),
            std::slice::from_ref(&module),
            &candidate.pinned,
            &ScriptedSession::default(),
            false,
            &[],
        );
        let seed = &collected.count_only_seeds[0];
        let owner = candidate
            .plan
            .modules
            .iter()
            .find(|summary| summary.object == object)
            .unwrap()
            .id;
        let slot = candidate
            .plan
            .add_provisional_get_function_list(plan::ProvisionalGetFunctionList {
                module: owner,
                object: seed.object,
                object_path: seed.object_path.clone(),
                file_offset: seed.file_offset,
            })
            .unwrap()
            .unwrap();
        candidate.delta.new.push(slot.clone());

        let mut session = ScriptedSession::default();
        session.fail_target_slots([slot.index]);
        let mut additions_allowed = true;
        let outcome = engine
            .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
            .unwrap();

        assert!(!outcome.required_complete());
        assert_eq!(session.attached_slots, [1]);
        assert_eq!(session.detached_slots, [0, 1]);
        assert!(!engine.plan.is_active(slot.index));
        assert_eq!(engine.plan.slots[slot.index as usize].descriptor_index, 0);
        assert_eq!(
            engine.plan.slots[slot.index as usize].names,
            ["C_GetFunctionList"]
        );
        assert_eq!(engine.plan.entries_seen, 0);
        assert!(engine.plan.surfaces.is_empty());
    }

    #[test]
    fn static_seed_preflight_refusal_keeps_accepted_plan_and_links_unchanged() {
        let (_fixture, view, module, pins) = loaded_seed_provider();
        let mut engine = Engine::empty();
        engine.views.push(view);
        let mut candidate = engine
            .live_candidate(pins, vec![module.clone()], Vec::new())
            .unwrap();
        let object = candidate
            .pinned
            .id_for_scanned(&module, module.key, &module.path)
            .unwrap();
        let owner = candidate
            .plan
            .modules
            .iter()
            .find(|summary| summary.object == object)
            .unwrap()
            .id;
        let seed = CountOnlySeedWork {
            object,
            object_path: module.path.clone(),
            file_offset: ElfSnapshot::read(candidate.pinned.file_for(object).unwrap())
                .unwrap()
                .defined_symbol("C_GetFunctionList")
                .unwrap()
                .unwrap()
                .file_offset,
        };
        let slot = candidate
            .plan
            .add_provisional_get_function_list(plan::ProvisionalGetFunctionList {
                module: owner,
                object: seed.object,
                object_path: seed.object_path,
                file_offset: seed.file_offset,
            })
            .unwrap()
            .unwrap();
        candidate.delta.new.push(slot);
        let accepted_plan = engine.plan.clone();
        let mut session = ScriptedSession::refusing_preflight();
        let mut additions_allowed = true;
        let outcome = engine
            .apply_candidate(&mut session, candidate, &mut additions_allowed, false, &[])
            .unwrap();

        assert!(outcome.refused());
        assert!(!outcome.required_complete());
        assert_eq!(engine.plan, accepted_plan);
        assert!(session.attached_slots.is_empty());
        assert!(session.detached_slots.is_empty());
    }

    /// Two provider modules over two distinct executable objects the live
    /// child really mapped.
    fn child_provider_modules(view: &ProcessView) -> Vec<ScannedModule> {
        for _ in 0..200 {
            let bytes = std::fs::read(format!("/proc/{}/maps", view.pid())).unwrap();
            let maps = parse_maps(&bytes).unwrap();
            let mut keys = BTreeSet::new();
            let mut modules = Vec::new();
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
                if !keys.insert(ObjectKey::of(mapping)) {
                    continue;
                }
                modules.push(provider_module(view, mapping, &path, 0x1000));
                if modules.len() == 2 {
                    return modules;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the live child never mapped two distinct file-backed objects");
    }

    fn pin_test_modules(view: &ProcessView, modules: &[ScannedModule]) -> PinnedObjects {
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        });
        let (pins, skipped) = pin_scanned_view_objects(view, modules, &mut budget).unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        pins
    }

    /// A live child, an Engine that retains one process view on it, and one
    /// accepted provider already attached in slot 0. The returned modules are
    /// `[accepted, peer]`; the peer is what a later candidate allocates.
    fn engine_with_one_accepted_provider() -> (std::process::Child, Engine, Vec<ScannedModule>) {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let view = ProcessView::open(ProcessViewId(3), child.id()).unwrap();
        let modules = child_provider_modules(&view);
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(child.id());
        engine.next_view_id = 4;
        engine.views.push(view);
        let pins = pin_test_modules(&engine.views[0], &modules[..1]);
        let candidate = engine
            .live_candidate(pins, vec![modules[0].clone()], Vec::new())
            .unwrap();
        assert_eq!(candidate.delta.new.len(), 1);
        let mut session = ScriptedSession::default();
        let mut additions = true;
        let outcome = engine
            .apply_candidate(&mut session, candidate, &mut additions, false, &[])
            .unwrap();
        assert!(outcome.accepted(), "the first candidate is accepted whole");
        assert_eq!(engine.plan.slots.len(), 1);
        assert!(engine.plan.module_of_slot(0).is_some());
        (child, engine, modules)
    }

    /// The candidate that allocates one more cell for the peer provider.
    fn peer_candidate(engine: &mut Engine, modules: &[ScannedModule]) -> LiveCandidate {
        let mut pins = engine.pinned.clone();
        let skipped = pins.absorb(pin_test_modules(&engine.views[0], &modules[1..2]));
        let candidate = engine
            .live_candidate(pins, modules.to_vec(), skipped)
            .unwrap();
        assert_eq!(
            candidate.delta.new.len(),
            1,
            "only the peer provider is newly allocated"
        );
        assert_eq!(candidate.plan.slots.len(), 2);
        candidate
    }

    #[test]
    fn post_mutation_generation_loss_never_owns_the_cell_it_allocated() {
        let (child, mut engine, modules) = engine_with_one_accepted_provider();
        let accepted_owner = engine.plan.module_of_slot(0);
        let candidate = peer_candidate(&mut engine, &modules);
        let mut session = ScriptedSession::losing_generation_at_attach(child.id());
        let mut additions = true;

        let outcome = engine
            .apply_candidate(&mut session, candidate, &mut additions, false, &[])
            .unwrap();

        assert!(!outcome.stale_views.is_empty(), "the generation was lost");
        assert_eq!(
            engine.plan.slots.len(),
            2,
            "an allocated endpoint is never given back"
        );
        assert!(!engine.plan.is_active(0));
        assert!(!engine.plan.is_active(1));
        assert_eq!(
            engine.plan.module_of_slot(1),
            None,
            "a cell this candidate allocated but never got accepted owns nothing"
        );
        assert_eq!(
            engine.plan.module_of_slot(0),
            accepted_owner,
            "an owner already accepted before the candidate stays valid"
        );
        assert_eq!(engine.plan.module_ambiguous, 0);
        assert_eq!(
            engine.pinned.pinned().count(),
            0,
            "the stale view's live pins are cleaned"
        );
        assert!(engine.modules.is_empty());
        assert!(!additions);
        assert!(!outcome.required_complete());
    }

    #[test]
    fn generation_loss_cleanup_finishes_after_one_failed_detach() {
        let (child, mut engine, modules) = engine_with_one_accepted_provider();
        let accepted_owner = engine.plan.module_of_slot(0);
        let candidate = peer_candidate(&mut engine, &modules);
        let mut session = ScriptedSession::losing_generation_at_attach(child.id());
        session.fail_slot_detaches([false, false, true]);
        let mut additions = true;

        let outcome = engine
            .apply_candidate(&mut session, candidate, &mut additions, false, &[])
            .unwrap();

        assert_eq!(
            session.detached_slots.len(),
            3,
            "the failed one-shot cleanup detach was not retried"
        );
        assert_eq!(session.detached_slots[2], 2, "both endpoints were retired");
        assert!(
            engine
                .counters
                .object_skips
                .iter()
                .any(|skip| skip.subject == "live discovery detach"),
            "{:?}",
            engine.counters.object_skips
        );
        assert_eq!(engine.plan.module_of_slot(1), None);
        assert_eq!(engine.plan.module_of_slot(0), accepted_owner);
        assert_eq!(
            engine.pinned.pinned().count(),
            0,
            "cleanup finished past the detach failure"
        );
        assert!(engine.modules.is_empty());
        assert!(!additions);
        assert!(!outcome.required_complete());
    }

    #[test]
    fn a_history_preparation_failure_never_enters_the_link_mutation() {
        let (mut child, mut engine, modules) = engine_with_one_accepted_provider();
        let candidate = peer_candidate(&mut engine, &modules);
        let plan = engine.plan.clone();
        let pins = engine.pinned.pinned().count();
        // The accepted manifest history lost its source ordinals, so no
        // candidate of this Engine can publish provider history.
        engine.manifest_ordinals.push(0);
        let mut session = ScriptedSession::default();
        let mut additions = true;

        let error = engine
            .apply_candidate(&mut session, candidate, &mut additions, false, &[])
            .err()
            .expect("history preparation refuses the candidate");

        assert!(
            format!("{error:#}").contains("source ordinals"),
            "{error:#}"
        );
        assert!(
            session.detached_slots.is_empty() && session.attached_slots.is_empty(),
            "the link-mutation closure was never entered"
        );
        assert_eq!(engine.plan, plan, "the accepted plan is unchanged");
        assert_eq!(engine.pinned.pinned().count(), pins);
        assert!(additions, "a pre-mutation refusal keeps the additions gate");
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn a_post_mutation_retirement_is_not_an_accepted_candidate() {
        let (child, mut engine, modules) = engine_with_one_accepted_provider();
        let view = engine.views[0].id();
        let candidate = peer_candidate(&mut engine, &modules);
        let mut session = ScriptedSession::losing_generation_at_attach(child.id());
        let mut additions = true;

        let retired = engine
            .apply_candidate(&mut session, candidate, &mut additions, false, &[])
            .unwrap();

        assert_eq!(
            retired.disposition,
            ApplyDisposition::ConservativeRetirement,
            "a conservative post-mutation retirement is not an accepted candidate"
        );
        assert!(!retired.accepted());
        let mut closure = PauseClosure::new(true);
        closure.observe_apply(&retired);
        assert!(
            !closure.required_complete(),
            "a retired candidate cannot confirm pause completeness"
        );
        let mut pending = PendingViewRetirements::new();
        engine.pending_retirements.insert(view);
        engine.queue_conservative_outcome(
            &retired,
            &[view].into_iter().collect(),
            &BTreeSet::new(),
            &mut pending,
        );
        assert!(
            engine.pending_retirements.is_empty(),
            "conservative cleanup clears the retry intent it consumed"
        );

        let refused_candidate = engine
            .live_candidate(engine.pinned.clone(), Vec::new(), Vec::new())
            .unwrap();
        let mut refusing = ScriptedSession::refusing_preflight();
        let refused = engine
            .apply_candidate(&mut refusing, refused_candidate, &mut additions, false, &[])
            .unwrap();

        assert!(refused.refused());
        engine.pending_retirements.insert(view);
        engine.queue_conservative_outcome(
            &refused,
            &[view].into_iter().collect(),
            &BTreeSet::new(),
            &mut pending,
        );
        assert_eq!(
            engine.pending_retirements,
            [view].into_iter().collect(),
            "a refusal retains the retry intent it never consumed"
        );
    }

    #[test]
    fn a_failed_start_returns_its_own_error_after_restoring_publication() {
        let (mut engine, _, _, _) = engine_with_overlay(58);
        engine
            .capture_facts
            .bind_plan_module_ids(&mut engine.plan, &engine.modules, &[], &engine.pinned)
            .unwrap();
        engine.publish_current_capture_facts().unwrap();
        let owner = engine.plan.module_of_slot(0);
        let snapshot = engine.begin_start_capture_attempt().unwrap();

        // A post-link rebuild has to re-derive this registry; restoration must
        // not depend on it, and must never speak over the original failure.
        engine
            .capture_facts
            .module_keys
            .insert(plan::ModuleId(0), timing_key(0));

        let result: Result<()> =
            engine.finish_start_capture_attempt(snapshot, Err(anyhow!("late loader failure")));

        assert_eq!(
            format!("{}", result.unwrap_err()),
            "late loader failure",
            "restoration must not obscure the original start failure"
        );
        assert_eq!(engine.plan.module_of_slot(0), owner);
        assert!(engine.capture_facts.staged.is_none());
        assert_eq!(engine.discovery.modules.len(), 1);
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

        if refused.accepted() {
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
        let queued = tagged_by_authority(context, &snapshot, record);
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
            selection_binding: None,
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
        let other = tagged_by_authority(context, &snapshot, record);
        assert_eq!(other.terminal_owner, None);
        assert!(other.terminal_exports.is_empty());
    }

    #[test]
    fn terminal_authority_tags_every_matching_record_in_the_owned_batch() {
        let owner = LoaderContextId::from_case_id(2);
        let export = DynamicExportIdentity {
            object: PinnedObjectId(7),
            file_offset: 0x10,
            cookie: 1,
            abi: HookAbi::FunctionList,
        };
        let mut matching: DiscoveryRecord = unsafe { std::mem::zeroed() };
        matching.kind = DISCOVERY_KIND_LOADER;
        matching.case_id = (owner.get() - 1) as u8;
        let mut unrelated = matching;
        unrelated.case_id = unrelated.case_id.wrapping_add(1);
        let mut records = [matching, matching, unrelated].map(|record| QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        });
        let authority = TerminalAuthority {
            owner,
            exports: vec![export],
        };

        assert!(authority.tag_matching(&mut records));
        assert_eq!(
            records
                .iter()
                .map(|record| record.terminal_owner)
                .collect::<Vec<_>>(),
            [Some(owner), Some(owner), None]
        );
        assert_eq!(records[0].terminal_exports, [export]);
        assert_eq!(records[1].terminal_exports, [export]);
        assert!(records[2].terminal_exports.is_empty());
    }

    #[test]
    fn terminal_authority_tags_selection_by_binding_not_request_class() {
        let owner = LoaderContextId::from_case_id(2);
        let export = DynamicExportIdentity {
            object: PinnedObjectId(7),
            file_offset: 0x10,
            cookie: 41,
            abi: HookAbi::Interface,
        };
        let mut matching: DiscoveryRecord = unsafe { std::mem::zeroed() };
        matching.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        matching.case_id = DISCOVERY_NAME_NULL;
        matching.binding_id = export.cookie;
        let mut wrong_binding = matching;
        wrong_binding.binding_id += 1;
        let mut records = [matching, wrong_binding].map(|record| QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        });

        assert!(
            (TerminalAuthority {
                owner,
                exports: vec![export],
            })
            .tag_matching(&mut records)
        );
        assert_eq!(records[0].terminal_owner, Some(owner));
        assert_eq!(records[0].terminal_exports, [export]);
        assert_eq!(records[1].terminal_owner, None);
        assert!(records[1].terminal_exports.is_empty());
    }

    #[test]
    fn predispatch_failure_returns_the_exact_batch_for_one_retry() {
        let record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        let records = vec![QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }];

        let (error, retained) = match begin_discovery_batch(records, Err(anyhow!("counter read"))) {
            Err(retained) => retained,
            Ok(_) => panic!("predispatch failure must keep ownership unconsumed"),
        };
        assert!(error.to_string().contains("counter read"));
        assert_eq!(retained.len(), 1);

        let dispatching = match begin_discovery_batch(retained, Ok(())) {
            Ok(dispatching) => dispatching,
            Err(_) => panic!("the retained batch must begin exactly once"),
        };
        assert_eq!(dispatching.len(), 1);
    }

    #[test]
    fn generic_batches_cannot_consume_or_tag_terminal_authority() {
        let owner = LoaderContextId::from_case_id(2);
        let authority = TerminalAuthority {
            owner,
            exports: Vec::new(),
        };
        let mut engine = Engine::empty();
        engine.terminal_journal = Some(TerminalJournal {
            owner,
            dispatch_started: false,
            retry_used: false,
        });
        engine.terminal_batch = Some(TerminalBatch::empty(authority));
        let queued = |case_id| {
            let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
            record.kind = DISCOVERY_KIND_LOADER;
            record.case_id = case_id;
            QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }
        };
        let unrelated = [queued(((owner.get() - 1) as u8).wrapping_add(1))];
        let matching = queued((owner.get() - 1) as u8);

        assert_eq!(unrelated[0].terminal_owner, None);
        engine
            .retain_terminal_batch([matching.record, matching.record], true, 0)
            .unwrap();
        assert!(
            engine
                .terminal_batch
                .as_ref()
                .unwrap()
                .records
                .iter()
                .all(|record| record.terminal_owner == Some(owner))
        );
        assert!(engine.terminal_journal.is_some());
    }

    #[test]
    fn a_second_terminal_authority_is_rejected_without_replacing_the_first() {
        let (registry, first) = prepared_loader_registry();
        let second = LoaderContextId::from_case_id(2);
        let mut engine = Engine::empty();
        engine.loader_registry = registry;
        engine.loader_registry.mark_attached(first).unwrap();
        let deferred = engine
            .begin_terminal_drain(first, Vec::new(), || Err::<(), _>(anyhow!("deferred")))
            .unwrap();
        assert!(deferred.is_err());

        let error = engine
            .begin_terminal_drain(second, Vec::new(), || Ok(()))
            .unwrap_err();

        assert!(error.to_string().contains("already pending"), "{error:#}");
        assert_eq!(
            engine
                .terminal_journal
                .as_ref()
                .map(|journal| journal.owner),
            Some(first)
        );
    }

    #[test]
    fn fallible_terminal_drain_keeps_tombstoned_authority_for_retry() {
        let (registry, context) = prepared_loader_registry();
        let export = DynamicExportIdentity {
            object: PinnedObjectId(7),
            file_offset: 0x10,
            cookie: 1,
            abi: HookAbi::FunctionList,
        };
        let mut engine = Engine::empty();
        engine.loader_registry = registry;
        engine.loader_registry.mark_attached(context).unwrap();

        let drained = engine
            .begin_terminal_drain(context, vec![export], || Err::<(), _>(anyhow!("deferred")))
            .unwrap();

        assert!(drained.is_err());
        assert!(engine.loader_registry.is_tombstoned(context));
        let batch = engine.terminal_batch.as_ref().unwrap();
        assert_eq!(batch.authority.owner, context);
        assert_eq!(batch.authority.exports, [export]);
        assert!(!batch.complete());

        assert!(engine.terminal_batch.is_some());
        assert!(engine.terminal_journal.is_some());
        engine.loader_registry.remove(context).unwrap();
    }

    #[test]
    fn terminal_predispatch_counter_failure_uses_one_retry_before_cleanup() {
        let (registry, context) = prepared_loader_registry();
        let mut engine = Engine::empty();
        engine.loader_registry = registry;
        engine.loader_registry.mark_attached(context).unwrap();
        engine
            .begin_terminal_drain(context, Vec::new(), || Err::<(), _>(anyhow!("deferred")))
            .unwrap()
            .unwrap_err();
        let mut additions_allowed = true;
        let mut closure = PauseClosure::new(true);

        engine.retry_terminal_predispatch_failure(&mut additions_allowed, &mut closure);

        assert!(engine.terminal_journal.as_ref().unwrap().retry_used);
        assert!(engine.loader_registry.is_tombstoned(context));
        assert!(engine.terminal_batch.is_some());

        engine.retry_terminal_predispatch_failure(&mut additions_allowed, &mut closure);

        assert!(engine.terminal_journal.is_none());
        assert!(engine.terminal_batch.is_none());
        assert!(engine.loader_registry.context(context).is_none());
        assert!(!additions_allowed);
        assert!(!closure.required_complete());
    }

    /// One record put through the real production authority-tagging path.
    fn tagged_by_authority(
        owner: LoaderContextId,
        exports: &[DynamicExportIdentity],
        record: DiscoveryRecord,
    ) -> QueuedDiscoveryRecord {
        let mut batch = TerminalBatch::empty(TerminalAuthority {
            owner,
            exports: exports.to_vec(),
        });
        batch.extend([record]);
        batch
            .records
            .into_iter()
            .next()
            .expect("the authority batch holds the extended record")
    }

    fn terminal_export() -> DynamicExportIdentity {
        DynamicExportIdentity {
            object: PinnedObjectId(7),
            file_offset: 0x10,
            cookie: 1,
            abi: HookAbi::FunctionList,
        }
    }

    fn closed_terminal_selection(
        engine: &mut Engine,
        owner: LoaderContextId,
        pid: u32,
    ) -> (DynamicExportIdentity, DiscoveryRecord) {
        let identity = DynamicExportIdentity {
            object: PinnedObjectId(7),
            file_offset: 0x20,
            cookie: 2,
            abi: HookAbi::Interface,
        };
        engine.selection_bindings.insert(
            identity.cookie,
            SelectionBindingFact {
                id: identity.cookie,
                context: owner,
                view: ProcessViewId(0),
                object: identity.object,
                file_offset: identity.file_offset,
                hook_id: HookRegistry::builtin().id("C_GetInterface").unwrap(),
                abi: identity.abi,
                attached: true,
                retired: false,
                provider: plan::ModuleId(0),
                observed: false,
                coverage: SelectionCoverageState::OwnedClosed(NonZeroU64::new(1).unwrap()),
            },
        );
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_INTERFACE_RETURN;
        record.pid_tgid = u64::from(pid) << 32;
        record.binding_id = identity.cookie;
        (identity, record)
    }

    fn loader_record_for(context: LoaderContextId, pid: u32) -> DiscoveryRecord {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_LOADER;
        record.case_id = (context.get() - 1) as u8;
        record.pid_tgid = u64::from(pid) << 32;
        record
    }

    /// One ordinary non-terminal Engine batch through the real application
    /// route, with the real generic collector.
    fn apply_ordinary_batch(
        engine: &mut Engine,
        session: &mut ScriptedSession,
        records: Vec<DiscoveryRecord>,
    ) -> Result<DiscoveryBatchOutcome> {
        let mut collect = Engine::collect_discovery_records;
        engine.apply_discovery_batch_with(session, records, 0, true, false, &mut collect, None)
    }

    #[test]
    fn discovery_batch_deadline_is_cleared_after_success_and_error() {
        let (_fixture, mut engine, _context, _record, mut session) = armed_seed_route(0);
        let mut collect = Engine::collect_discovery_records;
        engine
            .apply_discovery_batch_with(
                &mut session,
                Vec::new(),
                0,
                true,
                false,
                &mut collect,
                Some(1),
            )
            .unwrap();
        assert_eq!(engine.budget.deadline_for_test(), None);

        session.fail_counter_reads([true]);
        let mut collect = Engine::collect_discovery_records;
        assert!(
            engine
                .apply_discovery_batch_with(
                    &mut session,
                    Vec::new(),
                    0,
                    true,
                    false,
                    &mut collect,
                    Some(1),
                )
                .is_err()
        );
        assert_eq!(engine.budget.deadline_for_test(), None);
    }

    /// A real failed post-detach drain: the retirement route detaches,
    /// tombstones, and keeps an undispatched authority-bearing batch.
    fn start_failed_terminal_drain(
        engine: &mut Engine,
        session: &mut ScriptedSession,
        owner: LoaderContextId,
    ) {
        session
            .dequeues
            .push_back(Err(anyhow!("scripted ring read failed")));
        apply_ordinary_batch(engine, session, Vec::new())
            .expect("a failed terminal drain is loss, never a batch error");
        assert_eq!(
            engine.terminal_journal.map(|journal| journal.owner),
            Some(owner)
        );
        assert!(engine.loader_registry.is_tombstoned(owner));
    }

    #[test]
    fn rejected_terminal_cleanup_leaves_both_batch_owners_unchanged() {
        let pid = std::process::id();
        for case in [
            "missing journal",
            "mismatched journal owner",
            "dispatch started",
            "competing engine batch",
        ] {
            let (mut engine, owner) = Engine::retiring_loader_context(pid);
            let other = LoaderContextId::from_case_id(9);
            let export = terminal_export();
            let mut first = loader_record_for(owner, pid);
            first.hook_ts_ns = 11;
            let mut second = loader_record_for(other, pid);
            second.hook_ts_ns = 22;
            let mut returned = TerminalBatch::empty(TerminalAuthority {
                owner,
                exports: vec![export],
            });
            returned.extend([first, second]);
            returned.complete = true;
            let mut returned = Some(returned);

            match case {
                "missing journal" => {}
                "mismatched journal owner" => {
                    engine.terminal_journal = Some(TerminalJournal {
                        owner: other,
                        dispatch_started: false,
                        retry_used: true,
                    });
                }
                "dispatch started" => {
                    engine.terminal_journal = Some(TerminalJournal {
                        owner,
                        dispatch_started: true,
                        retry_used: true,
                    });
                }
                "competing engine batch" => {
                    engine.terminal_journal = Some(TerminalJournal {
                        owner,
                        dispatch_started: false,
                        retry_used: true,
                    });
                    engine.terminal_batch = Some(TerminalBatch::empty(TerminalAuthority {
                        owner: other,
                        exports: Vec::new(),
                    }));
                }
                _ => unreachable!(),
            }

            let batch_state = |batch: Option<&TerminalBatch>| {
                batch.map(|batch| {
                    (
                        batch.authority.owner,
                        batch.authority.exports.clone(),
                        batch.record_count(),
                        batch.complete(),
                        batch.tagged_owners(),
                    )
                })
            };
            let journal = engine.terminal_journal_for_test();
            let engine_batch = batch_state(engine.terminal_batch.as_ref());
            let registry = engine.loader_context_state_for_test(owner);
            let skips = engine.counters.object_skips.clone();
            let plan = engine.plan.clone();
            let truncated = engine.capture_facts().discovery_truncated;
            let dispatched = engine.dispatched_loader_records();

            let error = engine
                .cleanup_terminal_batch_without_replay(&mut returned)
                .unwrap_err();

            assert!(!error.to_string().is_empty(), "{case}");
            let returned = returned.as_ref().expect("coordinator keeps its batch");
            assert_eq!(returned.authority.owner, owner, "{case}");
            assert_eq!(returned.authority.exports, [export], "{case}");
            assert_eq!(returned.record_count(), 2, "{case}");
            assert!(returned.complete(), "{case}");
            assert_eq!(returned.tagged_owners(), [Some(owner), None], "{case}");
            assert_eq!(returned.records[0].record.hook_ts_ns, 11, "{case}");
            assert_eq!(
                returned.records[0].record.pid_tgid,
                u64::from(pid) << 32,
                "{case}"
            );
            assert_eq!(returned.records[1].record.hook_ts_ns, 22, "{case}");
            assert_eq!(
                returned.records[1].record.pid_tgid,
                u64::from(pid) << 32,
                "{case}"
            );
            assert_eq!(engine.terminal_journal_for_test(), journal, "{case}");
            assert_eq!(
                batch_state(engine.terminal_batch.as_ref()),
                engine_batch,
                "{case}"
            );
            assert_eq!(
                engine.loader_context_state_for_test(owner),
                registry,
                "{case}"
            );
            assert_eq!(engine.counters.object_skips, skips, "{case}");
            assert_eq!(engine.plan, plan, "{case}");
            assert_eq!(
                engine.capture_facts().discovery_truncated,
                truncated,
                "{case}"
            );
            assert_eq!(engine.dispatched_loader_records(), dispatched, "{case}");
        }
    }

    #[test]
    fn terminal_cleanup_consumes_once_then_retries_only_registry_removal() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let other = LoaderContextId::from_case_id(9);
        let export = terminal_export();
        let (selection_export, selection_record) =
            closed_terminal_selection(&mut engine, owner, pid);
        let mut returned = TerminalBatch::empty(TerminalAuthority {
            owner,
            exports: vec![export, selection_export],
        });
        returned.extend([
            loader_record_for(owner, pid),
            loader_record_for(other, pid),
            selection_record,
        ]);
        returned.complete = true;
        let mut returned = Some(returned);
        engine.terminal_journal = Some(TerminalJournal {
            owner,
            dispatch_started: false,
            retry_used: true,
        });
        let plan = engine.plan.clone();
        let truncated = engine.capture_facts().discovery_truncated;
        let malformed = engine.malformed_discovery_for_test();
        let pending = engine.pending_discovery_records_for_test();

        let error = engine
            .cleanup_terminal_batch_without_replay(&mut returned)
            .unwrap_err();

        assert!(error.to_string().contains("not tombstoned"), "{error:#}");
        assert!(returned.is_none(), "the coordinator batch was consumed");
        assert_eq!(
            engine.selection_bindings[&selection_export.cookie].coverage,
            SelectionCoverageState::Uncovered
        );
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(
            engine.terminal_journal_for_test(),
            Some((owner, true, true))
        );
        assert_eq!(engine.loader_context_state_for_test(owner), Some("live"));
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert_eq!(engine.counters.object_skips.len(), 1);
        assert_eq!(
            engine.counters.object_skips[0].subject,
            TERMINAL_DRAIN_SUBJECT
        );
        assert_eq!(
            engine.counters.object_skips[0].reason,
            "the bounded terminal cleanup retry failed; its undispatched batch was discarded without replay"
        );
        assert_eq!(engine.plan, plan);
        assert_eq!(engine.capture_facts().discovery_truncated, truncated);
        assert_eq!(engine.malformed_discovery_for_test(), malformed);
        assert_eq!(engine.pending_discovery_records_for_test(), pending);

        engine.tombstone_loader_context_for_test(owner);
        let skips = engine.counters.object_skips.clone();
        engine.cleanup_started_terminal_journal().unwrap();

        assert_eq!(engine.terminal_journal_for_test(), None);
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.loader_context_state_for_test(owner), None);
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert_eq!(engine.counters.object_skips, skips);
        assert_eq!(engine.plan, plan);
        assert_eq!(engine.capture_facts().discovery_truncated, truncated);
        assert_eq!(engine.malformed_discovery_for_test(), malformed);
        assert_eq!(engine.pending_discovery_records_for_test(), pending);
    }

    #[test]
    fn generic_apply_and_replay_never_consume_the_retained_terminal_authority() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let view = engine.views[0].id();
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        start_failed_terminal_drain(&mut engine, &mut session, owner);

        // No retirement is due, so an ordinary batch cannot reach the authority.
        engine.retirement_intents.remove(&view);
        apply_ordinary_batch(
            &mut engine,
            &mut session,
            vec![loader_record_for(unrelated, pid)],
        )
        .unwrap();

        assert_eq!(engine.loader_records_accepted, 1);
        let batch = engine.terminal_batch.as_ref().unwrap();
        assert_eq!(
            batch.record_count(),
            0,
            "a generic batch cannot enter the authority batch"
        );
        assert!(!batch.complete());
        assert_eq!(batch.authority.exports, [terminal_export()]);
        assert!(!engine.terminal_journal.unwrap().dispatch_started);

        // The coordinator now owns the exact batch; a retirement replay may
        // neither reconstruct nor dispatch it behind the coordinator's back.
        let carried = engine.take_terminal_batch_for_deferred().unwrap();
        engine
            .retirement_intents
            .insert(view, RetirementCause::ExecRefresh);
        apply_ordinary_batch(
            &mut engine,
            &mut session,
            vec![loader_record_for(unrelated, pid)],
        )
        .unwrap();

        assert_eq!(
            engine.loader_records_accepted, 2,
            "only the two generic records were dispatched"
        );
        assert!(engine.terminal_batch.is_none());
        assert_eq!(
            engine
                .terminal_journal
                .map(|journal| (journal.owner, journal.dispatch_started)),
            Some((owner, false))
        );
        assert!(engine.loader_registry.is_tombstoned(owner));
        assert_eq!(carried.authority.owner, owner);
    }

    /// The failed-drain record announces a *retry*: "the exact terminal batch
    /// remains tombstoned for retry". While the journal is pending that is
    /// true. Once the retry lands and the journal clears, nothing remains
    /// tombstoned and the announcement is contradicted by the same document
    /// that carries it — so capture end judges it, like the empty-scan rule.
    #[test]
    fn a_terminal_drain_the_capture_retried_is_not_a_published_loss() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        start_failed_terminal_drain(&mut engine, &mut session, owner);

        let announced = Skipped {
            subject: TERMINAL_DRAIN_SUBJECT.into(),
            reason: TERMINAL_DRAIN_RETRY_REASON.into(),
        };
        assert_eq!(
            announced.reason,
            "the post-detach private discovery drain failed; the exact terminal batch remains \
             tombstoned for retry",
            "the published reason is unchanged"
        );
        assert!(
            engine.plan.skipped.contains(&announced),
            "a failed drain announces its retry: {:?}",
            engine.plan.skipped
        );

        // Still owed at capture end: the announcement is true and stands.
        engine.settle_terminal_drain();
        assert!(engine.plan.skipped.contains(&announced));

        session.dequeues.extend(
            [
                loader_record_for(owner, pid),
                loader_record_for(unrelated, pid),
            ]
            .map(|record| Ok(Some(crate::events::DiscoveryItem::Record(record)))),
        );
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
        assert!(engine.terminal_journal.is_none(), "the retry landed");

        engine.settle_terminal_drain();
        assert!(
            !engine.plan.skipped.contains(&announced),
            "a retry the capture proved leaves nothing tombstoned: {:?}",
            engine.plan.skipped
        );
        assert!(
            !engine.counters.object_skips.contains(&announced),
            "and nothing to rebuild the record from"
        );
    }

    #[test]
    fn an_incomplete_terminal_drain_is_continued_and_dispatched_exactly_once() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        start_failed_terminal_drain(&mut engine, &mut session, owner);

        session.dequeues.extend(
            [
                loader_record_for(owner, pid),
                loader_record_for(owner, pid),
                loader_record_for(unrelated, pid),
            ]
            .map(|record| Ok(Some(crate::events::DiscoveryItem::Record(record)))),
        );
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 3,
            "the continued batch dispatched every collected record once"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(engine.terminal_journal.is_none());
        assert!(engine.loader_registry.context(owner).is_none());

        engine
            .retirement_intents
            .insert(engine.views[0].id(), RetirementCause::ExecRefresh);
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 3,
            "a consumed terminal batch is never collected or dispatched again"
        );
    }

    #[test]
    fn a_mid_drain_ring_failure_retains_the_already_dequeued_prefix() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        // The post-detach drain takes two records off the ring, then fails.
        session.dequeues.extend([
            Ok(Some(crate::events::DiscoveryItem::Record(
                loader_record_for(owner, pid),
            ))),
            Ok(Some(crate::events::DiscoveryItem::Record(
                loader_record_for(unrelated, pid),
            ))),
            Err(anyhow!("scripted ring read failed")),
        ]);

        apply_ordinary_batch(&mut engine, &mut session, Vec::new())
            .expect("a failed terminal drain is loss, never a batch error");

        assert_eq!(
            engine.loader_records_accepted, 0,
            "an incomplete batch dispatches nothing"
        );
        let batch = engine.terminal_batch.as_ref().unwrap();
        assert_eq!(
            batch.record_count(),
            2,
            "the records already off the ring stay in the retained prefix"
        );
        assert!(!batch.complete());
        assert_eq!(
            batch.tagged_owners(),
            [Some(owner), None],
            "only the owned record of the retained prefix carries authority"
        );
        let journal = engine.terminal_journal.unwrap();
        assert!(!journal.dispatch_started && !journal.retry_used);

        // The one shared continuation finishes the drain and dispatches once.
        session
            .dequeues
            .push_back(Ok(Some(crate::events::DiscoveryItem::Record(
                loader_record_for(owner, pid),
            ))));
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 3,
            "every dequeued record reached dispatch exactly once"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(engine.terminal_journal.is_none());
        assert!(engine.loader_registry.context(owner).is_none());
    }

    /// The post-detach collector shares the quantum. A stop there is retained
    /// as an explicitly incomplete batch — never claimed complete, nothing
    /// dispatched — and the one shared continuation finishes it once the ring
    /// reads empty, dispatching every dequeued record exactly once.
    #[test]
    fn a_quantum_stop_after_detach_retains_an_incomplete_batch_until_the_ring_reads_empty() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records([], 1024);
        session.detach_exports = vec![terminal_export()];
        session
            .dequeues
            .push_back(Ok(Some(crate::events::DiscoveryItem::Record(
                loader_record_for(owner, pid),
            ))));
        session
            .dequeues
            .extend((1..=LIVE_DISCOVERY_DRAIN_QUANTUM).map(|_| {
                Ok(Some(crate::events::DiscoveryItem::Record(
                    loader_record_for(unrelated, pid),
                )))
            }));
        session
            .dequeues
            .push_back(Err(anyhow!("dequeued past the quantum")));

        apply_ordinary_batch(&mut engine, &mut session, Vec::new())
            .expect("a quantum stop is backlog, never a batch error");

        assert_eq!(
            engine.loader_records_accepted, 0,
            "an incomplete batch dispatches nothing"
        );
        let batch = engine.terminal_batch.as_ref().unwrap();
        assert_eq!(batch.record_count(), LIVE_DISCOVERY_DRAIN_QUANTUM);
        assert!(
            !batch.complete(),
            "a quantum stop never claims a complete drain"
        );
        assert_eq!(
            session.dequeues.len(),
            2,
            "the record past the quantum and the sentinel stay queued"
        );
        assert!(engine.terminal_journal.is_some());

        session.dequeues.pop_back();
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted as usize,
            LIVE_DISCOVERY_DRAIN_QUANTUM + 1,
            "every dequeued record reached dispatch exactly once"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(engine.terminal_journal.is_none());
        assert!(engine.loader_registry.context(owner).is_none());
    }

    /// The terminal sink charges too: a retained prefix is dequeued work even
    /// while nothing has been dispatched yet.
    #[test]
    fn a_retained_terminal_prefix_is_charged_as_capture_work() {
        const WORK_CEILING: u64 = 16 * 1024 * 1024;
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        assert!(
            engine
                .budget
                .charge(WORK_CEILING - LIVE_DISCOVERY_DRAIN_QUANTUM as u64)
        );
        let mut session = ScriptedSession::with_records([], 1024);
        session.detach_exports = vec![terminal_export()];
        session
            .dequeues
            .extend((0..=LIVE_DISCOVERY_DRAIN_QUANTUM).map(|_| {
                Ok(Some(crate::events::DiscoveryItem::Record(
                    loader_record_for(owner, pid),
                )))
            }));

        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(engine.loader_records_accepted, 0);
        assert!(!engine.terminal_batch.as_ref().unwrap().complete());
        assert!(
            !engine.budget.charge(1),
            "the retained quantum consumed the last work units"
        );
    }

    #[test]
    fn terminal_predispatch_counter_failure_retains_the_exact_batch_for_one_retry() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let unrelated = LoaderContextId::from_case_id(9);
        let (selection_export, selection_record) =
            closed_terminal_selection(&mut engine, owner, pid);
        let mut session = ScriptedSession::with_records(
            [
                loader_record_for(owner, pid),
                loader_record_for(owner, pid),
                loader_record_for(unrelated, pid),
                selection_record,
            ],
            16,
        );
        session.detach_exports = vec![terminal_export(), selection_export];
        session.fail_counter_reads([false, true]);

        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 0,
            "a predispatch counter failure dispatches nothing"
        );
        let batch = engine.terminal_batch.as_ref().unwrap();
        assert_eq!(batch.record_count(), 4);
        assert!(batch.complete());
        assert_eq!(batch.authority.owner, owner);
        assert_eq!(
            batch.authority.exports,
            [terminal_export(), selection_export]
        );
        assert_eq!(
            batch.tagged_owners(),
            [Some(owner), Some(owner), None, Some(owner)],
            "only the owned records carry terminal authority"
        );
        let journal = engine.terminal_journal.unwrap();
        assert!(journal.retry_used && !journal.dispatch_started);
        assert_eq!(
            engine.selection_bindings[&selection_export.cookie].coverage,
            SelectionCoverageState::OwnedClosed(NonZeroU64::new(1).unwrap()),
            "a retained retry does not invalidate the closed proof"
        );

        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 3,
            "the one retry dispatches the exact retained batch once"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(engine.terminal_journal.is_none());
        assert!(engine.loader_registry.context(owner).is_none());
    }

    #[test]
    fn an_exhausted_terminal_predispatch_retry_cleans_up_without_dispatching() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let (selection_export, selection_record) =
            closed_terminal_selection(&mut engine, owner, pid);
        let mut session =
            ScriptedSession::with_records([loader_record_for(owner, pid), selection_record], 16);
        session.detach_exports = vec![selection_export];
        session.fail_counter_reads([false, true]);

        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
        assert!(engine.terminal_journal.unwrap().retry_used);
        assert_eq!(
            engine.selection_bindings[&selection_export.cookie].coverage,
            SelectionCoverageState::OwnedClosed(NonZeroU64::new(1).unwrap())
        );

        session.fail_counter_reads([false, true]);
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 0,
            "an exhausted retry never replays the records it dropped"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(engine.terminal_journal.is_none());
        assert!(engine.loader_registry.context(owner).is_none());
        assert_eq!(
            engine.selection_bindings[&selection_export.cookie].coverage,
            SelectionCoverageState::Uncovered
        );
    }

    #[test]
    fn a_failed_owned_prearm_cleanup_uses_the_shared_predispatch_journal() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records(
            [
                loader_record_for(owner, pid),
                loader_record_for(unrelated, pid),
            ],
            16,
        );
        session.detach_exports = vec![terminal_export()];
        session.fail_counter_reads([true]);
        // A prior snapshot already authorized these hits, so only the routing
        // of the failed post-detach read is under test.
        engine.counter_snapshot = session.counters;
        let mut pending_views = PendingViewRetirements::new();

        let error = engine
            .fail_owned_prearm_attachment(
                owner,
                true,
                &mut session,
                &mut pending_views,
                "loader registry mark-attached failed".into(),
            )
            .unwrap_err();

        assert!(error.to_string().contains("mark-attached"), "{error:#}");
        assert_eq!(
            engine.loader_records_accepted, 0,
            "a failed post-detach counter snapshot dispatches nothing"
        );
        let batch = engine.terminal_batch.as_ref().unwrap();
        assert_eq!(batch.record_count(), 2);
        assert!(batch.complete());
        assert_eq!(batch.authority.exports, [terminal_export()]);
        assert_eq!(batch.tagged_owners(), [Some(owner), None]);
        let journal = engine.terminal_journal.unwrap();
        assert!(journal.retry_used && !journal.dispatch_started);
        assert!(
            engine.loader_registry.is_tombstoned(owner),
            "the tombstone survives the shared one retry"
        );

        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 2,
            "the shared retry dispatches the exact batch once"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(engine.terminal_journal.is_none());
        assert!(engine.loader_registry.context(owner).is_none());
    }

    #[test]
    fn a_failed_owned_prearm_drain_retains_its_dequeued_prefix() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        // The pre-arm drain takes one record off the ring, then the ring fails.
        session.dequeues.extend([
            Ok(Some(crate::events::DiscoveryItem::Record(
                loader_record_for(owner, pid),
            ))),
            Err(anyhow!("scripted ring read failed")),
        ]);
        let mut pending_views = PendingViewRetirements::new();

        let error = engine
            .fail_owned_prearm_attachment(
                owner,
                true,
                &mut session,
                &mut pending_views,
                "loader registry mark-attached failed".into(),
            )
            .unwrap_err();

        assert!(error.to_string().contains("mark-attached"), "{error:#}");
        assert_eq!(
            engine.loader_records_accepted, 0,
            "an incomplete batch dispatches nothing"
        );
        let batch = engine.terminal_batch.as_ref().unwrap();
        assert_eq!(
            batch.record_count(),
            1,
            "the record already off the ring stays in the retained prefix"
        );
        assert!(!batch.complete());
        assert_eq!(batch.tagged_owners(), [Some(owner)]);
        assert!(engine.loader_registry.is_tombstoned(owner));

        // The one shared continuation finishes the drain and dispatches once.
        session
            .dequeues
            .push_back(Ok(Some(crate::events::DiscoveryItem::Record(
                loader_record_for(owner, pid),
            ))));
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 2,
            "every dequeued record reached dispatch exactly once"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(engine.terminal_journal.is_none());
        assert!(engine.loader_registry.context(owner).is_none());
    }

    #[test]
    fn a_started_terminal_journal_retries_registry_cleanup_without_replaying_records() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records(
            [
                loader_record_for(owner, pid),
                loader_record_for(unrelated, pid),
            ],
            16,
        );
        session.fail_counter_reads([false, true]);
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
        assert_eq!(engine.loader_records_accepted, 0);

        // The tombstoned entry is gone before the retry, so the started journal
        // can never finish its cleanup.
        engine.loader_registry.remove(owner).unwrap();
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 2,
            "the retry dispatched the exact batch once"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(
            engine.terminal_journal.unwrap().dispatch_started,
            "a failed registry removal keeps the started journal pending"
        );

        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 2,
            "a started journal repeats only its registry removal"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(engine.terminal_journal.unwrap().dispatch_started);
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

        let index = MapIndex::new(&maps).unwrap();
        let (mapping, path) = exact_executable_mapping(&index, key).unwrap();
        assert_eq!(mapping.start, 0x3000, "inode alone is not full identity");
        assert_eq!(path, mapped, "pin through the mapping's usable alias");
        assert_ne!(path, interpreter, "PT_INTERP spelling is not map authority");
    }

    fn bounded_elf(interpreters: &[&[u8]]) -> Vec<u8> {
        let count = interpreters.len().max(1);
        let table_len = count * ELF_PROGRAM_HEADER_BYTES;
        let mut bytes = vec![0u8; ELF_HEADER_BYTES + table_len];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF_HEADER_BYTES as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF_HEADER_BYTES as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF_PROGRAM_HEADER_BYTES as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(count as u16).to_le_bytes());
        if interpreters.is_empty() {
            bytes[ELF_HEADER_BYTES..ELF_HEADER_BYTES + 4].copy_from_slice(&1u32.to_le_bytes());
            return bytes;
        }
        for (index, interpreter) in interpreters.iter().enumerate() {
            let program = ELF_HEADER_BYTES + index * ELF_PROGRAM_HEADER_BYTES;
            let offset = bytes.len() as u64;
            bytes[program..program + 4].copy_from_slice(&3u32.to_le_bytes());
            bytes[program + 8..program + 16].copy_from_slice(&offset.to_le_bytes());
            bytes[program + 32..program + 40]
                .copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
            bytes.extend_from_slice(interpreter);
        }
        bytes
    }

    fn bounded_interpreter(bytes: &[u8]) -> std::result::Result<Option<PathBuf>, String> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("executable");
        std::fs::write(&path, bytes).unwrap();
        let file = std::fs::File::open(path).unwrap();
        read_bounded_interpreter(&file, bytes.len() as u64)
    }

    #[test]
    fn bounded_pt_interp_reader_rejects_malformed_or_unbounded_elf() {
        assert_eq!(
            bounded_interpreter(&bounded_elf(&[b"/lib/ld.so\0"])),
            Ok(Some(PathBuf::from("/lib/ld.so")))
        );
        assert_eq!(bounded_interpreter(&bounded_elf(&[])), Ok(None));
        for interpreter in [
            &b"relative\0"[..],
            &b"/lib/ld.so"[..],
            &b"/lib/ld\0.so\0"[..],
            &b"\0"[..],
        ] {
            assert!(bounded_interpreter(&bounded_elf(&[interpreter])).is_err());
        }
        assert!(bounded_interpreter(&bounded_elf(&[b"/a\0", b"/b\0"])).is_err());
        let oversized = vec![b'a'; MAX_INTERPRETER_BYTES + 1];
        assert!(bounded_interpreter(&bounded_elf(&[&oversized])).is_err());

        let mut malformed = bounded_elf(&[b"/lib/ld.so\0"]);
        for index in [4usize, 5, 18, 52, 54] {
            let saved = malformed[index];
            malformed[index] = 0;
            assert!(
                bounded_interpreter(&malformed).is_err(),
                "accepted byte {index}"
            );
            malformed[index] = saved;
        }
        malformed[56..58].copy_from_slice(&0xffffu16.to_le_bytes());
        assert!(bounded_interpreter(&malformed).is_err());

        let mut out_of_bounds = bounded_elf(&[b"/lib/ld.so\0"]);
        out_of_bounds[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(bounded_interpreter(&out_of_bounds).is_err());
        let mut overflowing_interp = bounded_elf(&[b"/lib/ld.so\0"]);
        overflowing_interp[ELF_HEADER_BYTES + 8..ELF_HEADER_BYTES + 16]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(bounded_interpreter(&overflowing_interp).is_err());
    }

    /// Task 11 fix round 3 (shadow finding 5). The live consumers used the
    /// compatibility `maps::resolve(&[MapEntry], addr)`, which rebuilds — and
    /// so revalidates, O(entries) — the whole index for every lookup: the
    /// loader snapshot loops were quadratic in a target-controlled entry count
    /// and none of it was charged. One validated index is now built per
    /// accepted snapshot and every examined entry and lookup is charged, so
    /// this exact unit arithmetic is what a regression to that wrapper breaks.
    #[test]
    fn one_charged_index_serves_every_live_lookup_in_one_snapshot() {
        const WORK_CEILING: u64 = 16 * 1024 * 1024;
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 20,
        };
        // The shape a target creates to make a per-lookup index rebuild
        // quadratic: many executable mappings of one identity and one path.
        let entries: Vec<MapEntry> = (0..128u64)
            .map(|index| MapEntry {
                start: 0x700000 + index * 0x2000,
                end: 0x700000 + index * 0x2000 + 0x1000,
                file_offset: index * 0x1000,
                permissions: if index % 2 == 0 { *b"r-xp" } else { *b"rw-p" },
                device: key.device,
                inode: if index % 2 == 0 { key.inode } else { 0 },
                raw_path: (index % 2 == 0).then(|| b"/lib/ld.so".to_vec()),
            })
            .collect();
        let matching = 64u64;

        // One validation pass per snapshot, then one unit per entry examined
        // and one per index lookup in each of the two snapshot loops.
        let expected = entries.len() as u64 * 3 + matching * 2;
        let snapshots = |budget: &mut CaptureWorkBudget| {
            let index = index_maps_or_refuse(&entries, budget).expect("a kernel-ordered snapshot");
            let executable =
                executable_map_snapshot(&index, key, budget).expect("the executable mappings");
            assert_eq!(executable.len() as u64, matching);
            let (path, loader) =
                loader_map_snapshot(&index, key, budget).expect("the loader mappings");
            assert_eq!(path, PathBuf::from("/lib/ld.so"));
            assert_eq!(loader.len() as u64, matching);
        };

        let mut budget = CaptureWorkBudget::default();
        assert!(budget.charge(WORK_CEILING - expected));
        snapshots(&mut budget);
        assert!(
            !budget.charge(1),
            "one index and two charged passes cost exactly {expected} units"
        );

        let mut budget = CaptureWorkBudget::default();
        assert!(budget.charge(WORK_CEILING - expected - 1));
        snapshots(&mut budget);
        assert!(budget.charge(1), "and never fewer");
        assert!(!budget.charge(1));

        // A stopped capture refuses the snapshot under its own reason, not as
        // "no usable executable mapping".
        let mut budget = CaptureWorkBudget::default();
        assert!(!budget.charge(u64::MAX));
        assert_eq!(
            index_maps_or_refuse(&entries, &mut budget).unwrap_err(),
            WORK_CEILING_REASON
        );
        let index = MapIndex::new(&entries).unwrap();
        assert_eq!(
            executable_map_snapshot(&index, key, &mut budget).unwrap_err(),
            WORK_CEILING_REASON
        );
        assert_eq!(
            loader_map_snapshot(&index, key, &mut budget).unwrap_err(),
            WORK_CEILING_REASON
        );
    }

    #[test]
    fn loader_mapping_selection_is_path_qualified_and_offset_exact() {
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 20,
        };
        let mapping = |start, offset, path: &[u8]| MapEntry {
            start,
            end: start + 0x1000,
            file_offset: offset,
            permissions: *b"r-xp",
            device: key.device,
            inode: key.inode,
            raw_path: Some(path.to_vec()),
        };
        let maps = vec![
            mapping(0x700000, 0, b"/lib/ld.so"),
            mapping(0x702000, 0x2000, b"/lib/ld.so"),
        ];
        let mut budget = CaptureWorkBudget::default();
        let index = MapIndex::new(&maps).unwrap();
        let (path, executable) = loader_map_snapshot(&index, key, &mut budget).unwrap();
        assert_eq!(path, PathBuf::from("/lib/ld.so"));
        assert_eq!(
            unique_mapping_for_offset(&executable, 0x2100).unwrap(),
            maps[1]
        );

        let mut collision = maps.clone();
        collision.push(mapping(0x800000, 0, b"/other/ld.so"));
        let collision_index = MapIndex::new(&collision).unwrap();
        assert!(loader_map_snapshot(&collision_index, key, &mut budget).is_err());
        assert!(unique_mapping_for_offset(&executable, 0x5000).is_err());
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
    fn exact_loader_pin_survives_cross_overlay_canonicalization() {
        let (mut engine, _, provider, _) = engine_with_overlay(104);
        let loader_module = overlay_module(overlay_key(102));
        let mut loader_pins = overlay_view_pin(&loader_module, 999, OVERLAY_SHA, 1, true);
        let (_, bind_skips) =
            bind_scanned_modules(std::slice::from_ref(&loader_module), &mut loader_pins);
        assert!(bind_skips.is_empty(), "{bind_skips:?}");
        let local_loader = loader_pins
            .id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
            .unwrap();

        let (candidate, loader) = engine
            .loader_candidate(
                loader_module.view,
                &loader_module,
                &loader_pins,
                local_loader,
                Vec::new(),
            )
            .unwrap();
        let loader = loader.expect("the exact local loader pin survives reconciliation");

        assert_ne!(loader, provider);
        assert!(loader_pins.exactly_matches(local_loader, &candidate.pinned, loader));
        assert_eq!(
            candidate
                .pinned
                .id_for_scanned(&loader_module, loader_module.key, &loader_module.path),
            Some(loader)
        );
        assert!(
            candidate
                .pinned
                .view_claims(loader_module.view)
                .is_some_and(|claims| claims.pins.contains(&loader))
        );
        assert!(candidate.pinned.has_overlay_uncertainty());
        assert!(candidate_identity_is_complete(
            &candidate.plan,
            &candidate.modules,
            &candidate.pinned
        ));
        assert_eq!(candidate.plan.modules.len(), 1);
        assert_eq!(candidate.plan.modules[0].object, provider);
        assert!(
            candidate
                .plan
                .slots
                .iter()
                .all(|slot| slot.object != loader)
        );
        let evidence = discovery_evidence(
            &candidate.plan,
            &candidate.pinned,
            &DiscoveryCounters::default(),
        );
        assert_eq!(evidence.modules.len(), 1);

        let mut retired = candidate.pinned;
        let claims = retired.remove_view(loader_module.view).unwrap();
        assert!(claims.pins.contains(&loader));
        assert!(retired.summary(loader).is_none());
        assert_eq!(
            retired.id_for_scanned(&loader_module, loader_module.key, &loader_module.path),
            None,
            "retiring the loader view removes its raw ownership"
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
            file_offset: Some(0),
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
            disposition: ApplyDisposition::Accepted,
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
        let remaining_reconciled: Vec<_> = modules
            .iter()
            .filter(|module| module.scanned.view != stale)
            .cloned()
            .collect();

        let mut candidate = LiveCandidate {
            pinned: pins,
            modules,
            plan: plan::build_from_reconciled_modules(&[]),
            delta: plan::AttachDelta {
                new: Vec::new(),
                replace: Vec::new(),
                retire: Vec::new(),
            },
            views: [stale].into_iter().collect(),
            corroboration: Vec::new(),
            manifest_fallbacks: Vec::new(),
            selection_claims: BTreeMap::new(),
            selection_tables: BTreeMap::new(),
            selection_admission: None,
            manifest_selection_admissions: Vec::new(),
            manifest_inventory_slots: BTreeMap::new(),
        };
        commit_cleaned_candidate_identity(
            &mut candidate,
            remaining_pins,
            remaining_reconciled,
            &[stale].into_iter().collect(),
        );
        assert!(candidate.modules.is_empty());
        assert!(candidate.pinned.pinned().next().is_none());
        assert!(candidate.views.is_empty());
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
        let queued = tagged_by_authority(first, &[], second_hit);
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
        let queued = tagged_by_authority(second, &[], second_hit);
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
    fn merge_scanned_interfaces_retains_the_richer_name() {
        let module = |name_lossy| ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: crate::process::MountNamespaceId {
                device: 1,
                inode: 2,
            },
            key: ObjectKey {
                device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
                inode: 42,
            },
            path: "/opt/p.so".into(),
            exports: vec![],
            tables: vec![ScannedTable {
                version: (3, 0),
                walk: "full",
                entries: vec![],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x1000,
                file_offset: Some(0),
            }],
            interfaces: vec![ScannedInterface {
                index: 0,
                name_class: "exact_standard",
                name_lossy,
                name_private: Some(b"PKCS 11".to_vec()),
                flags: 7,
                table: Some(0),
            }],
        };

        let mut merged = vec![module(Some("PKCS 11".into()))];
        merge_scanned_module(&mut merged, module(None));

        assert_eq!(merged[0].interfaces.len(), 1);
        assert_eq!(
            merged[0].interfaces[0].name_lossy.as_deref(),
            Some("PKCS 11")
        );
    }

    /// The valid self-export fixture: a retained view of this process, its own
    /// `/proc/self/maps`, and one structurally valid FUNCTION_LIST record whose
    /// table owner is a file-backed readable data mapping of the test
    /// executable and whose single pointer is the matching code mapping —
    /// exactly the shape `engine_lowers_export_table_owner_and_prefix` proves
    /// lowers whole.
    fn self_export_fixture(id: ProcessViewId) -> (ProcessView, Vec<MapEntry>, DiscoveryRecord) {
        use p11scope_ebpf_common::DISCOVERY_KIND_FUNCTION_LIST_RETURN;

        let pid = std::process::id();
        let view = ProcessView::open(id, pid).unwrap();
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
            .expect("the test executable has a file-backed data mapping")
            .clone();
        let code = maps
            .iter()
            .find(|mapping| {
                mapping.inode == owner.inode
                    && mapping.device == owner.device
                    && mapping.permissions[2] == b'x'
            })
            .expect("the test executable has a matching code mapping")
            .clone();

        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_FUNCTION_LIST_RETURN;
        record.symbol_id = 1;
        record.pid_tgid = u64::from(pid) << 32;
        record.table_ptr = owner.start;
        record.version_major = 2;
        record.version_minor = 40;
        record.pointers[0] = code.start;
        record.pointers_attempted = 1;
        record.completed_prefix = 1;
        record.usable_n = 1;
        (view, maps, record)
    }

    /// Task 11 fix round 3 (shadow finding 5): live admission is stop-aware.
    /// A structurally valid record used to lower whole through a capture that
    /// had already stopped — `admit_table`/`admit_interface` looked only at
    /// their own cardinality counters, so a sticky work stop refused nothing
    /// and an expired batch deadline was never polled between the snapshot and
    /// the decode.
    #[test]
    fn a_stopped_capture_refuses_a_valid_live_export_record() {
        let (view, maps, record) = self_export_fixture(ProcessViewId(42));
        let hooks = HookRegistry::builtin();
        let index = MapIndex::new(&maps).expect("a kernel-ordered self snapshot");

        // An expired batch deadline, nothing sticky yet: only an admission
        // clock poll can catch it.
        let mut budget = CaptureWorkBudget::default();
        budget.set_deadline(Some(0));
        assert_eq!(
            lower_export_record(&view, &index, &hooks, &record, &mut budget).unwrap_err(),
            SCAN_DEADLINE_REASON
        );

        // A sticky work stop left by any other consumer of the one budget.
        let mut budget = CaptureWorkBudget::default();
        assert!(
            !budget.charge(u64::MAX),
            "the work ceiling refuses and sticks"
        );
        assert_eq!(
            lower_export_record(&view, &index, &hooks, &record, &mut budget).unwrap_err(),
            WORK_CEILING_REASON
        );

        // The same record still lowers when neither ceiling was reached: the
        // refusals above are the capture's stop, not the fixture's shape.
        let mut budget = CaptureWorkBudget::default();
        assert!(
            lower_export_record(&view, &index, &hooks, &record, &mut budget)
                .unwrap()
                .is_some()
        );

        // And the admission functions refuse the stop themselves, so no caller
        // of theirs can decode new work past the capture's ceiling.
        let mut budget = CaptureWorkBudget::default();
        assert!(budget.admit_table(1) && budget.admit_interface());
        assert!(!budget.charge(u64::MAX));
        assert!(!budget.admit_table(1), "a stopped capture admits no table");
        assert!(
            !budget.admit_interface(),
            "a stopped capture admits no interface"
        );
    }

    /// Task 11 fix round 3 (shadow-review test blocker 1): the production call
    /// site. An ordinary batch carrying the valid self-export record under an
    /// expired batch deadline admits no candidate and no slot, and publishes
    /// the exact live loss — and the refusal lands before one byte of the
    /// target's maps is read.
    #[test]
    fn an_expired_batch_deadline_admits_no_live_export_record() {
        let refused = {
            let (view, _maps, record) = self_export_fixture(ProcessViewId(0));
            let mut engine = Engine::empty();
            engine.next_view_id = 1;
            engine.views.push(view);
            let mut session = ScriptedSession::default();
            let mut collect = Engine::collect_discovery_records;
            let outcome = engine
                .apply_discovery_batch_with(
                    &mut session,
                    vec![record],
                    0,
                    true,
                    false,
                    &mut collect,
                    Some(0),
                )
                .expect("a refused live snapshot is loss, never a batch error");
            assert!(!outcome.required_complete, "the batch is incomplete");
            assert!(engine.plan.slots.is_empty(), "no slot is admitted");
            assert!(engine.modules.is_empty(), "no candidate is admitted");
            assert!(
                engine.counters.object_skips.contains(&Skipped {
                    subject: "live discovery record".into(),
                    reason: "a structurally valid private record failed exact live resolution"
                        .into(),
                }),
                "{:?}",
                engine.counters.object_skips
            );
            assert_eq!(
                engine.budget.attempted_io_bytes(),
                0,
                "the expired deadline refuses the snapshot before a byte is read"
            );
            engine.counters.object_skips.clone()
        };

        // The positive control: the same fixture through the same route with no
        // deadline is admitted, so the refusal above is the deadline's.
        let (view, _maps, record) = self_export_fixture(ProcessViewId(0));
        let mut engine = Engine::empty();
        engine.next_view_id = 1;
        engine.views.push(view);
        // This test binary is larger than the default per-object cap, which
        // would skip its own pin for an unrelated reason.
        engine.budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        });
        let mut session = ScriptedSession::default();
        let mut collect = Engine::collect_discovery_records;
        engine
            .apply_discovery_batch_with(
                &mut session,
                vec![record],
                0,
                true,
                false,
                &mut collect,
                None,
            )
            .expect("an ordinary batch");
        assert_eq!(
            engine.plan.slots.len(),
            1,
            "{:?}",
            engine.counters.object_skips
        );
        assert!(
            engine.budget.attempted_io_bytes() > 0,
            "the snapshot was read"
        );
        assert!(
            !engine
                .counters
                .object_skips
                .iter()
                .any(|skip| refused.contains(skip)),
            "{:?}",
            engine.counters.object_skips
        );
    }

    #[test]
    fn engine_lowers_export_table_owner_and_prefix() {
        use p11scope_ebpf_common::{
            DISCOVERY_KIND_FUNCTION_LIST_RETURN, DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN,
            DISCOVERY_STATUS_READ_FAILURE, DiscoveryRecord,
        };

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
        let index = MapIndex::new(&maps).expect("a kernel-ordered self snapshot");
        let lowered = lower_export_record(&view, &index, &hooks, &record, &mut budget)
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
        let interface = lower_export_record(&view, &index, &hooks, &interface_record, &mut budget)
            .unwrap()
            .unwrap();
        let mut merged = vec![lowered.clone()];
        merge_scanned_module(&mut merged, interface);
        assert_eq!(merged[0].interfaces[0].table, Some(1));

        let mut wrong_hook = record;
        wrong_hook.symbol_id = 2;
        assert!(
            lower_export_record(&view, &index, &hooks, &wrong_hook, &mut budget).is_err(),
            "the retained symbol ABI must agree with the record kind"
        );
        wrong_hook.symbol_id = u32::MAX;
        assert!(
            lower_export_record(&view, &index, &hooks, &wrong_hook, &mut budget).is_err(),
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
            lower_export_record(&view, &index, &hooks, &record, &mut budget)
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
            lower_export_record(&view, &index, &hooks, &record, &mut budget)
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
            file_offset: Some(0),
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
            selection_evidence: Default::default(),
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
                file_offset: Some(0),
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
                file_offset: Some(0),
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
                    file_offset: Some(offset),
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
                    file_offset: Some(0),
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
                    file_offset: Some(0),
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
    fn legacy_manifest_schemas_are_rejected_with_rediscovery_instruction() {
        for schema in [
            "p11scope-manifest/1",
            "p11scope-manifest/2",
            "p11scope-manifest/3",
            "p11scope-manifest/4",
        ] {
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
        let maps_bytes = std::fs::read("/proc/self/maps").unwrap();
        let maps = p11scope_manifest::maps::parse_maps(&maps_bytes).unwrap();
        let scan_bytes: u64 = maps
            .iter()
            .filter(|m| m.inode == inode && m.permissions[0] == b'r' && m.permissions[2] != b'x')
            .map(|m| m.end - m.start)
            .sum();
        let hash_bytes = std::fs::metadata(&exe).unwrap().len();
        let scan_pass = maps_bytes.len() as u64 + scan_bytes;
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: scan_bytes.max(hash_bytes),
            total_bytes: scan_pass * 2 + hash_bytes,
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
                file_offset: Some(0),
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
                file_offset: Some(0),
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
            attach_gap_ms: None,
            pause: "none",
            pause_attempts: 0,
            pause_confirmed: 0,
            pause_partial: 0,
            child_still_running: None,
            discovery_ring_loss: 0,
            discovery_state_failures: 0,
            discovery_read_failures: 0,
            discovery_truncated: 0,
            loader_discovery: render::LoaderDiscovery::default(),
            unprotected_live_windows: 0,
            module_unresolved_slots: 0,
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
        let trace = trace::evidence_line(&evidence, CapturePolicy::Allowlisted, false);

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
                file_offset: Some(0),
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
            selection_evidence: Default::default(),
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
            selection_evidence: Default::default(),
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
    fn cgroup_walk_follows_the_retained_directory_not_a_replaced_path() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("target.scope");
        let impostor = root.path().join("impostor.scope");
        std::fs::create_dir_all(real.join("leaf.scope")).unwrap();
        std::fs::create_dir(&impostor).unwrap();
        std::fs::write(real.join("cgroup.procs"), "11\n").unwrap();
        std::fs::write(real.join("leaf.scope/cgroup.procs"), "22\n").unwrap();
        std::fs::write(impostor.join("cgroup.procs"), "99\n").unwrap();
        let scope = crate::scope::cgroup(&real).unwrap();
        let stash = root.path().join("moved.scope");
        std::fs::rename(&real, &stash).unwrap();
        std::fs::rename(&impostor, &real).unwrap();

        let (pids, lost) = scope_pids(&scope);

        assert_eq!(pids, vec![11, 22], "the retained fd's descendants, not 99");
        assert!(!pids.contains(&99));
        assert_eq!(lost, vec![]);
    }

    #[test]
    fn cgroup_walk_reports_losses_under_the_operator_path_not_a_proc_fd_path() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("target.scope");
        let leaf = real.join("leaf.scope");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(real.join("cgroup.procs"), "11\n").unwrap();
        std::fs::create_dir(leaf.join("cgroup.procs")).unwrap();
        let scope = crate::scope::cgroup(&real).unwrap();

        let (pids, lost) = scope_pids(&scope);

        assert_eq!(pids, vec![11]);
        assert_eq!(
            lost.len(),
            1,
            "the directory cannot be read as text: {lost:?}"
        );
        assert_eq!(lost[0].subject, leaf.display().to_string());
        assert!(!format!("{lost:?}").contains("/proc/self/fd"));
    }

    #[test]
    fn cgroup_scope_collects_pids_from_every_descendant() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("kubepods.slice").join("container.scope");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(root.path().join("cgroup.procs"), "11\n").unwrap();
        std::fs::write(leaf.join("cgroup.procs"), "22\n33\n\n22\n").unwrap();
        let scope = crate::scope::cgroup(root.path()).unwrap();
        let (pids, lost) = scope_pids(&scope);
        assert_eq!(pids, vec![11, 22, 33], "deduplicated, descendants included");
        assert_eq!(lost, vec![], "every directory was readable");
        assert_eq!(scope_pids(&Scope::Pid(7)).0, vec![7]);

        // A cgroup that is gone by the time the walk reaches it — container
        // cgroups churn constantly, and one is removable only when empty — held
        // no process to lose, on either read. Claiming otherwise would publish a
        // false loss and force PARTIAL on ordinary pod turnover.
        let vanished = tempfile::tempdir().unwrap();
        let vanished_scope = crate::scope::cgroup(vanished.path()).unwrap();
        std::fs::remove_dir(vanished.path()).unwrap();
        let (pids, lost) = scope_pids(&vanished_scope);
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
        let (pids, lost) = scope_pids(&scope);
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

    fn merged_object(sources: Vec<&'static str>) -> render::ObjectSummary {
        render::ObjectSummary {
            dev: (0, 30),
            ino: 12_043_768,
            sha256: Some("5f48fcc1".into()),
            path: "/tmp/freeze-provider.so".into(),
            build_id: Some("23a2c057".into()),
            identity_source: "mountinfo",
            note: None,
            sources,
        }
    }

    fn merged_module(sources: Vec<&'static str>) -> render::DiscoveredModule {
        render::DiscoveredModule {
            id: plan::ModuleId(0),
            dev: (0, 30),
            ino: 12_043_768,
            sha256: Some("5f48fcc1".into()),
            path: "/tmp/freeze-provider.so".into(),
            build_id: Some("23a2c057".into()),
            objects: vec![merged_object(sources.clone())],
            sources,
            corroborated: false,
            corroboration: vec!["uncorroborated"],
            tables: Vec::new(),
            interfaces: 0,
            skipped: Vec::new(),
        }
    }

    /// A manifest-first module that the scan only reaches later is the one
    /// arrival order an append-union renders as `["manifest", "scan"]`, which
    /// is outside the schema's three legal arrays
    /// (docs/schema/observed-profile-v2.md: "in that canonical order").
    #[test]
    fn a_later_scan_merges_into_a_manifest_module_in_canonical_source_order() {
        let mut retained = merged_module(vec!["manifest"]);
        merge_discovered_module(&mut retained, merged_module(vec!["scan", "manifest"]));
        assert_eq!(retained.sources, vec!["scan", "manifest"]);
    }

    /// `objects[]` is "every object this module's planned slots attach into" —
    /// one entry per object. A source set that grows between snapshots is the
    /// same physical object described better, not a second one.
    #[test]
    fn one_physical_object_keeps_one_objects_entry_across_a_source_change() {
        let mut retained = merged_module(vec!["manifest"]);
        merge_discovered_module(&mut retained, merged_module(vec!["scan", "manifest"]));
        assert_eq!(
            retained.objects,
            vec![merged_object(vec!["scan", "manifest"])]
        );
    }

    /// Two genuinely different objects still both appear.
    #[test]
    fn distinct_objects_are_never_coalesced_by_the_source_union() {
        let mut retained = merged_module(vec!["scan"]);
        let mut incoming = merged_module(vec!["manifest"]);
        incoming.objects[0].ino = 999;
        merge_discovered_module(&mut retained, incoming);
        assert_eq!(retained.objects.len(), 2);
        assert_eq!(retained.sources, vec!["scan", "manifest"]);
    }
}
