//! Initial and incremental provider discovery ownership.

use crate::attach::{
    CapturePolicy, CounterSnapshot, DynamicExportIdentity, DynamicLoaderAttachFailure,
    OwnedPauseGeneration, Scope, Session,
};
use crate::cli::CaptureArgs;
use crate::discovery::hooks::{HookAbi, HookRegistry};
use crate::discovery::identity::{
    ManifestStaleReason, PinnedObjectId, PinnedObjects, PinnedTimingKey, ReconciledModule,
    StaleManifestObject, bind_scanned_modules, canonicalize_scanned_overlays,
    pin_manifest_objects_deferred_in_views, pin_scanned_view_objects, retained_object_key,
    target_paths_equal, view_object_key,
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
use p11scope_manifest::manifest::{Acquisition, Manifest, Resolution, SCHEMA, WalkOutcome};
use p11scope_manifest::maps::{
    Device, MapEntry, MappedPath, ObjectKey, Resolved, parse_maps, resolve,
};
use std::collections::{BTreeMap, BTreeSet};
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
    /// The deduplicated bound-context set behind `loader_discovery`'s
    /// strategy/timing/capture counts (design §9.2). Keyed by the exact
    /// internal `{process generation, optional bound tuple}` — the loader
    /// context id stands for the bound tuple and is absent when binding
    /// failed — so one context contributes exactly once no matter how many
    /// records it produces. All identity stays out: only the classification
    /// is kept, and it is all that can be rendered.
    loader_contexts: BTreeMap<(ProcessViewId, Option<u16>), LoaderContextClass>,
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
}

impl DecodedOccurrence {
    fn module(&self) -> plan::ModuleId {
        match self {
            Self::Target { module, .. }
            | Self::ScanSkip { module, .. }
            | Self::ManifestFunction { module, .. } => *module,
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
    refusals: BTreeMap<plan::ModuleId, Skipped>,
    fallbacks: BTreeMap<(u32, u32), render::ManifestObjectFallback>,
    corroboration_tombstones: BTreeSet<plan::ModuleId>,
    fallback_tombstones: BTreeSet<(u32, u32)>,
    conflicts: u64,
    uncorroborated: u64,
    scan_unavailable: Option<String>,
    scan_ms: u64,
    vendor_interfaces: usize,
    interface_list: String,
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

    fn replace_visible_history(&mut self, history: CaptureHistory) {
        if self.staged.is_some() {
            self.staged = Some(history);
        } else {
            self.history = history;
        }
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
            if history.corroboration_tombstones.insert(module) && was_corroborated {
                history.uncorroborated = history.uncorroborated.saturating_add(1);
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
        let current = discovery_evidence(plan, pinned, counters);
        for mut module in current.modules {
            let tombstoned = history.corroboration_tombstones.contains(&module.id);
            if tombstoned {
                module.corroborated = false;
                module.corroboration = vec!["uncorroborated"];
            }
            history
                .modules
                .entry(module.id)
                .and_modify(|known| {
                    merge_discovered_module(known, module.clone());
                    if tombstoned {
                        known.corroborated = false;
                        known.corroboration = vec!["uncorroborated"];
                    }
                })
                .or_insert(module);
        }

        for module in modules {
            let owner = self.module_id_for_object(pinned, module.object)?;
            let mut targets = BTreeMap::new();
            let mut skips = BTreeMap::new();
            let mut surfaces = BTreeMap::new();
            let mut tables = BTreeMap::new();
            for (table_index, table) in module.scanned.tables.iter().enumerate() {
                let functions =
                    table.entries.len() + table.null_entries.len() + table.unpinned.len();
                let surface = (table.version, table.walk.to_string(), functions);
                let surface_occurrence = surfaces.entry(surface.clone()).or_insert(0usize);
                history
                    .surfaces
                    .entry(SurfaceOccurrence::Scan {
                        module: owner,
                        version: surface.0,
                        walk: surface.1.clone(),
                        functions,
                        occurrence: *surface_occurrence,
                    })
                    .or_insert_with(|| plan::SurfaceSummary {
                        source: format!(
                            "{} table {}.{}",
                            module.scanned.path, table.version.0, table.version.1
                        ),
                        walk: table.walk.to_string(),
                        acquisition: "ok".into(),
                        functions,
                    });
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

        for skipped in &counters.object_skips {
            history
                .losses
                .entry((skipped.subject.clone(), skipped.reason.clone()))
                .or_insert_with(|| skipped.clone());
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
        render::DiscoveryEvidence {
            modules,
            conflicts: history.conflicts,
            uncorroborated: history.uncorroborated,
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

fn merge_discovered_module(
    retained: &mut render::DiscoveredModule,
    incoming: render::DiscoveredModule,
) {
    extend_occurrences(&mut retained.objects, incoming.objects);
    extend_occurrences(&mut retained.tables, incoming.tables);
    extend_occurrences(&mut retained.skipped, incoming.skipped);
    retained.interfaces = retained.interfaces.max(incoming.interfaces);
    retained.corroborated |= incoming.corroborated;
    for source in incoming.sources {
        if !retained.sources.contains(&source) {
            retained.sources.push(source);
        }
    }
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
    fn discovery_dequeue(&mut self) -> Result<Option<crate::events::DiscoveryItem>>;
    fn counter_snapshot(&self) -> Result<CounterSnapshot>;
    fn detach_failures(&self) -> &[String];
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
    fn discovery_dequeue(&mut self) -> Result<Option<crate::events::DiscoveryItem>> {
        Session::discovery_dequeue(self)
    }

    fn counter_snapshot(&self) -> Result<CounterSnapshot> {
        Session::counter_snapshot(self)
    }

    fn detach_failures(&self) -> &[String] {
        Session::detach_failures(self)
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
    cause: String,
}

impl IncompleteTerminalDrain {
    pub(crate) fn new(records: Vec<DiscoveryRecord>, malformed: u64, cause: anyhow::Error) -> Self {
        Self {
            records,
            malformed,
            cause: cause.to_string(),
        }
    }
}

impl std::fmt::Debug for IncompleteTerminalDrain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IncompleteTerminalDrain")
            .field("records", &self.records.len())
            .field("malformed", &self.malformed)
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
}

struct StartPublicationSnapshot {
    plan: plan::AttachPlan,
    pinned: PinnedObjects,
    discovery: render::DiscoveryEvidence,
    modules: Vec<ReconciledModule>,
    corroboration: Vec<(BTreeSet<PinnedObjectId>, &'static str)>,
    manifest_fallbacks: Vec<ManifestFallback>,
    views: BTreeSet<ProcessViewId>,
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
            if queued.record.kind == DISCOVERY_KIND_LOADER
                && LoaderContextId::from_case_id(queued.record.case_id) == self.owner
            {
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
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            lost.push(Skipped {
                                subject: dir.display().to_string(),
                                reason: format!(
                                    "a cgroup directory entry could not be read ({error}); membership absence is not authoritative"
                                ),
                            });
                            continue;
                        }
                    };
                    match entry.file_type() {
                        Ok(kind) if kind.is_dir() => stack.push(entry.path()),
                        Ok(_) => {}
                        Err(error) => lost.push(Skipped {
                            subject: entry.path().display().to_string(),
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
                accepted_ordinals.push(manifest_number);
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
                accepted_ordinals.push(manifest_number);
                counters
                    .object_skips
                    .extend(pinned.absorb(manifest_pins.clone()));
            }
            Corroboration::Uncorroborated => {
                retarget_to_pins(&mut manifest, &[], &pinned, manifest_pins);
                accepted.push(manifest);
                accepted_ordinals.push(manifest_number);
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
            loader_contexts: BTreeMap::new(),
        }
    }

    /// Classifies the exact live-loader context this view owns after an arming
    /// attempt. Re-arming the same context updates its entry rather than
    /// adding a second — that is what makes the published counts per-context
    /// and not per-record — and a context never changes load kind once
    /// recorded, so a later ordinary refresh cannot relabel the pre-exec
    /// initial-set context as an ordinary `dlopen` one.
    fn record_loader_arm(&mut self, view: ProcessViewId, initial_set: bool) {
        let bound = self
            .loader_registry
            .ids_for_view(view)
            .into_iter()
            .find(|id| !self.loader_registry.is_tombstoned(*id));
        let class = LoaderContextClass {
            bound: bound.is_some(),
            initial_set,
        };
        self.loader_contexts
            .entry((view, bound.map(LoaderContextId::get)))
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

    fn collect_discovery_records(
        session: &mut dyn EngineSession,
    ) -> Result<(Vec<DiscoveryRecord>, u64)> {
        let mut records = Vec::new();
        let mut malformed = 0u64;
        loop {
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
                    return Err(IncompleteTerminalDrain::new(records, malformed, error).into());
                }
            }
        }
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
        }
    }

    fn begin_start_capture_attempt(&mut self) -> Result<StartPublicationSnapshot> {
        self.capture_facts.begin_stage()?;
        let snapshot = self.start_publication_snapshot();
        if let Err(error) = self.publish_current_capture_facts() {
            self.capture_facts.rollback_stage();
            return Err(error);
        }
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
        self.capture_facts.bind_plan_module_ids(
            &mut rebuilt,
            &modules,
            &self.manifests,
            &pinned,
        )?;
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
        record_object_skips(&mut candidate.plan, &self.counters.object_skips);
        outcome.changed |= candidate.plan != self.plan;
        self.pinned = candidate.pinned;
        self.modules = candidate.modules;
        self.plan = candidate.plan;
        self.counters.corroboration = candidate.corroboration;
        self.counters.manifest_fallbacks = candidate.manifest_fallbacks;
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
    }

    /// Drops the pins, modules, proofs, and live endpoints a lost process
    /// generation owned. Infallible on purpose: it runs after link mutation.
    fn retire_stale_candidate_sources(
        &mut self,
        session: &mut dyn EngineSession,
        candidate: &mut LiveCandidate,
        stale_views: &BTreeSet<ProcessViewId>,
    ) {
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
        session: &mut dyn EngineSession,
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
        let view_id = self.views[position].id();
        if context.spec.view != view_id
            || context
                .spec
                .mapping
                .as_ref()
                .is_some_and(|expected| expected != mapping)
        {
            // An `exec` this capture has already seen — it is queued right
            // now as this exact view's `ExecRefresh` — re-maps the loader at a
            // new load base, and every hit until the refresh runs resolves
            // into the moved mapping. The hit is still rejected: it cannot be
            // resolved against the armed context. It is not a loss: the queued
            // refresh rescans that view whole and re-arms it, so nothing goes
            // unobserved. Timing proof does go, so that stays invalidated.
            let remapped_by_queued_exec = context.spec.view == view_id
                && pending_views.get(&view_id) == Some(&RetirementCause::ExecRefresh)
                && context
                    .spec
                    .mapping
                    .as_ref()
                    .is_some_and(|expected| same_object_remapped(expected, mapping));
            if remapped_by_queued_exec {
                self.loader_registry.reject_hit();
                self.invalidate_causal_timing();
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
        if terminal_owner.is_none() && outcome.accepted() {
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
        session: &dyn EngineSession,
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
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> std::result::Result<bool, LoaderArmFailure> {
        let view_id = self.views[position].id();
        if !self.loader_registry.ids_for_view(view_id).is_empty() {
            return Ok(false);
        }
        let maps = Self::read_maps(&self.views[position])?;
        let pid = self.views[position].pid();
        let executable_identity = view_object_key(
            &self.views[position],
            Path::new(&format!("/proc/{pid}/exe")),
        )
        .map_err(anyhow::Error::msg)?;
        let Some((executable_mapping, executable_path)) =
            exact_executable_mapping(&maps, executable_identity)
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
        let loader_identity = view_object_key(
            &self.views[position],
            Path::new(&format!("/proc/{}/root{}", pid, interpreter.display())),
        )
        .map_err(anyhow::Error::msg)?;
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
                    Ok((incomplete.records, incomplete.malformed))
                }
                drained => drained,
            },
        );
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
        batch.extend(records);
        batch.complete = complete;
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
        batch.complete = true;
        self.terminal_batch = Some(batch);
        Ok(())
    }

    pub(crate) fn take_terminal_batch_for_deferred(&mut self) -> Result<TerminalBatch> {
        self.terminal_batch
            .take()
            .ok_or_else(|| anyhow!("terminal loader drain batch is missing"))
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
        for queued in records.drain(..) {
            let origin = (queued.record.pid_tgid >> 32) as u32;
            match self.dispatch_discovery_record(queued, session, additions_allowed, pending_views)
            {
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
                    self.mark_live_loss(
                        "live loader retirement",
                        "the post-detach private discovery drain failed; the exact terminal batch remains tombstoned for retry",
                    );
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
                            self.retain_terminal_batch(
                                incomplete.records,
                                false,
                                incomplete.malformed,
                            )?;
                        }
                        closure.fail();
                        self.mark_live_loss(
                            "live loader retirement",
                            "the post-detach private discovery drain failed; the exact terminal batch remains tombstoned for retry",
                        );
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
    ) {
        let pid = (record.pid_tgid >> 32) as u32;
        if let Some((view, cause)) =
            lifecycle_retirement(&self.views, pid, record.hook_ts_ns, record.kind)
        {
            self.queue_retirement(view, cause, pending_views);
        } else if record.kind == DISCOVERY_KIND_EXEC
            && unmatched_exec_requests_refresh(&self.views, pid)
        {
            self.refresh_requested.insert(pid);
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
                self.dispatch_lifecycle_record(&record, pending_views);
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
            for queued in std::mem::take(records) {
                let origin = (queued.record.pid_tgid >> 32) as u32;
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
        let (records, malformed) =
            Self::collect_discovery_records(session).map_err(Self::generic_drain_error)?;
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
        self.apply_discovery_batch_with(session, records, malformed, true, false, &mut collect)
            .map(|outcome| outcome.changed)
    }

    pub(crate) fn apply_discovery_batch_with(
        &mut self,
        session: &mut dyn EngineSession,
        records: Vec<DiscoveryRecord>,
        malformed: u64,
        additions_allowed: bool,
        terminal_dispatch: bool,
        collect: &mut DiscoveryCollector<'_>,
    ) -> Result<DiscoveryBatchOutcome> {
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
        let result = (|| {
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
    use std::cell::RefCell;
    use std::collections::VecDeque;

    #[derive(Default)]
    pub(crate) struct ScriptedSession {
        pub(crate) dequeues: VecDeque<Result<Option<crate::events::DiscoveryItem>>>,
        pub(crate) counters: CounterSnapshot,
        /// One entry per upcoming `counter_snapshot` call; `true` fails it.
        counter_script: RefCell<VecDeque<bool>>,
        pub(crate) detach_exports: Vec<DynamicExportIdentity>,
        pub(crate) detach_failed: bool,
        pub(crate) detached: Vec<LoaderContextId>,
        /// Slot counts of every `detach_slots` call, in order.
        pub(crate) detached_slots: Vec<usize>,
        /// One entry per upcoming `detach_slots` call; `true` fails it.
        detach_slot_script: VecDeque<bool>,
        /// Slot counts of every `attach_targets` call, in order.
        pub(crate) attached_slots: Vec<usize>,
        /// Killed and reaped from inside `attach_targets`, i.e. exactly between
        /// a generation precheck and its postcheck.
        kill_on_attach: Option<u32>,
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
    }

    impl EngineSession for ScriptedSession {
        fn discovery_dequeue(&mut self) -> Result<Option<crate::events::DiscoveryItem>> {
            self.dequeues.pop_front().unwrap_or(Ok(None))
        }

        fn counter_snapshot(&self) -> Result<CounterSnapshot> {
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
            Ok((Vec::new(), Vec::new()))
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
            _: (PinnedObjectId, u64),
            _: u64,
            _: HookAbi,
        ) -> bool {
            false
        }

        fn attach_dynamic_export(
            &mut self,
            _: LoaderContextId,
            _: u32,
            _: (PinnedObjectId, u64),
            _: u64,
            _: HookAbi,
            _: &PinnedObjects,
        ) -> Result<(bool, Option<u64>)> {
            Ok((false, None))
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
            IncompleteTerminalDrain::new(vec![record], 0, anyhow!("scripted ring read failed"));

        let error = Engine::generic_drain_error(retained.into());

        assert_eq!(error.to_string(), "scripted ring read failed");
        assert!(
            !error.to_string().contains("retained"),
            "the generic drain retains nothing across ticks: {error:#}"
        );
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
    /// executable and its PT_INTERP are located by matching `/proc/<pid>/maps`
    /// identities, and `stat`'s `st_dev` is not that representation: on a btrfs
    /// rootfs it is the subvolume's anonymous device, so every comparison
    /// failed and every capture on such a host reported a false unavailable.
    #[test]
    fn an_ordinary_dynamic_target_binds_its_live_loader_context() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let view = ProcessView::open(ProcessViewId(0), child.id()).unwrap();
        let mut engine = Engine::empty();
        engine.scope = Scope::Pid(child.id());
        engine.views.push(view);

        let mut session = ScriptedSession::default();
        let armed = engine.arm_loader_or_partial(
            0,
            &mut session,
            &mut true,
            &mut PendingViewRetirements::new(),
        );
        child.kill().unwrap();
        child.wait().unwrap();
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

    /// Task 9.2b defect D. An `exec` re-maps the loader at a new load base, so
    /// every loader hit between that exec and the refresh it queues resolves
    /// into a mapping the armed context cannot match. Rejecting the record is
    /// right; calling it a *loss* is not — the queued `ExecRefresh` rescans
    /// that view whole, so nothing goes unobserved, and the public
    /// `discovery unavailable` skip made every capture whose target execs
    /// permanently PARTIAL on an otherwise healthy capture.
    #[test]
    fn a_loader_hit_remapped_by_a_queued_exec_refresh_is_not_a_discovery_loss() {
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
                .all(|skip| skip.subject != "live loader discovery"),
            "an exec this capture already queued a refresh for explains the moved \
             mapping; the hit is rejected, not lost: {skips:?}"
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
        engine.scope = Scope::Cgroup {
            path: PathBuf::from("/sys/fs/cgroup/test.scope"),
            id: 0,
        };
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
        cgroup.scope = Scope::Cgroup {
            id: 7,
            path: "/sys/fs/cgroup/p11scope.test".into(),
        };
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
        }];
        module
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
        engine.apply_discovery_batch_with(session, records, 0, true, false, &mut collect)
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

    #[test]
    fn terminal_predispatch_counter_failure_retains_the_exact_batch_for_one_retry() {
        let pid = std::process::id();
        let (mut engine, owner) = Engine::retiring_loader_context(pid);
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records(
            [
                loader_record_for(owner, pid),
                loader_record_for(owner, pid),
                loader_record_for(unrelated, pid),
            ],
            16,
        );
        session.detach_exports = vec![terminal_export()];
        session.fail_counter_reads([false, true]);

        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 0,
            "a predispatch counter failure dispatches nothing"
        );
        let batch = engine.terminal_batch.as_ref().unwrap();
        assert_eq!(batch.record_count(), 3);
        assert!(batch.complete());
        assert_eq!(batch.authority.owner, owner);
        assert_eq!(batch.authority.exports, [terminal_export()]);
        assert_eq!(
            batch.tagged_owners(),
            [Some(owner), Some(owner), None],
            "only the owned records carry terminal authority"
        );
        let journal = engine.terminal_journal.unwrap();
        assert!(journal.retry_used && !journal.dispatch_started);

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
        let mut session = ScriptedSession::with_records([loader_record_for(owner, pid)], 16);
        session.fail_counter_reads([false, true]);

        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();
        assert!(engine.terminal_journal.unwrap().retry_used);

        session.fail_counter_reads([false, true]);
        apply_ordinary_batch(&mut engine, &mut session, Vec::new()).unwrap();

        assert_eq!(
            engine.loader_records_accepted, 0,
            "an exhausted retry never replays the records it dropped"
        );
        assert!(engine.terminal_batch.is_none());
        assert!(engine.terminal_journal.is_none());
        assert!(engine.loader_registry.context(owner).is_none());
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
