//! Discovered modules → one attach plan. The eBPF side has a single fixed-size
//! slot array, so every module a capture found shares one slot space: one slot per
//! unique {object, file_offset} across all of them. A target two modules both hand
//! out is attached once (attaching twice would double-count every call through it),
//! and because its counts then belong to neither module its semantics degrade to
//! COUNT_ONLY (spec §4.7). Capacity is refused whole modules at a time, never
//! truncated: a partially attached module silently under-reports a provider.
//!
//! Both discovery sources — the memory scan and a manifest — lower into `Discovered`
//! and go through the same `merge`, so there is exactly one implementation of the
//! merge rules rather than two that can drift.

use crate::discovery::identity::{PinnedObjectId, PinnedObjects, ReconciledModule};
pub use crate::discovery::scan::Skipped;
use p11scope_ebpf_common::{MAX_SLOTS, SlotSemantics};
use p11scope_manifest::manifest::{
    Acquisition, InterfaceClassification, Manifest, ObjectRecord, Resolution, SurfaceSource,
    WalkOutcome,
};
use p11scope_manifest::maps::{Device, ObjectKey};
use std::collections::{BTreeMap, BTreeSet};

/// Capture-local module index; the stable identity in output is {dev, ino, sha256, path}.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleId(pub u32);

#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    pub index: u32,
    /// Fixed descriptor selected by the static attach cookie. Zero is
    /// count-only; canonical descriptors are `function_id + 1`.
    pub descriptor_index: u32,
    /// The object the probe attaches into — a table entry may legally point
    /// into a dependency rather than the module that published it.
    pub object: PinnedObjectId,
    /// That object's pathname as discovery saw it, for messages only.
    pub object_path: String,
    pub file_offset: u64,
    /// Every distinct function name resolving here, sorted.
    pub names: Vec<String>,
    /// True when >= 2 distinct names share this target: counts belong to
    /// the group, never to one name.
    pub aliased: bool,
    pub semantics: SlotSemantics,
    /// True only when every surviving canonical-name claim at this exact
    /// pinned target is operator-attested. Scan-only claims stay count-only.
    pub semantic_authorized: bool,
    /// At least one name was unknown, the aliased names disagreed, or two
    /// modules claim this target.
    pub semantic_ambiguous: bool,
    /// True only when every surface exposing this exact target is a
    /// standard interface carrying CKF_INTERFACE_FORK_SAFE.
    pub fork_safe: bool,
    /// Every module claiming this exact {object, offset}. Length >= 2 ⇒ ambiguous.
    pub module_ids: Vec<ModuleId>,
}

/// One function table a module published.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TableSummary {
    /// `[major, minor]` of the `CK_VERSION` header the table carries.
    pub version: (u8, u8),
    /// Entries with a usable target; the unusable ones are in `skipped`.
    pub entries: usize,
    /// "scan" | "manifest".
    pub source: &'static str,
}

/// One module that contributed targets to this plan.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleSummary {
    pub id: ModuleId,
    pub object: PinnedObjectId,
    pub key: ObjectKey,
    pub path: String,
    pub tables: Vec<TableSummary>,
    /// The most interfaces any one source saw, never the sum across sources —
    /// two sources describing one provider both count its interfaces.
    pub interfaces: usize,
    /// "scan" | "manifest".
    pub source: &'static str,
    /// Whether a second discovery source agreed with this one (spec §4.12).
    pub corroborated: bool,
    /// This module's own entries with no attachable target, and why — the same
    /// records as `AttachPlan::skipped`, attributed to the module that
    /// published them so a report can say *which* provider lost entries.
    pub skipped: Vec<Skipped>,
}

/// Per-surface discovery provenance, carried through to evidence so a
/// manifest that never finished walking a surface can't be reported as a
/// complete capture just because its (empty) function list produced no
/// skips or aliases.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SurfaceSummary {
    /// Short human label for the surface (legacy table or interface name).
    pub source: String,
    pub walk: String,
    pub acquisition: String,
    pub functions: usize,
}

/// A surface label for capture output. Never the interface's recorded name:
/// those bytes were read out of a provider's memory, and capture output does not
/// carry provider byte strings (spec §4.3, `docs/privacy/allowlist-v1.md`) —
/// `p11scope inspect` is where names are shown. The classification is what a
/// reader can act on anyway, and it stays honest for the corroborated case,
/// where the recorded name was alternate, null or unreadable.
///
/// `pub(crate)` so a renderer's test can assert against the real label rather
/// than one it made up.
pub(crate) fn source_label(s: &SurfaceSource) -> String {
    match s {
        SurfaceSource::LegacyFunctionList => "legacy_function_list".into(),
        SurfaceSource::Interface {
            index,
            classification,
            ..
        } => format!(
            "interface[{index}] {}",
            match classification {
                InterfaceClassification::ExactStandard => "exact_standard",
                InterfaceClassification::CorroboratedStandardPrefix =>
                    "corroborated_standard_prefix",
            }
        ),
    }
}

fn walk_label(w: &WalkOutcome) -> String {
    match w {
        WalkOutcome::Full => "full".into(),
        WalkOutcome::KnownPrefix => "known_prefix".into(),
        WalkOutcome::Refused => "refused".into(),
        WalkOutcome::NotWalked => "not_walked".into(),
        WalkOutcome::Unreadable { detail } => format!("unreadable: {detail}"),
    }
}

fn acquisition_label(a: &Acquisition) -> String {
    match a {
        Acquisition::Ok => "ok".into(),
        Acquisition::Absent => "absent".into(),
        Acquisition::Empty => "empty".into(),
        Acquisition::Error { detail } => format!("error: {detail}"),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttachPlan {
    pub slots: Vec<Slot>,
    pub modules: Vec<ModuleSummary>,
    pub skipped: Vec<Skipped>,
    /// Modules refused whole because the slot ceiling was reached.
    pub modules_skipped: Vec<Skipped>,
    /// Total function records seen across every walked surface.
    pub entries_seen: usize,
    /// One entry per surface, so evidence can see discovery gaps (partial
    /// walks, failed acquisitions) even when they produced no skipped/aliased
    /// function records of their own.
    pub surfaces: Vec<SurfaceSummary>,
    /// Present-but-undecoded vendor interfaces (never walked).
    pub vendor_interfaces: usize,
    /// Outcome of the manifest-level C_GetInterfaceList enumeration.
    pub interface_list: String,
    /// Slots claimed by >=2 modules — count-only, forces PARTIAL (spec §4.7).
    pub module_ambiguous: usize,
    // Exact target -> allocated slot. Retired targets leave this index so an
    // exact reappearance gets a fresh monotonic slot rather than reviving a
    // historical cookie.
    slot_by_key: BTreeMap<AttachKey, usize>,
    // Slot indices never leave this set during one capture. Their historical
    // aggregate-map cells remain readable but may not receive new links.
    retired_slots: BTreeSet<usize>,
    // Aggregate cells are capture-lifetime state. Once counts in a slot may
    // belong to more than one module, later owner retirement cannot make those
    // historical counts attributable to the survivor.
    historically_ambiguous_slots: BTreeSet<usize>,
}

/// The one physical attachment identity. A pathname is diagnostic data, not
/// identity: attachment always uses the retained pinned object fd.
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct AttachKey {
    pub object: PinnedObjectId,
    pub file_offset: u64,
}

impl AttachKey {
    fn of(slot: &Slot) -> Self {
        Self {
            object: slot.object,
            file_offset: slot.file_offset,
        }
    }
}

/// The finite link work induced by one complete rebuilt-plan snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct AttachDelta {
    pub new: Vec<Slot>,
    pub replace: Vec<Slot>,
    pub retire: Vec<Slot>,
}

impl AttachPlan {
    pub fn from_slots(slots: Vec<Slot>) -> Self {
        let mut slot_by_key = BTreeMap::new();
        let historically_ambiguous_slots: BTreeSet<_> = slots
            .iter()
            .enumerate()
            .filter_map(|(position, slot)| (slot.module_ids.len() >= 2).then_some(position))
            .collect();
        for (position, slot) in slots.iter().enumerate() {
            assert_eq!(slot.index as usize, position, "slot indices must be dense");
            assert!(
                slot_by_key.insert(AttachKey::of(slot), position).is_none(),
                "one exact target may occupy one slot"
            );
        }
        Self {
            slots,
            modules: vec![],
            skipped: vec![],
            modules_skipped: vec![],
            entries_seen: 0,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            module_ambiguous: historically_ambiguous_slots.len(),
            slot_by_key,
            retired_slots: BTreeSet::new(),
            historically_ambiguous_slots,
        }
    }

    /// Rebuilds the one complete, capacity-aware snapshot a live caller passes
    /// unchanged to [`Self::extend_exact`]. Historical allocations remain
    /// reserved; active exact keys consume no additional slot.
    pub fn rebuild_from_sources(
        &self,
        scanned: &[ReconciledModule],
        manifests: &[Manifest],
        pinned: &PinnedObjects,
    ) -> AttachPlan {
        self.rebuild_from_sources_with(scanned, manifests, |key, path| {
            pinned.id_for_manifest(key, path)
        })
    }

    fn rebuild_from_sources_with(
        &self,
        scanned: &[ReconciledModule],
        manifests: &[Manifest],
        pinned_id: impl FnMut(ObjectKey, &str) -> Option<PinnedObjectId>,
    ) -> AttachPlan {
        build_from_sources_with(
            scanned,
            manifests,
            pinned_id,
            self.slots.len(),
            &self.slot_by_key,
        )
    }

    /// True while this slot still accepts probes. Retired slots remain in
    /// `slots` so their already-collected aggregate-map cells stay stable.
    pub fn is_active(&self, slot: u32) -> bool {
        let position = slot as usize;
        position < self.slots.len() && !self.retired_slots.contains(&position)
    }

    /// The module a slot's counts belong to, or `None` when no single module
    /// can own them (unknown slot, or a target two modules ever both handed out).
    pub fn module_of_slot(&self, slot: u32) -> Option<ModuleId> {
        if !self.is_active(slot) || self.slot_is_module_ambiguous(slot) {
            return None;
        }
        self.slots
            .get(slot as usize)
            .filter(|s| s.module_ids.len() == 1)
            .map(|s| s.module_ids[0])
    }

    pub(crate) fn slot_is_module_ambiguous(&self, slot: u32) -> bool {
        self.historically_ambiguous_slots.contains(&(slot as usize))
    }

    pub(crate) fn effective_semantics(&self, slot: &Slot) -> SlotSemantics {
        if self.slot_is_module_ambiguous(slot.index) {
            SlotSemantics::COUNT_ONLY
        } else {
            slot.semantics
        }
    }

    /// Retains only the aggregate-cell provenance a fully reconciled candidate
    /// proved about already-active exact targets. Candidate identities and
    /// topology remain local until their transaction commits.
    pub(crate) fn latch_ambiguity_from(&mut self, candidate: &Self) -> bool {
        let before = self.historically_ambiguous_slots.len();
        for (key, candidate_position) in &candidate.slot_by_key {
            if !candidate
                .historically_ambiguous_slots
                .contains(candidate_position)
            {
                continue;
            }
            if let Some(current_position) = self.slot_by_key.get(key) {
                self.historically_ambiguous_slots.insert(*current_position);
            }
        }
        self.module_ambiguous = self.historically_ambiguous_slots.len();
        self.historically_ambiguous_slots.len() != before
    }

    /// Applies a complete fresh planner snapshot without changing already
    /// allocated slot IDs. Only a semantic downgrade to descriptor zero may
    /// replace an existing exact target; descriptors are frozen before any
    /// attachment and can never be upgraded or otherwise mutated live.
    pub fn extend_exact(&mut self, mut rebuilt: AttachPlan) -> Result<AttachDelta, String> {
        self.validate_slot_index()?;
        rebuilt.validate_slot_index()?;
        self.remap_modules(&mut rebuilt)?;
        self.validate_extension_capacity(&rebuilt)?;

        let mut slots = self.slots.clone();
        let mut slot_by_key = self.slot_by_key.clone();
        let mut retired_slots = self.retired_slots.clone();
        let mut historically_ambiguous_slots = self.historically_ambiguous_slots.clone();
        historically_ambiguous_slots.extend(
            self.slots
                .iter()
                .enumerate()
                .filter_map(|(position, slot)| (slot.module_ids.len() >= 2).then_some(position)),
        );
        let mut delta = AttachDelta {
            new: vec![],
            replace: vec![],
            retire: vec![],
        };

        for (key, position) in &self.slot_by_key {
            if rebuilt.slot_by_key.contains_key(key) {
                continue;
            }
            retired_slots.insert(*position);
            slot_by_key.remove(key);
            delta.retire.push(slots[*position].clone());
        }

        for slot in &rebuilt.slots {
            let key = AttachKey::of(slot);
            if let Some(position) = self.slot_by_key.get(&key).copied() {
                let old = slots[position].clone();
                let mut updated = slot.clone();
                updated.index = old.index;
                if updated.module_ids.len() >= 2 {
                    historically_ambiguous_slots.insert(position);
                }
                if historically_ambiguous_slots.contains(&position) {
                    updated.names.extend(old.names);
                    updated.names.sort();
                    updated.names.dedup();
                    updated.aliased |= old.aliased || updated.names.len() >= 2;
                    if old.descriptor_index == 0 || updated.descriptor_index == 0 {
                        updated.semantic_ambiguous = true;
                    }
                }
                if old.descriptor_index != updated.descriptor_index {
                    if old.descriptor_index == 0 {
                        updated.descriptor_index = 0;
                        updated.semantics = SlotSemantics::COUNT_ONLY;
                    } else if updated.descriptor_index != 0 && old.semantics == updated.semantics {
                        updated.descriptor_index = old.descriptor_index;
                    } else {
                        if updated.descriptor_index != 0 {
                            return Err(format!(
                                "slot {} descriptor cannot change from {} to {} after policy freeze",
                                old.index, old.descriptor_index, updated.descriptor_index
                            ));
                        }
                        delta.replace.push(updated.clone());
                    }
                }
                slots[position] = updated;
            } else {
                let mut added = slot.clone();
                added.index = slots.len() as u32;
                if added.module_ids.len() >= 2 {
                    historically_ambiguous_slots.insert(slots.len());
                }
                slot_by_key.insert(key, slots.len());
                delta.new.push(added.clone());
                slots.push(added);
            }
        }

        self.slots = slots;
        self.modules = rebuilt.modules;
        self.skipped = rebuilt.skipped;
        self.modules_skipped = rebuilt.modules_skipped;
        self.entries_seen = rebuilt.entries_seen;
        self.surfaces = rebuilt.surfaces;
        self.vendor_interfaces = rebuilt.vendor_interfaces;
        self.interface_list = rebuilt.interface_list;
        self.slot_by_key = slot_by_key;
        self.retired_slots = retired_slots;
        self.historically_ambiguous_slots = historically_ambiguous_slots;
        self.module_ambiguous = self.historically_ambiguous_slots.len();
        Ok(delta)
    }

    fn validate_extension_capacity(&self, rebuilt: &AttachPlan) -> Result<(), String> {
        let additions = rebuilt
            .slots
            .iter()
            .filter(|slot| !self.slot_by_key.contains_key(&AttachKey::of(slot)))
            .count();
        let required = self.slots.len() + additions;
        if required > MAX_SLOTS as usize {
            return Err(format!(
                "attach plan requires {required} allocated slots but only {MAX_SLOTS} are available; \
                 refusing to attach a prefix"
            ));
        }
        Ok(())
    }

    /// A failed replacement must not revive the old descriptor or reuse its
    /// cookie. It remains a visible, inactive aggregate slot with finite
    /// attachment evidence owned by the caller.
    pub(crate) fn deactivate(&mut self, slot: u32) {
        if !self.is_active(slot) {
            return;
        }
        let position = slot as usize;
        self.retired_slots.insert(position);
        self.slot_by_key
            .remove(&AttachKey::of(&self.slots[position]));
        self.module_ambiguous = self.historically_ambiguous_slots.len();
    }

    fn validate_slot_index(&self) -> Result<(), String> {
        if self.slots.len() > MAX_SLOTS as usize {
            return Err(format!(
                "attach plan has {} allocated slots but only {MAX_SLOTS} are available",
                self.slots.len()
            ));
        }
        let mut keys = BTreeSet::new();
        for (position, slot) in self.slots.iter().enumerate() {
            if slot.index as usize != position {
                return Err(format!(
                    "slot index {} does not match its allocated position {position}",
                    slot.index
                ));
            }
            let Some(descriptor) = crate::kinds::DESCRIPTORS.get(slot.descriptor_index as usize)
            else {
                return Err(format!(
                    "slot {} selects descriptor {} outside the fixed inventory",
                    slot.index, slot.descriptor_index
                ));
            };
            if slot.semantics != *descriptor {
                return Err(format!(
                    "slot {} semantics do not match fixed descriptor {}",
                    slot.index, slot.descriptor_index
                ));
            }
            if slot.descriptor_index != 0
                && (!slot.semantic_authorized
                    || slot.semantic_ambiguous
                    || slot.module_ids.len() != 1)
            {
                return Err(format!(
                    "slot {} has a semantic descriptor without one unambiguous authorized owner",
                    slot.index
                ));
            }
            let key = AttachKey::of(slot);
            if !keys.insert(key) {
                return Err(format!("duplicate exact target at slot {}", slot.index));
            }
            let indexed = self.slot_by_key.get(&key).copied();
            if self.retired_slots.contains(&position) {
                if indexed.is_some() {
                    return Err(format!(
                        "retired slot {} remains attach-indexed",
                        slot.index
                    ));
                }
            } else if indexed != Some(position) {
                return Err(format!(
                    "slot {} is missing from the exact attach index",
                    slot.index
                ));
            }
        }
        if self
            .slot_by_key
            .values()
            .any(|position| *position >= self.slots.len())
        {
            return Err("exact attach index points outside the slot vector".into());
        }
        Ok(())
    }

    fn remap_modules(&self, rebuilt: &mut AttachPlan) -> Result<(), String> {
        let mut source_ids = BTreeMap::new();
        let mut objects = BTreeSet::new();
        let mut next = self
            .modules
            .iter()
            .map(|module| module.id.0)
            .chain(
                self.slots
                    .iter()
                    .flat_map(|slot| slot.module_ids.iter().map(|id| id.0)),
            )
            .max()
            .map_or(0, |id| id + 1);
        for module in &mut rebuilt.modules {
            if !objects.insert(module.object) {
                return Err(format!("duplicate module object {:?}", module.object));
            }
            let source = module.id;
            let stable = self
                .modules
                .iter()
                .find(|old| old.object == module.object)
                .map(|old| old.id)
                .unwrap_or_else(|| {
                    let id = ModuleId(next);
                    next += 1;
                    id
                });
            if source_ids.insert(source, stable).is_some() {
                return Err(format!("duplicate rebuilt module id {}", source.0));
            }
            module.id = stable;
        }
        for slot in &mut rebuilt.slots {
            let mut ids = Vec::with_capacity(slot.module_ids.len());
            for source in &slot.module_ids {
                let Some(stable) = source_ids.get(source).copied() else {
                    return Err(format!(
                        "slot {} references missing rebuilt module {}",
                        slot.index, source.0
                    ));
                };
                ids.push(stable);
            }
            ids.sort();
            ids.dedup();
            slot.module_ids = ids;
        }
        Ok(())
    }
}

pub fn ensure_capacity(plan: &AttachPlan) -> Result<(), String> {
    let required = plan.slots.len();
    let available = MAX_SLOTS as usize;
    if required > available {
        Err(format!(
            "attach plan requires {required} slots but only {available} are available; refusing to attach a prefix"
        ))
    } else {
        Ok(())
    }
}

/// A stand-in object identity for slot fixtures in other modules' unit tests.
#[cfg(test)]
pub(crate) const TEST_OBJECT: ObjectKey = ObjectKey {
    device: Device { major: 8, minor: 1 },
    inode: 42,
};

#[cfg(test)]
pub(crate) const TEST_PINNED_OBJECT: PinnedObjectId = PinnedObjectId(42);

/// One attachable target as discovery reported it.
struct Target<'a> {
    name: &'a str,
    object: PinnedObjectId,
    object_path: &'a str,
    file_offset: u64,
    fork_safe: bool,
    semantic_authorized: bool,
}

/// One module lowered for `merge`.
struct Discovered<'a> {
    object: PinnedObjectId,
    key: ObjectKey,
    path: &'a str,
    source: &'static str,
    tables: Vec<TableSummary>,
    interfaces: usize,
    surfaces: Vec<SurfaceSummary>,
    /// Published table slots seen, including the NULL ones that became `skipped`.
    entries_seen: usize,
    targets: Vec<Target<'a>>,
    skipped: Vec<Skipped>,
}

/// A slot under construction: the names and modules claiming one target.
struct Building {
    object: PinnedObjectId,
    object_path: String,
    file_offset: u64,
    name_authority: BTreeMap<String, bool>,
    fork_safe: bool,
    module_ids: Vec<ModuleId>,
}

fn merge(
    discovered: Vec<Discovered<'_>>,
    vendor_interfaces: usize,
    interface_list: String,
    allocated_slots: usize,
    existing_slots: &BTreeMap<AttachKey, usize>,
) -> AttachPlan {
    let capacity = MAX_SLOTS as usize;
    let mut groups: Vec<Vec<Discovered<'_>>> = Vec::new();
    let mut group_positions: BTreeMap<PinnedObjectId, usize> = BTreeMap::new();
    for module in discovered {
        let position = *group_positions.entry(module.object).or_insert_with(|| {
            let position = groups.len();
            groups.push(Vec::new());
            position
        });
        groups[position].push(module);
    }

    let mut positions: BTreeMap<(PinnedObjectId, u64), usize> = BTreeMap::new();
    let mut building: Vec<Building> = Vec::new();
    let mut modules = Vec::new();
    let mut modules_skipped = Vec::new();
    let mut skipped = Vec::new();
    let mut surfaces = Vec::new();
    let mut entries_seen = 0usize;
    let mut allocated_slots = allocated_slots;
    for group in groups {
        let key = group[0].key;
        let object = group[0].object;
        let path = group[0].path;
        let source = group[0].source;
        let wanted: BTreeSet<AttachKey> = group
            .iter()
            .flat_map(|module| &module.targets)
            .map(|target| AttachKey {
                object: target.object,
                file_offset: target.file_offset,
            })
            .filter(|target| {
                !positions.contains_key(&(target.object, target.file_offset))
                    && !existing_slots.contains_key(target)
            })
            .collect();
        if allocated_slots + wanted.len() > capacity {
            modules_skipped.push(Skipped {
                subject: path.to_string(),
                reason: format!(
                    "module needs {} more of the {MAX_SLOTS} attach slots; {} are in use \
                     — refusing to attach a prefix",
                    wanted.len(),
                    allocated_slots
                ),
            });
            continue;
        }
        allocated_slots += wanted.len();

        // One object is one module however many sources described it. A manifest
        // corroborating a scanned module must not read as two rivals claiming the same
        // target: that would make every corroborated slot COUNT_ONLY (§4.7) and turn
        // the fallback `--manifest` of §4.12 into a trapdoor.
        let id = ModuleId(modules.len() as u32);
        modules.push(ModuleSummary {
            id,
            object,
            key,
            path: path.to_string(),
            tables: Vec::new(),
            interfaces: 0,
            source,
            corroborated: false,
            skipped: Vec::new(),
        });
        let mut seen_targets = BTreeSet::new();
        let mut seen_skips = BTreeSet::new();
        let mut seen_tables = Vec::new();
        let mut seen_surfaces = Vec::new();
        let mut group_surfaces = Vec::new();
        let mut group_skips = Vec::new();
        for module in group {
            debug_assert_eq!(
                module.entries_seen,
                module.targets.len() + module.skipped.len()
            );
            let mut target_occurrences = BTreeMap::new();
            for target in &module.targets {
                let record = (target.name.to_string(), target.object, target.file_offset);
                let occurrence = target_occurrences.entry(record.clone()).or_insert(0usize);
                seen_targets.insert((record.0, record.1, record.2, *occurrence));
                *occurrence += 1;
                let position = *positions
                    .entry((target.object, target.file_offset))
                    .or_insert_with(|| {
                        building.push(Building {
                            object: target.object,
                            object_path: target.object_path.to_string(),
                            file_offset: target.file_offset,
                            name_authority: BTreeMap::new(),
                            fork_safe: true,
                            module_ids: Vec::new(),
                        });
                        building.len() - 1
                    });
                let slot = &mut building[position];
                // A module reaching one target under two names is aliasing, not module
                // ambiguity, so each module is recorded at most once per slot.
                if !slot.module_ids.contains(&id) {
                    slot.module_ids.push(id);
                }
                slot.name_authority
                    .entry(target.name.to_string())
                    .and_modify(|authorized| *authorized |= target.semantic_authorized)
                    .or_insert(target.semantic_authorized);
                slot.fork_safe &= target.fork_safe;
            }
            let summary = &mut modules[id.0 as usize];
            if summary.source != module.source {
                summary.source = "scan+manifest";
            }
            let mut module_tables = Vec::new();
            for table in module.tables {
                let occurrence = module_tables
                    .iter()
                    .filter(|known| *known == &table)
                    .count();
                module_tables.push(table.clone());
                if !seen_tables.iter().any(|(source, known, known_occurrence)| {
                    *source == module.source && known == &table && *known_occurrence == occurrence
                }) {
                    seen_tables.push((module.source, table.clone(), occurrence));
                    summary.tables.push(table);
                }
            }
            // Never summed across sources: the scan and a manifest describing one
            // provider both count *its* interfaces, so adding them reports two where
            // there is one — on exactly the corroborated path this slice is built
            // around. Each source sees a subset (the scan only records an interface
            // whose table it decoded), so the most any one saw is the honest number.
            summary.interfaces = summary.interfaces.max(module.interfaces);
            let mut module_surfaces = Vec::new();
            for surface in module.surfaces {
                let occurrence = module_surfaces
                    .iter()
                    .filter(|known| *known == &surface)
                    .count();
                module_surfaces.push(surface.clone());
                if !seen_surfaces
                    .iter()
                    .any(|(source, known, known_occurrence)| {
                        *source == module.source
                            && known == &surface
                            && *known_occurrence == occurrence
                    })
                {
                    seen_surfaces.push((module.source, surface.clone(), occurrence));
                    group_surfaces.push(surface);
                }
            }
            let mut skip_occurrences = BTreeMap::new();
            for skip in module.skipped {
                let record = (skip.subject.clone(), skip.reason.clone());
                let occurrence = skip_occurrences.entry(record.clone()).or_insert(0usize);
                if seen_skips.insert((module.source, record.0, record.1, *occurrence)) {
                    summary.skipped.push(skip.clone());
                    group_skips.push(skip);
                }
                *occurrence += 1;
            }
        }
        entries_seen += seen_targets.len() + seen_skips.len();
        surfaces.extend(group_surfaces);
        skipped.extend(group_skips);
    }

    let slots: Vec<Slot> = building
        .into_iter()
        .enumerate()
        .map(|(index, slot)| {
            let names: Vec<_> = slot.name_authority.keys().cloned().collect();
            let semantic_authorized = slot.name_authority.values().all(|value| *value);
            let (descriptor_index, semantic_ambiguous) = crate::kinds::descriptor_index(&names);
            let semantics = crate::kinds::DESCRIPTORS[descriptor_index as usize];
            // Counts through a target two modules both publish cannot be attributed
            // to either, so the slot may not carry semantics — it is counted, and the
            // report says it was not attributed.
            let shared = slot.module_ids.len() >= 2;
            Slot {
                index: index as u32,
                descriptor_index: if shared || !semantic_authorized {
                    0
                } else {
                    descriptor_index
                },
                object: slot.object,
                object_path: slot.object_path,
                file_offset: slot.file_offset,
                aliased: names.len() >= 2,
                names,
                semantics: if shared || !semantic_authorized {
                    SlotSemantics::COUNT_ONLY
                } else {
                    semantics
                },
                semantic_authorized,
                semantic_ambiguous: semantic_ambiguous || shared,
                fork_safe: slot.fork_safe,
                module_ids: slot.module_ids,
            }
        })
        .collect();
    let mut plan = AttachPlan::from_slots(slots);
    plan.modules = modules;
    plan.skipped = skipped;
    plan.modules_skipped = modules_skipped;
    plan.entries_seen = entries_seen;
    plan.surfaces = surfaces;
    plan.vendor_interfaces = vendor_interfaces;
    plan.interface_list = interface_list;
    plan
}

/// Merges every reconciled scanned module into one plan over a single slot space.
pub fn build_from_reconciled_modules(modules: &[ReconciledModule]) -> AttachPlan {
    merge(
        modules.iter().map(lower_scanned).collect(),
        0,
        "absent".into(),
        0,
        &BTreeMap::new(),
    )
}

/// Every module discovery found — scanned and manifest-supplied — merged into one
/// plan over the single slot space the eBPF side has. Both sources lower into
/// `Discovered`, so a target both describe becomes one slot rather than two probes
/// on one address (spec §4.12's union).
pub fn build_from_sources(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
) -> AttachPlan {
    build_from_sources_with(
        scanned,
        manifests,
        |key, path| pinned.id_for_manifest(key, path),
        0,
        &BTreeMap::new(),
    )
}

fn build_from_sources_with(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    mut pinned_id: impl FnMut(ObjectKey, &str) -> Option<PinnedObjectId>,
    allocated_slots: usize,
    existing_slots: &BTreeMap<AttachKey, usize>,
) -> AttachPlan {
    let mut discovered: Vec<Discovered<'_>> = scanned.iter().map(lower_scanned).collect();
    let mut orphaned = Vec::new();
    for manifest in manifests {
        let (module, skipped) = lower_manifest(manifest, &mut pinned_id);
        discovered.extend(module);
        orphaned.extend(skipped);
    }
    // The scan never calls the provider, so it contributes no C_GetInterfaceList
    // enumeration and leaves nothing present-but-undecoded: every interface it
    // records names a table it decoded. Only a manifest can report either.
    let mut plan = merge(
        discovered,
        manifests.iter().map(|m| m.vendor_interfaces.len()).sum(),
        manifests.first().map_or_else(
            || "absent".to_string(),
            |m| acquisition_label(&m.interface_list),
        ),
        allocated_slots,
        existing_slots,
    );
    plan.skipped.extend(orphaned);
    plan
}

#[cfg(test)]
fn build_from_test_sources(scanned: &[ReconciledModule], manifests: &[Manifest]) -> AttachPlan {
    build_from_sources_with(
        scanned,
        manifests,
        |key, _| u32::try_from(key.inode).ok().map(PinnedObjectId),
        0,
        &BTreeMap::new(),
    )
}

fn lower_scanned(module: &ReconciledModule) -> Discovered<'_> {
    let scanned = &module.scanned;
    let mut tables = Vec::new();
    let mut surfaces = Vec::new();
    let mut targets = Vec::new();
    let mut skipped = Vec::new();
    let mut entries_seen = 0usize;
    for (index, table) in scanned.tables.iter().enumerate() {
        // CKF_INTERFACE_FORK_SAFE is bit 0. A table no standard interface exposes
        // is never assumed fork-safe.
        let fork_safe = scanned.interfaces.iter().any(|interface| {
            interface.table == Some(index)
                && interface.name_class == "exact_standard"
                && interface.flags & 1 != 0
        });
        // Every record the scan decoded, including the ones no probe can reach:
        // "seen" must not shrink because a target turned out to be unusable,
        // or `slots` vs `table_entries` stops reading as attached vs seen.
        let published = table.entries.len() + table.null_entries.len() + table.unpinned.len();
        entries_seen += published;
        tables.push(TableSummary {
            version: table.version,
            entries: table.entries.len(),
            source: "scan",
        });
        surfaces.push(SurfaceSummary {
            source: format!(
                "{} table {}.{}",
                scanned.path, table.version.0, table.version.1
            ),
            walk: table.walk.to_string(),
            // The bytes were read straight out of the target's mapping.
            acquisition: "ok".into(),
            functions: published,
        });
        targets.extend(table.entries.iter().zip(&module.entry_objects[index]).map(
            |(entry, object)| Target {
                name: entry.name,
                object: *object,
                object_path: &entry.object_path,
                file_offset: entry.file_offset,
                fork_safe,
                semantic_authorized: false,
            },
        ));
        skipped.extend(table.null_entries.iter().map(|name| Skipped {
            subject: (*name).to_string(),
            reason: "null pointer".into(),
        }));
        skipped.extend(table.unpinned.iter().cloned());
    }
    Discovered {
        object: module.object,
        key: scanned.key,
        path: &scanned.path,
        source: "scan",
        tables,
        interfaces: scanned.interfaces.len(),
        surfaces,
        entries_seen,
        targets,
        skipped,
    }
}

/// Which `provenance_objects[]` record carries the identity of an `objects[]` record.
/// Matching by equal path and identity first, then by one unique whole-file hash, is
/// what `validate_structure` guarantees. The two paths are *not* the same string in
/// general — `p11scope-discover` writes `objects[].path` as the `--module` argument
/// was spelled and `provenance_objects[].path` as `/proc/self/maps` renders it, which
/// differ for any provider named by symlink. A digest shared by multiple non-path
/// records is incomparable rather than first-wins authority.
///
/// Public because `main.rs::retarget_to_pins` rewrites the record this returns before
/// the plan is built: one relation used by both, rather than two written against
/// different fields, which is exactly how they drifted apart once already.
pub fn provenance_of(m: &Manifest, object: &ObjectRecord) -> Option<usize> {
    if let Some((index, provenance)) = m
        .provenance_objects
        .iter()
        .enumerate()
        .find(|(_, provenance)| provenance.path == object.path)
    {
        return (provenance.identity.sha256 == object.identity.sha256).then_some(index);
    }
    let sha256 = object.identity.sha256.as_deref()?;
    let mut matches = m
        .provenance_objects
        .iter()
        .enumerate()
        .filter(|(_, provenance)| provenance.identity.sha256.as_deref() == Some(sha256));
    let (index, _) = matches.next()?;
    matches.next().is_none().then_some(index)
}

/// The (device, inode) discovery recorded for a manifest object. Identity lives
/// in `provenance_objects`; `objects[]` carries only paths and hashes.
fn object_key(m: &Manifest, object: &ObjectRecord) -> Option<ObjectKey> {
    let provenance = &m.provenance_objects[provenance_of(m, object)?];
    Some(ObjectKey {
        device: Device {
            major: provenance.device_major,
            minor: provenance.device_minor,
        },
        inode: provenance.inode,
    })
}

#[cfg(test)]
fn build(m: &Manifest) -> AttachPlan {
    let mut ids = BTreeMap::new();
    for key in m.objects.iter().filter_map(|object| object_key(m, object)) {
        let next = PinnedObjectId(ids.len() as u32);
        ids.entry(key).or_insert(next);
    }
    let (discovered, orphaned) = lower_manifest(m, |key, _| ids.get(&key).copied());
    let mut plan = merge(
        discovered.into_iter().collect(),
        m.vendor_interfaces.len(),
        acquisition_label(&m.interface_list),
        0,
        &BTreeMap::new(),
    );
    plan.skipped.extend(orphaned);
    plan
}

fn lower_manifest(
    m: &Manifest,
    mut pinned_id: impl FnMut(ObjectKey, &str) -> Option<PinnedObjectId>,
) -> (Option<Discovered<'_>>, Vec<Skipped>) {
    let mut tables = Vec::new();
    let mut surfaces = Vec::new();
    let mut targets = Vec::new();
    let mut skipped = Vec::new();
    let mut entries_seen = 0usize;

    for surface in &m.surfaces {
        surfaces.push(SurfaceSummary {
            source: source_label(&surface.source),
            walk: walk_label(&surface.walk),
            acquisition: acquisition_label(&surface.acquisition),
            functions: surface.functions.len(),
        });
        tables.push(TableSummary {
            version: surface
                .version
                .map_or((0, 0), |version| (version.major, version.minor)),
            entries: surface.functions.len(),
            source: "manifest",
        });
        let fork_safe = matches!(
            &surface.source,
            SurfaceSource::Interface { flags, .. } if flags & 1 != 0
        );
        for f in &surface.functions {
            entries_seen += 1;
            let mut skip = |reason: String| {
                skipped.push(Skipped {
                    subject: f.name.clone(),
                    reason,
                })
            };
            match &f.resolution {
                Resolution::Resolved {
                    object,
                    file_offset,
                } => {
                    let Some(record) = m.objects.iter().find(|o| o.id == *object) else {
                        skip(format!("object id {object} missing from manifest"));
                        continue;
                    };
                    let Some(key) = object_key(m, record) else {
                        skip(format!(
                            "object id {object} has no provenance record naming {}",
                            record.path
                        ));
                        continue;
                    };
                    let Some(object) = pinned_id(key, &record.path) else {
                        skip(format!(
                            "object id {object} has no comparable pinned identity"
                        ));
                        continue;
                    };
                    targets.push(Target {
                        name: &f.name,
                        object,
                        object_path: &record.path,
                        file_offset: *file_offset,
                        fork_safe,
                        semantic_authorized: true,
                    });
                }
                Resolution::NullPointer => skip("null pointer".into()),
                Resolution::NonFileBacked => skip("non-file-backed".into()),
                Resolution::Unmapped => skip("unmapped".into()),
                Resolution::UnusableFile { reason, .. } => skip(reason.clone()),
            }
        }
    }

    let key = m
        .objects
        .iter()
        .find(|o| o.path == m.module_path)
        .and_then(|o| object_key(m, o));
    let Some(key) = key else {
        return (None, skipped);
    };
    let Some(module_record) = m.objects.iter().find(|o| o.path == m.module_path) else {
        return (None, skipped);
    };
    let Some(object) = pinned_id(key, &module_record.path) else {
        return (None, skipped);
    };
    (
        Some(Discovered {
            object,
            // Informational only: every target carries the key of the object it
            // resolved into, which for a forwarded entry is a dependency, not this.
            key,
            path: &m.module_path,
            source: "manifest",
            tables,
            interfaces: m
                .surfaces
                .iter()
                .filter(|s| matches!(s.source, SurfaceSource::Interface { .. }))
                .count(),
            surfaces,
            entries_seen,
            targets,
            skipped,
        }),
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::scan::ScannedModule;
    use crate::process::{MountNamespaceId, ProcessViewId};
    use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
    use p11scope_manifest::manifest::*;

    fn manifest_with(functions: Vec<FunctionRecord>) -> Manifest {
        Manifest {
            schema: SCHEMA.to_string(),
            module_path: "/opt/p11.so".into(),
            objects: vec![ObjectRecord {
                id: 0,
                path: "/opt/p11.so".into(),
                identity: ObjectIdentity {
                    kind: IdentityKind::GnuBuildId,
                    value: Some("aa".into()),
                    sha256: Some("11".repeat(32)),
                    reusable: true,
                    note: None,
                },
            }],
            provenance_objects: vec![ProvenanceObject {
                path: "/opt/p11.so".into(),
                device_major: 8,
                device_minor: 1,
                inode: 42,
                identity: ObjectIdentity {
                    kind: IdentityKind::GnuBuildId,
                    value: Some("aa".into()),
                    sha256: Some("11".repeat(32)),
                    reusable: true,
                    note: None,
                },
            }],
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: None,
                walk: WalkOutcome::Full,
                functions,
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        }
    }

    fn rec(name: &str, r: Resolution) -> FunctionRecord {
        FunctionRecord {
            name: name.into(),
            resolution: r,
        }
    }

    fn resolved(name: &str, file_offset: u64) -> FunctionRecord {
        rec(
            name,
            Resolution::Resolved {
                object: 0,
                file_offset,
            },
        )
    }

    fn scanned_with(
        key: ObjectKey,
        path: &str,
        offsets: impl IntoIterator<Item = u64>,
    ) -> ReconciledModule {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let entries: Vec<_> = offsets
            .into_iter()
            .map(|file_offset| ScannedEntry {
                name: "C_Sign",
                object: key,
                object_path: path.into(),
                file_offset,
            })
            .collect();
        let object = PinnedObjectId(key.inode as u32);
        ReconciledModule {
            object,
            entry_objects: vec![vec![object; entries.len()]],
            scanned: ScannedModule {
                view: ProcessViewId(0),
                mount_namespace: MountNamespaceId {
                    device: 1,
                    inode: 1,
                },
                key,
                path: path.into(),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries,
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000,
                }],
                interfaces: vec![],
            },
        }
    }

    #[test]
    fn one_slot_per_unique_target_and_aliases_flagged() {
        let m = manifest_with(vec![
            resolved("C_Sign", 0x10),
            resolved("C_Verify", 0x20),
            resolved("C_OpenSession", 0x40),
            resolved("C_CancelFunction", 0x30),
            resolved("C_WaitForSlotEvent", 0x30),
        ]);
        let p = build(&m);
        assert_eq!(p.slots.len(), 4, "aliased pair collapses to one slot");
        assert_eq!(p.entries_seen, 5);
        let aliased: Vec<&Slot> = p.slots.iter().filter(|s| s.aliased).collect();
        assert_eq!(aliased.len(), 1);
        assert_eq!(
            aliased[0].names,
            vec!["C_CancelFunction", "C_WaitForSlotEvent"]
        );
        assert!(aliased[0].semantic_ambiguous);
        assert_eq!(aliased[0].semantics, SlotSemantics::COUNT_ONLY);
        // Slot indices are dense and start at zero.
        let idx: Vec<u32> = p.slots.iter().map(|s| s.index).collect();
        assert_eq!(idx, vec![0, 1, 2, 3]);
        // Assert C_OpenSession slot gets the exact descriptor.
        let open_session_slot = p
            .slots
            .iter()
            .find(|s| s.names == vec!["C_OpenSession"])
            .unwrap();
        assert_eq!(
            open_session_slot.semantics,
            crate::kinds::descriptor("C_OpenSession").unwrap()
        );
        // The manifest is one module, and aliasing inside it is not module ambiguity.
        assert_eq!(p.modules.len(), 1);
        assert_eq!(p.modules[0].source, "manifest");
        assert_eq!(p.module_ambiguous, 0);
        for slot in &p.slots {
            assert_eq!(slot.module_ids, vec![ModuleId(0)]);
            assert_eq!(slot.object_path, "/opt/p11.so");
            assert_eq!(slot.object, PinnedObjectId(0));
        }
    }

    #[test]
    fn scan_only_target_is_unverified_and_count_only() {
        let scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10]);

        let plan = build_from_reconciled_modules(std::slice::from_ref(&scanned));

        assert_eq!(plan.slots.len(), 1);
        assert_eq!(plan.entries_seen, 1);
        assert_eq!(plan.slots[0].names, ["C_Sign"]);
        assert_eq!(plan.slots[0].semantics, SlotSemantics::COUNT_ONLY);
        assert!(!plan.slots[0].semantic_authorized);
        assert!(
            !plan.slots[0].semantic_ambiguous,
            "missing semantic authority is not alias or module ambiguity"
        );
    }

    #[test]
    fn identical_scan_and_manifest_claim_counts_one_entry() {
        let scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10]);
        let manifest = manifest_with(vec![resolved("C_Sign", 0x10)]);

        let plan = build_from_test_sources(
            std::slice::from_ref(&scanned),
            std::slice::from_ref(&manifest),
        );

        assert_eq!(plan.modules.len(), 1);
        assert_eq!(plan.modules[0].tables.len(), 2, "both sources stay visible");
        assert_eq!(plan.slots.len(), 1);
        assert_eq!(plan.entries_seen, 1, "one published table position");
        assert!(plan.slots[0].semantic_authorized);
        assert_eq!(
            plan.slots[0].semantics,
            crate::kinds::descriptor("C_Sign").unwrap()
        );
    }

    #[test]
    fn manifest_cannot_authorize_a_different_name_at_the_same_target() {
        let scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10]);
        let manifest = manifest_with(vec![resolved("C_Login", 0x10)]);

        let plan = build_from_test_sources(
            std::slice::from_ref(&scanned),
            std::slice::from_ref(&manifest),
        );

        assert_eq!(plan.slots.len(), 1);
        assert_eq!(plan.slots[0].names, ["C_Login", "C_Sign"]);
        assert!(!plan.slots[0].semantic_authorized);
        assert_eq!(plan.slots[0].semantics, SlotSemantics::COUNT_ONLY);
        assert!(plan.slots[0].semantic_ambiguous);
    }

    #[test]
    fn raw_key_cannot_authorize_a_distinct_pinned_object() {
        let mut scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10]);
        let scanned_object = PinnedObjectId(200);
        scanned.object = scanned_object;
        scanned.entry_objects[0][0] = scanned_object;
        let manifest = manifest_with(vec![resolved("C_Sign", 0x10)]);
        let manifest_object = PinnedObjectId(100);

        let plan = build_from_sources_with(
            std::slice::from_ref(&scanned),
            std::slice::from_ref(&manifest),
            |_, _| Some(manifest_object),
            0,
            &BTreeMap::new(),
        );

        assert_eq!(plan.slots.len(), 2, "distinct pinned objects stay distinct");
        let scan_slot = plan
            .slots
            .iter()
            .find(|slot| slot.object == scanned_object)
            .unwrap();
        assert_eq!(scan_slot.semantics, SlotSemantics::COUNT_ONLY);
        assert!(!scan_slot.semantic_authorized);
        assert!(!scan_slot.semantic_ambiguous);
        let manifest_slot = plan
            .slots
            .iter()
            .find(|slot| slot.object == manifest_object)
            .unwrap();
        assert_eq!(
            manifest_slot.semantics,
            crate::kinds::descriptor("C_Sign").unwrap()
        );
        assert!(manifest_slot.semantic_authorized);
    }

    #[test]
    fn unresolvable_entries_become_skipped_evidence() {
        let m = manifest_with(vec![
            resolved("C_Sign", 0x10),
            rec("C_GetFunctionStatus", Resolution::NullPointer),
            rec("C_Weird", Resolution::NonFileBacked),
            rec("C_Gone", Resolution::Unmapped),
        ]);
        let p = build(&m);
        assert_eq!(p.slots.len(), 1);
        assert_eq!(p.skipped.len(), 3);
        assert_eq!(p.entries_seen, 4);
        let reasons: Vec<&str> = p.skipped.iter().map(|s| s.reason.as_str()).collect();
        assert!(reasons.contains(&"null pointer"));
        assert!(reasons.contains(&"non-file-backed"));
        assert!(reasons.contains(&"unmapped"));
    }

    #[test]
    fn an_object_with_no_provenance_identity_is_skipped_not_attached() {
        let mut m = manifest_with(vec![resolved("C_Sign", 0x10)]);
        m.provenance_objects[0].path = "/opt/other.so".into();
        m.provenance_objects[0].identity.sha256 = Some("22".repeat(32));
        let p = build(&m);
        assert!(p.slots.is_empty());
        assert_eq!(p.skipped.len(), 1);
        assert!(
            p.skipped[0].reason.contains("no provenance record"),
            "{:?}",
            p.skipped[0]
        );
    }

    #[test]
    fn surface_summaries_are_populated_from_the_manifest() {
        let m = manifest_with(vec![resolved("C_Sign", 0x10)]);
        let p = build(&m);
        assert_eq!(p.surfaces.len(), 1);
        assert_eq!(p.surfaces[0].source, "legacy_function_list");
        assert_eq!(p.surfaces[0].walk, "full");
        assert_eq!(p.surfaces[0].acquisition, "ok");
        assert_eq!(p.surfaces[0].functions, 1);
        assert_eq!(p.vendor_interfaces, 0);
        assert_eq!(p.interface_list, "absent");
    }

    /// An interface name is provider-supplied bytes. `inspect` shows them; a
    /// capture document must not carry them, however they got into the manifest.
    #[test]
    fn an_interface_surface_is_labelled_by_classification_never_by_provider_bytes() {
        let mut m = manifest_with(vec![resolved("C_Sign", 0x10)]);
        m.surfaces[0].source = SurfaceSource::Interface {
            index: 0,
            raw_name_hex: Some("504b4353203131".into()),
            name_lossy: Some("PKCS 11".into()),
            name_error: None,
            flags: 1,
            classification: InterfaceClassification::ExactStandard,
        };
        let p = build(&m);
        assert_eq!(p.surfaces[0].source, "interface[0] exact_standard");

        m.surfaces[0].source = SurfaceSource::Interface {
            index: 3,
            raw_name_hex: None,
            name_lossy: None,
            name_error: Some("null name pointer".into()),
            flags: 0,
            classification: InterfaceClassification::CorroboratedStandardPrefix,
        };
        m.surfaces[0].walk = WalkOutcome::KnownPrefix;
        let p = build(&m);
        assert_eq!(
            p.surfaces[0].source, "interface[3] corroborated_standard_prefix",
            "an unnamed interface is classified, never labelled with its error text"
        );
    }

    #[test]
    fn surface_summaries_carry_gap_provenance() {
        let mut m = manifest_with(vec![resolved("C_Sign", 0x10)]);
        m.interface_list = Acquisition::Error {
            detail: "boom".into(),
        };
        m.surfaces[0].walk = WalkOutcome::KnownPrefix;
        m.surfaces[0].acquisition = Acquisition::Error {
            detail: "partial read".into(),
        };
        m.vendor_interfaces = vec![VendorInterface {
            index: 1,
            raw_name_hex: None,
            name_lossy: None,
            name_error: Some("null name pointer".into()),
            version: None,
            version_error: Some("null function-list pointer".into()),
            flags: 0,
            func_list_null: true,
        }];
        let p = build(&m);
        assert_eq!(p.surfaces[0].walk, "known_prefix");
        assert_eq!(p.surfaces[0].acquisition, "error: partial read");
        assert_eq!(p.vendor_interfaces, 1);
        assert_eq!(p.interface_list, "error: boom");
    }

    #[test]
    fn known_matrix_fits_and_overflow_is_refused_whole() {
        let make = |count| {
            let mut plan = AttachPlan::from_slots(
                (0..count)
                    .map(|index| Slot {
                        index: index as u32,
                        descriptor_index: 0,
                        object: PinnedObjectId(42),
                        object_path: "/opt/p11.so".into(),
                        file_offset: index as u64 * 8,
                        names: vec!["C_Initialize".into()],
                        aliased: false,
                        semantics: SlotSemantics::COUNT_ONLY,
                        semantic_authorized: true,
                        semantic_ambiguous: false,
                        fork_safe: false,
                        module_ids: vec![ModuleId(0)],
                    })
                    .collect(),
            );
            plan.entries_seen = count;
            plan
        };
        assert!(ensure_capacity(&make(424)).is_ok());
        let error = ensure_capacity(&make(513)).unwrap_err();
        assert!(error.contains("requires 513"));
        assert!(error.contains("only 512"));
        assert!(error.contains("refusing to attach a prefix"));
    }

    /// Mutation caught: allowing a scan-only or ambiguous target to retain a
    /// canonical descriptor would make semantic capture depend on discovery.
    #[test]
    fn slot_descriptor_indices_follow_manifest_authority() {
        let mut scan = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10]);
        scan.scanned.tables[0].entries[0].name = "C_SignInit";
        let scan = build_from_test_sources(&[scan], &[]);
        assert_eq!(scan.slots[0].descriptor_index, 0);

        let manifest = build(&manifest_with(vec![resolved("C_SignInit", 0x10)]));
        assert_eq!(
            manifest.slots[0].descriptor_index,
            crate::kinds::function_id("C_SignInit").unwrap() + 1
        );

        let aliases = build(&manifest_with(vec![
            resolved("C_InitPIN", 0x10),
            resolved("C_SetPIN", 0x10),
        ]));
        assert_eq!(
            aliases.slots[0].descriptor_index,
            crate::kinds::function_id("C_InitPIN").unwrap() + 1
        );

        let conflict = build(&manifest_with(vec![
            resolved("C_SignInit", 0x10),
            resolved("C_VerifyInit", 0x10),
        ]));
        assert_eq!(conflict.slots[0].descriptor_index, 0);
    }

    #[test]
    fn a_manifest_over_the_ceiling_is_refused_whole_and_names_the_module() {
        let m = manifest_with(
            (0..(MAX_SLOTS as u64 + 1))
                .map(|i| resolved("C_Sign", i * 8))
                .collect(),
        );
        let p = build(&m);
        assert!(p.slots.is_empty(), "a prefix is never attached");
        assert!(p.modules.is_empty());
        assert_eq!(p.modules_skipped.len(), 1);
        assert_eq!(p.modules_skipped[0].subject, "/opt/p11.so");
        assert!(
            p.modules_skipped[0].reason.contains("513")
                && p.modules_skipped[0].reason.contains("512"),
            "{:?}",
            p.modules_skipped[0]
        );
    }

    /// A manifest and the scan describing the *same object* are one module with one
    /// slot space, not two rivals: treating them as two would mark every corroborated
    /// target COUNT_ONLY and force PARTIAL, turning `--manifest` into a trapdoor.
    #[test]
    fn a_manifest_and_a_scan_of_the_same_object_are_one_module() {
        use crate::discovery::scan::ScannedInterface;

        let mut m = manifest_with(vec![resolved("C_Sign", 0x10), resolved("C_Login", 0x50)]);
        // Both sources describe the same one standard interface of the same
        // provider — the shape that made the old sum report two.
        m.surfaces[0].source = SurfaceSource::Interface {
            index: 0,
            raw_name_hex: Some("504b4353203131".into()),
            name_lossy: Some("PKCS 11".into()),
            name_error: None,
            flags: 1,
            classification: InterfaceClassification::ExactStandard,
        };
        let mut scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10, 0x60]);
        scanned.scanned.tables[0].entries[1].name = "C_Verify";
        scanned.scanned.interfaces = vec![ScannedInterface {
            index: 0,
            name_class: "exact_standard",
            name_lossy: Some("PKCS 11".into()),
            flags: 1,
            table: Some(0),
        }];

        let p = build_from_test_sources(std::slice::from_ref(&scanned), std::slice::from_ref(&m));
        assert_eq!(p.modules.len(), 1, "{:?}", p.modules);
        assert_eq!(p.modules[0].source, "scan+manifest");
        assert_eq!(p.module_ambiguous, 0, "corroboration is not ambiguity");
        // The union: 0x10 from both, 0x60 only the scan saw, 0x50 only the manifest.
        let offsets: Vec<u64> = p.slots.iter().map(|s| s.file_offset).collect();
        assert_eq!(offsets, vec![0x10, 0x60, 0x50]);
        for slot in &p.slots {
            assert_eq!(slot.module_ids, vec![ModuleId(0)], "{slot:?}");
            assert!(!slot.semantic_ambiguous, "{slot:?}");
        }
        // Both sources' tables stay visible as evidence — they declare their own
        // source, so two entries for one table is honest. `interfaces` is a flat
        // count with nowhere to say that, so it must never double.
        assert_eq!(p.modules[0].tables.len(), 2);
        assert_eq!(
            p.modules[0].interfaces, 1,
            "one provider, one interface, described twice"
        );
    }

    #[test]
    fn an_oversized_scan_cannot_be_reattached_through_a_manifest_subset() {
        let later = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 99,
        };
        let scanned = [
            scanned_with(TEST_OBJECT, "/opt/p11.so", (0..513).map(|i| i * 8)),
            scanned_with(later, "/opt/later.so", [0x9000, 0x9010]),
        ];
        let manifest = manifest_with(vec![resolved("C_Sign", 0)]);

        let p = build_from_test_sources(&scanned, std::slice::from_ref(&manifest));
        assert_eq!(p.slots.len(), 2, "only the later distinct module fits");
        assert!(
            p.slots
                .iter()
                .all(|slot| slot.object == PinnedObjectId(later.inode as u32))
        );
        assert_eq!(p.modules.len(), 1);
        assert_eq!(p.modules[0].path, "/opt/later.so");
        assert_eq!(p.modules[0].source, "scan");
        assert_eq!(p.modules_skipped.len(), 1);
        assert_eq!(p.modules_skipped[0].subject, "/opt/p11.so");
        assert!(
            p.modules_skipped[0]
                .reason
                .contains("module needs 513 more")
        );
        assert!(p.modules_skipped[0].reason.contains("0 are in use"));
    }

    #[test]
    fn an_overflowing_scan_manifest_union_refuses_the_whole_module() {
        let later = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 99,
        };
        let scanned = [
            scanned_with(TEST_OBJECT, "/opt/p11.so", [0, 8]),
            scanned_with(later, "/opt/later.so", [0x9000, 0x9010]),
        ];
        let manifest = manifest_with((0..513).map(|i| resolved("C_Sign", i * 8)).collect());

        let p = build_from_test_sources(&scanned, std::slice::from_ref(&manifest));
        assert_eq!(
            p.slots.len(),
            2,
            "no scan prefix of the refused module remains"
        );
        assert!(
            p.slots
                .iter()
                .all(|slot| slot.object == PinnedObjectId(later.inode as u32))
        );
        assert_eq!(p.modules.len(), 1);
        assert_eq!(p.modules[0].path, "/opt/later.so");
        assert_eq!(
            p.modules[0].tables.len(),
            1,
            "later-module evidence stays complete"
        );
        assert_eq!(p.modules_skipped.len(), 1);
        assert_eq!(p.modules_skipped[0].subject, "/opt/p11.so");
        assert!(
            p.modules_skipped[0]
                .reason
                .contains("module needs 513 more")
        );
        assert!(p.modules_skipped[0].reason.contains("0 are in use"));
    }

    #[test]
    fn module_of_slot_names_one_module_or_nobody() {
        let m = manifest_with(vec![resolved("C_Sign", 0x10)]);
        let p = build(&m);
        assert_eq!(p.module_of_slot(0), Some(ModuleId(0)));
        assert_eq!(p.module_of_slot(7), None, "unknown slot");
    }

    fn exact_module(id: u32, object: PinnedObjectId) -> ModuleSummary {
        ModuleSummary {
            id: ModuleId(id),
            object,
            key: ObjectKey {
                device: Device { major: 8, minor: 1 },
                inode: u64::from(object.0),
            },
            path: format!("/opt/module{}.so", object.0),
            tables: vec![],
            interfaces: 0,
            source: "manifest",
            corroborated: false,
            skipped: vec![],
        }
    }

    fn exact_slot(
        index: u32,
        object: PinnedObjectId,
        file_offset: u64,
        descriptor_index: u32,
        module_ids: Vec<ModuleId>,
    ) -> Slot {
        Slot {
            index,
            descriptor_index,
            object,
            object_path: format!("/proc/self/fd/{}", object.0),
            file_offset,
            names: vec!["C_Sign".into()],
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[descriptor_index as usize],
            semantic_authorized: descriptor_index != 0,
            semantic_ambiguous: descriptor_index == 0,
            fork_safe: false,
            module_ids,
        }
    }

    fn exact_plan(slots: Vec<Slot>, modules: Vec<ModuleSummary>) -> AttachPlan {
        let mut plan = AttachPlan::from_slots(slots);
        plan.modules = modules;
        plan.entries_seen = plan.slots.len();
        plan
    }

    fn discovered_for_capacity(
        object: PinnedObjectId,
        path: &'static str,
        targets: impl IntoIterator<Item = (PinnedObjectId, u64)>,
    ) -> Discovered<'static> {
        let targets: Vec<_> = targets
            .into_iter()
            .map(|(object, file_offset)| Target {
                name: "C_Sign",
                object,
                object_path: "/proc/self/fd/target",
                file_offset,
                fork_safe: false,
                semantic_authorized: true,
            })
            .collect();
        Discovered {
            object,
            key: ObjectKey {
                device: Device { major: 8, minor: 1 },
                inode: u64::from(object.0),
            },
            path,
            source: "manifest",
            tables: vec![],
            interfaces: 0,
            surfaces: vec![],
            entries_seen: targets.len(),
            targets,
            skipped: vec![],
        }
    }

    #[test]
    fn extend_exact_keeps_initial_slots_and_indices_unchanged() {
        let object = PinnedObjectId(1);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
        );
        let initial = plan.clone();

        let delta = plan.extend_exact(initial.clone()).unwrap();

        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert_eq!(plan, initial);
    }

    #[test]
    fn extend_exact_allocates_one_monotonic_slot_for_a_new_exact_target() {
        let object = PinnedObjectId(1);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
        );
        let rebuilt = exact_plan(
            vec![
                exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)]),
                exact_slot(1, object, 0x20, descriptor, vec![ModuleId(0)]),
            ],
            vec![exact_module(0, object)],
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].index, 1);
        assert_eq!(
            p11scope_ebpf_common::attach_cookie(delta.new[0].index, delta.new[0].descriptor_index),
            (u64::from(descriptor) << 32) | 1
        );
        assert!(plan.is_active(1));
    }

    #[test]
    fn extend_exact_merges_existing_metadata_without_another_attachment() {
        let object = PinnedObjectId(1);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
        );
        let mut rebuilt = plan.clone();
        rebuilt.slots[0].object_path = "/new/metadata-only-path.so".into();

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert_eq!(plan.slots[0].object_path, "/new/metadata-only-path.so");
    }

    #[test]
    fn extend_exact_merges_agreeing_alias_metadata_without_changing_the_cookie() {
        let object = PinnedObjectId(1);
        let set_pin = crate::kinds::function_id("C_SetPIN").unwrap() + 1;
        let init_pin = crate::kinds::function_id("C_InitPIN").unwrap() + 1;
        let mut initial = exact_slot(0, object, 0x10, set_pin, vec![ModuleId(0)]);
        initial.names = vec!["C_SetPIN".into()];
        let mut plan = exact_plan(vec![initial], vec![exact_module(0, object)]);
        let mut rebuilt = exact_slot(0, object, 0x10, init_pin, vec![ModuleId(0)]);
        rebuilt.names = vec!["C_InitPIN".into(), "C_SetPIN".into()];
        rebuilt.aliased = true;

        let delta = plan
            .extend_exact(exact_plan(vec![rebuilt], vec![exact_module(0, object)]))
            .unwrap();

        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert_eq!(plan.slots[0].descriptor_index, set_pin);
        assert_eq!(plan.slots[0].names, ["C_InitPIN", "C_SetPIN"]);
    }

    #[test]
    fn extend_exact_keeps_frozen_count_only_when_one_shared_owner_survives() {
        let first = PinnedObjectId(1);
        let surviving = PinnedObjectId(2);
        let target = PinnedObjectId(3);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut shared = exact_slot(0, target, 0x10, 0, vec![ModuleId(0), ModuleId(1)]);
        shared.names.push("C_SignRecover".into());
        shared.aliased = true;
        let mut plan = exact_plan(
            vec![shared],
            vec![exact_module(0, first), exact_module(1, surviving)],
        );
        let rebuilt = exact_plan(
            vec![exact_slot(0, target, 0x10, descriptor, vec![ModuleId(1)])],
            vec![exact_module(1, surviving)],
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(delta.new.is_empty());
        assert!(
            delta.replace.is_empty(),
            "the frozen cookie is not replaced"
        );
        assert!(delta.retire.is_empty());
        assert_eq!(plan.slots[0].descriptor_index, 0);
        assert_eq!(plan.slots[0].semantics, SlotSemantics::COUNT_ONLY);
        assert_eq!(plan.slots[0].module_ids, [ModuleId(1)]);
        assert_eq!(plan.slots[0].names, ["C_Sign", "C_SignRecover"]);
        assert!(plan.slots[0].aliased);
        assert_eq!(plan.module_of_slot(0), None);
        assert_eq!(plan.module_ambiguous, 1);
    }

    #[test]
    fn refused_shared_candidate_latches_only_the_current_exact_slot() {
        let first = PinnedObjectId(1);
        let second = PinnedObjectId(2);
        let target = PinnedObjectId(3);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![exact_slot(0, target, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, first)],
        );
        let original_slots = plan.slots.clone();
        let mut shared = exact_slot(0, target, 0x10, 0, vec![ModuleId(0), ModuleId(1)]);
        shared.semantic_ambiguous = true;
        let mut candidate = plan.clone();
        let delta = candidate
            .extend_exact(exact_plan(
                vec![shared],
                vec![exact_module(0, first), exact_module(1, second)],
            ))
            .unwrap();
        assert_eq!(delta.replace.len(), 1);

        assert!(plan.latch_ambiguity_from(&candidate));

        assert_eq!(plan.slots, original_slots, "candidate topology stays local");
        assert_eq!(plan.slots[0].descriptor_index, descriptor);
        assert_eq!(plan.module_of_slot(0), None);
        assert_eq!(plan.module_ambiguous, 1);
        assert!(
            !plan.latch_ambiguity_from(&candidate),
            "the capture-lifetime loss fact is idempotent"
        );

        let sole_owner = exact_plan(
            vec![exact_slot(0, target, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, first)],
        );
        plan.extend_exact(sole_owner.clone()).unwrap();
        assert_eq!(plan.slots[0].descriptor_index, descriptor);
        assert_eq!(plan.module_of_slot(0), None);
        assert_eq!(
            plan.effective_semantics(&plan.slots[0]),
            SlotSemantics::COUNT_ONLY
        );
        plan.extend_exact(sole_owner).unwrap();

        plan.extend_exact(candidate).unwrap();
        assert_eq!(plan.slots[0].descriptor_index, 0);
        assert_eq!(plan.module_of_slot(0), None);
        assert_eq!(plan.module_ambiguous, 1);
    }

    #[test]
    fn extend_exact_refuses_only_a_crossing_module_after_retirement() {
        let old = PinnedObjectId(10);
        let old_key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: u64::from(old.0),
        };
        let mut plan = exact_plan(
            (0..511)
                .map(|index| exact_slot(index, old, u64::from(index) * 8, 0, vec![ModuleId(0)]))
                .collect(),
            vec![exact_module(0, old)],
        );
        plan.extend_exact(exact_plan(
            (0..500)
                .map(|index| exact_slot(index, old, u64::from(index) * 8, 0, vec![ModuleId(0)]))
                .collect(),
            vec![exact_module(0, old)],
        ))
        .unwrap();

        let crossing = PinnedObjectId(11);
        let later = PinnedObjectId(12);
        let pinned = PinnedObjects::empty();
        let rebuilt = plan.rebuild_from_sources(
            &[
                scanned_with(old_key, "/opt/old.so", (0..500).map(|index| index * 8)),
                scanned_with(
                    ObjectKey {
                        device: Device { major: 8, minor: 1 },
                        inode: u64::from(crossing.0),
                    },
                    "/opt/crossing.so",
                    [0x1000, 0x1008, 0x1010],
                ),
                scanned_with(
                    ObjectKey {
                        device: Device { major: 8, minor: 1 },
                        inode: u64::from(later.0),
                    },
                    "/opt/later.so",
                    [0x2000],
                ),
            ],
            &[],
            &pinned,
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].index, 511);
        assert_eq!(delta.new[0].object, later);
        assert!(plan.slots.iter().all(|slot| slot.object != crossing));
        assert_eq!(
            plan.modules
                .iter()
                .map(|module| module.id)
                .collect::<Vec<_>>(),
            [ModuleId(0), ModuleId(1)]
        );
        assert_eq!(plan.modules_skipped.len(), 1);
        assert_eq!(plan.modules_skipped[0].subject, "/opt/crossing.so");
    }

    #[test]
    fn capacity_rejection_retires_every_existing_key_and_admits_a_later_module() {
        let existing = PinnedObjectId(10);
        let later = PinnedObjectId(12);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            (0..511)
                .map(|index| {
                    exact_slot(
                        index,
                        existing,
                        u64::from(index) * 8,
                        descriptor,
                        vec![ModuleId(0)],
                    )
                })
                .collect(),
            vec![exact_module(0, existing)],
        );
        let pinned = PinnedObjects::empty();
        let rebuilt = plan.rebuild_from_sources(
            &[
                scanned_with(
                    ObjectKey {
                        device: Device { major: 8, minor: 1 },
                        inode: u64::from(existing.0),
                    },
                    "/opt/existing-crossing.so",
                    [0, 0x1000, 0x1008],
                ),
                scanned_with(
                    ObjectKey {
                        device: Device { major: 8, minor: 1 },
                        inode: u64::from(later.0),
                    },
                    "/opt/later-fitting.so",
                    [0x2000],
                ),
            ],
            &[],
            &pinned,
        );

        assert_eq!(rebuilt.modules.len(), 1);
        assert_eq!(rebuilt.modules[0].object, later);
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert_eq!(
            rebuilt.modules_skipped[0].subject,
            "/opt/existing-crossing.so"
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert_eq!(delta.retire.len(), 511);
        assert!(delta.retire.iter().all(|slot| slot.object == existing));
        assert!((0..511).all(|slot| !plan.is_active(slot)));
        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].index, 511);
        assert_eq!(delta.new[0].object, later);
        assert!(plan.is_active(511));
    }

    #[test]
    fn a_rejected_shared_claimant_cannot_downgrade_an_accepted_slot() {
        let accepted = PinnedObjectId(1);
        let rejected = PinnedObjectId(2);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            (0..511)
                .map(|index| {
                    exact_slot(
                        index,
                        accepted,
                        u64::from(index) * 8,
                        descriptor,
                        vec![ModuleId(0)],
                    )
                })
                .collect(),
            vec![exact_module(0, accepted)],
        );
        let rebuilt = merge(
            vec![
                discovered_for_capacity(accepted, "/opt/accepted.so", [(accepted, 0)]),
                discovered_for_capacity(
                    rejected,
                    "/opt/rejected.so",
                    [(accepted, 0), (rejected, 0x1000), (rejected, 0x1008)],
                ),
            ],
            0,
            "absent".into(),
            plan.slots.len(),
            &plan.slot_by_key,
        );

        assert_eq!(rebuilt.modules.len(), 1);
        assert_eq!(rebuilt.modules[0].object, accepted);
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert_eq!(rebuilt.modules_skipped[0].subject, "/opt/rejected.so");
        assert_eq!(rebuilt.slots.len(), 1);
        assert_eq!(rebuilt.slots[0].descriptor_index, descriptor);
        assert!(!rebuilt.slots[0].semantic_ambiguous);
        assert_eq!(rebuilt.slots[0].module_ids, [ModuleId(0)]);

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(delta.replace.is_empty());
        assert_eq!(plan.slots[0].descriptor_index, descriptor);
        assert!(!plan.slots[0].semantic_ambiguous);
        assert_eq!(plan.slots[0].module_ids, [ModuleId(0)]);
    }

    #[test]
    fn extend_exact_rejects_a_semantic_descriptor_without_an_owner() {
        let object = PinnedObjectId(1);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
        );
        let before = plan.clone();
        let rebuilt = exact_plan(
            vec![
                exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)]),
                exact_slot(1, object, 0x20, descriptor, vec![]),
            ],
            vec![exact_module(0, object)],
        );

        let error = plan.extend_exact(rebuilt).unwrap_err();

        assert!(
            error.contains("one unambiguous authorized owner"),
            "{error}"
        );
        assert_eq!(plan, before);
    }

    #[test]
    fn extend_exact_refuses_an_over_capacity_snapshot_without_a_prefix_mutation() {
        let object = PinnedObjectId(1);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let slots = (0..MAX_SLOTS)
            .map(|index| {
                exact_slot(
                    index,
                    object,
                    u64::from(index) * 8,
                    descriptor,
                    vec![ModuleId(0)],
                )
            })
            .collect();
        let mut plan = exact_plan(slots, vec![exact_module(0, object)]);
        let before = plan.clone();
        let rebuilt = exact_plan(
            (0..=MAX_SLOTS)
                .map(|index| {
                    exact_slot(
                        index,
                        object,
                        u64::from(index) * 8,
                        descriptor,
                        vec![ModuleId(0)],
                    )
                })
                .collect(),
            vec![exact_module(0, object)],
        );

        let error = plan.extend_exact(rebuilt).unwrap_err();

        assert!(error.contains("512"), "{error}");
        assert_eq!(
            plan, before,
            "capacity failure must leave no attached prefix"
        );
    }

    #[test]
    fn extend_exact_refuses_an_invalid_new_descriptor_without_mutating() {
        let object = PinnedObjectId(1);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
        );
        let before = plan.clone();
        let mut invalid = exact_slot(1, object, 0x20, descriptor, vec![ModuleId(0)]);
        invalid.descriptor_index = p11scope_ebpf_common::MAX_DESCRIPTORS;
        invalid.semantics = SlotSemantics::COUNT_ONLY;
        let rebuilt = exact_plan(
            vec![
                exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)]),
                invalid,
            ],
            vec![exact_module(0, object)],
        );

        let error = plan.extend_exact(rebuilt).unwrap_err();

        assert!(error.contains("descriptor"), "{error}");
        assert_eq!(plan, before);
    }

    #[test]
    fn extend_exact_replaces_a_shared_target_with_count_only_and_retires_without_reuse() {
        let object = PinnedObjectId(1);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![
                exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)]),
                exact_slot(1, object, 0x20, descriptor, vec![ModuleId(0)]),
            ],
            vec![exact_module(0, object)],
        );
        let rebuilt = exact_plan(
            vec![exact_slot(
                0,
                object,
                0x10,
                0,
                vec![ModuleId(0), ModuleId(1)],
            )],
            vec![exact_module(0, object), exact_module(1, PinnedObjectId(2))],
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert_eq!(delta.replace.len(), 1);
        assert_eq!(delta.replace[0].index, 0);
        assert_eq!(delta.replace[0].descriptor_index, 0);
        assert_eq!(delta.retire.len(), 1);
        assert_eq!(delta.retire[0].index, 1);
        assert!(plan.is_active(0));
        assert!(!plan.is_active(1));
        assert_eq!(plan.module_ambiguous, 1);

        let reappeared = exact_plan(
            vec![
                exact_slot(0, object, 0x10, 0, vec![ModuleId(0), ModuleId(1)]),
                exact_slot(1, object, 0x20, descriptor, vec![ModuleId(0)]),
            ],
            vec![exact_module(0, object), exact_module(1, PinnedObjectId(2))],
        );
        let delta = plan.extend_exact(reappeared).unwrap();
        assert_eq!(delta.new[0].index, 2, "retired slot 1 stays reserved");
        assert!(!plan.is_active(1));
        assert!(plan.is_active(2));
    }
}
