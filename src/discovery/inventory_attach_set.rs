//! SPDX-License-Identifier: GPL-3.0-or-later
//! The Inventory attach set: the append-only, budgeted table of physical
//! endpoints the inventory command would instrument, retained across scan
//! passes.
//!
//! Every inventory pass collects a catalog and lowers it once, under the
//! Inventory admission policy (`inspect_system::CatalogLowering`). The set
//! absorbs that plan and the aggregate pins it was lowered from: it maps each
//! active slot to a physical endpoint — a retained object plus a file offset —
//! and appends the ones it has not seen, under the capture-lifetime endpoint
//! budget. It is the existing discovery path (catalog scan plus plan
//! lowering) retained, not a second discovery engine.
//!
//! Invariants:
//!
//! - Endpoint IDs are dense, append-only and never reused or renumbered: a
//!   later pass whose plan orders its slots differently maps every known
//!   endpoint back to the ID it already has.
//! - One physical object is one retained object, whatever path or raw maps
//!   key a pass saw it under. Identical bytes at another inode are another
//!   object with their own endpoints.
//! - An object whose identity changed under a retained raw key (digest or
//!   `(inode, size, ctime)` pin) is never extended again, and a gap names it.
//!   Under an alias key (a view proven through the content fallback) that
//!   holds only while the retained fd is still the same kernel file: an
//!   alias key recycled for another file is dropped, never a changed object.
//! - Growth that would exceed the budget is refused whole and by name; a
//!   module this set admitted before keeps its endpoints and says what it
//!   lost. A module never admitted is refused, even when some of its
//!   targets are endpoints another module brought in.
//! - The admission verdicts the inventory output shows come from here, so
//!   they are judged against the Inventory budget, never the Detailed slot
//!   ceiling `inspect` reports.
//!
//! Costs per pass: one map lookup per active slot and per module, no file
//! open and no hashing — the catalog already pinned and hashed every
//! object. Retaining a new object clones the catalog's `Arc` file and runs
//! one `fstat`; an object first seen under another mount runs an `fstat`
//! pair once, after which that raw key is recorded as an alias. State is
//! bounded by the endpoint budget: at most that many endpoints, retained
//! objects, alias keys, module records and refusal-gap memo entries.

use crate::attach::capture::MapperEstimate;
use crate::capacity::InventoryBudget;
use crate::discovery::identity::{
    PinnedContentKey, PinnedObjectId, PinnedObjects, RetainedInventoryTarget,
};
use crate::plan::{AdmissionPolicy, AttachPlan, ModuleId};
use p11scope_manifest::elf::ElfAbi;
use p11scope_manifest::maps::ObjectKey;
use std::collections::{BTreeMap, BTreeSet};

/// Checked identity of the attachment membership view; exhaustion is terminal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttachRevision(Option<u64>);
impl AttachRevision {
    pub(crate) fn sequence(self) -> Option<u64> {
        self.0
    }
}

pub(crate) struct CountMembershipCursor {
    revision: AttachRevision,
    endpoint: usize,
    after: Option<AttachModuleKey>,
    modules_after: Option<AttachModuleKey>,
    modules_done: bool,
    header_seen: bool,
}
impl CountMembershipCursor {
    #[cfg(test)]
    pub(crate) fn retained_keys(&self) -> usize {
        usize::from(self.after.is_some()) + usize::from(self.modules_after.is_some())
    }
}

pub(crate) enum CountMembershipItem {
    Endpoint {
        object: AttachObjectId,
        unknown: bool,
    },
    Module {
        object: AttachObjectId,
        module: AttachModuleKey,
    },
    Unknown,
    Skipped,
}

pub(crate) struct CountMembershipPage {
    pub items: Vec<CountMembershipItem>,
    pub cursor: Option<CountMembershipCursor>,
    pub visited: usize,
}

pub(crate) enum CountMembershipRefusal {
    Stale,
    Exhausted,
    Refused,
}

/// One physical endpoint's capture-lifetime ID: dense, append-only, never
/// reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EndpointId(pub(crate) u32);

/// One retained physical object's index: append-only, never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AttachObjectId(u32);

impl AttachObjectId {
    /// The capture-lifetime index the capture facade publishes as the
    /// ENDPOINT_OBJECT object ID (so CALLER_USE rows name this object).
    pub(crate) const fn index(self) -> u32 {
        self.0
    }

    /// A scripted object index for tests that need no retained object.
    #[cfg(test)]
    pub(crate) const fn scripted(index: u32) -> Self {
        Self(index)
    }
}

/// What the set knows about the endpoints one admitted module needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleMembers<'a> {
    /// The module's admitted endpoints, in ID order. Coverage may claim
    /// the module is watched only when every one is attached.
    Known(&'a [EndpointId]),
    /// Admitted, but the membership table was full when it was recorded:
    /// completeness cannot be shown (`inventory_attach_memberships`).
    Unrecorded,
}

/// The membership table's resource name, when its bound is reached.
pub(crate) const MEMBERSHIP_RESOURCE: &str = "inventory_attach_memberships";
/// Membership entries per endpoint of budget. A target two modules claim
/// is one endpoint but two memberships; real providers share few targets.
const MEMBERSHIP_FACTOR: usize = 4;

#[derive(Debug, Clone)]
struct ModuleRecord {
    endpoints: usize,
    members: Option<Vec<EndpointId>>,
}

/// One retained physical endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttachEndpoint {
    pub id: EndpointId,
    pub object: AttachObjectId,
    pub file_offset: u64,
    pub abi: ElfAbi,
}

/// A module's physical identity, as the catalog and the caller registry key
/// it: the raw maps key plus the whole-file digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AttachModuleKey {
    pub object: ObjectKey,
    pub sha256: String,
}

/// The admission verdict the inventory output shows for one module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttachVerdict {
    /// `endpoints` of the module's endpoints are in the set. Non-empty
    /// `reasons` mean it is partially covered: what it needs next was not
    /// added, and why.
    Admitted {
        endpoints: usize,
        reasons: Vec<String>,
    },
    Refused {
        reason: String,
    },
}

/// A refusal the registry must record as an explicit gap. Recorded once per
/// (module, refusal kind) or changed object, not once per pass, and bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachGap {
    pub subject: String,
    pub reason: String,
    /// `(resource, limit, requested)` exactly when a budget refused.
    pub budget: Option<(&'static str, usize, usize)>,
}

/// What one pass added to the set, for the capture facade: the new
/// endpoints in ID order and the objects first retained by this pass. Never
/// a whole plan replacement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TargetDelta {
    pub endpoints: Vec<AttachEndpoint>,
    pub objects: Vec<AttachObjectId>,
}

impl TargetDelta {
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.endpoints.is_empty() && self.objects.is_empty()
    }

    /// Appends a later pass's delta. IDs only grow, so the result stays in
    /// ID order.
    pub(crate) fn append(&mut self, mut later: TargetDelta) {
        self.endpoints.append(&mut later.endpoints);
        self.objects.append(&mut later.objects);
    }
}

/// One pass's absorption: the delta, the per-module verdicts keyed by
/// physical module identity, and the gaps to record.
#[derive(Debug, Default)]
pub(crate) struct AbsorbOutcome {
    pub delta: TargetDelta,
    pub verdicts: BTreeMap<AttachModuleKey, AttachVerdict>,
    pub gaps: Vec<AttachGap>,
}

pub(crate) const CHANGED_SUBJECT: &str = "inventory attach target changed identity";
pub(crate) const REFUSED_SUBJECT: &str = "inventory attach set refused module";
pub(crate) const ENDPOINT_RESOURCE: &str = "inventory_endpoints";
pub(crate) const MODULE_RESOURCE: &str = "inventory_attach_modules";
pub(crate) const GAP_OVERFLOW_SUBJECT: &str = "inventory attach set refusal gaps bounded";

struct RetainedObject {
    target: RetainedInventoryTarget,
    /// Sticky: once set, this object is never extended again.
    changed: Option<String>,
}

pub(crate) struct InventoryAttachSet {
    count_revision: AttachRevision,
    budget: InventoryBudget,
    endpoints: Vec<AttachEndpoint>,
    by_endpoint: BTreeMap<(AttachObjectId, u64), EndpointId>,
    objects: Vec<RetainedObject>,
    by_raw: BTreeMap<ObjectKey, AttachObjectId>,
    /// Raw keys recorded in `by_raw` beyond each object's own: views of a
    /// retained object proven through the content fallback. Bounded by the
    /// endpoint budget.
    aliases: usize,
    by_content: BTreeMap<PinnedContentKey, Vec<AttachObjectId>>,
    /// Endpoints each admitted module was last admitted with, and which
    /// (bounded: `memberships` entries in all, at most
    /// `MEMBERSHIP_FACTOR` per endpoint of budget).
    modules: BTreeMap<AttachModuleKey, ModuleRecord>,
    memberships: usize,
    /// The reverse of the recorded memberships: the modules each endpoint
    /// is admitted for. Exactly the recorded memberships, so bounded the
    /// same way.
    by_member: BTreeMap<EndpointId, BTreeSet<AttachModuleKey>>,
    /// `(module, refusal kind)` pairs already recorded as a gap, bounded
    /// by the endpoint budget; past the bound one overflow gap is
    /// recorded and further refusals live in module verdicts only.
    reported: BTreeSet<(AttachModuleKey, RefusalKind)>,
    reported_overflow: bool,
    endpoint_refusals: u64,
    module_record_refusals: u64,
    /// The processes discovery last saw mapping each retained object
    /// (replaced every pass; bounded by the retained objects).
    mappers: BTreeMap<AttachObjectId, usize>,
    /// What the last pass's view was: `None` before any pass, `Some(true)`
    /// for a whole-system view whose counts estimate a link's cost, and
    /// `Some(false)` for a scope-limited one whose counts never do.
    mappers_system_view: Option<bool>,
}

impl InventoryAttachSet {
    pub(crate) fn new(budget: InventoryBudget) -> Self {
        Self {
            count_revision: AttachRevision(Some(0)),
            budget,
            endpoints: Vec::new(),
            by_endpoint: BTreeMap::new(),
            objects: Vec::new(),
            by_raw: BTreeMap::new(),
            aliases: 0,
            by_content: BTreeMap::new(),
            modules: BTreeMap::new(),
            memberships: 0,
            by_member: BTreeMap::new(),
            reported: BTreeSet::new(),
            reported_overflow: false,
            endpoint_refusals: 0,
            module_record_refusals: 0,
            mappers: BTreeMap::new(),
            mappers_system_view: None,
        }
    }

    /// Record one pass's mapper counts by raw object key (a catalog's
    /// objects with their mappings); keys that name no retained object
    /// are ignored, and an object seen under several keys sums them.
    /// `system_view` says whether the pass saw the whole system: only then
    /// do the counts estimate how many processes the kernel walks (review
    /// R4); a scope-limited view keeps none.
    pub(crate) fn note_mappers<'a>(
        &mut self,
        system_view: bool,
        counts: impl IntoIterator<Item = (&'a ObjectKey, usize)>,
    ) {
        self.mappers.clear();
        self.mappers_system_view = Some(system_view);
        if !system_view {
            return;
        }
        for (key, count) in counts {
            if let Some(&object) = self.by_raw.get(key) {
                *self.mappers.entry(object).or_default() += count;
            }
        }
    }

    /// What the last pass knew of the processes mapping `object`. A system
    /// pass that did not see it counts none.
    pub(crate) fn mappers(&self, object: AttachObjectId) -> MapperEstimate {
        match self.mappers_system_view {
            None => MapperEstimate::Unknown,
            Some(false) => MapperEstimate::ScopeLimited,
            Some(true) => MapperEstimate::System(self.mappers.get(&object).copied().unwrap_or(0)),
        }
    }

    pub(crate) const fn budget(&self) -> InventoryBudget {
        self.budget
    }
}

/// The read side the capture facade (Task 6 C3) attaches through. Until it
/// lands, only tests read it.
#[cfg_attr(not(test), allow(dead_code))]
impl InventoryAttachSet {
    pub(crate) fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub(crate) fn endpoint(&self, id: EndpointId) -> Option<&AttachEndpoint> {
        self.endpoints.get(id.0 as usize)
    }

    pub(crate) fn endpoints(&self) -> impl Iterator<Item = &AttachEndpoint> {
        self.endpoints.iter()
    }

    pub(crate) fn count_revision(&self) -> AttachRevision {
        self.count_revision
    }

    pub(crate) fn count_membership_page(
        &self,
        cursor: Option<CountMembershipCursor>,
        revision: AttachRevision,
        item_limit: usize,
    ) -> Result<CountMembershipPage, CountMembershipRefusal> {
        use std::ops::Bound::{Excluded, Unbounded};
        if self.count_revision.0.is_none() {
            return Err(CountMembershipRefusal::Exhausted);
        }
        if revision != self.count_revision
            || cursor
                .as_ref()
                .is_some_and(|cursor| cursor.revision != revision)
        {
            return Err(CountMembershipRefusal::Stale);
        }
        let limit = item_limit.min(128);
        if limit == 0 {
            return Err(CountMembershipRefusal::Refused);
        }
        let mut cursor = cursor.unwrap_or(CountMembershipCursor {
            revision,
            endpoint: 0,
            after: None,
            modules_after: None,
            modules_done: false,
            header_seen: false,
        });
        let mut items = Vec::with_capacity(limit);
        while items.len() < limit {
            if !cursor.modules_done {
                let next = match &cursor.modules_after {
                    Some(after) => self.modules.range((Excluded(after), Unbounded)).next(),
                    None => self.modules.first_key_value(),
                };
                if let Some((key, record)) = next {
                    cursor.modules_after = Some(key.clone());
                    items.push(if record.members.is_none() {
                        CountMembershipItem::Unknown
                    } else {
                        CountMembershipItem::Skipped
                    });
                    continue;
                }
                cursor.modules_done = true;
            }
            let Some(endpoint) = self.endpoints.get(cursor.endpoint) else {
                break;
            };
            if !cursor.header_seen {
                items.push(CountMembershipItem::Endpoint {
                    object: endpoint.object,
                    unknown: self
                        .objects
                        .get(endpoint.object.0 as usize)
                        .is_none_or(|object| object.changed.is_some()),
                });
                cursor.header_seen = true;
                continue;
            }
            let next = self
                .by_member
                .get(&endpoint.id)
                .and_then(|members| match &cursor.after {
                    Some(after) => members.range((Excluded(after), Unbounded)).next(),
                    None => members.first(),
                });
            if let Some(module) = next {
                cursor.after = Some(module.clone());
                items.push(CountMembershipItem::Module {
                    object: endpoint.object,
                    module: module.clone(),
                });
            } else {
                cursor.endpoint += 1;
                cursor.after = None;
                cursor.header_seen = false;
            }
        }
        let visited = items.len();
        let cursor =
            (cursor.endpoint < self.endpoints.len() || !cursor.modules_done).then_some(cursor);
        Ok(CountMembershipPage {
            items,
            cursor,
            visited,
        })
    }

    fn invalidate_count_memberships(&mut self) {
        self.count_revision.0 = self
            .count_revision
            .0
            .and_then(|revision| revision.checked_add(1));
    }

    /// The retained pin of one object: what the capture facade attaches
    /// through. The set keeps custody.
    pub(crate) fn target(&self, object: AttachObjectId) -> Option<&RetainedInventoryTarget> {
        self.objects
            .get(object.0 as usize)
            .map(|object| &object.target)
    }

    /// Module records the set holds (bounded by the endpoint budget).
    pub(crate) fn module_records(&self) -> usize {
        self.modules.len()
    }

    /// Per-pass module refusals on the endpoint budget (`inventory_endpoints`
    /// loss counter): each pass that refuses a module's growth for want of
    /// endpoints counts once.
    pub(crate) fn endpoint_refusals(&self) -> u64 {
        self.endpoint_refusals
    }

    /// Per-pass module refusals on the module-record cap
    /// (`inventory_attach_modules` loss counter).
    pub(crate) fn module_record_refusals(&self) -> u64 {
        self.module_record_refusals
    }

    /// Endpoints the module was last admitted with, or `None` when it never
    /// was.
    pub(crate) fn module_endpoints(&self, module: &AttachModuleKey) -> Option<usize> {
        self.modules.get(module).map(|record| record.endpoints)
    }

    /// The admitted modules whose recorded membership holds `endpoint`
    /// (Task 6 C4): what a native witness of that endpoint is use of. A
    /// module whose membership is unrecorded is never listed.
    pub(crate) fn modules_with_member(
        &self,
        endpoint: EndpointId,
    ) -> impl Iterator<Item = &AttachModuleKey> {
        self.by_member.get(&endpoint).into_iter().flatten()
    }

    /// The endpoints one admitted module holds, or `None` when the set
    /// never admitted it. The capture coverage producer (Task 6 C3) reads
    /// this to tell a completely attached module from a partial one.
    pub(crate) fn module_members(&self, module: &AttachModuleKey) -> Option<ModuleMembers<'_>> {
        self.modules
            .get(module)
            .map(|record| match &record.members {
                Some(members) => ModuleMembers::Known(members),
                None => ModuleMembers::Unrecorded,
            })
    }
}

// Private preparation ceilings. Existing state remains bounded by InventoryBudget.
const PREPARED_INPUT_LIMIT: usize = 512;
const PREPARED_COMPARISON_LIMIT: usize = 8192;

#[derive(Clone, Copy, Default)]
struct ProviderRelation {
    same_object: bool,
    same_kernel_file: bool,
}
struct PreparedProviderFacts {
    inputs: BTreeMap<PinnedObjectId, RetainedInventoryTarget>,
    existing: BTreeMap<(AttachObjectId, PinnedObjectId), ProviderRelation>,
    incoming: BTreeMap<(PinnedObjectId, PinnedObjectId), ProviderRelation>,
    origins: BTreeMap<AttachObjectId, PinnedObjectId>,
    base_objects: usize,
}
impl PreparedProviderFacts {
    fn relation(&self, object: AttachObjectId, input: PinnedObjectId) -> ProviderRelation {
        if (object.0 as usize) < self.base_objects {
            return self
                .existing
                .get(&(object, input))
                .copied()
                .unwrap_or_default();
        }
        let Some(origin) = self.origins.get(&object) else {
            return ProviderRelation::default();
        };
        if *origin == input {
            return ProviderRelation {
                same_object: true,
                same_kernel_file: true,
            };
        }
        self.incoming
            .get(&(*origin, input))
            .copied()
            .unwrap_or_default()
    }
    fn contains_exact(&self, pins: &PinnedObjects, input: PinnedObjectId) -> bool {
        let Some(target) = self.inputs.get(&input) else {
            return false;
        };
        let held = target.retirement_lease();
        pins.file_for(input)
            .is_some_and(|file| std::ptr::eq(file, held.as_ref()))
            && pins
                .summary(input)
                .is_some_and(|summary| summary.key == target.object_key())
            && pins
                .content_key(input)
                .is_some_and(|key| key == target.content_key())
    }
}
/// Exclusive attach-set custody prevents its resolution state changing between
/// read preparation and consumption. Every input retains the exact opened File.
/// The final allowed-PID lowering may consume a subset; it never reruns stat.
pub(crate) struct PreparedAbsorption<'a> {
    set: &'a mut InventoryAttachSet,
    facts: PreparedProviderFacts,
}
impl PreparedAbsorption<'_> {
    pub(crate) fn absorb(
        mut self,
        plan: &AttachPlan,
        pins: &PinnedObjects,
        mut work: impl FnMut(usize) -> bool,
    ) -> Result<AbsorbOutcome, String> {
        if !work(
            plan.slots
                .len()
                .saturating_mul(8)
                .saturating_add(plan.modules.len().saturating_mul(8))
                .saturating_add(1),
        ) {
            return Err("cgroup provider commit allowance exhausted".into());
        }
        for input in plan
            .slots
            .iter()
            .filter(|slot| plan.is_active(slot.index))
            .map(|slot| slot.object)
            .chain(plan.modules.iter().map(|module| module.object))
        {
            if !work(2) || !self.facts.contains_exact(pins, input) {
                return Err(
                    "cgroup provider preparation no longer names the exact aggregate input".into(),
                );
            }
        }
        Ok(self.set.absorb_with(plan, pins, Some(&mut self.facts)))
    }
}

impl InventoryAttachSet {
    pub(crate) fn prepare_absorption(
        &mut self,
        pins: &PinnedObjects,
        mut work: impl FnMut(usize) -> bool,
    ) -> Result<PreparedAbsorption<'_>, String> {
        let mut facts = PreparedProviderFacts {
            inputs: BTreeMap::new(),
            existing: BTreeMap::new(),
            incoming: BTreeMap::new(),
            origins: BTreeMap::new(),
            base_objects: self.objects.len(),
        };
        for summary in pins.pinned() {
            if facts.inputs.len() >= PREPARED_INPUT_LIMIT {
                return Err("cgroup provider preparation input ceiling reached".into());
            }
            let bytes = summary
                .path
                .len()
                .saturating_mul(2)
                .saturating_add(summary.sha256.len())
                .saturating_add(summary.build_id.map_or(0, str::len));
            if !work(bytes.div_ceil(16).saturating_add(8)) {
                return Err(
                    "cgroup provider preparation interrupted or allowance exhausted".into(),
                );
            }
            let target = pins.retain_inventory_target(summary.id);
            #[cfg(test)]
            provider_read_test::retention_returned();
            let target = target?;
            if !work(1) {
                return Err("cgroup provider preparation interrupted after retention".into());
            }
            facts.inputs.insert(summary.id, target);
        }
        for (&input, target) in &facts.inputs {
            if !work(2) {
                return Err("cgroup provider resolution interrupted".into());
            }
            let mut candidates = BTreeSet::new();
            if let Some(object) = self.by_raw.get(&target.object_key()) {
                if !work(1) {
                    return Err("cgroup provider resolution interrupted".into());
                }
                candidates.insert(*object);
            }
            if let Some(objects) = self.by_content.get(&target.content_key()) {
                for &object in objects {
                    if !work(1) {
                        return Err("cgroup provider resolution interrupted".into());
                    }
                    candidates.insert(object);
                }
            }
            for object in candidates {
                if facts.existing.len() + facts.incoming.len() >= PREPARED_COMPARISON_LIMIT {
                    return Err("cgroup provider preparation comparison ceiling reached".into());
                }
                if !work(6) {
                    return Err("cgroup provider identity comparison interrupted".into());
                }
                let retained = &self.objects[object.0 as usize].target;
                let same_object = retained.same_object_as(pins, input);
                if !work(4) {
                    return Err("cgroup provider identity comparison interrupted".into());
                }
                let same_kernel_file = retained.same_kernel_file_as(pins, input);
                #[cfg(test)]
                provider_read_test::comparison_returned();
                facts.existing.insert(
                    (object, input),
                    ProviderRelation {
                        same_object,
                        same_kernel_file,
                    },
                );
            }
        }
        for (&origin, target) in &facts.inputs {
            for (&input, other) in &facts.inputs {
                if !work(1) {
                    return Err("cgroup provider input comparison interrupted".into());
                }
                if origin == input
                    || (target.object_key() != other.object_key()
                        && target.content_key() != other.content_key())
                {
                    continue;
                }
                if facts.existing.len() + facts.incoming.len() >= PREPARED_COMPARISON_LIMIT {
                    return Err("cgroup provider preparation comparison ceiling reached".into());
                }
                if !work(6) {
                    return Err("cgroup provider input comparison interrupted".into());
                }
                let same_object = target.same_object_as(pins, input);
                if !work(4) {
                    return Err("cgroup provider input comparison interrupted".into());
                }
                let same_kernel_file = target.same_kernel_file_as(pins, input);
                #[cfg(test)]
                provider_read_test::comparison_returned();
                facts.incoming.insert(
                    (origin, input),
                    ProviderRelation {
                        same_object,
                        same_kernel_file,
                    },
                );
            }
        }
        if !work(1) {
            return Err("cgroup provider preparation interrupted before completion".into());
        }
        Ok(PreparedAbsorption { set: self, facts })
    }
}

impl InventoryAttachSet {
    /// Absorbs one pass's Inventory lowering. `pins` must be the aggregate
    /// the plan was lowered from: plan object IDs index it and nothing else.
    pub(crate) fn absorb(&mut self, plan: &AttachPlan, pins: &PinnedObjects) -> AbsorbOutcome {
        self.absorb_with(plan, pins, None)
    }
    fn absorb_with(
        &mut self,
        plan: &AttachPlan,
        pins: &PinnedObjects,
        mut prepared: Option<&mut PreparedProviderFacts>,
    ) -> AbsorbOutcome {
        let mut outcome = AbsorbOutcome::default();
        let refused: BTreeMap<PinnedObjectId, String> = plan
            .refused_modules()
            .map(|(object, skip)| (object, skip.reason.clone()))
            .collect();
        if plan.admission_policy() != AdmissionPolicy::Inventory(self.budget) {
            for object in plan
                .modules
                .iter()
                .map(|module| module.object)
                .chain(refused.keys().copied())
            {
                if let Some(key) = module_key(pins, object) {
                    outcome.verdicts.insert(
                        key,
                        AttachVerdict::Refused {
                            reason: POLICY_MISMATCH.into(),
                        },
                    );
                }
            }
            return outcome;
        }

        // Every object an active slot attaches into, resolved once.
        let mut resolved: BTreeMap<PinnedObjectId, Resolution> = BTreeMap::new();
        for slot in plan.slots.iter().filter(|slot| plan.is_active(slot.index)) {
            if let std::collections::btree_map::Entry::Vacant(entry) = resolved.entry(slot.object) {
                entry.insert(self.resolve(
                    pins,
                    slot.object,
                    &mut outcome.gaps,
                    prepared.as_deref(),
                ));
            }
        }
        // An object marked changed later in this same resolution loop
        // (another plan object reaching it by raw key) is never extended,
        // whichever plan object resolved to it first.
        for resolution in resolved.values_mut() {
            if let Resolution::Known(object) = *resolution
                && let Some(reason) = &self.objects[object.0 as usize].changed
            {
                *resolution = Resolution::Blocked {
                    reason: reason.clone(),
                    recorded: true,
                };
            }
        }
        // Each module's demand: the exact targets of the active slots it
        // owns. A target two modules claim is one endpoint in both.
        let owners: BTreeMap<ModuleId, PinnedObjectId> = plan
            .modules
            .iter()
            .map(|module| (module.id, module.object))
            .collect();
        let mut demand: BTreeMap<PinnedObjectId, BTreeSet<(PinnedObjectId, u64)>> = BTreeMap::new();
        for slot in plan.slots.iter().filter(|slot| plan.is_active(slot.index)) {
            for module in &slot.module_ids {
                if let Some(object) = owners.get(module) {
                    demand
                        .entry(*object)
                        .or_default()
                        .insert((slot.object, slot.file_offset));
                }
            }
        }

        // Refused by this pass's lowering: nothing is added. A module that
        // already holds endpoints keeps them, and the refusal is disclosed.
        for (object, reason) in &refused {
            let Some(key) = module_key(pins, *object) else {
                continue;
            };
            let verdict = match self.modules.get(&key).map(|record| record.endpoints) {
                Some(kept) if kept > 0 => AttachVerdict::Admitted {
                    endpoints: kept,
                    reasons: vec![format!(
                        "this pass's Inventory lowering refused the module ({reason}); \
                         the attach set keeps the {kept} retained {} it holds and adds none",
                        endpoint_noun(kept)
                    )],
                },
                _ => AttachVerdict::Refused {
                    reason: reason.clone(),
                },
            };
            outcome.verdicts.insert(key, verdict);
        }
        // Admitted by the lowering: decided in plan order against the
        // capture-lifetime budget.
        let none = BTreeSet::new();
        let mut decided = BTreeSet::new();
        for module in &plan.modules {
            if refused.contains_key(&module.object) || !decided.insert(module.object) {
                continue;
            }
            let Some(key) = module_key(pins, module.object) else {
                continue;
            };
            let wanted = demand.get(&module.object).unwrap_or(&none);
            let verdict = self.admit(
                &key,
                &module.path,
                wanted,
                &mut resolved,
                pins,
                &mut outcome,
                prepared.as_deref_mut(),
            );
            outcome.verdicts.insert(key, verdict);
        }
        outcome
    }

    /// Maps one plan object onto the retained objects: by raw maps key
    /// first (an equal key with unequal identity is a changed object), then
    /// by content (the same file under another key or mount).
    fn resolve(
        &mut self,
        pins: &PinnedObjects,
        id: PinnedObjectId,
        gaps: &mut Vec<AttachGap>,
        prepared: Option<&PreparedProviderFacts>,
    ) -> Resolution {
        let Some(summary) = pins.summary(id) else {
            return Resolution::Blocked {
                reason: format!(
                    "plan object {} is not pinned in this pass's aggregate",
                    id.0
                ),
                recorded: false,
            };
        };
        if let Some(&object) = self.by_raw.get(&summary.key) {
            let retained = &mut self.objects[object.0 as usize];
            // The retained fd keeps the object's own raw key from naming
            // another file, but not an alias key from another mount: an
            // anonymous overlay device can be recycled once its container
            // exits. Staleness is tested first, whether or not the object is
            // already changed: a mismatch under an alias is the object only
            // when the fd is still the same kernel file (a real in-place
            // rewrite); otherwise the alias is stale, it is dropped, and the
            // pinned file is looked up by content like any unseen key.
            let alias = retained.target.object_key() != summary.key;
            if alias
                && !prepared.map_or_else(
                    || retained.target.same_object_as(pins, id),
                    |facts| facts.relation(object, id).same_object,
                )
                && !prepared.map_or_else(
                    || retained.target.same_kernel_file_as(pins, id),
                    |facts| facts.relation(object, id).same_kernel_file,
                )
            {
                self.by_raw.remove(&summary.key);
                self.aliases = self.aliases.saturating_sub(1);
                return self.resolve_by_content(pins, id, prepared);
            }
            if let Some(reason) = &retained.changed {
                return Resolution::Blocked {
                    reason: reason.clone(),
                    recorded: true,
                };
            }
            if prepared.map_or_else(
                || retained.target.same_object_as(pins, id),
                |facts| facts.relation(object, id).same_object,
            ) {
                return Resolution::Known(object);
            }
            let reason = format!(
                "{} (device {}:{}, inode {}) changed identity since its endpoints were \
                 retained: its digest or (inode, size, ctime) pin differs, and the attach \
                 set never extends a changed object",
                summary.path, summary.key.device.major, summary.key.device.minor, summary.key.inode
            );
            retained.changed = Some(reason.clone());
            self.invalidate_count_memberships();
            gaps.push(AttachGap {
                subject: CHANGED_SUBJECT.into(),
                reason: reason.clone(),
                budget: None,
            });
            return Resolution::Blocked {
                reason,
                recorded: true,
            };
        }
        self.resolve_by_content(pins, id, prepared)
    }

    /// The content fallback: the same file under another raw key or mount,
    /// proven by `same_object_as`, or a fresh object.
    fn resolve_by_content(
        &mut self,
        pins: &PinnedObjects,
        id: PinnedObjectId,
        prepared: Option<&PreparedProviderFacts>,
    ) -> Resolution {
        let Some(summary) = pins.summary(id) else {
            return Resolution::Blocked {
                reason: format!(
                    "plan object {} is not pinned in this pass's aggregate",
                    id.0
                ),
                recorded: false,
            };
        };
        let Some(content) = pins.content_key(id) else {
            return Resolution::Blocked {
                reason: format!("{} carries no comparable digest", summary.path),
                recorded: false,
            };
        };
        let proven = self.by_content.get(&content).and_then(|candidates| {
            candidates.iter().copied().find(|object| {
                let retained = &self.objects[object.0 as usize];
                retained.changed.is_none()
                    && prepared.map_or_else(
                        || retained.target.same_object_as(pins, id),
                        |facts| facts.relation(*object, id).same_object,
                    )
            })
        });
        if let Some(object) = proven {
            // Record the proven view, so a later in-place change seen only
            // under this raw key reads as a changed object, never as a
            // fresh one on the same inode.
            if self.aliases < self.limit() {
                self.by_raw.insert(summary.key, object);
                self.aliases += 1;
            }
            return Resolution::Known(object);
        }
        Resolution::Fresh
    }

    /// Admits one module's demand whole, or refuses its growth whole.
    #[allow(clippy::too_many_arguments)] // Optional prepared provider custody adds one internal argument.
    fn admit(
        &mut self,
        key: &AttachModuleKey,
        path: &str,
        wanted: &BTreeSet<(PinnedObjectId, u64)>,
        resolved: &mut BTreeMap<PinnedObjectId, Resolution>,
        pins: &PinnedObjects,
        outcome: &mut AbsorbOutcome,
        prepared: Option<&mut PreparedProviderFacts>,
    ) -> AttachVerdict {
        let mut kept = 0usize;
        let mut fresh: Vec<(PinnedObjectId, u64)> = Vec::new();
        let mut blocked: Option<(String, bool, RefusalKind)> = None;
        let mut blocked_count = 0usize;
        for &(object, offset) in wanted {
            match resolved.get(&object) {
                Some(Resolution::Known(retained))
                    if self.by_endpoint.contains_key(&(*retained, offset)) =>
                {
                    kept += 1;
                }
                Some(Resolution::Known(_) | Resolution::Fresh) => fresh.push((object, offset)),
                Some(Resolution::Blocked { reason, recorded }) => {
                    blocked_count += 1;
                    blocked.get_or_insert_with(|| {
                        (reason.clone(), *recorded, RefusalKind::Unresolvable)
                    });
                }
                None => {
                    blocked_count += 1;
                    blocked.get_or_insert_with(|| {
                        (
                            format!("plan object {} was never resolved", object.0),
                            false,
                            RefusalKind::Unresolvable,
                        )
                    });
                }
            }
        }
        let limit = self.limit();
        let needed = fresh.len() + blocked_count;
        let refusal = if let Some((cause, recorded, kind)) = blocked {
            Some(Refusal {
                cause,
                recorded,
                kind,
                budget: None,
            })
        } else if !self.modules.contains_key(key) && self.modules.len() >= limit {
            Some(Refusal {
                cause: format!(
                    "the inventory attach set holds {} of {limit} module records",
                    self.modules.len()
                ),
                recorded: false,
                kind: RefusalKind::ModuleRecords,
                budget: Some((MODULE_RESOURCE, limit, self.modules.len() + 1)),
            })
        } else if self.endpoints.len() + fresh.len() > limit {
            Some(Refusal {
                cause: format!(
                    "the inventory attach set holds {} of {limit} capture-lifetime \
                     endpoints and never reuses an endpoint ID",
                    self.endpoints.len()
                ),
                recorded: false,
                kind: RefusalKind::Endpoints,
                budget: Some((ENDPOINT_RESOURCE, limit, self.endpoints.len() + fresh.len())),
            })
        } else {
            self.add(&fresh, resolved, pins, &mut outcome.delta, prepared)
                .err()
                .map(|cause| Refusal {
                    cause,
                    recorded: false,
                    kind: RefusalKind::Retention,
                    budget: None,
                })
        };
        match refusal.as_ref().map(|refusal| refusal.kind) {
            Some(RefusalKind::Endpoints) => {
                self.endpoint_refusals = self.endpoint_refusals.saturating_add(1);
            }
            Some(RefusalKind::ModuleRecords) => {
                self.module_record_refusals = self.module_record_refusals.saturating_add(1);
            }
            _ => {}
        }
        let Some(Refusal {
            cause,
            recorded,
            kind,
            budget,
        }) = refusal
        else {
            let endpoints = kept + fresh.len();
            let members = self.members_of(wanted, resolved);
            self.record_module(key, endpoints, members);
            return AttachVerdict::Admitted {
                endpoints,
                reasons: Vec::new(),
            };
        };
        // Partial coverage belongs only to a module this set admitted
        // before: `kept` alone can count targets another module added.
        let verdict = if kept > 0 && self.modules.contains_key(key) {
            let members = self.members_of(wanted, resolved);
            self.record_module(key, kept, members);
            // The plan's growth-omission prefix, so
            // `plan::growth_omitted_count` reads the omitted count.
            AttachVerdict::Admitted {
                endpoints: kept,
                reasons: vec![format!(
                    "admitted module needs {needed} more; {cause} — {needed} {} not added; \
                     kept its {kept} retained {}",
                    endpoint_noun(needed),
                    endpoint_noun(kept)
                )],
            }
        } else {
            AttachVerdict::Refused {
                reason: format!(
                    "{path} needs {needed} more {}; {cause} — refusing to add a prefix",
                    endpoint_noun(needed)
                ),
            }
        };
        if !recorded {
            let reason = match &verdict {
                AttachVerdict::Refused { reason } => reason.clone(),
                AttachVerdict::Admitted { reasons, .. } => format!("{path}: {}", reasons[0]),
            };
            self.report(key, kind, reason, budget, &mut outcome.gaps);
        }
        verdict
    }

    /// Records a refusal gap once per `(module, kind)`: a different kind of
    /// refusal for one module is its own gap. The memo is bounded by the
    /// endpoint budget; past it one overflow gap is recorded and later
    /// refusals stay visible in module verdicts only.
    fn report(
        &mut self,
        key: &AttachModuleKey,
        kind: RefusalKind,
        reason: String,
        budget: Option<(&'static str, usize, usize)>,
        gaps: &mut Vec<AttachGap>,
    ) {
        let memo = (key.clone(), kind);
        if self.reported.contains(&memo) {
            return;
        }
        if self.reported.len() >= self.limit() {
            if !self.reported_overflow {
                self.reported_overflow = true;
                gaps.push(AttachGap {
                    subject: GAP_OVERFLOW_SUBJECT.into(),
                    reason: format!(
                        "{} distinct attach-set refusals were recorded; further refusals \
                         are reported in module admission verdicts only",
                        self.reported.len()
                    ),
                    budget: None,
                });
            }
            return;
        }
        self.reported.insert(memo);
        gaps.push(AttachGap {
            subject: REFUSED_SUBJECT.into(),
            reason,
            budget,
        });
    }

    /// Retains every new object first, so a failed retention adds nothing,
    /// then appends the new endpoints in demand order.
    fn add(
        &mut self,
        fresh: &[(PinnedObjectId, u64)],
        resolved: &mut BTreeMap<PinnedObjectId, Resolution>,
        pins: &PinnedObjects,
        delta: &mut TargetDelta,
        mut prepared: Option<&mut PreparedProviderFacts>,
    ) -> Result<(), String> {
        let mut retained: Vec<(PinnedObjectId, RetainedInventoryTarget)> = Vec::new();
        for &(object, _) in fresh {
            if matches!(resolved.get(&object), Some(Resolution::Fresh))
                && !retained.iter().any(|(id, _)| *id == object)
            {
                let target = if let Some(facts) = prepared.as_deref() {
                    facts
                        .inputs
                        .get(&object)
                        .ok_or_else(|| "cgroup provider input was not prepared".to_string())?
                        .share()
                } else {
                    let target = pins.retain_inventory_target(object);
                    #[cfg(test)]
                    provider_read_test::retention_returned();
                    target?
                };
                retained.push((object, target));
            }
        }
        for (object, target) in retained {
            let id = AttachObjectId(self.objects.len() as u32);
            if let Some(facts) = prepared.as_deref_mut() {
                facts.origins.insert(id, object);
            }
            self.by_raw.insert(target.object_key(), id);
            self.by_content
                .entry(target.content_key())
                .or_default()
                .push(id);
            self.objects.push(RetainedObject {
                target,
                changed: None,
            });
            resolved.insert(object, Resolution::Known(id));
            delta.objects.push(id);
        }
        for &(object, file_offset) in fresh {
            let Some(Resolution::Known(retained)) = resolved.get(&object).cloned() else {
                return Err(format!("plan object {} was not retained", object.0));
            };
            if self.by_endpoint.contains_key(&(retained, file_offset)) {
                continue;
            }
            let endpoint = AttachEndpoint {
                id: EndpointId(self.endpoints.len() as u32),
                object: retained,
                file_offset,
                abi: self.objects[retained.0 as usize].target.abi(),
            };
            self.by_endpoint
                .insert((retained, file_offset), endpoint.id);
            self.invalidate_count_memberships();
            self.endpoints.push(endpoint);
            delta.endpoints.push(endpoint);
        }
        Ok(())
    }

    fn limit(&self) -> usize {
        usize::try_from(self.budget.endpoint_limit()).unwrap_or(usize::MAX)
    }

    /// The endpoint IDs a module's demand maps to right now, in ID order:
    /// its retained targets (kept and just added), never its refused ones.
    fn members_of(
        &self,
        wanted: &BTreeSet<(PinnedObjectId, u64)>,
        resolved: &BTreeMap<PinnedObjectId, Resolution>,
    ) -> Vec<EndpointId> {
        let mut members: Vec<EndpointId> = wanted
            .iter()
            .filter_map(|(object, offset)| match resolved.get(object) {
                Some(Resolution::Known(retained)) => {
                    self.by_endpoint.get(&(*retained, *offset)).copied()
                }
                _ => None,
            })
            .collect();
        members.sort_unstable();
        members.dedup();
        members
    }

    /// Replaces one module's record. Past the membership bound the module
    /// stays admitted with its count, but its membership is unrecorded.
    fn record_module(&mut self, key: &AttachModuleKey, endpoints: usize, members: Vec<EndpointId>) {
        let previous = self
            .modules
            .get(key)
            .and_then(|record| record.members.as_ref())
            .map_or(0, Vec::len);
        let bound = self.limit().saturating_mul(MEMBERSHIP_FACTOR);
        let others = self.memberships - previous;
        let members = (others + members.len() <= bound).then_some(members);
        if self
            .modules
            .get(key)
            .is_none_or(|previous| previous.endpoints != endpoints || previous.members != members)
        {
            self.invalidate_count_memberships();
        }
        self.memberships = others + members.as_ref().map_or(0, Vec::len);
        if let Some(previous) = self
            .modules
            .get(key)
            .and_then(|record| record.members.as_ref())
        {
            for member in previous {
                if let Some(modules) = self.by_member.get_mut(member) {
                    modules.remove(key);
                    if modules.is_empty() {
                        self.by_member.remove(member);
                    }
                }
            }
        }
        for member in members.iter().flatten() {
            self.by_member
                .entry(*member)
                .or_default()
                .insert(key.clone());
        }
        self.modules
            .insert(key.clone(), ModuleRecord { endpoints, members });
    }
}

/// Why one module's growth was not added. `recorded` when its gap was
/// already pushed (a changed object records its own).
struct Refusal {
    cause: String,
    recorded: bool,
    kind: RefusalKind,
    budget: Option<(&'static str, usize, usize)>,
}

/// The refusal class gap dedup keys on. Cause text carries live counts, so
/// it would never repeat exactly; the class does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RefusalKind {
    Unresolvable,
    ModuleRecords,
    Endpoints,
    Retention,
}

/// How one plan object maps onto the retained objects this pass.
#[derive(Debug, Clone)]
enum Resolution {
    Known(AttachObjectId),
    Fresh,
    /// Never extended; `recorded` when its gap was already pushed.
    Blocked {
        reason: String,
        recorded: bool,
    },
}

const POLICY_MISMATCH: &str = "the inventory attach set absorbs only a plan lowered under its \
     own Inventory policy and endpoint budget; this module was not added";

fn module_key(pins: &PinnedObjects, object: PinnedObjectId) -> Option<AttachModuleKey> {
    let summary = pins.summary(object)?;
    (!summary.sha256.is_empty()).then(|| AttachModuleKey {
        object: summary.key,
        sha256: summary.sha256.to_string(),
    })
}

fn endpoint_noun(count: usize) -> &'static str {
    if count == 1 { "endpoint" } else { "endpoints" }
}

#[cfg(test)]
pub(crate) mod provider_read_test {
    use std::cell::RefCell;

    type Observer = Box<dyn FnMut(bool)>;
    thread_local! {
        static OBSERVER: RefCell<Option<Observer>> = RefCell::new(None);
    }

    struct Restore(Option<Observer>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OBSERVER.with(|observer| *observer.borrow_mut() = self.0.take());
        }
    }
    pub(crate) fn observe<T>(
        mut observer: impl FnMut() + 'static,
        action: impl FnOnce() -> T,
    ) -> T {
        observe_kind(
            move |retention| {
                if retention {
                    observer();
                }
            },
            action,
        )
    }
    pub(crate) fn observe_comparisons<T>(
        mut observer: impl FnMut() + 'static,
        action: impl FnOnce() -> T,
    ) -> T {
        observe_kind(
            move |retention| {
                if !retention {
                    observer();
                }
            },
            action,
        )
    }
    pub(crate) fn observe_all<T>(
        mut observer: impl FnMut() + 'static,
        action: impl FnOnce() -> T,
    ) -> T {
        observe_kind(move |_| observer(), action)
    }
    fn observe_kind<T>(observer: impl FnMut(bool) + 'static, action: impl FnOnce() -> T) -> T {
        let _restore = Restore(OBSERVER.with(|slot| slot.replace(Some(Box::new(observer)))));
        action()
    }
    pub(super) fn retention_returned() {
        returned(true);
    }
    pub(super) fn comparison_returned() {
        returned(false);
    }
    fn returned(retention: bool) {
        OBSERVER.with(|observer| {
            if let Some(observer) = observer.borrow_mut().as_mut() {
                observer(retention);
            }
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::discovery::identity::ReconciledModule;
    use crate::discovery::identity::test_fixture::real_scan_pin;
    use crate::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    use crate::plan::{self, AdmissionScope};
    use crate::process::{MountNamespaceId, ProcessViewId};
    use p11scope_manifest::maps::Device;
    use std::path::{Path, PathBuf};

    fn budget(endpoints: u64) -> InventoryBudget {
        InventoryBudget::new(endpoints, endpoints * 8).unwrap()
    }

    pub(crate) fn provider(dir: &tempfile::TempDir, name: &str, bytes: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// One pass's pin store: every `(path, sha256)` opened afresh, the way
    /// each catalog pass pins its objects.
    pub(crate) fn pass_pins(files: &[(&Path, &str)]) -> PinnedObjects {
        let mut pins = PinnedObjects::empty();
        for (path, sha256) in files {
            assert!(pins.absorb(real_scan_pin(path, None, 1, sha256)).is_empty());
        }
        pins
    }

    fn id_of(pins: &PinnedObjects, path: &Path) -> PinnedObjectId {
        pins.pinned()
            .find(|summary| summary.path == path.to_str().unwrap())
            .unwrap()
            .id
    }

    /// A scanned module publishing one table whose entries all target its own
    /// object at `offsets`, in the order given.
    pub(crate) fn module(pins: &PinnedObjects, path: &Path, offsets: &[u64]) -> ReconciledModule {
        let targets: Vec<(&Path, u64)> = offsets.iter().map(|offset| (path, *offset)).collect();
        module_with_targets(pins, path, &targets)
    }

    /// A scanned module at `path` whose one table's entries target
    /// `(object path, offset)` pairs — its own object or another one.
    /// Cross-object targets share the target's endpoints (P3
    /// shared-endpoint fixtures).
    pub(crate) fn module_with_targets(
        pins: &PinnedObjects,
        path: &Path,
        targets: &[(&Path, u64)],
    ) -> ReconciledModule {
        let object = id_of(pins, path);
        let key = pins.summary(object).unwrap().key;
        let entries: Vec<ScannedEntry> = targets
            .iter()
            .map(|(target, file_offset)| ScannedEntry {
                name: "C_Sign",
                object: pins.summary(id_of(pins, target)).unwrap().key,
                object_path: target.to_str().unwrap().to_string(),
                file_offset: *file_offset,
            })
            .collect();
        let entry_objects = targets
            .iter()
            .map(|(target, _)| id_of(pins, target))
            .collect();
        let path = path.to_str().unwrap().to_string();
        ReconciledModule {
            exports: Default::default(),
            object,
            entry_objects: vec![entry_objects],
            scanned: ScannedModule {
                mapped_identity: None,
                double_loaded: false,
                view: ProcessViewId(0),
                mount_namespace: MountNamespaceId {
                    device: 1,
                    inode: 1,
                },
                key,
                path,
                decoder_abi: Some(ElfAbi::Lp64),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries,
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000,
                    file_offset: Some(0),
                    live_return: false,
                    manifest_supported: false,
                }],
                interfaces: vec![],
            },
        }
    }

    pub(crate) fn offsets(count: u64) -> Vec<u64> {
        (0..count).map(|index| 0x1000 + index * 16).collect()
    }

    /// The production lowering shape: shared scope, scan evidence only. The
    /// budget must leave room beside the shared-scope reserve (at least 104
    /// endpoints) for the heuristic tables these fixtures publish.
    fn lower(
        modules: &[ReconciledModule],
        pins: &PinnedObjects,
        policy: AdmissionPolicy,
    ) -> AttachPlan {
        plan::build_from_sources_for_policy_scoped(
            modules,
            &[],
            pins,
            policy,
            AdmissionScope::Shared,
        )
    }

    /// First-come whole-module lowering, for budgets too small to leave a
    /// shared-scope reserve for heuristic providers.
    pub(crate) fn lower_named(
        modules: &[ReconciledModule],
        pins: &PinnedObjects,
        policy: AdmissionPolicy,
    ) -> AttachPlan {
        plan::build_from_sources_for_policy(modules, &[], pins, policy)
    }

    fn module_key(path: &Path, sha256: &str) -> AttachModuleKey {
        let metadata = std::fs::metadata(path).unwrap();
        use std::os::unix::fs::MetadataExt as _;
        AttachModuleKey {
            object: ObjectKey {
                device: Device {
                    major: u64::from(libc::major(metadata.dev())),
                    minor: u64::from(libc::minor(metadata.dev())),
                },
                inode: metadata.ino(),
            },
            sha256: sha256.to_string(),
        }
    }

    /// The module key a pin store files `path` under (raw key may be forged).
    fn key_in(pins: &PinnedObjects, path: &Path) -> AttachModuleKey {
        super::module_key(pins, id_of(pins, path)).unwrap()
    }

    /// `path` pinned under another raw maps key and mount: a container view.
    fn view_pins(path: &Path, minor: u64, mount_id: u64, sha256: &str) -> PinnedObjects {
        let inode = std::fs::metadata(path).map(|metadata| {
            use std::os::unix::fs::MetadataExt as _;
            metadata.ino()
        });
        let key = ObjectKey {
            device: Device { major: 0, minor },
            inode: inode.unwrap(),
        };
        let mut pins = PinnedObjects::empty();
        assert!(
            pins.absorb(real_scan_pin(path, Some(key), mount_id, sha256))
                .is_empty()
        );
        pins
    }

    /// Every endpoint as `(retained path, offset) -> id`.
    fn ids_by_target(set: &InventoryAttachSet) -> BTreeMap<(String, u64), u32> {
        set.endpoints()
            .map(|endpoint| {
                (
                    (
                        set.target(endpoint.object).unwrap().path().to_string(),
                        endpoint.file_offset,
                    ),
                    endpoint.id.0,
                )
            })
            .collect()
    }

    #[test]
    fn cgroup_prepared_absorption_keeps_reads_before_no_read_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = provider(&dir, "prepared.so", "provider");
        let pins = pass_pins(&[(&path, "sha-a")]);
        let mut set = InventoryAttachSet::new(budget(4096));
        let plan = lower(
            &[module(&pins, &path, &offsets(3))],
            &pins,
            AdmissionPolicy::Inventory(set.budget()),
        );
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let counter = reads.clone();
        let prepared = provider_read_test::observe(
            move || counter.set(counter.get() + 1),
            || set.prepare_absorption(&pins, |_| true).unwrap(),
        );
        assert_eq!(reads.get(), 1);
        assert_eq!(prepared.set.len(), 0, "preparation cannot grow endpoints");
        assert_eq!(prepared.set.aliases, 0);
        let result = provider_read_test::observe_all(
            || panic!("no provider retention or identity read at consumption"),
            || prepared.absorb(&plan, &pins, |_| true).unwrap(),
        );
        assert_eq!(result.delta.endpoints.len(), 3);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn cgroup_prepared_absorption_rejects_another_aggregate_with_equal_scalars() {
        let dir = tempfile::tempdir().unwrap();
        let path = provider(&dir, "prepared.so", "provider");
        let pins = pass_pins(&[(&path, "sha-a")]);
        let other = pass_pins(&[(&path, "sha-a")]);
        let mut set = InventoryAttachSet::new(budget(4096));
        let plan = lower(
            &[module(&other, &path, &offsets(3))],
            &other,
            AdmissionPolicy::Inventory(set.budget()),
        );
        let prepared = set.prepare_absorption(&pins, |_| true).unwrap();
        assert!(prepared.absorb(&plan, &other, |_| true).is_err());
        assert_eq!(set.len(), 0);
        assert!(set.by_raw.is_empty());
    }

    #[test]
    fn cgroup_prepared_alias_resolution_uses_held_read_facts_and_stable_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let path = provider(&dir, "alias.so", "provider");
        let pins = pass_pins(&[(&path, "sha-a")]);
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());
        let plan = lower(&[module(&pins, &path, &offsets(3))], &pins, policy);
        set.absorb(&plan, &pins);
        let before = ids_by_target(&set);
        let view = view_pins(&path, 4242, 2, "sha-a");
        let plan = lower(&[module(&view, &path, &offsets(3))], &view, policy);
        let comparisons = std::rc::Rc::new(std::cell::Cell::new(0));
        let counter = comparisons.clone();
        let prepared = provider_read_test::observe_comparisons(
            move || counter.set(counter.get() + 1),
            || set.prepare_absorption(&view, |_| true).unwrap(),
        );
        assert!(
            comparisons.get() > 0,
            "cross-mount preparation performed actual held-FD comparisons"
        );
        assert_eq!(prepared.set.aliases, 0);
        let outcome = provider_read_test::observe_all(
            || panic!("prepared consumption must not retain or stat again"),
            || prepared.absorb(&plan, &view, |_| true).unwrap(),
        );
        assert!(outcome.delta.is_empty());
        assert_eq!(ids_by_target(&set), before);
        assert_eq!(set.aliases, 1);
    }

    #[test]
    fn endpoint_ids_stay_stable_across_passes() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a"), (&b, "sha-b")]);
        let modules = [
            module(&pins, &a, &[0x1000, 0x1010, 0x1020]),
            module(&pins, &b, &[0x2000, 0x2010]),
        ];
        let first = set.absorb(&lower(&modules, &pins, policy), &pins);
        assert_eq!(
            first
                .delta
                .endpoints
                .iter()
                .map(|endpoint| endpoint.id.0)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3, 4]
        );
        assert_eq!(first.delta.objects.len(), 2);
        assert!(first.gaps.is_empty(), "{:?}", first.gaps);
        let before = ids_by_target(&set);
        assert_eq!(before.len(), 5);
        for (index, endpoint) in first.delta.endpoints.iter().enumerate() {
            assert_eq!(endpoint.id.0 as usize, index);
            assert_eq!(set.endpoint(endpoint.id), Some(endpoint));
        }
        assert_eq!(set.endpoint(EndpointId(5)), None);

        // A later pass opens and hashes everything again: new pin store,
        // new capture-local IDs, same physical endpoints.
        let pins = pass_pins(&[(&b, "sha-b"), (&a, "sha-a")]);
        let modules = [
            module(&pins, &b, &[0x2000, 0x2010]),
            module(&pins, &a, &[0x1000, 0x1010, 0x1020]),
        ];
        let second = set.absorb(&lower(&modules, &pins, policy), &pins);
        assert!(second.delta.is_empty(), "{:?}", second.delta);
        assert_eq!(ids_by_target(&set), before);
        assert_eq!(set.len(), 5);
        assert_eq!(
            second.verdicts.get(&module_key(&a, "sha-a")),
            Some(&AttachVerdict::Admitted {
                endpoints: 3,
                reasons: vec![]
            })
        );
        assert_eq!(
            second.verdicts.get(&module_key(&b, "sha-b")),
            Some(&AttachVerdict::Admitted {
                endpoints: 2,
                reasons: vec![]
            })
        );
    }

    #[test]
    fn an_alias_path_or_view_of_one_inode_adds_no_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let alias = dir.path().join("a-alias.so");
        std::fs::hard_link(&a, &alias).unwrap();
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a")]);
        let modules = [module(&pins, &a, &offsets(3))];
        assert_eq!(
            set.absorb(&lower(&modules, &pins, policy), &pins)
                .delta
                .endpoints
                .len(),
            3
        );

        // The hard link: another path, the same inode and raw key.
        let pins = pass_pins(&[(&alias, "sha-a")]);
        let modules = [module(&pins, &alias, &offsets(3))];
        let outcome = set.absorb(&lower(&modules, &pins, policy), &pins);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
        assert_eq!(
            outcome.verdicts.get(&module_key(&a, "sha-a")),
            Some(&AttachVerdict::Admitted {
                endpoints: 3,
                reasons: vec![]
            })
        );

        // The same file through another mount view: another raw maps key
        // and mount, the same kernel file behind the fd.
        let view_key = ObjectKey {
            device: Device {
                major: 0,
                minor: 4242,
            },
            inode: module_key(&a, "sha-a").object.inode,
        };
        let mut pins = PinnedObjects::empty();
        assert!(
            pins.absorb(real_scan_pin(&a, Some(view_key), 2, "sha-a"))
                .is_empty()
        );
        let modules = [module(&pins, &a, &offsets(3))];
        let outcome = set.absorb(&lower(&modules, &pins, policy), &pins);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
        assert_eq!(set.len(), 3);
    }

    /// Review R3/R4: mapper counts key by raw object key and sum an
    /// object's aliases, ignore keys of no retained object, are replaced
    /// every pass, and count only from a whole-system view.
    #[test]
    fn mapper_counts_sum_aliases_replace_per_pass_and_need_a_system_view() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());
        let pins = pass_pins(&[(&a, "sha-a")]);
        let modules = [module(&pins, &a, &offsets(3))];
        let delta = set.absorb(&lower(&modules, &pins, policy), &pins).delta;
        let object = delta.endpoints[0].object;
        let key = module_key(&a, "sha-a").object;
        // The same file through another mount view: an alias raw key.
        let view_key = ObjectKey {
            device: Device {
                major: 0,
                minor: 4242,
            },
            inode: key.inode,
        };
        let mut pins = PinnedObjects::empty();
        assert!(
            pins.absorb(real_scan_pin(&a, Some(view_key), 2, "sha-a"))
                .is_empty()
        );
        let modules = [module(&pins, &a, &offsets(3))];
        assert!(
            set.absorb(&lower(&modules, &pins, policy), &pins)
                .delta
                .is_empty()
        );
        let stranger = ObjectKey {
            device: Device {
                major: 0,
                minor: 4343,
            },
            inode: key.inode + 1,
        };

        assert_eq!(
            set.mappers(object),
            MapperEstimate::Unknown,
            "before a pass"
        );
        set.note_mappers(true, [(&key, 3), (&view_key, 2), (&stranger, 7)]);
        assert_eq!(set.mappers(object), MapperEstimate::System(5));
        // The next pass replaces the counts; one that did not see it, none.
        set.note_mappers(true, [(&view_key, 4)]);
        assert_eq!(set.mappers(object), MapperEstimate::System(4));
        set.note_mappers(true, []);
        assert_eq!(set.mappers(object), MapperEstimate::System(0));
        // A scope-limited view never estimates, whatever it counted.
        set.note_mappers(false, [(&key, 1)]);
        assert_eq!(set.mappers(object), MapperEstimate::ScopeLimited);
        set.note_mappers(true, [(&key, 9)]);
        assert_eq!(set.mappers(object), MapperEstimate::System(9));
    }

    #[test]
    fn identical_bytes_at_a_distinct_inode_get_distinct_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "identical-provider-bytes");
        let copy = provider(&dir, "copy.so", "identical-provider-bytes");
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-same")]);
        let modules = [module(&pins, &a, &offsets(3))];
        set.absorb(&lower(&modules, &pins, policy), &pins);

        let pins = pass_pins(&[(&copy, "sha-same")]);
        let modules = [module(&pins, &copy, &offsets(3))];
        let outcome = set.absorb(&lower(&modules, &pins, policy), &pins);
        assert_eq!(
            outcome
                .delta
                .endpoints
                .iter()
                .map(|endpoint| endpoint.id.0)
                .collect::<Vec<_>>(),
            [3, 4, 5]
        );
        assert_eq!(outcome.delta.objects.len(), 1);
        let objects: BTreeSet<AttachObjectId> =
            set.endpoints().map(|endpoint| endpoint.object).collect();
        assert_eq!(objects.len(), 2);
    }

    #[test]
    fn budget_exhaustion_refuses_the_module_by_name_with_one_gap() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let mut set = InventoryAttachSet::new(budget(8));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a")]);
        let modules = [module(&pins, &a, &offsets(6))];
        set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert_eq!(set.len(), 6);

        // A has exited; B alone fits a fresh 8-endpoint lowering, but the
        // set's lifetime budget holds A's six for the whole capture.
        let pins = pass_pins(&[(&b, "sha-b")]);
        let modules = [module(&pins, &b, &offsets(4))];
        let plan = lower_named(&modules, &pins, policy);
        assert_eq!(plan.refused_modules().count(), 0, "the lowering admits B");
        let outcome = set.absorb(&plan, &pins);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
        assert_eq!(set.len(), 6);
        let Some(AttachVerdict::Refused { reason }) =
            outcome.verdicts.get(&module_key(&b, "sha-b"))
        else {
            panic!("B must be refused: {:?}", outcome.verdicts);
        };
        assert!(reason.contains("needs 4 more endpoints"), "{reason}");
        assert!(reason.contains("6 of 8"), "{reason}");
        assert_eq!(outcome.gaps.len(), 1, "{:?}", outcome.gaps);
        assert_eq!(outcome.gaps[0].subject, REFUSED_SUBJECT);
        assert!(outcome.gaps[0].reason.contains(b.to_str().unwrap()));
        assert_eq!(outcome.gaps[0].budget, Some((ENDPOINT_RESOURCE, 8, 10)));

        // The next pass refuses it again, without a second gap.
        let pins = pass_pins(&[(&b, "sha-b")]);
        let modules = [module(&pins, &b, &offsets(4))];
        let outcome = set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert!(matches!(
            outcome.verdicts.get(&module_key(&b, "sha-b")),
            Some(AttachVerdict::Refused { .. })
        ));
        assert!(outcome.gaps.is_empty(), "{:?}", outcome.gaps);
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn growth_past_the_budget_keeps_retained_endpoints_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let mut set = InventoryAttachSet::new(budget(8));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a"), (&b, "sha-b")]);
        let modules = [
            module(&pins, &a, &offsets(5)),
            module(&pins, &b, &offsets(3)),
        ];
        set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert_eq!(set.len(), 8);
        let retained_ids = ids_by_target(&set);

        // A grows by one: the fresh lowering admits A whole (6) first-come
        // and refuses B, which no longer fits beside it.
        let pins = pass_pins(&[(&a, "sha-a"), (&b, "sha-b")]);
        let modules = [
            module(&pins, &a, &offsets(6)),
            module(&pins, &b, &offsets(3)),
        ];
        let plan = lower_named(&modules, &pins, policy);
        assert_eq!(plan.refused_modules().count(), 1);
        let outcome = set.absorb(&plan, &pins);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
        assert_eq!(set.len(), 8);
        assert_eq!(ids_by_target(&set), retained_ids);
        let Some(AttachVerdict::Admitted { endpoints, reasons }) =
            outcome.verdicts.get(&module_key(&a, "sha-a"))
        else {
            panic!("A keeps its endpoints: {:?}", outcome.verdicts);
        };
        assert_eq!(*endpoints, 5);
        assert_eq!(reasons.len(), 1);
        assert!(plan::is_growth_omission(&reasons[0]), "{reasons:?}");
        assert_eq!(plan::growth_omitted_count(&reasons[0]), Some(1));
        assert!(reasons[0].contains("kept its 5"), "{reasons:?}");
        let Some(AttachVerdict::Admitted { endpoints, reasons }) =
            outcome.verdicts.get(&module_key(&b, "sha-b"))
        else {
            panic!("B keeps its endpoints: {:?}", outcome.verdicts);
        };
        assert_eq!(*endpoints, 3);
        assert_eq!(reasons.len(), 1, "the lowering's refusal is disclosed");
        assert_eq!(outcome.gaps.len(), 1, "{:?}", outcome.gaps);
        assert_eq!(outcome.gaps[0].budget, Some((ENDPOINT_RESOURCE, 8, 9)));
        assert_eq!(set.module_endpoints(&module_key(&a, "sha-a")), Some(5));
        assert_eq!(set.module_endpoints(&module_key(&b, "sha-b")), Some(3));
    }

    #[test]
    fn a_module_past_512_endpoints_is_admitted_under_inventory_but_not_detailed() {
        let dir = tempfile::tempdir().unwrap();
        let big = provider(&dir, "big.so", "provider-big");
        let pins = pass_pins(&[(&big, "sha-big")]);
        let modules = [module(&pins, &big, &offsets(600))];

        let detailed = lower(&modules, &pins, AdmissionPolicy::detailed());
        assert_eq!(detailed.refused_modules().count(), 1);
        assert!(detailed.slots.is_empty());

        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());
        let outcome = set.absorb(&lower(&modules, &pins, policy), &pins);
        assert_eq!(outcome.delta.endpoints.len(), 600);
        assert_eq!(
            outcome.delta.endpoints.last().map(|endpoint| endpoint.id.0),
            Some(599)
        );
        assert_eq!(
            outcome.verdicts.get(&module_key(&big, "sha-big")),
            Some(&AttachVerdict::Admitted {
                endpoints: 600,
                reasons: vec![]
            })
        );
        // A Detailed lowering is not this set's input: every module is
        // refused by name and nothing is added.
        let mut other = InventoryAttachSet::new(budget(4096));
        let outcome = other.absorb(&detailed, &pins);
        assert_eq!(other.len(), 0);
        assert!(matches!(
            outcome.verdicts.get(&module_key(&big, "sha-big")),
            Some(AttachVerdict::Refused { reason }) if reason.contains("Inventory policy")
        ));
    }

    #[test]
    fn a_relowered_plan_with_reordered_slots_does_not_renumber() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a"), (&b, "sha-b")]);
        let modules = [
            module(&pins, &a, &offsets(4)),
            module(&pins, &b, &offsets(3)),
        ];
        let first_plan = lower_named(&modules, &pins, policy);
        set.absorb(&first_plan, &pins);
        let before = ids_by_target(&set);
        assert_eq!(before.len(), 7);

        let mut reversed_a = offsets(4);
        reversed_a.reverse();
        let mut reversed_b = offsets(3);
        reversed_b.reverse();
        let pins = pass_pins(&[(&b, "sha-b"), (&a, "sha-a")]);
        let modules = [
            module(&pins, &b, &reversed_b),
            module(&pins, &a, &reversed_a),
        ];
        let second_plan = lower_named(&modules, &pins, policy);
        let order = |plan: &AttachPlan| -> Vec<(String, u64)> {
            plan.slots
                .iter()
                .map(|slot| (slot.object_path.clone(), slot.file_offset))
                .collect()
        };
        assert_ne!(
            order(&first_plan),
            order(&second_plan),
            "precondition: the relowered plan orders its slots differently"
        );
        let outcome = set.absorb(&second_plan, &pins);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
        assert_eq!(ids_by_target(&set), before);
    }

    #[test]
    fn a_changed_pin_identity_is_never_extended() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a-v1");
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-v1")]);
        let modules = [module(&pins, &a, &offsets(3))];
        set.absorb(&lower(&modules, &pins, policy), &pins);
        assert_eq!(set.len(), 3);

        // Rewritten in place: same inode and raw key, new size, ctime and
        // digest, and one more endpoint.
        let inode = module_key(&a, "sha-v1").object.inode;
        std::fs::write(&a, "provider-a-v2-longer").unwrap();
        assert_eq!(module_key(&a, "sha-v2").object.inode, inode);
        for pass in 0..2 {
            let pins = pass_pins(&[(&a, "sha-v2")]);
            let modules = [module(&pins, &a, &offsets(4))];
            let outcome = set.absorb(&lower(&modules, &pins, policy), &pins);
            assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
            assert_eq!(set.len(), 3);
            let Some(AttachVerdict::Refused { reason }) =
                outcome.verdicts.get(&module_key(&a, "sha-v2"))
            else {
                panic!("the changed object must be refused: {:?}", outcome.verdicts);
            };
            assert!(reason.contains("changed identity"), "{reason}");
            assert!(reason.contains(a.to_str().unwrap()), "{reason}");
            let changed: Vec<&AttachGap> = outcome
                .gaps
                .iter()
                .filter(|gap| gap.subject == CHANGED_SUBJECT)
                .collect();
            assert_eq!(changed.len(), usize::from(pass == 0), "{:?}", outcome.gaps);
        }
    }

    #[test]
    fn module_members_name_each_admitted_modules_endpoints_and_stay_bounded() {
        // Budget 8: membership bound 32. P holds 8 endpoints; seven
        // forwarders each target all eight (8 memberships each).
        let dir = tempfile::tempdir().unwrap();
        let p = provider(&dir, "p.so", "provider-p");
        let forwarders: Vec<PathBuf> = (0..7)
            .map(|index| provider(&dir, &format!("f{index}.so"), &format!("forwarder-{index}")))
            .collect();
        let mut set = InventoryAttachSet::new(budget(8));
        let policy = AdmissionPolicy::Inventory(set.budget());
        let mut files: Vec<(&Path, String)> = vec![(p.as_path(), "sha-p".into())];
        files.extend(
            forwarders
                .iter()
                .enumerate()
                .map(|(index, path)| (path.as_path(), format!("sha-f{index}"))),
        );
        let borrowed: Vec<(&Path, &str)> = files
            .iter()
            .map(|(path, sha)| (*path, sha.as_str()))
            .collect();
        let pins = pass_pins(&borrowed);
        let targets: Vec<(&Path, u64)> = offsets(8).into_iter().map(|o| (p.as_path(), o)).collect();
        let mut modules = vec![module(&pins, &p, &offsets(8))];
        modules.extend(
            forwarders
                .iter()
                .map(|path| module_with_targets(&pins, path, &targets)),
        );
        let outcome = set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert_eq!(set.len(), 8, "shared targets are one endpoint each");
        let all: Vec<EndpointId> = (0..8).map(EndpointId).collect();
        assert_eq!(
            set.module_members(&key_in(&pins, &p)),
            Some(ModuleMembers::Known(&all))
        );
        let recorded = forwarders
            .iter()
            .filter(|path| {
                matches!(
                    set.module_members(&key_in(&pins, path)),
                    Some(ModuleMembers::Known(members)) if members == all.as_slice()
                )
            })
            .count();
        let unrecorded = forwarders
            .iter()
            .filter(|path| {
                set.module_members(&key_in(&pins, path)) == Some(ModuleMembers::Unrecorded)
            })
            .count();
        assert_eq!(
            (recorded, unrecorded),
            (3, 4),
            "32 memberships fit, then none"
        );
        assert!(set.memberships <= 32);
        for path in &forwarders {
            assert!(
                matches!(
                    outcome.verdicts.get(&key_in(&pins, path)),
                    Some(AttachVerdict::Admitted { endpoints: 8, reasons }) if reasons.is_empty()
                ),
                "an unrecorded membership never changes admission"
            );
        }
        // The reverse index is exactly the recorded memberships: each
        // endpoint lists P and the three recorded forwarders, never an
        // unrecorded one.
        let recorded_keys: BTreeSet<AttachModuleKey> = std::iter::once(&p)
            .chain(forwarders.iter())
            .map(|path| key_in(&pins, path))
            .filter(|key| matches!(set.module_members(key), Some(ModuleMembers::Known(_))))
            .collect();
        assert_eq!(recorded_keys.len(), 4);
        for endpoint in &all {
            let listed: BTreeSet<AttachModuleKey> =
                set.modules_with_member(*endpoint).cloned().collect();
            assert_eq!(listed, recorded_keys, "endpoint {endpoint:?}");
        }
        assert_eq!(set.modules_with_member(EndpointId(8)).count(), 0);
        // A second pass re-records the same memberships: no duplicates.
        set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert_eq!(set.modules_with_member(EndpointId(0)).count(), 4);
        assert!(set.memberships <= 32);
    }

    #[test]
    fn the_reverse_membership_follows_a_module_whose_demand_shrinks() {
        // A module re-lowered with fewer targets keeps its endpoints in the
        // set, but its membership (and so what a witness of the dropped
        // endpoint is use of) is the current one.
        let dir = tempfile::tempdir().unwrap();
        let p = provider(&dir, "p.so", "provider-p");
        let mut set = InventoryAttachSet::new(budget(8));
        let policy = AdmissionPolicy::Inventory(set.budget());
        let pins = pass_pins(&[(p.as_path(), "sha-p")]);
        let key = key_in(&pins, &p);
        let wide = [module(&pins, &p, &offsets(2))];
        set.absorb(&lower_named(&wide, &pins, policy), &pins);
        assert_eq!(set.modules_with_member(EndpointId(1)).count(), 1);
        let narrow = [module(&pins, &p, &offsets(1))];
        set.absorb(&lower_named(&narrow, &pins, policy), &pins);
        assert_eq!(
            set.module_members(&key),
            Some(ModuleMembers::Known(&[EndpointId(0)]))
        );
        assert_eq!(
            set.modules_with_member(EndpointId(0)).collect::<Vec<_>>(),
            vec![&key]
        );
        assert_eq!(
            set.modules_with_member(EndpointId(1)).count(),
            0,
            "a dropped member never stays indexed"
        );
    }

    #[test]
    fn a_shared_target_never_grants_partial_admission_to_a_new_module() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let c = provider(&dir, "c.so", "provider-c");
        let mut set = InventoryAttachSet::new(budget(5));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a"), (&c, "sha-c")]);
        let modules = [
            module(&pins, &a, &offsets(3)),
            module(&pins, &c, &offsets(2)),
        ];
        set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert_eq!(set.len(), 5);

        // C has exited. B shares A's first target and needs one of its own:
        // the lowering admits it (3 + 1 of 5), the lifetime budget cannot.
        let pins = pass_pins(&[(&a, "sha-a"), (&b, "sha-b")]);
        let shared = offsets(3)[0];
        let modules = [
            module(&pins, &a, &offsets(3)),
            module_with_targets(&pins, &b, &[(&a, shared), (&b, 0x4000)]),
        ];
        let plan = lower_named(&modules, &pins, policy);
        assert_eq!(plan.refused_modules().count(), 0, "the lowering admits B");
        let outcome = set.absorb(&plan, &pins);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
        let Some(AttachVerdict::Refused { reason }) = outcome.verdicts.get(&key_in(&pins, &b))
        else {
            panic!(
                "B was never admitted, so it is refused: {:?}",
                outcome.verdicts
            );
        };
        assert!(reason.contains("needs 1 more endpoint"), "{reason}");
        assert_eq!(set.module_endpoints(&key_in(&pins, &b)), None);
        assert_eq!(set.module_endpoints(&key_in(&pins, &a)), Some(3));
    }

    #[test]
    fn the_module_record_cap_refuses_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let c = provider(&dir, "c.so", "provider-c");
        let mut set = InventoryAttachSet::new(budget(2));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a"), (&b, "sha-b"), (&c, "sha-c")]);
        let target = offsets(1)[0];
        let modules = [
            module(&pins, &a, &[target]),
            module(&pins, &b, &[target]),
            // C needs no new endpoint: its only target is A's.
            module_with_targets(&pins, &c, &[(&a, target)]),
        ];
        let plan = lower_named(&modules, &pins, policy);
        assert_eq!(plan.refused_modules().count(), 0);
        let outcome = set.absorb(&plan, &pins);
        assert_eq!(set.len(), 2);
        let Some(AttachVerdict::Refused { reason }) = outcome.verdicts.get(&key_in(&pins, &c))
        else {
            panic!("C must be refused: {:?}", outcome.verdicts);
        };
        assert!(reason.contains("2 of 2 module records"), "{reason}");
        assert_eq!(outcome.gaps.len(), 1, "{:?}", outcome.gaps);
        assert_eq!(outcome.gaps[0].budget, Some((MODULE_RESOURCE, 2, 3)));
    }

    #[test]
    fn a_failed_retention_leaves_the_set_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let x = provider(&dir, "x.so", "provider-x");
        let y = provider(&dir, "y.so", "provider-y");
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        // The module targets its own object and a dependency; the
        // dependency changes between pinning and retention.
        let pins = pass_pins(&[(&x, "sha-x"), (&y, "sha-y")]);
        let modules = [module_with_targets(
            &pins,
            &x,
            &[(&x, 0x1000), (&x, 0x1010), (&y, 0x2000)],
        )];
        let plan = lower_named(&modules, &pins, policy);
        std::fs::write(&y, "provider-y-rewritten").unwrap();
        let outcome = set.absorb(&plan, &pins);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
        assert_eq!(set.len(), 0);
        assert!(
            set.target(AttachObjectId(0)).is_none(),
            "no object retained"
        );
        let Some(AttachVerdict::Refused { reason }) = outcome.verdicts.get(&key_in(&pins, &x))
        else {
            panic!("the module must be refused: {:?}", outcome.verdicts);
        };
        assert!(reason.contains("changed before retention"), "{reason}");
        assert_eq!(outcome.gaps.len(), 1, "{:?}", outcome.gaps);
    }

    #[test]
    fn the_same_object_proof_needs_the_same_kernel_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-a");
        let pins = pass_pins(&[(&a, "sha-a")]);
        let retained = pins.retain_inventory_target(id_of(&pins, &a)).unwrap();

        // Another mount view of `a`: the fstat pair proves one file.
        let view = view_pins(&a, 4242, 2, "sha-a");
        assert!(retained.same_object_as(&view, id_of(&view, &a)));
        // The same pin, digest and view, backed by another kernel file.
        let mut forged = view_pins(&a, 4242, 2, "sha-a");
        crate::discovery::identity::test_fixture::reback(
            &mut forged,
            &std::sync::Arc::new(std::fs::File::open(&b).unwrap()),
        );
        assert_eq!(
            forged.content_key(id_of(&forged, &a)),
            view.content_key(id_of(&view, &a))
        );
        assert!(!retained.same_object_as(&forged, id_of(&forged, &a)));

        // Through the set: the forged view is never merged onto `a`'s
        // retained object or endpoints.
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());
        let modules = [module(&pins, &a, &offsets(3))];
        set.absorb(&lower(&modules, &pins, policy), &pins);
        let before = ids_by_target(&set);
        let modules = [module(&forged, &a, &offsets(3))];
        let outcome = set.absorb(&lower(&modules, &forged, policy), &forged);
        assert_ne!(
            outcome.verdicts.get(&key_in(&forged, &a)),
            Some(&AttachVerdict::Admitted {
                endpoints: 3,
                reasons: vec![]
            }),
            "a content match on another kernel file is not the retained object"
        );
        assert_eq!(ids_by_target(&set), before);
    }

    #[test]
    fn an_in_place_change_seen_only_through_a_proven_view_is_never_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a-v1");
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-v1")]);
        let modules = [module(&pins, &a, &offsets(3))];
        set.absorb(&lower(&modules, &pins, policy), &pins);
        // The container view, proven once.
        let view = view_pins(&a, 4242, 2, "sha-v1");
        let modules = [module(&view, &a, &offsets(3))];
        assert!(
            set.absorb(&lower(&modules, &view, policy), &view)
                .delta
                .is_empty()
        );

        // Rewritten in place, then seen only through that view.
        std::fs::write(&a, "provider-a-v2-longer").unwrap();
        let view = view_pins(&a, 4242, 2, "sha-v2");
        let modules = [module(&view, &a, &offsets(3))];
        let outcome = set.absorb(&lower(&modules, &view, policy), &view);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
        assert_eq!(set.len(), 3, "no second endpoint set on the same inode");
        assert!(
            outcome
                .gaps
                .iter()
                .any(|gap| gap.subject == CHANGED_SUBJECT),
            "{:?}",
            outcome.gaps
        );
    }

    /// The proven container view key of `path`: the raw key `view_pins`
    /// files it under.
    fn view_key(path: &Path) -> ObjectKey {
        view_pins(path, 4242, 2, "unused")
            .pinned()
            .next()
            .unwrap()
            .key
    }

    #[test]
    fn an_object_changed_later_in_the_same_pass_is_not_extended() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let link = dir.path().join("a-view.so");
        std::fs::hard_link(&a, &link).unwrap();
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a")]);
        let modules = [module(&pins, &a, &offsets(3))];
        set.absorb(&lower_named(&modules, &pins, policy), &pins);
        let view = view_pins(&a, 4242, 2, "sha-a");
        let modules = [module(&view, &a, &offsets(3))];
        set.absorb(&lower_named(&modules, &view, policy), &view);

        // One pass: `a` pinned under its own key (identical, resolved
        // first), then rewritten in place mid-pass and pinned again under
        // its proven view key — the same kernel file, a new identity.
        let mut pins = pass_pins(&[(&a, "sha-a")]);
        std::fs::write(&a, "provider-a-rewritten-mid-pass").unwrap();
        let mut rewritten = PinnedObjects::empty();
        assert!(
            rewritten
                .absorb(real_scan_pin(&link, Some(view_key(&a)), 2, "sha-a2"))
                .is_empty()
        );
        assert!(pins.absorb(rewritten).is_empty());
        let modules = [
            module(&pins, &a, &offsets(4)),
            module(&pins, &link, &offsets(3)),
        ];
        let plan = lower_named(&modules, &pins, policy);
        assert_eq!(plan.slots[0].object, id_of(&pins, &a), "a resolves first");
        let outcome = set.absorb(&plan, &pins);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
        assert_eq!(set.len(), 3);
        assert!(matches!(
            outcome.verdicts.get(&key_in(&pins, &a)),
            Some(AttachVerdict::Refused { reason }) if reason.contains("changed identity")
        ));
        assert_eq!(
            outcome
                .gaps
                .iter()
                .filter(|gap| gap.subject == CHANGED_SUBJECT)
                .count(),
            1,
            "{:?}",
            outcome.gaps
        );
    }

    #[test]
    fn an_impostor_under_a_stale_alias_key_leaves_the_object_extendable() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a")]);
        let modules = [module(&pins, &a, &offsets(3))];
        set.absorb(&lower_named(&modules, &pins, policy), &pins);
        let view = view_pins(&a, 4242, 2, "sha-a");
        let modules = [module(&view, &a, &offsets(3))];
        set.absorb(&lower_named(&modules, &view, policy), &view);
        assert_eq!(set.len(), 3);

        // The container is gone and its overlay device recycled: another
        // file now answers under `a`'s recorded alias key, in the same pass
        // that grows `a` by one endpoint.
        let mut pins = pass_pins(&[(&a, "sha-a")]);
        let mut impostor = PinnedObjects::empty();
        assert!(
            impostor
                .absorb(real_scan_pin(&b, Some(view_key(&a)), 3, "sha-b"))
                .is_empty()
        );
        assert!(pins.absorb(impostor).is_empty());
        let modules = [
            module(&pins, &a, &offsets(4)),
            module(&pins, &b, &offsets(2)),
        ];
        let outcome = set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert!(
            !outcome
                .gaps
                .iter()
                .any(|gap| gap.subject == CHANGED_SUBJECT),
            "a stale alias is not a changed object: {:?}",
            outcome.gaps
        );
        assert_eq!(
            outcome.verdicts.get(&key_in(&pins, &a)),
            Some(&AttachVerdict::Admitted {
                endpoints: 4,
                reasons: vec![]
            }),
            "the original object stays extendable"
        );
        assert_eq!(
            outcome.verdicts.get(&key_in(&pins, &b)),
            Some(&AttachVerdict::Admitted {
                endpoints: 2,
                reasons: vec![]
            }),
            "the impostor is its own object"
        );
        assert_eq!(set.len(), 6);
        let objects: BTreeSet<AttachObjectId> =
            set.endpoints().map(|endpoint| endpoint.object).collect();
        assert_eq!(objects.len(), 2, "never merged onto a's endpoints");

        // A later pass of `a` alone still extends nothing it already holds.
        let pins = pass_pins(&[(&a, "sha-a")]);
        let modules = [module(&pins, &a, &offsets(4))];
        let outcome = set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert!(outcome.delta.is_empty(), "{:?}", outcome.delta);
    }

    #[test]
    fn refusal_gaps_are_deduplicated_per_kind_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let c = provider(&dir, "c.so", "provider-c");
        let mut set = InventoryAttachSet::new(budget(8));
        let policy = AdmissionPolicy::Inventory(set.budget());
        let refusals = |outcome: &AbsorbOutcome| -> usize {
            outcome
                .gaps
                .iter()
                .filter(|gap| gap.subject == REFUSED_SUBJECT)
                .count()
        };

        let pins = pass_pins(&[(&a, "sha-a")]);
        let modules = [module(&pins, &a, &offsets(4))];
        set.absorb(&lower_named(&modules, &pins, policy), &pins);

        // B: a retention refusal (changed between pin and retention).
        let pins = pass_pins(&[(&b, "sha-b")]);
        let modules = [module(&pins, &b, &offsets(3))];
        let plan = lower_named(&modules, &pins, policy);
        std::fs::write(&b, "provider-b-rewritten").unwrap();
        assert_eq!(refusals(&set.absorb(&plan, &pins)), 1);

        // B again, now an endpoint-budget refusal behind C: another kind,
        // another gap; the same kind on the next pass, none.
        for expected in [1, 0] {
            let pins = pass_pins(&[(&c, "sha-c"), (&b, "sha-b")]);
            let modules = [
                module(&pins, &c, &offsets(2)),
                module(&pins, &b, &offsets(3)),
            ];
            let outcome = set.absorb(&lower_named(&modules, &pins, policy), &pins);
            assert_eq!(refusals(&outcome), expected, "{:?}", outcome.gaps);
            assert!(matches!(
                outcome.verdicts.get(&key_in(&pins, &b)),
                Some(AttachVerdict::Refused { .. })
            ));
        }
        assert_eq!(set.len(), 6);

        // Distinct refusals past the memo bound (8): one overflow gap, then
        // nothing more, while every verdict still names its refusal.
        let mut gaps = 0;
        let mut overflow = 0;
        for index in 0..12 {
            let d = provider(&dir, &format!("d{index}.so"), &format!("provider-d{index}"));
            let pins = pass_pins(&[(&d, "sha-d")]);
            let modules = [module(&pins, &d, &offsets(3))];
            let outcome = set.absorb(&lower_named(&modules, &pins, policy), &pins);
            assert!(matches!(
                outcome.verdicts.get(&key_in(&pins, &d)),
                Some(AttachVerdict::Refused { .. })
            ));
            gaps += refusals(&outcome);
            overflow += outcome
                .gaps
                .iter()
                .filter(|gap| gap.subject == GAP_OVERFLOW_SUBJECT)
                .count();
        }
        // Two memo entries were used above: B, once per refusal kind.
        assert_eq!(gaps, 8 - 2);
        assert_eq!(overflow, 1);
    }

    #[test]
    fn a_stale_alias_of_a_changed_object_is_dropped_not_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let mut set = InventoryAttachSet::new(budget(4096));
        let policy = AdmissionPolicy::Inventory(set.budget());

        let pins = pass_pins(&[(&a, "sha-a")]);
        let modules = [module(&pins, &a, &offsets(3))];
        set.absorb(&lower_named(&modules, &pins, policy), &pins);
        let view = view_pins(&a, 4242, 2, "sha-a");
        let modules = [module(&view, &a, &offsets(3))];
        set.absorb(&lower_named(&modules, &view, policy), &view);
        let alias = view_key(&a);

        // `a` is rewritten in place and seen under its own key: changed.
        std::fs::write(&a, "provider-a-rewritten").unwrap();
        let pins = pass_pins(&[(&a, "sha-a2")]);
        let modules = [module(&pins, &a, &offsets(3))];
        let outcome = set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert!(
            outcome
                .gaps
                .iter()
                .any(|gap| gap.subject == CHANGED_SUBJECT),
            "{:?}",
            outcome.gaps
        );

        // Then another file answers under `a`'s recycled alias key: it is
        // its own object, never blocked by `a`'s changed mark.
        let mut impostor = PinnedObjects::empty();
        assert!(
            impostor
                .absorb(real_scan_pin(&b, Some(alias), 3, "sha-b"))
                .is_empty()
        );
        let modules = [module(&impostor, &b, &offsets(2))];
        let outcome = set.absorb(&lower_named(&modules, &impostor, policy), &impostor);
        assert_eq!(
            outcome.verdicts.get(&key_in(&impostor, &b)),
            Some(&AttachVerdict::Admitted {
                endpoints: 2,
                reasons: vec![]
            }),
            "{:?}",
            outcome.gaps
        );
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn refusal_counters_feed_the_budget_rows() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let b = provider(&dir, "b.so", "provider-b");
        let c = provider(&dir, "c.so", "provider-c");
        let mut set = InventoryAttachSet::new(budget(8));
        let policy = AdmissionPolicy::Inventory(set.budget());
        // A takes 6; later B alone needs 4 (the lowering admits it) and the
        // lifetime budget refuses it, once per pass.
        let pins = pass_pins(&[(&a, "sha-a")]);
        let modules = [module(&pins, &a, &offsets(6))];
        set.absorb(&lower_named(&modules, &pins, policy), &pins);
        for _ in 0..2 {
            let pins = pass_pins(&[(&b, "sha-b")]);
            let modules = [module(&pins, &b, &offsets(4))];
            set.absorb(&lower_named(&modules, &pins, policy), &pins);
        }
        assert_eq!(set.endpoint_refusals(), 2);
        assert_eq!(set.module_record_refusals(), 0);
        assert_eq!(set.module_records(), 1);

        // Budget 2: A and B take one record each; C (only A's target)
        // is refused on the module-record cap.
        let mut set = InventoryAttachSet::new(budget(2));
        let policy = AdmissionPolicy::Inventory(set.budget());
        let pins = pass_pins(&[(&a, "sha-a"), (&b, "sha-b"), (&c, "sha-c")]);
        let target = offsets(1)[0];
        let modules = [
            module(&pins, &a, &[target]),
            module(&pins, &b, &[target]),
            module_with_targets(&pins, &c, &[(&a, target)]),
        ];
        set.absorb(&lower_named(&modules, &pins, policy), &pins);
        assert_eq!(set.module_record_refusals(), 1);
        assert_eq!(set.endpoint_refusals(), 0);
        assert_eq!(set.module_records(), 2);
    }
    #[test]
    fn demotion_retirement_membership_revision_exhaustion_is_sticky() {
        let dir = tempfile::tempdir().unwrap();
        let a = provider(&dir, "a.so", "provider-a");
        let pins = pass_pins(&[(&a, "sha-a")]);
        let mut set = InventoryAttachSet::new(budget(8));
        let policy = AdmissionPolicy::Inventory(set.budget());
        let plan = lower_named(&[module(&pins, &a, &offsets(2))], &pins, policy);
        set.absorb(&plan, &pins);
        set.count_revision = AttachRevision(Some(u64::MAX));
        set.absorb(&plan, &pins);
        assert!(
            set.count_revision.0.is_some(),
            "equivalent observations do not consume revisions"
        );
        let changed = lower_named(&[module(&pins, &a, &offsets(1))], &pins, policy);
        set.absorb(&changed, &pins);
        for _ in 0..3 {
            let revision = set.count_revision();
            assert!(matches!(
                set.count_membership_page(None, revision, 128),
                Err(CountMembershipRefusal::Exhausted)
            ));
            set.absorb(&plan, &pins);
        }
        assert!(
            set.count_revision.0.is_none(),
            "actual mutation exhaustion cannot wrap or recover"
        );
    }
}
