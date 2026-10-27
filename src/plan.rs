//! SPDX-License-Identifier: GPL-3.0-or-later
//! Discovered modules → one attach plan. The eBPF side has a single fixed-size
//! slot array, so every module a capture found shares one slot space: one slot per
//! unique {object, file_offset} across all of them. A target two modules both hand
//! out is attached once (attaching twice would double-count every call through it),
//! and because its counts then belong to neither module its semantics degrade to
//! COUNT_ONLY (spec §4.7). A module is never silently truncated: a partially
//! attached module would under-report a provider. Scan tables admit in
//! publication-evidence order: unresolved heuristic tables admit until the
//! per-object cap, and their spill is reported as `uncorroborated_candidates`
//! rather than refused. The demand that must fit atomically — the manifest
//! subset, the strongest table, the union of the corroborated/published
//! tables (which bypass the per-object cap), and under broad or Inventory
//! admission the complete validated union — refuses the module whole when it
//! exceeds the remaining budget. That holds for a module new to the capture
//! and for one whose sources no longer list any endpoint the capture attached
//! for it (its old endpoints retire; capture history still names it). A
//! module whose sources still list such endpoints is never refused whole
//! (G-03): when what it needs next does not fit, it keeps those endpoints, no
//! prefix of the rest is attached, and the omission is reported, so it is
//! partial but never silent.
//!
//! Both discovery sources — the memory scan and a manifest — lower into `Discovered`
//! and go through the same `merge`, so there is exactly one implementation of the
//! merge rules rather than two that can drift.

use crate::discovery::identity::{
    GraphRefusal, GraphStep, PinnedObjectId, PinnedObjects, ReconciledModule,
};
pub use crate::discovery::scan::Skipped;
use crate::discovery::scan::{
    ObjectExports, ScannedEntry, ScannedInterface, ScannedTable, TableEvidenceScore,
    export_agreement, order_tables_by_evidence, standard_ordinal, table_evidence_score,
    table_linkage, table_name_authorized, table_observation_authorized,
};
use crate::inventory_semantics::SemanticRefusal;
use crate::kinds::AliasAgreement;
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
use p11scope_ebpf_common::{MAX_SLOTS, SlotSemantics};
use p11scope_manifest::manifest::{
    Acquisition, InterfaceClassification, Manifest, ObjectRecord, Resolution, SurfaceSource,
    WalkOutcome,
};
use p11scope_manifest::maps::{Device, ObjectKey};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

/// Immutable admission contract carried by one planner for its whole capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionPolicy {
    /// Existing metrics/profile/trace behavior: 512 lifetime slots and K4
    /// unresolved heuristic tables per physical provider object.
    Detailed,
    /// Compact entry-use inventory: every validated physical target is
    /// count-only and the complete union is admitted atomically within this
    /// endpoint/payload budget.
    Inventory(crate::capacity::InventoryBudget),
    /// Planner preparation for metrics counters: the complete validated union
    /// is count-only within a lifetime endpoint envelope. This policy grants
    /// no native map capacity or runtime activation.
    Counters(crate::capacity::CounterBudget),
}

impl AdmissionPolicy {
    pub const fn detailed() -> Self {
        Self::Detailed
    }

    pub const fn inventory(budget: crate::capacity::InventoryBudget) -> Self {
        Self::Inventory(budget)
    }

    pub const fn counters(budget: crate::capacity::CounterBudget) -> Self {
        Self::Counters(budget)
    }

    fn endpoint_limit(self) -> usize {
        match self {
            Self::Detailed => MAX_SLOTS as usize,
            Self::Inventory(budget) => budget.endpoint_limit() as usize,
            Self::Counters(budget) => budget.endpoint_limit() as usize,
        }
    }

    fn admits_complete_validated_union(self) -> bool {
        matches!(self, Self::Inventory(_) | Self::Counters(_))
    }

    fn forces_count_only(self) -> bool {
        matches!(self, Self::Inventory(_) | Self::Counters(_))
    }

    fn count_only_subject(self) -> &'static str {
        match self {
            Self::Detailed => "detailed",
            Self::Inventory(_) => "inventory",
            Self::Counters(_) => "counter",
        }
    }

    fn capacity_subject(self) -> &'static str {
        match self {
            Self::Detailed | Self::Inventory(_) => "attach slots",
            Self::Counters(_) => "counter endpoints",
        }
    }

    fn validate_count(self, endpoints: usize) -> Result<(), String> {
        match self {
            Self::Detailed if endpoints <= MAX_SLOTS as usize => Ok(()),
            Self::Detailed => Err(format!(
                "attach plan requires {endpoints} allocated slots but only {MAX_SLOTS} are available"
            )),
            Self::Inventory(budget) => budget.validate_count(endpoints),
            Self::Counters(budget) => budget.validate_count(endpoints),
        }
    }

    fn checked_required(self, current: usize, additions: usize) -> Result<usize, String> {
        let required = current.checked_add(additions).ok_or_else(|| {
            match self {
                Self::Counters(_) => "counter endpoint requirement overflowed",
                Self::Detailed | Self::Inventory(_) => "attach slot requirement overflowed",
            }
            .to_string()
        })?;
        self.validate_count(required)?;
        Ok(required)
    }
}

/// Capture-local module index; the stable identity in output is {dev, ino, sha256, path}.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregateOwner {
    Unowned,
    Sole(ModuleId),
    Ambiguous,
}

impl AggregateOwner {
    fn from_module_ids(module_ids: &[ModuleId]) -> Self {
        match module_ids {
            [] => Self::Unowned,
            [module] => Self::Sole(*module),
            _ => Self::Ambiguous,
        }
    }

    fn merge(self, current: Self) -> Self {
        match (self, current) {
            (Self::Ambiguous, _) | (_, Self::Ambiguous) => Self::Ambiguous,
            (Self::Unowned, _) | (_, Self::Unowned) => Self::Unowned,
            (Self::Sole(previous), Self::Sole(current)) if previous == current => self,
            (Self::Sole(_), Self::Sole(_)) => Self::Ambiguous,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Per-slot object authority computed from the sealed plan: either the
/// frozen cookie stays eligible, or the claim is refused with its reason
/// and fresh alias verdict. Inactive in slice A.
#[cfg_attr(not(test), allow(dead_code))] // Slices B/C admit markers from this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObjectSlotEligibility {
    Eligible {
        descriptor_index: u32,
    },
    Refused {
        reason: SemanticRefusal,
        agreement: AliasAgreement,
    },
}

/// The presented name for a slot no authorized source named: an unlinked
/// heuristic table's ordinal labels are positional guesses, never attributions.
/// Transparent in a slot's claim set — an authorized name always wins over it —
/// never a rival claim and never semantic authority.
pub(crate) const UNKNOWN_FUNCTION_NAME: &str = "unknown";

/// One table ordinal that reaches a slot's exact target (review answer (c)).
/// Several on one target are several ordinals sharing it — the grouping an
/// unnamed row would otherwise hide. The ordinal is a position, never a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct SlotOrdinal {
    /// The reaching table's version-word file offset, the same value
    /// `discovery[].tables[].file_offset` publishes; `None` for a manifest
    /// surface or selection table (no table location) and for a table with
    /// no provable file owner.
    pub table_file_offset: Option<u64>,
    /// Position in the standard function list (the pinned 104-name catalog,
    /// of which every walkable layout is a prefix).
    pub ordinal: u16,
}

/// The pinned object a slot attaches into, identified exactly as
/// `discovery[].objects[]` identifies it. File facts only.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TargetObject {
    pub dev: (u64, u64),
    pub ino: u64,
    pub sha256: Option<String>,
}

/// The one display label for a slot: its names, or — for a slot no
/// authorized source named — `unknown#<ordinal>` per distinct ordinal
/// reaching it (`unknown@0x<offset>` when none does), so unnamed rows stay
/// distinguishable without presenting a positional guess as a name.
pub(crate) fn presented_label(
    names: &[String],
    ordinals: &[SlotOrdinal],
    file_offset: u64,
) -> String {
    if names != [UNKNOWN_FUNCTION_NAME] {
        return names.join("|");
    }
    let mut numbers: Vec<u16> = ordinals.iter().map(|ordinal| ordinal.ordinal).collect();
    numbers.sort_unstable();
    numbers.dedup();
    if numbers.is_empty() {
        return format!("{UNKNOWN_FUNCTION_NAME}@0x{file_offset:x}");
    }
    numbers
        .iter()
        .map(|number| format!("{UNKNOWN_FUNCTION_NAME}#{number}"))
        .collect::<Vec<_>>()
        .join("|")
}

/// `unknown` is the absence of a name claim: it never survives beside a real
/// name. Applied everywhere slot names union (merge drops it from the claim
/// map before collecting; extend and selection drop it from the vec).
fn drop_transparent_unknown(names: &mut Vec<String>) {
    if names.len() > 1 {
        names.retain(|name| name != UNKNOWN_FUNCTION_NAME);
    }
}

/// Opens every `modules_skipped` reason for a module that was already
/// attached when its growth did not fit (G-03): it keeps the endpoints it
/// had, so it is partially covered, never refused. A whole refusal opens
/// with `module needs` instead.
const GROWTH_OMISSION: &str = "admitted module needs";

/// Whether a `modules_skipped` reason records a partially covered module
/// rather than one refused whole.
pub(crate) fn is_growth_omission(reason: &str) -> bool {
    reason.starts_with(GROWTH_OMISSION)
}

/// The omitted count a growth omission states — the `N` of
/// `admitted module needs N more;` — or `None` for any other reason.
pub(crate) fn growth_omitted_count(reason: &str) -> Option<usize> {
    reason
        .strip_prefix(GROWTH_OMISSION)?
        .strip_prefix(' ')?
        .split_once(" more;")?
        .0
        .parse()
        .ok()
}

/// The count a whole capacity refusal states — the `N` of
/// `module needs N more;` — or `None` for any other reason (PD-T6-1).
pub(crate) fn whole_refusal_needed_count(reason: &str) -> Option<usize> {
    reason
        .strip_prefix("module needs ")?
        .split_once(" more;")?
        .0
        .parse()
        .ok()
}

/// The omitted endpoints are not called new: an endpoint deactivated earlier
/// in the capture and listed again needs a fresh slot just the same.
fn growth_omission_reason(
    omitted: usize,
    capacity: usize,
    in_use: usize,
    retired: usize,
    kept: usize,
    policy: AdmissionPolicy,
) -> String {
    let endpoints = |count: usize| if count == 1 { "endpoint" } else { "endpoints" };
    format!(
        "{GROWTH_OMISSION} {omitted} more; only {capacity} {} are available; \
         {} — {omitted} {} not attached; kept its {kept} attached {}",
        policy.capacity_subject(),
        slot_use(in_use, retired, &[]),
        endpoints(omitted),
        endpoints(kept),
    )
}

/// A module's admission class in a shared scope, in admission order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AdmissionClass {
    /// Named by the operator's `--manifest`: attested, admitted first and
    /// under the named-scope rule.
    Operator,
    /// At least one table with publication evidence, and no closure-array
    /// excess of unresolved lookalikes. Observation authorization is independent
    /// of the permission to present ordinal names as API names.
    Corroborated,
    /// Only unresolved heuristic tables, at most [`MAX_TABLES_PER_OBJECT`].
    Heuristic,
    /// More than [`MAX_TABLES_PER_OBJECT`] *unresolved* lookalike tables in
    /// one object: a proxy's closure array (p11-kit decodes 64). A call
    /// through the proxy is seen at the real provider's own functions once
    /// that provider is attached, and the whole array (~6,656 endpoints)
    /// never fits, so it is admitted last and only whole.
    ClosureArray,
}

impl AdmissionClass {
    const fn leaves_reserve(self) -> bool {
        matches!(self, Self::Heuristic | Self::ClosureArray)
    }
}

/// One object's admission class and its distinct *unresolved* lookalike
/// count. Corroborated (interface-linked, live-return, manifest or
/// export-authorized) tables never count as lookalikes: a genuine
/// multi-table provider (NSS softokn) is corroborated however many tables
/// it publishes, while a proxy closure array (p11-kit) stays one however
/// few linked tables it keeps beside its templates. The count feeds the
/// shared-scope within-class order and the closure-array refusal message,
/// both of which are about lookalikes.
fn admission_class(group: &[Discovered<'_>]) -> (AdmissionClass, usize) {
    let mut observations = BTreeMap::<TableKey, bool>::new();
    for (piece, module) in group.iter().enumerate() {
        let Some(evidence) = &module.scan_evidence else {
            continue;
        };
        for (index, table) in evidence.tables.iter().enumerate() {
            let authorized = table_observation_authorized(
                table,
                &table_evidence_score(
                    index,
                    evidence.tables,
                    evidence.interfaces,
                    &[],
                    &[],
                    &evidence.exports,
                ),
            );
            observations
                .entry(table_key(piece, index, table))
                .and_modify(|known| *known |= authorized)
                .or_insert(authorized);
        }
    }
    let unresolved = observations
        .values()
        .filter(|authorized| !**authorized)
        .count();
    let corroborated = observations.values().any(|authorized| *authorized);
    let class = if group.iter().any(|module| module.scan_evidence.is_none()) {
        AdmissionClass::Operator
    } else if unresolved > MAX_TABLES_PER_OBJECT {
        AdmissionClass::ClosureArray
    } else if corroborated {
        AdmissionClass::Corroborated
    } else {
        AdmissionClass::Heuristic
    };
    (class, unresolved)
}

impl AdmissionClass {
    /// The catalog label for this class. `operator` never appears in a
    /// scan-only lowering (no manifests), but the mapping stays total so a
    /// future manifest-aware catalog cannot mislabel it.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Corroborated => "corroborated",
            Self::Heuristic => "heuristic",
            Self::ClosureArray => "closure_array",
        }
    }
}

/// Scan-evidence-only classification of one pinned object's reconciled
/// observations: the same [`lower_scanned`] + [`admission_class`] the merge
/// decides by, so the reported class is the deciding class, never a
/// reimplementation. Pure over its inputs — no attach, no history, no
/// budget — which is what makes it safe for `inspect --system` to call on
/// every catalog object. Returns the class label and the unresolved
/// lookalike count (meaningful for `closure_array`).
pub(crate) fn classify_scanned_object(modules: &[ReconciledModule]) -> (&'static str, usize) {
    let lowered: Vec<Discovered<'_>> = modules.iter().map(lower_scanned).collect();
    let (class, lookalikes) = admission_class(&lowered);
    (class.label(), lookalikes)
}

/// One module's view of the slot budget: the policy's capacity, or less for a
/// shared-scope module that must leave the reserve free. A check that adds
/// nothing always fits, so kept endpoints never fail it.
#[derive(Debug, Clone, Copy)]
struct GroupBudget {
    policy: AdmissionPolicy,
    ceiling: usize,
}

impl GroupBudget {
    fn checked_required(self, current: usize, additions: usize) -> Result<usize, String> {
        let required = self.policy.checked_required(current, additions)?;
        if additions > 0 && required > self.ceiling {
            return Err(format!(
                "attach plan requires {required} slots but only {} are open to this module",
                self.ceiling
            ));
        }
        Ok(required)
    }
}

/// One module's admission, decided before any module is built.
enum AdmissionDecision {
    Admitted {
        admitted: BTreeSet<TableKey>,
        refused_growth: Option<BTreeSet<AttachKey>>,
        kept: BTreeSet<AttachKey>,
        /// Allocated slots once this module was admitted.
        allocated_slots: usize,
    },
    Refused(Skipped),
}

/// Names at most this many slot holders in a capacity refusal.
const REFUSAL_HOLDERS_SHOWN: usize = 3;

/// `N are in use (A active, R retired[; held by …])`: retired slots stay
/// allocated for the capture lifetime and are never reused, so "in use" alone
/// overstated what live modules hold.
fn slot_use(in_use: usize, retired: usize, holders: &[(&str, usize)]) -> String {
    let active = in_use.saturating_sub(retired);
    let mut text = format!("{in_use} are in use ({active} active, {retired} retired");
    if !holders.is_empty() {
        let shown: Vec<String> = holders
            .iter()
            .take(REFUSAL_HOLDERS_SHOWN)
            .map(|(path, count)| format!("{path} {count}"))
            .collect();
        text.push_str("; held by ");
        text.push_str(&shown.join(", "));
        let more = holders.len().saturating_sub(REFUSAL_HOLDERS_SHOWN);
        if more > 0 {
            let noun = if more == 1 { "module" } else { "modules" };
            text.push_str(&format!(", and {more} more {noun}"));
        }
    }
    text.push(')');
    text
}

/// Active endpoints by module path, largest first.
fn slot_holders<'a>(
    holding: &BTreeMap<PinnedObjectId, usize>,
    paths: &BTreeMap<PinnedObjectId, &'a str>,
) -> Vec<(&'a str, usize)> {
    let mut holders: Vec<(&str, usize)> = holding
        .iter()
        .filter(|(_, count)| **count > 0)
        .filter_map(|(object, count)| paths.get(object).map(|path| (*path, *count)))
        .collect();
    holders.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    holders
}

/// A whole-module capacity refusal: the demand, the budget, what holds it,
/// and — in a shared scope — the reserve and how to aim the capture.
struct CapacityRefusal<'a> {
    policy: AdmissionPolicy,
    needed: usize,
    capacity: usize,
    in_use: usize,
    retired: usize,
    holders: Vec<(&'a str, usize)>,
    reserve: Option<usize>,
    closure_tables: Option<usize>,
    aim_hint: bool,
}

impl CapacityRefusal<'_> {
    fn reason(&self) -> String {
        let mut reason = format!(
            "module needs {} more; only {} {} are available; {}",
            self.needed,
            self.capacity,
            self.policy.capacity_subject(),
            slot_use(self.in_use, self.retired, &self.holders)
        );
        if let Some(reserve) = self.reserve {
            reason.push_str(&format!(
                "; {reserve} are reserved for providers with a corroborated function table"
            ));
        }
        reason.push_str(" — refusing to attach a prefix");
        if let Some(tables) = self.closure_tables {
            reason.push_str(&format!(
                " of its {tables} lookalike function tables (a proxy closure array is \
                 admitted whole or not at all)"
            ));
        }
        if self.aim_hint {
            reason.push_str("; to capture one provider, name it with --module <path>");
        }
        reason
    }
}

/// How a plan orders module admission against its one capture-lifetime slot
/// budget. Carried by the plan for the whole capture, like [`AdmissionPolicy`],
/// so every live rebuild admits under the rule the capture started with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdmissionScope {
    /// One named process (`--pid`, `run`), or a capture the operator aimed
    /// with `--module`: modules are admitted first-come in discovery order,
    /// and an unresolved heuristic object admits its strongest
    /// [`MAX_TABLES_PER_OBJECT`] tables (K4).
    #[default]
    Named,
    /// Cgroup or system scope without `--module` (GT-5). Every process in
    /// scope competes for one budget, so first-come admission let long-lived
    /// ambient processes decide what a capture could see: a desktop's
    /// `libp11-kit` took a 410-endpoint prefix of its closure array and the
    /// provider the operator cared about was refused. Admission here is
    /// value-ordered — operator-attested (`--manifest`) modules, then
    /// providers with a corroborated table, then heuristic providers with the
    /// fewest tables, and proxy closure arrays last, each class ordered by
    /// `(dev, inode)` so the admitted set never depends on discovery order.
    /// Every module but an operator-attested one is admitted whole or not at
    /// all, and uncorroborated ones leave [`shared_scope_reserve`] slots free.
    Shared,
}

/// The share of a shared-scope capture's slot budget that uncorroborated
/// modules — heuristic providers and proxy closure arrays — may not take,
/// so a provider whose table is corroborated later in the capture (by a live
/// `C_GetFunctionList` return, an interface or its exports) still fits.
///
/// A quarter, as the GT-5 review proposed. On the 512-slot release build it
/// is 128 slots: one whole PKCS#11 3.2 function list (104 entries) or a 2.40
/// list (68) with room to spare, while the other 384 still hold what a
/// desktop maps ambiently — `p11-kit-trust` (68) plus an NSS-softokn-sized
/// multi-table provider. It never drops below one whole largest standard
/// table (see [`shared_scope_reserve`]), so it keeps its meaning for smaller
/// budgets, and it scales with the wide profile (528 of 2,112).
pub(crate) const SHARED_SCOPE_RESERVE_PERCENT: usize = 25;

/// Entries of the largest standard function list (PKCS#11 3.2).
const LARGEST_STANDARD_TABLE_ENTRIES: usize = 104;

/// Slots a shared-scope plan keeps free of uncorroborated modules.
pub(crate) fn shared_scope_reserve(capacity: usize) -> usize {
    (capacity * SHARED_SCOPE_RESERVE_PERCENT / 100)
        .max(LARGEST_STANDARD_TABLE_ENTRIES)
        .min(capacity)
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
    /// Exact object-relative location of the table's version word, when the
    /// table was decoded from mapped bytes. `None` for manifest tables (the
    /// manifest records entry offsets, not table locations) and for tables
    /// decoded where no file owner could be proven.
    pub file_offset: Option<u64>,
    /// Strongest publication evidence behind this table: "interface" (named by
    /// an interface triple), "live_return" (returned by a live provider
    /// export), "manifest" (operator-authoritative), "exports" (every
    /// standard name the object itself exports sits exactly at its ordinal's
    /// target), or "heuristic" (bare decode with no linkage — its names are
    /// presented as `unknown`). Every non-heuristic linkage names the table;
    /// none of them gives a scan target semantic authority.
    pub linkage: &'static str,
    /// Ordinals whose target is exactly the same-named `.dynsym` definition
    /// in the table's own object. `None` for manifest tables, which are not
    /// compared.
    pub exports_agreeing: Option<usize>,
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

fn acquisition_label(a: &Acquisition) -> String {
    match a {
        Acquisition::Ok => "ok".into(),
        Acquisition::Absent => "absent".into(),
        Acquisition::Empty => "empty".into(),
        Acquisition::Error { detail } => format!("error: {detail}"),
    }
}

/// Unresolved heuristic (scan-decoded, uncorroborated) tables admitted per
/// object, strongest publication evidence first. The scan admits any plausible
/// version word, so one object can decode dozens of lookalike tables (p11-kit
/// decodes 64 closure templates); the cap bounds one object's unresolved
/// slots to `MAX_TABLES_PER_OBJECT * 104 = 416`, inside the 512 slot ceiling,
/// while the spill is reported as `uncorroborated_candidates` instead of
/// refusing the module. Corroborated/published scan tables (interface-linked,
/// manifest/live-return supported) bypass this cap, subject only to the global
/// budget with atomic whole-module refusal. Manifest tables are
/// operator-authoritative and never capped.
///
/// Task 1.6 experiment: broad admission (`P11SCOPE_BROAD_ADMIT=1`) lifts this
/// cap for validated tables — every validated table admits until the global
/// budget, and the first table that does not fit refuses the module whole
/// (the `spent` arm below). Validation is unchanged: only decoder-accepted
/// tables reach `merge`, broad or not.
pub(crate) const MAX_TABLES_PER_OBJECT: usize = 4;

#[derive(Debug, Clone, PartialEq)]
pub struct AttachPlan {
    pub slots: Vec<Slot>,
    pub modules: Vec<ModuleSummary>,
    /// Heuristic tables decoded but not admitted: past the per-object cap or
    /// past the remaining global budget. Evidence, never slots — the module
    /// they were decoded from is still admitted on its strongest tables.
    pub uncorroborated_candidates: u64,
    pub skipped: Vec<Skipped>,
    /// Modules the slot ceiling cut short: refused whole, or — for a module
    /// already attached whose growth did not fit — partially covered, its
    /// endpoints kept and its growth omitted (G-03, [`is_growth_omission`]).
    pub modules_skipped: Vec<Skipped>,
    // Exact private owner for each public capacity refusal. Paths remain
    // diagnostic text and never identify capture-lifetime history.
    refused_module_objects: Vec<(PinnedObjectId, Skipped)>,
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
    // Exact bootstrap targets which have not yet acquired table authority.
    provisional_get_function_list: BTreeMap<AttachKey, PinnedObjectId>,
    // Every table ordinal that reached an exact target this capture. Keyed
    // like `slot_by_key` but never pruned: a retired row keeps its ordinals.
    slot_ordinals: BTreeMap<AttachKey, BTreeSet<SlotOrdinal>>,
    // Identity of every pinned object a slot or module used, recorded where
    // the pins were in hand; capture-lifetime like the slots themselves.
    object_identities: BTreeMap<PinnedObjectId, TargetObject>,
    // Slot indices never leave this set during one capture. Their historical
    // aggregate-map cells remain readable but may not receive new links.
    retired_slots: BTreeSet<usize>,
    // Capture-lifetime ownership for every allocated aggregate cell. Active
    // topology remains in `slot_by_key` and each slot's current `module_ids`.
    aggregate_owners: Vec<AggregateOwner>,
    // Counter staging consumed these original positions, including inactive
    // published rows and never-published rollback holes. Retention only:
    // the counter directory, not this floor, records publication.
    counter_consumed_end: u32,
    admission_policy: AdmissionPolicy,
    admission_scope: AdmissionScope,
    // Plan fence for the conservative rebuild cursor: every `&mut self`
    // method bumps `mutations` first, and `token` is minted fresh per plan
    // value (`Clone` mints, so whole-plan replacement changes the token).
    // Both are transparent to `PartialEq`.
    mutations: MutationCount,
    token: PlanToken,
}

/// Mutation generation of one [`AttachPlan`] value. Bumped first by every
/// `&mut self` method so the conservative cursor's fence notices in-place
/// writes. Transparent to plan equality.
#[derive(Clone, Copy, Debug, Default)]
struct MutationCount(u64);

impl PartialEq for MutationCount {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl MutationCount {
    fn bump(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
}

/// Identity of one [`AttachPlan`] value. Minted from a process-wide counter
/// the way `mint_pin_copy_cache_id` mints pin generations; the counter never
/// wraps, and exhaustion (or contention loss) yields [`PLAN_TOKEN_POISON`],
/// which the fence always refuses. `Clone` mints a fresh token, so no
/// whole-plan replacement can replay an old fence. Transparent to plan
/// equality; prints nothing.
// consumed by T4: read only by the plan fence until the graph polls it.
#[allow(dead_code)]
struct PlanToken(u64);

/// Token value the plan fence always refuses: minted only when the token
/// counter is exhausted.
const PLAN_TOKEN_POISON: u64 = u64::MAX;

static NEXT_PLAN_TOKEN: AtomicU64 = AtomicU64::new(0);

impl PlanToken {
    fn mint() -> Self {
        Self(
            NEXT_PLAN_TOKEN
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                    old.checked_add(1)
                })
                .unwrap_or(PLAN_TOKEN_POISON),
        )
    }
}

impl Clone for PlanToken {
    fn clone(&self) -> Self {
        Self::mint()
    }
}

impl Default for PlanToken {
    fn default() -> Self {
        Self::mint()
    }
}

impl PartialEq for PlanToken {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl std::fmt::Debug for PlanToken {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProvisionalGetFunctionList {
    pub(crate) module: ModuleId,
    pub(crate) object: PinnedObjectId,
    pub(crate) object_path: String,
    pub(crate) file_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectionTableTarget {
    pub(crate) object: PinnedObjectId,
    pub(crate) object_path: String,
    pub(crate) file_offset: u64,
    pub(crate) name: &'static str,
    pub(crate) ordinal: Option<u16>,
    // Foreign targets can acquire this binding only through comparable pins.
    provider: PinnedObjectId,
}

impl SelectionTableTarget {
    pub(crate) fn provider_local(
        object: PinnedObjectId,
        object_path: String,
        file_offset: u64,
        name: &'static str,
    ) -> Self {
        Self {
            object,
            object_path,
            file_offset,
            name,
            ordinal: standard_ordinal(name),
            provider: object,
        }
    }

    pub(crate) fn from_pinned(
        provider: PinnedObjectId,
        object: PinnedObjectId,
        object_path: String,
        file_offset: u64,
        name: &'static str,
        ordinal: u16,
        pinned: &PinnedObjects,
    ) -> Option<Self> {
        matches!((pinned.abi_for(provider), pinned.abi_for(object)),
            (Some(provider), Some(target)) if provider == target)
        .then_some(Self {
            object,
            object_path,
            file_offset,
            name,
            ordinal: Some(ordinal),
            provider,
        })
    }
}

/// The finite link work induced by one complete rebuilt-plan snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct AttachDelta {
    pub new: Vec<Slot>,
    pub replace: Vec<Slot>,
    pub retire: Vec<Slot>,
}

/// Refusal before counter history is consumed; no native authority is implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // The counter staging adapter is a separate slice.
pub(crate) enum CounterHistoryError {
    Policy,
    Extent,
    Frontier,
    Topology,
}

impl AttachPlan {
    /// Object authority for one slot of the sealed plan: the slot must be
    /// current, single-owned, authorized, unambiguous and S1-consistent,
    /// its names must freshly agree, and its frozen cookie must name a
    /// canonical non-NONE object protocol whose function remains among the
    /// slot's names. The frozen cookie is preserved, never reselected.
    #[cfg_attr(not(test), allow(dead_code))] // Slices B/C admit markers from this.
    pub(crate) fn object_slot_eligibility(&self, slot: u32) -> ObjectSlotEligibility {
        let Some(entry) = self.slots.get(slot as usize) else {
            let (_, agreement) = crate::kinds::descriptor_index_with_object_agreement(&[]);
            return ObjectSlotEligibility::Refused {
                reason: SemanticRefusal::IncompleteProvider,
                agreement,
            };
        };
        let (_, agreement) = crate::kinds::descriptor_index_with_object_agreement(&entry.names);
        let refused = |reason| ObjectSlotEligibility::Refused { reason, agreement };
        if entry.index != slot {
            return refused(SemanticRefusal::IncompleteProvider);
        }
        if entry.module_ids.is_empty() {
            return refused(SemanticRefusal::IncompleteProvider);
        }
        if entry.module_ids.len() >= 2 {
            return refused(SemanticRefusal::Descriptor);
        }
        if !entry.semantic_authorized {
            return refused(SemanticRefusal::Unattested);
        }
        if entry.semantic_ambiguous {
            return refused(SemanticRefusal::Descriptor);
        }
        if entry.descriptor_index == 0
            || entry.descriptor_index >= p11scope_ebpf_common::MAX_DESCRIPTORS
        {
            return refused(SemanticRefusal::Descriptor);
        }
        if entry.semantics != crate::kinds::DESCRIPTORS[entry.descriptor_index as usize] {
            return refused(SemanticRefusal::Descriptor);
        }
        if agreement != AliasAgreement::Agree {
            return refused(SemanticRefusal::Descriptor);
        }
        // The frozen cookie is preserved, never reselected: its function
        // must remain among the slot's names with a canonical non-NONE
        // object protocol. Extensions can only narrow, never upgrade.
        let function = entry.descriptor_index - 1;
        if !entry
            .names
            .iter()
            .any(|name| crate::kinds::function_id(name) == Some(function))
        {
            return refused(SemanticRefusal::Descriptor);
        }
        if p11scope_ebpf_common::object_wire::canonical_object_wire(function)
            == p11scope_ebpf_common::object_wire::none_object_wire()
        {
            return refused(SemanticRefusal::Descriptor);
        }
        ObjectSlotEligibility::Eligible {
            descriptor_index: entry.descriptor_index,
        }
    }

    /// Initial subset only: retain descriptor decisions made with every rival
    /// claim still present, then allocate a fresh dense slot space.
    pub(crate) fn attested_subset(
        &self,
        providers: &BTreeSet<PinnedObjectId>,
        degraded: &BTreeSet<AttachKey>,
    ) -> Result<Self, String> {
        if self.counter_consumed_end != 0
            || !self.retired_slots.is_empty()
            || !self.provisional_get_function_list.is_empty()
        {
            return Err("semantic subsets require a fresh initial plan".into());
        }
        let selected: BTreeSet<_> = self
            .modules
            .iter()
            .filter(|module| providers.contains(&module.object))
            .map(|module| module.id)
            .collect();
        let mut slots: Vec<_> = self
            .slots
            .iter()
            .filter(|slot| slot.module_ids.iter().any(|id| selected.contains(id)))
            .cloned()
            .collect();
        let referenced: BTreeSet<_> = slots
            .iter()
            .flat_map(|slot| slot.module_ids.iter().copied())
            .collect();
        let ids: BTreeMap<_, _> = self
            .modules
            .iter()
            .filter(|module| referenced.contains(&module.id))
            .enumerate()
            .map(|(index, module)| (module.id, ModuleId(index as u32)))
            .collect();
        for (index, slot) in slots.iter_mut().enumerate() {
            slot.index = index as u32;
            if degraded.contains(&AttachKey::of(slot)) {
                slot.descriptor_index = 0;
                slot.semantics = SlotSemantics::COUNT_ONLY;
                slot.semantic_authorized = false;
                slot.semantic_ambiguous = true;
            }
            for id in &mut slot.module_ids {
                *id = ids[id];
            }
        }
        let mut subset = Self::from_slots_with_policy(slots, AdmissionPolicy::Detailed)?;
        subset.modules = self
            .modules
            .iter()
            .filter(|module| referenced.contains(&module.id))
            .cloned()
            .map(|mut module| {
                module.id = ids[&module.id];
                module
            })
            .collect();
        subset.slot_ordinals = self
            .slot_ordinals
            .iter()
            .filter(|(key, _)| subset.slot_by_key.contains_key(key))
            .map(|(key, value)| (*key, value.clone()))
            .collect();
        subset.object_identities = self.object_identities.clone();
        subset.validate_slot_index()?;
        Ok(subset)
    }

    pub fn from_slots(slots: Vec<Slot>) -> Self {
        Self::from_indexed_slots(slots, AdmissionPolicy::detailed())
            .expect("slots must have dense indices and unique exact targets")
    }

    pub fn from_slots_with_policy(
        slots: Vec<Slot>,
        admission_policy: AdmissionPolicy,
    ) -> Result<Self, String> {
        admission_policy.validate_count(slots.len())?;
        let plan = Self::from_indexed_slots(slots, admission_policy)?;
        plan.validate_slot_index()?;
        Ok(plan)
    }

    fn from_indexed_slots(
        slots: Vec<Slot>,
        admission_policy: AdmissionPolicy,
    ) -> Result<Self, String> {
        let mut slot_by_key = BTreeMap::new();
        let aggregate_owners: Vec<_> = slots
            .iter()
            .map(|slot| AggregateOwner::from_module_ids(&slot.module_ids))
            .collect();
        for (position, slot) in slots.iter().enumerate() {
            if slot.index as usize != position {
                return Err(format!(
                    "slot index {} does not match its allocated position {position}",
                    slot.index
                ));
            }
            if slot_by_key.insert(AttachKey::of(slot), position).is_some() {
                return Err("one exact target may occupy one slot".into());
            }
        }
        Ok(Self {
            slots,
            modules: vec![],
            uncorroborated_candidates: 0,
            skipped: vec![],
            modules_skipped: vec![],
            refused_module_objects: vec![],
            entries_seen: 0,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            module_ambiguous: aggregate_owners
                .iter()
                .filter(|owner| matches!(owner, AggregateOwner::Ambiguous))
                .count(),
            slot_by_key,
            provisional_get_function_list: BTreeMap::new(),
            retired_slots: BTreeSet::new(),
            aggregate_owners,
            counter_consumed_end: 0,
            admission_policy,
            admission_scope: AdmissionScope::Named,
            slot_ordinals: BTreeMap::new(),
            object_identities: BTreeMap::new(),
            mutations: MutationCount::default(),
            token: PlanToken::default(),
        })
    }

    /// Every table ordinal that reached this slot's exact target, sorted.
    pub(crate) fn ordinals_of(&self, slot: &Slot) -> Vec<SlotOrdinal> {
        self.slot_ordinals
            .get(&AttachKey::of(slot))
            .map(|ordinals| ordinals.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Borrow presentation metadata before reserving its eventual owned copy.
    pub(crate) fn borrowed_ordinals_of(
        &self,
        slot: &Slot,
    ) -> impl Iterator<Item = SlotOrdinal> + '_ {
        self.slot_ordinals
            .get(&AttachKey::of(slot))
            .into_iter()
            .flat_map(|ordinals| ordinals.iter().copied())
    }

    pub(crate) fn ordinal_count(&self, slot: &Slot) -> usize {
        self.slot_ordinals
            .get(&AttachKey::of(slot))
            .map_or(0, BTreeSet::len)
    }

    /// The pinned identity of the object this slot attaches into, when the
    /// plan was built with the pins in hand.
    pub(crate) fn target_object_of(&self, slot: &Slot) -> Option<TargetObject> {
        self.object_identities.get(&slot.object).cloned()
    }

    pub(crate) fn borrowed_target_object_of(&self, slot: &Slot) -> Option<&TargetObject> {
        self.object_identities.get(&slot.object)
    }

    /// The one display label for `slot` ([`presented_label`]).
    pub(crate) fn label_of(&self, slot: &Slot) -> String {
        presented_label(&slot.names, &self.ordinals_of(slot), slot.file_offset)
    }

    /// Records the pinned identity of every object a slot or module of this
    /// plan uses. Called wherever a plan is built from pins, so a later
    /// report can identify a target even after its pin retires.
    fn note_object_identities(&mut self, pinned: &PinnedObjects) {
        self.mutations.bump();
        let objects: BTreeSet<PinnedObjectId> = self
            .slots
            .iter()
            .map(|slot| slot.object)
            .chain(self.modules.iter().map(|module| module.object))
            .collect();
        for id in objects {
            if let Some(summary) = pinned.summary(id) {
                self.object_identities.insert(
                    id,
                    TargetObject {
                        dev: (summary.key.device.major, summary.key.device.minor),
                        ino: summary.key.inode,
                        sha256: (!summary.sha256.is_empty()).then(|| summary.sha256.to_string()),
                    },
                );
            }
        }
    }

    pub const fn admission_policy(&self) -> AdmissionPolicy {
        self.admission_policy
    }

    pub const fn admission_scope(&self) -> AdmissionScope {
        self.admission_scope
    }

    /// Re-admit this plan's exact slots under a counter budget, preserving
    /// slots, activity, modules and evidence. Rebuilds do not preserve the
    /// policy: `rebuild_discovered` always lowers a Detailed plan, so Engine
    /// callers that need Counters must re-admit the retained plan afterwards
    /// (counter starts do this via `restore_counters_policy_after_retain`).
    pub(crate) fn with_counters_policy(
        &self,
        budget: crate::capacity::CounterBudget,
    ) -> Result<Self, String> {
        budget.validate_count(self.slots.len())?;
        let mut next = self.clone();
        next.admission_policy = AdmissionPolicy::Counters(budget);
        Ok(next)
    }

    /// Restore the staged counter prefix on a freshly rebuilt plan, which
    /// always starts unconsumed. The caller passes the committed staged
    /// length (the directory high-water); lengths past the slots refuse.
    pub(crate) fn adopt_counter_consumed(&mut self, consumed: u32) -> Result<(), String> {
        if consumed as usize > self.slots.len() {
            return Err(format!(
                "counter staged prefix {consumed} exceeds {} plan slots",
                self.slots.len()
            ));
        }
        self.counter_consumed_end = consumed;
        Ok(())
    }

    /// Exclusive end of consumed counter history, independent of publication.
    #[cfg_attr(not(test), allow(dead_code))] // The counter staging adapter is a separate slice.
    pub(crate) const fn counter_consumed_end(&self) -> u32 {
        self.counter_consumed_end
    }

    /// Consume the complete fresh tail of this same historical plan exactly
    /// once. The caller must finish charged topology/provider/commit-absence
    /// preflight first and acquire this floor before directory/native mutation.
    /// This allocation-free port grants no map, link or publication authority.
    /// Rollback deactivates failed cells without refunding their positions;
    /// previously published cells likewise survive later inactivity.
    #[cfg_attr(not(test), allow(dead_code))] // The counter staging adapter is a separate slice.
    pub(crate) fn consume_counter_extent(
        &mut self,
        first: u32,
        end: u32,
    ) -> Result<(), CounterHistoryError> {
        self.mutations.bump();
        let AdmissionPolicy::Counters(budget) = self.admission_policy else {
            return Err(CounterHistoryError::Policy);
        };
        if first >= end
            || end as usize != self.slots.len()
            || u64::from(end) > budget.endpoint_limit()
        {
            return Err(CounterHistoryError::Extent);
        }
        if first != self.counter_consumed_end {
            return Err(CounterHistoryError::Frontier);
        }
        if self.slots.iter().enumerate().any(|(position, slot)| {
            slot.index as usize != position
                || (position >= first as usize && !self.is_active(slot.index))
        }) {
            return Err(CounterHistoryError::Topology);
        }
        self.counter_consumed_end = end;
        Ok(())
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
        self.rebuild_from_sources_broad(scanned, manifests, pinned, false)
    }

    /// Task 1.6 experiment: `broad_admit` lifts the per-object heuristic cap
    /// and refuses a module whole unless every validated table fits. Only the
    /// engine's broad pass sets this; every other caller keeps `false`.
    pub fn rebuild_from_sources_broad(
        &self,
        scanned: &[ReconciledModule],
        manifests: &[Manifest],
        pinned: &PinnedObjects,
        broad_admit: bool,
    ) -> AttachPlan {
        let (pinned_id, compatible) = pinned_manifest_lookups(pinned);
        let mut rebuilt = self.rebuild_from_sources_with(
            scanned,
            manifests,
            pinned_id,
            compatible,
            broad_admit,
            self.admission_policy,
        );
        rebuilt.note_object_identities(pinned);
        rebuilt
    }

    fn rebuild_from_sources_with(
        &self,
        scanned: &[ReconciledModule],
        manifests: &[Manifest],
        pinned_id: impl FnMut(ObjectKey, &str) -> Option<PinnedObjectId>,
        compatible: impl FnMut(PinnedObjectId, PinnedObjectId) -> bool,
        broad_admit: bool,
        admission_policy: AdmissionPolicy,
    ) -> AttachPlan {
        let owned = self.active_keys_by_owner();
        let mut rebuilt = build_from_sources_with(
            scanned,
            manifests,
            pinned_id,
            compatible,
            ExistingAllocation {
                slots: self.slots.len(),
                active: &self.slot_by_key,
                owned: &owned,
            },
            broad_admit,
            admission_policy,
            self.admission_scope,
        );
        for (key, object) in &self.provisional_get_function_list {
            if key.object != *object || rebuilt.slot_by_key.contains_key(key) {
                continue;
            }
            let Some(module_id) = rebuilt
                .modules
                .iter()
                .find(|module| module.object == *object)
                .map(|module| module.id)
            else {
                continue;
            };
            let Some(position) = self.slot_by_key.get(key).copied() else {
                continue;
            };
            let Some(slot) = self.slots.get(position) else {
                continue;
            };
            if rebuilt.slots.len() < admission_policy.endpoint_limit() {
                rebuilt
                    .add_provisional_get_function_list(ProvisionalGetFunctionList {
                        module: module_id,
                        object: *object,
                        object_path: slot.object_path.clone(),
                        file_offset: key.file_offset,
                    })
                    .expect("rebuilt provisional provider must remain valid");
            }
        }
        rebuilt
    }

    /// Provider objects attached only through a count-only
    /// `C_GetFunctionList` seed: their function table is not published yet.
    pub(crate) fn provisional_objects(&self) -> impl Iterator<Item = PinnedObjectId> + '_ {
        self.provisional_get_function_list.values().copied()
    }

    pub(crate) fn add_provisional_get_function_list(
        &mut self,
        provisional: ProvisionalGetFunctionList,
    ) -> Result<Option<Slot>, String> {
        self.mutations.bump();
        self.validate_slot_index()?;
        let Some(module) = self
            .modules
            .iter()
            .find(|module| module.id == provisional.module)
        else {
            return Err(format!(
                "provisional C_GetFunctionList names missing module {}",
                provisional.module.0
            ));
        };
        if module.object != provisional.object {
            return Err(format!(
                "provisional C_GetFunctionList module {} names object {:?}, got {:?}",
                provisional.module.0, module.object, provisional.object
            ));
        }
        let key = AttachKey {
            object: provisional.object,
            file_offset: provisional.file_offset,
        };
        if let Some(position) = self.slot_by_key.get(&key).copied()
            && self.is_active(position as u32)
        {
            return Ok(None);
        }
        self.admission_policy
            .checked_required(self.slots.len(), 1)
            .map_err(|error| format!("provisional C_GetFunctionList: {error}"))?;
        let slot = Slot {
            index: self.slots.len() as u32,
            descriptor_index: 0,
            object: provisional.object,
            object_path: provisional.object_path,
            file_offset: provisional.file_offset,
            names: vec!["C_GetFunctionList".into()],
            aliased: false,
            semantics: SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![provisional.module],
        };
        self.slot_by_key.insert(key, slot.index as usize);
        self.provisional_get_function_list
            .insert(key, provisional.object);
        self.slots.push(slot.clone());
        self.aggregate_owners
            .push(AggregateOwner::Sole(provisional.module));
        Ok(Some(slot))
    }

    /// Adds one complete selection-only table to a rebuilt candidate. Capacity
    /// is checked against capture-lifetime allocations before any candidate
    /// mutation, so a table either contributes every physical target or none.
    pub(crate) fn add_selection_table(
        &mut self,
        allocated: &Self,
        module: ModuleId,
        targets: impl IntoIterator<Item = SelectionTableTarget>,
    ) -> Result<(), String> {
        self.mutations.bump();
        self.validate_slot_index()?;
        allocated.validate_slot_index()?;
        if self.admission_policy != allocated.admission_policy {
            return Err("selection table admission policy does not match allocated plan".into());
        }
        let Some(provider) = self.modules.iter().find(|known| known.id == module) else {
            return Err(format!("selection table names missing module {}", module.0));
        };
        let mut grouped: BTreeMap<AttachKey, (String, BTreeSet<&'static str>, BTreeSet<u16>)> =
            BTreeMap::new();
        for target in targets {
            if target.provider != provider.object {
                return Err(format!(
                    "selection table module {} names object {:?}, got {:?}",
                    module.0, provider.object, target.object
                ));
            }
            let (path, names, ordinals) = grouped
                .entry(AttachKey {
                    object: target.object,
                    file_offset: target.file_offset,
                })
                .or_insert_with(|| (target.object_path.clone(), BTreeSet::new(), BTreeSet::new()));
            if target.object_path < *path {
                *path = target.object_path;
            }
            names.insert(target.name);
            ordinals.extend(target.ordinal);
        }

        let candidate_additions = self
            .slot_by_key
            .keys()
            .filter(|key| !allocated.slot_by_key.contains_key(key))
            .count();
        let table_additions = grouped
            .keys()
            .filter(|key| {
                !self.slot_by_key.contains_key(key) && !allocated.slot_by_key.contains_key(key)
            })
            .count();
        let pending = self
            .admission_policy
            .checked_required(allocated.slots.len(), candidate_additions)?;
        if self
            .admission_policy
            .checked_required(pending, table_additions)
            .is_err()
        {
            let capacity = self.admission_policy.endpoint_limit();
            let resource = self.admission_policy.capacity_subject();
            return Err(format!(
                "selection table needs {table_additions} more of the {capacity} {resource}; \
                 {pending} are allocated or pending — refusing to attach a prefix"
            ));
        }

        for (key, (object_path, names, ordinals)) in grouped {
            // Selection tables carry no table location, only positions.
            self.slot_ordinals
                .entry(key)
                .or_default()
                .extend(ordinals.into_iter().map(|ordinal| SlotOrdinal {
                    table_file_offset: None,
                    ordinal,
                }));
            if let Some(position) = self.slot_by_key.get(&key).copied() {
                let slot = &mut self.slots[position];
                slot.names.extend(names.into_iter().map(str::to_string));
                slot.names.sort();
                slot.names.dedup();
                // An available naming witness displaces a prior `unknown`.
                drop_transparent_unknown(&mut slot.names);
                slot.aliased |= slot.names.len() >= 2;
                continue;
            }
            let mut names: Vec<_> = names.into_iter().map(str::to_string).collect();
            drop_transparent_unknown(&mut names);
            let slot = Slot {
                index: self.slots.len() as u32,
                descriptor_index: 0,
                object: key.object,
                object_path,
                file_offset: key.file_offset,
                aliased: names.len() >= 2,
                names,
                semantics: SlotSemantics::COUNT_ONLY,
                semantic_authorized: false,
                semantic_ambiguous: false,
                fork_safe: false,
                module_ids: vec![module],
            };
            self.slot_by_key.insert(key, slot.index as usize);
            self.slots.push(slot);
            self.aggregate_owners.push(AggregateOwner::Sole(module));
        }
        Ok(())
    }

    /// True while this slot still accepts probes. Retired slots remain in
    /// `slots` so their already-collected aggregate-map cells stay stable.
    pub fn is_active(&self, slot: u32) -> bool {
        let position = slot as usize;
        position < self.slots.len() && !self.retired_slots.contains(&position)
    }

    /// How many allocated slots are still active right now (U-14): the plan's
    /// current active set, not a churn count. It reaches 0 for a scan-only
    /// `--pid` capture once its target has exited (every key an unpinned
    /// object loses retires together), and shrinks independently whenever a
    /// live attach or replacement fails or a process generation is lost.
    /// `self.slots.len() - active_slot_count()` therefore mixes several
    /// causes and must not be read as a restart/replacement count.
    pub fn active_slot_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| self.is_active(slot.index))
            .count()
    }

    /// The capture-lifetime aggregate owner, including an inactive slot, or
    /// `None` when no single module can own that cell's counts.
    pub fn module_of_slot(&self, slot: u32) -> Option<ModuleId> {
        match self.aggregate_owners.get(slot as usize) {
            Some(AggregateOwner::Sole(module)) => Some(*module),
            Some(AggregateOwner::Unowned | AggregateOwner::Ambiguous) | None => None,
        }
    }

    /// The sole owner in the current attachment topology. Inactive slots and
    /// currently shared targets have no active owner.
    pub fn active_module_of_slot(&self, slot: u32) -> Option<ModuleId> {
        if !self.is_active(slot) {
            return None;
        }
        self.slots
            .get(slot as usize)
            .filter(|slot| slot.module_ids.len() == 1)
            .map(|slot| slot.module_ids[0])
    }

    pub(crate) fn slot_is_module_ambiguous(&self, slot: u32) -> bool {
        matches!(
            self.aggregate_owners.get(slot as usize),
            Some(AggregateOwner::Ambiguous)
        )
    }

    pub(crate) fn refused_modules(&self) -> impl Iterator<Item = (PinnedObjectId, &Skipped)> {
        self.refused_module_objects
            .iter()
            .map(|(object, skipped)| (*object, skipped))
    }

    /// Every active exact target, under the object of each module that
    /// currently owns it. A module found here is already admitted: when its
    /// growth does not fit, it keeps these endpoints (G-03).
    fn active_keys_by_owner(&self) -> BTreeMap<PinnedObjectId, BTreeSet<AttachKey>> {
        let objects: BTreeMap<ModuleId, PinnedObjectId> = self
            .modules
            .iter()
            .map(|module| (module.id, module.object))
            .collect();
        let mut owned: BTreeMap<PinnedObjectId, BTreeSet<AttachKey>> = BTreeMap::new();
        for (key, position) in &self.slot_by_key {
            let Some(slot) = self.slots.get(*position) else {
                continue;
            };
            for module in &slot.module_ids {
                if let Some(object) = objects.get(module) {
                    owned.entry(*object).or_default().insert(*key);
                }
            }
        }
        owned
    }

    pub(crate) fn effective_semantics(&self, slot: &Slot) -> SlotSemantics {
        if self.slot_is_module_ambiguous(slot.index) {
            SlotSemantics::COUNT_ONLY
        } else {
            slot.semantics
        }
    }

    /// Renames this snapshot's providers, aggregate cells included. Slot
    /// ownership and the aggregate-cell owners name the same modules, so they
    /// are renamed together: leaving the cells on the pre-rename IDs makes the
    /// next [`Self::extend_exact_with_stable_module_ids`] read one provider
    /// under two IDs as two rivals and latch a false `module_ambiguous` on
    /// every one of its cells.
    pub(crate) fn rebind_module_ids(
        &mut self,
        slots: Vec<Slot>,
        remap: &BTreeMap<ModuleId, ModuleId>,
    ) {
        self.mutations.bump();
        for owner in &mut self.aggregate_owners {
            if let AggregateOwner::Sole(id) = owner
                && let Some(stable) = remap.get(id)
            {
                *owner = AggregateOwner::Sole(*stable);
            }
        }
        self.slots = slots;
    }

    /// Retains only the aggregate-cell provenance a fully reconciled candidate
    /// proved about already-active exact targets. Candidate identities and
    /// topology remain local until their transaction commits.
    pub(crate) fn latch_ambiguity_from(&mut self, candidate: &Self) -> bool {
        self.mutations.bump();
        let mut changed = false;
        for (key, candidate_position) in &candidate.slot_by_key {
            if candidate.aggregate_owners.get(*candidate_position)
                != Some(&AggregateOwner::Ambiguous)
            {
                continue;
            }
            if let Some(current_position) = self.slot_by_key.get(key) {
                let owner = &mut self.aggregate_owners[*current_position];
                changed |= *owner != AggregateOwner::Ambiguous;
                *owner = AggregateOwner::Ambiguous;
            }
        }
        self.module_ambiguous = self
            .aggregate_owners
            .iter()
            .filter(|owner| matches!(owner, AggregateOwner::Ambiguous))
            .count();
        changed
    }

    /// Applies a complete fresh planner snapshot without changing already
    /// allocated slot IDs. Only a semantic downgrade to descriptor zero may
    /// replace an existing exact target; descriptors are frozen before any
    /// attachment and can never be upgraded or otherwise mutated live.
    pub fn extend_exact(&mut self, mut rebuilt: AttachPlan) -> Result<AttachDelta, String> {
        self.mutations.bump();
        self.validate_slot_index()?;
        rebuilt.validate_slot_index()?;
        self.validate_matching_policy(&rebuilt)?;
        self.remap_modules(&mut rebuilt)?;
        self.extend_exact_prepared(rebuilt)
    }

    /// Applies an Engine-bound snapshot whose stable module IDs were already
    /// resolved from exact capture-lifetime identity.
    pub(crate) fn extend_exact_with_stable_module_ids(
        &mut self,
        rebuilt: AttachPlan,
    ) -> Result<AttachDelta, String> {
        self.mutations.bump();
        self.validate_slot_index()?;
        rebuilt.validate_slot_index()?;
        self.validate_matching_policy(&rebuilt)?;
        Self::validate_stable_module_ids(&rebuilt)?;
        self.extend_exact_prepared(rebuilt)
    }

    fn extend_exact_prepared(&mut self, rebuilt: AttachPlan) -> Result<AttachDelta, String> {
        self.mutations.bump();
        self.validate_slot_index()?;
        rebuilt.validate_slot_index()?;
        self.validate_extension_capacity(&rebuilt)?;

        let mut slots = self.slots.clone();
        let mut slot_by_key = self.slot_by_key.clone();
        let mut retired_slots = self.retired_slots.clone();
        let mut aggregate_owners = self.aggregate_owners.clone();
        for (owner, slot) in aggregate_owners.iter_mut().zip(&self.slots) {
            *owner = owner.merge(AggregateOwner::from_module_ids(&slot.module_ids));
        }
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
                let previous_owner = aggregate_owners[position];
                let candidate_owner = if rebuilt.slot_is_module_ambiguous(slot.index) {
                    AggregateOwner::Ambiguous
                } else {
                    AggregateOwner::from_module_ids(&updated.module_ids)
                };
                aggregate_owners[position] = previous_owner.merge(candidate_owner);
                if previous_owner != AggregateOwner::Ambiguous
                    && aggregate_owners[position] == AggregateOwner::Ambiguous
                    && updated.descriptor_index != 0
                {
                    updated.descriptor_index = 0;
                    updated.semantics = SlotSemantics::COUNT_ONLY;
                    updated.semantic_ambiguous = true;
                }
                if aggregate_owners[position] == AggregateOwner::Ambiguous {
                    updated.names.extend(old.names);
                    updated.names.sort();
                    updated.names.dedup();
                    drop_transparent_unknown(&mut updated.names);
                    updated.aliased |= old.aliased || updated.names.len() >= 2;
                    if old.descriptor_index == 0 || updated.descriptor_index == 0 {
                        updated.semantic_ambiguous = true;
                    }
                } else if updated.names == [UNKNOWN_FUNCTION_NAME] {
                    // A rebuild that learned nothing new about names must not
                    // clobber the last authorized name (an export-derived
                    // provisional seed, an earlier linkage) with `unknown`.
                    updated.names.clone_from(&old.names);
                    updated.aliased = old.aliased;
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
                let owner = if rebuilt.slot_is_module_ambiguous(slot.index) {
                    AggregateOwner::Ambiguous
                } else {
                    AggregateOwner::from_module_ids(&added.module_ids)
                };
                slot_by_key.insert(key, slots.len());
                delta.new.push(added.clone());
                slots.push(added);
                aggregate_owners.push(owner);
            }
        }

        self.slots = slots;
        // Capture-lifetime disclosure: ordinals and identities only grow.
        for (key, ordinals) in rebuilt.slot_ordinals {
            self.slot_ordinals.entry(key).or_default().extend(ordinals);
        }
        self.object_identities.extend(rebuilt.object_identities);
        self.modules = rebuilt.modules;
        // The spill count is current-state evidence like `entries_seen`,
        // not a high-water mark (capture history keeps those separately):
        // a live merge that bypasses a spilled table resolves the spill.
        self.uncorroborated_candidates = rebuilt.uncorroborated_candidates;
        self.skipped = rebuilt.skipped;
        self.modules_skipped = rebuilt.modules_skipped;
        self.refused_module_objects = rebuilt.refused_module_objects;
        self.entries_seen = rebuilt.entries_seen;
        self.surfaces = rebuilt.surfaces;
        self.vendor_interfaces = rebuilt.vendor_interfaces;
        self.interface_list = rebuilt.interface_list;
        self.slot_by_key = slot_by_key;
        self.provisional_get_function_list = rebuilt.provisional_get_function_list;
        self.retired_slots = retired_slots;
        self.aggregate_owners = aggregate_owners;
        self.module_ambiguous = self
            .aggregate_owners
            .iter()
            .filter(|owner| matches!(owner, AggregateOwner::Ambiguous))
            .count();
        Ok(delta)
    }

    fn validate_stable_module_ids(rebuilt: &AttachPlan) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        let mut objects = BTreeSet::new();
        for module in &rebuilt.modules {
            if !ids.insert(module.id) {
                return Err(format!("duplicate rebuilt module id {}", module.id.0));
            }
            if !objects.insert(module.object) {
                return Err(format!("duplicate module object {:?}", module.object));
            }
        }
        for slot in &rebuilt.slots {
            for module in &slot.module_ids {
                if !ids.contains(module) {
                    return Err(format!(
                        "slot {} references missing rebuilt module {}",
                        slot.index, module.0
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_extension_capacity(&self, rebuilt: &AttachPlan) -> Result<(), String> {
        let additions = rebuilt
            .slots
            .iter()
            .filter(|slot| !self.slot_by_key.contains_key(&AttachKey::of(slot)))
            .count();
        self.admission_policy
            .checked_required(self.slots.len(), additions)
            .map(|_| ())
            .map_err(|error| format!("{error}; refusing to attach a prefix"))
    }

    fn validate_matching_policy(&self, rebuilt: &AttachPlan) -> Result<(), String> {
        if self.admission_policy != rebuilt.admission_policy {
            return Err("rebuilt attach plan admission policy changed during capture".into());
        }
        Ok(())
    }

    /// The one infallible cleanup for a candidate that lost a process
    /// generation after its links were already mutated. Every endpoint whose
    /// exact pinned identity left with that generation stops accepting probes,
    /// and its module and capacity refusal go with it. Allocated slot IDs are
    /// never given back. A cell this candidate allocated itself — index at or
    /// past `accepted_slots` — was never accepted by anybody, so it may not
    /// keep a sole provider owner; an already-accepted owner and latched
    /// ambiguity both stay. Returns the endpoints the caller must detach.
    pub(crate) fn retire_unpinned_targets(
        &mut self,
        pinned: &PinnedObjects,
        accepted_slots: usize,
    ) -> Vec<Slot> {
        self.mutations.bump();
        self.modules
            .retain(|module| pinned.summary(module.object).is_some());
        self.refused_module_objects
            .retain(|(object, _)| pinned.summary(*object).is_some());
        let retired: Vec<Slot> = self
            .slots
            .iter()
            .filter(|slot| self.is_active(slot.index) && pinned.summary(slot.object).is_none())
            .cloned()
            .collect();
        for slot in &retired {
            self.deactivate(slot.index);
            let position = slot.index as usize;
            if position >= accepted_slots
                && matches!(self.aggregate_owners[position], AggregateOwner::Sole(_))
            {
                self.aggregate_owners[position] = AggregateOwner::Unowned;
            }
        }
        retired
    }

    /// A failed replacement must not revive the old descriptor or reuse its
    /// cookie. It remains a visible, inactive aggregate slot with finite
    /// attachment evidence owned by the caller.
    pub(crate) fn deactivate(&mut self, slot: u32) {
        self.mutations.bump();
        let position = slot as usize;
        if position >= self.slots.len() {
            return;
        }
        let key = AttachKey::of(&self.slots[position]);
        self.provisional_get_function_list.remove(&key);
        if !self.is_active(slot) {
            return;
        }
        self.retired_slots.insert(position);
        self.slot_by_key.remove(&key);
        self.module_ambiguous = self
            .aggregate_owners
            .iter()
            .filter(|owner| matches!(owner, AggregateOwner::Ambiguous))
            .count();
    }

    /// Gives back the cells at `accepted..` — every cell this candidate
    /// allocated past the accepted plan — when none of them was ever linked
    /// (PC-1). "Allocated slot IDs are never given back" protects a cell that
    /// a link may have counted into; a candidate whose attach never ran has
    /// no such cell, and keeping them burned the lifetime budget whenever the
    /// same listed-but-inactive endpoints were planned again with additions
    /// closed. Only a wholly inactive tail is withdrawn: an active cell means
    /// a link exists, and then nothing is given back. Counter staging also
    /// consumes positions before links/publication: its history is retained
    /// even when clean rollback left those cells inactive and never published.
    pub(crate) fn withdraw_unlinked_additions(&mut self, accepted: usize) {
        self.mutations.bump();
        let accepted = accepted.max(self.counter_consumed_end as usize);
        if self.slots.len() <= accepted
            || (accepted..self.slots.len()).any(|position| self.is_active(position as u32))
        {
            return;
        }
        self.slots.truncate(accepted);
        self.aggregate_owners.truncate(accepted);
        self.retired_slots.retain(|position| *position < accepted);
        self.slot_by_key.retain(|_, position| *position < accepted);
        let slot_by_key = &self.slot_by_key;
        self.provisional_get_function_list
            .retain(|key, _| slot_by_key.contains_key(key));
        self.module_ambiguous = self
            .aggregate_owners
            .iter()
            .filter(|owner| matches!(owner, AggregateOwner::Ambiguous))
            .count();
    }

    /// Excises never-linked tail cells this candidate allocated past
    /// `accepted` — the partial-withhold companion to
    /// [`withdraw_unlinked_additions`](Self::withdraw_unlinked_additions),
    /// which only takes back a wholly inactive tail. A withheld retry's
    /// cell was allocated by this candidate and deactivated before any
    /// link, so giving it back cannot strand a count; keeping it would
    /// burn the capture-lifetime budget on every deferral tick. Only
    /// cells at `accepted..` that are inactive are removed — active cells
    /// and cells below `accepted` or the consumed counter floor are never
    /// touched. Surviving unconsumed tail cells
    /// shift down with their indices, owners, and key/retirement
    /// positions remapped. Returns the old-index → new-index map
    /// (`u32::MAX` for excised cells) so the caller can remap detached
    /// slot clones (delta entries).
    pub(crate) fn excise_unlinked_tail_cells(
        &mut self,
        accepted: usize,
        cells: &BTreeSet<u32>,
    ) -> Vec<u32> {
        self.mutations.bump();
        let accepted = accepted.max(self.counter_consumed_end as usize);
        let old_len = self.slots.len();
        debug_assert_eq!(self.aggregate_owners.len(), old_len);
        let remove: BTreeSet<usize> = cells
            .iter()
            .map(|cell| *cell as usize)
            .filter(|position| {
                *position >= accepted && *position < old_len && !self.is_active(*position as u32)
            })
            .collect();
        let mut old_to_new = vec![u32::MAX; old_len];
        if remove.is_empty() {
            for (position, new) in old_to_new.iter_mut().enumerate() {
                *new = position as u32;
            }
            return old_to_new;
        }
        let mut slots = Vec::with_capacity(old_len - remove.len());
        for (position, mut slot) in self.slots.drain(..).enumerate() {
            if remove.contains(&position) {
                continue;
            }
            slot.index = slots.len() as u32;
            old_to_new[position] = slot.index;
            slots.push(slot);
        }
        let mut owners = Vec::with_capacity(old_len - remove.len());
        for (position, owner) in self.aggregate_owners.drain(..).enumerate() {
            if !remove.contains(&position) {
                owners.push(owner);
            }
        }
        debug_assert_eq!(slots.len(), owners.len());
        self.slots = slots;
        self.aggregate_owners = owners;
        self.retired_slots = self
            .retired_slots
            .iter()
            .filter_map(|position| {
                let new = old_to_new.get(*position).copied().unwrap_or(u32::MAX);
                (new != u32::MAX).then_some(new as usize)
            })
            .collect();
        for position in self.slot_by_key.values_mut() {
            let new = old_to_new.get(*position).copied().unwrap_or(u32::MAX);
            debug_assert!(
                new != u32::MAX,
                "an excised cell must already have left the key index"
            );
            if new != u32::MAX {
                *position = new as usize;
            }
        }
        self.slot_by_key
            .retain(|_, position| *position < self.slots.len());
        let slot_by_key = &self.slot_by_key;
        self.provisional_get_function_list
            .retain(|key, _| slot_by_key.contains_key(key));
        self.module_ambiguous = self
            .aggregate_owners
            .iter()
            .filter(|owner| matches!(owner, AggregateOwner::Ambiguous))
            .count();
        old_to_new
    }

    pub(crate) fn validate_slot_index(&self) -> Result<(), String> {
        if self.counter_consumed_end as usize > self.slots.len() {
            return Err("consumed counter history extends past allocated slots".into());
        }
        if self.counter_consumed_end != 0
            && !matches!(self.admission_policy, AdmissionPolicy::Counters(_))
        {
            return Err("consumed counter history requires counter admission policy".into());
        }
        if self.aggregate_owners.len() != self.slots.len() {
            return Err("aggregate-owner state does not match allocated slots".into());
        }
        self.admission_policy.validate_count(self.slots.len())?;
        let mut active_keys = BTreeSet::new();
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
            if self.admission_policy.forces_count_only()
                && (slot.descriptor_index != 0
                    || slot.semantics != SlotSemantics::COUNT_ONLY
                    || slot.semantic_authorized)
            {
                return Err(format!(
                    "{} slot {} is not count-only",
                    self.admission_policy.count_only_subject(),
                    slot.index
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
            let indexed = self.slot_by_key.get(&key).copied();
            if self.retired_slots.contains(&position) {
                if indexed == Some(position) {
                    return Err(format!(
                        "retired slot {} remains attach-indexed",
                        slot.index
                    ));
                }
            } else {
                if !active_keys.insert(key) {
                    return Err(format!("duplicate exact target at slot {}", slot.index));
                }
                if indexed != Some(position) {
                    return Err(format!(
                        "slot {} is missing from the exact attach index",
                        slot.index
                    ));
                }
            }
        }
        for (key, position) in &self.slot_by_key {
            if *position >= self.slots.len() {
                return Err("exact attach index points outside the slot vector".into());
            }
            if self.retired_slots.contains(position) {
                return Err("exact attach index points to a retired slot".into());
            }
            if AttachKey::of(&self.slots[*position]) != *key {
                return Err("exact attach index key does not match its slot".into());
            }
        }
        for (key, object) in &self.provisional_get_function_list {
            let Some(position) = self.slot_by_key.get(key).copied() else {
                return Err("provisional exact key is missing from attach index".into());
            };
            if self.retired_slots.contains(&position) || !self.is_active(position as u32) {
                return Err("provisional exact key points to a retired slot".into());
            }
            let slot = &self.slots[position];
            if AttachKey::of(slot) != *key {
                return Err("provisional exact key does not match its slot".into());
            }
            if slot.descriptor_index != 0
                || slot.semantics != SlotSemantics::COUNT_ONLY
                || slot.names != ["C_GetFunctionList"]
                || slot.semantic_authorized
                || slot.aliased
                || slot.fork_safe
                || slot.module_ids.len() != 1
            {
                return Err("provisional exact key names a non-provisional slot".into());
            }
            let module_id = slot.module_ids[0];
            let aggregate_ambiguous = match self.aggregate_owners.get(position) {
                Some(AggregateOwner::Sole(owner)) if *owner == module_id => false,
                Some(AggregateOwner::Ambiguous) => true,
                _ => return Err("provisional exact key has no valid aggregate owner".into()),
            };
            if slot.semantic_ambiguous && !aggregate_ambiguous {
                return Err("provisional sole-owner slot is semantically ambiguous".into());
            }
            let mut modules = self.modules.iter().filter(|module| module.id == module_id);
            let Some(module) = modules.next() else {
                return Err("provisional exact key names a missing module".into());
            };
            if modules.next().is_some() {
                return Err("provisional exact key names multiple modules".into());
            }
            if module.object != *object || slot.object != *object {
                return Err("provisional exact key provider object does not match".into());
            }
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
    plan.admission_policy
        .validate_count(required)
        .map_err(|_| {
            let available = plan.admission_policy.endpoint_limit();
            format!(
                "attach plan requires {required} slots but only {available} are available; refusing to attach a prefix"
            )
        })
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
    /// The ordinal/operator label as decoded. Occurrence counting keys on this
    /// verbatim label, so the mislabel guard must NOT rewrite it here — the
    /// presented name is decided at slot building from `name_authorized`.
    name: &'a str,
    object: PinnedObjectId,
    object_path: &'a str,
    file_offset: u64,
    fork_safe: bool,
    semantic_authorized: bool,
    /// Whether `name` may be presented as a PKCS#11 name: manifest targets are
    /// operator-authoritative, scan targets need linkage-or-manifest
    /// authorization for their table.
    name_authorized: bool,
    /// Index into the scan piece's `tables` this target was decoded from.
    /// `None` for manifest targets, which are authoritative and never capped.
    table: Option<usize>,
    /// The standard-list position this target was published at, with its
    /// table's location (`SlotOrdinal`); `None` for a non-standard label.
    ordinal: Option<SlotOrdinal>,
    /// Other standard names the target's object exports at this exact
    /// target, presented beside `name` when an export-corroborated table
    /// published it: an application reaches the target through any of them
    /// with `dlsym`, so the counts belong to the group.
    aliases: Vec<&'a str>,
}

/// Borrowed scan decode behind one scan piece, for evidence-ordered table
/// admission in `merge`. Manifest pieces carry `None`: their tables are
/// operator-authoritative, admitted whole or refused whole as before — except
/// that a module whose sources still list targets the capture attached for it
/// keeps those targets when what it needs next does not fit (G-03). An
/// attached module whose sources list none of them is refused whole, like a
/// new one.
struct ScanEvidence<'a> {
    tables: &'a [ScannedTable],
    interfaces: &'a [ScannedInterface],
    exports: ObjectExports<'a>,
}

/// Identity of one heuristic table for cross-view dedup: one object seen
/// from several processes decodes the same tables repeatedly, and the
/// per-object cap counts distinct tables, not decode instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TableKey {
    /// Version-word file offset plus decoded version: the same table however
    /// many views decoded it.
    Located { file_offset: u64, version: (u8, u8) },
    /// No file offset, so sameness is unprovable (runtime addresses are
    /// generation-local): each instance admits alone.
    Unlocated { piece: usize, table: usize },
}

fn table_key(piece: usize, index: usize, table: &ScannedTable) -> TableKey {
    match table.file_offset {
        Some(file_offset) => TableKey::Located {
            file_offset,
            version: table.version,
        },
        None => TableKey::Unlocated {
            piece,
            table: index,
        },
    }
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
    scan_evidence: Option<ScanEvidence<'a>>,
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

/// Occurrence-deduped decoded counts for one merge group: a manifest
/// corroborating a scanned entry names the same occurrence and is counted
/// once. Generic over borrowed (`&str`, for [`decoded_occurrence_count`]) and
/// owned (`String`, for the conservative cursor's strided recount) names.
#[derive(Debug, Default)]
struct OccurrenceCounter<N, S> {
    targets: BTreeSet<(N, PinnedObjectId, u64, usize)>,
    skips: BTreeSet<(&'static str, S, S, usize)>,
}

impl<N: Ord + Clone, S: Ord + Clone> OccurrenceCounter<N, S> {
    fn feed_target(
        &mut self,
        within: &mut BTreeMap<(N, PinnedObjectId, u64), usize>,
        name: N,
        object: PinnedObjectId,
        file_offset: u64,
    ) {
        let occurrence = within
            .entry((name.clone(), object, file_offset))
            .or_insert(0usize);
        self.targets
            .insert((name, object, file_offset, *occurrence));
        *occurrence += 1;
    }

    fn feed_skip(
        &mut self,
        within: &mut BTreeMap<(S, S), usize>,
        source: &'static str,
        subject: S,
        reason: S,
    ) {
        let occurrence = within
            .entry((subject.clone(), reason.clone()))
            .or_insert(0usize);
        self.skips.insert((source, subject, reason, *occurrence));
        *occurrence += 1;
    }

    fn count(&self) -> usize {
        self.targets.len() + self.skips.len()
    }

    // consumed by T4: the cursor clears the counter per group; merge never does.
    #[allow(dead_code)]
    fn clear(&mut self) {
        self.targets.clear();
        self.skips.clear();
    }
}

fn decoded_occurrence_count(group: &[Discovered<'_>]) -> usize {
    let mut counter: OccurrenceCounter<&str, &str> = OccurrenceCounter::default();
    for module in group {
        debug_assert_eq!(
            module.entries_seen,
            module.targets.len() + module.skipped.len()
        );
        let mut target_occurrences = BTreeMap::new();
        for target in &module.targets {
            counter.feed_target(
                &mut target_occurrences,
                target.name,
                target.object,
                target.file_offset,
            );
        }
        let mut skip_occurrences = BTreeMap::new();
        for skip in &module.skipped {
            counter.feed_skip(
                &mut skip_occurrences,
                module.source,
                skip.subject.as_str(),
                skip.reason.as_str(),
            );
        }
    }
    counter.count()
}

fn merge(
    discovered: Vec<Discovered<'_>>,
    vendor_interfaces: usize,
    interface_list: String,
    allocated: ExistingAllocation<'_>,
    broad_admit: bool,
    admission_policy: AdmissionPolicy,
    admission_scope: AdmissionScope,
) -> AttachPlan {
    let capacity = admission_policy.endpoint_limit();
    let existing_slots = allocated.active;
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

    // Admission is decided first — in value order for a shared scope — and
    // modules are built afterwards in discovery order, so module IDs, slot
    // order and record order stay what discovery saw whichever order decided
    // admission. A named scope decides in discovery order: first-come.
    let shared = admission_scope == AdmissionScope::Shared;
    let classes: Vec<(AdmissionClass, usize)> =
        groups.iter().map(|group| admission_class(group)).collect();
    let mut order: Vec<usize> = (0..groups.len()).collect();
    if shared {
        order.sort_by_key(|&position| (classes[position], groups[position][0].key, position));
    }
    let reserve = shared_scope_reserve(capacity);
    // Retired slots stay allocated for the capture lifetime and are never
    // reused; refusals say so apart from the active endpoints.
    let retired = allocated.slots.saturating_sub(existing_slots.len());
    let paths: BTreeMap<PinnedObjectId, &str> = groups
        .iter()
        .map(|group| (group[0].object, group[0].path))
        .collect();
    // Active endpoints by provider object, for refusal messages: what the
    // current plan holds, updated as each module of this merge is decided.
    let mut holding: BTreeMap<PinnedObjectId, usize> = allocated
        .owned
        .iter()
        .map(|(object, keys)| (*object, keys.len()))
        .collect();
    // Exact targets an earlier-decided module of this merge admitted fresh.
    let mut claimed: BTreeSet<AttachKey> = BTreeSet::new();
    let mut decisions: Vec<Option<AdmissionDecision>> = (0..groups.len()).map(|_| None).collect();
    let mut uncorroborated_candidates = 0u64;
    let mut allocated_slots = allocated.slots;
    for position in order {
        let group = &groups[position];
        let object = group[0].object;
        let path = group[0].path;
        let (class, table_count) = classes[position];
        // Shared scope: every module but an operator-attested one is admitted
        // whole or not at all, and uncorroborated ones leave the reserve free.
        let whole = broad_admit
            || admission_policy.admits_complete_validated_union()
            || (shared && class != AdmissionClass::Operator);
        let reserved = shared && class.leaves_reserve();
        let budget = GroupBudget {
            policy: admission_policy,
            ceiling: if reserved {
                capacity.saturating_sub(reserve)
            } else {
                capacity
            },
        };
        // G-03: the exact targets this module already has attached — active
        // in the current plan with this module among their owners — that its
        // sources still list. Empty for a module new to the capture.
        let kept: BTreeSet<AttachKey> = allocated
            .owned
            .get(&object)
            .map(|owned| {
                group
                    .iter()
                    .flat_map(|module| &module.targets)
                    .map(|target| AttachKey {
                        object: target.object,
                        file_offset: target.file_offset,
                    })
                    .filter(|key| owned.contains(key))
                    .collect()
            })
            .unwrap_or_default();
        // The demand a capacity check refused this module while it has
        // endpoints to keep. Admission then runs once more over `kept` alone:
        // the module keeps every endpoint it has, no prefix of its growth is
        // attached, and the growth is reported as omitted below. A module
        // with nothing to keep is refused whole, as before.
        let mut refused_growth: Option<BTreeSet<AttachKey>> = None;
        // The refused table — the strongest one, or a non-leading one that
        // holds kept endpoints: its endpoints are all in the omission
        // record, never also counted as spill.
        let mut refused_top: Option<TableKey> = None;
        // Spill accounting is per admission pass: the kept-only retry
        // recounts this module's spill from scratch, so the first pass's
        // counts are discarded before retrying. Otherwise every table the
        // first pass spilled before the refusal would be counted again on
        // the retry — a double spill alongside the omission.
        let spill_baseline = uncorroborated_candidates;
        let outcome = 'admission: loop {
            let kept_only = refused_growth.is_some();
            let admissible = |key: &AttachKey| !kept_only || kept.contains(key);
            let refused: BTreeSet<AttachKey> = 'refused: {
                // Manifest targets are operator-authoritative: admitted whole, and the
                // module is refused whole when even they exceed the remaining budget
                // (a module with endpoints to keep keeps them instead, above).
                let manifest_wanted: BTreeSet<AttachKey> = group
                    .iter()
                    .filter(|module| module.scan_evidence.is_none())
                    .flat_map(|module| &module.targets)
                    .map(|target| AttachKey {
                        object: target.object,
                        file_offset: target.file_offset,
                    })
                    .filter(|target| {
                        admissible(target)
                            && !claimed.contains(target)
                            && !existing_slots.contains_key(target)
                    })
                    .collect();
                if budget
                    .checked_required(allocated_slots, manifest_wanted.len())
                    .is_err()
                {
                    break 'refused manifest_wanted;
                }
                // Scan tables admit in publication-evidence order. Corroborated tables
                // (interface-linked, manifest/live-return supported) bypass the
                // per-object cap, subject only to the global budget with atomic
                // whole-module refusal; unresolved heuristic tables admit until the
                // per-object cap, and their spill is counted, never slotted. Linkage
                // is preferred, never gated: unlinked tables still admit in turn, so
                // scan-only capture of never-called legacy providers keeps working.
                // One object seen from several views decodes the same tables
                // repeatedly: distinct tables admit once, scored by the strongest
                // instance. Publication is retained independently: a weaker
                // opaque observation must survive a stronger unobserved view.
                let mut distinct: BTreeMap<TableKey, (TableEvidenceScore, usize, bool)> =
                    BTreeMap::new();
                let mut sequence = 0usize;
                for (piece, module) in group.iter().enumerate() {
                    let Some(evidence) = &module.scan_evidence else {
                        continue;
                    };
                    for index in order_tables_by_evidence(
                        evidence.tables,
                        evidence.interfaces,
                        &[],
                        &[],
                        &evidence.exports,
                    ) {
                        let score = table_evidence_score(
                            index,
                            evidence.tables,
                            evidence.interfaces,
                            &[],
                            &[],
                            &evidence.exports,
                        );
                        let key = table_key(piece, index, &evidence.tables[index]);
                        let observed =
                            table_observation_authorized(&evidence.tables[index], &score);
                        distinct
                            .entry(key)
                            .and_modify(|slot| {
                                slot.0 = slot.0.max(score);
                                slot.2 |= observed;
                            })
                            .or_insert_with(|| {
                                let slot = (score, sequence, observed);
                                sequence += 1;
                                slot
                            });
                    }
                }
                let mut ordered: Vec<(TableKey, TableEvidenceScore, usize, bool)> = distinct
                    .into_iter()
                    .map(|(key, (score, sequence, observed))| (key, score, sequence, observed))
                    .collect();
                // Actual observations precede heuristics even when their API
                // names are uncertain. Remaining ties retain evidence order.
                ordered.sort_by(|left, right| {
                    right
                        .3
                        .cmp(&left.3)
                        .then_with(|| right.1.cmp(&left.1))
                        .then_with(|| left.2.cmp(&right.2))
                });
                // Every scan target of this group, by distinct table, for marginal
                // budget accounting across views of one object.
                let mut keys_of: BTreeMap<TableKey, BTreeSet<AttachKey>> = BTreeMap::new();
                for (piece, module) in group.iter().enumerate() {
                    let Some(evidence) = &module.scan_evidence else {
                        continue;
                    };
                    for target in &module.targets {
                        let Some(index) = target.table else { continue };
                        let Some(table) = evidence.tables.get(index) else {
                            continue;
                        };
                        let key = AttachKey {
                            object: target.object,
                            file_offset: target.file_offset,
                        };
                        if admissible(&key) {
                            keys_of
                                .entry(table_key(piece, index, table))
                                .or_default()
                                .insert(key);
                        }
                    }
                }
                let is_fresh =
                    |key: &AttachKey| !claimed.contains(key) && !existing_slots.contains_key(key);
                // A table the module already has attached must never spill:
                // its kept endpoints would vanish from the snapshot and
                // retire. Its fresh demand, when it holds any kept endpoint,
                // routes to the refused-growth retry instead (G-03).
                let kept_demand = |key: &TableKey| -> Option<BTreeSet<AttachKey>> {
                    let keys = keys_of.get(key)?;
                    keys.iter()
                        .any(|candidate| kept.contains(candidate))
                        .then(|| {
                            keys.iter()
                                .filter(|candidate| is_fresh(candidate))
                                .copied()
                                .collect()
                        })
                };
                // All-or-nothing refusal survives only here: when even the strongest
                // table exceeds the remaining global budget, the module — scan and
                // manifest parts alike — is refused whole (or, with endpoints to keep,
                // kept on them alone, above). A manifest subset must not reattach an
                // oversized scan as a prefix.
                if let Some((top, _, _, _)) = ordered.first() {
                    let top_fresh: BTreeSet<AttachKey> = keys_of
                        .get(top)
                        .map(|keys| keys.iter().filter(|key| is_fresh(key)).copied().collect())
                        .unwrap_or_default();
                    if budget
                        .checked_required(allocated_slots, top_fresh.len())
                        .is_err()
                    {
                        refused_top = Some(*top);
                        break 'refused top_fresh;
                    }
                }
                // Published tables bypass the per-object cap but stay atomic: their
                // union with the manifest subset must fit the remaining global budget,
                // else the whole module is refused. A published spill would be neither
                // an honest refusal nor an honest uncorroborated count, so it never
                // spills — it refuses.
                let mut fresh: BTreeSet<AttachKey> = manifest_wanted;
                let mut admitted: BTreeSet<TableKey> = BTreeSet::new();
                let published: Vec<TableKey> = ordered
                    .iter()
                    .filter(|(_, _, _, observed)| *observed)
                    .map(|(key, _, _, _)| *key)
                    .collect();
                let mut published_union = fresh.clone();
                for key in &published {
                    if let Some(keys) = keys_of.get(key) {
                        published_union.extend(keys.iter().filter(|key| is_fresh(key)).copied());
                    }
                }
                if budget
                    .checked_required(allocated_slots, published_union.len())
                    .is_err()
                {
                    break 'refused published_union;
                }
                fresh = published_union;
                // Empty published tables cost nothing: admitted, never spilled, never
                // counted — they are corroborated, not uncorroborated.
                admitted.extend(published.iter().copied());
                // Unresolved heuristic tables admit strongest-first until the
                // per-object cap or the remaining global budget; the spill is
                // uncorroborated evidence, never slots.
                //
                // Broad (Task 1.6 experiment) instead demands the complete validated
                // set: every table's targets must fit the remaining global budget or
                // the module refuses whole, like a published over-budget module. A
                // strongest-prefix plus spill would break the dormant-activation
                // promise (spill is informational, never PARTIAL), so broad never
                // spills — it refuses, loudly, with the same shape. Empty tables cost
                // nothing either way and admit, never spilling.
                if whole {
                    let mut scan_union = fresh.clone();
                    for (key, _, _, _) in &ordered {
                        if let Some(keys) = keys_of.get(key) {
                            scan_union.extend(keys.iter().filter(|key| is_fresh(key)).copied());
                        }
                    }
                    if budget
                        .checked_required(allocated_slots, scan_union.len())
                        .is_err()
                    {
                        break 'refused scan_union;
                    }
                    fresh = scan_union;
                    admitted.extend(ordered.iter().map(|(key, _, _, _)| *key));
                } else {
                    let mut heuristic_admitted = 0usize;
                    let mut spent = false;
                    for (key, _, _, observed) in &ordered {
                        if *observed {
                            continue;
                        }
                        // A heuristic table with no attachable target costs nothing either
                        // way: counted as spill, never consuming the cap — unless it is
                        // the refused strongest table of a growth, whose endpoints the
                        // omission record already reports.
                        if keys_of.get(key).is_none_or(|keys| keys.is_empty()) {
                            if refused_top != Some(*key) {
                                uncorroborated_candidates += 1;
                            }
                            continue;
                        }
                        // The kept-only retry after a refused growth admits
                        // every table that still lists a kept endpoint: kept
                        // endpoints need no new slot, so the cap must not
                        // spill one of their tables and retire it (G-03).
                        if !kept_only && (spent || heuristic_admitted >= MAX_TABLES_PER_OBJECT) {
                            // A spent budget or a full cap still must not
                            // drop a table the module has attached: route
                            // to the refused-growth retry like a direct
                            // budget failure. Attached is not
                            // surviving-in-admitted-tables: a kept table
                            // with zero fresh demand still loses its kept
                            // endpoints when it spills, so empty demand
                            // routes too — the retry bypasses the cap and
                            // preserves them, while the omission below is
                            // suppressed for an empty total (an unchanged
                            // provider stays COMPLETE). Tables with
                            // nothing to keep still spill, counted once
                            // as uncorroborated.
                            if let Some(demand) = kept_demand(key) {
                                refused_top = Some(*key);
                                break 'refused demand;
                            }
                            uncorroborated_candidates += 1;
                            continue;
                        }
                        let marginal = keys_of.get(key).map_or(0, |keys| {
                            keys.iter()
                                .filter(|key| is_fresh(key) && !fresh.contains(key))
                                .count()
                        });
                        if budget
                            .checked_required(allocated_slots, fresh.len())
                            .and_then(|required| budget.checked_required(required, marginal))
                            .is_err()
                        {
                            // A table the module already has attached must not
                            // spill: its kept endpoints would vanish from the
                            // snapshot and retire. Route to the refused-growth
                            // retry like the leading table, so the kept
                            // endpoints stay and any growth is omitted
                            // explicitly — for empty demand too, as above:
                            // the retry preserves what a spill would drop,
                            // and the omission below is suppressed for an
                            // empty total. Tables with nothing to keep still
                            // spill, counted once as uncorroborated.
                            if !kept_only && let Some(demand) = kept_demand(key) {
                                refused_top = Some(*key);
                                break 'refused demand;
                            }
                            // The budget is spent: this table and every weaker one spill.
                            // Admission stays a strongest-evidence prefix — a strong
                            // table is never skipped to admit a weaker one.
                            uncorroborated_candidates += 1;
                            spent = true;
                            continue;
                        }
                        if let Some(keys) = keys_of.get(key) {
                            fresh.extend(keys.iter().filter(|key| is_fresh(key)).copied());
                        }
                        admitted.insert(*key);
                        heuristic_admitted += 1;
                    }
                }
                break 'admission Ok((fresh, admitted));
            };
            // Over `kept` alone nothing is fresh, so only the first pass
            // refuses; were that ever broken, the module is refused whole
            // rather than retried.
            debug_assert!(!kept_only, "kept endpoints alone need no new slot");
            // A whole-union policy refuses the group's complete fresh demand,
            // even when its manifest or strongest table failed first. Scan
            // targets without a valid table never enter that admission union.
            let refused = if whole {
                group
                    .iter()
                    .flat_map(|module| {
                        module.targets.iter().filter(move |target| {
                            module.scan_evidence.as_ref().is_none_or(|evidence| {
                                target
                                    .table
                                    .is_some_and(|index| evidence.tables.get(index).is_some())
                            })
                        })
                    })
                    .map(|target| AttachKey {
                        object: target.object,
                        file_offset: target.file_offset,
                    })
                    .filter(|key| !claimed.contains(key) && !existing_slots.contains_key(key))
                    .collect()
            } else {
                refused
            };
            if !kept_only && !kept.is_empty() {
                refused_growth = Some(refused);
                uncorroborated_candidates = spill_baseline;
                continue 'admission;
            }
            break 'admission Err(refused);
        };
        let (fresh, admitted) = match outcome {
            Ok(admission) => admission,
            Err(refused) => {
                holding.remove(&object);
                let refusal = CapacityRefusal {
                    policy: admission_policy,
                    needed: refused.len(),
                    capacity,
                    in_use: allocated_slots,
                    retired,
                    holders: slot_holders(&holding, &paths),
                    reserve: reserved.then_some(reserve),
                    closure_tables: (shared && class == AdmissionClass::ClosureArray)
                        .then_some(table_count),
                    aim_hint: shared,
                };
                decisions[position] = Some(AdmissionDecision::Refused(Skipped {
                    subject: path.to_string(),
                    reason: refusal.reason(),
                }));
                continue;
            }
        };
        allocated_slots = admission_policy
            .checked_required(allocated_slots, fresh.len())
            .expect("admitted target union was checked before allocation");
        claimed.extend(fresh.iter().copied());
        holding.insert(object, kept.len() + fresh.len());
        decisions[position] = Some(AdmissionDecision::Admitted {
            admitted,
            refused_growth,
            kept,
            allocated_slots,
        });
    }

    let mut positions: BTreeMap<(PinnedObjectId, u64), usize> = BTreeMap::new();
    let mut building: Vec<Building> = Vec::new();
    let mut slot_ordinals: BTreeMap<AttachKey, BTreeSet<SlotOrdinal>> = BTreeMap::new();
    let mut modules = Vec::new();
    let mut modules_skipped = Vec::new();
    let mut refused_module_objects = Vec::new();
    let mut skipped = Vec::new();
    let mut surfaces = Vec::new();
    let mut entries_seen = 0usize;
    for (group, decision) in groups.into_iter().zip(decisions) {
        let key = group[0].key;
        let object = group[0].object;
        let path = group[0].path;
        let source = group[0].source;
        entries_seen += decoded_occurrence_count(&group);
        let (admitted, refused_growth, kept, allocated_slots) =
            match decision.expect("merge decides every module before building it") {
                AdmissionDecision::Refused(refusal) => {
                    refused_module_objects.push((object, refusal.clone()));
                    modules_skipped.push(refusal);
                    continue;
                }
                AdmissionDecision::Admitted {
                    admitted,
                    refused_growth,
                    kept,
                    allocated_slots,
                } => (admitted, refused_growth, kept, allocated_slots),
            };
        // Per scan piece, per table index: admitted above. Manifest pieces
        // carry `None` and admit every target.
        let admitted_instance: Vec<Option<Vec<bool>>> = group
            .iter()
            .enumerate()
            .map(|(piece, module)| {
                module.scan_evidence.as_ref().map(|evidence| {
                    evidence
                        .tables
                        .iter()
                        .enumerate()
                        .map(|(index, table)| admitted.contains(&table_key(piece, index, table)))
                        .collect()
                })
            })
            .collect();

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
        let mut seen_skips = BTreeSet::new();
        let mut seen_tables = Vec::new();
        let mut seen_surfaces = Vec::new();
        let mut group_surfaces = Vec::new();
        let mut group_skips = Vec::new();
        // A refused growth's endpoints no other module attaches, and the kept
        // endpoints this module stays attached through.
        let mut omitted = BTreeSet::new();
        let mut kept_attached = BTreeSet::new();
        for (piece, module) in group.into_iter().enumerate() {
            debug_assert_eq!(
                module.entries_seen,
                module.targets.len() + module.skipped.len()
            );
            for target in &module.targets {
                if let Some(admit) = admitted_instance.get(piece).and_then(|slot| slot.as_ref()) {
                    // Spilled heuristic tables are evidence, never slots. A
                    // scan target naming no admitted table fails closed.
                    let admitted_table = target
                        .table
                        .and_then(|index| admit.get(index).copied())
                        .unwrap_or(false);
                    if !admitted_table {
                        continue;
                    }
                }
                if refused_growth.is_some() {
                    let target_key = AttachKey {
                        object: target.object,
                        file_offset: target.file_offset,
                    };
                    if !kept.contains(&target_key) {
                        // Never a new claim, not even on a target another
                        // module attaches: kept endpoints keep their owners.
                        if !positions.contains_key(&(target.object, target.file_offset))
                            && !existing_slots.contains_key(&target_key)
                        {
                            omitted.insert(target_key);
                        }
                        continue;
                    }
                    kept_attached.insert(target_key);
                }
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
                for name in std::iter::once(presented_name(target.name_authorized, target.name))
                    .chain(target.aliases.iter().copied())
                {
                    slot.name_authority
                        .entry(name.to_string())
                        .and_modify(|authorized| *authorized |= target.semantic_authorized)
                        .or_insert(target.semantic_authorized);
                }
                slot.fork_safe &= target.fork_safe;
                if let Some(ordinal) = target.ordinal {
                    slot_ordinals
                        .entry(AttachKey {
                            object: target.object,
                            file_offset: target.file_offset,
                        })
                        .or_default()
                        .insert(ordinal);
                }
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
        surfaces.extend(group_surfaces);
        skipped.extend(group_skips);
        if let Some(demand) = refused_growth {
            omitted.extend(demand);
            // A zero-demand kept table routes only for preservation: with
            // nothing omitted there is no refusal to record, and the
            // snapshot stays COMPLETE. Non-empty demand always leaves the
            // total non-empty, so explicit refusals are unchanged.
            if !omitted.is_empty() {
                let omission = Skipped {
                    subject: path.to_string(),
                    reason: growth_omission_reason(
                        omitted.len(),
                        capacity,
                        allocated_slots,
                        retired,
                        kept_attached.len(),
                        admission_policy,
                    ),
                };
                refused_module_objects.push((object, omission.clone()));
                modules_skipped.push(omission);
            }
        }
    }

    let slots: Vec<Slot> = building
        .into_iter()
        .enumerate()
        .map(|(index, mut slot)| {
            // `unknown` is the absence of a name claim, not a rival one: an
            // authorized name (manifest, linked table) always wins over it,
            // so a corroborated slot is never "C_Sign|unknown (aliased)".
            if slot.name_authority.len() > 1 {
                slot.name_authority.remove(UNKNOWN_FUNCTION_NAME);
            }
            let names: Vec<_> = slot.name_authority.keys().cloned().collect();
            let semantic_authorized = !admission_policy.forces_count_only()
                && slot.name_authority.values().all(|value| *value);
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
    let mut plan = AttachPlan::from_slots_with_policy(slots, admission_policy)
        .expect("merge enforces its immutable admission policy");
    plan.slot_ordinals = slot_ordinals;
    plan.modules = modules;
    plan.uncorroborated_candidates = uncorroborated_candidates;
    plan.skipped = skipped;
    plan.modules_skipped = modules_skipped;
    plan.refused_module_objects = refused_module_objects;
    plan.entries_seen = entries_seen;
    plan.surfaces = surfaces;
    plan.vendor_interfaces = vendor_interfaces;
    plan.interface_list = interface_list;
    plan.admission_scope = admission_scope;
    plan
}

/// Merges every reconciled scanned module into one plan over a single slot space.
pub fn build_from_reconciled_modules(modules: &[ReconciledModule]) -> AttachPlan {
    merge(
        modules.iter().map(lower_scanned).collect(),
        0,
        "absent".into(),
        ExistingAllocation {
            slots: 0,
            active: &BTreeMap::new(),
            owned: &BTreeMap::new(),
        },
        false,
        AdmissionPolicy::detailed(),
        AdmissionScope::Named,
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
    build_from_sources_broad(scanned, manifests, pinned, false)
}

/// Task 1.6 experiment: `broad_admit` lifts the per-object heuristic cap
/// and refuses a module whole unless every validated table fits. Only the
/// engine's broad pass sets this; every other caller keeps `false`.
pub fn build_from_sources_broad(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
    broad_admit: bool,
) -> AttachPlan {
    build_from_sources_with_policy(
        scanned,
        manifests,
        pinned,
        broad_admit,
        AdmissionPolicy::detailed(),
        AdmissionScope::Named,
    )
}

/// Builds the initial detailed plan of a capture under `admission_scope`,
/// which every live rebuild of it keeps. `broad_admit` is the Task 1.6
/// experiment, as for [`build_from_sources_broad`].
pub fn build_from_sources_scoped(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
    broad_admit: bool,
    admission_scope: AdmissionScope,
) -> AttachPlan {
    build_from_sources_with_policy(
        scanned,
        manifests,
        pinned,
        broad_admit,
        AdmissionPolicy::detailed(),
        admission_scope,
    )
}

/// Builds an initial plan under an explicit immutable admission policy.
/// Inventory callers do not depend on the detailed-mode broad-admit experiment.
pub fn build_from_sources_for_policy(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
    admission_policy: AdmissionPolicy,
) -> AttachPlan {
    build_from_sources_with_policy(
        scanned,
        manifests,
        pinned,
        false,
        admission_policy,
        AdmissionScope::Named,
    )
}

/// Builds an initial plan under an explicit immutable admission policy and
/// admission scope. The `inspect --system` catalog lowers Detailed and the
/// inventory catalog lowers Inventory through this one entry point, so the
/// two differ only in the policy they pass.
pub fn build_from_sources_for_policy_scoped(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
    admission_policy: AdmissionPolicy,
    admission_scope: AdmissionScope,
) -> AttachPlan {
    build_from_sources_with_policy(
        scanned,
        manifests,
        pinned,
        false,
        admission_policy,
        admission_scope,
    )
}

/// Complete target requirements before table/slot admission. These are negative
/// completeness and ambiguity facts, never permission to read arguments.
pub(crate) struct SemanticSourceClaims {
    pub(crate) providers: BTreeMap<PinnedObjectId, BTreeSet<AttachKey>>,
    pub(crate) degraded: BTreeSet<AttachKey>,
    pub(crate) incomplete: BTreeSet<PinnedObjectId>,
}

pub(crate) fn semantic_source_claims(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
) -> SemanticSourceClaims {
    let affecting = |name: &str| {
        crate::kinds::descriptor(name)
            .is_none_or(|descriptor| descriptor != SlotSemantics::COUNT_ONLY)
    };
    let mut incomplete: BTreeSet<_> = scanned
        .iter()
        .filter(|module| {
            module.scanned.tables.iter().any(|table| {
                table.walk != "full" || table.unpinned.iter().any(|entry| affecting(&entry.subject))
            })
        })
        .map(|module| module.object)
        .collect();
    let mut pieces: Vec<_> = scanned.iter().map(lower_scanned).collect();
    let mut selection_claims = Vec::new();
    for manifest in manifests {
        let (piece, _) = lower_manifest(
            manifest,
            |key, path| pinned.id_for_manifest(key, path),
            // A retained target rejected by ordinary ABI admission still
            // belongs to the complete demand; omitting it cannot certify a prefix.
            |_, _| true,
        );
        if let Some(piece) = &piece {
            if manifest.surfaces.iter().any(|surface| {
                (matches!(surface.acquisition, Acquisition::Ok)
                    && !crate::manifest_input::surface_function_inventory_complete(surface))
                    || surface.functions.iter().any(|function| {
                        affecting(&function.name)
                            && !matches!(
                                function.resolution,
                                Resolution::Resolved { .. } | Resolution::NullPointer
                            )
                    })
            }) {
                // Only typed null/absent entries prove optional absence.
                // A successfully acquired undecoded table is incomplete;
                // diagnostic strings cannot stand in for either fact.
                incomplete.insert(piece.object);
            }
            if manifest
                .selection_evidence
                .tables
                .iter()
                .any(crate::manifest_input::selection_table_inventory_incomplete)
            {
                incomplete.insert(piece.object);
            }
            for (table_id, targets) in
                crate::discovery::engine::manifest_selection_targets(manifest, pinned)
            {
                if manifest
                    .selection_evidence
                    .tables
                    .iter()
                    .find(|table| table.id == table_id)
                    .is_some_and(|table| {
                        table
                            .functions
                            .iter()
                            .filter(|function| {
                                matches!(function.resolution, Resolution::Resolved { .. })
                            })
                            .count()
                            != targets.len()
                    })
                {
                    incomplete.insert(piece.object);
                }
                selection_claims.extend(targets.into_iter().map(|target| (piece.object, target)));
            }
        }
        pieces.extend(piece);
    }
    let mut providers = BTreeMap::<_, BTreeSet<_>>::new();
    let mut owners = BTreeMap::<_, BTreeSet<_>>::new();
    let mut names = BTreeMap::<_, BTreeMap<String, bool>>::new();
    for piece in pieces {
        for target in piece.targets {
            let key = AttachKey {
                object: target.object,
                file_offset: target.file_offset,
            };
            providers.entry(piece.object).or_default().insert(key);
            owners.entry(key).or_default().insert(piece.object);
            let claims = names.entry(key).or_default();
            for name in std::iter::once(presented_name(target.name_authorized, target.name))
                .chain(target.aliases)
            {
                claims
                    .entry(name.to_owned())
                    .and_modify(|attested| *attested |= target.semantic_authorized)
                    .or_insert(target.semantic_authorized);
            }
        }
    }
    let mut selection_keys = BTreeSet::new();
    for (provider, target) in selection_claims {
        let key = AttachKey {
            object: target.object,
            file_offset: target.file_offset,
        };
        providers.entry(provider).or_default().insert(key);
        owners.entry(key).or_default().insert(provider);
        names
            .entry(key)
            .or_default()
            .entry(target.name.to_owned())
            .or_insert(false);
        // Selection-only input grants no semantic authority, even when a
        // target also has a trusted name. Keep that negative claim before
        // provider selection/admission can hide it.
        selection_keys.insert(key);
    }
    let degraded = names
        .into_iter()
        .filter_map(|(key, mut names)| {
            if names.len() > 1 {
                names.remove(UNKNOWN_FUNCTION_NAME);
            }
            let labels = names.keys().cloned().collect::<Vec<_>>();
            (selection_keys.contains(&key)
                || owners[&key].len() > 1
                || names.values().any(|attested| !attested)
                || crate::kinds::descriptor_index(&labels).1)
                .then_some(key)
        })
        .collect();
    SemanticSourceClaims {
        providers,
        degraded,
        incomplete,
    }
}

fn build_from_sources_with_policy(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
    broad_admit: bool,
    admission_policy: AdmissionPolicy,
    admission_scope: AdmissionScope,
) -> AttachPlan {
    let (pinned_id, compatible) = pinned_manifest_lookups(pinned);
    let mut plan = build_from_sources_with(
        scanned,
        manifests,
        pinned_id,
        compatible,
        ExistingAllocation {
            slots: 0,
            active: &BTreeMap::new(),
            owned: &BTreeMap::new(),
        },
        broad_admit,
        admission_policy,
        admission_scope,
    );
    plan.note_object_identities(pinned);
    plan
}

/// Historical allocations, their still-active subset, and its current owners
/// travel together. Retired slots count against capacity even though they are
/// absent from `active`.
struct ExistingAllocation<'a> {
    slots: usize,
    active: &'a BTreeMap<AttachKey, usize>,
    /// `active`, under the object of each module that currently owns a
    /// target: a module listed here is already admitted (G-03).
    owned: &'a BTreeMap<PinnedObjectId, BTreeSet<AttachKey>>,
}

/// The standard manifest lookups over live pins: manifest keys resolve to
/// pinned objects, and a retained target is admitted only under the
/// provider's own ABI. Shared by the build paths and the conservative plan
/// cursor so manifest keys cannot resolve differently between them.
fn pinned_manifest_lookups(
    pinned: &PinnedObjects,
) -> (
    impl FnMut(ObjectKey, &str) -> Option<PinnedObjectId> + '_,
    impl FnMut(PinnedObjectId, PinnedObjectId) -> bool + '_,
) {
    (
        |key, path| pinned.id_for_manifest(key, path),
        |provider, target| {
            matches!(
                (pinned.abi_for(provider), pinned.abi_for(target)),
                (Some(provider), Some(target)) if provider == target
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn build_from_sources_with(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    mut pinned_id: impl FnMut(ObjectKey, &str) -> Option<PinnedObjectId>,
    mut compatible: impl FnMut(PinnedObjectId, PinnedObjectId) -> bool,
    allocated: ExistingAllocation<'_>,
    broad_admit: bool,
    admission_policy: AdmissionPolicy,
    admission_scope: AdmissionScope,
) -> AttachPlan {
    let mut discovered: Vec<Discovered<'_>> = scanned.iter().map(lower_scanned).collect();
    let mut orphaned = Vec::new();
    for manifest in manifests {
        let (module, skipped) = lower_manifest(manifest, &mut pinned_id, &mut compatible);
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
        allocated,
        broad_admit,
        admission_policy,
        admission_scope,
    );
    plan.skipped.extend(orphaned);
    plan
}

#[cfg(test)]
fn build_from_test_sources(scanned: &[ReconciledModule], manifests: &[Manifest]) -> AttachPlan {
    build_from_test_sources_with_policy(scanned, manifests, AdmissionPolicy::detailed())
}

#[cfg(test)]
fn build_from_test_sources_with_policy(
    scanned: &[ReconciledModule],
    manifests: &[Manifest],
    admission_policy: AdmissionPolicy,
) -> AttachPlan {
    build_from_sources_with(
        scanned,
        manifests,
        |key, _| u32::try_from(key.inode).ok().map(PinnedObjectId),
        |_, _| true,
        ExistingAllocation {
            slots: 0,
            active: &BTreeMap::new(),
            owned: &BTreeMap::new(),
        },
        false,
        admission_policy,
        AdmissionScope::Named,
    )
}

/// Mislabel guard: an unlinked heuristic table's ordinal label is a positional
/// guess — its slots are named `unknown`, never e.g. `C_Sign`. Only
/// linkage-or-manifest authorization presents PKCS#11 names. Admission is
/// untouched: linkage is preferred, never gated.
fn presented_name(authorized: bool, name: &str) -> &str {
    if authorized {
        name
    } else {
        UNKNOWN_FUNCTION_NAME
    }
}

/// The lowered target rows of one scanned table: each decoded entry with the
/// object it attaches into. Shared by [`lower_scanned`] and the conservative
/// plan cursor, so the cursor's live-key set is enumerated by the same row
/// function merge uses and cannot drift from it.
fn scanned_table_rows(
    module: &ReconciledModule,
    table: usize,
) -> impl Iterator<Item = (&ScannedEntry, PinnedObjectId)> + '_ {
    module.scanned.tables[table]
        .entries
        .iter()
        .zip(module.entry_objects[table].iter().copied())
}

fn lower_scanned(module: &ReconciledModule) -> Discovered<'_> {
    let scanned = &module.scanned;
    // The module object's own `.dynsym`: the export-linkage witness for
    // every table this module published.
    let exports = ObjectExports {
        object: scanned.key,
        symbols: &module.exports,
    };
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
        // Same score inputs `merge` admits by, so provenance, the heuristic
        // cap, and name authorization can never disagree about one table.
        let score = table_evidence_score(
            index,
            &scanned.tables,
            &scanned.interfaces,
            &[],
            &[],
            &exports,
        );
        let authorized = table_name_authorized(&score);
        tables.push(TableSummary {
            version: table.version,
            entries: table.entries.len(),
            source: "scan",
            file_offset: table.file_offset,
            linkage: table_linkage(&score),
            exports_agreeing: Some(export_agreement(table, &exports).agreeing),
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
        surfaces.extend(
            scanned
                .interfaces
                .iter()
                .filter(|interface| interface.table == Some(index))
                .map(|interface| SurfaceSummary {
                    source: format!("interface[{}] {}", interface.index, interface.name_class),
                    walk: table.walk.to_string(),
                    acquisition: "ok".into(),
                    functions: published,
                }),
        );
        targets.extend(
            scanned_table_rows(module, index).map(|(entry, object)| Target {
                name: entry.name,
                object,
                object_path: &entry.object_path,
                file_offset: entry.file_offset,
                fork_safe,
                semantic_authorized: false,
                name_authorized: authorized,
                table: Some(index),
                ordinal: standard_ordinal(entry.name).map(|ordinal| SlotOrdinal {
                    table_file_offset: table.file_offset,
                    ordinal,
                }),
                aliases: if score.exports && entry.object == exports.object {
                    exports.aliases_at(entry.name, entry.file_offset)
                } else {
                    Vec::new()
                },
            }),
        );
        skipped.extend(table.null_entries.iter().map(|name| Skipped {
            subject: presented_name(authorized, name).to_string(),
            reason: "null pointer".into(),
        }));
        // Unpinned subjects are the same ordinal labels (reconciliation records
        // them verbatim), so the same gate applies; the reasons keep the facts.
        skipped.extend(table.unpinned.iter().map(|skip| Skipped {
            subject: presented_name(authorized, &skip.subject).to_string(),
            reason: skip.reason.clone(),
        }));
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
        scan_evidence: Some(ScanEvidence {
            tables: &scanned.tables,
            interfaces: &scanned.interfaces,
            exports,
        }),
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
    let (discovered, orphaned) = lower_manifest(m, |key, _| ids.get(&key).copied(), |_, _| true);
    let mut plan = merge(
        discovered.into_iter().collect(),
        m.vendor_interfaces.len(),
        acquisition_label(&m.interface_list),
        ExistingAllocation {
            slots: 0,
            active: &BTreeMap::new(),
            owned: &BTreeMap::new(),
        },
        false,
        AdmissionPolicy::detailed(),
        AdmissionScope::Named,
    );
    plan.skipped.extend(orphaned);
    plan
}

fn lower_manifest(
    m: &Manifest,
    mut pinned_id: impl FnMut(ObjectKey, &str) -> Option<PinnedObjectId>,
    mut compatible: impl FnMut(PinnedObjectId, PinnedObjectId) -> bool,
) -> (Option<Discovered<'_>>, Vec<Skipped>) {
    let mut tables = Vec::new();
    let mut surfaces = Vec::new();
    let mut targets = Vec::new();
    let mut skipped = Vec::new();
    let mut entries_seen = 0usize;

    for surface in &m.surfaces {
        surfaces.push(SurfaceSummary {
            source: source_label(&surface.source),
            walk: crate::manifest_input::effective_surface_walk(surface),
            acquisition: acquisition_label(&surface.acquisition),
            functions: surface.functions.len(),
        });
        tables.push(TableSummary {
            version: surface
                .version
                .map_or((0, 0), |version| (version.major, version.minor)),
            entries: surface.functions.len(),
            source: "manifest",
            file_offset: None,
            linkage: "manifest",
            exports_agreeing: None,
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
                    if let Some(provider) = m
                        .objects
                        .iter()
                        .find(|candidate| candidate.path == m.module_path)
                        .and_then(|candidate| {
                            object_key(m, candidate).and_then(|key| pinned_id(key, &candidate.path))
                        })
                        && !compatible(provider, object)
                    {
                        skip(format!(
                            "object id {} has a different target ABI from the provider",
                            record.id
                        ));
                        continue;
                    }
                    targets.push(Target {
                        name: &f.name,
                        table: None,
                        ordinal: standard_ordinal(&f.name).map(|ordinal| SlotOrdinal {
                            table_file_offset: None,
                            ordinal,
                        }),
                        aliases: Vec::new(),
                        object,
                        object_path: &record.path,
                        file_offset: *file_offset,
                        fork_safe,
                        semantic_authorized: true,
                        name_authorized: true,
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
    let Some(module_object) = pinned_id(key, &module_record.path) else {
        return (None, skipped);
    };

    (
        Some(Discovered {
            object: module_object,
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
            scan_evidence: None,
        }),
        Vec::new(),
    )
}

/// Conservative plan cursor: removal-only rebuild of an [`AttachPlan`] from
/// surviving sources, one bounded step per credit.
///
/// The cursor never grows: output slots are a subset of the old plan's, and
/// output modules are the already-admitted groups rebuilt from the surviving
/// sources. A slot survives exactly when a surviving source row still yields
/// its exact key (through the shared [`lower_scanned`]/[`lower_manifest`]
/// lowering), or when it is a provisional seed whose object still has an
/// admitted group (the rebuilt carry loop's module check). Everything else
/// retires in place. Growth in the sources (new keys, new groups) is ignored:
/// the delta's `new`/`replace` stay empty and historical refusals are kept.
///
/// Output assembly mirrors [`AttachPlan::extend_exact_prepared`]'s removal
/// path (retired slots stay in place with unchanged content, aggregate owners
/// merge the same way, retire rows leave in key order), and module summaries,
/// skips and surfaces replicate merge's per-group build (same dedup rules)
/// over the surviving groups, so a removal-only derivation equals the
/// rebuild-then-extend reference field for field. Admission is deliberately
/// not replicated: surviving groups were admitted under a tighter budget, so
/// they stay admitted; capacity refusals, spill counts and the broad-admit
/// flag affect only evidence the cursor carries over (see `assemble`). The
/// known divergences from a full rebuild are all growth-shaped (new slots,
/// resurrected retired keys, shared-target name narrowing, re-refusal reason
/// strings) and resolve to no-growth by design.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct PlanFence {
    token: u64,
    mutations: u64,
    slots: usize,
    modules: usize,
    skipped: usize,
}

// consumed by T4: the fence runs only inside the cursor poll.
#[allow(dead_code)]
impl PlanFence {
    /// Snapshots the fenced members. A poisoned token refuses at once, before
    /// any derivation step runs.
    fn snapshot(plan: &AttachPlan) -> Result<Self, GraphRefusal> {
        if plan.token.0 == PLAN_TOKEN_POISON {
            return Err(GraphRefusal::SourceChanged);
        }
        Ok(Self {
            token: plan.token.0,
            mutations: plan.mutations.0,
            slots: plan.slots.len(),
            modules: plan.modules.len(),
            skipped: plan.skipped.len(),
        })
    }

    fn check(&self, plan: &AttachPlan) -> Result<(), GraphRefusal> {
        if Self::snapshot(plan)? == *self {
            Ok(())
        } else {
            Err(GraphRefusal::SourceChanged)
        }
    }
}

/// Byte accounting mirrors `discovery::identity`'s conservative-copy
/// accounting, which is private to that module: every owned allocation below
/// is covered by the one measured reservation before it happens.
// consumed by T4: used only by the cursor measure phase.
#[allow(dead_code)]
fn plan_bytes_for<T>(count: usize) -> Result<usize, GraphRefusal> {
    count
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| bytes.checked_add(OWNED_ALLOCATION_PADDING))
        .ok_or(GraphRefusal::Overflow)
}

// consumed by T4: used only by the cursor measure phase.
#[allow(dead_code)]
fn plan_byte_len(len: usize) -> Result<usize, GraphRefusal> {
    len.checked_add(OWNED_ALLOCATION_PADDING)
        .ok_or(GraphRefusal::Overflow)
}

// consumed by T4: used only by the cursor measure phase.
#[allow(dead_code)]
fn plan_text_bytes(text: &str) -> Result<usize, GraphRefusal> {
    plan_byte_len(text.len())
}

// consumed by T4: used only by the cursor measure phase.
// Rust 1.99.1 B=6 BTree keeps every non-root node at >=5 keys, so n entries
// need at most 1+(n-1)/5 nodes; empty maps allocate nothing. Node size is the
// full internal size applied to every node.
#[allow(dead_code)]
fn plan_tree_bytes<K, V>(entries: usize) -> Result<usize, GraphRefusal> {
    fn align8(bytes: usize) -> Option<usize> {
        bytes.checked_add(7).map(|value| value & !7)
    }
    if std::mem::align_of::<K>() > 8 || std::mem::align_of::<V>() > 8 {
        return Err(GraphRefusal::Overflow);
    }
    let keys = std::mem::size_of::<K>()
        .checked_mul(11)
        .and_then(align8)
        .ok_or(GraphRefusal::Overflow)?;
    let values = std::mem::size_of::<V>()
        .checked_mul(11)
        .and_then(align8)
        .ok_or(GraphRefusal::Overflow)?;
    let node = 16usize
        .checked_add(keys)
        .and_then(|bytes| bytes.checked_add(values))
        .and_then(|bytes| bytes.checked_add(12 * 8))
        .and_then(|bytes| bytes.checked_add(OWNED_ALLOCATION_PADDING))
        .ok_or(GraphRefusal::Overflow)?;
    let nodes = if entries == 0 {
        0
    } else {
        1 + (entries - 1) / 5
    };
    nodes.checked_mul(node).ok_or(GraphRefusal::Overflow)
}

// consumed by T4: used only by the cursor measure phase.
#[allow(dead_code)]
fn plan_add(total: &mut usize, bytes: usize) -> Result<(), GraphRefusal> {
    *total = total.checked_add(bytes).ok_or(GraphRefusal::Overflow)?;
    Ok(())
}

// consumed by T4: used only by the cursor copy/retire phases.
#[allow(dead_code)]
fn next_after<K: Ord + Clone, V: Clone>(map: &BTreeMap<K, V>, after: &Option<K>) -> Option<(K, V)> {
    use std::ops::Bound::{Excluded, Unbounded};
    match after {
        Some(key) => map.range((Excluded(key), Unbounded)).next(),
        None => map.first_key_value(),
    }
    .map(|(key, value)| (key.clone(), value.clone()))
}

// consumed by T4: constructed only by graph callers and cursor tests.
#[allow(dead_code)]
pub(crate) struct ConservativePlanSources<'a> {
    modules: &'a [ReconciledModule],
    manifests: &'a [Manifest],
    pins: &'a PinnedObjects,
    broad_admit: bool,
}

// consumed by T4: constructed only by graph callers and cursor tests.
#[allow(dead_code)]
impl<'a> ConservativePlanSources<'a> {
    pub(crate) fn new(
        modules: &'a [ReconciledModule],
        manifests: &'a [Manifest],
        pins: &'a PinnedObjects,
        broad_admit: bool,
    ) -> Self {
        Self {
            modules,
            manifests,
            pins,
            broad_admit,
        }
    }
}

// consumed by T4: stored in the graph backing until the old canonical is reclaimed.
#[allow(dead_code)]
pub(crate) struct InstalledPlanBacking {
    output: Option<ResourceLease>,
    header: Option<ResourceLease>,
}

/// One lowered source piece, fully owned so the cursor can suspend and
/// resume across credits without retaining source borrows. Targets are kept
/// only as occurrence-count triples plus their keys: names feed the
/// occurrence recount, keys feed the live set.
// consumed by T4: read only inside the cursor derivation.
#[allow(dead_code)]
struct OwnedPiece {
    object: PinnedObjectId,
    key: ObjectKey,
    path: String,
    source: &'static str,
    tables: Vec<TableSummary>,
    interfaces: usize,
    surfaces: Vec<SurfaceSummary>,
    count_targets: Vec<(String, PinnedObjectId, u64)>,
    skipped: Vec<Skipped>,
}

// consumed by T4: called only by the cursor lowering phase.
#[allow(dead_code)]
fn own_piece(piece: Discovered<'_>) -> OwnedPiece {
    OwnedPiece {
        object: piece.object,
        key: piece.key,
        path: piece.path.to_owned(),
        source: piece.source,
        tables: piece.tables,
        interfaces: piece.interfaces,
        surfaces: piece.surfaces,
        count_targets: piece
            .targets
            .iter()
            .map(|target| (target.name.to_owned(), target.object, target.file_offset))
            .collect(),
        skipped: piece.skipped,
    }
}

/// One old plan module, cached for the slot remap and refusal attribution.
// consumed by T4: read only inside the cursor derivation.
#[allow(dead_code)]
struct OldModuleInfo {
    id: ModuleId,
    object: PinnedObjectId,
    path: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
// consumed by T4: transitioned only inside the cursor derivation.
#[allow(dead_code)]
enum ConservativePlanPhase {
    New,
    Measure,
    Measured,
    Lower,
    DrainKeys,
    RecordModules,
    Replicate,
    Derive,
    CopyMaps,
    Retire,
    Ready,
    Installed,
    Cancelled,
    Refused,
    Reclaim,
    Reclaimed,
}

// consumed by T4: driven only by graph callers and cursor tests.
#[allow(dead_code)]
pub(crate) struct ConservativePlanCursor {
    phase: ConservativePlanPhase,
    fence: Option<PlanFence>,
    refusal: Option<GraphRefusal>,
    broad_admit: bool,
    // Measure (allocation-free lens only).
    measured: usize,
    measured_slots: usize,
    required: Option<usize>,
    measure_stage: u8,
    measure_slot: usize,
    measure_module: usize,
    measure_source: usize,
    measure_table: usize,
    measure_manifest: usize,
    measure_surface: usize,
    measure_ordinals_after: Option<AttachKey>,
    measure_identities_after: Option<PinnedObjectId>,
    measure_provisional_after: Option<AttachKey>,
    measure_refused: usize,
    measure_skipped: usize,
    // Owned derivation state (allocated after the reservation).
    storage: Option<ResourceLease>,
    live: BTreeSet<AttachKey>,
    pieces: Vec<OwnedPiece>,
    groups: BTreeMap<PinnedObjectId, Vec<usize>>,
    group_order: Vec<PinnedObjectId>,
    manifest_orphaned: Vec<Skipped>,
    orphan_idx: usize,
    old_modules: Vec<OldModuleInfo>,
    old_id_objects: BTreeMap<ModuleId, PinnedObjectId>,
    old_objects: BTreeSet<PinnedObjectId>,
    old_paths: BTreeSet<String>,
    surviving_paths: BTreeSet<String>,
    stable_ids: BTreeMap<PinnedObjectId, ModuleId>,
    lower_source: usize,
    lower_manifest: usize,
    drain_piece: usize,
    drain_target: usize,
    record_module: usize,
    replicate_group: usize,
    replicate_step: u8,
    replicate_piece: usize,
    replicate_item: usize,
    replicate_count_only: bool,
    in_summary: Option<ModuleSummary>,
    piece_tables: Vec<TableSummary>,
    piece_surfaces: Vec<SurfaceSummary>,
    piece_skip_occurrences: BTreeMap<(String, String), usize>,
    seen_tables: Vec<(&'static str, TableSummary, usize)>,
    seen_surfaces: Vec<(&'static str, SurfaceSummary, usize)>,
    seen_skips: BTreeSet<(&'static str, String, String, usize)>,
    counter: OccurrenceCounter<String, String>,
    within_targets: BTreeMap<(String, PinnedObjectId, u64), usize>,
    within_skips: BTreeMap<(String, String), usize>,
    entries_seen: usize,
    derive_slot: usize,
    output_slots: Vec<Slot>,
    output_slot_by_key: BTreeMap<AttachKey, usize>,
    output_retired: BTreeSet<usize>,
    output_owners: Vec<AggregateOwner>,
    retired_by_cursor: BTreeSet<usize>,
    ambiguous_count: usize,
    output_modules: Vec<ModuleSummary>,
    output_skipped: Vec<Skipped>,
    output_surfaces: Vec<SurfaceSummary>,
    copy_stage: u8,
    copy_key: Option<AttachKey>,
    copy_object: Option<PinnedObjectId>,
    copy_provisional: Option<AttachKey>,
    copy_index: usize,
    output_ordinals: BTreeMap<AttachKey, BTreeSet<SlotOrdinal>>,
    output_identities: BTreeMap<PinnedObjectId, TargetObject>,
    output_provisional: BTreeMap<AttachKey, PinnedObjectId>,
    output_refused: Vec<(PinnedObjectId, Skipped)>,
    output_modules_skipped: Vec<Skipped>,
    retire_slot: usize,
    retire_key: Option<AttachKey>,
    output_removed: Vec<u32>,
    output_retire: Vec<Slot>,
    output: Option<AttachPlan>,
    delta: Option<AttachDelta>,
    old: Option<AttachPlan>,
    reclaim_step: u8,
}

// consumed by T4: driven only by graph callers and cursor tests.
#[allow(dead_code)]
impl ConservativePlanCursor {
    pub(crate) fn new() -> Self {
        Self {
            phase: ConservativePlanPhase::New,
            fence: None,
            refusal: None,
            broad_admit: false,
            measured: 0,
            measured_slots: 0,
            required: None,
            measure_stage: 0,
            measure_slot: 0,
            measure_module: 0,
            measure_source: 0,
            measure_table: 0,
            measure_manifest: 0,
            measure_surface: 0,
            measure_ordinals_after: None,
            measure_identities_after: None,
            measure_provisional_after: None,
            measure_refused: 0,
            measure_skipped: 0,
            storage: None,
            live: BTreeSet::new(),
            pieces: Vec::new(),
            groups: BTreeMap::new(),
            group_order: Vec::new(),
            manifest_orphaned: Vec::new(),
            orphan_idx: 0,
            old_modules: Vec::new(),
            old_id_objects: BTreeMap::new(),
            old_objects: BTreeSet::new(),
            old_paths: BTreeSet::new(),
            surviving_paths: BTreeSet::new(),
            stable_ids: BTreeMap::new(),
            lower_source: 0,
            lower_manifest: 0,
            drain_piece: 0,
            drain_target: 0,
            record_module: 0,
            replicate_group: 0,
            replicate_step: 0,
            replicate_piece: 0,
            replicate_item: 0,
            replicate_count_only: false,
            in_summary: None,
            piece_tables: Vec::new(),
            piece_surfaces: Vec::new(),
            piece_skip_occurrences: BTreeMap::new(),
            seen_tables: Vec::new(),
            seen_surfaces: Vec::new(),
            seen_skips: BTreeSet::new(),
            counter: OccurrenceCounter::default(),
            within_targets: BTreeMap::new(),
            within_skips: BTreeMap::new(),
            entries_seen: 0,
            derive_slot: 0,
            output_slots: Vec::new(),
            output_slot_by_key: BTreeMap::new(),
            output_retired: BTreeSet::new(),
            output_owners: Vec::new(),
            retired_by_cursor: BTreeSet::new(),
            ambiguous_count: 0,
            output_modules: Vec::new(),
            output_skipped: Vec::new(),
            output_surfaces: Vec::new(),
            copy_stage: 0,
            copy_key: None,
            copy_object: None,
            copy_provisional: None,
            copy_index: 0,
            output_ordinals: BTreeMap::new(),
            output_identities: BTreeMap::new(),
            output_provisional: BTreeMap::new(),
            output_refused: Vec::new(),
            output_modules_skipped: Vec::new(),
            retire_slot: 0,
            retire_key: None,
            output_removed: Vec::new(),
            output_retire: Vec::new(),
            output: None,
            delta: None,
            old: None,
            reclaim_step: 0,
        }
    }

    pub(crate) fn required_bytes(&self) -> Option<usize> {
        self.required
    }

    pub(crate) fn plan(&self) -> Option<&AttachPlan> {
        self.output.as_ref()
    }

    pub(crate) fn delta(&self) -> Option<&AttachDelta> {
        self.delta.as_ref()
    }

    pub(crate) fn removed(&self) -> Option<&[u32]> {
        if self.phase == ConservativePlanPhase::Ready
            || self.phase == ConservativePlanPhase::Installed
        {
            Some(&self.output_removed)
        } else {
            None
        }
    }
}

// consumed by T4: polled only by graph callers and cursor tests.
#[allow(dead_code)]
impl AttachPlan {
    /// Removal-only rebuild of this plan from surviving sources, one bounded
    /// step per credit. See the [`ConservativePlanCursor`] docs for the
    /// derivation rules.
    pub(crate) fn poll_conservative_rebuild(
        &self,
        source: ConservativePlanSources<'_>,
        stable_id: &mut dyn FnMut(PinnedObjectId) -> Option<ModuleId>,
        cursor: &mut ConservativePlanCursor,
        reserve: &SemanticResourceReserver,
        work: usize,
    ) -> Result<GraphStep, GraphRefusal> {
        if work == 0 {
            return Ok(GraphStep::Yielded);
        }
        match cursor.fence {
            Some(fence) => fence.check(self)?,
            None => cursor.fence = Some(PlanFence::snapshot(self)?),
        }
        if cursor.phase == ConservativePlanPhase::Cancelled {
            return Err(GraphRefusal::Cancelled);
        }
        if cursor.phase == ConservativePlanPhase::Refused {
            return Err(cursor.refusal.expect("a refused cursor keeps its refusal"));
        }
        if cursor.phase == ConservativePlanPhase::Ready
            || cursor.phase == ConservativePlanPhase::Installed
        {
            return Ok(GraphStep::Ready);
        }
        if cursor.phase == ConservativePlanPhase::Reclaim
            || cursor.phase == ConservativePlanPhase::Reclaimed
        {
            return Err(GraphRefusal::Cancelled);
        }
        for _ in 0..work {
            if cursor.advance(self, &source, stable_id, reserve)? {
                return Ok(GraphStep::Ready);
            }
        }
        Ok(GraphStep::Advanced)
    }

    /// An empty plan shell under the given policy/scope for the conservative
    /// cursor to fill in strided. O(1): no slots, no tables.
    fn empty_like(admission_policy: AdmissionPolicy, admission_scope: AdmissionScope) -> Self {
        let mut out = Self::from_indexed_slots(Vec::new(), admission_policy)
            .expect("an empty slot vec is always a valid plan");
        out.admission_scope = admission_scope;
        out
    }

    #[cfg(test)]
    pub(crate) fn poison_token_for_test(&mut self) {
        self.token = PlanToken(PLAN_TOKEN_POISON);
    }
}

// consumed by T4: stepped only inside the cursor derivation.
#[allow(dead_code)]
impl ConservativePlanCursor {
    /// One bounded derivation step. Returns `true` exactly when the step
    /// reached `Ready`.
    fn advance(
        &mut self,
        old: &AttachPlan,
        source: &ConservativePlanSources<'_>,
        stable_id: &mut dyn FnMut(PinnedObjectId) -> Option<ModuleId>,
        reserve: &SemanticResourceReserver,
    ) -> Result<bool, GraphRefusal> {
        match self.step(old, source, stable_id, reserve) {
            Ok(ready) => Ok(ready),
            Err(refusal) => {
                // A short pool is retryable: the measured derivation stays in
                // place and the next credit re-attempts the reservation.
                // Every other refusal is terminal for this derivation.
                if !matches!(refusal, GraphRefusal::Storage(_)) {
                    self.phase = ConservativePlanPhase::Refused;
                    self.refusal = Some(refusal);
                }
                Err(refusal)
            }
        }
    }

    fn step(
        &mut self,
        old: &AttachPlan,
        source: &ConservativePlanSources<'_>,
        stable_id: &mut dyn FnMut(PinnedObjectId) -> Option<ModuleId>,
        reserve: &SemanticResourceReserver,
    ) -> Result<bool, GraphRefusal> {
        match self.phase {
            ConservativePlanPhase::New => {
                self.broad_admit = source.broad_admit;
                self.measured_slots = old.slots.len();
                self.phase = ConservativePlanPhase::Measure;
                self.measure_one(old, source)
            }
            ConservativePlanPhase::Measure => self.measure_one(old, source),
            ConservativePlanPhase::Measured => self.reserve_one(reserve),
            ConservativePlanPhase::Lower => self.lower_one(source),
            ConservativePlanPhase::DrainKeys => self.drain_one_key(),
            ConservativePlanPhase::RecordModules => self.record_one_module(old),
            ConservativePlanPhase::Replicate => self.replicate_one(stable_id),
            ConservativePlanPhase::Derive => self.derive_one_slot(old),
            ConservativePlanPhase::CopyMaps => self.copy_one_map_entry(old),
            ConservativePlanPhase::Retire => self.retire_one(old),
            ConservativePlanPhase::Ready
            | ConservativePlanPhase::Installed
            | ConservativePlanPhase::Reclaim
            | ConservativePlanPhase::Reclaimed
            | ConservativePlanPhase::Cancelled
            | ConservativePlanPhase::Refused => Err(GraphRefusal::Cancelled),
        }
    }

    /// One measure unit: O(1) lens only, no allocation, no queries. Stage
    /// order is old slots, old modules, source modules (header plus one table
    /// each), manifests (header plus one surface each), the carried maps, then
    /// the fixed tail that publishes the requirement.
    fn measure_one(
        &mut self,
        old: &AttachPlan,
        source: &ConservativePlanSources<'_>,
    ) -> Result<bool, GraphRefusal> {
        use std::ops::Bound::{Excluded, Unbounded};
        match self.measure_stage {
            0 => {
                let Some(slot) = old.slots.get(self.measure_slot) else {
                    self.measure_stage = 1;
                    return Ok(false);
                };
                // The output slot clone plus every per-slot structure it may
                // fill: key index, retirement set, aggregate owner, and the
                // removal-only delta rows.
                plan_add(&mut self.measured, plan_bytes_for::<Slot>(1)?)?;
                plan_add(&mut self.measured, plan_text_bytes(&slot.object_path)?)?;
                for name in &slot.names {
                    plan_add(&mut self.measured, plan_text_bytes(name)?)?;
                }
                plan_add(
                    &mut self.measured,
                    plan_bytes_for::<ModuleId>(slot.module_ids.len())?,
                )?;
                plan_add(&mut self.measured, plan_bytes_for::<AggregateOwner>(1)?)?;
                plan_add(&mut self.measured, plan_tree_bytes::<AttachKey, usize>(1)?)?;
                plan_add(&mut self.measured, plan_tree_bytes::<usize, ()>(1)?)?;
                plan_add(&mut self.measured, plan_bytes_for::<u32>(1)?)?;
                self.measure_slot += 1;
                Ok(false)
            }
            1 => {
                let Some(module) = old.modules.get(self.measure_module) else {
                    self.measure_stage = 2;
                    return Ok(false);
                };
                // The remap cache entry plus its index and attribution sets.
                plan_add(&mut self.measured, plan_bytes_for::<OldModuleInfo>(1)?)?;
                plan_add(&mut self.measured, plan_text_bytes(&module.path)?)?;
                plan_add(
                    &mut self.measured,
                    plan_tree_bytes::<ModuleId, PinnedObjectId>(1)?,
                )?;
                plan_add(
                    &mut self.measured,
                    plan_tree_bytes::<PinnedObjectId, ()>(1)?,
                )?;
                plan_add(&mut self.measured, plan_text_bytes(&module.path)?)?;
                self.measure_module += 1;
                Ok(false)
            }
            2 => {
                let Some(module) = source.modules.get(self.measure_source) else {
                    self.measure_stage = 3;
                    return Ok(false);
                };
                if self.measure_table == 0 {
                    // The owned-piece shell plus one upper-bound entry per
                    // group-level structure this piece may open.
                    plan_add(&mut self.measured, plan_bytes_for::<OwnedPiece>(1)?)?;
                    plan_add(&mut self.measured, plan_text_bytes(&module.scanned.path)?)?;
                    plan_add(
                        &mut self.measured,
                        plan_bytes_for::<TableSummary>(module.scanned.tables.len())?,
                    )?;
                    plan_add(
                        &mut self.measured,
                        plan_tree_bytes::<PinnedObjectId, Vec<usize>>(1)?,
                    )?;
                    plan_add(&mut self.measured, plan_bytes_for::<PinnedObjectId>(1)?)?;
                    plan_add(&mut self.measured, plan_bytes_for::<ModuleId>(1)?)?;
                    plan_add(&mut self.measured, plan_bytes_for::<ModuleSummary>(1)?)?;
                    plan_add(&mut self.measured, plan_text_bytes(&module.scanned.path)?)?;
                }
                let Some(table) = module.scanned.tables.get(self.measure_table) else {
                    self.measure_source += 1;
                    self.measure_table = 0;
                    return Ok(false);
                };
                // Owned count triples plus the two occurrence structures that
                // clone each name again, the transient lowered targets, and
                // the live-set entry.
                for entry in &table.entries {
                    plan_add(
                        &mut self.measured,
                        plan_bytes_for::<(String, PinnedObjectId, u64)>(1)?,
                    )?;
                    for _ in 0..3 {
                        plan_add(&mut self.measured, plan_text_bytes(entry.name)?)?;
                    }
                    plan_add(&mut self.measured, plan_bytes_for::<Target<'_>>(1)?)?;
                    plan_add(
                        &mut self.measured,
                        plan_bytes_for::<&str>(module.exports.len())?,
                    )?;
                    plan_add(&mut self.measured, plan_tree_bytes::<AttachKey, ()>(1)?)?;
                    plan_add(
                        &mut self.measured,
                        plan_tree_bytes::<(String, PinnedObjectId, u64, usize), ()>(1)?,
                    )?;
                    plan_add(
                        &mut self.measured,
                        plan_tree_bytes::<(String, PinnedObjectId, u64), usize>(1)?,
                    )?;
                }
                for skip in &table.unpinned {
                    self.measure_skip_texts(&skip.subject, &skip.reason)?;
                }
                for null in &table.null_entries {
                    self.measure_skip_texts(null, "null pointer")?;
                    // The subject may instead present as `unknown`.
                    for _ in 0..5 {
                        plan_add(&mut self.measured, plan_text_bytes("unknown")?)?;
                    }
                }
                // One table summary plus its surfaces (the table surface and,
                // upper bound, one per interface), each held three times
                // (piece, dedup seen-set, output clone).
                for _ in 0..3 {
                    plan_add(&mut self.measured, plan_bytes_for::<TableSummary>(1)?)?;
                }
                let surfaces = module
                    .scanned
                    .interfaces
                    .len()
                    .checked_add(1)
                    .ok_or(GraphRefusal::Overflow)?;
                for _ in 0..surfaces {
                    for _ in 0..3 {
                        plan_add(&mut self.measured, plan_bytes_for::<SurfaceSummary>(1)?)?;
                        plan_add(&mut self.measured, plan_text_bytes(&module.scanned.path)?)?;
                        plan_add(&mut self.measured, plan_byte_len(32)?)?;
                        plan_add(&mut self.measured, plan_text_bytes(table.walk)?)?;
                        plan_add(&mut self.measured, plan_text_bytes("ok")?)?;
                    }
                }
                self.measure_table += 1;
                Ok(false)
            }
            3 => {
                let Some(manifest) = source.manifests.get(self.measure_manifest) else {
                    self.measure_stage = 4;
                    return Ok(false);
                };
                if self.measure_surface == 0 {
                    plan_add(&mut self.measured, plan_bytes_for::<OwnedPiece>(1)?)?;
                    plan_add(&mut self.measured, plan_text_bytes(&manifest.module_path)?)?;
                    plan_add(
                        &mut self.measured,
                        plan_bytes_for::<TableSummary>(manifest.surfaces.len())?,
                    )?;
                    plan_add(
                        &mut self.measured,
                        plan_bytes_for::<SurfaceSummary>(manifest.surfaces.len())?,
                    )?;
                    plan_add(
                        &mut self.measured,
                        plan_tree_bytes::<PinnedObjectId, Vec<usize>>(1)?,
                    )?;
                    plan_add(&mut self.measured, plan_bytes_for::<PinnedObjectId>(1)?)?;
                    plan_add(&mut self.measured, plan_bytes_for::<ModuleId>(1)?)?;
                    plan_add(&mut self.measured, plan_bytes_for::<ModuleSummary>(1)?)?;
                    plan_add(&mut self.measured, plan_text_bytes(&manifest.module_path)?)?;
                }
                let Some(surface) = manifest.surfaces.get(self.measure_surface) else {
                    self.measure_manifest += 1;
                    self.measure_surface = 0;
                    return Ok(false);
                };
                for function in &surface.functions {
                    // Upper bound: every function leaves both a count triple
                    // and a skip (it leaves exactly one of the two).
                    plan_add(
                        &mut self.measured,
                        plan_bytes_for::<(String, PinnedObjectId, u64)>(1)?,
                    )?;
                    for _ in 0..3 {
                        plan_add(&mut self.measured, plan_text_bytes(&function.name)?)?;
                    }
                    plan_add(&mut self.measured, plan_bytes_for::<Target<'_>>(1)?)?;
                    plan_add(&mut self.measured, plan_tree_bytes::<AttachKey, ()>(1)?)?;
                    plan_add(
                        &mut self.measured,
                        plan_tree_bytes::<(String, PinnedObjectId, u64, usize), ()>(1)?,
                    )?;
                    plan_add(
                        &mut self.measured,
                        plan_tree_bytes::<(String, PinnedObjectId, u64), usize>(1)?,
                    )?;
                    let mut reason = function
                        .name
                        .len()
                        .checked_add(manifest.module_path.len())
                        .and_then(|bytes| bytes.checked_add(128))
                        .ok_or(GraphRefusal::Overflow)?;
                    if let Resolution::UnusableFile { reason: cause, .. } = &function.resolution {
                        reason = reason
                            .checked_add(cause.len())
                            .ok_or(GraphRefusal::Overflow)?;
                    }
                    let reason = plan_byte_len(reason)?;
                    plan_add(&mut self.measured, plan_bytes_for::<Skipped>(5)?)?;
                    for _ in 0..5 {
                        plan_add(&mut self.measured, plan_text_bytes(&function.name)?)?;
                        plan_add(&mut self.measured, reason)?;
                    }
                    plan_add(
                        &mut self.measured,
                        plan_tree_bytes::<(String, String), usize>(1)?,
                    )?;
                    plan_add(
                        &mut self.measured,
                        plan_tree_bytes::<(&'static str, String, String, usize), ()>(1)?,
                    )?;
                    plan_add(
                        &mut self.measured,
                        plan_tree_bytes::<(&'static str, String, String, usize), ()>(1)?,
                    )?;
                }
                // The surface summary, three lives; label bytes from the
                // source records (walk/acquisition details are read, never
                // copied here).
                let (source_len, walk_len, acquisition_len) = manifest_surface_label_bytes(surface);
                for _ in 0..3 {
                    plan_add(&mut self.measured, plan_bytes_for::<SurfaceSummary>(1)?)?;
                    plan_add(&mut self.measured, plan_byte_len(source_len)?)?;
                    plan_add(&mut self.measured, plan_byte_len(walk_len)?)?;
                    plan_add(&mut self.measured, plan_byte_len(acquisition_len)?)?;
                }
                self.measure_surface += 1;
                Ok(false)
            }
            4 => {
                let next = match &self.measure_ordinals_after {
                    Some(after) => old.slot_ordinals.range((Excluded(after), Unbounded)).next(),
                    None => old.slot_ordinals.first_key_value(),
                };
                let Some((key, ordinals)) = next else {
                    self.measure_stage = 5;
                    self.measure_ordinals_after = None;
                    return Ok(false);
                };
                plan_add(
                    &mut self.measured,
                    plan_tree_bytes::<AttachKey, BTreeSet<SlotOrdinal>>(1)?,
                )?;
                plan_add(
                    &mut self.measured,
                    plan_tree_bytes::<SlotOrdinal, ()>(ordinals.len())?,
                )?;
                self.measure_ordinals_after = Some(*key);
                Ok(false)
            }
            5 => {
                let next = match &self.measure_identities_after {
                    Some(after) => old
                        .object_identities
                        .range((Excluded(after), Unbounded))
                        .next(),
                    None => old.object_identities.first_key_value(),
                };
                let Some((object, identity)) = next else {
                    self.measure_stage = 6;
                    self.measure_identities_after = None;
                    return Ok(false);
                };
                plan_add(
                    &mut self.measured,
                    plan_tree_bytes::<PinnedObjectId, TargetObject>(1)?,
                )?;
                if let Some(sha) = &identity.sha256 {
                    plan_add(&mut self.measured, plan_text_bytes(sha)?)?;
                }
                self.measure_identities_after = Some(*object);
                Ok(false)
            }
            6 => {
                let next = match &self.measure_provisional_after {
                    Some(after) => old
                        .provisional_get_function_list
                        .range((Excluded(after), Unbounded))
                        .next(),
                    None => old.provisional_get_function_list.first_key_value(),
                };
                let Some((key, _)) = next else {
                    self.measure_stage = 7;
                    self.measure_provisional_after = None;
                    return Ok(false);
                };
                plan_add(
                    &mut self.measured,
                    plan_tree_bytes::<AttachKey, PinnedObjectId>(1)?,
                )?;
                self.measure_provisional_after = Some(*key);
                Ok(false)
            }
            7 => {
                let Some((_, skip)) = old.refused_module_objects.get(self.measure_refused) else {
                    self.measure_stage = 8;
                    return Ok(false);
                };
                plan_add(
                    &mut self.measured,
                    plan_bytes_for::<(PinnedObjectId, Skipped)>(1)?,
                )?;
                plan_add(&mut self.measured, plan_text_bytes(&skip.subject)?)?;
                plan_add(&mut self.measured, plan_text_bytes(&skip.reason)?)?;
                self.measure_refused += 1;
                Ok(false)
            }
            8 => {
                let Some(skip) = old.modules_skipped.get(self.measure_skipped) else {
                    self.measure_stage = 9;
                    return Ok(false);
                };
                plan_add(&mut self.measured, plan_bytes_for::<Skipped>(1)?)?;
                plan_add(&mut self.measured, plan_text_bytes(&skip.subject)?)?;
                plan_add(&mut self.measured, plan_text_bytes(&skip.reason)?)?;
                self.measure_skipped += 1;
                Ok(false)
            }
            _ => {
                // Fixed tail: stack-resident shells need no charge; every heap
                // byte is covered per element above.
                self.required = Some(self.measured);
                self.phase = ConservativePlanPhase::Measured;
                Ok(false)
            }
        }
    }

    /// One skip's five lives: owned piece, dedup seen-set, occurrence
    /// within-map, module summary, and plan-level output.
    fn measure_skip_texts(&mut self, subject: &str, reason: &str) -> Result<(), GraphRefusal> {
        plan_add(&mut self.measured, plan_bytes_for::<Skipped>(5)?)?;
        for _ in 0..5 {
            plan_add(&mut self.measured, plan_text_bytes(subject)?)?;
            plan_add(&mut self.measured, plan_text_bytes(reason)?)?;
        }
        plan_add(
            &mut self.measured,
            plan_tree_bytes::<(String, String), usize>(1)?,
        )?;
        plan_add(
            &mut self.measured,
            plan_tree_bytes::<(&'static str, String, String, usize), ()>(1)?,
        )?;
        plan_add(
            &mut self.measured,
            plan_tree_bytes::<(&'static str, String, String, usize), ()>(1)?,
        )?;
        Ok(())
    }

    fn reserve_one(&mut self, reserve: &SemanticResourceReserver) -> Result<bool, GraphRefusal> {
        let required = self.required.expect("measured before reserve");
        match reserve.reserve(required) {
            Ok(lease) => {
                self.storage = Some(lease);
                // The removal index, preallocated from the measure (upper
                // bound: every old slot).
                self.output_removed = Vec::with_capacity(self.measured_slots);
                self.phase = ConservativePlanPhase::Lower;
                Ok(false)
            }
            Err(refusal) => Err(GraphRefusal::Storage(refusal)),
        }
    }

    /// One lowering unit: one source piece through the shared lowering,
    /// converted to owned form. Piece lowering is O(piece) per unit (one
    /// view's single-object decode); every per-row step downstream is
    /// strided.
    fn lower_one(&mut self, source: &ConservativePlanSources<'_>) -> Result<bool, GraphRefusal> {
        if let Some(module) = source.modules.get(self.lower_source) {
            self.push_piece(own_piece(lower_scanned(module)));
            self.lower_source += 1;
            return Ok(false);
        }
        if let Some(manifest) = source.manifests.get(self.lower_manifest) {
            let (pinned_id, compatible) = pinned_manifest_lookups(source.pins);
            let (piece, orphaned) = lower_manifest(manifest, pinned_id, compatible);
            if let Some(piece) = piece {
                self.push_piece(own_piece(piece));
            }
            // Orphaned manifest skips are rare resolution failures; they move
            // to the plan tail after the group skips, in manifest order.
            self.manifest_orphaned.extend(orphaned);
            self.lower_manifest += 1;
            return Ok(false);
        }
        self.phase = ConservativePlanPhase::DrainKeys;
        Ok(false)
    }

    fn push_piece(&mut self, piece: OwnedPiece) {
        let index = self.pieces.len();
        let object = piece.object;
        self.groups
            .entry(object)
            .or_insert_with(|| {
                self.group_order.push(object);
                Vec::new()
            })
            .push(index);
        self.pieces.push(piece);
    }

    /// One live-key unit: one lowered row into the live set.
    fn drain_one_key(&mut self) -> Result<bool, GraphRefusal> {
        while let Some(piece) = self.pieces.get(self.drain_piece) {
            let next =
                piece
                    .count_targets
                    .get(self.drain_target)
                    .map(|(_, object, file_offset)| AttachKey {
                        object: *object,
                        file_offset: *file_offset,
                    });
            match next {
                Some(key) => {
                    self.live.insert(key);
                    self.drain_target += 1;
                    return Ok(false);
                }
                None => {
                    self.drain_piece += 1;
                    self.drain_target = 0;
                }
            }
        }
        self.phase = ConservativePlanPhase::RecordModules;
        Ok(false)
    }

    /// One remap-cache unit: one old module's identity triple plus its index
    /// and attribution entries.
    fn record_one_module(&mut self, old: &AttachPlan) -> Result<bool, GraphRefusal> {
        let Some(module) = old.modules.get(self.record_module) else {
            self.phase = ConservativePlanPhase::Replicate;
            return Ok(false);
        };
        self.old_modules.push(OldModuleInfo {
            id: module.id,
            object: module.object,
            path: module.path.clone(),
        });
        self.old_id_objects.insert(module.id, module.object);
        self.old_objects.insert(module.object);
        self.old_paths.insert(module.path.clone());
        self.record_module += 1;
        Ok(false)
    }

    /// One replication unit within the current group. Groups replicate in
    /// first-seen order; only already-admitted groups produce summaries (no
    /// growth at Q), while every group feeds the occurrence recount.
    fn replicate_one(
        &mut self,
        stable_id: &mut dyn FnMut(PinnedObjectId) -> Option<ModuleId>,
    ) -> Result<bool, GraphRefusal> {
        let Some(object) = self.group_order.get(self.replicate_group).copied() else {
            // All groups done: orphaned manifest skips tail the plan skips.
            if self.orphan_idx < self.manifest_orphaned.len() {
                let skip = self.manifest_orphaned[self.orphan_idx].clone();
                self.output_skipped.push(skip);
                self.orphan_idx += 1;
                return Ok(false);
            }
            self.phase = ConservativePlanPhase::Derive;
            return Ok(false);
        };
        match self.replicate_step {
            0 => {
                self.counter.clear();
                self.piece_tables.clear();
                self.piece_surfaces.clear();
                self.piece_skip_occurrences.clear();
                if !self.old_objects.contains(&object) {
                    // Growth refused: the group feeds only the recount.
                    self.replicate_count_only = true;
                    self.replicate_step = 5;
                    self.replicate_piece = 0;
                    self.replicate_item = 0;
                    return Ok(false);
                }
                let Some(stable) = stable_id(object) else {
                    return Err(GraphRefusal::Identity);
                };
                self.stable_ids.insert(object, stable);
                let first = self
                    .groups
                    .get(&object)
                    .and_then(|pieces| pieces.first().copied())
                    .ok_or(GraphRefusal::Identity)?;
                let piece = self.pieces.get(first).ok_or(GraphRefusal::Identity)?;
                self.in_summary = Some(ModuleSummary {
                    id: stable,
                    object,
                    key: piece.key,
                    path: piece.path.clone(),
                    tables: Vec::new(),
                    interfaces: 0,
                    source: piece.source,
                    corroborated: false,
                    skipped: Vec::new(),
                });
                self.surviving_paths.insert(piece.path.clone());
                self.replicate_count_only = false;
                self.replicate_step = 1;
                self.replicate_piece = 0;
                self.replicate_item = 0;
                Ok(false)
            }
            1 => self.replicate_tables(object),
            2 => self.replicate_surfaces(object),
            3 => self.replicate_skips(object),
            4 => self.replicate_interfaces(object),
            5 => self.replicate_counts(object),
            _ => {
                self.entries_seen = self
                    .entries_seen
                    .checked_add(self.counter.count())
                    .ok_or(GraphRefusal::Overflow)?;
                if !self.replicate_count_only {
                    let summary = self.in_summary.take().ok_or(GraphRefusal::Identity)?;
                    self.output_modules.push(summary);
                }
                self.in_summary = None;
                self.seen_tables.clear();
                self.seen_surfaces.clear();
                self.seen_skips.clear();
                self.replicate_count_only = false;
                self.replicate_group += 1;
                self.replicate_step = 0;
                self.replicate_piece = 0;
                self.replicate_item = 0;
                Ok(false)
            }
        }
    }

    /// The current group's piece at position, or `None` once exhausted.
    fn group_piece(
        &self,
        object: PinnedObjectId,
        position: usize,
    ) -> Result<Option<usize>, GraphRefusal> {
        self.groups
            .get(&object)
            .ok_or(GraphRefusal::Identity)
            .map(|pieces| pieces.get(position).copied())
    }

    /// One table unit: merge's per-piece table dedup, verbatim.
    fn replicate_tables(&mut self, object: PinnedObjectId) -> Result<bool, GraphRefusal> {
        let piece_idx = self.group_piece(object, self.replicate_piece)?;
        let Some(piece_idx) = piece_idx else {
            self.replicate_step = 2;
            self.replicate_piece = 0;
            self.replicate_item = 0;
            return Ok(false);
        };
        let piece = self.pieces.get(piece_idx).ok_or(GraphRefusal::Identity)?;
        let Some(table) = piece.tables.get(self.replicate_item) else {
            self.piece_tables.clear();
            self.replicate_piece += 1;
            self.replicate_item = 0;
            return Ok(false);
        };
        let (source, table) = (piece.source, table.clone());
        let occurrence = self
            .piece_tables
            .iter()
            .filter(|known| *known == &table)
            .count();
        self.piece_tables.push(table.clone());
        if !self
            .seen_tables
            .iter()
            .any(|(known_source, known, known_occurrence)| {
                *known_source == source && known == &table && *known_occurrence == occurrence
            })
        {
            self.seen_tables.push((source, table.clone(), occurrence));
            self.in_summary
                .as_mut()
                .ok_or(GraphRefusal::Identity)?
                .tables
                .push(table);
        }
        self.replicate_item += 1;
        Ok(false)
    }

    /// One surface unit: merge's per-piece surface dedup, verbatim; accepted
    /// surfaces also tail the plan surfaces.
    fn replicate_surfaces(&mut self, object: PinnedObjectId) -> Result<bool, GraphRefusal> {
        let piece_idx = self.group_piece(object, self.replicate_piece)?;
        let Some(piece_idx) = piece_idx else {
            self.replicate_step = 3;
            self.replicate_piece = 0;
            self.replicate_item = 0;
            return Ok(false);
        };
        let piece = self.pieces.get(piece_idx).ok_or(GraphRefusal::Identity)?;
        let Some(surface) = piece.surfaces.get(self.replicate_item) else {
            self.piece_surfaces.clear();
            self.replicate_piece += 1;
            self.replicate_item = 0;
            return Ok(false);
        };
        let (source, surface) = (piece.source, surface.clone());
        let occurrence = self
            .piece_surfaces
            .iter()
            .filter(|known| *known == &surface)
            .count();
        self.piece_surfaces.push(surface.clone());
        if !self
            .seen_surfaces
            .iter()
            .any(|(known_source, known, known_occurrence)| {
                *known_source == source && known == &surface && *known_occurrence == occurrence
            })
        {
            self.seen_surfaces
                .push((source, surface.clone(), occurrence));
            self.output_surfaces.push(surface);
        }
        self.replicate_item += 1;
        Ok(false)
    }

    /// One skip unit: merge's per-piece skip dedup, verbatim; accepted skips
    /// land both in the module summary and at the plan tail.
    fn replicate_skips(&mut self, object: PinnedObjectId) -> Result<bool, GraphRefusal> {
        let piece_idx = self.group_piece(object, self.replicate_piece)?;
        let Some(piece_idx) = piece_idx else {
            self.replicate_step = 4;
            self.replicate_piece = 0;
            self.replicate_item = 0;
            return Ok(false);
        };
        let piece = self.pieces.get(piece_idx).ok_or(GraphRefusal::Identity)?;
        let Some(skip) = piece.skipped.get(self.replicate_item) else {
            self.piece_skip_occurrences.clear();
            self.replicate_piece += 1;
            self.replicate_item = 0;
            return Ok(false);
        };
        let (source, skip) = (piece.source, skip.clone());
        let record = (skip.subject.clone(), skip.reason.clone());
        let occurrence = *self
            .piece_skip_occurrences
            .entry(record.clone())
            .or_insert(0usize);
        if self
            .seen_skips
            .insert((source, record.0.clone(), record.1.clone(), occurrence))
        {
            self.in_summary
                .as_mut()
                .ok_or(GraphRefusal::Identity)?
                .skipped
                .push(skip.clone());
            self.output_skipped.push(skip);
        }
        *self.piece_skip_occurrences.entry(record).or_insert(0usize) += 1;
        self.replicate_item += 1;
        Ok(false)
    }

    /// One interface unit: the summary keeps the most any one source saw,
    /// never the sum across sources.
    fn replicate_interfaces(&mut self, object: PinnedObjectId) -> Result<bool, GraphRefusal> {
        let piece_idx = self.group_piece(object, self.replicate_piece)?;
        let Some(piece_idx) = piece_idx else {
            self.replicate_step = 5;
            self.replicate_piece = 0;
            self.replicate_item = 0;
            return Ok(false);
        };
        let interfaces = self
            .pieces
            .get(piece_idx)
            .ok_or(GraphRefusal::Identity)?
            .interfaces;
        let summary = self.in_summary.as_mut().ok_or(GraphRefusal::Identity)?;
        summary.interfaces = summary.interfaces.max(interfaces);
        self.replicate_piece += 1;
        Ok(false)
    }

    /// One recount unit: occurrence-deduped decoded counts for the group,
    /// fed through the shared counter.
    fn replicate_counts(&mut self, object: PinnedObjectId) -> Result<bool, GraphRefusal> {
        let piece_idx = self.group_piece(object, self.replicate_piece)?;
        let Some(piece_idx) = piece_idx else {
            self.replicate_step = 6;
            self.replicate_piece = 0;
            self.replicate_item = 0;
            return Ok(false);
        };
        let piece = self.pieces.get(piece_idx).ok_or(GraphRefusal::Identity)?;
        if let Some((name, target_object, file_offset)) =
            piece.count_targets.get(self.replicate_item)
        {
            let (name, target_object, file_offset) = (name.clone(), *target_object, *file_offset);
            self.counter
                .feed_target(&mut self.within_targets, name, target_object, file_offset);
            self.replicate_item += 1;
            return Ok(false);
        }
        let skip_idx = self.replicate_item - piece.count_targets.len();
        if let Some(skip) = piece.skipped.get(skip_idx) {
            let (source, subject, reason) =
                (piece.source, skip.subject.clone(), skip.reason.clone());
            self.counter
                .feed_skip(&mut self.within_skips, source, subject, reason);
            self.replicate_item += 1;
            return Ok(false);
        }
        self.within_targets.clear();
        self.within_skips.clear();
        self.replicate_piece += 1;
        self.replicate_item = 0;
        Ok(false)
    }

    /// One derive unit: one old slot. A slot survives exactly when its key
    /// is still yielded by the surviving sources and it was not already
    /// retired, or when it is a retained provisional seed. Surviving slots
    /// keep their content and index with retired claimers remapped away;
    /// retired slots stay in place with unchanged content, exactly like the
    /// reference extend.
    fn derive_one_slot(&mut self, old: &AttachPlan) -> Result<bool, GraphRefusal> {
        let Some(old_slot) = old.slots.get(self.derive_slot) else {
            self.phase = ConservativePlanPhase::CopyMaps;
            return Ok(false);
        };
        let index = self.derive_slot;
        let key = AttachKey::of(old_slot);
        let was_retired = old.retired_slots.contains(&index);
        let retained_provisional = !was_retired
            && old
                .provisional_get_function_list
                .get(&key)
                .is_some_and(|object| self.stable_ids.contains_key(object));
        let live = self.live.contains(&key);
        let owner = old
            .aggregate_owners
            .get(index)
            .copied()
            .ok_or(GraphRefusal::Identity)?;
        if (live || retained_provisional) && !was_retired {
            let mut slot = old_slot.clone();
            let mut ids = Vec::with_capacity(old_slot.module_ids.len());
            for id in &old_slot.module_ids {
                match self
                    .old_id_objects
                    .get(id)
                    .and_then(|object| self.stable_ids.get(object))
                {
                    Some(stable) => ids.push(*stable),
                    None if self.old_id_objects.contains_key(id) => {
                        // Retired claimer: the rebuilt plan lacks it.
                    }
                    None => ids.push(*id),
                }
            }
            slot.module_ids = ids;
            // Extend's two owner merges, verbatim.
            let owner = owner
                .merge(AggregateOwner::from_module_ids(&old_slot.module_ids))
                .merge(AggregateOwner::from_module_ids(&slot.module_ids));
            self.ambiguous_count += usize::from(owner == AggregateOwner::Ambiguous);
            self.output_slot_by_key.insert(key, index);
            self.output_owners.push(owner);
            self.output_slots.push(slot);
        } else {
            let owner = owner.merge(AggregateOwner::from_module_ids(&old_slot.module_ids));
            self.ambiguous_count += usize::from(owner == AggregateOwner::Ambiguous);
            self.output_owners.push(owner);
            self.output_slots.push(old_slot.clone());
            self.output_retired.insert(index);
            if !was_retired {
                self.retired_by_cursor.insert(index);
            }
        }
        self.derive_slot += 1;
        Ok(false)
    }

    /// One carried-map unit. Ordinals and object identities only grow, so the
    /// old maps carry over whole; provisionals and refusals survive exactly
    /// when their object does; historical module skips drop only entries
    /// provably tied to retired modules.
    fn copy_one_map_entry(&mut self, old: &AttachPlan) -> Result<bool, GraphRefusal> {
        match self.copy_stage {
            0 => {
                let next = next_after(&old.slot_ordinals, &self.copy_key);
                let Some((key, ordinals)) = next else {
                    self.copy_stage = 1;
                    self.copy_key = None;
                    return Ok(false);
                };
                self.copy_key = Some(key);
                self.output_ordinals.insert(key, ordinals);
                Ok(false)
            }
            1 => {
                let next = next_after(&old.object_identities, &self.copy_object);
                let Some((object, identity)) = next else {
                    self.copy_stage = 2;
                    self.copy_object = None;
                    return Ok(false);
                };
                self.copy_object = Some(object);
                self.output_identities.insert(object, identity);
                Ok(false)
            }
            2 => {
                let next = next_after(&old.provisional_get_function_list, &self.copy_provisional);
                let Some((key, object)) = next else {
                    self.copy_stage = 3;
                    self.copy_provisional = None;
                    return Ok(false);
                };
                self.copy_provisional = Some(key);
                if self.stable_ids.contains_key(&object) {
                    self.output_provisional.insert(key, object);
                }
                Ok(false)
            }
            3 => {
                let Some((object, skip)) = old.refused_module_objects.get(self.copy_index) else {
                    self.copy_stage = 4;
                    self.copy_index = 0;
                    return Ok(false);
                };
                if self.stable_ids.contains_key(object) {
                    self.output_refused.push((*object, skip.clone()));
                }
                self.copy_index += 1;
                Ok(false)
            }
            _ => {
                let Some(skip) = old.modules_skipped.get(self.copy_index) else {
                    self.phase = ConservativePlanPhase::Retire;
                    self.copy_index = 0;
                    return Ok(false);
                };
                // Only refusals attributable to a retired module drop;
                // unattributed entries are evidence and stay.
                let retired_module = self.old_paths.contains(&skip.subject)
                    && !self.surviving_paths.contains(&skip.subject);
                if !retired_module {
                    self.output_modules_skipped.push(skip.clone());
                }
                self.copy_index += 1;
                Ok(false)
            }
        }
    }

    /// One retire unit: removed indices leave in ascending slot order, delta
    /// retire rows in rebuilt key order.
    fn retire_one(&mut self, old: &AttachPlan) -> Result<bool, GraphRefusal> {
        if self.retire_slot < old.slots.len() {
            if self.retired_by_cursor.contains(&self.retire_slot) {
                self.output_removed.push(self.retire_slot as u32);
            }
            self.retire_slot += 1;
            return Ok(false);
        }
        let next = next_after(&old.slot_by_key, &self.retire_key);
        match next {
            Some((key, position)) => {
                self.retire_key = Some(key);
                if self.retired_by_cursor.contains(&position) {
                    let slot = old
                        .slots
                        .get(position)
                        .ok_or(GraphRefusal::Identity)?
                        .clone();
                    self.output_retire.push(slot);
                }
                Ok(false)
            }
            None => {
                self.assemble(old);
                self.phase = ConservativePlanPhase::Ready;
                Ok(true)
            }
        }
    }

    /// Moves the derived pieces into the output plan. All moves are O(1);
    /// scalars come from the old plan or the derivation. Uncorroborated
    /// spill is exact under broad admit (broad never spills, so the rebuilt
    /// count is zero) and carried otherwise; the capture-concurrency
    /// counters, policy and scope are the old plan's, exactly as the
    /// reference extend leaves them.
    fn assemble(&mut self, old: &AttachPlan) {
        let mut out = AttachPlan::empty_like(old.admission_policy, old.admission_scope);
        out.slots = std::mem::take(&mut self.output_slots);
        out.modules = std::mem::take(&mut self.output_modules);
        out.skipped = std::mem::take(&mut self.output_skipped);
        out.modules_skipped = std::mem::take(&mut self.output_modules_skipped);
        out.refused_module_objects = std::mem::take(&mut self.output_refused);
        out.surfaces = std::mem::take(&mut self.output_surfaces);
        out.slot_by_key = std::mem::take(&mut self.output_slot_by_key);
        out.provisional_get_function_list = std::mem::take(&mut self.output_provisional);
        out.slot_ordinals = std::mem::take(&mut self.output_ordinals);
        out.object_identities = std::mem::take(&mut self.output_identities);
        out.retired_slots = std::mem::take(&mut self.output_retired);
        out.aggregate_owners = std::mem::take(&mut self.output_owners);
        out.entries_seen = self.entries_seen;
        out.module_ambiguous = self.ambiguous_count;
        out.vendor_interfaces = old.vendor_interfaces;
        out.interface_list = old.interface_list.clone();
        out.counter_consumed_end = old.counter_consumed_end;
        out.uncorroborated_candidates = if self.broad_admit {
            0
        } else {
            old.uncorroborated_candidates
        };
        self.output = Some(out);
        self.delta = Some(AttachDelta {
            new: Vec::new(),
            replace: Vec::new(),
            retire: std::mem::take(&mut self.output_retire),
        });
    }
}

impl ConservativePlanCursor {
    fn drain_vec<T>(vec: &mut Vec<T>) -> bool {
        vec.pop().is_none()
    }

    fn drain_map<K: Ord, V>(map: &mut BTreeMap<K, V>) -> bool {
        map.pop_first().is_none()
    }

    fn drain_set<T: Ord>(set: &mut BTreeSet<T>) -> bool {
        set.pop_first().is_none()
    }

    // consumed by T4: installs the Ready output into the canonical plan.
    #[allow(dead_code)]
    pub(crate) fn swap_ready(
        &mut self,
        canonical: &mut AttachPlan,
    ) -> Result<InstalledPlanBacking, GraphRefusal> {
        if self.phase == ConservativePlanPhase::Cancelled {
            return Err(GraphRefusal::Cancelled);
        }
        if self.phase != ConservativePlanPhase::Ready {
            return Err(GraphRefusal::Identity);
        }
        let mut output = self.output.take().ok_or(GraphRefusal::Identity)?;
        std::mem::swap(&mut output, canonical);
        self.old = Some(output);
        self.phase = ConservativePlanPhase::Installed;
        Ok(InstalledPlanBacking {
            output: self.storage.take(),
            header: None,
        })
    }

    // consumed by T4: drops derived leaves one per credit after install or refusal.
    #[allow(dead_code)]
    pub(crate) fn reclaim(&mut self, work: usize) -> Result<GraphStep, GraphRefusal> {
        if work == 0 {
            return Ok(GraphStep::Yielded);
        }
        if self.phase == ConservativePlanPhase::Reclaimed {
            return Ok(GraphStep::Ready);
        }
        self.phase = ConservativePlanPhase::Reclaim;
        for _ in 0..work {
            if self.reclaim_one() {
                self.phase = ConservativePlanPhase::Reclaimed;
                return Ok(GraphStep::Ready);
            }
        }
        Ok(GraphStep::Advanced)
    }

    // consumed by T4: abandons the derivation; drops nothing.
    #[allow(dead_code)]
    pub(crate) fn cancel(&mut self) {
        self.phase = ConservativePlanPhase::Cancelled;
    }

    /// One reclaim leaf. Returns `true` once nothing remains.
    fn reclaim_one(&mut self) -> bool {
        match self.reclaim_step {
            0 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_vec(&mut plan.slots),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            1 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_vec(&mut plan.modules),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            2 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_vec(&mut plan.skipped),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            3 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_vec(&mut plan.modules_skipped),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            4 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_vec(&mut plan.surfaces),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            5 => {
                if let Some(plan) = self.output.as_mut().or(self.old.as_mut()) {
                    plan.aggregate_owners = Vec::new();
                }
                self.reclaim_step += 1;
                false
            }
            6 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_map(&mut plan.slot_by_key),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            7 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_set(&mut plan.retired_slots),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            8 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_map(&mut plan.slot_ordinals),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            9 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_map(&mut plan.object_identities),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            10 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_map(&mut plan.provisional_get_function_list),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            11 => {
                let done = match self.output.as_mut().or(self.old.as_mut()) {
                    Some(plan) => Self::drain_vec(&mut plan.refused_module_objects),
                    None => true,
                };
                if done {
                    self.reclaim_step += 1;
                }
                false
            }
            12 => {
                if let Some(plan) = self.output.as_mut().or(self.old.as_mut()) {
                    plan.interface_list = String::new();
                }
                self.output = None;
                self.old = None;
                self.reclaim_step += 1;
                false
            }
            13 => {
                if Self::drain_vec(&mut self.output_slots) {
                    self.reclaim_step += 1;
                }
                false
            }
            14 => {
                if Self::drain_vec(&mut self.output_modules) {
                    self.reclaim_step += 1;
                }
                false
            }
            15 => {
                if Self::drain_vec(&mut self.output_skipped) {
                    self.reclaim_step += 1;
                }
                false
            }
            16 => {
                if Self::drain_vec(&mut self.output_modules_skipped) {
                    self.reclaim_step += 1;
                }
                false
            }
            17 => {
                if Self::drain_vec(&mut self.output_surfaces) {
                    self.reclaim_step += 1;
                }
                false
            }
            18 => {
                self.output_owners = Vec::new();
                self.reclaim_step += 1;
                false
            }
            19 => {
                if Self::drain_map(&mut self.output_slot_by_key) {
                    self.reclaim_step += 1;
                }
                false
            }
            20 => {
                if Self::drain_set(&mut self.output_retired) {
                    self.reclaim_step += 1;
                }
                false
            }
            21 => {
                if Self::drain_map(&mut self.output_ordinals) {
                    self.reclaim_step += 1;
                }
                false
            }
            22 => {
                if Self::drain_map(&mut self.output_identities) {
                    self.reclaim_step += 1;
                }
                false
            }
            23 => {
                if Self::drain_map(&mut self.output_provisional) {
                    self.reclaim_step += 1;
                }
                false
            }
            24 => {
                if Self::drain_vec(&mut self.output_refused) {
                    self.reclaim_step += 1;
                }
                false
            }
            25 => {
                match self.delta.as_mut() {
                    Some(delta) => {
                        if delta.retire.pop().is_none() {
                            delta.new = Vec::new();
                            delta.replace = Vec::new();
                            self.delta = None;
                            self.reclaim_step += 1;
                        }
                    }
                    None => self.reclaim_step += 1,
                }
                false
            }
            26 => {
                self.output_removed = Vec::new();
                self.reclaim_step += 1;
                false
            }
            27 => {
                if Self::drain_vec(&mut self.output_retire) {
                    self.reclaim_step += 1;
                }
                false
            }
            28 => {
                if Self::drain_set(&mut self.live) {
                    self.reclaim_step += 1;
                }
                false
            }
            29 => {
                if Self::drain_vec(&mut self.pieces) {
                    self.reclaim_step += 1;
                }
                false
            }
            30 => {
                if Self::drain_map(&mut self.groups) {
                    self.reclaim_step += 1;
                }
                false
            }
            31 => {
                self.group_order = Vec::new();
                self.reclaim_step += 1;
                false
            }
            32 => {
                if Self::drain_vec(&mut self.manifest_orphaned) {
                    self.reclaim_step += 1;
                }
                false
            }
            33 => {
                if Self::drain_vec(&mut self.old_modules) {
                    self.reclaim_step += 1;
                }
                false
            }
            34 => {
                if Self::drain_map(&mut self.old_id_objects) {
                    self.reclaim_step += 1;
                }
                false
            }
            35 => {
                if Self::drain_set(&mut self.old_objects) {
                    self.reclaim_step += 1;
                }
                false
            }
            36 => {
                if Self::drain_set(&mut self.old_paths) {
                    self.reclaim_step += 1;
                }
                false
            }
            37 => {
                if Self::drain_set(&mut self.surviving_paths) {
                    self.reclaim_step += 1;
                }
                false
            }
            38 => {
                if Self::drain_map(&mut self.stable_ids) {
                    self.reclaim_step += 1;
                }
                false
            }
            39 => {
                if Self::drain_set(&mut self.retired_by_cursor) {
                    self.reclaim_step += 1;
                }
                false
            }
            40 => {
                let done = match self.in_summary.as_mut() {
                    Some(summary) => {
                        if summary.tables.pop().is_none() {
                            summary.skipped.pop().is_none()
                        } else {
                            false
                        }
                    }
                    None => true,
                };
                if done {
                    self.in_summary = None;
                    self.reclaim_step += 1;
                }
                false
            }
            41 => {
                if Self::drain_vec(&mut self.piece_surfaces) {
                    self.reclaim_step += 1;
                }
                false
            }
            42 => {
                if Self::drain_vec(&mut self.seen_surfaces) {
                    self.reclaim_step += 1;
                }
                false
            }
            43 => {
                self.piece_tables = Vec::new();
                self.seen_tables = Vec::new();
                self.reclaim_step += 1;
                false
            }
            44 => {
                if Self::drain_map(&mut self.piece_skip_occurrences) {
                    self.reclaim_step += 1;
                }
                false
            }
            45 => {
                if Self::drain_set(&mut self.seen_skips) {
                    self.reclaim_step += 1;
                }
                false
            }
            46 => {
                if Self::drain_set(&mut self.counter.targets) {
                    self.reclaim_step += 1;
                }
                false
            }
            47 => {
                if Self::drain_set(&mut self.counter.skips) {
                    self.reclaim_step += 1;
                }
                false
            }
            48 => {
                if Self::drain_map(&mut self.within_targets) {
                    self.reclaim_step += 1;
                }
                false
            }
            49 => {
                if Self::drain_map(&mut self.within_skips) {
                    self.reclaim_step += 1;
                }
                false
            }
            _ => {
                self.storage.take();
                true
            }
        }
    }
}

/// Upper-bound label bytes for one manifest surface summary, read from the
/// source records without allocating.
// consumed by T4: used only by the cursor measure phase.
#[allow(dead_code)]
fn manifest_surface_label_bytes(
    surface: &p11scope_manifest::manifest::SurfaceRecord,
) -> (usize, usize, usize) {
    let source = match &surface.source {
        SurfaceSource::LegacyFunctionList => "legacy_function_list".len(),
        SurfaceSource::Interface { .. } => 48,
    };
    let walk = match &surface.walk {
        WalkOutcome::Unreadable { detail } => detail.len().checked_add(16),
        _ => Some(16),
    };
    let acquisition = match &surface.acquisition {
        Acquisition::Error { detail } => detail.len().checked_add(16),
        _ => Some(16),
    };
    (
        source,
        walk.unwrap_or(usize::MAX),
        acquisition.unwrap_or(usize::MAX),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::scan::ScannedModule;
    use crate::process::{MountNamespaceId, ProcessViewId};
    use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
    use p11scope_manifest::manifest::*;

    #[test]
    fn borrowed_projection_metadata_matches_exact_lookups_and_empty_twins() {
        let mut plan =
            build_from_reconciled_modules(&[scanned_with(TEST_OBJECT, "/owned.so", [0x10])]);
        let slot = plan.slots[0].clone();
        plan.object_identities.insert(
            slot.object,
            TargetObject {
                dev: (8, 1),
                ino: 42,
                sha256: Some("11".repeat(32)),
            },
        );
        let ordinals: Vec<_> = plan.borrowed_ordinals_of(&slot).collect();
        assert_eq!(ordinals, plan.ordinals_of(&slot));
        assert!(!ordinals.is_empty());
        assert_eq!(plan.ordinal_count(&slot), ordinals.len());
        assert!(std::ptr::eq(
            plan.borrowed_target_object_of(&slot).unwrap(),
            plan.object_identities.get(&slot.object).unwrap(),
        ));
        let mut absent = slot.clone();
        absent.file_offset += 1;
        assert_eq!(plan.ordinal_count(&absent), 0);
        assert_eq!(plan.borrowed_ordinals_of(&absent).count(), 0);
        absent.object = PinnedObjectId(u32::MAX);
        assert!(plan.borrowed_target_object_of(&absent).is_none());
    }

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
            selection_evidence: SelectionEvidence::default(),
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
            exports: Default::default(),
            object,
            entry_objects: vec![vec![object; entries.len()]],
            scanned: ScannedModule {
                mapped_identity: None,
                double_loaded: false,
                view: ProcessViewId(0),
                mount_namespace: MountNamespaceId {
                    device: 1,
                    inode: 1,
                },
                key,
                path: path.into(),
                decoder_abi: Some(p11scope_manifest::elf::ElfAbi::Lp64),
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

    #[test]
    fn native_short_prefix_without_bad_targets_remains_semantically_incomplete() {
        for words in [0, 1, 3, 67] {
            let mut module = scanned_with(
                TEST_OBJECT,
                "/opt/p11.so",
                if words == 0 { vec![] } else { vec![0x10] },
            );
            let table = &mut module.scanned.tables[0];
            for entry in &mut table.entries {
                entry.name = "C_Initialize";
            }
            table.walk = "known_prefix";
            table.live_return = true;
            table.null_entries = pkcs11_module::FUNCTION_LIST_FIELDS
                .iter()
                .take(words)
                .skip(1)
                .map(|field| field.name)
                .collect();
            assert!(table.unpinned.is_empty());
            let plan = build_from_reconciled_modules(std::slice::from_ref(&module));
            assert_eq!(plan.slots.len(), usize::from(words > 0));
            assert_eq!(plan.entries_seen, words);
            assert!(plan.slots.iter().all(|slot| !slot.semantic_authorized));
            let claims =
                semantic_source_claims(std::slice::from_ref(&module), &[], &PinnedObjects::empty());
            assert!(
                claims.incomplete.contains(&module.object),
                "{words} observed words cannot prove the missing tail"
            );
            if words > 0 {
                assert_eq!(plan.slots[0].names, ["C_Initialize"]);
                assert!(claims.providers[&module.object].contains(&AttachKey {
                    object: module.object,
                    file_offset: 0x10,
                }));
            }
        }
    }

    #[test]
    fn native_complete_all_null_inventory_remains_a_complete_empty_observation() {
        for version in [(2, 40), (3, 0), (3, 1), (3, 2), (4, 19)] {
            let mut module = scanned_with(TEST_OBJECT, "/opt/p11.so", []);
            let table = &mut module.scanned.tables[0];
            table.live_return = true;
            table.version = version;
            table.null_entries = pkcs11_module::FUNCTION_LIST_FIELDS
                .iter()
                .map(|field| field.name)
                .collect();
            let plan = build_from_reconciled_modules(std::slice::from_ref(&module));
            assert!(plan.slots.is_empty());
            assert_eq!(plan.entries_seen, 68);
            let claims = semantic_source_claims(&[module], &[], &PinnedObjects::empty());
            assert!(claims.incomplete.is_empty());
        }
    }

    fn pinnable_null_manifest() -> Manifest {
        let path = "/bin/true";
        let file = p11scope_manifest::identity::open_object(std::path::Path::new(path)).unwrap();
        let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let identity = p11scope_manifest::identity::inspect_file(&file)
            .unwrap()
            .identity;
        let mut manifest = manifest_with(
            pkcs11_module::FUNCTION_LIST_FIELDS
                .iter()
                .map(|field| rec(field.name, Resolution::NullPointer))
                .collect(),
        );
        manifest.module_path = path.into();
        manifest.objects[0].path = path.into();
        manifest.objects[0].identity = identity.clone();
        manifest.provenance_objects[0] = ProvenanceObject {
            path: path.into(),
            device_major: key.device_major,
            device_minor: key.device_minor,
            inode: key.inode,
            identity,
        };
        manifest.surfaces[0].version = Some(Version {
            major: 2,
            minor: 40,
        });
        manifest
    }

    #[test]
    fn normalized_historical_full_prefix_has_partial_walk_and_no_complete_authority() {
        let mut manifest = pinnable_null_manifest();
        let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
        manifest.surfaces[0].version = Some(Version { major: 2, minor: 0 });
        manifest.surfaces[0].functions.truncate(67);
        let plan = build_from_sources(&[], std::slice::from_ref(&manifest), &pins);
        assert_eq!(plan.surfaces[0].walk, "known_prefix");
        assert_eq!(plan.entries_seen, 67);
        assert!(!crate::manifest_input::selection_surface_usable(
            &manifest.surfaces[0]
        ));
        let claims = semantic_source_claims(&[], &[manifest], &pins);
        assert_eq!(claims.incomplete.len(), 1);
    }

    #[test]
    fn normalized_header_uncertainty_does_not_invent_missing_function_demand() {
        let mut manifest = pinnable_null_manifest();
        let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
        manifest.surfaces[0].version = None;
        manifest.surfaces[0].walk = WalkOutcome::Unreadable {
            detail: "version header unavailable".into(),
        };
        let claims = semantic_source_claims(&[], std::slice::from_ref(&manifest), &pins);
        assert!(
            claims.incomplete.is_empty(),
            "all 68 function words are observed"
        );
        assert!(!crate::manifest_input::selection_surface_usable(
            &manifest.surfaces[0]
        ));
        manifest.surfaces[0].functions.pop();
        let claims = semantic_source_claims(&[], &[manifest], &pins);
        assert_eq!(
            claims.incomplete.len(),
            1,
            "a missing function word remains unknown"
        );
    }

    #[test]
    fn manifest_missing_tail_prevents_provider_completeness_but_metadata_does_not() {
        let mut manifest = pinnable_null_manifest();
        manifest.surfaces[0].version = Some(Version {
            major: 0,
            minor: 255,
        });
        manifest.surfaces[0].walk = WalkOutcome::KnownPrefix;
        for interface in [false, true] {
            let mut manifest = manifest.clone();
            let surface_index = usize::from(interface);
            if interface {
                manifest.surfaces[0].source = SurfaceSource::Interface {
                    index: 0,
                    raw_name_hex: Some("504b4353203131".into()),
                    name_lossy: Some("PKCS 11".into()),
                    name_error: None,
                    flags: 0,
                    classification: InterfaceClassification::ExactStandard,
                };
                manifest.surfaces.insert(
                    0,
                    SurfaceRecord {
                        source: SurfaceSource::LegacyFunctionList,
                        acquisition: Acquisition::Absent,
                        version: None,
                        walk: WalkOutcome::NotWalked,
                        functions: vec![],
                    },
                );
                manifest.interface_list = Acquisition::Ok;
            }
            let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
            let claims = semantic_source_claims(&[], std::slice::from_ref(&manifest), &pins);
            assert!(
                claims.incomplete.is_empty(),
                "complete common inventory is independent of version metadata"
            );
            manifest.surfaces[surface_index].walk = WalkOutcome::Unreadable {
                detail: "slot 3 unavailable".into(),
            };
            manifest.surfaces[surface_index].functions.truncate(3);
            let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
            let claims = semantic_source_claims(&[], &[manifest], &pins);
            assert_eq!(
                claims.incomplete.len(),
                1,
                "observed NULLs cannot certify the unavailable tail"
            );
        }
    }

    fn scanned_with_heuristic_tables(count: usize) -> ReconciledModule {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let mut scanned = scanned_with(TEST_OBJECT, "/opt/heuristic.so", []);
        let object = scanned.object;
        scanned.scanned.tables = (0..count)
            .map(|index| ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![ScannedEntry {
                    name: "C_Sign",
                    object: TEST_OBJECT,
                    object_path: "/opt/heuristic.so".into(),
                    file_offset: index as u64 * 8,
                }],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000 + index as u64 * 0x1000,
                file_offset: Some(index as u64 * 0x1000),
                live_return: false,
                manifest_supported: false,
            })
            .collect();
        scanned.entry_objects = vec![vec![object]; count];
        scanned
    }

    fn inventory_policy(endpoint_limit: u64) -> AdmissionPolicy {
        AdmissionPolicy::inventory(
            crate::capacity::InventoryBudget::new(
                endpoint_limit,
                endpoint_limit.checked_mul(8).unwrap(),
            )
            .unwrap(),
        )
    }

    fn inventory_plan(
        slots: Vec<Slot>,
        modules: Vec<ModuleSummary>,
        endpoint_limit: u64,
    ) -> AttachPlan {
        let mut plan =
            AttachPlan::from_slots_with_policy(slots, inventory_policy(endpoint_limit)).unwrap();
        plan.modules = modules;
        plan.entries_seen = plan.slots.len();
        plan
    }

    fn object_slot(index: u32, names: &[&str], descriptor_index: u32) -> Slot {
        Slot {
            index,
            descriptor_index,
            object: PinnedObjectId(7),
            object_path: "/opt/p11.so".into(),
            file_offset: 0x1000 + u64::from(index),
            names: names.iter().map(|name| name.to_string()).collect(),
            aliased: names.len() >= 2,
            semantics: crate::kinds::DESCRIPTORS[descriptor_index as usize],
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![ModuleId(0)],
        }
    }

    fn object_plan(slots: Vec<Slot>) -> AttachPlan {
        AttachPlan::from_slots_with_policy(slots, AdmissionPolicy::Detailed).unwrap()
    }

    #[test]
    fn counter_policy_conversion_preserves_plan() {
        let mut detailed = object_plan(vec![
            object_slot(0, &["C_SignInit"], 43),
            object_slot(1, &["C_Sign"], 43),
            object_slot(2, &["C_Verify"], 43),
        ]);
        detailed.deactivate(1);
        let budget = crate::capacity::CounterBudget::new(8192).unwrap();
        let converted = detailed.with_counters_policy(budget).unwrap();
        assert!(matches!(
            converted.admission_policy(),
            AdmissionPolicy::Counters(budget) if budget.endpoint_limit() == 8192
        ));
        assert_eq!(converted.slots, detailed.slots);
        assert_eq!(converted.modules, detailed.modules);
        for index in 0..3 {
            assert_eq!(
                converted.is_active(index),
                detailed.is_active(index),
                "activity survives conversion"
            );
        }
        assert!(!converted.is_active(1));
        // Over-budget conversion refuses without mutating the source.
        let tight = crate::capacity::CounterBudget::new(2).unwrap();
        assert!(detailed.with_counters_policy(tight).is_err());
        assert!(matches!(
            detailed.admission_policy(),
            AdmissionPolicy::Detailed
        ));
    }

    #[test]
    fn counter_consumed_adoption_restores_staged_prefix() {
        let rebuilt = object_plan(vec![
            object_slot(0, &["C_SignInit"], 43),
            object_slot(1, &["C_Sign"], 43),
            object_slot(2, &["C_Verify"], 43),
        ]);
        let budget = crate::capacity::CounterBudget::new(8192).unwrap();
        let mut rebuilt = rebuilt.with_counters_policy(budget).unwrap();
        assert_eq!(rebuilt.counter_consumed_end(), 0);
        rebuilt.adopt_counter_consumed(2).unwrap();
        assert_eq!(rebuilt.counter_consumed_end(), 2);
        assert!(rebuilt.adopt_counter_consumed(4).is_err());
        assert_eq!(rebuilt.counter_consumed_end(), 2);
    }

    #[test]
    fn object_producer_plan_eligibility_requires_current_authority() {
        use ObjectSlotEligibility::{Eligible, Refused};
        let plan = object_plan(vec![object_slot(0, &["C_SignInit"], 43)]);
        assert_eq!(
            plan.object_slot_eligibility(0),
            Eligible {
                descriptor_index: 43
            }
        );
        // Missing slots and index/owner bookkeeping refuse without authority.
        assert!(matches!(
            plan.object_slot_eligibility(7),
            Refused {
                reason: SemanticRefusal::IncompleteProvider,
                ..
            }
        ));
        let mut moved = object_plan(vec![object_slot(0, &["C_SignInit"], 43)]);
        moved.slots[0].index = 5;
        assert!(matches!(
            moved.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::IncompleteProvider,
                ..
            }
        ));
        let mut unowned = object_plan(vec![object_slot(0, &["C_SignInit"], 43)]);
        unowned.slots[0].module_ids.clear();
        assert!(matches!(
            unowned.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::IncompleteProvider,
                ..
            }
        ));
        let mut rival = object_plan(vec![object_slot(0, &["C_SignInit"], 43)]);
        rival.slots[0].module_ids.push(ModuleId(1));
        assert!(matches!(
            rival.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                ..
            }
        ));
        // Attestation and S1 consistency gate before any protocol reading.
        let mut unattested = object_plan(vec![object_slot(0, &["C_SignInit"], 43)]);
        unattested.slots[0].semantic_authorized = false;
        assert!(matches!(
            unattested.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Unattested,
                ..
            }
        ));
        let mut vague = object_plan(vec![object_slot(0, &["C_SignInit"], 43)]);
        vague.slots[0].semantic_ambiguous = true;
        assert!(matches!(
            vague.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                ..
            }
        ));
        let mut drifted = object_plan(vec![object_slot(0, &["C_SignInit"], 43)]);
        drifted.slots[0].semantics = SlotSemantics::COUNT_ONLY;
        assert!(matches!(
            drifted.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                ..
            }
        ));
        let mut wild = object_plan(vec![object_slot(0, &["C_SignInit"], 43)]);
        wild.slots[0].descriptor_index = 105;
        assert!(matches!(
            wild.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                ..
            }
        ));
    }

    #[test]
    fn object_producer_plan_eligibility_refuses_count_only_none_and_ambiguous() {
        use crate::kinds::AliasAgreement;
        use ObjectSlotEligibility::{Eligible, Refused};
        // Eligible names never upgrade a frozen count-only slot.
        let plan = object_plan(vec![object_slot(0, &["C_CreateObject"], 0)]);
        assert!(matches!(
            plan.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                agreement: AliasAgreement::Agree,
            }
        ));
        // Ordinary functions carry no object protocol.
        let plan = object_plan(vec![object_slot(0, &["C_Sign"], 44)]);
        assert_eq!(
            plan.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                agreement: AliasAgreement::Agree,
            }
        );
        // S1 ambiguity, object disagreement and unknown names refuse.
        let plan = object_plan(vec![object_slot(0, &["C_SignInit", "C_VerifyInit"], 43)]);
        assert_eq!(
            plan.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                agreement: AliasAgreement::S1Ambiguous,
            }
        );
        let plan = object_plan(vec![object_slot(
            0,
            &["C_DestroyObject", "C_GetObjectSize"],
            23,
        )]);
        assert_eq!(
            plan.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                agreement: AliasAgreement::ObjectDisagree,
            }
        );
        let plan = object_plan(vec![object_slot(0, &["C_Nonexistent"], 43)]);
        assert_eq!(
            plan.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                agreement: AliasAgreement::S1Ambiguous,
            }
        );
        // Vacuous agreement on empty names grants nothing without a cookie.
        let plan = object_plan(vec![object_slot(0, &[], 0)]);
        assert!(matches!(
            plan.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                agreement: AliasAgreement::Agree,
            }
        ));
        // Control: the agreeing alias pair stays eligible.
        let plan = object_plan(vec![object_slot(
            0,
            &["C_VerifyInit", "C_VerifySignatureInit"],
            49,
        )]);
        assert_eq!(
            plan.object_slot_eligibility(0),
            Eligible {
                descriptor_index: 49
            }
        );
    }

    #[test]
    fn object_producer_plan_eligibility_preserves_frozen_cookie_and_rechecks_extensions() {
        use crate::kinds::AliasAgreement;
        use ObjectSlotEligibility::{Eligible, Refused};
        // An agreeing alias added by extension changes the lowest index,
        // but eligibility keeps the frozen cookie.
        let mut plan = object_plan(vec![object_slot(0, &["C_VerifySignatureInit"], 95)]);
        assert_eq!(
            plan.object_slot_eligibility(0),
            Eligible {
                descriptor_index: 95
            }
        );
        plan.slots[0].names.push("C_VerifyInit".into());
        assert_eq!(
            plan.object_slot_eligibility(0),
            Eligible {
                descriptor_index: 95
            }
        );
        // A disagreeing extension is rechecked and refused.
        plan.slots[0].names.push("C_SignInit".into());
        assert_eq!(
            plan.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                agreement: AliasAgreement::S1Ambiguous,
            }
        );
        // A cookie whose function left the names refuses.
        let plan = object_plan(vec![object_slot(0, &["C_VerifyInit"], 95)]);
        assert_eq!(
            plan.object_slot_eligibility(0),
            Refused {
                reason: SemanticRefusal::Descriptor,
                agreement: AliasAgreement::Agree,
            }
        );
    }

    #[test]
    fn scanned_interfaces_are_published_as_classified_surfaces() {
        use crate::discovery::scan::ScannedInterface;

        let mut scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10]);
        scanned.scanned.interfaces.push(ScannedInterface {
            index: 0,
            name_class: "exact_standard",
            name_lossy: None,
            name_private: None,
            flags: 0,
            table: Some(0),
        });

        let plan = build_from_test_sources(&[scanned], &[]);
        assert_eq!(plan.modules[0].interfaces, 1);
        assert_eq!(plan.surfaces.len(), 2);
        assert_eq!(plan.surfaces[1].source, "interface[0] exact_standard");
        assert_eq!(plan.surfaces[1].walk, "full");
        assert_eq!(plan.surfaces[1].acquisition, "ok");
        assert_eq!(plan.surfaces[1].functions, 1);
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
        // Task 1.3 mislabel guard: the unlinked table's ordinal label is a
        // positional guess, never presented as a PKCS#11 name.
        assert_eq!(plan.slots[0].names, ["unknown"]);
        assert_eq!(plan.slots[0].semantics, SlotSemantics::COUNT_ONLY);
        assert!(!plan.slots[0].semantic_authorized);
        assert!(
            plan.slots[0].semantic_ambiguous,
            "an unnamed slot cannot resolve one descriptor"
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
    fn unlinked_scan_label_is_not_a_rival_claim_against_the_manifest() {
        // Task 1.3: an unlinked table's ordinal label carries no information,
        // so it cannot dispute the manifest's operator-authoritative name —
        // `unknown` is transparent, never a rival claim.
        let scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10]);
        let manifest = manifest_with(vec![resolved("C_Login", 0x10)]);

        let plan = build_from_test_sources(
            std::slice::from_ref(&scanned),
            std::slice::from_ref(&manifest),
        );

        assert_eq!(plan.slots.len(), 1);
        assert_eq!(plan.slots[0].names, ["C_Login"]);
        assert!(plan.slots[0].semantic_authorized);
        assert_eq!(
            plan.slots[0].semantics,
            crate::kinds::descriptor("C_Login").unwrap()
        );
        assert!(!plan.slots[0].semantic_ambiguous);
    }

    #[test]
    fn linked_scan_label_disputing_the_manifest_stays_count_only() {
        // The safety property the unlinked case retires survives where it has
        // teeth: two AUTHORIZED names disagreeing about one target stay
        // unresolvable, counted but never attributed.
        use crate::discovery::scan::ScannedInterface;

        let mut scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10]);
        scanned.scanned.interfaces.push(ScannedInterface {
            index: 0,
            name_class: "exact_standard",
            name_lossy: None,
            name_private: Some(b"PKCS 11".to_vec()),
            flags: 0,
            table: Some(0),
        });
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
            |_, _| true,
            ExistingAllocation {
                slots: 0,
                active: &BTreeMap::new(),
                owned: &BTreeMap::new(),
            },
            false,
            AdmissionPolicy::detailed(),
            AdmissionScope::Named,
        );

        assert_eq!(plan.slots.len(), 2, "distinct pinned objects stay distinct");
        let scan_slot = plan
            .slots
            .iter()
            .find(|slot| slot.object == scanned_object)
            .unwrap();
        assert_eq!(scan_slot.semantics, SlotSemantics::COUNT_ONLY);
        assert!(!scan_slot.semantic_authorized);
        // Task 1.3: the unlinked scan slot is unnamed, and an unnamed slot
        // cannot resolve one descriptor.
        assert_eq!(scan_slot.names, ["unknown"]);
        assert!(scan_slot.semantic_ambiguous);
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
    fn manifest_target_with_a_different_provider_abi_is_skipped() {
        let manifest = manifest_with(vec![resolved("C_Sign", 0x10)]);
        let plan = build_from_sources_with(
            &[],
            std::slice::from_ref(&manifest),
            |_, _| Some(PinnedObjectId(1)),
            |_, _| false,
            ExistingAllocation {
                slots: 0,
                active: &BTreeMap::new(),
                owned: &BTreeMap::new(),
            },
            false,
            AdmissionPolicy::detailed(),
            AdmissionScope::Named,
        );
        assert!(plan.slots.is_empty());
        assert_eq!(plan.entries_seen, 1);
        assert!(plan.skipped[0].reason.contains("different target ABI"));
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
        let m = manifest_with(vec![resolved("C_Initialize", 0x10)]);
        let p = build(&m);
        assert_eq!(p.surfaces.len(), 1);
        assert_eq!(p.surfaces[0].source, "legacy_function_list");
        assert_eq!(p.surfaces[0].walk, "known_prefix");
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
        let error = ensure_capacity(&make(MAX_SLOTS as usize + 1)).unwrap_err();
        assert!(error.contains(&format!("requires {}", MAX_SLOTS + 1)));
        assert!(error.contains(&format!("only {MAX_SLOTS}")));
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
        assert_eq!(
            p.entries_seen,
            MAX_SLOTS as usize + 1,
            "decoded occurrences survive refusal"
        );
        assert_eq!(p.modules_skipped.len(), 1);
        assert_eq!(p.modules_skipped[0].subject, "/opt/p11.so");
        assert!(
            p.modules_skipped[0]
                .reason
                .contains(&format!("{}", MAX_SLOTS + 1))
                && p.modules_skipped[0]
                    .reason
                    .contains(&format!("{MAX_SLOTS}")),
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
            name_private: Some(b"PKCS 11".to_vec()),
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
            scanned_with(
                TEST_OBJECT,
                "/opt/p11.so",
                (0..MAX_SLOTS + 1).map(|i| u64::from(i) * 8),
            ),
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
                .contains(&format!("module needs {} more", MAX_SLOTS + 1))
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
        let manifest = manifest_with(
            (0..u64::from(MAX_SLOTS + 1))
                .map(|i| resolved("C_Sign", i * 8))
                .collect(),
        );

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
                .contains(&format!("module needs {} more", MAX_SLOTS + 1))
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

    #[cfg(feature = "wide-detailed-2112")]
    #[test]
    fn wide_detailed_admits_all_2112_exact_targets_and_refuses_2113_whole() {
        let object = PinnedObjectId(7);
        let slots: Vec<_> = (0..2_113)
            .map(|index| exact_slot(index, object, u64::from(index) * 8, 0, vec![]))
            .collect();
        let admitted =
            AttachPlan::from_slots_with_policy(slots[..2_112].to_vec(), AdmissionPolicy::Detailed)
                .expect("all 2,112 distinct physical offsets must fit the wide profile");
        assert_eq!(admitted.slots.len(), 2_112);
        assert_eq!(admitted.slots[2_111].index, 2_111);
        let error = AttachPlan::from_slots_with_policy(slots, AdmissionPolicy::Detailed)
            .expect_err("2,113 endpoints must be refused before any attachment");
        assert!(error.contains("2113") && error.contains("2112"), "{error}");
    }

    fn provisional_plan(object: PinnedObjectId) -> AttachPlan {
        exact_plan(vec![], vec![exact_module(0, object)])
    }

    #[test]
    fn interface_only_helper_inventory_reaches_count_only_selection_plan() {
        let dir = tempfile::tempdir().unwrap();
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/discover/tests/fixture");
        let helper = dir.path().join("helper.so");
        let provider = dir.path().join("provider.so");
        assert!(
            std::process::Command::new("gcc")
                .args(["-shared", "-fPIC", "-Wl,-soname,helper.so", "-o"])
                .arg(&helper)
                .arg(fixtures.join("helper.c"))
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("gcc")
                .args(["-shared", "-fPIC", "-DINTERFACE_ONLY_FIXTURE=1", "-o"])
                .arg(&provider)
                .arg(fixtures.join("provider.c"))
                .arg(&helper)
                .arg(format!("-Wl,-rpath,{}", dir.path().display()))
                .status()
                .unwrap()
                .success()
        );
        let manifest = p11scope_discover::discover::discover(&provider).unwrap();
        assert_eq!(manifest.interface_list, Acquisition::Absent);
        assert_eq!(manifest.surfaces[0].acquisition, Acquisition::Absent);
        assert!(crate::manifest_input::validate_structure(&manifest).is_empty());
        let pins = crate::discovery::identity::pin_manifest_objects(&manifest).unwrap();
        let mut plan = build_from_sources(&[], std::slice::from_ref(&manifest), &pins);
        assert!(plan.slots.is_empty());
        assert_eq!(plan.modules.len(), 1);
        let allocated = plan.clone();
        for (_, targets) in crate::discovery::engine::manifest_selection_targets(&manifest, &pins) {
            plan.add_selection_table(&allocated, ModuleId(0), targets)
                .unwrap();
        }
        assert_eq!(plan.slots.len(), 92);
        assert!(plan.slots.iter().all(|slot| slot.descriptor_index == 0
            && !slot.semantic_authorized
            && slot.semantics == SlotSemantics::COUNT_ONLY));
        assert!(
            plan.slots
                .iter()
                .any(|slot| slot.names == ["C_MessageVerifyFinal"])
        );
    }

    fn selection_target(
        object: PinnedObjectId,
        file_offset: u64,
        name: &'static str,
    ) -> SelectionTableTarget {
        SelectionTableTarget::provider_local(
            object,
            format!("/proc/self/fd/{}", object.0),
            file_offset,
            name,
        )
    }

    #[test]
    fn selection_table_reuses_inventory_key_without_descriptor_downgrade() {
        let object = PinnedObjectId(7);
        let inventory = exact_slot(0, object, 0x10, 1, vec![ModuleId(0)]);
        let allocated = exact_plan(vec![inventory.clone()], vec![exact_module(0, object)]);
        let mut rebuilt = allocated.clone();

        rebuilt
            .add_selection_table(
                &allocated,
                ModuleId(0),
                [selection_target(object, 0x10, "C_Verify")],
            )
            .unwrap();

        assert_eq!(rebuilt.slots.len(), 1);
        let reused = &rebuilt.slots[0];
        assert_eq!(reused.descriptor_index, inventory.descriptor_index);
        assert_eq!(reused.semantics, inventory.semantics);
        assert_eq!(reused.semantic_authorized, inventory.semantic_authorized);
        assert_eq!(reused.semantic_ambiguous, inventory.semantic_ambiguous);
        assert_eq!(reused.fork_safe, inventory.fork_safe);
        assert_eq!(reused.module_ids, inventory.module_ids);
        assert_eq!(reused.names, ["C_Sign", "C_Verify"]);
        assert!(reused.aliased);
        let mut expected = allocated.clone();
        expected.slots[0].names.push("C_Verify".into());
        expected.slots[0].aliased = true;
        // The selected position is disclosed too (review answer (c)); a
        // selection table has no table location.
        expected.slot_ordinals.insert(
            AttachKey::of(&expected.slots[0]),
            BTreeSet::from([SlotOrdinal {
                table_file_offset: None,
                ordinal: standard_ordinal("C_Verify").unwrap(),
            }]),
        );
        assert_eq!(rebuilt, expected, "only finite alias metadata may change");
        assert_eq!(rebuilt.module_of_slot(0), Some(ModuleId(0)));
    }

    #[test]
    fn selection_table_coalesces_physical_keys_and_extends_with_ordinary_delta() {
        let object = PinnedObjectId(7);
        let allocated = exact_plan(vec![], vec![exact_module(0, object)]);
        let mut rebuilt = allocated.clone();

        rebuilt
            .add_selection_table(
                &allocated,
                ModuleId(0),
                [
                    selection_target(object, 0x10, "C_Sign"),
                    selection_target(object, 0x10, "C_Verify"),
                    selection_target(object, 0x20, "C_Encrypt"),
                ],
            )
            .unwrap();

        assert_eq!(rebuilt.slots.len(), 2);
        assert_eq!(rebuilt.slots[0].names, ["C_Sign", "C_Verify"]);
        assert!(rebuilt.slots[0].aliased);
        assert_eq!(rebuilt.slots[1].names, ["C_Encrypt"]);
        for slot in &rebuilt.slots {
            assert_eq!(slot.descriptor_index, 0);
            assert_eq!(slot.semantics, SlotSemantics::COUNT_ONLY);
            assert!(!slot.semantic_authorized);
            assert!(!slot.semantic_ambiguous);
            assert!(!slot.fork_safe);
            assert_eq!(slot.module_ids, [ModuleId(0)]);
        }

        let mut committed = allocated;
        let delta = committed.extend_exact(rebuilt).unwrap();
        assert_eq!(
            delta.new.iter().map(|slot| slot.index).collect::<Vec<_>>(),
            [0, 1]
        );
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
    }

    #[test]
    fn selection_table_capacity_refusal_mutates_nothing() {
        let object = PinnedObjectId(7);
        let slots = (0..MAX_SLOTS)
            .map(|index| exact_slot(index, object, u64::from(index) * 8, 0, vec![ModuleId(0)]))
            .collect();
        let allocated = exact_plan(slots, vec![exact_module(0, object)]);
        let mut rebuilt = exact_plan(vec![], vec![exact_module(0, object)]);
        let before = rebuilt.clone();

        assert!(
            rebuilt
                .add_selection_table(
                    &allocated,
                    ModuleId(0),
                    [
                        selection_target(object, 0x10000, "C_Sign"),
                        selection_target(object, 0x10008, "C_Verify"),
                    ],
                )
                .is_err()
        );
        assert_eq!(rebuilt, before, "a refused table cannot leave a prefix");
    }

    #[test]
    fn selection_table_capacity_counts_pending_overlap_and_retired_allocations() {
        let object = PinnedObjectId(7);
        let allocated_slots = (0..MAX_SLOTS - 2)
            .map(|index| exact_slot(index, object, u64::from(index) * 8, 0, vec![ModuleId(0)]))
            .collect();
        let allocated = exact_plan(allocated_slots, vec![exact_module(0, object)]);
        let pending = exact_slot(0, object, 0x10000, 1, vec![ModuleId(0)]);
        let mut fits = exact_plan(vec![pending.clone()], vec![exact_module(0, object)]);
        fits.add_selection_table(
            &allocated,
            ModuleId(0),
            [
                selection_target(object, pending.file_offset, "C_Verify"),
                selection_target(object, 0x10008, "C_Encrypt"),
            ],
        )
        .unwrap();
        assert_eq!(
            fits.slots.len(),
            2,
            "the overlapping target is not charged twice"
        );
        let mut committed = allocated.clone();
        assert_eq!(committed.extend_exact(fits).unwrap().new.len(), 2);
        assert_eq!(committed.slots.len(), MAX_SLOTS as usize);

        let mut overflows = exact_plan(vec![pending], vec![exact_module(0, object)]);
        let before = overflows.clone();
        assert!(
            overflows
                .add_selection_table(
                    &allocated,
                    ModuleId(0),
                    [
                        selection_target(object, 0x10000, "C_Verify"),
                        selection_target(object, 0x10008, "C_Encrypt"),
                        selection_target(object, 0x10010, "C_Decrypt"),
                    ],
                )
                .is_err()
        );
        assert_eq!(
            overflows, before,
            "pending over-budget work leaves no prefix"
        );

        let retired_key = 0x20000;
        let mut retired = exact_plan(
            vec![exact_slot(0, object, retired_key, 0, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
        );
        retired.deactivate(0);
        let mut rebuilt = exact_plan(vec![], vec![exact_module(0, object)]);
        rebuilt
            .add_selection_table(
                &retired,
                ModuleId(0),
                [selection_target(object, retired_key, "C_Sign")],
            )
            .unwrap();
        let delta = retired.extend_exact(rebuilt).unwrap();
        assert_eq!(delta.new[0].index, 1, "a retired key gets a fresh slot");
    }

    #[test]
    fn selection_table_rejects_missing_or_wrong_provider_without_mutation() {
        let object = PinnedObjectId(7);
        let allocated = exact_plan(vec![], vec![exact_module(0, object)]);
        let mut rebuilt = allocated.clone();
        let before = rebuilt.clone();

        assert!(
            rebuilt
                .add_selection_table(
                    &allocated,
                    ModuleId(9),
                    [selection_target(object, 0x10, "C_Sign")],
                )
                .is_err()
        );
        assert_eq!(rebuilt, before);
        assert!(
            rebuilt
                .add_selection_table(
                    &allocated,
                    ModuleId(0),
                    [selection_target(PinnedObjectId(8), 0x10, "C_Sign")],
                )
                .is_err()
        );
        assert_eq!(rebuilt, before);
    }

    #[test]
    fn provisional_get_function_list_seed_is_count_only_without_table_evidence() {
        let object = PinnedObjectId(7);
        let mut plan = provisional_plan(object);

        let inserted = plan
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap()
            .unwrap();

        assert_eq!(inserted.index, 0);
        assert_eq!(inserted.descriptor_index, 0);
        assert_eq!(inserted.names, ["C_GetFunctionList"]);
        assert!(!inserted.semantic_authorized);
        assert!(!inserted.semantic_ambiguous);
        assert!(!inserted.aliased);
        assert!(!inserted.fork_safe);
        assert_eq!(inserted.module_ids, [ModuleId(0)]);
        assert!(plan.modules[0].tables.is_empty());
        assert!(plan.surfaces.is_empty());
        assert_eq!(plan.entries_seen, 0);
        assert_eq!(plan.provisional_get_function_list.len(), 1);
    }

    #[test]
    fn tableless_rebuild_carries_provisional_without_attach_delta() {
        let object = PinnedObjectId(42);
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: u64::from(object.0),
        };
        let mut plan = provisional_plan(object);
        let seeded = plan
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap()
            .unwrap();
        let mut tableless = scanned_with(key, "/opt/p11.so", []);
        tableless.scanned.tables.clear();
        tableless.entry_objects.clear();

        let rebuilt = plan.rebuild_from_sources(&[tableless], &[], &PinnedObjects::empty());
        assert_eq!(rebuilt.entries_seen, 0);
        assert_eq!(rebuilt.slots, [seeded]);
        assert_eq!(rebuilt.provisional_get_function_list.len(), 1);

        let delta = plan.extend_exact(rebuilt).unwrap();
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert_eq!(plan.provisional_get_function_list.len(), 1);
    }

    #[test]
    fn real_table_reuses_provisional_slot_and_removes_marker() {
        let object = PinnedObjectId(42);
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: u64::from(object.0),
        };
        let mut plan = provisional_plan(object);
        let seeded = plan
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap()
            .unwrap();
        let mut table = scanned_with(key, "/opt/p11.so", [0x10]);
        table.scanned.tables[0].entries[0].name = "C_GetFunctionList";

        let rebuilt = plan.rebuild_from_sources(&[table], &[], &PinnedObjects::empty());
        assert_eq!(rebuilt.entries_seen, 1);
        assert!(rebuilt.provisional_get_function_list.is_empty());
        assert_eq!(rebuilt.slots.len(), 1);
        assert_eq!(rebuilt.slots[0].index, seeded.index);

        let delta = plan.extend_exact(rebuilt).unwrap();
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert!(plan.provisional_get_function_list.is_empty());
        assert_eq!(plan.entries_seen, 1);
        assert_eq!(plan.slots[0].names, ["C_GetFunctionList"]);
    }

    #[test]
    fn provider_retirement_prunes_provisional_marker_with_slot() {
        let object = PinnedObjectId(7);
        let mut plan = provisional_plan(object);
        let seeded = plan
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap()
            .unwrap();

        let retired = plan.retire_unpinned_targets(&PinnedObjects::empty(), 0);
        assert_eq!(retired.as_slice(), std::slice::from_ref(&seeded));
        assert!(!plan.is_active(seeded.index));
        assert!(plan.provisional_get_function_list.is_empty());
    }

    #[test]
    fn latched_ambiguity_keeps_a_provisional_target_through_tableless_rebuild() {
        let object = PinnedObjectId(42);
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: u64::from(object.0),
        };
        let mut plan = provisional_plan(object);
        let seeded = plan
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap()
            .unwrap();
        let mut ambiguous = plan.clone();
        ambiguous.aggregate_owners[0] = AggregateOwner::Ambiguous;

        assert!(plan.latch_ambiguity_from(&ambiguous));
        assert!(plan.validate_slot_index().is_ok());
        assert_eq!(plan.module_of_slot(seeded.index), None);
        assert!(plan.slot_is_module_ambiguous(seeded.index));
        assert_eq!(plan.provisional_get_function_list.len(), 1);

        let mut tableless = scanned_with(key, "/opt/p11.so", []);
        tableless.scanned.tables.clear();
        tableless.entry_objects.clear();
        let rebuilt = plan.rebuild_from_sources(&[tableless], &[], &PinnedObjects::empty());
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert_eq!(plan.provisional_get_function_list.len(), 1);
        assert!(plan.slot_is_module_ambiguous(seeded.index));

        let mut table = scanned_with(key, "/opt/p11.so", [0x10]);
        table.scanned.tables[0].entries[0].name = "C_GetFunctionList";
        let rebuilt = plan.rebuild_from_sources(&[table], &[], &PinnedObjects::empty());
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert!(plan.provisional_get_function_list.is_empty());
        assert_eq!(plan.slots[seeded.index as usize].descriptor_index, 0);
        assert!(plan.slot_is_module_ambiguous(seeded.index));
    }

    #[test]
    fn provisional_get_function_list_refuses_capacity() {
        let object = PinnedObjectId(7);
        let slots = (0..MAX_SLOTS)
            .map(|index| exact_slot(index, object, u64::from(index) * 8, 0, vec![ModuleId(0)]))
            .collect();
        let mut plan = exact_plan(slots, vec![exact_module(0, object)]);

        let error = plan
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10000,
            })
            .unwrap_err();

        assert!(error.contains(&MAX_SLOTS.to_string()), "{error}");
        assert!(plan.provisional_get_function_list.is_empty());
        assert_eq!(plan.slots.len(), MAX_SLOTS as usize);
    }

    #[test]
    fn provisional_index_validation_rejects_stale_retired_and_mismatched_entries() {
        let object = PinnedObjectId(7);
        let key = AttachKey {
            object,
            file_offset: 0x10,
        };

        let mut stale = provisional_plan(object);
        stale.provisional_get_function_list.insert(key, object);
        assert!(stale.validate_slot_index().is_err());

        let mut retired = provisional_plan(object);
        let seeded = retired
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap()
            .unwrap();
        retired.deactivate(seeded.index);
        retired.provisional_get_function_list.insert(key, object);
        assert!(retired.validate_slot_index().is_err());

        let mut mismatched = provisional_plan(object);
        mismatched
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap();
        mismatched
            .provisional_get_function_list
            .insert(key, PinnedObjectId(8));
        assert!(mismatched.validate_slot_index().is_err());

        let mut unowned = provisional_plan(object);
        unowned
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap();
        unowned.aggregate_owners[0] = AggregateOwner::Unowned;
        assert!(unowned.validate_slot_index().is_err());

        let mut wrong_owner = exact_plan(
            vec![],
            vec![exact_module(0, object), exact_module(1, PinnedObjectId(8))],
        );
        wrong_owner
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap();
        wrong_owner.aggregate_owners[0] = AggregateOwner::Sole(ModuleId(1));
        assert!(wrong_owner.validate_slot_index().is_err());
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
                name_authorized: true,
                table: None,
                ordinal: None,
                aliases: Vec::new(),
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
            scan_evidence: None,
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
    fn retired_slot_keeps_its_aggregate_owner() {
        let object = PinnedObjectId(1);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
        );
        let frozen = plan.slots[0].clone();

        plan.extend_exact(exact_plan(vec![], vec![])).unwrap();

        assert!(!plan.is_active(0));
        assert_eq!(plan.active_module_of_slot(0), None);
        assert_eq!(plan.module_of_slot(0), Some(ModuleId(0)));
        assert_eq!(plan.slots[0], frozen);
    }

    #[test]
    fn retiring_an_unpinned_target_keeps_latched_ambiguity_on_a_new_cell() {
        let object = PinnedObjectId(1);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![
                exact_slot(0, object, 0x10, descriptor, vec![ModuleId(0)]),
                exact_slot(1, object, 0x20, descriptor, vec![ModuleId(0), ModuleId(1)]),
            ],
            vec![exact_module(0, object)],
        );
        assert_eq!(plan.module_ambiguous, 1);

        // Nothing is pinned any more and no cell was accepted before this
        // candidate, so slot 0 loses its sole owner and slot 1 stays ambiguous.
        let retired = plan.retire_unpinned_targets(&PinnedObjects::empty(), 0);

        assert_eq!(retired.len(), 2);
        assert_eq!(plan.slots.len(), 2, "allocated cells are never given back");
        assert_eq!(plan.module_of_slot(0), None);
        assert_eq!(plan.module_of_slot(1), None);
        assert!(plan.slot_is_module_ambiguous(1), "ambiguity stays sticky");
        assert_eq!(plan.module_ambiguous, 1);
        assert!(plan.modules.is_empty());
    }

    #[test]
    fn a_new_active_owner_makes_the_aggregate_owner_permanently_ambiguous() {
        let first = PinnedObjectId(1);
        let second = PinnedObjectId(2);
        let target = PinnedObjectId(3);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![exact_slot(0, target, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, first)],
        );

        let delta = plan
            .extend_exact(exact_plan(
                vec![exact_slot(0, target, 0x10, descriptor, vec![ModuleId(0)])],
                vec![exact_module(0, second)],
            ))
            .unwrap();

        assert_eq!(plan.active_module_of_slot(0), Some(ModuleId(1)));
        assert_eq!(plan.module_of_slot(0), None);
        assert_eq!(plan.module_ambiguous, 1);
        assert_eq!(plan.slots[0].descriptor_index, 0);
        assert_eq!(delta.replace.len(), 1);

        plan.extend_exact(exact_plan(
            vec![exact_slot(0, target, 0x10, descriptor, vec![ModuleId(0)])],
            vec![exact_module(0, second)],
        ))
        .unwrap();
        assert_eq!(plan.module_of_slot(0), None, "ambiguity is sticky");
    }

    #[test]
    fn engine_assigned_module_id_survives_a_new_pinned_object() {
        let first = PinnedObjectId(1);
        let reloaded = PinnedObjectId(2);
        let target = PinnedObjectId(3);
        let stable = ModuleId(7);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            vec![exact_slot(0, target, 0x10, descriptor, vec![stable])],
            vec![exact_module(stable.0, first)],
        );

        let delta = plan
            .extend_exact_with_stable_module_ids(exact_plan(
                vec![exact_slot(0, target, 0x10, descriptor, vec![stable])],
                vec![exact_module(stable.0, reloaded)],
            ))
            .unwrap();

        assert!(delta.replace.is_empty());
        assert_eq!(plan.active_module_of_slot(0), Some(stable));
        assert_eq!(plan.module_of_slot(0), Some(stable));
        assert_eq!(plan.modules[0].id, stable);
    }

    #[test]
    fn an_unowned_aggregate_cell_cannot_be_retroactively_attributed() {
        let module = PinnedObjectId(1);
        let target = PinnedObjectId(2);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut unowned = exact_slot(0, target, 0x10, descriptor, vec![]);
        unowned.descriptor_index = 0;
        unowned.semantics = SlotSemantics::COUNT_ONLY;
        unowned.semantic_authorized = false;
        let mut plan = exact_plan(vec![unowned], vec![]);

        plan.extend_exact_with_stable_module_ids(exact_plan(
            vec![exact_slot(0, target, 0x10, descriptor, vec![ModuleId(7)])],
            vec![exact_module(7, module)],
        ))
        .unwrap();

        assert_eq!(plan.module_of_slot(0), None);
        assert!(!plan.slot_is_module_ambiguous(0));
        assert_eq!(plan.slots[0].descriptor_index, 0);
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
            (0..MAX_SLOTS - 1)
                .map(|index| exact_slot(index, old, u64::from(index) * 8, 0, vec![ModuleId(0)]))
                .collect(),
            vec![exact_module(0, old)],
        );
        plan.extend_exact(exact_plan(
            (0..MAX_SLOTS - 12)
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
                scanned_with(
                    old_key,
                    "/opt/old.so",
                    (0..MAX_SLOTS - 12).map(|index| u64::from(index) * 8),
                ),
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
        assert_eq!(delta.new[0].index, MAX_SLOTS - 1);
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

    /// The omission record reads right in the singular and the plural, and
    /// keeps the prefix `is_growth_omission` and its consumers key on.
    #[test]
    fn growth_omission_reason_counts_endpoints_in_singular_and_plural() {
        assert_eq!(
            growth_omission_reason(1, 512, 512, 0, 1, AdmissionPolicy::Detailed),
            "admitted module needs 1 more; only 512 attach slots are available; 512 are in use \
             (512 active, 0 retired) — 1 endpoint not attached; kept its 1 attached endpoint"
        );
        assert_eq!(
            growth_omission_reason(2, 512, 511, 11, 500, AdmissionPolicy::Detailed),
            "admitted module needs 2 more; only 512 attach slots are available; 511 are in use \
             (500 active, 11 retired) — 2 endpoints not attached; kept its 500 attached endpoints"
        );
        assert!(is_growth_omission(&growth_omission_reason(
            1,
            512,
            512,
            0,
            1,
            AdmissionPolicy::Detailed
        )));
        let whole = "module needs 2 more; only 512 attach slots are available; 511 are in use — \
                     refusing to attach a prefix";
        assert!(!is_growth_omission(whole));
        // The omitted count round-trips through the record the engine ranks.
        for omitted in [1, 2, 511, 2_113] {
            assert_eq!(
                growth_omitted_count(&growth_omission_reason(
                    omitted,
                    512,
                    511,
                    3,
                    7,
                    AdmissionPolicy::Detailed
                )),
                Some(omitted)
            );
        }
        assert_eq!(growth_omitted_count(whole), None);
        assert_eq!(whole_refusal_needed_count(whole), Some(2));
        assert_eq!(
            whole_refusal_needed_count(&growth_omission_reason(
                2,
                512,
                511,
                3,
                7,
                AdmissionPolicy::Detailed
            )),
            None
        );
        assert_eq!(
            growth_omitted_count("admitted module needs many more;"),
            None
        );
    }

    /// The key a `scanned_with` fixture pins to `object`.
    fn scanned_key(object: PinnedObjectId) -> ObjectKey {
        ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: u64::from(object.0),
        }
    }

    /// A provider already admitted on `admitted` count-only endpoints (the
    /// shape a scan-derived plan has) at offsets `0, 8, …`, and the rebuilt
    /// scan of it after it grew: a grown provider still exports every
    /// function it had, so the scan lists every admitted offset plus
    /// `growth` new ones past them.
    fn grown_provider(
        object: PinnedObjectId,
        path: &str,
        admitted: u32,
        growth: u32,
    ) -> (AttachPlan, ReconciledModule) {
        let plan = exact_plan(
            (0..admitted)
                .map(|index| exact_slot(index, object, u64::from(index) * 8, 0, vec![ModuleId(0)]))
                .collect(),
            vec![exact_module(0, object)],
        );
        let grown = scanned_with(
            scanned_key(object),
            path,
            (0..admitted + growth).map(|index| u64::from(index) * 8),
        );
        (plan, grown)
    }

    /// Inventory admission in a shared scope keeps the GT-5 reserve: an
    /// uncorroborated provider may take at most 3072 of the 4096 Inventory
    /// endpoints (the inventory catalog's lowering shape); a named scope has
    /// no reserve.
    #[test]
    fn inventory_shared_scope_keeps_the_uncorroborated_reserve() {
        let policy = AdmissionPolicy::Inventory(
            crate::capacity::InventoryBudget::new(4096, 4096 * 8).unwrap(),
        );
        let lower = |endpoints: u64, scope: AdmissionScope| {
            build_from_sources_for_policy_scoped(
                &[scanned_with(
                    scanned_key(PinnedObjectId(7)),
                    "/opt/heuristic.so",
                    (0..endpoints).map(|index| index * 8),
                )],
                &[],
                &PinnedObjects::empty(),
                policy,
                scope,
            )
        };
        assert_eq!(shared_scope_reserve(4096), 1024);
        let fits = lower(3072, AdmissionScope::Shared);
        assert_eq!(fits.refused_modules().count(), 0);
        assert_eq!(fits.slots.len(), 3072);
        let over = lower(3073, AdmissionScope::Shared);
        assert_eq!(over.refused_modules().count(), 1);
        assert!(over.slots.is_empty());
        let named = lower(3073, AdmissionScope::Named);
        assert_eq!(named.refused_modules().count(), 0);
        assert_eq!(named.slots.len(), 3073);
    }

    /// G-03 (owner decision 2026-09-23): an admitted provider that grows past
    /// capacity keeps every endpoint it had and only its growth is refused,
    /// explicitly; a later provider that fits still takes the remaining slot.
    /// Growth is modelled faithfully: the rebuilt scan lists every admitted
    /// offset plus the two new ones, over the count-only endpoints a
    /// scan-derived plan carries.
    #[test]
    fn capacity_rejection_keeps_a_grown_providers_endpoints_and_admits_a_later_module() {
        let existing = PinnedObjectId(10);
        let later = PinnedObjectId(12);
        let (mut plan, grown) =
            grown_provider(existing, "/opt/existing-crossing.so", MAX_SLOTS - 1, 2);
        let pinned = PinnedObjects::empty();
        let rebuilt = plan.rebuild_from_sources(
            &[
                grown,
                scanned_with(scanned_key(later), "/opt/later-fitting.so", [0x2000]),
            ],
            &[],
            &pinned,
        );

        assert_eq!(
            rebuilt
                .modules
                .iter()
                .map(|module| module.object)
                .collect::<Vec<_>>(),
            [existing, later],
            "the grown provider stays admitted beside the later one"
        );
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        let omission = &rebuilt.modules_skipped[0];
        assert_eq!(omission.subject, "/opt/existing-crossing.so");
        assert!(
            omission.reason.starts_with("admitted module needs 2 more;"),
            "{omission:?}"
        );
        assert!(
            omission
                .reason
                .contains(&format!("only {MAX_SLOTS} attach slots are available")),
            "{omission:?}"
        );
        assert!(
            omission.reason.contains(&format!(
                "2 endpoints not attached; kept its {} attached endpoints",
                MAX_SLOTS - 1
            )),
            "{omission:?}"
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(
            delta.retire.is_empty(),
            "{} admitted endpoints retired",
            delta.retire.len()
        );
        assert!(delta.replace.is_empty());
        assert!((0..MAX_SLOTS - 1).all(|slot| plan.is_active(slot)));
        assert!(
            plan.slots[..MAX_SLOTS as usize - 1]
                .iter()
                .all(|slot| slot.object == existing && slot.module_ids == [ModuleId(0)])
        );
        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].index, MAX_SLOTS - 1);
        assert_eq!(delta.new[0].object, later);
        assert!(plan.is_active(MAX_SLOTS - 1));
        assert_eq!(
            plan.active_slot_count(),
            MAX_SLOTS as usize,
            "kept endpoints stay in the active set"
        );
        assert!(
            plan.slots
                .iter()
                .all(|slot| slot.object != existing
                    || slot.file_offset < u64::from(MAX_SLOTS - 1) * 8),
            "no prefix of the growth is attached"
        );
        assert_eq!(
            plan.refused_modules()
                .map(|(object, _)| object)
                .collect::<Vec<_>>(),
            [existing]
        );
    }

    /// G-03 with no slot left at all: the grown provider keeps every
    /// endpoint, its growth is refused and reported, and nothing else in the
    /// plan changes.
    #[test]
    fn a_grown_provider_with_no_slot_left_keeps_its_endpoints_and_nothing_else_changes() {
        let existing = PinnedObjectId(10);
        // The scan names the object the way `exact_slot` does, so the kept
        // endpoints' metadata is byte-for-byte what the plan already holds.
        let (mut plan, grown) = grown_provider(existing, "/proc/self/fd/10", MAX_SLOTS, 2);
        let before = plan.clone();

        let rebuilt = plan.rebuild_from_sources(&[grown], &[], &PinnedObjects::empty());

        assert_eq!(
            rebuilt.slots.len(),
            MAX_SLOTS as usize,
            "every admitted endpoint and no growth"
        );
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        let omission = &rebuilt.modules_skipped[0];
        assert_eq!(omission.subject, "/proc/self/fd/10");
        assert!(
            omission.reason.starts_with("admitted module needs 2 more;"),
            "{omission:?}"
        );
        assert!(
            omission.reason.contains(&format!(
                "{MAX_SLOTS} are in use ({MAX_SLOTS} active, 0 retired) — 2 endpoints not \
                 attached; kept its {MAX_SLOTS} attached endpoints"
            )),
            "{omission:?}"
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert_eq!(plan.slots, before.slots, "no endpoint changed");
        assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize);
        assert!((0..MAX_SLOTS).all(|slot| plan.module_of_slot(slot) == Some(ModuleId(0))));
        assert_eq!(plan.module_ambiguous, 0);
        assert_eq!(
            plan.modules
                .iter()
                .map(|module| (module.id, module.object))
                .collect::<Vec<_>>(),
            [(ModuleId(0), existing)]
        );
    }

    /// G-03, retry: the same grown sources applied again allocate nothing,
    /// retire nothing, and leave exactly one omission record — a refused
    /// growth is a fixed point, neither a capacity sink nor a growing list.
    #[test]
    fn reapplying_a_refused_growth_allocates_nothing_and_keeps_one_omission() {
        let existing = PinnedObjectId(10);
        let later = PinnedObjectId(12);
        let (mut plan, grown) =
            grown_provider(existing, "/opt/existing-crossing.so", MAX_SLOTS - 1, 2);
        let sources = [
            grown,
            scanned_with(scanned_key(later), "/opt/later-fitting.so", [0x2000]),
        ];
        let pinned = PinnedObjects::empty();

        let first = plan.rebuild_from_sources(&sources, &[], &pinned);
        let delta = plan.extend_exact(first).unwrap();
        assert!(delta.retire.is_empty(), "{} retired", delta.retire.len());
        assert_eq!(delta.new.len(), 1, "only the later provider is allocated");
        let settled = plan.clone();

        let second = plan.rebuild_from_sources(&sources, &[], &pinned);
        let delta = plan.extend_exact(second).unwrap();

        assert!(
            delta.new.is_empty(),
            "the refused growth burned {} slots",
            delta.new.len()
        );
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert_eq!(plan.slots, settled.slots);
        assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize);
        assert_eq!(plan.modules_skipped.len(), 1);
        assert_eq!(plan.modules_skipped[0].subject, "/opt/existing-crossing.so");
        assert!(
            plan.modules_skipped[0]
                .reason
                .starts_with("admitted module needs 2 more;"),
            "{:?}",
            plan.modules_skipped[0]
        );
        assert_eq!(plan.refused_modules().count(), 1);
    }

    /// The growth the owner named: an admitted provider builds a second
    /// function table — published, as a live `C_GetFunctionList` return is —
    /// that no longer fits. Its first table stays attached; the new table
    /// stays visible as evidence and its endpoints are counted as omitted,
    /// never spilled.
    #[test]
    fn a_provider_that_builds_a_second_table_past_capacity_keeps_its_first_table() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let existing = PinnedObjectId(10);
        let (mut plan, mut grown) = grown_provider(existing, "/proc/self/fd/10", MAX_SLOTS - 4, 0);
        let key = scanned_key(existing);
        grown.scanned.tables.push(ScannedTable {
            version: (3, 0),
            walk: "full",
            entries: (0..8u64)
                .map(|index| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/proc/self/fd/10".into(),
                    file_offset: 0x10000 + index * 8,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x9000,
            file_offset: Some(0x9000),
            live_return: true,
            manifest_supported: false,
        });
        grown.entry_objects.push(vec![existing; 8]);
        let before = plan.clone();

        let rebuilt = plan.rebuild_from_sources(&[grown], &[], &PinnedObjects::empty());

        assert_eq!(rebuilt.slots.len(), MAX_SLOTS as usize - 4);
        assert_eq!(
            rebuilt.modules[0].tables.len(),
            2,
            "the refused table is still reported as discovered"
        );
        assert_eq!(
            rebuilt.uncorroborated_candidates, 0,
            "a published table is omitted, never spilled"
        );
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .starts_with("admitted module needs 8 more;"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert_eq!(plan.slots, before.slots);
        assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize - 4);
    }

    /// A refused growth whose strongest table is a new heuristic one holding
    /// none of the endpoints the provider had: that table's endpoints are all
    /// in the omission record, so it is not also counted as spill (G-03).
    #[test]
    fn a_refused_growths_strongest_heuristic_table_is_counted_once() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let existing = PinnedObjectId(10);
        let (mut plan, mut grown) = grown_provider(existing, "/proc/self/fd/10", MAX_SLOTS - 1, 0);
        let key = scanned_key(existing);
        // Equal heuristic evidence keeps discovery order, so the new table,
        // decoded first, is the strongest one.
        grown.scanned.tables.insert(
            0,
            ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: (0..2u64)
                    .map(|index| ScannedEntry {
                        name: "C_Sign",
                        object: key,
                        object_path: "/proc/self/fd/10".into(),
                        file_offset: 0x10000 + index * 8,
                    })
                    .collect(),
                null_entries: vec![],
                unpinned: vec![],
                address: 0x6000,
                file_offset: Some(0x9000),
                live_return: false,
                manifest_supported: false,
            },
        );
        grown.entry_objects.insert(0, vec![existing; 2]);
        let before = plan.clone();

        let rebuilt = plan.rebuild_from_sources(&[grown], &[], &PinnedObjects::empty());

        assert_eq!(rebuilt.slots.len(), MAX_SLOTS as usize - 1);
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .starts_with("admitted module needs 2 more;"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert_eq!(
            rebuilt.uncorroborated_candidates, 0,
            "the refused table is reported once, in the omission record"
        );
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert!(delta.new.is_empty() && delta.replace.is_empty() && delta.retire.is_empty());
        assert_eq!(plan.slots, before.slots);
    }

    /// G-03 against the heuristic cap (whole-branch review finding 1): the
    /// refused growth's new table sorts first and repeats one kept endpoint.
    /// The kept-only retry must keep every kept endpoint — the newcomer table
    /// must not consume one of the four cap slots, spill the old fourth
    /// table, and retire its previously attached endpoint.
    #[test]
    fn a_refused_growths_new_table_does_not_spill_a_kept_heuristic_table() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let existing = PinnedObjectId(10);
        let filler = PinnedObjectId(12);
        let key = scanned_key(existing);
        // Four kept endpoints, one per heuristic table, plus filler to one
        // slot short of the ceiling.
        let mut slots: Vec<Slot> = (0..4u32)
            .map(|index| exact_slot(index, existing, u64::from(index) * 8, 0, vec![ModuleId(0)]))
            .collect();
        slots.extend((0..MAX_SLOTS - 5).map(|index| {
            exact_slot(
                4 + index,
                filler,
                0x2000 + u64::from(index) * 8,
                0,
                vec![ModuleId(1)],
            )
        }));
        let mut plan = exact_plan(
            slots,
            vec![exact_module(0, existing), exact_module(1, filler)],
        );

        // The regrown scan: a new heuristic table decoded first — equal
        // evidence keeps discovery order, so it sorts first — repeating kept
        // offset 0 and adding two endpoints, then the four old tables with
        // their kept endpoints.
        let table = |address: u64, file_offset: u64, offsets: &[u64]| ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: offsets
                .iter()
                .map(|offset| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/proc/self/fd/10".into(),
                    file_offset: *offset,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address,
            file_offset: Some(file_offset),
            live_return: false,
            manifest_supported: false,
        };
        let mut grown = scanned_with(key, "/proc/self/fd/10", []);
        grown.scanned.tables = vec![
            table(0x9000, 0x9000, &[0, 0x10000, 0x10008]),
            table(0x7000, 0x0000, &[0]),
            table(0x7100, 0x1000, &[8]),
            table(0x7200, 0x2000, &[16]),
            table(0x7300, 0x3000, &[24]),
        ];
        grown.entry_objects = vec![
            vec![existing; 3],
            vec![existing],
            vec![existing],
            vec![existing],
            vec![existing],
        ];
        let filler_scan = scanned_with(
            scanned_key(filler),
            "/proc/self/fd/12",
            (0..MAX_SLOTS - 5).map(|index| 0x2000 + u64::from(index) * 8),
        );

        let rebuilt =
            plan.rebuild_from_sources(&[grown, filler_scan], &[], &PinnedObjects::empty());

        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .starts_with("admitted module needs 2 more;"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .contains("2 endpoints not attached; kept its 4 attached endpoints"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert_eq!(
            rebuilt.uncorroborated_candidates, 0,
            "kept tables are admitted, never spilled"
        );
        let kept: Vec<u64> = rebuilt
            .slots
            .iter()
            .filter(|slot| slot.object == existing)
            .map(|slot| slot.file_offset)
            .collect();
        assert_eq!(kept, [0, 8, 16, 24], "every kept endpoint stays slotted");

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(
            delta.retire.is_empty(),
            "{} kept endpoints retired",
            delta.retire.len()
        );
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize - 1);
    }

    /// G1 (G-03 hole): growth on a NON-leading table must not spill kept
    /// endpoints silently. T1 holds one kept endpoint and T2 one kept
    /// endpoint plus two new ones, with one slot free. T2's budget failure
    /// used to spill the whole table — its kept endpoint vanished from the
    /// snapshot and retired — with no growth-omission record. It must route
    /// to the refused-growth retry like the leading table: the kept
    /// endpoint stays, the two new ones are refused with an explicit
    /// omission, and nothing is double-counted as spill.
    #[test]
    fn a_non_leading_tables_growth_refuses_explicitly_and_keeps_its_kept_endpoint() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let existing = PinnedObjectId(10);
        let filler = PinnedObjectId(12);
        let key = scanned_key(existing);
        // Two kept endpoints plus filler to one slot short of the ceiling.
        let mut slots = vec![
            exact_slot(0, existing, 0, 0, vec![ModuleId(0)]),
            exact_slot(1, existing, 8, 0, vec![ModuleId(0)]),
        ];
        slots.extend((0..MAX_SLOTS - 3).map(|index| {
            exact_slot(
                2 + index,
                filler,
                0x2000 + u64::from(index) * 8,
                0,
                vec![ModuleId(1)],
            )
        }));
        let mut plan = exact_plan(
            slots,
            vec![exact_module(0, existing), exact_module(1, filler)],
        );

        // The regrown scan: equal heuristic evidence keeps discovery order,
        // so T1 (one kept endpoint) sorts first and T2 (one kept endpoint
        // plus two new ones) is the non-leading table whose growth does not
        // fit the one free slot.
        let table = |address: u64, file_offset: u64, offsets: &[u64]| ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: offsets
                .iter()
                .map(|offset| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/proc/self/fd/10".into(),
                    file_offset: *offset,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address,
            file_offset: Some(file_offset),
            live_return: false,
            manifest_supported: false,
        };
        let mut grown = scanned_with(key, "/proc/self/fd/10", []);
        grown.scanned.tables = vec![
            table(0x7000, 0x0000, &[0]),
            table(0x7100, 0x1000, &[8, 0x10000, 0x10008]),
        ];
        grown.entry_objects = vec![vec![existing], vec![existing; 3]];
        let filler_scan = scanned_with(
            scanned_key(filler),
            "/proc/self/fd/12",
            (0..MAX_SLOTS - 3).map(|index| 0x2000 + u64::from(index) * 8),
        );

        let rebuilt =
            plan.rebuild_from_sources(&[grown, filler_scan], &[], &PinnedObjects::empty());

        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert_eq!(
            rebuilt.modules_skipped[0].subject, "/proc/self/fd/10",
            "the omission names the grown module"
        );
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .starts_with("admitted module needs 2 more;"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .contains("2 endpoints not attached; kept its 2 attached endpoints"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert_eq!(
            rebuilt.uncorroborated_candidates, 0,
            "the refused growth is omitted, never also spilled"
        );
        let kept: Vec<u64> = rebuilt
            .slots
            .iter()
            .filter(|slot| slot.object == existing)
            .map(|slot| slot.file_offset)
            .collect();
        assert_eq!(kept, [0, 8], "both kept endpoints stay slotted");

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(
            delta.retire.is_empty(),
            "{} kept endpoints retired",
            delta.retire.len()
        );
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize - 1);
    }

    /// G-03 spill accounting (re-review): the kept-only retry must not
    /// recount the first pass's spill. A leading empty table — entries all
    /// unpinned during reconciliation — spills before the G1 refusal; the
    /// retry sees it empty again and must count the one table exactly once,
    /// alongside the growth omission, never twice.
    #[test]
    fn a_refused_growth_counts_a_leading_empty_table_once() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let existing = PinnedObjectId(10);
        let filler = PinnedObjectId(12);
        let key = scanned_key(existing);
        // Two kept endpoints plus filler to one slot short of the ceiling.
        let mut slots = vec![
            exact_slot(0, existing, 0, 0, vec![ModuleId(0)]),
            exact_slot(1, existing, 8, 0, vec![ModuleId(0)]),
        ];
        slots.extend((0..MAX_SLOTS - 3).map(|index| {
            exact_slot(
                2 + index,
                filler,
                0x2000 + u64::from(index) * 8,
                0,
                vec![ModuleId(1)],
            )
        }));
        let mut plan = exact_plan(
            slots,
            vec![exact_module(0, existing), exact_module(1, filler)],
        );

        // Equal heuristic evidence keeps discovery order: the empty table
        // sorts first and spills, then T1 admits, then T2's growth refuses
        // like G1's.
        let table = |address: u64, file_offset: u64, offsets: &[u64]| ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: offsets
                .iter()
                .map(|offset| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/proc/self/fd/10".into(),
                    file_offset: *offset,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address,
            file_offset: Some(file_offset),
            live_return: false,
            manifest_supported: false,
        };
        let mut grown = scanned_with(key, "/proc/self/fd/10", []);
        grown.scanned.tables = vec![
            table(0x6f00, 0x0f00, &[]),
            table(0x7000, 0x0000, &[0]),
            table(0x7100, 0x1000, &[8, 0x10000, 0x10008]),
        ];
        grown.entry_objects = vec![vec![existing; 0], vec![existing], vec![existing; 3]];
        let filler_scan = scanned_with(
            scanned_key(filler),
            "/proc/self/fd/12",
            (0..MAX_SLOTS - 3).map(|index| 0x2000 + u64::from(index) * 8),
        );

        let rebuilt =
            plan.rebuild_from_sources(&[grown, filler_scan], &[], &PinnedObjects::empty());

        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .starts_with("admitted module needs 2 more;"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert_eq!(
            rebuilt.uncorroborated_candidates, 1,
            "the one empty table spills exactly once, not once per admission pass"
        );
        let kept: Vec<u64> = rebuilt
            .slots
            .iter()
            .filter(|slot| slot.object == existing)
            .map(|slot| slot.file_offset)
            .collect();
        assert_eq!(kept, [0, 8], "both kept endpoints stay slotted");

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(
            delta.retire.is_empty(),
            "{} kept endpoints retired",
            delta.retire.len()
        );
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize - 1);
    }

    /// G-03 spill accounting (#2): an earlier all-growth table's budget
    /// spill sets `spent`, and a later kept-holding table then reaches the
    /// skip branch. It must route to the refused-growth retry like a direct
    /// budget failure — the kept endpoints stay, the growth is omitted
    /// explicitly — and the earlier spill is counted exactly once.
    #[test]
    fn a_spent_budget_routes_a_later_kept_table_to_the_refused_growth_retry() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let existing = PinnedObjectId(10);
        let filler = PinnedObjectId(12);
        let key = scanned_key(existing);
        // Two kept endpoints plus filler to one slot short of the ceiling.
        let mut slots = vec![
            exact_slot(0, existing, 0, 0, vec![ModuleId(0)]),
            exact_slot(1, existing, 8, 0, vec![ModuleId(0)]),
        ];
        slots.extend((0..MAX_SLOTS - 3).map(|index| {
            exact_slot(
                2 + index,
                filler,
                0x2000 + u64::from(index) * 8,
                0,
                vec![ModuleId(1)],
            )
        }));
        let mut plan = exact_plan(
            slots,
            vec![exact_module(0, existing), exact_module(1, filler)],
        );

        // Equal heuristic evidence keeps discovery order: the leading kept
        // table admits (its demand is zero, so the leading-table check
        // passes), the all-fresh table's two endpoints then do not fit the
        // one free slot, so it spills and spends the budget, and the kept
        // table reaches the skip branch instead of the budget check.
        let table = |address: u64, file_offset: u64, offsets: &[u64]| ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: offsets
                .iter()
                .map(|offset| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/proc/self/fd/10".into(),
                    file_offset: *offset,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address,
            file_offset: Some(file_offset),
            live_return: false,
            manifest_supported: false,
        };
        let mut grown = scanned_with(key, "/proc/self/fd/10", []);
        grown.scanned.tables = vec![
            table(0x7000, 0x0000, &[0]),
            table(0x7100, 0x1000, &[0x10000, 0x10008]),
            table(0x7200, 0x2000, &[8, 0x10010]),
        ];
        grown.entry_objects = vec![vec![existing], vec![existing; 2], vec![existing; 2]];
        let filler_scan = scanned_with(
            scanned_key(filler),
            "/proc/self/fd/12",
            (0..MAX_SLOTS - 3).map(|index| 0x2000 + u64::from(index) * 8),
        );

        let rebuilt =
            plan.rebuild_from_sources(&[grown, filler_scan], &[], &PinnedObjects::empty());

        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .starts_with("admitted module needs 1 more;"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .contains("1 endpoint not attached; kept its 2 attached endpoints"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert_eq!(
            rebuilt.uncorroborated_candidates, 1,
            "the earlier all-growth spill counts exactly once"
        );
        let kept: Vec<u64> = rebuilt
            .slots
            .iter()
            .filter(|slot| slot.object == existing)
            .map(|slot| slot.file_offset)
            .collect();
        assert_eq!(kept, [0, 8], "both kept endpoints stay slotted");

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(
            delta.retire.is_empty(),
            "{} kept endpoints retired",
            delta.retire.len()
        );
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize - 1);
    }

    /// G-03 spill accounting (#3): a kept-holding table past
    /// `MAX_TABLES_PER_OBJECT` with budget still available must route to
    /// the refused-growth retry, not spill silently. The kept endpoint
    /// stays, the table's fresh endpoint is omitted explicitly, and the
    /// four genuinely-new tables spill counted exactly once each.
    #[test]
    fn a_kept_table_past_the_heuristic_cap_routes_to_the_refused_growth_retry() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let existing = PinnedObjectId(10);
        let filler = PinnedObjectId(12);
        let key = scanned_key(existing);
        // One kept endpoint plus a little filler: every fresh endpoint
        // would fit by budget, so only the per-object cap can refuse.
        let mut slots = vec![exact_slot(0, existing, 0, 0, vec![ModuleId(0)])];
        slots.extend((0..10u32).map(|index| {
            exact_slot(
                1 + index,
                filler,
                0x2000 + u64::from(index) * 8,
                0,
                vec![ModuleId(1)],
            )
        }));
        let mut plan = exact_plan(
            slots,
            vec![exact_module(0, existing), exact_module(1, filler)],
        );

        // Equal heuristic evidence keeps discovery order: four new tables
        // admit onto the four cap slots, and the fifth table — holding the
        // kept endpoint — reaches the cap branch with budget to spare.
        let table = |address: u64, file_offset: u64, offsets: &[u64]| ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: offsets
                .iter()
                .map(|offset| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/proc/self/fd/10".into(),
                    file_offset: *offset,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address,
            file_offset: Some(file_offset),
            live_return: false,
            manifest_supported: false,
        };
        let mut grown = scanned_with(key, "/proc/self/fd/10", []);
        grown.scanned.tables = vec![
            table(0x7000, 0x0000, &[0x10000]),
            table(0x7100, 0x1000, &[0x10008]),
            table(0x7200, 0x2000, &[0x10010]),
            table(0x7300, 0x3000, &[0x10018]),
            table(0x7400, 0x4000, &[0, 0x10020]),
        ];
        grown.entry_objects = vec![
            vec![existing],
            vec![existing],
            vec![existing],
            vec![existing],
            vec![existing; 2],
        ];
        let filler_scan = scanned_with(
            scanned_key(filler),
            "/proc/self/fd/12",
            (0..10u32).map(|index| 0x2000 + u64::from(index) * 8),
        );

        let rebuilt =
            plan.rebuild_from_sources(&[grown, filler_scan], &[], &PinnedObjects::empty());

        assert_eq!(
            MAX_TABLES_PER_OBJECT, 4,
            "this test fills exactly the per-object cap"
        );
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .starts_with("admitted module needs 1 more;"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .contains("1 endpoint not attached; kept its 1 attached endpoint"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        assert_eq!(
            rebuilt.uncorroborated_candidates, 4,
            "the four genuinely-new tables spill exactly once each"
        );
        let kept: Vec<u64> = rebuilt
            .slots
            .iter()
            .filter(|slot| slot.object == existing)
            .map(|slot| slot.file_offset)
            .collect();
        assert_eq!(kept, [0], "the kept endpoint stays slotted");

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(
            delta.retire.is_empty(),
            "{} kept endpoints retired",
            delta.retire.len()
        );
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert_eq!(plan.active_slot_count(), 11);
    }

    /// C1: an unchanged provider whose five heuristic tables share the same
    /// attached endpoints must not record a growth refusal. The fifth table
    /// reaches the cap branch with zero fresh demand, so it routes to the
    /// kept-only retry for preservation — with empty total demand no
    /// omission is recorded, every endpoint stays attached, and the snapshot
    /// stays COMPLETE (`modules_skipped` empty).
    #[test]
    fn an_unchanged_provider_past_the_heuristic_cap_records_no_refusal() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let existing = PinnedObjectId(10);
        let filler = PinnedObjectId(12);
        let key = scanned_key(existing);
        // Two kept endpoints plus a little filler: every endpoint is already
        // attached, so the refresh carries zero fresh demand and budget can
        // never refuse.
        let mut slots = vec![
            exact_slot(0, existing, 0, 0, vec![ModuleId(0)]),
            exact_slot(1, existing, 8, 0, vec![ModuleId(0)]),
        ];
        slots.extend((0..10u32).map(|index| {
            exact_slot(
                2 + index,
                filler,
                0x2000 + u64::from(index) * 8,
                0,
                vec![ModuleId(1)],
            )
        }));
        let mut plan = exact_plan(
            slots,
            vec![exact_module(0, existing), exact_module(1, filler)],
        );

        // Equal heuristic evidence keeps discovery order: four tables admit
        // onto the four cap slots, and the fifth — listing the same two
        // attached endpoints — reaches the cap branch with nothing fresh.
        let table = |address: u64, file_offset: u64| ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: [0, 8]
                .iter()
                .map(|offset| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/proc/self/fd/10".into(),
                    file_offset: *offset,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address,
            file_offset: Some(file_offset),
            live_return: false,
            manifest_supported: false,
        };
        let mut unchanged = scanned_with(key, "/proc/self/fd/10", []);
        unchanged.scanned.tables = vec![
            table(0x7000, 0x0000),
            table(0x7100, 0x1000),
            table(0x7200, 0x2000),
            table(0x7300, 0x3000),
            table(0x7400, 0x4000),
        ];
        unchanged.entry_objects = vec![vec![existing; 2]; 5];
        let filler_scan = scanned_with(
            scanned_key(filler),
            "/proc/self/fd/12",
            (0..10u32).map(|index| 0x2000 + u64::from(index) * 8),
        );

        let rebuilt =
            plan.rebuild_from_sources(&[unchanged, filler_scan], &[], &PinnedObjects::empty());

        assert_eq!(
            MAX_TABLES_PER_OBJECT, 4,
            "this test overflows the per-object cap by exactly one table"
        );
        assert!(
            rebuilt.modules_skipped.is_empty(),
            "no refused demand, so no refusal: {:?}",
            rebuilt.modules_skipped
        );
        assert_eq!(
            rebuilt.uncorroborated_candidates, 0,
            "the fifth table routes to the kept-only retry and admits there, it does not spill"
        );
        let kept: Vec<u64> = rebuilt
            .slots
            .iter()
            .filter(|slot| slot.object == existing)
            .map(|slot| slot.file_offset)
            .collect();
        assert_eq!(kept, [0, 8], "both kept endpoints stay slotted");

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(
            delta.retire.is_empty(),
            "{} kept endpoints retired",
            delta.retire.len()
        );
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert_eq!(plan.active_slot_count(), 12);
    }

    /// D1: a zero-demand kept table past the cap must be preserved without
    /// a refusal. The provider owns four attached endpoints; the refresh
    /// adds an earlier alias table, so five distinct single-endpoint
    /// heuristic tables ([0], [0], [8], [16], [24]) overflow the cap. The
    /// fifth holds kept 24 with zero fresh demand: attached is not
    /// surviving-in-admitted-tables, so it must route to the kept-only
    /// retry (where the cap is bypassed) instead of spilling — and with
    /// empty total demand no omission is recorded (COMPLETE intact).
    #[test]
    fn a_zero_demand_kept_table_past_the_cap_is_preserved_without_a_refusal() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let existing = PinnedObjectId(10);
        let filler = PinnedObjectId(12);
        let key = scanned_key(existing);
        // Four kept endpoints plus a little filler: every endpoint is
        // already attached, so the refresh carries zero fresh demand and
        // budget can never refuse — only the per-object cap can bite.
        let mut slots = vec![
            exact_slot(0, existing, 0, 0, vec![ModuleId(0)]),
            exact_slot(1, existing, 8, 0, vec![ModuleId(0)]),
            exact_slot(2, existing, 16, 0, vec![ModuleId(0)]),
            exact_slot(3, existing, 24, 0, vec![ModuleId(0)]),
        ];
        slots.extend((0..10u32).map(|index| {
            exact_slot(
                4 + index,
                filler,
                0x2000 + u64::from(index) * 8,
                0,
                vec![ModuleId(1)],
            )
        }));
        let mut plan = exact_plan(
            slots,
            vec![exact_module(0, existing), exact_module(1, filler)],
        );

        // Equal heuristic evidence keeps discovery order: the first four
        // single-endpoint tables admit onto the four cap slots, and the
        // fifth — holding only kept 24 — reaches the cap branch with
        // nothing fresh.
        let table = |address: u64, file_offset: u64, offsets: &[u64]| ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: offsets
                .iter()
                .map(|offset| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/proc/self/fd/10".into(),
                    file_offset: *offset,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address,
            file_offset: Some(file_offset),
            live_return: false,
            manifest_supported: false,
        };
        let mut refreshed = scanned_with(key, "/proc/self/fd/10", []);
        refreshed.scanned.tables = vec![
            table(0x7000, 0x0000, &[0]),
            table(0x7100, 0x1000, &[0]),
            table(0x7200, 0x2000, &[8]),
            table(0x7300, 0x3000, &[16]),
            table(0x7400, 0x4000, &[24]),
        ];
        refreshed.entry_objects = vec![vec![existing]; 5];
        let filler_scan = scanned_with(
            scanned_key(filler),
            "/proc/self/fd/12",
            (0..10u32).map(|index| 0x2000 + u64::from(index) * 8),
        );

        let rebuilt =
            plan.rebuild_from_sources(&[refreshed, filler_scan], &[], &PinnedObjects::empty());

        assert_eq!(
            MAX_TABLES_PER_OBJECT, 4,
            "this test overflows the per-object cap by exactly one table"
        );
        assert!(
            rebuilt.modules_skipped.is_empty(),
            "empty total demand, so no refusal: {:?}",
            rebuilt.modules_skipped
        );
        let kept: Vec<u64> = rebuilt
            .slots
            .iter()
            .filter(|slot| slot.object == existing)
            .map(|slot| slot.file_offset)
            .collect();
        assert_eq!(kept, [0, 8, 16, 24], "every kept endpoint stays slotted");
        assert_eq!(
            rebuilt.uncorroborated_candidates, 0,
            "the fifth table routes to the kept-only retry, it does not spill"
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(
            delta.retire.is_empty(),
            "{} kept endpoints retired",
            delta.retire.len()
        );
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert_eq!(plan.active_slot_count(), 14);
    }

    /// A provider that changed as well as grew: it no longer lists some
    /// endpoints it had, and its growth does not fit. The dropped endpoints
    /// retire exactly as before G-03, the ones it still lists stay attached,
    /// and the growth is omitted: the provider is partially covered.
    #[test]
    fn a_changed_provider_whose_growth_is_refused_retires_only_what_it_dropped() {
        let existing = PinnedObjectId(10);
        let (mut plan, _) = grown_provider(existing, "/proc/self/fd/10", MAX_SLOTS - 1, 0);
        let still_listed = MAX_SLOTS - 11;
        let changed = scanned_with(
            scanned_key(existing),
            "/proc/self/fd/10",
            (0..still_listed)
                .map(|index| u64::from(index) * 8)
                .chain([u64::from(MAX_SLOTS) * 8, u64::from(MAX_SLOTS + 1) * 8]),
        );
        let allocated = plan.slots.len();

        let rebuilt = plan.rebuild_from_sources(&[changed], &[], &PinnedObjects::empty());

        assert_eq!(rebuilt.slots.len(), still_listed as usize);
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        let omission = &rebuilt.modules_skipped[0];
        assert!(is_growth_omission(&omission.reason), "{omission:?}");
        assert!(
            omission.reason.starts_with("admitted module needs 2 more;"),
            "{omission:?}"
        );
        assert!(
            omission
                .reason
                .contains(&format!("kept its {still_listed} attached endpoints")),
            "{omission:?}"
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(delta.new.is_empty() && delta.replace.is_empty());
        assert_eq!(
            delta
                .retire
                .iter()
                .map(|slot| slot.index)
                .collect::<Vec<_>>(),
            (still_listed..MAX_SLOTS - 1).collect::<Vec<_>>(),
            "only the dropped endpoints retire"
        );
        assert!((0..still_listed).all(|slot| plan.is_active(slot)));
        assert_eq!(plan.active_slot_count(), still_listed as usize);
        assert_eq!(plan.slots.len(), allocated, "nothing is allocated");
        assert_eq!(plan.modules_skipped.len(), 1);
    }

    /// A provider whose sources list none of the endpoints it had is handled
    /// exactly as before G-03: refused whole when its listing does not fit,
    /// admitted on that listing when it does — its old endpoints retire
    /// either way. It is never admitted on no endpoint behind a growth record.
    #[test]
    fn a_provider_that_lists_none_of_its_endpoints_is_handled_as_before() {
        let existing = PinnedObjectId(10);
        let path = "/proc/self/fd/10";
        let admitted = MAX_SLOTS - 1;
        let beyond = |count: u32| (admitted..admitted + count).map(|index| u64::from(index) * 8);

        let (mut plan, _) = grown_provider(existing, path, admitted, 0);
        let rebuilt = plan.rebuild_from_sources(
            &[scanned_with(scanned_key(existing), path, beyond(2))],
            &[],
            &PinnedObjects::empty(),
        );
        assert!(
            rebuilt.modules.is_empty(),
            "refused whole, never admitted on no endpoint: {:?}",
            rebuilt.modules_skipped
        );
        assert!(rebuilt.slots.is_empty());
        assert_eq!(
            rebuilt.modules_skipped,
            [Skipped {
                subject: path.into(),
                reason: format!(
                    "module needs 2 more; only {MAX_SLOTS} attach slots are available; \
                     {admitted} are in use ({admitted} active, 0 retired) — refusing to attach \
                     a prefix"
                ),
            }]
        );
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert_eq!(delta.retire.len(), admitted as usize);
        assert!(delta.new.is_empty());
        assert_eq!(plan.active_slot_count(), 0);

        let (mut plan, _) = grown_provider(existing, path, admitted, 0);
        let rebuilt = plan.rebuild_from_sources(
            &[scanned_with(scanned_key(existing), path, beyond(1))],
            &[],
            &PinnedObjects::empty(),
        );
        assert!(rebuilt.modules_skipped.is_empty());
        assert_eq!(rebuilt.slots.len(), 1);
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert_eq!(delta.retire.len(), admitted as usize);
        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].index, admitted);
        assert_eq!(plan.active_slot_count(), 1);
    }

    /// The published-union refusal rather than the strongest table's: the
    /// admitted provider's strongest table is the one it has attached, and
    /// its new published table does not fit. The attached table stays and
    /// the new one is omitted, never spilled.
    #[test]
    fn a_published_union_refusal_keeps_the_admitted_table() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable, order_tables_by_evidence};

        let existing = PinnedObjectId(10);
        let key = scanned_key(existing);
        // The provider was admitted from its one published table.
        let mut admitted = scanned_with(
            key,
            "/proc/self/fd/10",
            (0..MAX_SLOTS - 4).map(|index| u64::from(index) * 8),
        );
        admitted.scanned.tables[0].live_return = true;
        let mut plan = build_from_test_sources(std::slice::from_ref(&admitted), &[]);
        assert_eq!(plan.slots.len(), MAX_SLOTS as usize - 4);
        // A published scan table authorizes names, never semantics: its
        // slots are count-only, like an unlinked table's.
        assert!(plan.slots.iter().all(|slot| slot.names == ["C_Sign"]
            && slot.descriptor_index == 0
            && !slot.semantic_authorized));
        let mut grown = admitted;
        grown.scanned.tables.push(ScannedTable {
            version: (3, 0),
            walk: "full",
            entries: (0..8u64)
                .map(|index| ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: "/proc/self/fd/10".into(),
                    file_offset: 0x10000 + index * 8,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x9000,
            file_offset: Some(0x9000),
            live_return: true,
            manifest_supported: false,
        });
        grown.entry_objects.push(vec![existing; 8]);
        // Equal published evidence keeps discovery order: the attached table
        // stays the strongest, so its demand is zero and only the published
        // union can refuse.
        assert_eq!(
            order_tables_by_evidence(
                &grown.scanned.tables,
                &grown.scanned.interfaces,
                &[],
                &[],
                &ObjectExports::NONE,
            ),
            [0, 1]
        );
        let before = plan.clone();

        let rebuilt = plan.rebuild_from_sources(&[grown], &[], &PinnedObjects::empty());

        assert_eq!(rebuilt.slots.len(), MAX_SLOTS as usize - 4);
        assert_eq!(rebuilt.uncorroborated_candidates, 0);
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        let omission = &rebuilt.modules_skipped[0];
        assert!(
            omission.reason.starts_with("admitted module needs 8 more;"),
            "{omission:?}"
        );
        assert!(
            omission
                .reason
                .contains(&format!("kept its {} attached endpoints", MAX_SLOTS - 4)),
            "{omission:?}"
        );
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert!(delta.new.is_empty() && delta.replace.is_empty() && delta.retire.is_empty());
        assert_eq!(plan.slots, before.slots);
    }

    /// One object mapped by two processes: its growth is seen through both
    /// views, yet it is one module, omitted once, and its kept endpoints are
    /// counted once.
    #[test]
    fn a_growth_seen_through_two_views_is_omitted_once() {
        let existing = PinnedObjectId(10);
        let (mut plan, grown) = grown_provider(existing, "/proc/self/fd/10", MAX_SLOTS - 1, 2);
        let mut other_view = grown.clone();
        other_view.scanned.view = ProcessViewId(1);
        let before = plan.clone();

        let rebuilt = plan.rebuild_from_sources(&[grown, other_view], &[], &PinnedObjects::empty());

        assert_eq!(rebuilt.modules.len(), 1);
        assert_eq!(rebuilt.slots.len(), MAX_SLOTS as usize - 1);
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert_eq!(rebuilt.refused_modules().count(), 1);
        let omission = &rebuilt.modules_skipped[0];
        assert!(
            omission.reason.starts_with("admitted module needs 2 more;"),
            "{omission:?}"
        );
        assert!(
            omission
                .reason
                .contains(&format!("kept its {} attached endpoints", MAX_SLOTS - 1)),
            "{omission:?}"
        );
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert!(delta.new.is_empty() && delta.replace.is_empty() && delta.retire.is_empty());
        assert_eq!(plan.slots, before.slots);
    }

    /// A manifest's targets are fixed at startup, so a manifest module never
    /// gains targets mid-capture. Its demand can still rise: an endpoint
    /// deactivated by a failed replacement or group reattach needs a fresh
    /// slot when the next rebuild lists it again. With no slot left, that
    /// re-admission is refused and the module keeps every other endpoint
    /// instead of losing all of them.
    #[test]
    fn a_manifest_module_that_cannot_readmit_a_deactivated_endpoint_keeps_the_rest() {
        let manifest = manifest_with(
            (0..u64::from(MAX_SLOTS))
                .map(|index| resolved("C_Sign", index * 8))
                .collect(),
        );
        let mut plan = build_from_test_sources(&[], std::slice::from_ref(&manifest));
        assert_eq!(plan.slots.len(), MAX_SLOTS as usize);
        plan.deactivate(5);
        let before = plan.clone();

        let rebuilt = plan.rebuild_from_sources_with(
            &[],
            std::slice::from_ref(&manifest),
            |key, _| u32::try_from(key.inode).ok().map(PinnedObjectId),
            |_, _| true,
            false,
            AdmissionPolicy::detailed(),
        );

        assert_eq!(rebuilt.slots.len(), MAX_SLOTS as usize - 1);
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        let omission = &rebuilt.modules_skipped[0];
        assert_eq!(omission.subject, "/opt/p11.so");
        assert!(
            omission.reason.starts_with("admitted module needs 1 more;"),
            "{omission:?}"
        );
        // The re-admitted endpoint is not called new.
        assert!(
            omission.reason.ends_with(&format!(
                "— 1 endpoint not attached; kept its {} attached endpoints",
                MAX_SLOTS - 1
            )),
            "{omission:?}"
        );

        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(
            delta.retire.is_empty(),
            "{} manifest endpoints retired",
            delta.retire.len()
        );
        assert_eq!(plan.slots, before.slots);
        assert!(!plan.is_active(5));
        assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize - 1);
    }

    /// An endpoint the grown provider shares with another provider keeps
    /// both owners, and an endpoint only the other provider owns is not
    /// claimed by the refused growth: kept endpoints keep their current
    /// ownership, whole.
    #[test]
    fn a_grown_provider_keeps_the_current_owners_of_its_shared_endpoints() {
        use crate::discovery::scan::ScannedEntry;

        let grown_object = PinnedObjectId(10);
        let other_object = PinnedObjectId(11);
        let other_offset = 0x100;
        let mut slots = vec![exact_slot(
            0,
            grown_object,
            0,
            0,
            vec![ModuleId(0), ModuleId(1)],
        )];
        slots.extend((1..MAX_SLOTS - 2).map(|index| {
            exact_slot(
                index,
                grown_object,
                u64::from(index) * 8,
                0,
                vec![ModuleId(0)],
            )
        }));
        slots.push(exact_slot(
            MAX_SLOTS - 2,
            other_object,
            other_offset,
            0,
            vec![ModuleId(1)],
        ));
        let mut plan = exact_plan(
            slots,
            vec![exact_module(0, grown_object), exact_module(1, other_object)],
        );
        assert_eq!(plan.module_ambiguous, 1);
        let before = plan.clone();

        // The grown provider lists every endpoint it has, two new ones, and
        // a new claim on the other provider's own endpoint.
        let mut grown = scanned_with(
            scanned_key(grown_object),
            "/proc/self/fd/10",
            (0..MAX_SLOTS - 2)
                .map(|index| u64::from(index) * 8)
                .chain([u64::from(MAX_SLOTS) * 8, u64::from(MAX_SLOTS + 1) * 8]),
        );
        grown.scanned.tables[0].entries.push(ScannedEntry {
            name: "C_Sign",
            object: scanned_key(other_object),
            object_path: "/proc/self/fd/11".into(),
            file_offset: other_offset,
        });
        grown.entry_objects[0].push(other_object);
        // The other provider still forwards into the shared endpoint.
        let mut other = scanned_with(
            scanned_key(other_object),
            "/proc/self/fd/11",
            [other_offset],
        );
        other.scanned.tables[0].entries.push(ScannedEntry {
            name: "C_Sign",
            object: scanned_key(grown_object),
            object_path: "/proc/self/fd/10".into(),
            file_offset: 0,
        });
        other.entry_objects[0].push(grown_object);

        let rebuilt = plan.rebuild_from_sources(&[grown, other], &[], &PinnedObjects::empty());
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert_eq!(rebuilt.modules_skipped[0].subject, "/proc/self/fd/10");
        let delta = plan.extend_exact(rebuilt).unwrap();

        assert!(delta.retire.is_empty(), "{} retired", delta.retire.len());
        assert!(delta.replace.is_empty());
        assert!(delta.new.is_empty());
        assert_eq!(plan.slots, before.slots, "every owner set is unchanged");
        assert_eq!(plan.slots[0].module_ids, [ModuleId(0), ModuleId(1)]);
        assert_eq!(
            plan.active_module_of_slot(MAX_SLOTS - 2),
            Some(ModuleId(1)),
            "the refused growth does not claim the other provider's endpoint"
        );
        assert_eq!(plan.module_ambiguous, 1);
        assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize - 1);
    }

    #[test]
    fn a_rejected_shared_claimant_cannot_downgrade_an_accepted_slot() {
        let accepted = PinnedObjectId(1);
        let rejected = PinnedObjectId(2);
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let mut plan = exact_plan(
            (0..MAX_SLOTS - 1)
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
            ExistingAllocation {
                slots: plan.slots.len(),
                active: &plan.slot_by_key,
                owned: &plan.active_keys_by_owner(),
            },
            false,
            AdmissionPolicy::detailed(),
            AdmissionScope::Named,
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

        assert!(error.contains(&MAX_SLOTS.to_string()), "{error}");
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
        let unchanged = reappeared.clone();
        let delta = plan.extend_exact(reappeared).unwrap();
        assert_eq!(delta.new[0].index, 2, "retired slot 1 stays reserved");
        assert!(!plan.is_active(1));
        assert!(plan.is_active(2));

        let delta = plan.extend_exact(unchanged).unwrap();
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
    }

    fn counters_policy(endpoints: u64) -> AdmissionPolicy {
        AdmissionPolicy::counters(crate::capacity::CounterBudget::new(endpoints).unwrap())
    }

    fn counters_plan(slots: Vec<Slot>, modules: Vec<ModuleSummary>, endpoints: u64) -> AttachPlan {
        let mut plan =
            AttachPlan::from_slots_with_policy(slots, counters_policy(endpoints)).unwrap();
        plan.modules = modules;
        plan.entries_seen = plan.slots.len();
        plan
    }

    fn counter_history_plan(count: u32) -> AttachPlan {
        let object = PinnedObjectId(7);
        counters_plan(
            (0..count)
                .map(|index| {
                    exact_slot(
                        index,
                        object,
                        0x10 + u64::from(index) * 0x10,
                        0,
                        vec![ModuleId(0)],
                    )
                })
                .collect(),
            vec![exact_module(0, object)],
            8,
        )
    }

    #[test]
    fn counter_consumed_history_prevents_tail_withdrawal() {
        let mut history = counter_history_plan(2);
        assert_eq!(history.counter_consumed_end(), 0);
        history.consume_counter_extent(0, 2).unwrap();
        history.deactivate(1);
        let consumed = history.clone();

        // Even a never-published rollback consumed its original ordinal.
        history.withdraw_unlinked_additions(1);
        assert_eq!(history, consumed, "consumed rollback holes stay allocated");

        let delta = history.extend_exact(counter_history_plan(2)).unwrap();
        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].index, 2, "the retry needs a fresh ordinal");
        assert_eq!(
            AttachKey::of(&delta.new[0]),
            AttachKey::of(&history.slots[1])
        );
        assert_eq!(history.slots[..2], consumed.slots);
        assert_eq!(history.counter_consumed_end(), 2);

        // A later planning-only cell still has the ordinary cleanup behavior.
        history.deactivate(2);
        history.withdraw_unlinked_additions(1);
        assert_eq!(history.slots, consumed.slots);
        assert_eq!(history.counter_consumed_end(), 2);
        let delta = history.extend_exact(counter_history_plan(2)).unwrap();
        assert_eq!(delta.new[0].index, 2);
        history.consume_counter_extent(2, 3).unwrap();
        assert_eq!(history.counter_consumed_end(), 3);
        assert!(!history.is_active(1) && history.is_active(2));
        assert!(history.validate_slot_index().is_ok());
    }

    #[test]
    fn counter_consumed_history_prevents_tail_compaction() {
        let mut history = counter_history_plan(3);
        history.consume_counter_extent(0, 3).unwrap();
        history.extend_exact(counter_history_plan(5)).unwrap();
        for index in [1, 2, 3] {
            history.deactivate(index);
        }
        let prefix = history.slots[..3].to_vec();
        let fresh_key = AttachKey::of(&history.slots[4]);

        let mapping = history.excise_unlinked_tail_cells(1, &BTreeSet::from([1, 2, 3, 99]));
        assert_eq!(mapping, [0, 1, 2, u32::MAX, 3]);
        assert_eq!(history.slots[..3], prefix);
        assert_eq!(history.slots.len(), 4);
        assert_eq!(history.slots[3].index, 3);
        assert_eq!(AttachKey::of(&history.slots[3]), fresh_key);
        assert!(history.is_active(0) && history.is_active(3));
        assert!(!history.is_active(1) && !history.is_active(2));
        assert_eq!(history.counter_consumed_end(), 3);
        assert!(history.validate_slot_index().is_ok());

        history.consume_counter_extent(3, 4).unwrap();
        assert_eq!(history.counter_consumed_end(), 4);
        assert_eq!(history.slots[..3], prefix);
    }

    #[test]
    fn counter_consumption_refuses_invalid_extents_without_mutation() {
        for policy in [AdmissionPolicy::Detailed, inventory_policy(8)] {
            let mut plan =
                AttachPlan::from_slots_with_policy(counter_history_plan(2).slots, policy).unwrap();
            let before = plan.clone();
            assert_eq!(
                plan.consume_counter_extent(0, 2),
                Err(CounterHistoryError::Policy)
            );
            assert_eq!(plan, before);
        }

        let initial = counter_history_plan(2);
        for (first, end, expected) in [
            (0, 0, CounterHistoryError::Extent),
            (0, 1, CounterHistoryError::Extent),
            (0, 3, CounterHistoryError::Extent),
            (1, 2, CounterHistoryError::Frontier),
            (0, u32::MAX, CounterHistoryError::Extent),
        ] {
            let mut plan = initial.clone();
            assert_eq!(plan.consume_counter_extent(first, end), Err(expected));
            assert_eq!(
                plan, initial,
                "refused extent [{first},{end}) mutates nothing"
            );
        }
        let mut sparse = initial.clone();
        sparse.slots[1].index = 7;
        let mut inactive = initial.clone();
        inactive.deactivate(1);
        for mut plan in [sparse, inactive] {
            let before = plan.clone();
            assert_eq!(
                plan.consume_counter_extent(0, 2),
                Err(CounterHistoryError::Topology)
            );
            assert_eq!(plan, before);
        }

        let mut history = initial;
        history.consume_counter_extent(0, 2).unwrap();
        let before = history.clone();
        assert_eq!(
            history.consume_counter_extent(0, 2),
            Err(CounterHistoryError::Frontier)
        );
        assert_eq!(
            history, before,
            "consumption cannot replay or refund an extent"
        );

        // Make an otherwise consistent short plan: only its consumed floor is wrong.
        let mut truncated = history.clone();
        truncated.slots.truncate(1);
        truncated.aggregate_owners.truncate(1);
        truncated.slot_by_key.retain(|_, position| *position < 1);
        assert!(truncated.validate_slot_index().is_err());
        let mut changed_policy = history;
        changed_policy.admission_policy = AdmissionPolicy::Detailed;
        assert!(changed_policy.validate_slot_index().is_err());
    }

    #[test]
    fn counter_consumption_preserves_inactive_published_positions() {
        let mut history = counter_history_plan(2);
        history.consume_counter_extent(0, 2).unwrap();
        let consumed = history.clone();
        assert_eq!(
            consumed.counter_consumed_end(),
            2,
            "clone retains consumption"
        );
        let before = history.clone();
        assert!(
            history
                .attested_subset(&BTreeSet::from([PinnedObjectId(7)]), &BTreeSet::new())
                .is_err(),
            "a consumed plan cannot become a fresh renumbered subset"
        );
        assert_eq!(history, before);

        let delta = history.extend_exact(counter_history_plan(3)).unwrap();
        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].index, 2);
        assert_eq!(history.counter_consumed_end(), 2);
        assert_eq!(history.slots[..2], consumed.slots);
        history.consume_counter_extent(2, 3).unwrap();

        // Publication belongs to the directory. A consumed row may already
        // be published; inactivity cannot erase its original identity/owner.
        let old = history.slots[1].clone();
        history.deactivate(1);
        let mapping = history.excise_unlinked_tail_cells(0, &BTreeSet::from([1]));
        assert_eq!(mapping, [0, 1, 2]);
        assert_eq!(history.slots[1], old);
        assert_eq!(history.module_of_slot(1), Some(ModuleId(0)));
        assert_eq!(history.active_module_of_slot(1), None);
        assert!(!history.is_active(1));
        assert_eq!(history.counter_consumed_end(), 3);
        assert_eq!(consumed.counter_consumed_end(), 2, "clone is independent");
        assert!(history.validate_slot_index().is_ok());
    }

    #[test]
    fn unconsumed_policies_preserve_tail_cleanup() {
        for policy in [
            AdmissionPolicy::Detailed,
            inventory_policy(8),
            counters_policy(8),
        ] {
            let fixture = counter_history_plan(3);
            let mut initial = AttachPlan::from_slots_with_policy(fixture.slots, policy).unwrap();
            initial.modules = fixture.modules;
            assert_eq!(initial.counter_consumed_end(), 0);

            let mut withdrawn = initial.clone();
            withdrawn.deactivate(1);
            withdrawn.deactivate(2);
            withdrawn.withdraw_unlinked_additions(1);
            assert_eq!(withdrawn.slots, initial.slots[..1]);
            assert_eq!(withdrawn.counter_consumed_end(), 0);
            assert!(withdrawn.validate_slot_index().is_ok());

            let mut compacted = initial.clone();
            compacted.deactivate(1);
            assert_eq!(
                compacted.excise_unlinked_tail_cells(1, &BTreeSet::from([0, 1, 99])),
                [0, u32::MAX, 1]
            );
            assert_eq!(compacted.slots[0], initial.slots[0]);
            assert_eq!(compacted.slots[1].index, 1);
            assert_eq!(
                AttachKey::of(&compacted.slots[1]),
                AttachKey::of(&initial.slots[2])
            );
            assert_eq!(compacted.counter_consumed_end(), 0);
            assert!(compacted.validate_slot_index().is_ok());

            let mut active_tail = initial.clone();
            active_tail.deactivate(1);
            let before = active_tail.clone();
            active_tail.withdraw_unlinked_additions(1);
            assert_eq!(
                active_tail, before,
                "active tail cells still prevent withdrawal"
            );

            let subset = initial
                .attested_subset(&BTreeSet::from([PinnedObjectId(7)]), &BTreeSet::new())
                .unwrap();
            assert_eq!(subset.slots, initial.slots);
            assert_eq!(subset.counter_consumed_end(), 0);
        }
        let default = AttachPlan::from_slots(counter_history_plan(1).slots);
        assert_eq!(default.admission_policy(), AdmissionPolicy::Detailed);
        assert_eq!(default.counter_consumed_end(), 0);
    }

    #[test]
    fn counters_admits_a_complete_union_and_refuses_a_module_whole() {
        let sources: Vec<_> = (0..3)
            .map(|index| {
                scanned_with(
                    ObjectKey {
                        device: TEST_OBJECT.device,
                        inode: TEST_OBJECT.inode + index,
                    },
                    &format!("/opt/counter-{index}.so"),
                    (0..4).map(|n| n * 8),
                )
            })
            .collect();
        let plan = build_from_test_sources_with_policy(&sources, &[], counters_policy(12));
        assert_eq!(plan.slots.len(), 12);
        assert!(plan.modules_skipped.is_empty());
        assert_eq!(plan.admission_policy(), counters_policy(12));
        assert!(plan.slots.iter().all(|slot| slot.descriptor_index == 0
            && slot.semantics == SlotSemantics::COUNT_ONLY
            && !slot.semantic_authorized));
        assert!(plan.validate_slot_index().is_ok());

        let refused = build_from_test_sources_with_policy(&sources, &[], counters_policy(4));
        assert_eq!(refused.slots.len(), 4);
        assert_eq!(refused.modules_skipped.len(), 2);
        assert!(
            refused
                .slots
                .iter()
                .all(|slot| slot.object == refused.slots[0].object)
        );
        assert!(
            refused
                .modules_skipped
                .iter()
                .all(|skip| skip.reason.contains("counter endpoints"))
        );
        let none = build_from_test_sources_with_policy(&sources[..1], &[], counters_policy(3));
        assert!(
            none.slots.is_empty(),
            "a refused provider leaves no partial union"
        );
        assert!(none.modules.is_empty());
        assert_eq!(none.modules_skipped.len(), 1);

        let all_tables = build_from_test_sources_with_policy(
            &[scanned_with_heuristic_tables(64)],
            &[],
            counters_policy(64),
        );
        assert_eq!(all_tables.slots.len(), 64);
        assert_eq!(all_tables.uncorroborated_candidates, 0);
        let past_legacy_slots = build_from_test_sources_with_policy(
            &[scanned_with(
                TEST_OBJECT,
                "/opt/counter-large.so",
                (0..513).map(|index| index * 8),
            )],
            &[],
            counters_policy(513),
        );
        assert_eq!(past_legacy_slots.slots.len(), 513);
        assert_eq!(past_legacy_slots.slots[512].index, 512);
        assert!(past_legacy_slots.modules_skipped.is_empty());

        let rebuilt = refused.rebuild_from_sources(&sources, &[], &PinnedObjects::empty());
        assert_eq!(rebuilt.admission_policy(), counters_policy(4));
        let descriptor = crate::kinds::function_id("C_Sign").unwrap() + 1;
        let error = AttachPlan::from_slots_with_policy(
            vec![exact_slot(
                0,
                PinnedObjectId(7),
                0x10,
                descriptor,
                vec![ModuleId(0)],
            )],
            counters_policy(1),
        )
        .unwrap_err();
        assert!(
            error.contains("counter") && error.contains("count-only"),
            "{error}"
        );

        // These are the existing runtime factories. An absent explicit
        // counter admission request keeps their previous policy selection.
        let detailed = build_from_reconciled_modules(&sources);
        assert_eq!(detailed.admission_policy(), AdmissionPolicy::Detailed);
        let inventory = build_from_test_sources_with_policy(&sources, &[], inventory_policy(12));
        assert_eq!(inventory.admission_policy(), inventory_policy(12));
        assert_eq!(inventory.slots.len(), 12);
    }

    #[test]
    fn counter_growth_preserves_allocated_positions_and_refuses_whole_module() {
        let aliased = manifest_with(vec![resolved("C_Sign", 0x10), resolved("C_Verify", 0x10)]);
        let mut other_inode = manifest_with(vec![resolved("C_Sign", 0x10)]);
        assert_eq!(
            aliased.provenance_objects[0].identity.sha256,
            other_inode.provenance_objects[0].identity.sha256
        );
        other_inode.provenance_objects[0].inode = 99;
        let initial =
            build_from_test_sources_with_policy(&[], &[aliased, other_inode], counters_policy(3));
        assert_eq!(
            initial.slots.len(),
            2,
            "equal bytes do not merge different physical objects"
        );
        assert_eq!(
            initial
                .slots
                .iter()
                .map(AttachKey::of)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                AttachKey {
                    object: PinnedObjectId(42),
                    file_offset: 0x10
                },
                AttachKey {
                    object: PinnedObjectId(99),
                    file_offset: 0x10
                },
            ])
        );
        let alias = initial
            .slots
            .iter()
            .find(|slot| slot.object == PinnedObjectId(42))
            .unwrap();
        assert_eq!(alias.names, ["C_Sign", "C_Verify"]);
        assert!(alias.aliased);
        let prefix: Vec<_> = initial
            .slots
            .iter()
            .map(|slot| (slot.index, AttachKey::of(slot)))
            .collect();
        let mut plan = initial.clone();
        let surviving = counters_plan(vec![initial.slots[0].clone()], initial.modules.clone(), 3);
        let retired = plan.extend_exact(surviving).unwrap();
        assert_eq!(retired.retire.len(), 1);
        assert_eq!(retired.retire[0].index, 1);
        assert!(!plan.is_active(1));
        let appended = plan.extend_exact(initial.clone()).unwrap();
        assert_eq!(appended.new.len(), 1);
        assert_eq!(appended.new[0].index, 2);
        assert_eq!(AttachKey::of(&appended.new[0]), prefix[1].1);
        assert!(!plan.is_active(1));
        assert!(plan.is_active(2));
        assert_eq!(
            plan.slots[..2]
                .iter()
                .map(|slot| (slot.index, AttachKey::of(slot)))
                .collect::<Vec<_>>(),
            prefix
        );

        let mut one_more = initial.slots.clone();
        one_more.push(exact_slot(
            2,
            initial.slots[0].object,
            0x1000,
            0,
            initial.slots[0].module_ids.clone(),
        ));
        let candidate = counters_plan(one_more, initial.modules.clone(), 3);
        let before = plan.clone();
        let error = plan.extend_exact(candidate).unwrap_err();
        assert!(error.contains("counter endpoints"), "{error}");
        assert_eq!(plan, before, "retired IDs cannot fund a partial extension");
        for policy in [
            counters_policy(4),
            AdmissionPolicy::Detailed,
            inventory_policy(3),
        ] {
            let mut mismatch =
                AttachPlan::from_slots_with_policy(initial.slots.clone(), policy).unwrap();
            mismatch.modules = initial.modules.clone();
            let error = plan.extend_exact(mismatch).unwrap_err();
            assert!(error.contains("admission policy"), "{error}");
            assert_eq!(plan, before, "policy/budget mismatch must precede mutation");
        }
    }

    #[test]
    fn selection_table_capacity_refusal_names_the_counters_resource() {
        let object = PinnedObjectId(7);
        let allocated = counters_plan(
            vec![exact_slot(0, object, 0x10, 0, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
            2,
        );
        let mut rebuilt = counters_plan(vec![], allocated.modules.clone(), 2);
        rebuilt
            .add_selection_table(
                &allocated,
                ModuleId(0),
                [selection_target(object, 0x20, "C_Encrypt")],
            )
            .unwrap();
        assert_eq!(rebuilt.slots.len(), 1);
        assert_eq!(rebuilt.slots[0].descriptor_index, 0);
        assert_eq!(rebuilt.slots[0].semantics, SlotSemantics::COUNT_ONLY);
        assert!(!rebuilt.slots[0].semantic_authorized);
        let before = rebuilt.clone();
        let error = rebuilt
            .add_selection_table(
                &allocated,
                ModuleId(0),
                [selection_target(object, 0x30, "C_Decrypt")],
            )
            .unwrap_err();
        assert!(
            error.contains("selection table needs 1 more of the 2 counter endpoints"),
            "{error}"
        );
        assert_eq!(rebuilt, before, "a refused table leaves no prefix");
    }

    #[test]
    fn inventory_admits_all_sixty_four_heuristic_tables_while_detailed_stays_k4() {
        let scanned = scanned_with_heuristic_tables(64);

        let detailed = build_from_reconciled_modules(std::slice::from_ref(&scanned));
        assert_eq!(detailed.admission_policy(), AdmissionPolicy::detailed());
        assert_eq!(detailed.slots.len(), MAX_TABLES_PER_OBJECT);
        assert_eq!(detailed.uncorroborated_candidates, 60);

        let inventory = build_from_test_sources_with_policy(
            std::slice::from_ref(&scanned),
            &[],
            inventory_policy(64),
        );
        assert_eq!(inventory.slots.len(), 64);
        assert_eq!(inventory.uncorroborated_candidates, 0);
        assert!(inventory.slots.iter().all(|slot| slot.descriptor_index == 0
            && slot.semantics == SlotSemantics::COUNT_ONLY
            && !slot.semantic_authorized));
        assert!(
            inventory
                .slots
                .iter()
                .any(|slot| slot.file_offset == 63 * 8),
            "the endpoint in the last heuristic table is admitted"
        );
    }

    #[test]
    fn inventory_checked_constructor_rejects_invalid_indices_and_duplicate_targets() {
        let object = PinnedObjectId(7);
        let non_dense = vec![exact_slot(1, object, 0x10, 0, vec![ModuleId(0)])];
        assert!(AttachPlan::from_slots_with_policy(non_dense, inventory_policy(2)).is_err());

        let duplicate = vec![
            exact_slot(0, object, 0x10, 0, vec![ModuleId(0)]),
            exact_slot(1, object, 0x10, 0, vec![ModuleId(0)]),
        ];
        assert!(AttachPlan::from_slots_with_policy(duplicate, inventory_policy(2)).is_err());
    }

    #[test]
    fn inventory_multi_provider_rebuild_crosses_512_without_duplicate_view_allocations() {
        let sources: Vec<_> = (0..9)
            .map(|index| {
                let key = ObjectKey {
                    device: TEST_OBJECT.device,
                    inode: TEST_OBJECT.inode + index,
                };
                scanned_with(
                    key,
                    &format!("/opt/provider-{index}.so"),
                    (0..64).map(|n| n * 8),
                )
            })
            .collect();
        let policy = inventory_policy(576);
        let mut plan = build_from_test_sources_with_policy(&sources[..8], &[], policy);
        assert_eq!(plan.slots.len(), 512);

        let mut duplicate_views = sources.clone();
        for source in &sources {
            let mut another_view = source.clone();
            another_view.scanned.view = ProcessViewId(1);
            duplicate_views.push(another_view);
        }
        let rebuilt = plan.rebuild_from_sources(&duplicate_views, &[], &PinnedObjects::empty());
        assert_eq!(rebuilt.slots.len(), 576);
        assert!(rebuilt.modules_skipped.is_empty());
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert_eq!(delta.new.len(), 64);
        assert_eq!(plan.slots.len(), 576);
        assert!(plan.is_active(575));
        assert!(delta.retire.is_empty());

        let refused = build_from_test_sources_with_policy(&sources, &[], inventory_policy(575));
        assert_eq!(
            refused.slots.len(),
            512,
            "the ninth provider is refused whole"
        );
        assert_eq!(refused.modules_skipped.len(), 1);
        assert!(
            refused
                .slots
                .iter()
                .all(|slot| slot.object != sources[8].object)
        );

        let mut expanded = sources.clone();
        expanded[8] = scanned_with(
            sources[8].scanned.key,
            "/opt/provider-8.so",
            (0..65).map(|n| n * 8),
        );
        let rebuilt = plan.rebuild_from_sources(&expanded, &[], &PinnedObjects::empty());
        assert_eq!(rebuilt.modules_skipped.len(), 1);
        assert_eq!(rebuilt.modules_skipped[0].subject, "/opt/provider-8.so");
        assert!(
            rebuilt.modules_skipped[0]
                .reason
                .starts_with("admitted module needs 1 more;"),
            "{:?}",
            rebuilt.modules_skipped[0]
        );
        // The over-budget provider was already admitted: it keeps its 64
        // endpoints and leaves no new prefix (G-03).
        assert_eq!(
            rebuilt.slots.len(),
            576,
            "an over-budget admitted provider keeps its endpoints and adds no prefix"
        );
        assert!(
            rebuilt
                .slots
                .iter()
                .all(|slot| slot.object != sources[8].object || slot.file_offset < 64 * 8),
            "no endpoint of the growth is admitted"
        );
        assert_eq!(
            plan.slots.len(),
            576,
            "building a snapshot does not mutate allocations"
        );
        // A capacity refusal is neither an unload nor quiescence evidence:
        // applying the refused snapshot retires no old probe and allocates
        // nothing.
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert!(delta.new.is_empty());
        assert!(delta.replace.is_empty());
        assert!(delta.retire.is_empty());
        assert_eq!(plan.active_slot_count(), 576);
    }

    #[test]
    fn inventory_selection_overlaps_and_deduplicates_beyond_512() {
        let object = PinnedObjectId(7);
        let slots = (0..513)
            .map(|index| exact_slot(index, object, u64::from(index) * 8, 0, vec![ModuleId(0)]))
            .collect();
        let mut allocated = inventory_plan(slots, vec![exact_module(0, object)], 514);
        let mut selection = allocated.clone();
        selection
            .add_selection_table(
                &allocated,
                ModuleId(0),
                [
                    selection_target(object, 0, "C_Sign"),
                    selection_target(object, 0x10000, "C_Encrypt"),
                    selection_target(object, 0x10000, "C_Decrypt"),
                ],
            )
            .unwrap();
        assert_eq!(selection.slots.len(), 514);
        let delta = allocated.extend_exact(selection).unwrap();
        assert_eq!(delta.new.len(), 1);
        assert_eq!(delta.new[0].index, 513);
        assert_eq!(delta.new[0].names, ["C_Decrypt", "C_Encrypt"]);
        assert!(delta.new[0].aliased);
        assert_eq!(delta.new[0].semantics, SlotSemantics::COUNT_ONLY);
    }

    #[test]
    fn inventory_unequal_budgets_reject_extension_and_selection_without_mutation() {
        let object = PinnedObjectId(7);
        let slots = vec![exact_slot(0, object, 0x10, 0, vec![ModuleId(0)])];
        let mut accepted = inventory_plan(slots.clone(), vec![exact_module(0, object)], 513);
        let unequal = inventory_plan(slots, vec![exact_module(0, object)], 514);
        let before = accepted.clone();
        assert!(accepted.extend_exact(unequal.clone()).is_err());
        assert_eq!(accepted, before);
        assert!(
            accepted
                .add_selection_table(
                    &unequal,
                    ModuleId(0),
                    [selection_target(object, 0x20, "C_Encrypt")],
                )
                .is_err()
        );
        assert_eq!(accepted, before);
    }

    #[test]
    fn inventory_admission_rejects_slot_count_overflow() {
        let policy = inventory_policy(1);

        assert!(policy.checked_required(usize::MAX, 1).is_err());
    }

    #[test]
    fn inventory_unions_published_heuristic_forwarded_aliased_and_distinct_equal_bytes() {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let mut scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0x10]);
        scanned.scanned.tables[0].live_return = true;
        let forwarded_key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 77,
        };
        scanned.scanned.tables[0].entries.push(ScannedEntry {
            name: "C_Encrypt",
            object: forwarded_key,
            object_path: "/opt/forwarded.so".into(),
            file_offset: 0x20,
        });
        scanned.entry_objects[0].push(PinnedObjectId(77));
        scanned.scanned.tables.push(ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name: "C_Decrypt",
                object: TEST_OBJECT,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x30,
            }],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x9000,
            file_offset: Some(0x1000),
            live_return: false,
            manifest_supported: false,
        });
        scanned.entry_objects.push(vec![scanned.object]);

        let aliased = manifest_with(vec![resolved("C_Sign", 0x10), resolved("C_Verify", 0x10)]);
        let mut equal_bytes_other_object = manifest_with(vec![resolved("C_Sign", 0x10)]);
        equal_bytes_other_object.provenance_objects[0].inode = 99;

        let plan = build_from_test_sources_with_policy(
            &[scanned],
            &[aliased, equal_bytes_other_object],
            inventory_policy(4),
        );
        let keys: BTreeSet<_> = plan.slots.iter().map(AttachKey::of).collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                AttachKey {
                    object: PinnedObjectId(42),
                    file_offset: 0x10,
                },
                AttachKey {
                    object: PinnedObjectId(42),
                    file_offset: 0x30,
                },
                AttachKey {
                    object: PinnedObjectId(77),
                    file_offset: 0x20,
                },
                AttachKey {
                    object: PinnedObjectId(99),
                    file_offset: 0x10,
                },
            ])
        );
        let alias = plan
            .slots
            .iter()
            .find(|slot| slot.object == PinnedObjectId(42) && slot.file_offset == 0x10)
            .unwrap();
        assert_eq!(alias.names, ["C_Sign", "C_Verify"]);
        assert!(alias.aliased);
        assert!(
            plan.slots
                .iter()
                .all(|slot| slot.semantics == SlotSemantics::COUNT_ONLY)
        );
    }

    #[test]
    fn inventory_initial_admission_is_exact_at_budget_and_refuses_one_over_whole() {
        let scanned = scanned_with(TEST_OBJECT, "/opt/p11.so", [0, 8, 16]);
        let exact = build_from_test_sources_with_policy(
            std::slice::from_ref(&scanned),
            &[],
            inventory_policy(3),
        );
        assert_eq!(exact.slots.len(), 3);
        assert!(exact.modules_skipped.is_empty());

        let over = build_from_test_sources_with_policy(&[scanned], &[], inventory_policy(2));
        assert!(over.slots.is_empty(), "a refused module leaves no prefix");
        assert!(over.modules.is_empty());
        assert_eq!(over.modules_skipped.len(), 1);
        assert!(over.modules_skipped[0].reason.contains("only 2"));
    }

    #[test]
    fn inventory_budget_is_carried_through_bootstrap_rebuild_selection_and_extension() {
        let object = PinnedObjectId(7);
        let mut bootstrap = inventory_plan(vec![], vec![exact_module(0, object)], 1);
        bootstrap
            .add_provisional_get_function_list(ProvisionalGetFunctionList {
                module: ModuleId(0),
                object,
                object_path: "/opt/p11.so".into(),
                file_offset: 0x10,
            })
            .unwrap();
        assert!(
            bootstrap
                .add_provisional_get_function_list(ProvisionalGetFunctionList {
                    module: ModuleId(0),
                    object,
                    object_path: "/opt/p11.so".into(),
                    file_offset: 0x20,
                })
                .is_err()
        );

        let mut committed = inventory_plan(
            vec![exact_slot(0, object, 0x10, 0, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
            3,
        );
        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: u64::from(object.0),
        };
        let rebuilt = committed.rebuild_from_sources(
            &[scanned_with(key, "/opt/p11.so", [0x10, 0x20, 0x30])],
            &[],
            &PinnedObjects::empty(),
        );
        assert_eq!(rebuilt.admission_policy(), inventory_policy(3));
        let delta = committed.extend_exact(rebuilt).unwrap();
        assert_eq!(delta.new.len(), 2);
        assert_eq!(committed.slots.len(), 3);

        let mut selection = committed.clone();
        let before = selection.clone();
        assert!(
            selection
                .add_selection_table(
                    &committed,
                    ModuleId(0),
                    [selection_target(object, 0x40, "C_Encrypt")],
                )
                .is_err()
        );
        assert_eq!(selection, before, "selection refusal is atomic");

        let detailed = exact_plan(
            vec![exact_slot(0, object, 0x10, 0, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
        );
        let before = committed.clone();
        assert!(committed.extend_exact(detailed).is_err());
        assert_eq!(committed, before, "mode policy cannot change in extension");
    }

    #[test]
    fn inventory_retirement_never_reuses_ids_or_refunds_lifetime_budget() {
        let object = PinnedObjectId(7);
        let slots = vec![
            exact_slot(0, object, 0x10, 0, vec![ModuleId(0)]),
            exact_slot(1, object, 0x20, 0, vec![ModuleId(0)]),
        ];
        let mut plan = inventory_plan(slots, vec![exact_module(0, object)], 3);
        let surviving = inventory_plan(
            vec![exact_slot(0, object, 0x10, 0, vec![ModuleId(0)])],
            vec![exact_module(0, object)],
            3,
        );
        plan.extend_exact(surviving).unwrap();
        assert!(!plan.is_active(1));

        let reappeared = inventory_plan(
            vec![
                exact_slot(0, object, 0x10, 0, vec![ModuleId(0)]),
                exact_slot(1, object, 0x20, 0, vec![ModuleId(0)]),
            ],
            vec![exact_module(0, object)],
            3,
        );
        let delta = plan.extend_exact(reappeared).unwrap();
        assert_eq!(delta.new[0].index, 2);
        assert!(!plan.is_active(1));

        let one_more = inventory_plan(
            vec![
                exact_slot(0, object, 0x10, 0, vec![ModuleId(0)]),
                exact_slot(1, object, 0x20, 0, vec![ModuleId(0)]),
                exact_slot(2, object, 0x30, 0, vec![ModuleId(0)]),
            ],
            vec![exact_module(0, object)],
            3,
        );
        let before = plan.clone();
        assert!(plan.extend_exact(one_more).is_err());
        assert_eq!(plan, before, "retirement does not refund an endpoint id");
    }

    /// A provider object publishing `tables` distinct function tables of
    /// `entries` endpoints each, every endpoint inside the object itself.
    /// `live_return` corroborates every table (a live `C_GetFunctionList`
    /// return), which makes the module a corroborated provider.
    fn provider_with_tables(
        inode: u32,
        path: &str,
        tables: usize,
        entries: usize,
        live_return: bool,
    ) -> ReconciledModule {
        use crate::discovery::scan::{ScannedEntry, ScannedTable};

        let key = scanned_key(PinnedObjectId(inode));
        let mut module = scanned_with(key, path, []);
        let object = module.object;
        module.scanned.tables = (0..tables)
            .map(|table| ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: (0..entries)
                    .map(|entry| ScannedEntry {
                        name: "C_Sign",
                        object: key,
                        object_path: path.into(),
                        file_offset: ((table * entries + entry) * 8) as u64,
                    })
                    .collect(),
                null_entries: vec![],
                unpinned: vec![],
                address: 0x10_0000 + table as u64 * 0x1000,
                file_offset: Some(table as u64 * 0x1000),
                live_return,
                manifest_supported: false,
            })
            .collect();
        module.entry_objects = vec![vec![object; entries]; tables];
        module
    }

    fn scoped_plan(modules: &[ReconciledModule], scope: AdmissionScope) -> AttachPlan {
        build_from_sources_scoped(modules, &[], &PinnedObjects::empty(), false, scope)
    }

    fn slots_of(plan: &AttachPlan, inode: u32) -> usize {
        plan.slots
            .iter()
            .filter(|slot| slot.object == PinnedObjectId(inode))
            .count()
    }

    fn refusal_of<'a>(plan: &'a AttachPlan, path: &str) -> Option<&'a Skipped> {
        plan.modules_skipped
            .iter()
            .find(|skipped| skipped.subject == path)
    }

    fn replace_table_targets(
        module: &mut ReconciledModule,
        table: usize,
        targets: &[(&'static str, u32, u64)],
    ) {
        module.scanned.tables[table].entries = targets
            .iter()
            .map(
                |&(name, object, file_offset)| crate::discovery::scan::ScannedEntry {
                    name,
                    object: scanned_key(PinnedObjectId(object)),
                    object_path: if PinnedObjectId(object) == module.object {
                        module.scanned.path.clone()
                    } else {
                        format!("/opt/obj{object}.so")
                    },
                    file_offset,
                },
            )
            .collect();
        module.entry_objects[table] = targets
            .iter()
            .map(|&(_, object, _)| PinnedObjectId(object))
            .collect();
    }

    /// The first table's three fresh keys already fail, but the whole group
    /// wants five: aliases/views/overlap dedup, equal offsets on distinct
    /// objects stay distinct, and another admitted module's key costs no slot.
    #[test]
    fn whole_module_demand_unions_later_tables_views_aliases_and_shared_targets() {
        let existing =
            provider_with_tables(201, "/opt/existing.so", 1, MAX_SLOTS as usize - 2, true);
        let mut refused = provider_with_tables(202, "/opt/refused.so", 2, 4, true);
        replace_table_targets(
            &mut refused,
            0,
            &[
                ("C_Sign", 202, 0x10),
                ("C_Sign", 202, 0x20),
                ("C_Sign", 202, 0x30),
                ("C_Sign", 201, 0),
            ],
        );
        replace_table_targets(
            &mut refused,
            1,
            &[
                ("C_Sign", 202, 0x30),
                ("C_Sign", 202, 0x40),
                ("C_Verify", 202, 0x40),
                ("C_Sign", 203, 0x40),
            ],
        );
        let mut repeated_view = refused.clone();
        repeated_view.scanned.view = ProcessViewId(99);
        let plan = scoped_plan(&[refused, repeated_view, existing], AdmissionScope::Shared);

        assert_eq!(plan.slots.len(), MAX_SLOTS as usize - 2);
        assert_eq!(plan.modules.len(), 1, "no refused prefix or duplicate view");
        assert_eq!(plan.modules_skipped.len(), 1);
        let refusal = refusal_of(&plan, "/opt/refused.so").unwrap();
        assert!(
            refusal.reason.starts_with("module needs 5 more;"),
            "{refusal:?}"
        );
    }

    #[test]
    fn whole_module_demand_preserves_the_shared_reserve() {
        let reserve = shared_scope_reserve(MAX_SLOTS as usize);
        let open = MAX_SLOTS as usize - reserve;
        let existing = provider_with_tables(211, "/opt/existing.so", 1, open - 2, false);
        let refused = provider_with_tables(212, "/opt/refused.so", 2, 3, false);
        let plan = scoped_plan(&[existing, refused], AdmissionScope::Shared);

        assert_eq!(plan.slots.len(), open - 2);
        let refusal = refusal_of(&plan, "/opt/refused.so").unwrap();
        assert!(
            refusal.reason.starts_with("module needs 6 more;"),
            "{refusal:?}"
        );
        assert!(
            refusal.reason.contains(&format!("{reserve} are reserved")),
            "{refusal:?}"
        );
    }

    /// Broad admission requires the scan union too, even when a manifest
    /// subset has already failed before any scan-table demand is considered.
    #[test]
    fn whole_module_demand_unions_scan_after_an_early_manifest_refusal() {
        let mut scan = provider_with_tables(42, "/opt/p11.so", 2, 3, false);
        replace_table_targets(
            &mut scan,
            0,
            &[
                ("C_Sign", 42, 0),
                ("C_Sign", 42, 0x100000),
                ("C_Verify", 42, 0x100008),
            ],
        );
        replace_table_targets(
            &mut scan,
            1,
            &[
                ("C_Sign", 42, 0x100008),
                ("C_Sign", 42, 0x100010),
                ("C_Verify", 42, 0),
            ],
        );
        let manifest = manifest_with(
            (0..=MAX_SLOTS)
                .map(|index| resolved("C_Sign", u64::from(index) * 8))
                .collect(),
        );
        let plan = build_from_sources_with(
            &[scan],
            &[manifest],
            |key, _| u32::try_from(key.inode).ok().map(PinnedObjectId),
            |_, _| true,
            ExistingAllocation {
                slots: 0,
                active: &BTreeMap::new(),
                owned: &BTreeMap::new(),
            },
            true,
            AdmissionPolicy::detailed(),
            AdmissionScope::Named,
        );

        assert!(plan.slots.is_empty() && plan.modules.is_empty());
        assert_eq!(plan.modules_skipped.len(), 1);
        assert!(
            plan.modules_skipped[0]
                .reason
                .starts_with(&format!("module needs {} more;", MAX_SLOTS + 4)),
            "{:?}",
            plan.modules_skipped
        );
    }

    #[test]
    fn whole_module_demand_excludes_scan_targets_without_a_valid_table() {
        let existing =
            provider_with_tables(221, "/opt/existing.so", 1, MAX_SLOTS as usize - 2, true);
        let refused = provider_with_tables(222, "/opt/refused.so", 2, 3, true);
        let mut lowered = lower_scanned(&refused);
        for (table, offset) in [(None, 0x9000), (Some(2), 0xa000)] {
            let mut stray = lower_scanned(&refused).targets.remove(0);
            stray.table = table;
            stray.file_offset = offset;
            lowered.targets.push(stray);
        }
        lowered.entries_seen = lowered.targets.len();
        let plan = merge(
            vec![lower_scanned(&existing), lowered],
            0,
            "absent".into(),
            ExistingAllocation {
                slots: 0,
                active: &BTreeMap::new(),
                owned: &BTreeMap::new(),
            },
            false,
            AdmissionPolicy::detailed(),
            AdmissionScope::Shared,
        );

        let refusal = refusal_of(&plan, "/opt/refused.so").unwrap();
        assert!(
            refusal.reason.starts_with("module needs 6 more;"),
            "{refusal:?}"
        );
        assert_eq!(plan.slots.len(), MAX_SLOTS as usize - 2);
    }

    #[test]
    fn whole_module_demand_keeps_named_heuristic_subset_reporting() {
        let existing =
            provider_with_tables(231, "/opt/existing.so", 1, MAX_SLOTS as usize - 2, false);
        let refused = provider_with_tables(232, "/opt/refused.so", 5, 3, false);
        let named = scoped_plan(&[existing, refused.clone()], AdmissionScope::Named);
        let refusal = refusal_of(&named, "/opt/refused.so").unwrap();
        assert!(
            refusal.reason.starts_with("module needs 3 more;"),
            "{refusal:?}"
        );
        assert_eq!(named.slots.len(), MAX_SLOTS as usize - 2);

        let prefix = scoped_plan(&[refused], AdmissionScope::Named);
        assert_eq!(
            prefix.slots.len(),
            12,
            "K4 admits its strongest four tables"
        );
        assert_eq!(prefix.uncorroborated_candidates, 1);
        assert!(prefix.modules_skipped.is_empty());
    }

    /// Retired keys cost fresh lifetime slots if they reappear. A failed
    /// growth keeps all old physical IDs and reports its nine-key union once.
    #[test]
    fn whole_module_demand_preserves_growth_and_retired_occupancy() {
        let existing =
            provider_with_tables(241, "/opt/existing.so", 1, MAX_SLOTS as usize - 12, true);
        let owner = provider_with_tables(242, "/opt/grown.so", 2, 2, true);
        let ended = provider_with_tables(243, "/opt/ended.so", 1, 4, true);
        let mut plan = scoped_plan(
            &[existing.clone(), owner.clone(), ended],
            AdmissionScope::Shared,
        );
        let without_ended = plan.rebuild_from_sources(
            &[existing.clone(), owner.clone()],
            &[],
            &PinnedObjects::empty(),
        );
        assert_eq!(plan.extend_exact(without_ended).unwrap().retire.len(), 4);
        let previous = plan.slots.clone();
        let mut grown = owner;
        replace_table_targets(
            &mut grown,
            0,
            &[
                ("C_Sign", 242, 0),
                ("C_Sign", 242, 8),
                ("C_Sign", 242, 0x10000),
                ("C_Sign", 242, 0x10008),
                ("C_Sign", 242, 0x10010),
                ("C_Sign", 242, 0x10018),
                ("C_Sign", 242, 0x10020),
            ],
        );
        replace_table_targets(
            &mut grown,
            1,
            &[
                ("C_Sign", 242, 16),
                ("C_Sign", 242, 24),
                ("C_Sign", 242, 0x10020),
                ("C_Sign", 242, 0x20000),
                ("C_Verify", 242, 0x20000),
                ("C_Sign", 242, 0x20008),
                ("C_Sign", 242, 0x20010),
                ("C_Sign", 241, 0),
                ("C_Sign", 243, 0),
            ],
        );

        for _ in 0..2 {
            let rebuilt = plan.rebuild_from_sources(
                &[existing.clone(), grown.clone()],
                &[],
                &PinnedObjects::empty(),
            );
            assert_eq!(rebuilt.modules_skipped.len(), 1);
            let omission = refusal_of(&rebuilt, "/opt/grown.so").unwrap();
            assert!(
                omission.reason.starts_with("admitted module needs 9 more;"),
                "{omission:?}"
            );
            assert!(omission.reason.contains("4 retired"), "{omission:?}");
            assert!(
                omission.reason.contains("kept its 4 attached endpoints"),
                "{omission:?}"
            );
            let delta = plan.extend_exact(rebuilt).unwrap();
            assert!(delta.new.is_empty() && delta.replace.is_empty() && delta.retire.is_empty());
            assert_eq!(plan.slots, previous, "no old identity or decoder changes");
            assert_eq!(plan.active_slot_count(), MAX_SLOTS as usize - 8);
            assert_eq!(
                plan.refused_modules().count(),
                1,
                "one omission across retries"
            );
        }
    }

    const P11_KIT: &str = "/usr/lib/x86_64-linux-gnu/libp11-kit.so.0.4.8";
    const TRUST: &str = "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so";
    const SOFTHSM: &str = "/usr/lib/softhsm/libsofthsm2.so";

    /// GT-5, the stock-desktop shape: an ambient `libp11-kit` decoding 64
    /// closure tables, ambient `p11-kit-trust`, and the SoftHSM2 the workload
    /// uses, all heuristic. First-come K4 admission (named scope, unchanged)
    /// hands p11-kit a 412-endpoint prefix and refuses SoftHSM. A shared scope
    /// admits both single-table providers in every discovery order, and
    /// refuses the closure array whole, saying why and how to aim the capture.
    #[test]
    fn shared_scope_admits_single_table_providers_ahead_of_a_proxy_closure_array() {
        let p11_kit = provider_with_tables(31, P11_KIT, 64, 103, false);
        let trust = provider_with_tables(32, TRUST, 1, 68, false);
        let softhsm = provider_with_tables(33, SOFTHSM, 1, 68, false);

        let named = scoped_plan(
            &[p11_kit.clone(), trust.clone(), softhsm.clone()],
            AdmissionScope::Named,
        );
        assert_eq!(named.admission_scope(), AdmissionScope::Named);
        assert_eq!(
            slots_of(&named, 31),
            MAX_TABLES_PER_OBJECT * 103,
            "named scope keeps the K4 prefix"
        );
        if (MAX_SLOTS as usize) < MAX_TABLES_PER_OBJECT * 103 + 2 * 68 {
            assert!(refusal_of(&named, SOFTHSM).is_some(), "the GT-5 outcome");
        }

        let orders = [
            [&p11_kit, &trust, &softhsm],
            [&p11_kit, &softhsm, &trust],
            [&trust, &p11_kit, &softhsm],
            [&trust, &softhsm, &p11_kit],
            [&softhsm, &p11_kit, &trust],
            [&softhsm, &trust, &p11_kit],
        ];
        for order in orders {
            let modules: Vec<_> = order.into_iter().cloned().collect();
            let shared = scoped_plan(&modules, AdmissionScope::Shared);
            let label: Vec<_> = modules.iter().map(|module| module.object.0).collect();

            assert_eq!(shared.admission_scope(), AdmissionScope::Shared);
            assert_eq!(
                slots_of(&shared, 33),
                68,
                "SoftHSM admitted whole: {label:?}"
            );
            assert_eq!(
                slots_of(&shared, 32),
                68,
                "p11-kit-trust admitted: {label:?}"
            );
            assert_eq!(slots_of(&shared, 31), 0, "no p11-kit prefix: {label:?}");
            assert_eq!(
                shared.modules_skipped.len(),
                1,
                "{:?}",
                shared.modules_skipped
            );
            let refusal = refusal_of(&shared, P11_KIT).expect("p11-kit refused whole");
            assert!(
                refusal.reason.starts_with(&format!(
                    "module needs {} more; only {MAX_SLOTS} attach slots are available; ",
                    64 * 103
                )),
                "{}",
                refusal.reason
            );
            assert!(
                refusal.reason.contains(
                    "refusing to attach a prefix of its 64 lookalike function tables \
                     (a proxy closure array is admitted whole or not at all)"
                ),
                "{}",
                refusal.reason
            );
            assert!(
                refusal.reason.contains(&format!(
                    "136 are in use (136 active, 0 retired; held by {SOFTHSM} 68, {TRUST} 68)"
                )),
                "{}",
                refusal.reason
            );
            assert!(
                refusal
                    .reason
                    .ends_with("; to capture one provider, name it with --module <path>"),
                "{}",
                refusal.reason
            );
            assert_eq!(
                shared.uncorroborated_candidates, 0,
                "a whole refusal spills nothing"
            );
        }
    }

    /// No module is admitted as a prefix in a shared scope. A corroborated
    /// provider that also decodes two heuristic lookalikes gets a prefix
    /// under named-scope K4 (its published table plus one heuristic table,
    /// the other spilled); in a shared scope the module is admitted whole or,
    /// as here, refused whole.
    #[test]
    fn shared_scope_never_admits_a_module_prefix() {
        let filled = MAX_SLOTS as usize - 112;
        let filler = provider_with_tables(51, "/opt/filler.so", 1, filled, true);
        let mut mixed = provider_with_tables(52, "/opt/mixed.so", 3, 50, false);
        mixed.scanned.tables[0].live_return = true;
        let modules = [filler, mixed];

        let named = scoped_plan(&modules, AdmissionScope::Named);
        assert_eq!(slots_of(&named, 52), 100, "named scope: a two-table prefix");
        assert_eq!(named.uncorroborated_candidates, 1);
        assert!(named.modules_skipped.is_empty());

        let shared = scoped_plan(&modules, AdmissionScope::Shared);
        assert_eq!(slots_of(&shared, 51), filled);
        assert_eq!(slots_of(&shared, 52), 0, "shared scope: whole or nothing");
        let refusal = refusal_of(&shared, "/opt/mixed.so").expect("refused whole");
        assert!(
            refusal.reason.starts_with(&format!(
                "module needs 150 more; only {MAX_SLOTS} attach slots are available; \
                 {filled} are in use ({filled} active, 0 retired; held by /opt/filler.so \
                 {filled}) — refusing to attach a prefix;"
            )),
            "a corroborated module is not held out of the reserve: {}",
            refusal.reason
        );
    }

    /// Uncorroborated modules leave the shared-scope reserve free, and a
    /// corroborated provider arriving later in the capture is admitted into
    /// it. The refusal says the reserve is why.
    #[test]
    fn shared_scope_reserve_holds_room_for_a_later_corroborated_provider() {
        let reserve = shared_scope_reserve(MAX_SLOTS as usize);
        assert_eq!(
            reserve,
            (MAX_SLOTS as usize / 4).max(104),
            "a quarter of the budget, never under one whole 3.2 function list"
        );
        let open = MAX_SLOTS as usize - reserve;
        let first = provider_with_tables(61, "/opt/ambient-a.so", 1, open - 80, false);
        let second = provider_with_tables(62, "/opt/ambient-b.so", 1, 80, false);
        let third = provider_with_tables(63, "/opt/ambient-c.so", 1, 10, false);
        let ambient = [first, second, third];

        let mut plan = scoped_plan(&ambient, AdmissionScope::Shared);
        assert_eq!(
            plan.slots.len(),
            open,
            "heuristic modules stop at the reserve"
        );
        assert_eq!(slots_of(&plan, 63), 0);
        let refusal = refusal_of(&plan, "/opt/ambient-c.so").expect("refused at the reserve");
        assert!(
            refusal.reason.contains(&format!(
                "{open} are in use ({open} active, 0 retired; held by /opt/ambient-a.so {}, \
                 /opt/ambient-b.so 80); {reserve} are reserved for providers with a \
                 corroborated function table — refusing to attach a prefix;",
                open - 80
            )),
            "{}",
            refusal.reason
        );

        let late = provider_with_tables(64, "/opt/late-provider.so", 1, reserve, true);
        let mut all = ambient.to_vec();
        all.push(late);
        let rebuilt = plan.rebuild_from_sources(&all, &[], &PinnedObjects::empty());
        assert_eq!(rebuilt.admission_scope(), AdmissionScope::Shared);
        assert_eq!(
            slots_of(&rebuilt, 64),
            reserve,
            "the late corroborated provider takes the reserve"
        );
        assert_eq!(
            slots_of(&rebuilt, 63),
            0,
            "the reserve stays closed to heuristics"
        );
        let delta = plan.extend_exact(rebuilt).unwrap();
        assert_eq!(delta.new.len(), reserve);
        assert_eq!(plan.slots.len(), MAX_SLOTS as usize);
    }

    /// A capacity refusal says how many allocated slots are live and how many
    /// are retired — lifetime cells never reused — and which modules hold the
    /// live ones. Named scope keeps its rule and its ending: no reserve, no
    /// `--module` hint.
    #[test]
    fn capacity_refusal_names_active_and_retired_slots_and_their_holders() {
        let capacity = MAX_SLOTS as usize;
        let kept = provider_with_tables(71, "/opt/kept.so", 1, capacity - 212, false);
        let ended = provider_with_tables(72, "/opt/ended.so", 1, 200, false);
        let late = provider_with_tables(73, "/opt/late.so", 1, 20, false);
        let mut plan = scoped_plan(&[kept.clone(), ended], AdmissionScope::Named);
        assert_eq!(plan.slots.len(), capacity - 12);
        let without_ended =
            plan.rebuild_from_sources(std::slice::from_ref(&kept), &[], &PinnedObjects::empty());
        let delta = plan.extend_exact(without_ended).unwrap();
        assert_eq!(delta.retire.len(), 200);

        let rebuilt = plan.rebuild_from_sources(&[kept, late], &[], &PinnedObjects::empty());

        let refusal = refusal_of(&rebuilt, "/opt/late.so").expect("refused");
        assert_eq!(
            refusal.reason,
            format!(
                "module needs 20 more; only {capacity} attach slots are available; {} are in \
                 use ({} active, 200 retired; held by /opt/kept.so {}) — refusing to attach \
                 a prefix",
                capacity - 12,
                capacity - 212,
                capacity - 212,
            )
        );
    }

    /// An NSS-softokn-shaped provider: every table named by a standard
    /// interface triple, so each carries publication evidence. `live_return`
    /// stays false: linkage alone must authorize.
    fn provider_with_linked_tables(
        inode: u32,
        path: &str,
        tables: usize,
        entries: usize,
    ) -> ReconciledModule {
        use crate::discovery::scan::ScannedInterface;

        let mut module = provider_with_tables(inode, path, tables, entries, false);
        module.scanned.interfaces = (0..tables)
            .map(|index| ScannedInterface {
                index,
                name_class: "exact_standard",
                name_lossy: Some("PKCS 11".into()),
                name_private: Some(b"PKCS 11".to_vec()),
                flags: 0,
                table: Some(index),
            })
            .collect();
        module
    }

    fn opaque_fifth_publication() -> ReconciledModule {
        let mut module = provider_with_tables(91, "/opt/opaque-published.so", 5, 1, false);
        for table in &mut module.scanned.tables {
            table.null_entries = pkcs11_module::FUNCTION_LIST_FIELDS
                .iter()
                .filter(|field| field.name != "C_Sign")
                .map(|field| field.name)
                .collect();
        }
        module.scanned.tables[4].live_return = true;
        module.scanned.interfaces.push(ScannedInterface {
            index: 0,
            name_class: "other",
            name_lossy: None,
            name_private: Some(b"OTHER".to_vec()),
            flags: 0,
            table: Some(4),
        });
        module
    }

    #[test]
    fn observed_opaque_fifth_table_survives_cap_without_semantic_permission() {
        let observed = opaque_fifth_publication();
        let name_score = TableEvidenceScore {
            linked: false,
            live_return: false,
            manifest: false,
            exports: false,
            full_walk: true,
        };
        assert!(!table_name_authorized(&name_score));
        assert!(crate::discovery::scan::table_observation_authorized(
            &observed.scanned.tables[4],
            &name_score
        ));
        let plan = build_from_reconciled_modules(std::slice::from_ref(&observed));
        assert_eq!(plan.slots.len(), 5);
        assert_eq!(plan.uncorroborated_candidates, 0);
        assert!(
            plan.slots
                .iter()
                .all(|slot| !slot.semantic_authorized && slot.descriptor_index == 0)
        );

        let mut raw = observed;
        raw.scanned.tables[4].live_return = false;
        assert!(!crate::discovery::scan::table_observation_authorized(
            &raw.scanned.tables[4],
            &name_score
        ));
        let plan = build_from_reconciled_modules(&[raw]);
        assert_eq!(plan.slots.len(), 4);
        assert_eq!(plan.uncorroborated_candidates, 1);
        assert!(
            plan.slots
                .iter()
                .all(|slot| slot.names == [UNKNOWN_FUNCTION_NAME] && !slot.semantic_authorized)
        );
    }

    #[test]
    fn observed_publication_survives_a_stronger_unobserved_view_of_the_same_table() {
        let mut observed = opaque_fifth_publication();
        observed.scanned.tables[4].walk = "known_prefix";
        observed.scanned.tables[4]
            .null_entries
            .retain(|name| *name != "C_GetInfo");
        observed.scanned.tables[4].unpinned.push(Skipped {
            subject: "C_GetInfo".into(),
            reason: "unmapped".into(),
        });
        let mut raw = opaque_fifth_publication();
        raw.scanned.tables[4].live_return = false;
        raw.scanned.view = ProcessViewId(7);
        for modules in [[observed.clone(), raw.clone()], [raw, observed]] {
            let pieces: Vec<_> = modules.iter().map(lower_scanned).collect();
            let (class, lookalikes) = admission_class(&pieces);
            assert_eq!(class, AdmissionClass::Corroborated);
            assert_eq!(lookalikes, 4);
            let plan = build_from_reconciled_modules(&modules);
            assert_eq!(plan.slots.len(), 5);
            assert_eq!(plan.uncorroborated_candidates, 0);
        }
    }

    /// The multiple-interface/closure-array precedence problem: a provider
    /// whose tables all carry publication evidence is corroborated however
    /// many tables it has. Only *unresolved* lookalikes count toward the
    /// closure-array threshold — the K4 cap and the closure-array class are
    /// both about unresolved tables (module docs), and `Corroborated` reads
    /// "at least one table with publication evidence".
    #[test]
    fn interface_linked_tables_do_not_count_as_closure_lookalikes() {
        let nss = provider_with_linked_tables(81, "/opt/nss-softokn.so", 6, 10);
        let (class, lookalikes) = admission_class(&[lower_scanned(&nss)]);
        assert_eq!(class, AdmissionClass::Corroborated);
        assert_eq!(lookalikes, 0);
    }

    /// The behavioral half of the precedence fix: in a shared scope the
    /// corroborated multi-table provider admits ahead of a proxy closure
    /// array in every discovery order. Within one class the fewer-table
    /// object decides first, so the closure array carries fewer tables
    /// than the provider: pre-fix both are closure arrays and the provider
    /// loses; post-fix evidence beats count.
    #[test]
    fn shared_scope_admits_a_corroborated_multi_table_provider_ahead_of_closure_arrays() {
        let open = MAX_SLOTS as usize - shared_scope_reserve(MAX_SLOTS as usize);
        // The closure array fits on its own but not beside the provider.
        // Wide profile: the open pool grows to 1,584, so the closure
        // carries more entries per table; the table count stays below
        // the provider's, keeping the within-class order under test.
        let entries = if cfg!(feature = "wide-detailed-2112") {
            310
        } else {
            64
        };
        let closure = provider_with_tables(82, P11_KIT, 5, entries, false);
        let combined = 5 * entries + 6 * 11;
        assert_eq!(
            combined,
            if cfg!(feature = "wide-detailed-2112") {
                1616
            } else {
                386
            }
        );
        assert!(
            (5 * entries..combined).contains(&open),
            "the margin the test needs"
        );
        let nss = provider_with_linked_tables(83, "/opt/nss-softokn.so", 6, 11);
        for modules in [&[nss.clone(), closure.clone()], &[closure, nss]] {
            let plan = scoped_plan(modules, AdmissionScope::Shared);
            assert_eq!(slots_of(&plan, 83), 66, "the provider admits whole");
            assert_eq!(slots_of(&plan, 82), 0, "no closure-array prefix");
            let refusal = refusal_of(&plan, P11_KIT).expect("closure refused whole");
            assert!(
                refusal
                    .reason
                    .contains("a proxy closure array is admitted whole or not at all"),
                "{}",
                refusal.reason
            );
            assert!(
                refusal_of(&plan, "/opt/nss-softokn.so").is_none(),
                "the provider is admitted, never refused"
            );
        }
    }

    /// Unresolved lookalikes still dominate a mixed object: two linked
    /// tables beside sixty bare decodes stay a closure array, and the
    /// refusal counts the lookalikes (60), not the linked tables.
    #[test]
    fn unresolved_tables_still_make_a_mixed_object_a_closure_array() {
        let mut mixed = provider_with_tables(84, "/opt/mixed-array.so", 62, 1, false);
        mixed.scanned.interfaces = vec![
            crate::discovery::scan::ScannedInterface {
                index: 0,
                name_class: "exact_standard",
                name_lossy: Some("PKCS 11".into()),
                name_private: Some(b"PKCS 11".to_vec()),
                flags: 0,
                table: Some(0),
            },
            crate::discovery::scan::ScannedInterface {
                index: 1,
                name_class: "exact_standard",
                name_lossy: Some("PKCS 11".into()),
                name_private: Some(b"PKCS 11".to_vec()),
                flags: 0,
                table: Some(1),
            },
        ];
        let (class, lookalikes) = admission_class(&[lower_scanned(&mixed)]);
        assert_eq!(class, AdmissionClass::ClosureArray);
        assert_eq!(lookalikes, 60);
    }

    #[test]
    fn plan_token_poison_is_refused_by_the_fence() {
        use crate::discovery::identity::{GraphRefusal, GraphStep};
        use crate::semantics_edge::resources::SemanticResourcePool;

        let retained = scanned_with(TEST_OBJECT, "/retained.so", [0x10]);
        let retired_key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 43,
        };
        let retired = scanned_with(retired_key, "/retired.so", [0x20]);
        let old = build_from_reconciled_modules(&[retained.clone(), retired]);
        assert_eq!(old.slots.len(), 2);
        let surviving = [retained];
        let pins = PinnedObjects::empty();
        let mut stable = |object: PinnedObjectId| Some(ModuleId(object.0));
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();

        // Mid-stream poison trips the fence on the next credit.
        let mut poisoned = old.clone();
        let mut cursor = ConservativePlanCursor::new();
        let sources = ConservativePlanSources::new(&surviving, &[], &pins, false);
        let first = poisoned
            .poll_conservative_rebuild(sources, &mut stable, &mut cursor, &reserve, 1)
            .unwrap();
        assert_eq!(first, GraphStep::Advanced);
        poisoned.poison_token_for_test();
        let sources = ConservativePlanSources::new(&surviving, &[], &pins, false);
        let err = poisoned
            .poll_conservative_rebuild(sources, &mut stable, &mut cursor, &reserve, 1)
            .unwrap_err();
        assert!(matches!(err, GraphRefusal::SourceChanged));

        // A pre-poisoned plan is refused at the first credit, before measuring.
        let mut poisoned = old.clone();
        poisoned.poison_token_for_test();
        let mut cursor = ConservativePlanCursor::new();
        let sources = ConservativePlanSources::new(&surviving, &[], &pins, false);
        let err = poisoned
            .poll_conservative_rebuild(sources, &mut stable, &mut cursor, &reserve, 1)
            .unwrap_err();
        assert!(matches!(err, GraphRefusal::SourceChanged));
        assert!(cursor.plan().is_none());
        assert!(cursor.required_bytes().is_none());
    }

    #[test]
    fn plan_tree_bound_covers_std_btree_allocations() {
        fn tight_nodes(entries: usize) -> usize {
            if entries == 0 {
                0
            } else {
                1 + (entries - 1) / 5
            }
        }
        fn expected_bytes<K, V>(entries: usize) -> usize {
            fn align8(bytes: usize) -> usize {
                (bytes + 7) & !7
            }
            let node = 16
                + align8(std::mem::size_of::<K>() * 11)
                + align8(std::mem::size_of::<V>() * 11)
                + 12 * 8
                + crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING;
            tight_nodes(entries) * node
        }
        fn ascending(n: usize) -> Vec<u64> {
            (0..n as u64).collect()
        }
        fn descending(n: usize) -> Vec<u64> {
            (0..n as u64).rev().collect()
        }
        fn xorshifted(n: usize) -> Vec<u64> {
            let mut keys: Vec<u64> = (0..n as u64).collect();
            let mut state = 0x9E3779B97F4A7C15u64;
            for i in (1..n).rev() {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                let j = (state.wrapping_mul(0x2545F4914F6CDD1D) >> 32) as usize % (i + 1);
                keys.swap(i, j);
            }
            keys
        }
        fn check_cover<K: Ord, V>(
            entries: usize,
            order: &[u64],
            mut key: impl FnMut(u64) -> K,
            mut value: impl FnMut(u64) -> V,
        ) {
            let bound = plan_tree_bytes::<K, V>(entries).expect("tight bound fits");
            assert_eq!(
                bound,
                expected_bytes::<K, V>(entries),
                "tight node count for {entries} entries"
            );
            let (map, peak) = crate::test_alloc::requested_peak_during(|| {
                let mut map = std::collections::BTreeMap::new();
                for k in order {
                    map.insert(key(*k), value(*k));
                }
                map
            });
            assert_eq!(map.len(), entries, "all test keys inserted");
            assert!(!peak.incomplete, "allocation probe stayed complete");
            assert_eq!(peak.failed_requests, 0, "no failed test allocations");
            if entries == 0 {
                assert_eq!(peak.live_blocks, 0, "empty map allocates nothing");
            } else {
                assert!(peak.live_blocks > 0, "nonempty map retains nodes");
                assert!(peak.peak_bytes > 0, "nonempty map requests bytes");
            }
            let need = peak
                .peak_bytes
                .max(peak.live_bytes)
                .max(peak.realloc_overlap_bytes);
            assert!(
                bound >= need,
                "bound {bound} covers heap {need} for {entries} entries"
            );
            drop(map);
        }
        fn check_half_removed<K: Ord, V>(
            entries: usize,
            mut key: impl FnMut(u64) -> K,
            mut value: impl FnMut(u64) -> V,
        ) {
            let remaining = entries / 2;
            let full = plan_tree_bytes::<K, V>(entries).expect("tight bound fits");
            assert_eq!(
                full,
                expected_bytes::<K, V>(entries),
                "tight node count for {entries} entries"
            );
            let rest = plan_tree_bytes::<K, V>(remaining).expect("tight bound fits");
            assert_eq!(
                rest,
                expected_bytes::<K, V>(remaining),
                "tight node count for {remaining} entries"
            );
            let (map, peak) = crate::test_alloc::requested_peak_during(|| {
                let mut map = std::collections::BTreeMap::new();
                for k in 0..entries as u64 {
                    map.insert(key(k), value(k));
                }
                for k in (0..entries as u64).filter(|k| k % 2 == 0) {
                    map.remove(&key(k));
                }
                map
            });
            assert_eq!(map.len(), remaining, "half the test keys removed");
            assert!(!peak.incomplete, "allocation probe stayed complete");
            assert_eq!(peak.failed_requests, 0, "no failed test allocations");
            assert!(
                full >= peak.peak_bytes.max(peak.realloc_overlap_bytes),
                "full bound {full} covers insertion peak {}",
                peak.peak_bytes.max(peak.realloc_overlap_bytes),
            );
            assert!(
                rest >= peak.live_bytes,
                "remaining bound {rest} covers live {}",
                peak.live_bytes,
            );
            drop(map);
        }
        for entries in [0, 1, 5, 11, 12, 64, 4096] {
            for order in [ascending(entries), descending(entries), xorshifted(entries)] {
                check_cover::<u64, u64>(entries, &order, |k| k, |k| k.wrapping_mul(3));
                check_cover::<u64, ()>(entries, &order, |k| k, |_| ());
                check_cover::<u64, [u64; 16]>(entries, &order, |k| k, |k| [k; 16]);
                check_cover::<[u64; 4], [u64; 4]>(entries, &order, |k| [k, 0, 1, 2], |k| [k; 4]);
            }
            if entries >= 2 {
                check_half_removed::<u64, u64>(entries, |k| k, |k| k);
                check_half_removed::<u64, ()>(entries, |k| k, |_| ());
                check_half_removed::<u64, [u64; 16]>(entries, |k| k, |k| [k; 16]);
                check_half_removed::<[u64; 4], [u64; 4]>(entries, |k| [k, 0, 1, 2], |k| [k; 4]);
            }
        }
        #[repr(align(16))]
        struct OverAligned;
        assert!(
            matches!(
                plan_tree_bytes::<OverAligned, u64>(1),
                Err(crate::discovery::identity::GraphRefusal::Overflow)
            ),
            "over-aligned keys refuse"
        );
        assert!(
            matches!(
                plan_tree_bytes::<u64, OverAligned>(1),
                Err(crate::discovery::identity::GraphRefusal::Overflow)
            ),
            "over-aligned values refuse"
        );
        assert!(
            plan_tree_bytes::<u64, u64>(usize::MAX).is_err(),
            "huge maps refuse instead of wrapping"
        );
    }
}
