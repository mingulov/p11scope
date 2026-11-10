//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Reading the aggregate maps. PerCpu values are summed in userspace;
//! percentiles come from log2 buckets and are therefore approximations
//! (the lower bound of the containing bucket), which every renderer must
//! state.

// Staged private collector; Session acquisition and admission charging follow
// separately. Existing readers and their public report layout stay unchanged.
#[cfg_attr(not(test), allow(dead_code))]
mod counter_collector;

// Private, unselected native reader; runtime admission/activation is separate.
#[cfg_attr(not(test), allow(dead_code))]
mod counter_reader;

#[cfg_attr(not(test), allow(dead_code))]
mod counter_projection;

// Selected-detail handoff→gate adapter (6.15 phase 2). Crate-visible
// (unlike the private collector siblings) because the attach gate
// shims and the future driver call into it; the banks-level seams
// stay `pub(super)` so only metrics code handles raw reads.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod selected_detail;
// 6.15 driver packet (this lane): CLI endpoint selection plus live
// promotion/demotion orchestration over the adapter above. The host
// composition calls the orchestration entries; the selection stage
// and composer are production-live.
pub(crate) mod selected_detail_driver;
// K0 live cells (this lane): `--select-endpoint` detail on a real
// SoftHSM workload, run by the controller on Fedora as root.
#[cfg(test)]
mod k0_live_cells;

pub(crate) use counter_projection::{CaptureCollection, CaptureSnapshot, CounterCaptureInputs};

#[cfg(test)]
pub(crate) use counter_projection::tests::{ConsumerFault, ConsumerFixture};

use crate::attach::Session;
use crate::plan::{AttachPlan, ModuleId};
use anyhow::{Context as _, Result};
use aya::maps::{Array, PerCpuArray, PerCpuHashMap};
use p11scope_ebpf_common::{
    CounterMode, EVIDENCE_ABI_REFUSALS, EVIDENCE_CGROUP_SCOPE_FAILURES, EVIDENCE_RING_LOSS,
    EVIDENCE_RV_UPDATE_FAILURES, EVIDENCE_SEMANTIC_CAPTURE_FAILURES,
    EVIDENCE_START_INSERT_FAILURES, EVIDENCE_TEMPLATE_TAIL_FAILURES, EVIDENCE_UNMATCHED_RETURNS,
    EVIDENCE_UNREGISTERED_MECHANISMS, IMAGE_IDENTITY_TICKET_LIMIT, ImageBankSelect,
    ImageIdentityControl, LATENCY_BUCKETS, LOADER_GATE_SLOTS, LoaderGateControl, OWNER_BAD_CONTROL,
    OWNER_BAD_RECORD, OWNER_BOOKKEEPING_FAILED, OWNER_CLASSIFIER_FAILED, OWNER_DELETE_FAILED,
    OWNER_DIRECTORY_MISMATCH, OWNER_LOOKUP_UNKNOWN, OWNER_REFUND_FAILED,
    OWNER_START_COUNT_MISMATCH, OWNER_START_KEY_MISMATCH, OWNER_START_ROW_MISSING,
    OWNER_STATE_DELETE_FAILED, ROOT_BAD_CELL, ROOT_BAD_CONTROL, ROOT_CAPACITY, ROOT_CREATE_FAILED,
    ROOT_EXISTING_CHILD, ROOT_EXIT_CLASSIFIER, ROOT_EXIT_DELETE, ROOT_REFUND_FAILED,
    ROOT_RESERVE_CAS, RootAffiliationControl, RvKey, SlotStats, ThreadOwnerControl,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, PartialEq)]
pub struct SlotReport {
    pub names: Vec<String>,
    pub aliased: bool,
    pub semantic_authorized: bool,
    /// The module these counts belong to; `None` when two modules publish this
    /// target and neither can be credited (spec §4.7).
    pub module: Option<ModuleId>,
    /// True exactly when `module` is `None` because the slot was ever shared.
    pub module_ambiguous: bool,
    /// True exactly when `module` is `None` for the other reason: a real
    /// allocated aggregate cell with no accepted sole owner (for example an
    /// endpoint whose post-mutation generation validation failed). Exclusive
    /// with `module_ambiguous` by construction.
    pub module_unresolved: bool,
    /// Timing capability of the native counter cell used for this row,
    /// independent of semantic authorization or requested CLI options.
    pub mode: CounterMode,
    /// Completed calls (entry and return both observed).
    pub calls: u64,
    pub errors: u64,
    /// Entered but never returned by capture end — excluded from latency.
    pub in_flight: u64,
    pub total_ns: u64,
    pub max_ns: u64,
    pub buckets: [u64; LATENCY_BUCKETS],
    /// CK_RV → count.
    pub rv_counts: BTreeMap<u64, u64>,
    /// The slot's exact target offset inside its pinned object.
    pub file_offset: u64,
    /// The pinned object that offset is in, when the plan recorded it.
    pub target_object: Option<crate::plan::TargetObject>,
    /// Every table ordinal that reached the target (`plan::SlotOrdinal`).
    pub ordinals: Vec<crate::plan::SlotOrdinal>,
}

fn slot_report(
    plan: &AttachPlan,
    slot: &crate::plan::Slot,
    acc: SlotStats,
    rv_counts: BTreeMap<u64, u64>,
) -> SlotReport {
    let module = plan.module_of_slot(slot.index);
    let module_ambiguous = plan.slot_is_module_ambiguous(slot.index);
    SlotReport {
        names: slot.names.clone(),
        aliased: slot.aliased,
        semantic_authorized: slot.semantic_authorized,
        module,
        module_ambiguous,
        // The exclusive third case, derived from the other two rather than
        // from a second owner list that could drift out of step with them.
        module_unresolved: module.is_none() && !module_ambiguous,
        // This constructor consumes the actual legacy SlotStats layout.
        mode: CounterMode::Latency,
        calls: acc.returned,
        errors: acc.errors,
        in_flight: acc.entered.saturating_sub(acc.returned),
        total_ns: acc.total_ns,
        max_ns: acc.max_ns,
        buckets: acc.buckets,
        rv_counts,
        file_offset: slot.file_offset,
        target_object: plan.target_object_of(slot),
        ordinals: plan.ordinals_of(slot),
    }
}

/// Gaps from a legacy aggregate read: slots whose STATS cell could not be
/// read (zero counts are unknown, not exact) and whether the RV table read
/// failed (per-slot RV breakdowns may be incomplete).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LegacySlotGaps {
    pub unread_stats: u64,
    pub rv_failed: bool,
}

/// Unknown kernel-evidence cells: one bit per EVIDENCE index and control
/// cell. A set bit means that cell read 0 as unknown, not exact.
pub(crate) const LEGACY_UNKNOWN_RING_LOSS: u64 = 1 << 0;
pub(crate) const LEGACY_UNKNOWN_START_INSERT: u64 = 1 << 1;
pub(crate) const LEGACY_UNKNOWN_UNMATCHED_RETURNS: u64 = 1 << 2;
pub(crate) const LEGACY_UNKNOWN_RV_UPDATES: u64 = 1 << 3;
pub(crate) const LEGACY_UNKNOWN_CGROUP_SCOPE: u64 = 1 << 4;
pub(crate) const LEGACY_UNKNOWN_SEMANTIC_CAPTURE: u64 = 1 << 5;
pub(crate) const LEGACY_UNKNOWN_TEMPLATE_TAIL: u64 = 1 << 6;
pub(crate) const LEGACY_UNKNOWN_UNREGISTERED_MECHANISMS: u64 = 1 << 7;
pub(crate) const LEGACY_UNKNOWN_ABI_REFUSALS: u64 = 1 << 8;
pub(crate) const LEGACY_UNKNOWN_OWNER: u64 = 1 << 9;
pub(crate) const LEGACY_UNKNOWN_COOKIE: u64 = 1 << 10;
pub(crate) const LEGACY_UNKNOWN_ROOT: u64 = 1 << 11;

/// Every unknown bit set: a kernel-evidence read that never landed.
pub(crate) const LEGACY_UNKNOWN_ALL: u64 = LEGACY_UNKNOWN_RING_LOSS
    | LEGACY_UNKNOWN_START_INSERT
    | LEGACY_UNKNOWN_UNMATCHED_RETURNS
    | LEGACY_UNKNOWN_RV_UPDATES
    | LEGACY_UNKNOWN_CGROUP_SCOPE
    | LEGACY_UNKNOWN_SEMANTIC_CAPTURE
    | LEGACY_UNKNOWN_TEMPLATE_TAIL
    | LEGACY_UNKNOWN_UNREGISTERED_MECHANISMS
    | LEGACY_UNKNOWN_ABI_REFUSALS
    | LEGACY_UNKNOWN_OWNER
    | LEGACY_UNKNOWN_COOKIE
    | LEGACY_UNKNOWN_ROOT;

/// Finite cell names for the unknown bitmask, in bit order.
pub(crate) const LEGACY_UNKNOWN_CELLS: &[(&str, u64)] = &[
    ("ring_loss", LEGACY_UNKNOWN_RING_LOSS),
    ("start_insert_failures", LEGACY_UNKNOWN_START_INSERT),
    ("unmatched_returns", LEGACY_UNKNOWN_UNMATCHED_RETURNS),
    ("rv_update_failures", LEGACY_UNKNOWN_RV_UPDATES),
    ("cgroup_scope_failures", LEGACY_UNKNOWN_CGROUP_SCOPE),
    ("semantic_capture_failures", LEGACY_UNKNOWN_SEMANTIC_CAPTURE),
    ("template_tail_failures", LEGACY_UNKNOWN_TEMPLATE_TAIL),
    (
        "unregistered_mechanisms",
        LEGACY_UNKNOWN_UNREGISTERED_MECHANISMS,
    ),
    ("abi_refusals", LEGACY_UNKNOWN_ABI_REFUSALS),
    ("owner", LEGACY_UNKNOWN_OWNER),
    ("cookie", LEGACY_UNKNOWN_COOKIE),
    ("root", LEGACY_UNKNOWN_ROOT),
];

fn collect_legacy_rvs(
    entries: Vec<Result<(RvKey, u64), ()>>,
) -> (BTreeMap<u32, BTreeMap<u64, u64>>, bool) {
    let mut map: BTreeMap<u32, BTreeMap<u64, u64>> = BTreeMap::new();
    let mut rv_failed = false;
    for entry in entries {
        match entry {
            Ok((key, total)) => {
                if total > 0 {
                    let slot_rv = map.entry(key.slot).or_default().entry(key.rv).or_default();
                    *slot_rv = slot_rv.saturating_add(total);
                }
            }
            Err(()) => {
                rv_failed = true;
            }
        }
    }
    (map, rv_failed)
}

fn collect_legacy_reports(
    plan: &AttachPlan,
    get_stats: impl Fn(u32) -> Result<Vec<SlotStats>, ()>,
    rvs: Vec<(RvKey, u64)>,
) -> (Vec<SlotReport>, LegacySlotGaps) {
    let mut rv_by_slot: BTreeMap<u32, BTreeMap<u64, u64>> = BTreeMap::new();
    for (key, total) in rvs {
        if total > 0 {
            let slot_rv = rv_by_slot
                .entry(key.slot)
                .or_default()
                .entry(key.rv)
                .or_default();
            *slot_rv = slot_rv.saturating_add(total);
        }
    }
    let mut out = Vec::with_capacity(plan.slots.len());
    let mut unread_stats = 0u64;
    for slot in &plan.slots {
        match get_stats(slot.index) {
            Ok(per_cpu) => {
                let mut acc = SlotStats::ZERO;
                for cpu in per_cpu {
                    acc.entered = acc.entered.saturating_add(cpu.entered);
                    acc.returned = acc.returned.saturating_add(cpu.returned);
                    acc.errors = acc.errors.saturating_add(cpu.errors);
                    acc.total_ns = acc.total_ns.saturating_add(cpu.total_ns);
                    acc.max_ns = acc.max_ns.max(cpu.max_ns);
                    for (i, bucket) in cpu.buckets.iter().enumerate() {
                        acc.buckets[i] = acc.buckets[i].saturating_add(*bucket);
                    }
                }
                out.push(slot_report(
                    plan,
                    slot,
                    acc,
                    rv_by_slot.remove(&slot.index).unwrap_or_default(),
                ));
            }
            Err(()) => {
                unread_stats = unread_stats.saturating_add(1);
                rv_by_slot.remove(&slot.index);
                out.push(slot_report(plan, slot, SlotStats::ZERO, BTreeMap::new()));
            }
        }
    }
    (
        out,
        LegacySlotGaps {
            unread_stats,
            rv_failed: false,
        },
    )
}

fn read_legacy_evidence_cell(value: Result<u64, ()>, bit: u64) -> (u64, u64) {
    match value {
        Ok(value) => (value, 0),
        Err(()) => (0, bit),
    }
}

/// Compose one legacy aggregate read from scripted inputs: RV entries fold
/// first, then per-slot STATS, and the RV failure flag rides the returned
/// gaps together with the unread-STATS count. `read_with_gaps` is this
/// composition over live maps; tests drive it directly.
fn compose_legacy_read(
    plan: &AttachPlan,
    get_stats: impl Fn(u32) -> Result<Vec<SlotStats>, ()>,
    entries: Vec<Result<(RvKey, u64), ()>>,
) -> (Vec<SlotReport>, LegacySlotGaps) {
    let (rv_map, rv_failed) = collect_legacy_rvs(entries);
    let flat: Vec<(RvKey, u64)> = rv_map
        .iter()
        .flat_map(|(slot, rvs)| {
            rvs.iter().map(|(rv, total)| {
                (
                    RvKey {
                        slot: *slot,
                        _pad: 0,
                        rv: *rv,
                    },
                    *total,
                )
            })
        })
        .collect();
    let (reports, mut gaps) = collect_legacy_reports(plan, get_stats, flat);
    gaps.rv_failed = rv_failed;
    (reports, gaps)
}

/// Compose kernel control state from typed control reads with gaps: a
/// failed control read contributes nothing and sets its unknown bit, while
/// a missing map (`Ok(None)`, Inventory flavors) contributes nothing
/// without a gap bit. `kernel_evidence_with_gaps` is this composition over
/// live maps; tests drive it directly.
fn compose_legacy_controls(
    owner: Result<Option<ThreadOwnerControl>, ()>,
    cookie: Result<Option<ImageIdentityControl>, ()>,
    root: Result<Option<RootAffiliationControl>, ()>,
) -> (KernelControl, u64) {
    let mut unknown = 0u64;
    let owner = match owner {
        Ok(cell) => cell,
        Err(()) => {
            unknown |= LEGACY_UNKNOWN_OWNER;
            None
        }
    };
    let cookie = match cookie {
        Ok(cell) => cell,
        Err(()) => {
            unknown |= LEGACY_UNKNOWN_COOKIE;
            None
        }
    };
    let root = match root {
        Ok(cell) => cell,
        Err(()) => {
            unknown |= LEGACY_UNKNOWN_ROOT;
            None
        }
    };
    (KernelControl::from_cells(owner, cookie, root), unknown)
}

pub fn read(session: &Session, plan: &AttachPlan) -> Result<Vec<SlotReport>> {
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS map")?)?;
    let rvs: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS map")?)?;

    let mut rv_by_slot: BTreeMap<u32, BTreeMap<u64, u64>> = BTreeMap::new();
    for entry in rvs.iter() {
        let (k, per_cpu) = entry?;
        let total = saturating_total(per_cpu.iter().copied());
        if total > 0 {
            let slot_rv = rv_by_slot
                .entry(k.slot)
                .or_default()
                .entry(k.rv)
                .or_default();
            *slot_rv = slot_rv.saturating_add(total);
        }
    }

    let mut out = Vec::with_capacity(plan.slots.len());
    for slot in &plan.slots {
        let per_cpu = stats.get(&slot.index, 0)?;
        let mut acc = SlotStats::ZERO;
        for cpu in per_cpu.iter() {
            acc.entered = acc.entered.saturating_add(cpu.entered);
            acc.returned = acc.returned.saturating_add(cpu.returned);
            acc.errors = acc.errors.saturating_add(cpu.errors);
            acc.total_ns = acc.total_ns.saturating_add(cpu.total_ns);
            acc.max_ns = acc.max_ns.max(cpu.max_ns);
            for (i, b) in cpu.buckets.iter().enumerate() {
                acc.buckets[i] = acc.buckets[i].saturating_add(*b);
            }
        }
        out.push(slot_report(
            plan,
            slot,
            acc,
            rv_by_slot.remove(&slot.index).unwrap_or_default(),
        ));
    }
    Ok(merge_slot_reports(out))
}

/// Fold slot reports that count the same function in the same file
/// into one aggregate row: two incarnations of one owned child (an
/// exec between them) retire one generation's slots and arm the
/// next, and the aggregate table must show the function once with
/// summed counts, not once per generation. Rows for different files
/// or different counter modes stay apart: sharing a name never
/// merges two modules, and counts never merge with timing rows.
/// First-seen order is kept; a merged row keeps the first row's
/// mode, authorization and module attribution alongside its identity
/// fields, and sums every counter, bucket and return tally.
pub fn merge_slot_reports(reports: Vec<SlotReport>) -> Vec<SlotReport> {
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct Key {
        names: Vec<String>,
        aliased: bool,
        target: Option<((u64, u64), u64, Option<String>)>,
        file_offset: u64,
        mode: u8,
    }
    let mut index: BTreeMap<Key, usize> = BTreeMap::new();
    let mut merged: Vec<SlotReport> = Vec::with_capacity(reports.len());
    for report in reports {
        let key = Key {
            names: report.names.clone(),
            aliased: report.aliased,
            target: report
                .target_object
                .as_ref()
                .map(|target| (target.dev, target.ino, target.sha256.clone())),
            file_offset: report.file_offset,
            mode: report.mode as u8,
        };
        let Some(position) = index.get(&key).copied() else {
            index.insert(key, merged.len());
            merged.push(report);
            continue;
        };
        let row = &mut merged[position];
        row.calls = row.calls.saturating_add(report.calls);
        row.errors = row.errors.saturating_add(report.errors);
        row.in_flight = row.in_flight.saturating_add(report.in_flight);
        row.total_ns = row.total_ns.saturating_add(report.total_ns);
        row.max_ns = row.max_ns.max(report.max_ns);
        for (slot, extra) in row.buckets.iter_mut().zip(report.buckets.iter()) {
            *slot = slot.saturating_add(*extra);
        }
        for (rv, count) in report.rv_counts {
            row.rv_counts
                .entry(rv)
                .and_modify(|total| *total = total.saturating_add(count))
                .or_insert(count);
        }
        row.ordinals.extend(report.ordinals);
        row.ordinals.sort();
        row.ordinals.dedup();
    }
    merged
}

/// Events the kernel side could not reserve ring buffer space for,
/// summed across CPUs. A nonzero count means the capture dropped
/// events — `STATS`/`RV_COUNTS` still saw them, but the per-call detail
/// in `EVENTS` is incomplete.
pub fn lost_events(session: &Session) -> Result<u64> {
    Ok(kernel_evidence(session)?.ring_loss)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelEvidence {
    pub ring_loss: u64,
    pub start_insert_failures: u64,
    pub unmatched_returns: u64,
    pub rv_update_failures: u64,
    pub cgroup_scope_failures: u64,
    pub semantic_capture_failures: u64,
    pub template_tail_failures: u64,
    pub unregistered_mechanisms: u64,
    pub abi_refusals: u64,
    /// Native control cells, read with every snapshot (see [`KernelControl`]).
    pub control: KernelControl,
    /// Bitmask of cells that read 0 as unknown, not exact (see
    /// [`LEGACY_UNKNOWN_CELLS`]). Zero when every cell read cleanly.
    pub unknown_cells: u64,
}

/// Native kernel control state: OWNER_CTL (call-ownership accounting),
/// COOKIE_CTL (lifetime identity tickets) and ROOT_CTL (owned-root
/// affiliation). Read at every evidence snapshot and at terminal, because
/// a poisoned owner makes every program refuse at its scope gate: without
/// this read a halted capture would look like a quiet one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelControl {
    /// `OWNER_CTL.poison` sticky reason bits; nonzero halts all capture.
    pub owner_poison: u64,
    pub owner_admission_failures: u64,
    /// `COOKIE_CTL.unavailable`: identity allocations/reads refused,
    /// including every fork record dropped once the budget is spent.
    pub identity_unavailable: u64,
    pub identity_budget_exhausted: bool,
    /// `ROOT_CTL.failure_flags` sticky reason bits.
    pub root_failures: u64,
}

const OWNER_POISON_NAMES: [(u64, &str); 12] = [
    (OWNER_BAD_CONTROL, "bad_control"),
    (OWNER_LOOKUP_UNKNOWN, "lookup_unknown"),
    (OWNER_BAD_RECORD, "bad_record"),
    (OWNER_DELETE_FAILED, "delete_failed"),
    (OWNER_BOOKKEEPING_FAILED, "bookkeeping_failed"),
    (OWNER_REFUND_FAILED, "refund_failed"),
    (OWNER_CLASSIFIER_FAILED, "classifier_failed"),
    (OWNER_STATE_DELETE_FAILED, "state_delete_failed"),
    (OWNER_START_KEY_MISMATCH, "start_key_mismatch"),
    (OWNER_START_COUNT_MISMATCH, "start_count_mismatch"),
    (OWNER_START_ROW_MISSING, "start_row_missing"),
    (OWNER_DIRECTORY_MISMATCH, "directory_mismatch"),
];

const ROOT_FAILURE_NAMES: [(u64, &str); 9] = [
    (ROOT_BAD_CONTROL, "bad_control"),
    (ROOT_CAPACITY, "capacity"),
    (ROOT_RESERVE_CAS, "reserve_contention"),
    (ROOT_CREATE_FAILED, "create_failed"),
    (ROOT_EXISTING_CHILD, "existing_child"),
    (ROOT_BAD_CELL, "bad_cell"),
    (ROOT_EXIT_CLASSIFIER, "exit_classifier"),
    (ROOT_EXIT_DELETE, "exit_delete"),
    (ROOT_REFUND_FAILED, "refund_failed"),
];

/// Finite, sorted, duplicate-free reason names for a sticky bitmask. Bits
/// outside the known set become the single name `unknown`: the raw mask is
/// never published.
fn reason_names(bits: u64, names: &[(u64, &'static str)]) -> Vec<&'static str> {
    let known = names.iter().fold(0, |mask, (bit, _)| mask | bit);
    let mut out: Vec<&'static str> = names
        .iter()
        .filter(|(bit, _)| bits & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if bits & !known != 0 {
        out.push("unknown");
    }
    out.sort_unstable();
    out.dedup();
    out
}

impl KernelControl {
    /// Decode the three control cells. A cell the object does not carry
    /// (an Inventory flavor) contributes nothing.
    pub fn from_cells(
        owner: Option<ThreadOwnerControl>,
        cookie: Option<ImageIdentityControl>,
        root: Option<RootAffiliationControl>,
    ) -> Self {
        Self {
            owner_poison: owner.map_or(0, |owner| owner.poison),
            owner_admission_failures: owner.map_or(0, |owner| owner.admission_failures),
            identity_unavailable: cookie.map_or(0, |cookie| cookie.unavailable),
            identity_budget_exhausted: cookie
                .is_some_and(|cookie| cookie.next_ticket >= cookie.limit.max(1)),
            root_failures: root.map_or(0, |root| root.failure_flags),
        }
    }

    pub fn halted(&self) -> bool {
        self.owner_poison != 0
    }

    /// The published, finite form: reason names and counts only.
    pub fn evidence(&self) -> KernelControlEvidence {
        KernelControlEvidence {
            capture_halted: self.halted(),
            owner_poison: reason_names(self.owner_poison, &OWNER_POISON_NAMES),
            owner_admission_failures: self.owner_admission_failures,
            identity_unavailable: self.identity_unavailable,
            identity_budget_exhausted: self.identity_budget_exhausted,
            root_affiliation_failures: reason_names(self.root_failures, &ROOT_FAILURE_NAMES),
        }
    }
}

/// `evidence.kernel_control` (observed-profile-v3): finite names and counts.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct KernelControlEvidence {
    /// True exactly when `owner_poison` is non-empty: every probe has refused
    /// capture since the poison, so nothing after it was counted.
    pub capture_halted: bool,
    pub owner_poison: Vec<&'static str>,
    pub owner_admission_failures: u64,
    pub identity_unavailable: u64,
    /// Informational on its own; the refusals it causes are counted in
    /// `identity_unavailable`.
    pub identity_budget_exhausted: bool,
    pub root_affiliation_failures: Vec<&'static str>,
}

impl KernelControlEvidence {
    /// No halt, refusal or failure: the kernel side lost nothing.
    pub fn complete(&self) -> bool {
        !self.capture_halted
            && self.owner_poison.is_empty()
            && self.owner_admission_failures == 0
            && self.identity_unavailable == 0
            && self.root_affiliation_failures.is_empty()
    }
}

/// L4b loader transitions: capture-wide saturating u64 totals read from
/// the session's single native loader-gate control cell. RED stub: the
/// shapes below encode the approved counter contract; the mapping lands
/// with the snapshot linkage.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct LoaderTransitions {
    /// Successful gate admissions.
    pub arms: u64,
    /// Acknowledged row reclaims.
    pub reclaims: u64,
    /// Peak simultaneous retained rows.
    pub retained_peak: u64,
    /// Post-cutover counted refusals.
    pub refusals: u64,
    /// Accounting update losses (bounds, not exact facts, when nonzero).
    pub update_losses: u64,
}

impl LoaderTransitions {
    /// Map the gate control cell to published totals. `None` (map absent
    /// or control malformed) stays `None`: a refused field never links,
    /// and absence is never published as zero. Only the five approved
    /// F1 totals leave this function; `limit`, `cutover`, `retired`
    /// and `retained` stay private.
    pub fn from_control(control: Option<LoaderGateControl>) -> Option<Self> {
        let control = control?;
        if control.limit != u64::from(LOADER_GATE_SLOTS) {
            return None;
        }
        Some(Self {
            arms: control.admitted,
            reclaims: control.reclaims,
            retained_peak: control.retained_peak,
            refusals: control.refusals,
            update_losses: control.update_losses,
        })
    }
}

/// L4b image transitions: capture-wide saturating u64 totals derived
/// from the native image-bank selection cell plus the live per-bank
/// watermarks, without spending a ticket. RED stub: the shapes below
/// encode the approved counter contract; the derivation lands with the
/// snapshot linkage.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ImageTransitions {
    /// Allocated ticket-number watermark (folded plus live).
    pub tickets_issued: u64,
    /// Completed bank cuts.
    pub bank_cuts: u64,
    /// Bank quota refusals.
    pub bank_refusals: u64,
    /// Accounting update losses (bounds, not exact facts, when nonzero).
    pub update_losses: u64,
}

impl ImageTransitions {
    /// Derive the published totals. `None` unless the bank producer
    /// (SELECT) and both bank controls are present and valid: a refused
    /// field never links, and absence is never published as zero. The
    /// issuance watermark adds the folded total to the live per-bank
    /// watermarks without spending a ticket; a folded bank contributes
    /// through the folded total only, never twice. Only the four
    /// approved F2 totals leave this function.
    pub fn from_cells(
        select: Option<ImageBankSelect>,
        bank_a: Option<ImageIdentityControl>,
        bank_b: Option<ImageIdentityControl>,
    ) -> Option<Self> {
        let select = select?;
        let bank_a = bank_a?;
        let bank_b = bank_b?;
        for bank in [&bank_a, &bank_b] {
            if bank.limit != IMAGE_IDENTITY_TICKET_LIMIT || bank.next_ticket > bank.limit {
                return None;
            }
        }
        let live = |folded: u64, next_ticket: u64| {
            if folded == 0 { next_ticket } else { 0 }
        };
        let tickets_issued = select
            .folded_issued
            .saturating_add(live(select.folded[0], bank_a.next_ticket));
        let tickets_issued =
            tickets_issued.saturating_add(live(select.folded[1], bank_b.next_ticket));
        Some(Self {
            tickets_issued,
            bank_cuts: select.cuts,
            bank_refusals: select.refusals,
            update_losses: select.update_losses,
        })
    }
}

/// One `Array` control cell, when the loaded object carries it.
fn control_cell<T: aya::Pod>(session: &Session, name: &str) -> Result<Option<T>> {
    let Some(map) = session.ebpf.map(name) else {
        return Ok(None);
    };
    let cell: Array<_, T> = Array::try_from(map).with_context(|| format!("{name} control map"))?;
    Ok(Some(
        cell.get(&0, 0)
            .with_context(|| format!("{name} control cell"))?,
    ))
}

static HALT_NOTICE: AtomicBool = AtomicBool::new(false);
static IDENTITY_NOTICE: AtomicBool = AtomicBool::new(false);

/// One stderr line the first time a halt or an identity refusal is seen, so
/// the operator learns when capture stopped, not only from the final report.
fn notice_kernel_control(control: &KernelControl) {
    if control.halted() && !HALT_NOTICE.swap(true, Ordering::Relaxed) {
        eprintln!(
            "p11scope: kernel capture halted: in-kernel call ownership accounting \
             stopped all capture ({}); nothing after this point is counted and \
             the report is PARTIAL",
            reason_names(control.owner_poison, &OWNER_POISON_NAMES).join(", ")
        );
    }
    if let Some(line) = identity_notice_line(control)
        && !IDENTITY_NOTICE.swap(true, Ordering::Relaxed)
    {
        eprintln!("{line}");
    }
}

/// The one stderr line for the first sighted identity refusal, so the
/// operator learns when capture thinned, not only from the final
/// report. `None` while nothing was refused. Pure, so tests pin the
/// wording without capturing stderr; the caller prints it once.
fn identity_notice_line(control: &KernelControl) -> Option<String> {
    if control.identity_unavailable == 0 {
        return None;
    }
    Some(format!(
        "p11scope: kernel could not give a process an identity ({} refused so far{}); \
         its calls and fork records are not captured and the report is PARTIAL",
        control.identity_unavailable,
        if control.identity_budget_exhausted {
            "; lifetime budget of 16384 identities spent"
        } else {
            ""
        }
    ))
}

pub fn kernel_evidence(session: &Session) -> Result<KernelEvidence> {
    let evidence: PerCpuArray<_, u64> =
        PerCpuArray::try_from(session.ebpf.map("EVIDENCE").context("EVIDENCE map")?)?;
    let read =
        |index| -> Result<u64> { Ok(saturating_total(evidence.get(&index, 0)?.iter().copied())) };
    let control = KernelControl::from_cells(
        control_cell::<ThreadOwnerControl>(session, "OWNER_CTL")?,
        control_cell::<ImageIdentityControl>(session, "COOKIE_CTL")?,
        control_cell::<RootAffiliationControl>(session, "ROOT_CTL")?,
    );
    notice_kernel_control(&control);
    Ok(KernelEvidence {
        ring_loss: read(EVIDENCE_RING_LOSS)?,
        start_insert_failures: read(EVIDENCE_START_INSERT_FAILURES)?,
        unmatched_returns: read(EVIDENCE_UNMATCHED_RETURNS)?,
        rv_update_failures: read(EVIDENCE_RV_UPDATE_FAILURES)?,
        cgroup_scope_failures: read(EVIDENCE_CGROUP_SCOPE_FAILURES)?,
        semantic_capture_failures: read(EVIDENCE_SEMANTIC_CAPTURE_FAILURES)?,
        template_tail_failures: read(EVIDENCE_TEMPLATE_TAIL_FAILURES)?,
        unregistered_mechanisms: read(EVIDENCE_UNREGISTERED_MECHANISMS)?,
        abi_refusals: read(EVIDENCE_ABI_REFUSALS)?,
        control,
        unknown_cells: 0,
    })
}

/// Combined gaps from one legacy read: unread STATS slots, an RV-table
/// failure flag, and unknown kernel-evidence cells. All zeros/false/empty
/// when the read was exact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LegacyReadGaps {
    pub slots: LegacySlotGaps,
    pub unknown_evidence: u64,
}

impl LegacyReadGaps {
    pub(crate) fn is_clean(&self) -> bool {
        self.slots.unread_stats == 0 && !self.slots.rv_failed && self.unknown_evidence == 0
    }

    pub(crate) fn unknown_names(&self) -> Vec<&'static str> {
        LEGACY_UNKNOWN_CELLS
            .iter()
            .filter(|(_, bit)| self.unknown_evidence & bit != 0)
            .map(|(name, _)| *name)
            .collect()
    }
}

/// Legacy aggregate read with per-slot gaps: one unread STATS slot reports
/// zero as unknown with a gap count, one bad RV entry is skipped with an RV
/// flag, and the rest stays exact. Missing STATS/RV maps remain fatal (the
/// data source itself is gone).
pub(crate) fn read_with_gaps(
    session: &Session,
    plan: &AttachPlan,
) -> Result<(Vec<SlotReport>, LegacySlotGaps)> {
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS map")?)?;
    let rvs: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS map")?)?;
    let mut entries = Vec::new();
    for entry in rvs.iter() {
        match entry {
            Ok((key, per_cpu)) => {
                entries.push(Ok((key, saturating_total(per_cpu.iter().copied()))));
            }
            Err(_) => {
                entries.push(Err(()));
            }
        }
    }
    let (reports, gaps) = compose_legacy_read(
        plan,
        |index| {
            stats
                .get(&index, 0)
                .map(|per_cpu| per_cpu.iter().copied().collect::<Vec<_>>())
                .map_err(|_| ())
        },
        entries,
    );
    Ok((reports, gaps))
}

/// Kernel evidence with per-cell unknowns: one unread EVIDENCE or control
/// cell reads 0 as unknown with its bit, and the rest stays exact. A missing
/// EVIDENCE map remains fatal; missing control maps (Inventory flavors)
/// contribute nothing without a gap bit.
pub(crate) fn kernel_evidence_with_gaps(session: &Session) -> Result<KernelEvidence> {
    let evidence: PerCpuArray<_, u64> =
        PerCpuArray::try_from(session.ebpf.map("EVIDENCE").context("EVIDENCE map")?)?;
    let read = |index: u32, bit: u64| -> (u64, u64) {
        let value = evidence
            .get(&index, 0)
            .map(|per_cpu| saturating_total(per_cpu.iter().copied()))
            .map_err(|_| ());
        read_legacy_evidence_cell(value, bit)
    };
    // Typed control reads with gaps: control_cell returns Ok(None) for map
    // absence (Inventory flavors, no gap bit) and Err for get failures (gap).
    let (control, control_unknown) = compose_legacy_controls(
        control_cell::<ThreadOwnerControl>(session, "OWNER_CTL").map_err(|_| ()),
        control_cell::<ImageIdentityControl>(session, "COOKIE_CTL").map_err(|_| ()),
        control_cell::<RootAffiliationControl>(session, "ROOT_CTL").map_err(|_| ()),
    );
    let mut unknown = control_unknown;
    notice_kernel_control(&control);
    let (ring_loss, bit) = read(EVIDENCE_RING_LOSS, LEGACY_UNKNOWN_RING_LOSS);
    unknown |= bit;
    let (start_insert_failures, bit) =
        read(EVIDENCE_START_INSERT_FAILURES, LEGACY_UNKNOWN_START_INSERT);
    unknown |= bit;
    let (unmatched_returns, bit) =
        read(EVIDENCE_UNMATCHED_RETURNS, LEGACY_UNKNOWN_UNMATCHED_RETURNS);
    unknown |= bit;
    let (rv_update_failures, bit) = read(EVIDENCE_RV_UPDATE_FAILURES, LEGACY_UNKNOWN_RV_UPDATES);
    unknown |= bit;
    let (cgroup_scope_failures, bit) =
        read(EVIDENCE_CGROUP_SCOPE_FAILURES, LEGACY_UNKNOWN_CGROUP_SCOPE);
    unknown |= bit;
    let (semantic_capture_failures, bit) = read(
        EVIDENCE_SEMANTIC_CAPTURE_FAILURES,
        LEGACY_UNKNOWN_SEMANTIC_CAPTURE,
    );
    unknown |= bit;
    let (template_tail_failures, bit) = read(
        EVIDENCE_TEMPLATE_TAIL_FAILURES,
        LEGACY_UNKNOWN_TEMPLATE_TAIL,
    );
    unknown |= bit;
    let (unregistered_mechanisms, bit) = read(
        EVIDENCE_UNREGISTERED_MECHANISMS,
        LEGACY_UNKNOWN_UNREGISTERED_MECHANISMS,
    );
    unknown |= bit;
    let (abi_refusals, bit) = read(EVIDENCE_ABI_REFUSALS, LEGACY_UNKNOWN_ABI_REFUSALS);
    unknown |= bit;
    Ok(KernelEvidence {
        ring_loss,
        start_insert_failures,
        unmatched_returns,
        rv_update_failures,
        cgroup_scope_failures,
        semantic_capture_failures,
        template_tail_failures,
        unregistered_mechanisms,
        abi_refusals,
        control,
        unknown_cells: unknown,
    })
}

/// L4b loader snapshot from a live session: the gate control cell mapped
/// through the approved counter contract. `None` when this build carries
/// no gate, the map is absent, or the cell is unpublished or malformed.
/// Staged read path; no evidence linkage.
pub fn loader_transitions(session: &Session) -> Result<Option<LoaderTransitions>> {
    Ok(LoaderTransitions::from_control(
        session.loader_gate_control()?,
    ))
}

/// L4b image snapshot from a live session: the bank-select word plus both
/// bank watermarks, derived without spending a ticket. `None` unless the
/// producer and both controls are present and valid. Staged read path; no
/// evidence linkage.
pub fn image_transitions(session: &Session) -> Result<Option<ImageTransitions>> {
    let select = session.image_bank_select()?;
    let bank_a = control_cell::<ImageIdentityControl>(session, "COOKIE_CTL")?;
    let bank_b = session.bank_b_control()?;
    Ok(ImageTransitions::from_cells(select, bank_a, bank_b))
}

/// Sum of counter cells (per-CPU values, histogram buckets), saturating at
/// `u64::MAX` like every other aggregate here instead of wrapping (F-58-T7).
fn saturating_total(values: impl IntoIterator<Item = u64>) -> u64 {
    values.into_iter().fold(0, u64::saturating_add)
}

/// Approximate quantile from log2 buckets: the lower bound of the bucket
/// containing the q-th observation. `q` is in (0.0, 1.0].
pub fn percentile_ns(buckets: &[u64; LATENCY_BUCKETS], q: f64) -> Option<u64> {
    let total = saturating_total(buckets.iter().copied());
    if total == 0 {
        return None;
    }
    let target = ((total as f64) * q).ceil() as u64;
    let mut seen = 0u64;
    for (i, count) in buckets.iter().enumerate() {
        seen = seen.saturating_add(*count);
        if seen >= target {
            // Bucket i holds [2^(i-1), 2^i); bucket 0 holds exactly 0.
            return Some(if i == 0 { 0 } else { 1u64 << (i - 1) });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::bucket_of;

    fn slot(index: u32, name: &str) -> crate::plan::Slot {
        let descriptor_index = crate::kinds::function_id(name).unwrap() + 1;
        crate::plan::Slot {
            index,
            descriptor_index,
            object: crate::plan::TEST_PINNED_OBJECT,
            object_path: "/proc/self/fd/42".into(),
            file_offset: 0x10 + u64::from(index) * 8,
            names: vec![name.into()],
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[descriptor_index as usize],
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![ModuleId(0)],
        }
    }

    fn exact_plan(slots: Vec<crate::plan::Slot>) -> AttachPlan {
        let mut plan = AttachPlan::from_slots(slots);
        plan.modules = vec![crate::plan::ModuleSummary {
            id: ModuleId(0),
            object: crate::plan::TEST_PINNED_OBJECT,
            key: crate::plan::TEST_OBJECT,
            path: "/proc/self/fd/42".into(),
            tables: vec![],
            interfaces: 0,
            source: "manifest",
            corroborated: false,
            skipped: vec![],
            admission_class: None,
        }];
        plan
    }

    fn module(id: u32) -> crate::plan::ModuleSummary {
        let object = crate::discovery::identity::PinnedObjectId(id + 1);
        crate::plan::ModuleSummary {
            id: ModuleId(id),
            object,
            key: p11scope_manifest::maps::ObjectKey {
                device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
                inode: u64::from(object.0),
            },
            path: format!("/proc/self/fd/{}", object.0),
            tables: vec![],
            interfaces: 0,
            source: "manifest",
            corroborated: false,
            skipped: vec![],
            admission_class: None,
        }
    }

    #[test]
    fn percentiles_come_from_bucket_lower_bounds() {
        let mut b = [0u64; LATENCY_BUCKETS];
        // 100 observations at ~1µs, 10 at ~1ms.
        b[bucket_of(1_000) as usize] = 100;
        b[bucket_of(1_000_000) as usize] = 10;
        let p50 = percentile_ns(&b, 0.50).unwrap();
        let p99 = percentile_ns(&b, 0.99).unwrap();
        assert_eq!(p50, 512, "1_000ns falls in the [512,1024) bucket");
        assert_eq!(
            p99, 524_288,
            "1_000_000ns falls in the [524288,1048576) bucket"
        );
        assert!(p99 > p50);
    }

    /// F-58-T7: per-CPU and per-bucket totals saturate at `u64::MAX`
    /// instead of wrapping (release) or panicking (debug).
    #[test]
    fn counter_totals_saturate_instead_of_wrapping() {
        assert_eq!(saturating_total([u64::MAX, 2]), u64::MAX);
        assert_eq!(saturating_total([1, u64::MAX, u64::MAX]), u64::MAX);
        assert_eq!(saturating_total([2, 3]), 5);
        // A wrapped total (0) would report no percentile; a wrapped running
        // sum would never reach the target.
        let mut b = [0u64; LATENCY_BUCKETS];
        b[bucket_of(1_000) as usize] = 1;
        b[bucket_of(1_000_000) as usize] = u64::MAX;
        assert_eq!(percentile_ns(&b, 0.50), Some(524_288));
        assert_eq!(percentile_ns(&b, 1.0), Some(524_288));
        // Every production total in this module goes through a saturating
        // add: outside comments there is no addition operator, sum,
        // wrapping/overflowing/checked add, and no fold except
        // `saturating_add` and the bitmask OR of the control names.
        let production: String = include_str!("metrics.rs")
            .split_once("#[cfg(test)]\nmod tests {")
            .unwrap()
            .0
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for wrapping in [
            "+=",
            " + ",
            ".sum(",
            ".sum::<",
            "wrapping_add",
            "overflowing_add",
            "checked_add",
            "unchecked_add",
        ] {
            assert!(
                !production.contains(wrapping),
                "an unsaturated total: {wrapping}"
            );
        }
        for (at, _) in production.match_indices(".fold(") {
            let call = production[at..].lines().next().unwrap();
            assert!(
                call.contains("u64::saturating_add") || call.contains("mask | bit"),
                "an unsaturated fold: {call}"
            );
        }
    }

    fn halted_owner() -> KernelControl {
        KernelControl {
            owner_poison: OWNER_REFUND_FAILED,
            ..KernelControl::default()
        }
    }

    #[test]
    fn owner_poison_and_kernel_refusals_force_a_concrete_gap() {
        let mut clean = crate::render::tests::evidence();
        clean.verdict();
        assert_eq!(clean.completeness, "COMPLETE", "the fixture starts clean");
        for control in [
            halted_owner(),
            KernelControl {
                owner_poison: OWNER_CLASSIFIER_FAILED,
                ..KernelControl::default()
            },
            KernelControl {
                owner_admission_failures: 1,
                ..KernelControl::default()
            },
            KernelControl {
                identity_unavailable: 1,
                identity_budget_exhausted: true,
                ..KernelControl::default()
            },
            KernelControl {
                root_failures: ROOT_CAPACITY,
                ..KernelControl::default()
            },
        ] {
            let mut evidence = crate::render::tests::evidence();
            evidence.kernel_control = control.evidence();
            evidence.verdict();
            assert_eq!(
                (evidence.completeness, evidence.verdict_detail),
                ("PARTIAL", crate::render::VERDICT_CONCRETE_GAP),
                "{control:?} must be a concrete gap"
            );
        }
        // A spent budget with no refusal yet lost nothing.
        let mut budget = crate::render::tests::evidence();
        budget.kernel_control = KernelControl {
            identity_budget_exhausted: true,
            ..KernelControl::default()
        }
        .evidence();
        budget.verdict();
        assert_eq!(budget.completeness, "COMPLETE");
    }

    // Identity budget (RED): the first-sighting notice names the
    // refusal count and the spent budget.
    #[test]
    fn identity_notice_line_names_counts_and_budget() {
        let line = identity_notice_line(&KernelControl {
            identity_unavailable: 168_027,
            identity_budget_exhausted: true,
            ..KernelControl::default()
        })
        .expect("notice line");
        assert!(line.contains("168027"), "{line}");
        assert!(line.contains("262144"), "{line}");
        assert!(line.contains("PARTIAL"), "{line}");
    }

    // Identity budget (RED): refusals without a spent budget name
    // the count and stay silent about the budget.
    #[test]
    fn identity_notice_line_without_spent_budget_names_counts_only() {
        let line = identity_notice_line(&KernelControl {
            identity_unavailable: 3,
            ..KernelControl::default()
        })
        .expect("notice line");
        assert!(line.contains('3'), "{line}");
        assert!(!line.contains("262144"), "{line}");
    }

    // Identity budget (RED twin): no refusals, no notice.
    #[test]
    fn identity_notice_line_quiet_twin_is_silent() {
        assert_eq!(identity_notice_line(&KernelControl::default()), None);
    }

    #[test]
    fn owner_poison_names_match_the_native_header_bits() {
        // The published names are keyed by the native bits: every #define in
        // task_owner.h must equal the Rust constant the name table uses.
        let header = include_str!("../crates/ebpf/native/task_owner.h");
        let native = |name: &str| -> u64 {
            let line = header
                .lines()
                .find(|line| line.starts_with(&format!("#define {name} ")))
                .unwrap_or_else(|| panic!("{name} missing from task_owner.h"));
            line.split_whitespace()
                .nth(2)
                .unwrap()
                .trim_end_matches("ULL")
                .parse()
                .unwrap()
        };
        for (name, bit) in [
            ("OWNER_BAD_CONTROL", OWNER_BAD_CONTROL),
            ("OWNER_LOOKUP_UNKNOWN", OWNER_LOOKUP_UNKNOWN),
            ("OWNER_BAD_RECORD", OWNER_BAD_RECORD),
            ("OWNER_DELETE_FAILED", OWNER_DELETE_FAILED),
            ("OWNER_BOOKKEEPING_FAILED", OWNER_BOOKKEEPING_FAILED),
            ("OWNER_REFUND_FAILED", OWNER_REFUND_FAILED),
            ("OWNER_CLASSIFIER_FAILED", OWNER_CLASSIFIER_FAILED),
            ("OWNER_STATE_DELETE_FAILED", OWNER_STATE_DELETE_FAILED),
            ("OWNER_START_KEY_MISMATCH", OWNER_START_KEY_MISMATCH),
            ("OWNER_START_COUNT_MISMATCH", OWNER_START_COUNT_MISMATCH),
            ("OWNER_START_ROW_MISSING", OWNER_START_ROW_MISSING),
            ("OWNER_DIRECTORY_MISMATCH", OWNER_DIRECTORY_MISMATCH),
        ] {
            assert_eq!(native(name), bit, "{name}");
            assert!(
                OWNER_POISON_NAMES.iter().any(|(named, _)| *named == bit),
                "{name}"
            );
        }
        // A bookkeeping poison names exactly which invariant failed.
        let control = KernelControl {
            owner_poison: OWNER_BOOKKEEPING_FAILED | OWNER_START_COUNT_MISMATCH,
            ..KernelControl::default()
        };
        assert_eq!(
            control.evidence().owner_poison,
            ["bookkeeping_failed", "start_count_mismatch"]
        );
    }

    #[test]
    fn control_cells_publish_only_finite_names_and_counts() {
        let owner = ThreadOwnerControl {
            limit: 16_448,
            outstanding: 3,
            poison: OWNER_REFUND_FAILED | OWNER_BAD_CONTROL | (1 << 40),
            admission_failures: 2,
            reclamation_failures: 9,
            abandoned_start: 1,
            abandoned_discovery: 1,
        };
        let cookie = ImageIdentityControl {
            limit: 16_384,
            next_ticket: 16_384,
            unavailable: 5,
            create_failures: 0,
            retry_exhausted: 0,
        };
        let root = RootAffiliationControl {
            failure_flags: ROOT_RESERVE_CAS | ROOT_BAD_CELL,
            ..RootAffiliationControl::default()
        };
        let control = KernelControl::from_cells(Some(owner), Some(cookie), Some(root));
        assert!(control.halted());
        let evidence = control.evidence();
        assert_eq!(
            evidence,
            KernelControlEvidence {
                capture_halted: true,
                owner_poison: vec!["bad_control", "refund_failed", "unknown"],
                owner_admission_failures: 2,
                identity_unavailable: 5,
                identity_budget_exhausted: true,
                root_affiliation_failures: vec!["bad_cell", "reserve_contention"],
            }
        );
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(
            json.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "capture_halted",
                "identity_budget_exhausted",
                "identity_unavailable",
                "owner_admission_failures",
                "owner_poison",
                "root_affiliation_failures"
            ])
        );
        // Masks, outstanding leases and other private words never publish.
        let text = json.to_string();
        for private in ["1099511627809", "16448", "reclamation", "outstanding"] {
            assert!(!text.contains(private), "{private} leaked: {text}");
        }
        // Absent cells (Inventory objects) contribute nothing.
        assert_eq!(
            KernelControl::from_cells(None, None, None),
            KernelControl::default()
        );
        let unspent = ImageIdentityControl {
            next_ticket: 17,
            ..cookie
        };
        assert!(!KernelControl::from_cells(None, Some(unspent), None).identity_budget_exhausted);
    }

    #[test]
    fn empty_buckets_have_no_percentile() {
        let b = [0u64; LATENCY_BUCKETS];
        assert_eq!(percentile_ns(&b, 0.5), None);
    }

    /// Review answer (c) / F-2: unnamed rows are distinct, keyed by their
    /// exact target, and carry every table ordinal reaching them. The live
    /// table and trace name them by ordinal — never a bare `unknown` and
    /// never the positional guess as a name.
    #[test]
    fn unnamed_rows_carry_their_target_and_ordinals() {
        use crate::discovery::identity::ReconciledModule;
        use crate::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable, standard_ordinal};
        use crate::process::{MountNamespaceId, ProcessViewId};
        use p11scope_manifest::maps::{Device, ObjectKey};
        use serde_json::json;

        let key = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 42,
        };
        let entry = |name: &'static str, file_offset: u64| ScannedEntry {
            name,
            object: key,
            object_path: "/opt/p11.so".into(),
            file_offset,
        };
        let object = crate::plan::TEST_PINNED_OBJECT;
        let plan = crate::plan::build_from_reconciled_modules(&[ReconciledModule {
            object,
            entry_objects: vec![vec![object; 3]],
            exports: Default::default(),
            getter_present: false,
            witness_fault: false,
            scanned: ScannedModule {
                module_hint: None,
                mapped_identity: None,
                double_loaded: false,
                same_file_loads: 1,
                pre_copy_up: None,
                view: ProcessViewId(0),
                mount_namespace: MountNamespaceId {
                    device: 1,
                    inode: 1,
                },
                key,
                path: "/opt/p11.so".into(),
                tables_scan_finished: false,
                decoder_abi: Some(p11scope_manifest::elf::ElfAbi::Lp64),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    // A heuristic table: two ordinals share one stub.
                    entries: vec![
                        entry("C_Sign", 0x10),
                        entry("C_SignUpdate", 0x10),
                        entry("C_Verify", 0x20),
                    ],
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000,
                    file_offset: Some(0x100),
                    live_return: false,
                    manifest_supported: false,
                    extension_impossible: false,
                }],
                interfaces: vec![],
            },
        }]);
        assert_eq!(plan.slots.len(), 2);
        let reports: Vec<SlotReport> = plan
            .slots
            .iter()
            .map(|slot| {
                slot_report(
                    &plan,
                    slot,
                    SlotStats {
                        returned: 1,
                        entered: 1,
                        ..SlotStats::ZERO
                    },
                    BTreeMap::new(),
                )
            })
            .collect();
        let ordinal = |name| u64::from(standard_ordinal(name).expect("standard name"));
        let evidence = crate::render::tests::evidence();
        let document = crate::render::json(
            &reports,
            &evidence,
            &crate::render::CaptureMeta {
                started: "t0",
                ended: "t1",
                kernel: "6.8.0",
                policy: crate::attach::CapturePolicy::Allowlisted,
                scope: "pid",
                caller: None,
                ring_bytes: p11scope_ebpf_common::RING_BYTES,
                drain_interval_ms: 1000,
            },
        );
        let functions = document["functions"].as_array().unwrap();
        let row = |offset: u64| {
            functions
                .iter()
                .find(|function| function["target"]["file_offset"] == offset)
                .unwrap_or_else(|| panic!("no row targets {offset:#x}: {functions:?}"))
        };
        let shared = row(0x10);
        assert_eq!(
            shared["names"],
            json!(["unknown"]),
            "never a positional name"
        );
        assert_eq!(
            shared["ordinals"],
            json!([
                {"table_file_offset": 0x100, "ordinal": ordinal("C_Sign")},
                {"table_file_offset": 0x100, "ordinal": ordinal("C_SignUpdate")},
            ])
        );
        assert_eq!(
            row(0x20)["ordinals"],
            json!([{"table_file_offset": 0x100, "ordinal": ordinal("C_Verify")}])
        );
        assert_ne!(shared["target"], row(0x20)["target"], "rows are distinct");

        let live = crate::render::live(
            &reports,
            &evidence,
            std::time::Duration::ZERO,
            "/opt/p11.so",
            "profile",
            crate::attach::CapturePolicy::Allowlisted,
        );
        let shared_label = format!(
            "function #{} (unnamed)|function #{} (unnamed)",
            ordinal("C_Sign"),
            ordinal("C_SignUpdate")
        );
        assert!(live.contains(&shared_label), "{live}");
        assert!(
            live.contains(&format!("function #{} (unnamed)", ordinal("C_Verify"))),
            "{live}"
        );

        let shared_slot = plan
            .slots
            .iter()
            .find(|slot| slot.file_offset == 0x10)
            .unwrap()
            .index;
        let mut state = crate::semantics::State::new(&plan);
        let line = crate::trace::Tracer::new(&plan).on_event(
            &p11scope_ebpf_common::Event {
                slot: shared_slot,
                pid_tgid: 7 << 32,
                ..p11scope_ebpf_common::Event::default()
            },
            &mut state,
        );
        assert!(line.contains(&shared_label), "{line}");
    }

    #[test]
    fn slot_reports_use_new_plan_slots_without_a_second_lookup_table() {
        let mut plan = exact_plan(vec![slot(0, "C_OpenSession")]);
        let delta = plan
            .extend_exact(exact_plan(vec![
                slot(0, "C_OpenSession"),
                slot(1, "C_Sign"),
            ]))
            .unwrap();
        assert_eq!(delta.new[0].index, 1);
        let report = slot_report(
            &plan,
            &plan.slots[1],
            SlotStats {
                returned: 3,
                ..SlotStats::ZERO
            },
            BTreeMap::new(),
        );

        assert_eq!(report.names, ["C_Sign"]);
        assert_eq!(report.calls, 3);
        assert_eq!(report.module, Some(ModuleId(0)));
        assert_eq!(
            plan.module_of_slot(99),
            None,
            "unknown slots are unattributed"
        );
    }

    #[test]
    fn retired_slot_attribution_distinguishes_sole_ambiguous_and_unowned() {
        let mut plan = exact_plan(vec![slot(0, "C_Sign")]);
        plan.deactivate(0);

        let report = slot_report(
            &plan,
            &plan.slots[0],
            SlotStats {
                returned: 7,
                ..SlotStats::ZERO
            },
            BTreeMap::new(),
        );

        assert!(!plan.is_active(0));
        assert_eq!(report.calls, 7);
        assert_eq!(report.module, Some(ModuleId(0)));
        assert!(!report.module_ambiguous);
        assert!(!report.module_unresolved);

        let mut shared = slot(0, "C_Sign");
        shared.module_ids = vec![ModuleId(0), ModuleId(1)];
        let mut shared_plan = AttachPlan::from_slots(vec![shared]);
        shared_plan.deactivate(0);
        let shared_report = slot_report(
            &shared_plan,
            &shared_plan.slots[0],
            SlotStats::ZERO,
            BTreeMap::new(),
        );
        assert_eq!(shared_report.module, None);
        assert!(shared_report.module_ambiguous);
        assert!(
            !shared_report.module_unresolved,
            "two-module ambiguity is not an unresolved owner"
        );

        let mut unowned = slot(0, "C_Sign");
        unowned.module_ids.clear();
        let mut unowned_plan = AttachPlan::from_slots(vec![unowned]);
        unowned_plan.deactivate(0);
        let unowned_report = slot_report(
            &unowned_plan,
            &unowned_plan.slots[0],
            SlotStats::ZERO,
            BTreeMap::new(),
        );
        assert_eq!(unowned_report.module, None);
        assert!(!unowned_report.module_ambiguous);
        assert!(
            unowned_report.module_unresolved,
            "an allocated cell with no accepted sole owner is unresolved, \
             never a silent null"
        );
    }

    fn merge_fixture(
        name: &str,
        file_offset: u64,
        ino: u64,
        calls: u64,
        errors: u64,
        buckets: [u64; LATENCY_BUCKETS],
    ) -> SlotReport {
        let mut rv_counts = BTreeMap::new();
        rv_counts.insert(0u64, calls);
        SlotReport {
            names: vec![name.into()],
            aliased: false,
            semantic_authorized: false,
            module: Some(ModuleId(0)),
            module_ambiguous: false,
            module_unresolved: false,
            mode: CounterMode::Latency,
            calls,
            errors,
            in_flight: 0,
            total_ns: calls * 1000,
            max_ns: 2000,
            buckets,
            rv_counts,
            file_offset,
            target_object: Some(crate::plan::TargetObject {
                dev: (8, 1),
                ino,
                sha256: Some("aa".into()),
            }),
            ordinals: vec![],
        }
    }

    fn buckets_with(first: u64, second: u64) -> [u64; LATENCY_BUCKETS] {
        let mut buckets = [0u64; LATENCY_BUCKETS];
        buckets[0] = first;
        buckets[1] = second;
        buckets
    }

    /// Two generations of one owned child count the same function in
    /// the same file: the aggregate folds them into one row with
    /// summed counts, buckets and return tallies, never two
    /// unlabeled rows.
    #[test]
    fn merge_slot_reports_folds_same_function_same_file_rows() {
        let first = merge_fixture(
            "C_DigestUpdate",
            0x1234,
            4242,
            5625,
            1,
            buckets_with(10, 20),
        );
        let second = merge_fixture(
            "C_DigestUpdate",
            0x1234,
            4242,
            1494,
            2,
            buckets_with(30, 40),
        );
        let merged = merge_slot_reports(vec![first, second]);
        assert_eq!(merged.len(), 1, "one function reads one row");
        let row = &merged[0];
        assert_eq!(row.names, vec!["C_DigestUpdate".to_string()]);
        assert_eq!(row.calls, 7119);
        assert_eq!(row.errors, 3);
        assert_eq!(row.buckets[0], 40);
        assert_eq!(row.buckets[1], 60);
        assert_eq!(row.rv_counts.get(&0), Some(&7119));
        assert_eq!(row.file_offset, 0x1234);
    }

    /// Sharing a name never merges two modules: the same function in
    /// different files stays two rows.
    #[test]
    fn merge_slot_reports_keeps_different_files_apart() {
        let left = merge_fixture("C_DigestUpdate", 0x1234, 4242, 10, 0, buckets_with(1, 0));
        let right = merge_fixture("C_DigestUpdate", 0x1234, 9999, 20, 0, buckets_with(0, 1));
        let merged = merge_slot_reports(vec![left, right]);
        assert_eq!(merged.len(), 2, "two files stay two rows");
        let calls: u64 = merged.iter().map(|row| row.calls).sum();
        assert_eq!(calls, 30);
    }

    /// Different counter modes never fold together: a counts row and
    /// a latency row for the same function stay two rows, since their
    /// cells measure different things.
    #[test]
    fn merge_slot_reports_keeps_different_modes_apart() {
        let mut counts = merge_fixture("C_DigestUpdate", 0x1234, 4242, 10, 0, buckets_with(1, 0));
        counts.mode = CounterMode::Counts;
        let mut latency = merge_fixture("C_DigestUpdate", 0x1234, 4242, 20, 0, buckets_with(0, 1));
        latency.mode = CounterMode::Latency;
        let merged = merge_slot_reports(vec![counts, latency]);
        assert_eq!(merged.len(), 2, "two modes stay two rows");
        let calls: u64 = merged.iter().map(|row| row.calls).sum();
        assert_eq!(calls, 30);
    }

    #[test]
    fn historical_shared_slot_counts_stay_unattributed_after_one_owner_survives() {
        let target = crate::discovery::identity::PinnedObjectId(10);
        let mut shared = slot(0, "C_Sign");
        shared.object = target;
        shared.descriptor_index = 0;
        shared.semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        shared.semantic_ambiguous = true;
        shared.module_ids = vec![ModuleId(0), ModuleId(1)];
        let mut plan = AttachPlan::from_slots(vec![shared]);
        plan.modules = vec![module(0), module(1)];

        let mut survivor = slot(0, "C_Sign");
        survivor.object = target;
        survivor.module_ids = vec![ModuleId(1)];
        let mut rebuilt = AttachPlan::from_slots(vec![survivor]);
        rebuilt.modules = vec![module(1)];

        plan.extend_exact(rebuilt).unwrap();
        let report = slot_report(
            &plan,
            &plan.slots[0],
            SlotStats {
                returned: 7,
                ..SlotStats::ZERO
            },
            BTreeMap::new(),
        );

        assert_eq!(plan.slots[0].module_ids, [ModuleId(1)]);
        assert_eq!(plan.slots[0].descriptor_index, 0);
        assert_eq!(report.calls, 7);
        assert_eq!(report.module, None);
        assert!(report.module_ambiguous);
        assert_eq!(plan.module_ambiguous, 1);
    }

    #[test]
    fn refused_shared_candidate_keeps_existing_counts_but_removes_attribution() {
        let target = crate::discovery::identity::PinnedObjectId(10);
        let mut current = slot(0, "C_Sign");
        current.object = target;
        let descriptor = current.descriptor_index;
        let mut plan = exact_plan(vec![current]);

        let mut shared = slot(0, "C_Sign");
        shared.object = target;
        shared.descriptor_index = 0;
        shared.semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        shared.semantic_ambiguous = true;
        shared.module_ids = vec![ModuleId(0), ModuleId(1)];
        let mut rebuilt = AttachPlan::from_slots(vec![shared]);
        rebuilt.modules = vec![module(0), module(1)];
        rebuilt.modules[0].object = crate::plan::TEST_PINNED_OBJECT;
        rebuilt.modules[0].key = crate::plan::TEST_OBJECT;
        let mut candidate = plan.clone();
        assert_eq!(candidate.extend_exact(rebuilt).unwrap().replace.len(), 1);

        assert!(plan.latch_ambiguity_from(&candidate));
        let report = slot_report(
            &plan,
            &plan.slots[0],
            SlotStats {
                returned: 7,
                ..SlotStats::ZERO
            },
            BTreeMap::new(),
        );

        assert_eq!(plan.slots[0].descriptor_index, descriptor);
        assert_eq!(report.calls, 7);
        assert_eq!(report.module, None);
        assert!(report.module_ambiguous);

        plan.extend_exact(candidate).unwrap();
        assert_eq!(plan.module_of_slot(0), None);
    }

    fn gate_control() -> LoaderGateControl {
        LoaderGateControl {
            limit: 256,
            cutover: 1,
            admitted: 11,
            refusals: 2,
            retired: 7,
            reclaims: 5,
            retained: 6,
            retained_peak: 9,
            update_losses: 1,
        }
    }

    fn bank_select() -> ImageBankSelect {
        ImageBankSelect {
            bank: 0,
            prepared: [1, 0],
            cuts: 1,
            refusals: 2,
            incarnation: [0, 0],
            folded: [0, 0],
            folds: 0,
            folded_issued: 100,
            update_losses: 0,
        }
    }

    fn bank_control(next_ticket: u64) -> ImageIdentityControl {
        ImageIdentityControl {
            limit: 16_384,
            next_ticket,
            unavailable: 0,
            create_failures: 0,
            retry_exhausted: 0,
        }
    }

    fn json_keys(value: &serde_json::Value) -> std::collections::BTreeSet<&str> {
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn loader_transitions_link_present_control_and_refuse_absence() {
        assert_eq!(LoaderTransitions::from_control(None), None);
        assert_eq!(
            LoaderTransitions::from_control(Some(gate_control())),
            Some(LoaderTransitions {
                arms: 11,
                reclaims: 5,
                retained_peak: 9,
                refusals: 2,
                update_losses: 1,
            })
        );
    }

    #[test]
    fn loader_transitions_absent_is_never_zero() {
        // Absence is None, never a zero-filled struct: without the
        // producer there is nothing to report, not a quiet capture.
        assert_eq!(LoaderTransitions::from_control(None), None);
        assert_ne!(
            LoaderTransitions::from_control(None),
            Some(LoaderTransitions::default())
        );
    }

    #[test]
    fn loader_transitions_publish_exactly_five_u64_cells() {
        let expected = std::collections::BTreeSet::from([
            "arms",
            "reclaims",
            "refusals",
            "retained_peak",
            "update_losses",
        ]);
        let default_json = serde_json::to_value(LoaderTransitions::default()).unwrap();
        assert_eq!(json_keys(&default_json), expected);
        let linked = LoaderTransitions::from_control(Some(gate_control())).unwrap();
        let json = serde_json::to_value(&linked).unwrap();
        assert_eq!(json_keys(&json), expected);
        assert_eq!(json["arms"], 11);
        assert_eq!(json["reclaims"], 5);
        assert_eq!(json["retained_peak"], 9);
        assert_eq!(json["refusals"], 2);
        assert_eq!(json["update_losses"], 1);
        for key in expected {
            assert!(json[key].is_u64(), "{key} must be a u64, not a bool");
        }
    }

    #[test]
    fn loader_transitions_hide_private_gate_words() {
        let control = LoaderGateControl {
            limit: 256,
            cutover: 9001,
            retired: 7001,
            retained: 3001,
            ..gate_control()
        };
        let linked = LoaderTransitions::from_control(Some(control)).unwrap();
        let text = serde_json::to_value(&linked).unwrap().to_string();
        for private in ["256", "9001", "7001", "3001"] {
            assert!(!text.contains(private), "{private} leaked: {text}");
        }
    }

    #[test]
    fn loader_transitions_refuse_malformed_control() {
        for limit in [0, 1, 255, 257, 512, u64::MAX] {
            let control = LoaderGateControl {
                limit,
                ..gate_control()
            };
            assert_eq!(
                LoaderTransitions::from_control(Some(control)),
                None,
                "limit={limit} is malformed and must refuse"
            );
        }
    }

    #[test]
    fn image_transitions_derive_issuance_and_refuse_absence() {
        assert_eq!(ImageTransitions::from_cells(None, None, None), None);
        // folded_issued plus both live watermarks, saturating.
        let linked = ImageTransitions::from_cells(
            Some(bank_select()),
            Some(bank_control(10)),
            Some(bank_control(20)),
        )
        .unwrap();
        assert_eq!(
            linked,
            ImageTransitions {
                tickets_issued: 130,
                bank_cuts: 1,
                bank_refusals: 2,
                update_losses: 0,
            }
        );
        // A retired-pending bank contributes through folded_issued, so
        // its still-intact watermark is excluded, never double counted.
        let folding = ImageBankSelect {
            folded: [1, 0],
            folded_issued: 100,
            ..bank_select()
        };
        let linked = ImageTransitions::from_cells(
            Some(folding),
            Some(bank_control(10)),
            Some(bank_control(20)),
        )
        .unwrap();
        assert_eq!(linked.tickets_issued, 120);
        // Saturation at the ceiling, never a wrap to a small count.
        let full = ImageBankSelect {
            folded_issued: u64::MAX,
            ..bank_select()
        };
        let linked = ImageTransitions::from_cells(
            Some(full),
            Some(bank_control(10)),
            Some(bank_control(20)),
        )
        .unwrap();
        assert_eq!(linked.tickets_issued, u64::MAX);
    }

    #[test]
    fn image_transitions_absent_is_never_zero() {
        assert_eq!(ImageTransitions::from_cells(None, None, None), None);
        assert_ne!(
            ImageTransitions::from_cells(None, None, None),
            Some(ImageTransitions::default())
        );
        // Any missing input refuses the whole field, never a partial sum.
        let select = Some(bank_select());
        let control = Some(bank_control(10));
        assert_eq!(ImageTransitions::from_cells(None, control, control), None);
        assert_eq!(ImageTransitions::from_cells(select, None, control), None);
        assert_eq!(ImageTransitions::from_cells(select, control, None), None);
    }

    #[test]
    fn image_transitions_publish_exactly_four_u64_cells() {
        let expected = std::collections::BTreeSet::from([
            "bank_cuts",
            "bank_refusals",
            "tickets_issued",
            "update_losses",
        ]);
        let default_json = serde_json::to_value(ImageTransitions::default()).unwrap();
        assert_eq!(json_keys(&default_json), expected);
        let linked = ImageTransitions::from_cells(
            Some(bank_select()),
            Some(bank_control(10)),
            Some(bank_control(20)),
        )
        .unwrap();
        let json = serde_json::to_value(&linked).unwrap();
        assert_eq!(json_keys(&json), expected);
        assert_eq!(json["tickets_issued"], 130);
        assert_eq!(json["bank_cuts"], 1);
        assert_eq!(json["bank_refusals"], 2);
        assert_eq!(json["update_losses"], 0);
        for key in expected {
            assert!(json[key].is_u64(), "{key} must be a u64, not a bool");
        }
    }

    #[test]
    fn image_transitions_hide_private_bank_words() {
        let select = ImageBankSelect {
            bank: 1,
            prepared: [0, 1],
            incarnation: [6001, 6002],
            folded: [0, 1],
            folds: 6003,
            ..bank_select()
        };
        let linked = ImageTransitions::from_cells(
            Some(select),
            Some(bank_control(10)),
            Some(bank_control(20)),
        )
        .unwrap();
        let text = serde_json::to_value(&linked).unwrap().to_string();
        for private in ["6001", "6002", "6003"] {
            assert!(!text.contains(private), "{private} leaked: {text}");
        }
    }

    #[test]
    fn image_transitions_refuse_invalid_controls() {
        let select = Some(bank_select());
        let good = Some(bank_control(10));
        // A watermark past the budget or a wrong limit fails closed.
        for bad in [
            bank_control(16_385),
            bank_control(u64::MAX),
            ImageIdentityControl {
                limit: 0,
                ..bank_control(10)
            },
            ImageIdentityControl {
                limit: u64::MAX,
                ..bank_control(10)
            },
        ] {
            assert_eq!(
                ImageTransitions::from_cells(select, Some(bad), good),
                None,
                "bank A {bad:?} must refuse"
            );
            assert_eq!(
                ImageTransitions::from_cells(select, good, Some(bad)),
                None,
                "bank B {bad:?} must refuse"
            );
        }
    }

    #[test]
    fn production_build_selects_loader_gate_behind_env_switch() {
        let source = include_str!("../build.rs");
        // Unset/0 = inactive default, 1 = production wiring, else refuse.
        assert!(
            source.contains("P11SCOPE_LOADER_GATE"),
            "build.rs selects no loader gate switch"
        );
        assert!(
            source.contains("cargo:rerun-if-env-changed=P11SCOPE_LOADER_GATE"),
            "the gate switch must invalidate the build cache"
        );
        assert!(
            source.contains("P11SCOPE_LOADER_GATE_ENABLED"),
            "the gate selection must be an emitted contract"
        );
    }

    #[test]
    fn production_flavors_compile_gate_unit_with_define() {
        let source = include_str!("../build.rs");
        assert!(
            source.contains("\"loader_gate\""),
            "no flavor compiles the gate unit"
        );
        assert_eq!(
            source.matches("-DP11SCOPE_LOADER_GATE").count(),
            1,
            "exactly one production gate define"
        );
        assert!(
            source.contains("--cfg=p11scope_loader_gate"),
            "the Rust gate maps need their cfg"
        );
        // Quote-terminated: LOADER_GATE must not match LOADER_GATE_CTL.
        assert_eq!(
            source.matches("link-arg=--export=LOADER_GATE\"").count(),
            1,
            "the rows map must survive the native link"
        );
        assert_eq!(
            source
                .matches("link-arg=--export=LOADER_GATE_CTL\"")
                .count(),
            1,
            "the control map must survive the native link"
        );
        for unit in ["loader_gate.c", "loader_gate.h"] {
            assert!(
                source.contains(&format!("cargo:rerun-if-changed=crates/ebpf/native/{unit}")),
                "native {unit} edits must invalidate the build cache"
            );
        }
    }

    #[test]
    fn legacy_slot_failure_reports_zero_with_gap_and_rest_exact() {
        // One STATS slot read fails; that slot reports zero as unknown with
        // a gap count, while the readable slot stays exact.
        let plan = exact_plan(vec![slot(0, "C_Sign"), slot(1, "C_Verify")]);
        let good = SlotStats {
            entered: 3,
            returned: 5,
            errors: 1,
            total_ns: 50,
            max_ns: 20,
            buckets: [0; LATENCY_BUCKETS],
        };
        let (reports, gaps) = collect_legacy_reports(
            &plan,
            |index| {
                if index == 0 { Err(()) } else { Ok(vec![good]) }
            },
            vec![(
                RvKey {
                    slot: 1,
                    _pad: 0,
                    rv: 0,
                },
                5,
            )],
        );
        assert_eq!(reports.len(), 2);
        assert_eq!((reports[0].calls, reports[0].errors), (0, 0));
        assert!(reports[0].rv_counts.is_empty());
        assert_eq!((reports[1].calls, reports[1].errors), (5, 1));
        assert_eq!(reports[1].rv_counts.get(&0), Some(&5));
        assert_eq!(gaps.unread_stats, 1);
        assert!(!gaps.rv_failed);
    }

    #[test]
    fn legacy_rv_failure_keeps_readable_entries_with_gap() {
        // One RV entry read fails; readable RVs stay exact with an RV gap.
        let plan = exact_plan(vec![slot(0, "C_Sign")]);
        let stats = SlotStats {
            entered: 3,
            returned: 5,
            errors: 1,
            ..SlotStats::ZERO
        };
        let entries: Vec<Result<(RvKey, u64), ()>> = vec![
            Ok((
                RvKey {
                    slot: 0,
                    _pad: 0,
                    rv: 0,
                },
                3,
            )),
            Err(()),
            Ok((
                RvKey {
                    slot: 0,
                    _pad: 0,
                    rv: 1,
                },
                2,
            )),
        ];
        let (mut map, rv_failed) = collect_legacy_rvs(entries.clone());
        assert!(rv_failed);
        assert_eq!(map.get(&0).unwrap().get(&0), Some(&3));
        assert_eq!(map.get(&0).unwrap().get(&1), Some(&2));
        let (reports, gaps) = collect_legacy_reports(
            &plan,
            |_| Ok(vec![stats]),
            map.remove(&0)
                .unwrap()
                .into_iter()
                .map(|(rv, total)| {
                    (
                        RvKey {
                            slot: 0,
                            _pad: 0,
                            rv,
                        },
                        total,
                    )
                })
                .collect(),
        );
        assert_eq!(reports[0].calls, 5);
        // The RV gap rides the composed collection gaps, not the STATS path.
        let (composed, composed_gaps) = compose_legacy_read(&plan, |_| Ok(vec![stats]), entries);
        assert_eq!(composed[0].calls, 5);
        assert_eq!(composed[0].rv_counts.get(&0), Some(&3));
        assert_eq!(composed[0].rv_counts.get(&1), Some(&2));
        assert_eq!(composed_gaps.unread_stats, 0);
        assert!(
            composed_gaps.rv_failed,
            "the composed gaps must carry the RV failure"
        );
        assert_eq!(
            gaps,
            LegacySlotGaps {
                unread_stats: 0,
                rv_failed: false,
            }
        );
    }

    #[test]
    fn compose_legacy_read_combines_unread_stats_and_rv_failure() {
        // An unread STATS slot and a failed RV entry in one read ride the
        // same composed gaps: zero as unknown for the unread slot, exact
        // readable entries, and both gap facts set together.
        let plan = exact_plan(vec![slot(0, "C_Sign"), slot(1, "C_Verify")]);
        let stats = SlotStats {
            entered: 3,
            returned: 5,
            errors: 1,
            ..SlotStats::ZERO
        };
        let entries: Vec<Result<(RvKey, u64), ()>> = vec![
            Ok((
                RvKey {
                    slot: 0,
                    _pad: 0,
                    rv: 0,
                },
                5,
            )),
            Err(()),
        ];
        let (reports, gaps) = compose_legacy_read(
            &plan,
            |index| {
                if index == 0 { Ok(vec![stats]) } else { Err(()) }
            },
            entries,
        );
        assert_eq!(reports.len(), 2);
        assert_eq!((reports[0].calls, reports[0].errors), (5, 1));
        assert_eq!(reports[0].rv_counts.get(&0), Some(&5));
        assert_eq!(
            (reports[1].calls, reports[1].errors),
            (0, 0),
            "unread slot reports zero as unknown"
        );
        assert!(reports[1].rv_counts.is_empty());
        assert_eq!(gaps.unread_stats, 1);
        assert!(
            gaps.rv_failed,
            "the composed gaps must carry the RV failure"
        );
    }

    #[test]
    fn compose_legacy_controls_marks_each_failed_cell_with_its_bit() {
        // Each failed control read sets exactly its own unknown bit and
        // contributes nothing; readable cells flow through, and a missing
        // map (Inventory flavors) contributes nothing without a gap bit.
        let owner = ThreadOwnerControl {
            poison: 4,
            admission_failures: 7,
            ..Default::default()
        };
        let cookie = ImageIdentityControl {
            unavailable: 3,
            ..Default::default()
        };
        let root = RootAffiliationControl {
            failure_flags: 9,
            ..Default::default()
        };
        let (control, unknown) =
            compose_legacy_controls(Ok(Some(owner)), Ok(Some(cookie)), Ok(Some(root)));
        assert_eq!(unknown, 0);
        assert_eq!(
            (
                control.owner_poison,
                control.owner_admission_failures,
                control.identity_unavailable,
                control.root_failures
            ),
            (4, 7, 3, 9),
            "readable control values flow through"
        );
        let (_, unknown) = compose_legacy_controls(Ok(None), Ok(None), Ok(None));
        assert_eq!(unknown, 0, "missing maps contribute no gap bit");
        for (name, owner, cookie, root, bit) in [
            (
                "owner",
                Err(()),
                Ok(Some(cookie)),
                Ok(Some(root)),
                LEGACY_UNKNOWN_OWNER,
            ),
            (
                "cookie",
                Ok(Some(owner)),
                Err(()),
                Ok(Some(root)),
                LEGACY_UNKNOWN_COOKIE,
            ),
            (
                "root",
                Ok(Some(owner)),
                Ok(Some(cookie)),
                Err(()),
                LEGACY_UNKNOWN_ROOT,
            ),
        ] {
            let (control, unknown) = compose_legacy_controls(owner, cookie, root);
            assert_eq!(unknown, bit, "{name} failure sets exactly its bit");
            assert_eq!(
                (
                    control.owner_poison,
                    control.owner_admission_failures,
                    control.identity_unavailable,
                    control.root_failures
                ),
                match name {
                    "owner" => (0, 0, 3, 9),
                    "cookie" => (4, 7, 0, 9),
                    _ => (4, 7, 3, 0),
                },
                "{name} failure contributes nothing else"
            );
        }
        let (_, unknown) = compose_legacy_controls(Err(()), Err(()), Err(()));
        assert_eq!(
            unknown,
            LEGACY_UNKNOWN_OWNER | LEGACY_UNKNOWN_COOKIE | LEGACY_UNKNOWN_ROOT
        );
    }

    #[test]
    fn legacy_slot_success_reports_exact_with_no_gap() {
        let plan = exact_plan(vec![slot(0, "C_Sign"), slot(1, "C_Verify")]);
        let stats = SlotStats {
            entered: 3,
            returned: 5,
            errors: 1,
            total_ns: 50,
            max_ns: 20,
            buckets: [0; LATENCY_BUCKETS],
        };
        let (reports, gaps) = collect_legacy_reports(
            &plan,
            |_| Ok(vec![stats]),
            vec![
                (
                    RvKey {
                        slot: 0,
                        _pad: 0,
                        rv: 0,
                    },
                    5,
                ),
                (
                    RvKey {
                        slot: 1,
                        _pad: 0,
                        rv: 0,
                    },
                    5,
                ),
            ],
        );
        assert_eq!(reports.len(), 2);
        for report in &reports {
            assert_eq!((report.calls, report.errors), (5, 1));
            assert_eq!(report.rv_counts.get(&0), Some(&5));
        }
        assert_eq!(
            gaps,
            LegacySlotGaps {
                unread_stats: 0,
                rv_failed: false,
            }
        );
    }

    #[test]
    fn legacy_rv_success_reports_exact_with_no_gap() {
        let entries: Vec<Result<(RvKey, u64), ()>> = vec![
            Ok((
                RvKey {
                    slot: 0,
                    _pad: 0,
                    rv: 0,
                },
                3,
            )),
            Ok((
                RvKey {
                    slot: 0,
                    _pad: 0,
                    rv: 1,
                },
                2,
            )),
        ];
        let (map, rv_failed) = collect_legacy_rvs(entries);
        assert!(!rv_failed);
        assert_eq!(map.get(&0).unwrap().get(&0), Some(&3));
        assert_eq!(map.get(&0).unwrap().get(&1), Some(&2));
    }

    #[test]
    fn legacy_evidence_cell_failure_reports_unknown_with_gap() {
        // Every EVIDENCE and control cell reports 0 as unknown with its bit
        // when its read fails, while readable cells stay exact.
        for (cell, bit) in LEGACY_UNKNOWN_CELLS {
            let (value, unknown) = read_legacy_evidence_cell(Err(()), *bit);
            assert_eq!((value, unknown), (0, *bit), "{cell} must read unknown");
            let (value, unknown) = read_legacy_evidence_cell(Ok(7), *bit);
            assert_eq!((value, unknown), (7, 0), "{cell} readable stays exact");
        }
    }

    #[test]
    fn harness_gate_compiles_keep_their_own_define() {
        // The three harness -D sites stay exactly as they are; the
        // production wiring adds a new define, never moves theirs.
        let standalone = include_str!("../tests/loader_gate_standalone.rs");
        let retirement = include_str!("../tests/task_owner_contracts.rs");
        assert_eq!(
            standalone.matches("-DP11SCOPE_LOADER_GATE").count(),
            2,
            "standalone harness compiles must keep both -D sites"
        );
        assert_eq!(
            retirement.matches("-DP11SCOPE_LOADER_GATE").count(),
            1,
            "retirement fixture compile must keep its -D site"
        );
    }
}
