//! SPDX-License-Identifier: GPL-3.0-or-later
//! Reading the aggregate maps. PerCpu values are summed in userspace;
//! percentiles come from log2 buckets and are therefore approximations
//! (the lower bound of the containing bucket), which every renderer must
//! state.

use crate::attach::Session;
use crate::plan::{AttachPlan, ModuleId};
use anyhow::{Context as _, Result};
use aya::maps::{Array, PerCpuArray, PerCpuHashMap};
use p11scope_ebpf_common::{
    EVIDENCE_ABI_REFUSALS, EVIDENCE_CGROUP_SCOPE_FAILURES, EVIDENCE_RING_LOSS,
    EVIDENCE_RV_UPDATE_FAILURES, EVIDENCE_SEMANTIC_CAPTURE_FAILURES,
    EVIDENCE_START_INSERT_FAILURES, EVIDENCE_TEMPLATE_TAIL_FAILURES, EVIDENCE_UNMATCHED_RETURNS,
    EVIDENCE_UNREGISTERED_MECHANISMS, ImageIdentityControl, LATENCY_BUCKETS, OWNER_BAD_CONTROL,
    OWNER_BAD_RECORD, OWNER_BOOKKEEPING_FAILED, OWNER_CLASSIFIER_FAILED, OWNER_DELETE_FAILED,
    OWNER_LOOKUP_UNKNOWN, OWNER_REFUND_FAILED, OWNER_STATE_DELETE_FAILED, ROOT_BAD_CELL,
    ROOT_BAD_CONTROL, ROOT_CAPACITY, ROOT_CREATE_FAILED, ROOT_EXISTING_CHILD, ROOT_EXIT_CLASSIFIER,
    ROOT_EXIT_DELETE, ROOT_REFUND_FAILED, ROOT_RESERVE_CAS, RootAffiliationControl, RvKey,
    SlotStats, ThreadOwnerControl,
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
        calls: acc.returned,
        errors: acc.errors,
        in_flight: acc.entered.saturating_sub(acc.returned),
        total_ns: acc.total_ns,
        max_ns: acc.max_ns,
        buckets: acc.buckets,
        rv_counts,
    }
}

pub fn read(session: &Session, plan: &AttachPlan) -> Result<Vec<SlotReport>> {
    let stats: PerCpuArray<_, SlotStats> =
        PerCpuArray::try_from(session.ebpf.map("STATS").context("STATS map")?)?;
    let rvs: PerCpuHashMap<_, RvKey, u64> =
        PerCpuHashMap::try_from(session.ebpf.map("RV_COUNTS").context("RV_COUNTS map")?)?;

    let mut rv_by_slot: BTreeMap<u32, BTreeMap<u64, u64>> = BTreeMap::new();
    for entry in rvs.iter() {
        let (k, per_cpu) = entry?;
        let total: u64 = per_cpu.iter().copied().sum();
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
    Ok(out)
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

const OWNER_POISON_NAMES: [(u64, &str); 8] = [
    (OWNER_BAD_CONTROL, "bad_control"),
    (OWNER_LOOKUP_UNKNOWN, "lookup_unknown"),
    (OWNER_BAD_RECORD, "bad_record"),
    (OWNER_DELETE_FAILED, "delete_failed"),
    (OWNER_BOOKKEEPING_FAILED, "bookkeeping_failed"),
    (OWNER_REFUND_FAILED, "refund_failed"),
    (OWNER_CLASSIFIER_FAILED, "classifier_failed"),
    (OWNER_STATE_DELETE_FAILED, "state_delete_failed"),
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
    if control.identity_unavailable != 0 && !IDENTITY_NOTICE.swap(true, Ordering::Relaxed) {
        eprintln!(
            "p11scope: kernel could not give a process an identity{}; its calls \
             and fork records are not captured and the report is PARTIAL",
            if control.identity_budget_exhausted {
                " (lifetime budget of 16384 identities spent)"
            } else {
                ""
            }
        );
    }
}

pub fn kernel_evidence(session: &Session) -> Result<KernelEvidence> {
    let evidence: PerCpuArray<_, u64> =
        PerCpuArray::try_from(session.ebpf.map("EVIDENCE").context("EVIDENCE map")?)?;
    let read = |index| -> Result<u64> { Ok(evidence.get(&index, 0)?.iter().copied().sum()) };
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
    })
}

/// Approximate quantile from log2 buckets: the lower bound of the bucket
/// containing the q-th observation. `q` is in (0.0, 1.0].
pub fn percentile_ns(buckets: &[u64; LATENCY_BUCKETS], q: f64) -> Option<u64> {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return None;
    }
    let target = ((total as f64) * q).ceil() as u64;
    let mut seen = 0u64;
    for (i, count) in buckets.iter().enumerate() {
        seen += count;
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
}
