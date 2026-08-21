//! Reading the aggregate maps. PerCpu values are summed in userspace;
//! percentiles come from log2 buckets and are therefore approximations
//! (the lower bound of the containing bucket), which every renderer must
//! state.

use crate::attach::Session;
use crate::plan::{AttachPlan, ModuleId};
use anyhow::{Context as _, Result};
use aya::maps::{PerCpuArray, PerCpuHashMap};
use p11scope_ebpf_common::{
    EVIDENCE_CGROUP_SCOPE_FAILURES, EVIDENCE_RING_LOSS, EVIDENCE_RV_UPDATE_FAILURES,
    EVIDENCE_SEMANTIC_CAPTURE_FAILURES, EVIDENCE_START_INSERT_FAILURES,
    EVIDENCE_TEMPLATE_TAIL_FAILURES, EVIDENCE_UNMATCHED_RETURNS, EVIDENCE_UNREGISTERED_MECHANISMS,
    LATENCY_BUCKETS, RvKey, SlotStats,
};
use std::collections::BTreeMap;

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
    SlotReport {
        names: slot.names.clone(),
        aliased: slot.aliased,
        semantic_authorized: slot.semantic_authorized,
        module: plan.module_of_slot(slot.index),
        module_ambiguous: plan.slot_is_module_ambiguous(slot.index),
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
            *rv_by_slot
                .entry(k.slot)
                .or_default()
                .entry(k.rv)
                .or_default() += total;
        }
    }

    let mut out = Vec::with_capacity(plan.slots.len());
    for slot in &plan.slots {
        let per_cpu = stats.get(&slot.index, 0)?;
        let mut acc = SlotStats::ZERO;
        for cpu in per_cpu.iter() {
            acc.entered += cpu.entered;
            acc.returned += cpu.returned;
            acc.errors += cpu.errors;
            acc.total_ns += cpu.total_ns;
            acc.max_ns = acc.max_ns.max(cpu.max_ns);
            for (i, b) in cpu.buckets.iter().enumerate() {
                acc.buckets[i] += b;
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
}

pub fn kernel_evidence(session: &Session) -> Result<KernelEvidence> {
    let evidence: PerCpuArray<_, u64> =
        PerCpuArray::try_from(session.ebpf.map("EVIDENCE").context("EVIDENCE map")?)?;
    let read = |index| -> Result<u64> { Ok(evidence.get(&index, 0)?.iter().copied().sum()) };
    Ok(KernelEvidence {
        ring_loss: read(EVIDENCE_RING_LOSS)?,
        start_insert_failures: read(EVIDENCE_START_INSERT_FAILURES)?,
        unmatched_returns: read(EVIDENCE_UNMATCHED_RETURNS)?,
        rv_update_failures: read(EVIDENCE_RV_UPDATE_FAILURES)?,
        cgroup_scope_failures: read(EVIDENCE_CGROUP_SCOPE_FAILURES)?,
        semantic_capture_failures: read(EVIDENCE_SEMANTIC_CAPTURE_FAILURES)?,
        template_tail_failures: read(EVIDENCE_TEMPLATE_TAIL_FAILURES)?,
        unregistered_mechanisms: read(EVIDENCE_UNREGISTERED_MECHANISMS)?,
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
}
