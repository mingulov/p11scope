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
    /// The module these counts belong to; `None` when two modules publish this
    /// target and neither can be credited (spec §4.7).
    pub module: Option<ModuleId>,
    /// True exactly when `module` is `None` because the target is shared.
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
        out.push(SlotReport {
            names: slot.names.clone(),
            aliased: slot.aliased,
            module: plan.module_of_slot(slot.index),
            module_ambiguous: slot.module_ids.len() >= 2,
            calls: acc.returned,
            errors: acc.errors,
            in_flight: acc.entered.saturating_sub(acc.returned),
            total_ns: acc.total_ns,
            max_ns: acc.max_ns,
            buckets: acc.buckets,
            rv_counts: rv_by_slot.remove(&slot.index).unwrap_or_default(),
        });
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
}
