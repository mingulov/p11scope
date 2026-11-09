//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Charged cumulative presentation from the existing complete counter collector.

use super::counter_collector::{
    CounterCellDelta, CounterCollector, CounterGaps, CounterHealth, CounterIssue, CounterLimits,
    CounterObservation, CounterRead, ReadReservation, ReadStage, ReadWindow, tree_bytes,
};
use super::{KernelEvidence, LegacyReadGaps, SlotReport};
use crate::discovery::identity::PinnedObjects;
use crate::plan::{AttachKey, AttachPlan, SlotOrdinal};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
use p11scope_ebpf_common::CounterMode;
use std::mem::size_of;
use std::num::NonZeroU64;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CounterFailure {
    Read(ReadStage),
    Collection(CounterIssue),
    Projection,
}

/// Data, source rows and the actual collector's delta allocation share this
/// view's lifetime. Cloning a display tick never deep-copies any of them.
#[derive(Debug)]
struct Projection {
    source: CounterRead,
    reports: Vec<SlotReport>,
    observation: CounterObservation,
    _storage: ResourceLease,
}

#[derive(Debug, Clone)]
pub(super) struct CounterSnapshot {
    data: Option<Arc<Projection>>,
    failure: Option<CounterFailure>,
    attempted_kernel: Option<KernelEvidence>,
    discontinuity: bool,
    bank_gaps: CounterGaps,
}

impl CounterSnapshot {
    pub(super) fn has_data(&self) -> bool {
        self.data.is_some()
    }

    pub(super) fn reports(&self) -> &[SlotReport] {
        self.data.as_ref().map_or(&[], |data| &data.reports)
    }

    pub(super) fn is_fresh(&self) -> bool {
        self.data.is_some() && self.failure.is_none()
    }

    pub(super) fn failure(&self) -> Option<CounterFailure> {
        self.failure
    }

    pub(super) fn discontinuity(&self) -> bool {
        self.discontinuity
    }

    pub(super) fn mode(&self) -> Option<CounterMode> {
        self.data.as_ref().map(|data| data.source.view().mode)
    }

    pub(super) fn generation(&self) -> Option<u64> {
        self.data
            .as_ref()
            .map(|data| data.source.view().generation.get())
    }

    pub(super) fn window(&self) -> Option<ReadWindow> {
        self.data
            .as_ref()
            .and_then(|data| data.source.view().window)
    }

    pub(super) fn kernel_evidence(&self) -> Option<KernelEvidence> {
        self.attempted_kernel
            .or_else(|| self.data.as_ref().map(|data| data.source.view().kernel))
    }

    pub(super) fn health(&self) -> Option<CounterHealth> {
        if !self.is_fresh() || self.bank_gaps.health_failed {
            return None;
        }
        Some(self.data.as_ref().unwrap().source.view().health)
    }

    pub(super) fn bank_gaps(&self) -> CounterGaps {
        self.bank_gaps
    }

    pub(super) fn deltas(&self) -> Option<&[CounterCellDelta]> {
        match &self.data.as_ref()?.observation {
            CounterObservation::Advanced { deltas, .. } => Some(deltas),
            _ => None,
        }
    }
}

impl CounterFailure {
    fn with_observed_health(self, health: CounterHealth) -> Self {
        if health.saturated {
            Self::Collection(CounterIssue::ProducerSaturated)
        } else if health.contended {
            Self::Collection(CounterIssue::Contended)
        } else {
            self
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Read(stage) => match stage {
                ReadStage::Shape(_) => "read_shape",
                ReadStage::Budget => "read_budget",
                ReadStage::Stats => "read_stats",
                ReadStage::Rvs => "read_rvs",
                ReadStage::Health => "read_health",
                ReadStage::KernelEvidence => "read_kernel_evidence",
                ReadStage::BankRouting => "bank_routing",
                ReadStage::BankQuarantined => "bank_quarantined",
            },
            Self::Collection(issue) => match issue {
                CounterIssue::Topology => "topology",
                CounterIssue::Mode => "mode",
                CounterIssue::GenerationRollback => "generation_rollback",
                CounterIssue::Limits => "limits",
                CounterIssue::ProducerSaturated | CounterIssue::Saturated { .. } => "saturated",
                CounterIssue::Contended => "contended",
                CounterIssue::KernelEvidence => "kernel_evidence",
                CounterIssue::BankRouting => "bank_routing",
                CounterIssue::BankQuarantined => "bank_quarantined",
                CounterIssue::FoldOverflow(_) => "fold_overflow",
                CounterIssue::Regressed { .. } => "regressed",
            },
            Self::Projection => "projection",
        }
    }
}

/// Admission/capture ownership supplies these limits and this existing pool.
/// There is deliberately no default pool or Session-derived budget here.
/// The requested mode identifies an empty capture that never reads banks.
pub(crate) struct CounterCaptureInputs {
    mode: CounterMode,
    limits: CounterLimits,
    reserve: SemanticResourceReserver,
}

impl CounterCaptureInputs {
    pub(crate) fn new(
        mode: CounterMode,
        rows: usize,
        rv_keys: usize,
        reserve: SemanticResourceReserver,
    ) -> Self {
        Self {
            mode,
            limits: CounterLimits { rows, rv_keys },
            reserve,
        }
    }

    pub(crate) fn rows(&self) -> usize {
        self.limits.rows
    }

    pub(crate) fn rv_keys(&self) -> usize {
        self.limits.rv_keys
    }
}

#[derive(Debug, Clone)]
enum CaptureData {
    Legacy(Vec<SlotReport>, KernelEvidence, LegacyReadGaps),
    Counter(CounterSnapshot),
}

/// Protected measurement plus an internal proof of acquisition in this call.
/// Cached clones preserve the measured status/window but cannot settle capture.
#[derive(Debug)]
pub(crate) struct CaptureSnapshot {
    data: CaptureData,
    new_acquisition: bool,
}

impl Clone for CaptureSnapshot {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            new_acquisition: false,
        }
    }
}

impl CaptureSnapshot {
    fn from_counter(snapshot: CounterSnapshot) -> anyhow::Result<Self> {
        if !snapshot.has_data() || snapshot.kernel_evidence().is_none() {
            anyhow::bail!(
                "counter collection unavailable ({})",
                snapshot
                    .failure()
                    .map_or("unavailable", CounterFailure::name)
            );
        }
        Ok(Self {
            new_acquisition: snapshot.is_fresh(),
            data: CaptureData::Counter(snapshot),
        })
    }

    fn counter(&self) -> Option<&CounterSnapshot> {
        match &self.data {
            CaptureData::Counter(snapshot) => Some(snapshot),
            CaptureData::Legacy(..) => None,
        }
    }

    pub(crate) fn reports(&self) -> &[SlotReport] {
        match &self.data {
            CaptureData::Legacy(reports, _, _) => reports,
            CaptureData::Counter(snapshot) => snapshot.reports(),
        }
    }

    pub(crate) fn kernel_evidence(&self) -> KernelEvidence {
        match &self.data {
            CaptureData::Legacy(_, kernel, _) => *kernel,
            CaptureData::Counter(snapshot) => snapshot
                .kernel_evidence()
                .expect("a presented counter snapshot retains actual kernel evidence"),
        }
    }

    pub(crate) fn has_counter_gap(&self) -> bool {
        self.counter().is_some_and(|snapshot| {
            !snapshot.is_fresh() || snapshot.discontinuity() || !snapshot.bank_gaps().is_clean()
        })
    }

    fn legacy_gaps(&self) -> Option<&LegacyReadGaps> {
        match &self.data {
            CaptureData::Legacy(_, _, gaps) => Some(gaps),
            CaptureData::Counter(_) => None,
        }
    }

    pub(crate) fn has_legacy_gap(&self) -> bool {
        self.legacy_gaps().is_some_and(|gaps| !gaps.is_clean())
    }

    /// Optional legacy gap object for the evidence document: counts and
    /// finite reason names only. Omitted when the legacy read was exact.
    pub(crate) fn legacy_collection(&self) -> Option<serde_json::Value> {
        let gaps = self.legacy_gaps()?;
        if gaps.is_clean() {
            return None;
        }
        Some(serde_json::json!({
            "unread_stats": gaps.slots.unread_stats,
            "rv_failed": gaps.slots.rv_failed,
            "unknown_evidence": gaps.unknown_names(),
        }))
    }

    /// Metadata can only be obtained from this accepted protected snapshot.
    /// A failed new attempt never substitutes its mode/generation/window.
    /// Per-bank gaps appear only when the acquisition was partial; exact
    /// reads omit `bank_gaps` so the full-coverage shape is unchanged.
    pub(crate) fn counter_collection(&self) -> Option<serde_json::Value> {
        let snapshot = self.counter()?;
        let mode = snapshot.mode()?;
        let generation = snapshot.generation()?;
        let mut value = serde_json::json!({
            "mode": mode.name(),
            "generation": generation,
            "read_window": snapshot.window().map(|window| serde_json::json!({
                "started_ns": window.started_ns, "finished_ns": window.finished_ns,
            })),
            "status": if snapshot.is_fresh() { "fresh" } else { "stale" },
            "health": snapshot.health().map(|health| serde_json::json!({
                "saturated": health.saturated, "contended": health.contended,
            })),
            "discontinuity": snapshot.discontinuity(),
            "failure": snapshot.failure().map(CounterFailure::name),
        });
        let bank_gaps = snapshot.bank_gaps();
        if !bank_gaps.is_clean() {
            value
                .as_object_mut()
                .expect("counter collection is an object")
                .insert(
                    "bank_gaps".into(),
                    serde_json::json!({
                        "failed_slots": bank_gaps.failed_slots,
                        "health_failed": bank_gaps.health_failed,
                        "kernel_failed": bank_gaps.kernel_failed,
                    }),
                );
        }
        Some(value)
    }

    pub(crate) fn counter_summary(&self) -> Option<String> {
        let snapshot = self.counter()?;
        let mode = snapshot.mode()?;
        let generation = snapshot.generation()?;
        let status = snapshot.failure().map_or_else(
            || "fresh".to_owned(),
            |failure| format!("stale ({})", failure.name()),
        );
        Some(format!(
            "Counter collection: {}; generation {}; last read {}{}\n",
            mode.name(),
            generation,
            status,
            if snapshot.discontinuity() {
                "; generation changed"
            } else {
                ""
            },
        ))
    }
}

/// The one collection owner shared by live snapshots and final publication.
pub(crate) struct CaptureCollection {
    counter: Option<CounterCapture>,
}

impl CaptureCollection {
    pub(crate) fn new(inputs: Option<CounterCaptureInputs>) -> Self {
        Self {
            counter: inputs
                .map(|inputs| CounterCapture::new(inputs.mode, inputs.limits, inputs.reserve)),
        }
    }

    pub(crate) fn fresh(
        &mut self,
        session: &crate::attach::Session,
        plan: &AttachPlan,
        pins: &PinnedObjects,
        profile: bool,
    ) -> anyhow::Result<CaptureSnapshot> {
        self.acquire(session, plan, pins, profile, false)
    }

    pub(crate) fn terminal(
        &mut self,
        session: &crate::attach::Session,
        plan: &AttachPlan,
        pins: &PinnedObjects,
        profile: bool,
    ) -> anyhow::Result<CaptureSnapshot> {
        self.acquire(session, plan, pins, profile, true)
    }

    fn acquire(
        &mut self,
        session: &crate::attach::Session,
        plan: &AttachPlan,
        pins: &PinnedObjects,
        profile: bool,
        terminal: bool,
    ) -> anyhow::Result<CaptureSnapshot> {
        // A new scoped, opaque binding comes only from actual preparation.
        let binding = session.counter_reader_binding();
        let legacy = || -> anyhow::Result<(Vec<SlotReport>, KernelEvidence, LegacyReadGaps)> {
            // Preserve the existing order of ordinary live/terminal reads.
            if terminal {
                let (reports, slots) = super::read_with_gaps(session, plan)?;
                let kernel = super::kernel_evidence_with_gaps(session)?;
                let gaps = LegacyReadGaps {
                    slots,
                    unknown_evidence: kernel.unknown_cells,
                };
                Ok((reports, kernel, gaps))
            } else {
                let kernel = super::kernel_evidence_with_gaps(session)?;
                let (reports, slots) = super::read_with_gaps(session, plan)?;
                let gaps = LegacyReadGaps {
                    slots,
                    unknown_evidence: kernel.unknown_cells,
                };
                Ok((reports, kernel, gaps))
            }
        };
        if terminal {
            self.terminal_with(
                plan,
                pins,
                profile,
                binding,
                super::counter_reader::read_bound,
                legacy,
                session.counter_collection_generation(),
                || super::kernel_evidence(session),
            )
        } else {
            self.fresh_with(
                plan,
                pins,
                profile,
                binding,
                super::counter_reader::read_bound,
                legacy,
                session.counter_collection_generation(),
                || super::kernel_evidence(session),
            )
        }
    }

    // I/O-only injection stays private. Production callers cannot supply an
    // arbitrary retained read paired with a newly selected plan. The
    // session's collection generation and a kernel-evidence source feed
    // the zero-endpoint bypass, which publishes no bank rows but must
    // still report measured kernel evidence under the real generation.
    #[allow(clippy::too_many_arguments)]
    fn fresh_with<B>(
        &mut self,
        plan: &AttachPlan,
        pins: &PinnedObjects,
        profile: bool,
        binding: Result<Option<B>, crate::attach::counter_banks::BankRefusal>,
        acquire: impl FnOnce(
            B,
            &AttachPlan,
            &PinnedObjects,
            CounterLimits,
            &SemanticResourceReserver,
        ) -> Result<CounterRead, ReadStage>,
        legacy: impl FnOnce() -> anyhow::Result<(Vec<SlotReport>, KernelEvidence, LegacyReadGaps)>,
        generation: NonZeroU64,
        kernel: impl FnOnce() -> anyhow::Result<KernelEvidence>,
    ) -> anyhow::Result<CaptureSnapshot> {
        match binding {
            Ok(None) => {
                if self.counter.is_some() {
                    anyhow::bail!("counter collection requires its prepared Session binding");
                }
                let (reports, mut kernel, mut gaps) = legacy()?;
                if !profile {
                    kernel.ring_loss = 0;
                    kernel.unknown_cells &= !super::LEGACY_UNKNOWN_RING_LOSS;
                    gaps.unknown_evidence = kernel.unknown_cells;
                }
                Ok(CaptureSnapshot {
                    data: CaptureData::Legacy(reports, kernel, gaps),
                    new_acquisition: true,
                })
            }
            binding => {
                if self.counter.is_none() {
                    let failure = match &binding {
                        Err(crate::attach::counter_banks::BankRefusal::Quarantined) => {
                            "bank_quarantined"
                        }
                        Err(_) => "bank_routing",
                        _ => "owner limits and reserver required",
                    };
                    anyhow::bail!("prepared counter collection unavailable ({failure})");
                }
                // Zero endpoints with a healthy binding is a normal capture:
                // nothing to count, nothing stale. Bypass banks and the
                // collector; later growth still starts from no baseline.
                // The bypass still reads kernel evidence: the lifecycle
                // programs are attached, so identity tickets and owner
                // accounting move even with nothing to count. A read
                // error fails loudly instead of publishing zeros.
                if plan.slots.is_empty() && matches!(&binding, Ok(Some(_))) {
                    let counter = self.counter.as_mut().expect("owner inputs checked above");
                    let mode = counter.mode;
                    let discontinuity = counter.discontinuity;
                    let reserve = counter.collector.reserver();
                    let kernel = kernel().map_err(|_| {
                        anyhow::anyhow!("counter collection unavailable (kernel_evidence)")
                    })?;
                    let reservation = ReadReservation::reserve(0, 0, reserve).map_err(|_| {
                        anyhow::anyhow!("counter collection unavailable (read_budget)")
                    })?;
                    let read = CounterRead::new(
                        generation,
                        mode,
                        None,
                        Ok(Vec::new()),
                        CounterHealth::default(),
                        kernel,
                        reservation,
                    )
                    .map_err(|stage| {
                        anyhow::anyhow!(
                            "counter collection unavailable ({})",
                            CounterFailure::Read(stage).name()
                        )
                    })?;
                    let (reports, storage) =
                        stage_projection(plan, pins, &read, reserve).map_err(|failure| {
                            anyhow::anyhow!("counter collection unavailable ({})", failure.name())
                        })?;
                    let snapshot = CounterSnapshot {
                        data: Some(Arc::new(Projection {
                            source: read,
                            reports,
                            observation: CounterObservation::Initial,
                            _storage: storage,
                        })),
                        failure: None,
                        attempted_kernel: Some(kernel),
                        discontinuity,
                        bank_gaps: CounterGaps::default(),
                    };
                    return CaptureSnapshot::from_counter(snapshot);
                }
                let counter = self.counter.as_mut().expect("owner inputs checked above");
                let snapshot =
                    counter.fresh_with(plan, pins, |plan, pins, limits, reserve| match binding {
                        Ok(Some(binding)) => acquire(binding, plan, pins, limits, reserve),
                        Err(crate::attach::counter_banks::BankRefusal::Quarantined) => {
                            Err(ReadStage::BankQuarantined)
                        }
                        Err(_) => Err(ReadStage::BankRouting),
                        Ok(None) => unreachable!("ordinary binding was handled above"),
                    });
                CaptureSnapshot::from_counter(snapshot)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn terminal_with<B>(
        &mut self,
        plan: &AttachPlan,
        pins: &PinnedObjects,
        profile: bool,
        binding: Result<Option<B>, crate::attach::counter_banks::BankRefusal>,
        acquire: impl FnOnce(
            B,
            &AttachPlan,
            &PinnedObjects,
            CounterLimits,
            &SemanticResourceReserver,
        ) -> Result<CounterRead, ReadStage>,
        legacy: impl FnOnce() -> anyhow::Result<(Vec<SlotReport>, KernelEvidence, LegacyReadGaps)>,
        generation: NonZeroU64,
        kernel: impl FnOnce() -> anyhow::Result<KernelEvidence>,
    ) -> anyhow::Result<CaptureSnapshot> {
        // Always acquire, observe and project again. A failed terminal read
        // publishes the last good snapshot as stale with its failure name;
        // only a capture that never acquired a snapshot fails.
        self.fresh_with(
            plan, pins, profile, binding, acquire, legacy, generation, kernel,
        )
    }
}

/// One collector per capture. No projection is reconstructed from a retained
/// baseline and an unrelated newer plan, including on acquisition failure.
/// The requested mode identifies an empty capture that never reads banks.
pub(super) struct CounterCapture {
    mode: CounterMode,
    collector: CounterCollector,
    limits: CounterLimits,
    last: Option<Arc<Projection>>,
    discontinuity: bool,
}

impl CounterCapture {
    pub(super) fn new(
        mode: CounterMode,
        limits: CounterLimits,
        reserve: SemanticResourceReserver,
    ) -> Self {
        Self {
            mode,
            collector: CounterCollector::new(limits, reserve),
            limits,
            last: None,
            discontinuity: false,
        }
    }

    fn failed(
        &self,
        failure: CounterFailure,
        kernel: Option<KernelEvidence>,
        gaps: CounterGaps,
    ) -> CounterSnapshot {
        CounterSnapshot {
            data: self.last.clone(),
            failure: Some(failure),
            attempted_kernel: kernel,
            discontinuity: self.discontinuity,
            bank_gaps: gaps,
        }
    }

    /// The replaceable boundary is native I/O, and is private. Production
    /// reaches it only from the actual prepared Session binding below.
    fn fresh_with(
        &mut self,
        plan: &AttachPlan,
        pins: &PinnedObjects,
        acquire: impl FnOnce(
            &AttachPlan,
            &PinnedObjects,
            CounterLimits,
            &SemanticResourceReserver,
        ) -> Result<CounterRead, ReadStage>,
    ) -> CounterSnapshot {
        let read = match acquire(plan, pins, self.limits, self.collector.reserver()) {
            Ok(read) => read,
            Err(stage) => {
                let _ = self.collector.observe(Err(stage));
                return self.failed(CounterFailure::Read(stage), None, CounterGaps::default());
            }
        };
        let kernel = read.view().kernel;
        let health = read.view().health;
        let gaps = read.view().gaps;
        // Reserve and copy before observe can advance the baseline. Both the
        // acquisition's owned rows and the old displayed view remain charged.
        let (reports, storage) =
            match stage_projection(plan, pins, &read, self.collector.reserver()) {
                Ok(staged) => staged,
                Err(CounterFailure::Collection(_)) => {
                    // Incomplete folded rows still reach the actual collector,
                    // which owns generation high water and sticky issue policy.
                    let observation = self.collector.observe(Ok(read));
                    let failure = match observation {
                        CounterObservation::Unavailable(issue) => CounterFailure::Collection(issue),
                        CounterObservation::ReadFailed(stage) => CounterFailure::Read(stage),
                        _ => unreachable!("invalid folded rows cannot establish a baseline"),
                    };
                    return self.failed(failure.with_observed_health(health), Some(kernel), gaps);
                }
                Err(failure) => {
                    return self.failed(failure.with_observed_health(health), Some(kernel), gaps);
                }
            };
        let observation = self.collector.observe(Ok(read));
        let failure = match &observation {
            CounterObservation::ReadFailed(stage) => Some(CounterFailure::Read(*stage)),
            CounterObservation::Unavailable(issue) => Some(CounterFailure::Collection(*issue)),
            _ => None,
        };
        if let Some(failure) = failure {
            return self.failed(failure.with_observed_health(health), Some(kernel), gaps);
        }
        self.discontinuity |= matches!(observation, CounterObservation::GenerationChanged { .. });
        let source = self
            .collector
            .current()
            .expect("accepted observation has a baseline")
            .clone();
        let data = Arc::new(Projection {
            source,
            reports,
            observation,
            _storage: storage,
        });
        self.last = Some(Arc::clone(&data));
        CounterSnapshot {
            data: Some(data),
            failure: None,
            attempted_kernel: Some(kernel),
            discontinuity: self.discontinuity,
            bank_gaps: gaps,
        }
    }
}

fn stage_projection(
    plan: &AttachPlan,
    pins: &PinnedObjects,
    read: &CounterRead,
    reserve: &SemanticResourceReserver,
) -> Result<(Vec<SlotReport>, ResourceLease), CounterFailure> {
    let view = read.view();
    let rows = view.rows.map_err(CounterFailure::Collection)?;
    let budget = || CounterFailure::Read(ReadStage::Budget);
    let mut bytes = size_of::<Projection>()
        .checked_add(2 * size_of::<usize>() + OWNED_ALLOCATION_PADDING)
        .and_then(|bytes| bytes.checked_add(rows.len().checked_mul(size_of::<SlotReport>())?))
        .and_then(|bytes| bytes.checked_add(OWNED_ALLOCATION_PADDING))
        .ok_or_else(budget)?;
    let mut charge = |amount: usize| -> Result<(), CounterFailure> {
        bytes = bytes.checked_add(amount).ok_or_else(budget)?;
        Ok(())
    };
    for raw in rows {
        let row = raw.view();
        let slot = plan
            .slots
            .get(row.slot as usize)
            .ok_or(CounterFailure::Projection)?;
        let target = AttachKey {
            object: slot.object,
            file_offset: slot.file_offset,
        };
        if row.slot != slot.index || row.target != target || row.mode != view.mode {
            return Err(CounterFailure::Projection);
        }
        if let (Some(expected), Some(actual)) = (
            plan.borrowed_target_object_of(slot),
            pins.summary(slot.object),
        ) {
            let sha256 = (!actual.sha256.is_empty()).then_some(actual.sha256);
            if expected.dev != (actual.key.device.major, actual.key.device.minor)
                || expected.ino != actual.key.inode
                || expected.sha256.as_deref() != sha256
            {
                return Err(CounterFailure::Projection);
            }
        }
        charge(
            slot.names
                .len()
                .checked_mul(size_of::<String>())
                .and_then(|bytes| bytes.checked_add(OWNED_ALLOCATION_PADDING))
                .ok_or_else(budget)?,
        )?;
        for name in &slot.names {
            charge(
                name.len()
                    .checked_add(OWNED_ALLOCATION_PADDING)
                    .ok_or_else(budget)?,
            )?;
        }
        charge(
            plan.ordinal_count(slot)
                .checked_mul(size_of::<SlotOrdinal>())
                .and_then(|bytes| bytes.checked_add(OWNED_ALLOCATION_PADDING))
                .ok_or_else(budget)?,
        )?;
        if let Some(sha256) = plan
            .borrowed_target_object_of(slot)
            .and_then(|target| target.sha256.as_ref())
        {
            charge(
                sha256
                    .len()
                    .checked_add(OWNED_ALLOCATION_PADDING)
                    .ok_or_else(budget)?,
            )?;
        }
        charge(tree_bytes::<u64, u64>(row.rv_counts.len()).ok_or_else(budget)?)?;
    }
    let storage = reserve.reserve(bytes).map_err(|_| budget())?;
    // Fold exec-generation duplicates like the legacy reader: two slots
    // for one function (retired plus armed) report once, summed.
    let mut reports = Vec::with_capacity(rows.len());
    for raw in rows {
        let row = raw.view();
        let slot = plan
            .slots
            .get(row.slot as usize)
            .expect("staging validated the actual row ID");
        let module = plan.module_of_slot(slot.index);
        let module_ambiguous = plan.slot_is_module_ambiguous(slot.index);
        let mut ordinals = Vec::with_capacity(plan.ordinal_count(slot));
        ordinals.extend(plan.borrowed_ordinals_of(slot));
        reports.push(SlotReport {
            names: slot.names.clone(),
            aliased: slot.aliased,
            semantic_authorized: slot.semantic_authorized,
            module,
            module_ambiguous,
            module_unresolved: module.is_none() && !module_ambiguous,
            mode: row.mode,
            calls: row.returned,
            errors: row.errors,
            in_flight: row.entered.saturating_sub(row.returned),
            total_ns: row.total_ns,
            max_ns: row.max_ns,
            buckets: *row.buckets,
            rv_counts: row.rv_counts.clone(),
            file_offset: slot.file_offset,
            target_object: plan.borrowed_target_object_of(slot).cloned(),
            ordinals,
        });
    }
    Ok((crate::metrics::merge_slot_reports(reports), storage))
}

#[cfg(test)]
pub(super) mod tests {
    use super::{
        CaptureCollection, CaptureSnapshot, CounterCapture, CounterCaptureInputs, CounterFailure,
    };
    use crate::discovery::identity::{PinnedObjects, ReconciledModule};
    use crate::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    use crate::metrics::counter_collector::{
        CounterCell, CounterGaps, CounterHealth, CounterIssue, CounterLimits, CounterRead,
        CounterRow, ReadReservation, ReadStage, ReadWindow,
    };
    use crate::metrics::{KernelEvidence, LegacyReadGaps};
    use crate::plan::{AdmissionPolicy, AttachPlan};
    use crate::process::{MountNamespaceId, ProcessViewId};
    use crate::semantics_edge::resources::{SemanticResourcePool, SemanticResourceReserver};
    use p11scope_ebpf_common::{
        CountStats, CounterMode, LATENCY_BUCKETS, RvKey, SlotStats, TimestampStats,
    };
    use sha2::{Digest as _, Sha256};
    use std::io::Write as _;

    const LIMITS: CounterLimits = CounterLimits {
        rows: 2,
        rv_keys: 4,
    };
    const HIGH_RV: u64 = 0x1_0000_0001;

    fn fixture() -> (tempfile::NamedTempFile, AttachPlan, PinnedObjects) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let bytes = format!("owned counter projection {}", file.path().display()).into_bytes();
        file.write_all(&bytes).unwrap();
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        // Existing pin seam retains a real opened file/dev/inode. No native
        // execution is claimed for these controlled cumulative cells.
        let pins =
            crate::discovery::identity::test_fixture::real_scan_pin(file.path(), None, 1, &hash);
        let summary = pins.pinned().next().unwrap();
        let object = summary.id;
        let key = summary.key;
        let path = file.path().to_str().unwrap();
        let module = ReconciledModule {
            object,
            entry_objects: vec![vec![object]],
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
                path: path.into(),
                tables_scan_finished: false,
                decoder_abi: Some(p11scope_manifest::elf::ElfAbi::Lp64),
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
                    live_return: false,
                    manifest_supported: false,
                    extension_impossible: false,
                }],
                interfaces: vec![],
            },
        };
        let plan = crate::plan::build_from_sources_for_policy(
            &[module],
            &[],
            &pins,
            AdmissionPolicy::counters(crate::capacity::CounterBudget::new(2).unwrap()),
        );
        assert_eq!(plan.slots.len(), 1);
        (file, plan, pins)
    }

    fn read(
        plan: &AttachPlan,
        mode: CounterMode,
        generation: u64,
        returned: u64,
        reserve: &SemanticResourceReserver,
    ) -> CounterRead {
        read_with_health(
            plan,
            mode,
            generation,
            returned,
            CounterHealth::default(),
            KernelEvidence::default(),
            reserve,
        )
    }

    fn read_with_health(
        plan: &AttachPlan,
        mode: CounterMode,
        generation: u64,
        returned: u64,
        health: CounterHealth,
        kernel: KernelEvidence,
        reserve: &SemanticResourceReserver,
    ) -> CounterRead {
        let reservation = ReadReservation::reserve(1, 2, reserve).unwrap();
        let slot = &plan.slots[0];
        let rvs = [
            (
                RvKey {
                    slot: slot.index,
                    _pad: 0,
                    rv: 0,
                },
                returned - 2,
            ),
            (
                RvKey {
                    slot: slot.index,
                    _pad: 0,
                    rv: HIGH_RV,
                },
                2,
            ),
        ];
        let row = match mode {
            CounterMode::Counts => CounterRow::fold(
                slot,
                mode,
                [CounterCell::Counts(&CountStats {
                    entered: returned + 1,
                    returned,
                    errors: 2,
                })],
                rvs,
                LIMITS,
            ),
            CounterMode::Timestamps => CounterRow::fold(
                slot,
                mode,
                [CounterCell::Timestamps(&TimestampStats {
                    entered: returned + 1,
                    returned,
                    errors: 2,
                    total_ns: returned * 100,
                    max_ns: 100,
                })],
                rvs,
                LIMITS,
            ),
            CounterMode::Latency => {
                let mut buckets = [0; LATENCY_BUCKETS];
                buckets[p11scope_ebpf_common::bucket_of(100) as usize] = returned;
                CounterRow::fold(
                    slot,
                    mode,
                    [CounterCell::Latency(&SlotStats {
                        entered: returned + 1,
                        returned,
                        errors: 2,
                        total_ns: returned * 100,
                        max_ns: 100,
                        buckets,
                    })],
                    rvs,
                    LIMITS,
                )
            }
        }
        .unwrap();
        let rows = vec![row];
        CounterRead::new(
            std::num::NonZeroU64::new(generation).unwrap(),
            mode,
            ReadWindow::new(Some(10), Some(20)),
            Ok(rows),
            health,
            kernel,
            reservation,
        )
        .unwrap()
    }

    #[derive(Clone, Copy)]
    pub(crate) enum ConsumerFault {
        ReadRvs,
        RowTopology,
        RowTopologySaturated,
        RowTopologyContended,
        RowTopologySaturatedContended,
        Saturated,
        Contended,
        KernelLoss,
        BankGaps,
        BankQuarantined,
    }

    /// The run-loop tests replace I/O only: every successful acquisition still
    /// folds real typed cells and passes through the actual charged collector.
    pub(crate) struct ConsumerFixture {
        _file: tempfile::NamedTempFile,
        plan: AttachPlan,
        pins: PinnedObjects,
        collection: CaptureCollection,
        native_reads: std::cell::Cell<usize>,
        legacy_reads: std::cell::Cell<usize>,
    }

    impl ConsumerFixture {
        pub(crate) fn ordinary_snapshot(profile: bool) -> CaptureSnapshot {
            let (_file, plan, pins) = fixture();
            CaptureCollection::new(None)
                .fresh_with(
                    &plan,
                    &pins,
                    profile,
                    Ok(None::<()>),
                    |(), _, _, _, _| panic!("ordinary snapshot cannot acquire counters"),
                    || {
                        Ok((
                            Vec::new(),
                            KernelEvidence::default(),
                            LegacyReadGaps::default(),
                        ))
                    },
                    std::num::NonZeroU64::new(1).unwrap(),
                    || Ok(KernelEvidence::default()),
                )
                .unwrap()
        }

        pub(crate) fn new() -> Self {
            let (file, plan, pins) = fixture();
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            Self {
                _file: file,
                plan,
                pins,
                collection: CaptureCollection::new(Some(CounterCaptureInputs::new(
                    CounterMode::Counts,
                    LIMITS.rows,
                    LIMITS.rv_keys,
                    pool.reserver(),
                ))),
                native_reads: std::cell::Cell::new(0),
                legacy_reads: std::cell::Cell::new(0),
            }
        }

        pub(crate) fn reads(&self) -> (usize, usize) {
            (self.native_reads.get(), self.legacy_reads.get())
        }

        pub(crate) fn fresh(
            &mut self,
            mode: CounterMode,
            generation: u64,
            returned: u64,
            fault: Option<ConsumerFault>,
        ) -> anyhow::Result<CaptureSnapshot> {
            self.snapshot(mode, generation, returned, fault, false)
        }

        pub(crate) fn terminal(
            &mut self,
            mode: CounterMode,
            generation: u64,
            returned: u64,
            fault: Option<ConsumerFault>,
        ) -> anyhow::Result<CaptureSnapshot> {
            self.snapshot(mode, generation, returned, fault, true)
        }

        fn snapshot(
            &mut self,
            mode: CounterMode,
            generation: u64,
            returned: u64,
            fault: Option<ConsumerFault>,
            terminal: bool,
        ) -> anyhow::Result<CaptureSnapshot> {
            let native_reads = &self.native_reads;
            let legacy_reads = &self.legacy_reads;
            let acquire = |(),
                           plan: &AttachPlan,
                           _: &PinnedObjects,
                           _,
                           reserve: &SemanticResourceReserver| {
                native_reads.set(native_reads.get() + 1);
                match fault {
                    Some(ConsumerFault::ReadRvs) => Err(ReadStage::Rvs),
                    Some(ConsumerFault::BankGaps) => {
                        let mut read = read_with_health(
                            plan,
                            mode,
                            generation,
                            returned,
                            CounterHealth::default(),
                            KernelEvidence::default(),
                            reserve,
                        );
                        read.set_gaps(CounterGaps {
                            failed_slots: 1,
                            health_failed: false,
                            kernel_failed: false,
                        });
                        Ok(read)
                    }
                    Some(ConsumerFault::BankQuarantined) => CounterRead::new(
                        std::num::NonZeroU64::new(generation).unwrap(),
                        mode,
                        ReadWindow::new(Some(30), Some(40)),
                        Err(CounterIssue::BankQuarantined),
                        CounterHealth::default(),
                        KernelEvidence::default(),
                        ReadReservation::reserve(0, 0, reserve).unwrap(),
                    ),
                    Some(
                        ConsumerFault::RowTopology
                        | ConsumerFault::RowTopologySaturated
                        | ConsumerFault::RowTopologyContended
                        | ConsumerFault::RowTopologySaturatedContended,
                    ) => CounterRead::new(
                        std::num::NonZeroU64::new(generation).unwrap(),
                        mode,
                        ReadWindow::new(Some(30), Some(40)),
                        Err(CounterIssue::Topology),
                        CounterHealth {
                            saturated: matches!(
                                fault,
                                Some(
                                    ConsumerFault::RowTopologySaturated
                                        | ConsumerFault::RowTopologySaturatedContended
                                )
                            ),
                            contended: matches!(
                                fault,
                                Some(
                                    ConsumerFault::RowTopologyContended
                                        | ConsumerFault::RowTopologySaturatedContended
                                )
                            ),
                        },
                        KernelEvidence::default(),
                        ReadReservation::reserve(0, 0, reserve).unwrap(),
                    ),
                    _ => Ok(read_with_health(
                        plan,
                        mode,
                        generation,
                        returned,
                        CounterHealth {
                            saturated: matches!(fault, Some(ConsumerFault::Saturated)),
                            contended: matches!(fault, Some(ConsumerFault::Contended)),
                        },
                        if matches!(fault, Some(ConsumerFault::KernelLoss)) {
                            KernelEvidence {
                                ring_loss: 7,
                                start_insert_failures: 3,
                                ..Default::default()
                            }
                        } else {
                            KernelEvidence::default()
                        },
                        reserve,
                    )),
                }
            };
            let legacy = || {
                legacy_reads.set(legacy_reads.get() + 1);
                anyhow::bail!("counter consumer must not use the legacy reader")
            };
            if terminal {
                self.collection.terminal_with(
                    &self.plan,
                    &self.pins,
                    false,
                    Ok(Some(())),
                    acquire,
                    legacy,
                    std::num::NonZeroU64::new(generation).unwrap(),
                    || Ok(KernelEvidence::default()),
                )
            } else {
                self.collection.fresh_with(
                    &self.plan,
                    &self.pins,
                    false,
                    Ok(Some(())),
                    acquire,
                    legacy,
                    std::num::NonZeroU64::new(generation).unwrap(),
                    || Ok(KernelEvidence::default()),
                )
            }
        }

        pub(crate) fn delta(snapshot: &CaptureSnapshot) -> Option<u64> {
            snapshot.counter()?.deltas().map(|rows| rows[0].returned)
        }

        pub(crate) fn terminal_eligible(snapshot: &CaptureSnapshot) -> bool {
            snapshot.new_acquisition && snapshot.counter().is_some_and(|counter| counter.is_fresh())
        }
    }

    /// Two exec generations of one function fold to one aggregate row
    /// in counter projections too, not just the legacy reader: same
    /// names, file and offset sum their counters instead of printing
    /// twice.
    #[test]
    fn projection_folds_duplicate_function_rows_across_generations() {
        let (_file, plan, pins) = fixture();
        let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
        let reserve = pool.reserver();
        let slot = &plan.slots[0];
        let row = |returned: u64| {
            CounterRow::fold(
                slot,
                CounterMode::Counts,
                [CounterCell::Counts(&CountStats {
                    entered: returned + 1,
                    returned,
                    errors: 1,
                })],
                [(
                    RvKey {
                        slot: slot.index,
                        _pad: 0,
                        rv: 0,
                    },
                    returned,
                )],
                LIMITS,
            )
            .unwrap()
        };
        let rows = vec![row(10), row(20)];
        let reservation = ReadReservation::reserve(2, 2, &reserve).unwrap();
        let read = CounterRead::new(
            std::num::NonZeroU64::new(1).unwrap(),
            CounterMode::Counts,
            ReadWindow::new(Some(10), Some(20)),
            Ok(rows),
            CounterHealth::default(),
            KernelEvidence::default(),
            reservation,
        )
        .unwrap();
        let (reports, _lease) = super::stage_projection(&plan, &pins, &read, &reserve).unwrap();
        assert_eq!(reports.len(), 1, "two generations fold to one row");
        assert_eq!(reports[0].calls, 30);
    }

    #[test]
    fn consumer_selection_uses_prepared_presence_and_never_falls_back_on_refusal() {
        use crate::attach::counter_banks::{BankRefusal, BankShapeCause};
        let (_file, plan, pins) = fixture();
        for binding in [
            Err(BankRefusal::Quarantined),
            // Representative cause; this mock input is cause-agnostic by
            // design (any shape refusal must refuse without fallback).
            Err(BankRefusal::Shape(BankShapeCause::BindingGeometryChanged)),
            Ok(Some(())),
        ] {
            let mut collection = CaptureCollection::new(None);
            let result = collection.fresh_with(
                &plan,
                &pins,
                false,
                binding,
                |(), _, _, _, _| panic!("absent owner inputs must refuse before native reads"),
                || panic!("present or refused counters must not fall back to legacy"),
                std::num::NonZeroU64::new(1).unwrap(),
                || Ok(KernelEvidence::default()),
            );
            assert!(result.is_err());
        }
        let mut fixture = ConsumerFixture::new();
        fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
        let stale = fixture
            .collection
            .fresh_with(
                &fixture.plan,
                &fixture.pins,
                false,
                Err::<Option<()>, _>(BankRefusal::Quarantined),
                |(), _, _, _, _| panic!("refused binding cannot read"),
                || panic!("refused binding cannot fall back"),
                std::num::NonZeroU64::new(1).unwrap(),
                || Ok(KernelEvidence::default()),
            )
            .unwrap();
        assert_eq!(stale.reports()[0].calls, 5);
        assert_eq!(
            stale.counter_collection().unwrap()["failure"],
            "bank_quarantined"
        );
        assert!(
            fixture
                .collection
                .fresh_with(
                    &fixture.plan,
                    &fixture.pins,
                    false,
                    Ok(None::<()>),
                    |(), _, _, _, _| panic!("no binding cannot read counters"),
                    || panic!("a counter capture cannot switch to legacy"),
                    std::num::NonZeroU64::new(1).unwrap(),
                    || Ok(KernelEvidence::default()),
                )
                .is_err()
        );
    }

    #[test]
    fn consumer_ordinary_metrics_and_profile_preserve_legacy_health() {
        let (_file, plan, pins) = fixture();
        for profile in [false, true] {
            let mut collection = CaptureCollection::new(None);
            let snapshot = collection
                .fresh_with(
                    &plan,
                    &pins,
                    profile,
                    Ok(None::<()>),
                    |(), _, _, _, _| panic!("ordinary Session must not use counter reader"),
                    || {
                        Ok((
                            Vec::new(),
                            KernelEvidence {
                                ring_loss: 7,
                                unmatched_returns: 3,
                                ..Default::default()
                            },
                            LegacyReadGaps::default(),
                        ))
                    },
                    std::num::NonZeroU64::new(1).unwrap(),
                    || Ok(KernelEvidence::default()),
                )
                .unwrap();
            assert!(snapshot.counter_collection().is_none());
            assert_eq!(
                snapshot.kernel_evidence().ring_loss,
                if profile { 7 } else { 0 }
            );
            assert_eq!(snapshot.kernel_evidence().unmatched_returns, 3);
        }
    }

    #[test]
    fn legacy_gaps_publish_partial_with_named_reasons() {
        use crate::metrics::{LEGACY_UNKNOWN_OWNER, LEGACY_UNKNOWN_RING_LOSS};
        let (_file, plan, pins) = fixture();
        let mut collection = CaptureCollection::new(None);
        let snapshot = collection
            .fresh_with(
                &plan,
                &pins,
                true,
                Ok(None::<()>),
                |(), _, _, _, _| panic!("ordinary Session must not use counter reader"),
                || {
                    Ok((
                        Vec::new(),
                        KernelEvidence {
                            unknown_cells: LEGACY_UNKNOWN_RING_LOSS | LEGACY_UNKNOWN_OWNER,
                            ..Default::default()
                        },
                        LegacyReadGaps {
                            slots: crate::metrics::LegacySlotGaps {
                                unread_stats: 2,
                                rv_failed: true,
                            },
                            unknown_evidence: LEGACY_UNKNOWN_RING_LOSS | LEGACY_UNKNOWN_OWNER,
                        },
                    ))
                },
                std::num::NonZeroU64::new(1).unwrap(),
                || Ok(KernelEvidence::default()),
            )
            .unwrap();
        assert!(snapshot.has_legacy_gap());
        assert!(!snapshot.has_counter_gap());
        assert!(snapshot.counter_collection().is_none());
        let gaps = snapshot.legacy_collection().unwrap();
        assert_eq!(gaps["unread_stats"], 2);
        assert_eq!(gaps["rv_failed"], true);
        assert_eq!(
            gaps["unknown_evidence"],
            serde_json::json!(["ring_loss", "owner"])
        );
        let mut evidence = crate::render::tests::evidence();
        evidence.verdict();
        assert_eq!(evidence.completeness, "COMPLETE");
        crate::render::apply_legacy_gaps(&mut evidence, &snapshot);
        assert_eq!(evidence.completeness, "PARTIAL");
        assert!(
            evidence
                .gap_classes
                .observation
                .causes
                .contains(&"legacy_collection"),
            "{:?}",
            evidence.gap_classes.observation.causes
        );
        let document =
            crate::render::with_legacy_snapshot(serde_json::json!({"evidence": {}}), &snapshot);
        assert_eq!(document["evidence"]["legacy_collection"], gaps);
    }

    #[test]
    fn legacy_exact_omits_gaps_and_stays_complete() {
        let (_file, plan, pins) = fixture();
        let mut collection = CaptureCollection::new(None);
        let snapshot = collection
            .fresh_with(
                &plan,
                &pins,
                true,
                Ok(None::<()>),
                |(), _, _, _, _| panic!("ordinary Session must not use counter reader"),
                || {
                    Ok((
                        Vec::new(),
                        KernelEvidence::default(),
                        LegacyReadGaps::default(),
                    ))
                },
                std::num::NonZeroU64::new(1).unwrap(),
                || Ok(KernelEvidence::default()),
            )
            .unwrap();
        assert!(!snapshot.has_legacy_gap());
        assert!(snapshot.legacy_collection().is_none());
        let mut evidence = crate::render::tests::evidence();
        evidence.verdict();
        crate::render::apply_legacy_gaps(&mut evidence, &snapshot);
        assert_eq!(evidence.completeness, "COMPLETE");
        assert!(
            !evidence
                .gap_classes
                .observation
                .causes
                .contains(&"legacy_collection"),
            "{:?}",
            evidence.gap_classes.observation.causes
        );
        let document =
            crate::render::with_legacy_snapshot(serde_json::json!({"evidence": {}}), &snapshot);
        assert!(document["evidence"].get("legacy_collection").is_none());
    }

    #[test]
    fn counter_bank_gaps_publish_partial_with_named_counts() {
        use p11scope_ebpf_common::CounterMode;
        let mut fixture = ConsumerFixture::new();
        fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
        let stale = fixture
            .fresh(CounterMode::Counts, 1, 9, Some(ConsumerFault::BankGaps))
            .expect("bank gaps must publish stale with named counts");
        assert_eq!(stale.reports()[0].calls, 5);
        assert!(stale.has_counter_gap());
        let gaps = stale.counter_collection().unwrap();
        assert_eq!(gaps["status"], "stale");
        assert_eq!(gaps["failure"], "topology");
        assert_eq!(gaps["bank_gaps"]["failed_slots"], 1);
        assert_eq!(gaps["bank_gaps"]["health_failed"], false);
        assert_eq!(gaps["bank_gaps"]["kernel_failed"], false);
        let mut evidence = crate::render::tests::evidence();
        evidence.verdict();
        crate::render::apply_counter_snapshot(&mut evidence, &stale);
        assert_eq!(evidence.completeness, "PARTIAL");
    }

    #[test]
    fn quarantined_bank_publishes_last_good_stale_with_named_failure() {
        // A quarantined or misrouted bank voids every bank: quarantine is
        // a directory-global integrity refusal with no per-bank surface,
        // so the capture publishes last-good stale with the named
        // failure instead of blanking. Per-bank quarantine partition
        // needs the bank-authority surface and stays deferred.
        use p11scope_ebpf_common::CounterMode;
        let mut fixture = ConsumerFixture::new();
        fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
        let stale = fixture
            .fresh(
                CounterMode::Counts,
                1,
                9,
                Some(ConsumerFault::BankQuarantined),
            )
            .expect("a quarantined bank must publish stale, never blank");
        assert_eq!(stale.reports()[0].calls, 5);
        assert!(stale.has_counter_gap());
        let collection = stale.counter_collection().unwrap();
        assert_eq!(collection["status"], "stale");
        assert_eq!(collection["failure"], "bank_quarantined");
        assert!(collection.get("bank_gaps").is_none());
        let mut evidence = crate::render::tests::evidence();
        evidence.verdict();
        crate::render::apply_counter_snapshot(&mut evidence, &stale);
        assert_eq!(evidence.completeness, "PARTIAL");
    }

    #[test]
    fn counter_exact_omits_bank_gaps_and_stays_complete() {
        use p11scope_ebpf_common::CounterMode;
        let mut fixture = ConsumerFixture::new();
        let fresh = fixture
            .fresh(CounterMode::Counts, 1, 5, None)
            .expect("exact reads stay exact");
        assert!(!fresh.has_counter_gap());
        let gaps = fresh.counter_collection().unwrap();
        assert_eq!(gaps["status"], "fresh");
        assert!(gaps.get("bank_gaps").is_none());
        let mut evidence = crate::render::tests::evidence();
        evidence.verdict();
        crate::render::apply_counter_snapshot(&mut evidence, &fresh);
        assert_eq!(evidence.completeness, "COMPLETE");
    }

    #[test]
    fn consumer_mixed_row_failure_preserves_observed_health_and_collector_cause() {
        for (fault, cause) in [
            (ConsumerFault::RowTopology, "topology"),
            (ConsumerFault::RowTopologySaturated, "saturated"),
            (ConsumerFault::RowTopologyContended, "contended"),
            (ConsumerFault::RowTopologySaturatedContended, "saturated"),
        ] {
            let mut fixture = ConsumerFixture::new();
            fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
            let stale = fixture
                .fresh(CounterMode::Timestamps, 2, 8, Some(fault))
                .unwrap();
            let metadata = stale.counter_collection().unwrap();
            assert_eq!(metadata["failure"], cause);
            assert!(metadata["health"].is_null());
            assert_eq!(metadata["mode"], "counts");
            assert_eq!(metadata["generation"], 1);
            assert_eq!(stale.reports()[0].calls, 5);
            // Presentation priority did not rewrite the read given to the
            // actual collector: its original Topology refusal stays sticky.
            let next = fixture.fresh(CounterMode::Timestamps, 2, 9, None).unwrap();
            assert_eq!(next.counter_collection().unwrap()["failure"], "topology");
            assert_eq!(next.reports()[0].calls, 5);
            assert!(!ConsumerFixture::terminal_eligible(&next));
        }
    }

    #[test]
    fn projection_uses_actual_modes_cumulative_counts_and_full_width_rvs() {
        let (_file, plan, pins) = fixture();
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            let mut capture = CounterCapture::new(CounterMode::Counts, LIMITS, pool.reserver());
            let snapshot = capture.fresh_with(
                &plan,
                &pins,
                |same_plan: &AttachPlan,
                 same_pins: &PinnedObjects,
                 _: CounterLimits,
                 reserve: &SemanticResourceReserver| {
                    assert!(std::ptr::eq(same_plan, &plan));
                    assert!(std::ptr::eq(same_pins, &pins));
                    Ok(read(same_plan, mode, 1, 5, reserve))
                },
            );
            assert!(snapshot.is_fresh());
            assert!(snapshot.has_data());
            assert_eq!(snapshot.mode(), Some(mode));
            assert_eq!(snapshot.generation(), Some(1));
            assert_eq!(snapshot.window(), ReadWindow::new(Some(10), Some(20)));
            assert_eq!(snapshot.health(), Some(CounterHealth::default()));
            let rows = snapshot.reports();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].mode, mode);
            assert_eq!(
                (rows[0].calls, rows[0].errors, rows[0].in_flight),
                (5, 2, 1)
            );
            assert_eq!(rows[0].rv_counts[&HIGH_RV], 2);
            assert_eq!(rows[0].rv_counts[&0], 3);
            assert_eq!(rows[0].ordinals, plan.ordinals_of(&plan.slots[0]));
            assert_eq!(rows[0].target_object, plan.target_object_of(&plan.slots[0]));
            assert_eq!(rows[0].total_ns, if mode.has_timing() { 500 } else { 0 });
        }
    }

    #[test]
    fn projection_reports_timing_and_buckets_per_mode_with_counts_nulls() {
        let (_file, plan, pins) = fixture();
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            let mut capture = CounterCapture::new(CounterMode::Counts, LIMITS, pool.reserver());
            let snapshot = capture.fresh_with(
                &plan,
                &pins,
                |same_plan: &AttachPlan,
                 same_pins: &PinnedObjects,
                 _: CounterLimits,
                 reserve: &SemanticResourceReserver| {
                    assert!(std::ptr::eq(same_plan, &plan));
                    assert!(std::ptr::eq(same_pins, &pins));
                    Ok(read(same_plan, mode, 1, 5, reserve))
                },
            );
            assert!(snapshot.is_fresh());
            let rows = snapshot.reports();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].mode, mode);
            assert_eq!(rows[0].total_ns, if mode.has_timing() { 500 } else { 0 });
            assert_eq!(rows[0].max_ns, if mode.has_timing() { 100 } else { 0 });
            if mode.has_histogram() {
                assert_eq!(
                    rows[0].buckets[p11scope_ebpf_common::bucket_of(100) as usize],
                    5
                );
                assert_eq!(rows[0].buckets.iter().sum::<u64>(), 5);
            } else {
                assert!(rows[0].buckets.iter().all(|&value| value == 0));
            }
        }
    }

    #[test]
    fn authoritative_published_rows_skip_holes_and_keep_inactive_history() {
        let (_file, first_plan, pins) = fixture();
        let slots = (0..3)
            .map(|index| {
                let mut slot = first_plan.slots[0].clone();
                slot.index = index;
                slot.file_offset = 0x10 + u64::from(index) * 0x10;
                slot
            })
            .collect();
        let mut plan = AttachPlan::from_slots_with_policy(
            slots,
            AdmissionPolicy::counters(crate::capacity::CounterBudget::new(4).unwrap()),
        )
        .unwrap();
        plan.deactivate(0);
        plan.deactivate(1);
        let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
        let mut capture = CounterCapture::new(CounterMode::Counts, LIMITS, pool.reserver());
        let published = |positions: &[(u32, u64)], reserve: &SemanticResourceReserver| {
            let reservation =
                ReadReservation::reserve(positions.len(), positions.len(), reserve).unwrap();
            let mut rows = Vec::with_capacity(positions.len());
            for &(index, returned) in positions {
                let slot = &plan.slots[index as usize];
                rows.push(
                    CounterRow::fold(
                        slot,
                        CounterMode::Counts,
                        [CounterCell::Counts(&CountStats {
                            entered: returned,
                            returned,
                            errors: 0,
                        })],
                        [(
                            RvKey {
                                slot: index,
                                _pad: 0,
                                rv: 0,
                            },
                            returned,
                        )],
                        LIMITS,
                    )
                    .unwrap(),
                );
            }
            CounterRead::new(
                std::num::NonZeroU64::new(1).unwrap(),
                CounterMode::Counts,
                ReadWindow::new(Some(10), Some(20)),
                Ok(rows),
                CounterHealth::default(),
                KernelEvidence::default(),
                reservation,
            )
            .unwrap()
        };
        let first = capture.fresh_with(&plan, &pins, |_, _, _, reserve| {
            Ok(published(&[(0, 5)], reserve))
        });
        assert_eq!(first.reports().len(), 1);
        let grown = capture.fresh_with(&plan, &pins, |_, _, _, reserve| {
            Ok(published(&[(0, 6), (2, 8)], reserve))
        });
        assert!(grown.is_fresh());
        assert_eq!(
            grown
                .reports()
                .iter()
                .map(|row| (row.file_offset, row.calls))
                .collect::<Vec<_>>(),
            [(0x10, 6), (0x30, 8)]
        );
        let deltas = grown.deltas().unwrap();
        assert_eq!(
            deltas
                .iter()
                .map(|delta| (delta.slot, delta.returned))
                .collect::<Vec<_>>(),
            [(0, 1), (2, 8)]
        );
        assert!(!plan.is_active(0));
        assert_eq!(
            plan.slots.len(),
            3,
            "never-published hole1 remains part of the historical plan"
        );
    }

    #[test]
    fn failed_fresh_read_never_relabels_old_projection_from_a_foreign_plan() {
        let (_old_file, old_plan, old_pins) = fixture();
        let (_foreign_file, foreign_plan, foreign_pins) = fixture();
        assert_eq!(old_plan.slots[0].object, foreign_plan.slots[0].object);
        assert_ne!(
            old_plan.target_object_of(&old_plan.slots[0]),
            foreign_plan.target_object_of(&foreign_plan.slots[0])
        );
        let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
        let mut capture = CounterCapture::new(CounterMode::Counts, LIMITS, pool.reserver());
        let old = capture.fresh_with(&old_plan, &old_pins, |plan, _, _, reserve| {
            Ok(read(plan, CounterMode::Counts, 1, 5, reserve))
        });
        let failed = capture.fresh_with(&foreign_plan, &foreign_pins, |_, _, _, _| {
            Err(ReadStage::Stats)
        });
        assert!(!failed.is_fresh());
        assert_eq!(failed.health(), None);
        assert_eq!(
            failed.failure(),
            Some(CounterFailure::Read(ReadStage::Stats))
        );
        assert_eq!(failed.reports(), old.reports());
        assert_eq!(
            failed.reports()[0].target_object,
            old_plan.target_object_of(&old_plan.slots[0])
        );
        assert_ne!(
            failed.reports()[0].target_object,
            foreign_plan.target_object_of(&foreign_plan.slots[0])
        );
        let replacement =
            capture.fresh_with(&foreign_plan, &foreign_pins, |plan, _, _, reserve| {
                Ok(read(plan, CounterMode::Counts, 2, 9, reserve))
            });
        assert!(replacement.is_fresh());
        assert!(replacement.discontinuity());
        assert_eq!(replacement.reports()[0].calls, 9);
        assert_eq!(
            replacement.reports()[0].target_object,
            foreign_plan.target_object_of(&foreign_plan.slots[0])
        );
    }

    #[test]
    fn projection_refusal_does_not_advance_the_actual_collector_baseline() {
        let (_file, plan, pins) = fixture();
        let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
        let mut capture = CounterCapture::new(CounterMode::Counts, LIMITS, pool.reserver());
        let first = capture.fresh_with(&plan, &pins, |plan, _, _, reserve| {
            Ok(read(plan, CounterMode::Latency, 1, 5, reserve))
        });
        let next = read(&plan, CounterMode::Latency, 1, 8, &pool.reserver());
        pool.reference_set_limit(pool.snapshot().charged_bytes);
        let failed = capture.fresh_with(&plan, &pins, |_, _, _, _| Ok(next));
        assert_eq!(
            failed.failure(),
            Some(CounterFailure::Read(ReadStage::Budget))
        );
        assert_eq!(failed.reports(), first.reports());
        pool.reference_set_limit(32 * 1024 * 1024);
        let recovered = capture.fresh_with(&plan, &pins, |plan, _, _, reserve| {
            Ok(read(plan, CounterMode::Latency, 1, 10, reserve))
        });
        assert!(recovered.is_fresh());
        assert_eq!(recovered.reports()[0].calls, 10);
        assert_eq!(recovered.deltas().unwrap()[0].returned, 5);
    }

    #[test]
    fn projection_clones_keep_source_and_delta_charges_until_the_last_view_drops() {
        let (_file, plan, pins) = fixture();
        let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
        let baseline = pool.snapshot().charged_bytes;
        let mut capture = CounterCapture::new(CounterMode::Counts, LIMITS, pool.reserver());
        drop(capture.fresh_with(&plan, &pins, |plan, _, _, reserve| {
            Ok(read(plan, CounterMode::Counts, 1, 5, reserve))
        }));
        let current = capture.fresh_with(&plan, &pins, |plan, _, _, reserve| {
            Ok(read(plan, CounterMode::Counts, 1, 8, reserve))
        });
        let charged = pool.snapshot().charged_bytes;
        assert!(
            charged > baseline,
            "the retained projection has an actual charge"
        );
        let held = current.clone();
        assert_eq!(pool.snapshot().charged_bytes, charged);
        drop(capture);
        drop(current);
        assert_eq!(pool.snapshot().charged_bytes, charged);
        assert_eq!(held.reports()[0].calls, 8);
        assert_eq!(held.deltas().unwrap()[0].returned, 3);
        drop(held);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn initial_unavailable_read_never_fabricates_zero_or_kernel_measurements() {
        let (_file, plan, pins) = fixture();
        let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
        let baseline = pool.snapshot().charged_bytes;
        let mut capture = CounterCapture::new(CounterMode::Counts, LIMITS, pool.reserver());
        let snapshot =
            capture.fresh_with(&plan, &pins, |_, _, _, _| Err(ReadStage::KernelEvidence));
        assert!(!snapshot.is_fresh());
        assert!(snapshot.reports().is_empty());
        assert_eq!(snapshot.mode(), None);
        assert_eq!(snapshot.generation(), None);
        assert_eq!(snapshot.kernel_evidence(), None);
        assert_eq!(
            snapshot.failure(),
            Some(CounterFailure::Read(ReadStage::KernelEvidence))
        );
        drop(snapshot);
        drop(capture);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn counter_empty_capture_reports_fresh_empty_for_all_modes() {
        use std::cell::Cell;
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let plan = AttachPlan::from_slots_with_policy(
                vec![],
                AdmissionPolicy::counters(crate::capacity::CounterBudget::new(512).unwrap()),
            )
            .unwrap();
            assert!(plan.slots.is_empty());
            let pins = PinnedObjects::empty();
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            let baseline = pool.snapshot().charged_bytes;
            let mut collection = CaptureCollection::new(Some(CounterCaptureInputs::new(
                mode,
                LIMITS.rows,
                LIMITS.rv_keys,
                pool.reserver(),
            )));
            let calls = Cell::new(0);
            let fresh = collection
                .fresh_with(
                    &plan,
                    &pins,
                    false,
                    Ok(Some(())),
                    |(), _, _, _, _| {
                        calls.set(calls.get() + 1);
                        Err(ReadStage::BankRouting)
                    },
                    || panic!("empty counter must not use legacy"),
                    std::num::NonZeroU64::new(1).unwrap(),
                    || Ok(KernelEvidence::default()),
                )
                .expect("unstaged empty counter fresh succeeds");
            assert_eq!(calls.get(), 0, "empty bypasses bank reads");
            assert!(fresh.reports().is_empty());
            let terminal = collection
                .terminal_with(
                    &plan,
                    &pins,
                    false,
                    Ok(Some(())),
                    |(), _, _, _, _| {
                        calls.set(calls.get() + 1);
                        Err(ReadStage::BankRouting)
                    },
                    || panic!("empty counter must not use legacy"),
                    std::num::NonZeroU64::new(1).unwrap(),
                    || Ok(KernelEvidence::default()),
                )
                .expect("unstaged empty counter terminal succeeds");
            assert_eq!(calls.get(), 0, "empty bypasses bank reads");
            assert!(terminal.reports().is_empty());
            let metadata = terminal
                .counter_collection()
                .expect("empty carries collection");
            assert_eq!(metadata["mode"], mode.name());
            assert_eq!(metadata["status"], "fresh");
            assert!(metadata["failure"].is_null());
            assert_eq!(metadata["health"]["saturated"], false);
            assert_eq!(metadata["health"]["contended"], false);
            assert_eq!(metadata["discontinuity"], false);
            assert!(metadata["generation"].as_u64().is_some_and(|g| g >= 1));
            assert!(metadata["read_window"].is_null());
            assert!(terminal.counter().is_some_and(|c| c.is_fresh()));
            drop(fresh);
            drop(terminal);
            drop(collection);
            assert_eq!(pool.snapshot().charged_bytes, baseline);
        }
    }

    #[test]
    fn counter_empty_capture_preserves_real_failures() {
        use crate::attach::counter_banks::BankRefusal;
        let empty_plan = || {
            AttachPlan::from_slots_with_policy(
                vec![],
                AdmissionPolicy::counters(crate::capacity::CounterBudget::new(512).unwrap()),
            )
            .unwrap()
        };
        // Empty with a quarantined binding still errors (no masking).
        {
            let plan = empty_plan();
            let pins = PinnedObjects::empty();
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            let mut collection = CaptureCollection::new(Some(CounterCaptureInputs::new(
                CounterMode::Counts,
                LIMITS.rows,
                LIMITS.rv_keys,
                pool.reserver(),
            )));
            assert!(
                collection
                    .terminal_with(
                        &plan,
                        &pins,
                        false,
                        Err::<Option<()>, _>(BankRefusal::Quarantined),
                        |(), _, _, _, _| panic!("quarantined must not read"),
                        || panic!("quarantined must not use legacy"),
                        std::num::NonZeroU64::new(1).unwrap(),
                        || Ok(KernelEvidence::default()),
                    )
                    .is_err()
            );
        }
        // Non-empty with bank routing still errors (no fabrication).
        {
            let (_file, plan, pins) = fixture();
            assert!(!plan.slots.is_empty());
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            let mut collection = CaptureCollection::new(Some(CounterCaptureInputs::new(
                CounterMode::Counts,
                LIMITS.rows,
                LIMITS.rv_keys,
                pool.reserver(),
            )));
            assert!(
                collection
                    .terminal_with(
                        &plan,
                        &pins,
                        false,
                        Ok(Some(())),
                        |(), _, _, _, _| Err(ReadStage::BankRouting),
                        || panic!("counter must not use legacy"),
                        std::num::NonZeroU64::new(1).unwrap(),
                        || Ok(KernelEvidence::default()),
                    )
                    .is_err()
            );
        }
        // Empty with a legacy binding and counter inputs still errors.
        {
            let plan = empty_plan();
            let pins = PinnedObjects::empty();
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            let mut collection = CaptureCollection::new(Some(CounterCaptureInputs::new(
                CounterMode::Counts,
                LIMITS.rows,
                LIMITS.rv_keys,
                pool.reserver(),
            )));
            assert!(
                collection
                    .terminal_with(
                        &plan,
                        &pins,
                        false,
                        Ok(None::<()>),
                        |(), _, _, _, _| panic!("absent binding must not read"),
                        || panic!("counter capture cannot switch to legacy"),
                        std::num::NonZeroU64::new(1).unwrap(),
                        || Ok(KernelEvidence::default()),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn counter_empty_capture_reports_sourced_evidence_and_generation() {
        use crate::metrics::KernelControl;
        use p11scope_ebpf_common::OWNER_BAD_CONTROL;
        // The bypass publishes no bank rows, but the kernel evidence it
        // reports must come from the source (production reads the live
        // control cells) under the session's real generation: refused
        // identities and a poisoned owner reach kernel_evidence() and
        // make the report PARTIAL, on both the live and terminal paths.
        for terminal in [false, true] {
            let plan = AttachPlan::from_slots_with_policy(
                vec![],
                AdmissionPolicy::counters(crate::capacity::CounterBudget::new(512).unwrap()),
            )
            .unwrap();
            let pins = PinnedObjects::empty();
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            let mut collection = CaptureCollection::new(Some(CounterCaptureInputs::new(
                CounterMode::Counts,
                LIMITS.rows,
                LIMITS.rv_keys,
                pool.reserver(),
            )));
            let kernel = KernelEvidence {
                ring_loss: 7,
                control: KernelControl {
                    identity_unavailable: 3,
                    owner_poison: OWNER_BAD_CONTROL,
                    ..Default::default()
                },
                ..Default::default()
            };
            let snapshot = if terminal {
                collection.terminal_with(
                    &plan,
                    &pins,
                    false,
                    Ok(Some(())),
                    |(), _, _, _, _| panic!("empty bypass reads no banks"),
                    || panic!("empty counter must not use legacy"),
                    std::num::NonZeroU64::new(2).unwrap(),
                    || Ok(kernel),
                )
            } else {
                collection.fresh_with(
                    &plan,
                    &pins,
                    false,
                    Ok(Some(())),
                    |(), _, _, _, _| panic!("empty bypass reads no banks"),
                    || panic!("empty counter must not use legacy"),
                    std::num::NonZeroU64::new(2).unwrap(),
                    || Ok(kernel),
                )
            }
            .expect("sourced empty bypass succeeds");
            assert_eq!(snapshot.kernel_evidence(), kernel);
            assert_eq!(snapshot.counter_collection().unwrap()["generation"], 2);
            let mut evidence = crate::render::tests::evidence();
            evidence.kernel_control = snapshot.kernel_evidence().control.evidence();
            evidence.verdict();
            assert_eq!(evidence.completeness, "PARTIAL");
        }
    }

    /// Data always: a profile run that ends with zero snapshots still
    /// seals its report. A terminal read failure with no prior snapshot
    /// publishes a degraded snapshot — no aggregate rows — instead of
    /// failing the publication; the report names the read failure.
    #[test]
    fn terminal_without_any_snapshot_still_seals_a_degraded_report() {
        use p11scope_ebpf_common::CounterMode;
        let mut fresh = ConsumerFixture::new();
        let degraded = fresh
            .terminal(CounterMode::Counts, 1, 5, Some(ConsumerFault::ReadRvs))
            .expect("a terminal without any prior snapshot seals a degraded report");
        assert!(
            degraded.reports().is_empty(),
            "a degraded snapshot carries no aggregate rows"
        );
    }

    #[test]
    fn terminal_failure_publishes_last_good_stale_with_gap() {
        use p11scope_ebpf_common::CounterMode;
        // Never-acquired terminal still fails: no snapshot exists to publish.
        {
            let mut fresh = ConsumerFixture::new();
            let error = fresh
                .terminal(CounterMode::Counts, 1, 5, Some(ConsumerFault::ReadRvs))
                .expect_err("a terminal without any prior snapshot must fail");
            assert!(
                format!("{error:#}").contains("counter collection unavailable"),
                "{error:#}"
            );
        }
        // A terminal read failure after a good snapshot publishes the last
        // good rows as stale with a named failure and a PARTIAL gap.
        let mut fixture = ConsumerFixture::new();
        fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
        let terminal = fixture
            .terminal(CounterMode::Counts, 1, 9, Some(ConsumerFault::ReadRvs))
            .expect("terminal must publish the last good snapshot as stale");
        assert_eq!(terminal.reports()[0].calls, 5);
        assert!(terminal.has_counter_gap());
        let metadata = terminal.counter_collection().unwrap();
        assert_eq!(metadata["status"], "stale");
        assert_eq!(metadata["failure"], "read_rvs");
        assert_eq!(metadata["mode"], "counts");
        assert_eq!(metadata["generation"], 1);
        let mut evidence = crate::render::tests::evidence();
        evidence.verdict();
        assert_eq!(evidence.completeness, "COMPLETE");
        crate::render::apply_counter_snapshot(&mut evidence, &terminal);
        assert_eq!(evidence.completeness, "PARTIAL");
        assert!(
            evidence
                .gap_classes
                .observation
                .causes
                .contains(&"counter_collection"),
            "{:?}",
            evidence.gap_classes.observation.causes
        );
    }

    #[test]
    fn terminal_success_after_good_snapshot_stays_fresh() {
        use p11scope_ebpf_common::CounterMode;
        let mut fixture = ConsumerFixture::new();
        fixture.fresh(CounterMode::Counts, 1, 5, None).unwrap();
        let terminal = fixture
            .terminal(CounterMode::Counts, 1, 8, None)
            .expect("a clean terminal read stays fresh");
        assert_eq!(terminal.reports()[0].calls, 8);
        assert!(!terminal.has_counter_gap());
        assert!(ConsumerFixture::terminal_eligible(&terminal));
        let metadata = terminal.counter_collection().unwrap();
        assert_eq!(metadata["status"], "fresh");
        assert!(metadata["failure"].is_null());
        assert_eq!(metadata["mode"], "counts");
        assert_eq!(metadata["generation"], 1);
        assert_eq!(metadata["health"]["saturated"], false);
        assert_eq!(metadata["health"]["contended"], false);
        let mut evidence = crate::render::tests::evidence();
        evidence.verdict();
        crate::render::apply_counter_snapshot(&mut evidence, &terminal);
        assert_eq!(evidence.completeness, "COMPLETE");
        assert!(
            !evidence
                .gap_classes
                .observation
                .causes
                .contains(&"counter_collection"),
            "{:?}",
            evidence.gap_classes.observation.causes
        );
    }

    #[test]
    fn counter_empty_capture_fails_when_kernel_evidence_is_unavailable() {
        // A kernel-evidence read error fails the bypass with its own
        // name instead of publishing default evidence, on both paths.
        for terminal in [false, true] {
            let plan = AttachPlan::from_slots_with_policy(
                vec![],
                AdmissionPolicy::counters(crate::capacity::CounterBudget::new(512).unwrap()),
            )
            .unwrap();
            let pins = PinnedObjects::empty();
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            let mut collection = CaptureCollection::new(Some(CounterCaptureInputs::new(
                CounterMode::Counts,
                LIMITS.rows,
                LIMITS.rv_keys,
                pool.reserver(),
            )));
            let result = if terminal {
                collection.terminal_with(
                    &plan,
                    &pins,
                    false,
                    Ok(Some(())),
                    |(), _, _, _, _| panic!("empty bypass reads no banks"),
                    || panic!("empty counter must not use legacy"),
                    std::num::NonZeroU64::new(1).unwrap(),
                    || anyhow::bail!("test EVIDENCE read failed"),
                )
            } else {
                collection.fresh_with(
                    &plan,
                    &pins,
                    false,
                    Ok(Some(())),
                    |(), _, _, _, _| panic!("empty bypass reads no banks"),
                    || panic!("empty counter must not use legacy"),
                    std::num::NonZeroU64::new(1).unwrap(),
                    || anyhow::bail!("test EVIDENCE read failed"),
                )
            };
            let error = result.expect_err("a kernel-evidence failure must fail");
            assert!(
                format!("{error:#}").contains("counter collection unavailable (kernel_evidence)"),
                "{error:#}"
            );
        }
    }
}
