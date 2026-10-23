//! SPDX-License-Identifier: GPL-3.0-or-later
//! Charged cumulative presentation from the existing complete counter collector.

use super::counter_collector::{
    CounterCellDelta, CounterCollector, CounterHealth, CounterIssue, CounterLimits,
    CounterObservation, CounterRead, ReadStage, ReadWindow, tree_bytes,
};
use super::{KernelEvidence, SlotReport};
use crate::discovery::identity::PinnedObjects;
use crate::plan::{AttachKey, AttachPlan, SlotOrdinal};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
use p11scope_ebpf_common::CounterMode;
use std::mem::size_of;
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
        self.is_fresh()
            .then(|| self.data.as_ref().unwrap().source.view().health)
    }

    pub(super) fn deltas(&self) -> Option<&[CounterCellDelta]> {
        match &self.data.as_ref()?.observation {
            CounterObservation::Advanced { deltas, .. } => Some(deltas),
            _ => None,
        }
    }
}

/// One collector per capture. No projection is reconstructed from a retained
/// baseline and an unrelated newer plan, including on acquisition failure.
pub(super) struct CounterCapture {
    collector: CounterCollector,
    limits: CounterLimits,
    last: Option<Arc<Projection>>,
    discontinuity: bool,
}

impl CounterCapture {
    pub(super) fn new(limits: CounterLimits, reserve: SemanticResourceReserver) -> Self {
        Self {
            collector: CounterCollector::new(limits, reserve),
            limits,
            last: None,
            discontinuity: false,
        }
    }

    fn failed(&self, failure: CounterFailure, kernel: Option<KernelEvidence>) -> CounterSnapshot {
        CounterSnapshot {
            data: self.last.clone(),
            failure: Some(failure),
            attempted_kernel: kernel,
            discontinuity: self.discontinuity,
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
                return self.failed(CounterFailure::Read(stage), None);
            }
        };
        let kernel = read.view().kernel;
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
                    return self.failed(failure, Some(kernel));
                }
                Err(failure) => return self.failed(failure, Some(kernel)),
            };
        let observation = self.collector.observe(Ok(read));
        let failure = match &observation {
            CounterObservation::ReadFailed(stage) => Some(CounterFailure::Read(*stage)),
            CounterObservation::Unavailable(issue) => Some(CounterFailure::Collection(*issue)),
            _ => None,
        };
        if let Some(failure) = failure {
            return self.failed(failure, Some(kernel));
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
        }
    }

    #[allow(dead_code)] // The actual prepared-binding consumer is integrated separately.
    pub(super) fn fresh(
        &mut self,
        binding: crate::attach::counter_banks::CounterReaderBinding<'_>,
        plan: &AttachPlan,
        pins: &PinnedObjects,
    ) -> CounterSnapshot {
        self.fresh_with(plan, pins, |plan, pins, limits, reserve| {
            super::counter_reader::read_bound(binding, plan, pins, limits, reserve)
        })
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
    Ok((reports, storage))
}

#[cfg(test)]
pub(super) mod tests {
    use super::{
        CaptureCollection, CaptureSnapshot, CounterCapture, CounterCaptureInputs, CounterFailure,
    };
    use crate::discovery::identity::{PinnedObjects, ReconciledModule};
    use crate::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    use crate::metrics::KernelEvidence;
    use crate::metrics::counter_collector::{
        CounterCell, CounterHealth, CounterIssue, CounterLimits, CounterRead, CounterRow,
        ReadReservation, ReadStage, ReadWindow,
    };
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
            reserve,
        )
    }

    fn read_with_health(
        plan: &AttachPlan,
        mode: CounterMode,
        generation: u64,
        returned: u64,
        health: CounterHealth,
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
            KernelEvidence::default(),
            reservation,
        )
        .unwrap()
    }

    #[derive(Clone, Copy)]
    pub(crate) enum ConsumerFault {
        ReadRvs,
        RowTopology,
        Saturated,
        Contended,
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
        pub(crate) fn new() -> Self {
            let (file, plan, pins) = fixture();
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            Self {
                _file: file,
                plan,
                pins,
                collection: CaptureCollection::new(Some(CounterCaptureInputs::new(
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
                    Some(ConsumerFault::RowTopology) => CounterRead::new(
                        std::num::NonZeroU64::new(generation).unwrap(),
                        mode,
                        ReadWindow::new(Some(30), Some(40)),
                        Err(CounterIssue::Topology),
                        CounterHealth::default(),
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
                )
            } else {
                self.collection.fresh_with(
                    &self.plan,
                    &self.pins,
                    false,
                    Ok(Some(())),
                    acquire,
                    legacy,
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

    #[test]
    fn consumer_selection_uses_prepared_presence_and_never_falls_back_on_refusal() {
        use crate::attach::counter_banks::BankRefusal;
        let (_file, plan, pins) = fixture();
        for binding in [
            Err(BankRefusal::Quarantined),
            Err(BankRefusal::Shape),
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
                    || panic!("a counter capture cannot switch to legacy")
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
                        ))
                    },
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
    fn projection_uses_actual_modes_cumulative_counts_and_full_width_rvs() {
        let (_file, plan, pins) = fixture();
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
            let mut capture = CounterCapture::new(LIMITS, pool.reserver());
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
        let mut capture = CounterCapture::new(LIMITS, pool.reserver());
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
        let mut capture = CounterCapture::new(LIMITS, pool.reserver());
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
        let mut capture = CounterCapture::new(LIMITS, pool.reserver());
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
        let mut capture = CounterCapture::new(LIMITS, pool.reserver());
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
        let mut capture = CounterCapture::new(LIMITS, pool.reserver());
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
}
