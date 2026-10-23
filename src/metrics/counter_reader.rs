//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private native counter acquisition; no selector or Session loading route.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::identity::PinnedObjectId;
    use crate::metrics::KernelEvidence;
    use crate::metrics::counter_collector::{
        CounterCell, CounterCollector, CounterField, CounterHealth, CounterIssue, CounterLimits,
        CounterObservation, CounterRow, ReadStage, ReadWindow,
    };
    use crate::plan::{AttachKey, AttachPlan, Slot};
    use crate::semantics_edge::resources::{SEMANTIC_TRANSITION_SCRATCH, SemanticResourcePool};
    use aya::maps::{Array, Map, MapData, PerCpuArray, PerCpuHashMap, PerCpuValues};
    use aya_obj::generated::bpf_map_type;
    use p11scope_ebpf_common::{
        CountStats, CounterMode, ImageIdentityControl, RootAffiliationControl, RvKey, SlotStats,
        ThreadOwnerControl, TimestampStats,
    };
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    const LIMITS: CounterLimits = CounterLimits {
        rows: 4,
        rv_keys: 12,
    };
    const HIGH_RV: u64 = 0x1_0000_0001;

    fn slot(index: u32, object: u32) -> Slot {
        Slot {
            index,
            descriptor_index: 0,
            object: PinnedObjectId(object),
            object_path: "/provider.so".into(),
            file_offset: 0x80,
            names: if index == 0 {
                vec!["alias-a".into(), "alias-b".into()]
            } else {
                vec!["alias-a".into()]
            },
            aliased: index == 0,
            semantics: crate::kinds::DESCRIPTORS[0],
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![],
        }
    }

    fn plan() -> AttachPlan {
        AttachPlan::from_slots(vec![slot(0, 1), slot(1, 2)])
    }

    fn test_pool() -> SemanticResourcePool {
        SemanticResourcePool::reference_limit(32 * 1024 * 1024)
    }

    fn key(slot: u32, rv: u64) -> RvKey {
        RvKey { slot, _pad: 0, rv }
    }

    /// Only the native I/O boundary is scripted. Acquisition, checked wire
    /// folds, resource ownership and collector transactions are production.
    struct Scripted {
        mode: CounterMode,
        cpus: usize,
        stats: BTreeMap<u32, Vec<SlotStats>>,
        rvs: Vec<(RvKey, [u64; 2])>,
        health: CounterHealth,
        kernel: KernelEvidence,
        fail: Option<ReadStage>,
        accesses: Cell<usize>,
        rv_reads: Cell<usize>,
        clocks: [Option<u64>; 2],
        clock_reads: Cell<usize>,
    }

    impl Scripted {
        fn sample(mode: CounterMode, later: bool) -> Self {
            let (entered, returned, errors, total_ns, max_ns, rv) = if later {
                (8, 9, 2, 90, 25, [4, 2, 3])
            } else {
                (3, 5, 1, 50, 20, [2, 1, 2])
            };
            let mut buckets = [0; 32];
            buckets[7] = if later { 4 } else { 2 };
            buckets[31] = if later { 5 } else { 3 };
            Self {
                mode,
                cpus: 2,
                stats: BTreeMap::from([
                    (
                        0,
                        vec![
                            SlotStats {
                                entered,
                                returned,
                                errors,
                                total_ns,
                                max_ns,
                                buckets,
                            },
                            SlotStats::ZERO,
                        ],
                    ),
                    (
                        1,
                        vec![
                            SlotStats {
                                entered: if later { 2 } else { 1 },
                                returned: if later { 2 } else { 1 },
                                ..SlotStats::ZERO
                            },
                            SlotStats::ZERO,
                        ],
                    ),
                ]),
                rvs: vec![
                    (key(0, 0), [rv[0], 0]),
                    (key(0, HIGH_RV), [rv[1], 0]),
                    (key(0, u64::MAX), [rv[2], 0]),
                ],
                health: CounterHealth::default(),
                kernel: KernelEvidence::default(),
                fail: None,
                accesses: Cell::new(0),
                rv_reads: Cell::new(0),
                clocks: if later {
                    [Some(30), Some(40)]
                } else {
                    [Some(10), Some(20)]
                },
                clock_reads: Cell::new(0),
            }
        }

        fn access(&self, stage: ReadStage) -> Result<(), ReadStage> {
            self.accesses.set(self.accesses.get() + 1);
            if self.fail == Some(stage) && (stage != ReadStage::Rvs || self.rv_reads.get() == 2) {
                Err(stage)
            } else {
                Ok(())
            }
        }
    }

    impl CounterSource for Scripted {
        fn mode(&self) -> CounterMode {
            self.mode
        }
        fn possible_cpus(&self) -> usize {
            self.cpus
        }
        fn rv_keys(&self) -> impl Iterator<Item = Result<RvKey, ReadStage>> + '_ {
            self.rvs.iter().map(|(key, _)| Ok(*key))
        }
        fn rv_total(&self, wanted: &RvKey) -> Result<Result<u64, CounterIssue>, ReadStage> {
            self.rv_reads.set(self.rv_reads.get() + 1);
            self.access(ReadStage::Rvs)?;
            let (_, values) = self
                .rvs
                .iter()
                .find(|(key, _)| (key.slot, key.rv) == (wanted.slot, wanted.rv))
                .unwrap();
            Ok(values[0]
                .checked_add(values[1])
                .ok_or(CounterIssue::FoldOverflow(CounterField::Rv(wanted.rv))))
        }
        fn fold_row(
            &self,
            slot: &Slot,
            rvs: &[(RvKey, u64)],
            limits: CounterLimits,
        ) -> Result<Result<CounterRow, CounterIssue>, ReadStage> {
            self.access(ReadStage::Stats)?;
            let values = self.stats.get(&slot.index).ok_or(ReadStage::Stats)?;
            let rvs = || rvs.iter().copied();
            Ok(match self.mode {
                CounterMode::Counts => {
                    let cells: Vec<_> = values
                        .iter()
                        .map(|v| CountStats {
                            entered: v.entered,
                            returned: v.returned,
                            errors: v.errors,
                        })
                        .collect();
                    CounterRow::fold(
                        slot,
                        self.mode,
                        cells.iter().map(CounterCell::Counts),
                        rvs(),
                        limits,
                    )
                }
                CounterMode::Timestamps => {
                    let cells: Vec<_> = values
                        .iter()
                        .map(|v| TimestampStats {
                            entered: v.entered,
                            returned: v.returned,
                            errors: v.errors,
                            total_ns: v.total_ns,
                            max_ns: v.max_ns,
                        })
                        .collect();
                    CounterRow::fold(
                        slot,
                        self.mode,
                        cells.iter().map(CounterCell::Timestamps),
                        rvs(),
                        limits,
                    )
                }
                CounterMode::Latency => CounterRow::fold(
                    slot,
                    self.mode,
                    values.iter().map(CounterCell::Latency),
                    rvs(),
                    limits,
                ),
            })
        }
        fn health(&self) -> Result<CounterHealth, ReadStage> {
            self.access(ReadStage::Health)?;
            Ok(self.health)
        }
        fn kernel(&self) -> Result<KernelEvidence, ReadStage> {
            self.access(ReadStage::KernelEvidence)?;
            Ok(self.kernel)
        }
        fn now(&self) -> Option<u64> {
            let index = self.clock_reads.get();
            self.clock_reads.set(index + 1);
            self.clocks[index % 2]
        }
    }

    #[test]
    fn counter_reader_failures_preserve_complete_baselines() {
        // Advancing on partial RV/STATS/health/evidence acquisition, or hiding
        // native read failures, breaks the hand-computed 5/4/1 continuation.
        for stage in [
            ReadStage::Rvs,
            ReadStage::Stats,
            ReadStage::Health,
            ReadStage::KernelEvidence,
        ] {
            let pool = test_pool();
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            let initial = acquire(
                &Scripted::sample(CounterMode::Latency, false),
                NonZeroU64::new(7).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver(),
            )
            .unwrap();
            assert_eq!(collector.observe(Ok(initial)), CounterObservation::Initial);
            let before = pool.snapshot().charged_bytes;
            let mut failed = Scripted::sample(CounterMode::Latency, true);
            failed.fail = Some(stage);
            let refusal = acquire(
                &failed,
                NonZeroU64::new(7).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver(),
            );
            assert_eq!(refusal.err(), Some(stage));
            assert_eq!(
                pool.snapshot().charged_bytes,
                before,
                "failed source storage leaked"
            );
            let later = acquire(
                &Scripted::sample(CounterMode::Latency, true),
                NonZeroU64::new(7).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver(),
            )
            .unwrap();
            match collector.observe(Ok(later)) {
                CounterObservation::Advanced { deltas, .. } => {
                    assert_eq!(
                        (deltas[0].entered, deltas[0].returned, deltas[0].errors),
                        (5, 4, 1)
                    );
                    assert_eq!(
                        deltas[0].rv_counts,
                        BTreeMap::from([(0, 2), (HIGH_RV, 1), (u64::MAX, 1)])
                    );
                    assert_eq!((deltas[0].buckets[7], deltas[0].buckets[31]), (2, 2));
                }
                other => panic!("complete continuation must telescope: {other:?}"),
            }
        }
        // A refused envelope must precede even the first native value lookup.
        let pool = test_pool();
        pool.reference_set_limit(SEMANTIC_TRANSITION_SCRATCH + 1);
        let source = Scripted::sample(CounterMode::Counts, false);
        assert_eq!(
            acquire(
                &source,
                NonZeroU64::new(1).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver()
            )
            .err(),
            Some(ReadStage::Budget)
        );
        assert_eq!(source.accesses.get(), 0);
        assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
        let pool = test_pool();
        let mut huge = Scripted::sample(CounterMode::Counts, false);
        huge.cpus = usize::MAX;
        assert_eq!(
            acquire(
                &huge,
                NonZeroU64::new(1).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver()
            )
            .err(),
            Some(ReadStage::Budget)
        );
        assert_eq!(huge.accesses.get(), 0);
        assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);

        for mutation in 0..5 {
            let pool = test_pool();
            let mut source = Scripted::sample(CounterMode::Counts, false);
            match mutation {
                0 => source.rvs[0].0._pad = 1,
                1 => source.rvs[0].0.slot = 3,
                2 => source.rvs.push(source.rvs[0]),
                3 => source.rvs = vec![source.rvs[0]; 13],
                4 => source.rvs[0].1 = [u64::MAX, 1],
                _ => unreachable!(),
            }
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            let read = acquire(
                &source,
                NonZeroU64::new(1).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver(),
            )
            .unwrap();
            let expected = if mutation == 4 {
                CounterIssue::FoldOverflow(CounterField::Rv(0))
            } else if mutation == 3 {
                CounterIssue::Limits
            } else {
                CounterIssue::Topology
            };
            assert_eq!(
                collector.observe(Ok(read)),
                CounterObservation::Unavailable(expected)
            );
        }
    }

    #[test]
    fn counter_reader_windows_preserve_sampled_component_semantics() {
        // Clamping entered, requiring RV-sum agreement, losing physical inode
        // identity, or treating a bad clock as zero duration breaks this.
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let pool = test_pool();
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            let mut initial = Scripted::sample(mode, false);
            initial.rvs[0].1 = [1, 0]; // sampled RV sum deliberately differs from returned=5
            assert_eq!(
                collector.observe(acquire(
                    &initial,
                    NonZeroU64::new(7).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Initial
            );
            let mut later = Scripted::sample(mode, true);
            later.clocks = [Some(60), Some(50)];
            match collector.observe(acquire(
                &later,
                NonZeroU64::new(7).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver(),
            )) {
                CounterObservation::Advanced {
                    deltas,
                    before,
                    after,
                } => {
                    assert_eq!((deltas[0].entered, deltas[0].returned), (5, 4));
                    assert_eq!(
                        deltas[0].target,
                        AttachKey {
                            object: PinnedObjectId(1),
                            file_offset: 0x80
                        }
                    );
                    assert_eq!(
                        deltas[1].target,
                        AttachKey {
                            object: PinnedObjectId(2),
                            file_offset: 0x80
                        }
                    );
                    assert_eq!(
                        before,
                        Some(ReadWindow {
                            started_ns: 10,
                            finished_ns: 20
                        })
                    );
                    assert_eq!(after, None);
                    assert_eq!(
                        (deltas[0].total_ns, deltas[0].max_ns),
                        if mode == CounterMode::Counts {
                            (0, 0)
                        } else {
                            (40, 25)
                        }
                    );
                    assert_eq!(
                        (deltas[0].buckets[7], deltas[0].buckets[31]),
                        if mode == CounterMode::Latency {
                            (2, 2)
                        } else {
                            (0, 0)
                        }
                    );
                }
                other => panic!("component-wise live read must remain usable: {other:?}"),
            }
        }
        for (health, kernel, expected) in [
            (
                CounterHealth {
                    saturated: true,
                    contended: false,
                },
                KernelEvidence::default(),
                CounterIssue::ProducerSaturated,
            ),
            (
                CounterHealth {
                    saturated: false,
                    contended: true,
                },
                KernelEvidence::default(),
                CounterIssue::Contended,
            ),
            (
                CounterHealth::default(),
                KernelEvidence {
                    start_insert_failures: 1,
                    ..KernelEvidence::default()
                },
                CounterIssue::KernelEvidence,
            ),
            (
                CounterHealth::default(),
                KernelEvidence {
                    rv_update_failures: 1,
                    ..KernelEvidence::default()
                },
                CounterIssue::KernelEvidence,
            ),
        ] {
            let pool = test_pool();
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            let mut source = Scripted::sample(CounterMode::Counts, false);
            source.health = health;
            source.kernel = kernel;
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(7).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Unavailable(expected)
            );
            let clean = || {
                acquire(
                    &Scripted::sample(CounterMode::Counts, false),
                    NonZeroU64::new(7).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver(),
                )
            };
            assert_eq!(
                collector.observe(clean()),
                CounterObservation::Unavailable(expected)
            );
            assert_eq!(
                collector.observe(acquire(
                    &Scripted::sample(CounterMode::Counts, false),
                    NonZeroU64::new(8).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::GenerationChanged {
                    previous: 7,
                    current: 8
                }
            );
        }
    }

    fn native_map(kind: bpf_map_type, key: u32, value: u32, count: u32) -> Map {
        let object = aya_obj::Map::new_from_params(kind as u32, key, value, count, 0);
        let data = MapData::create(object, "counter_fixture", None)
            .expect("actual native map creation is required; no skip");
        match kind {
            bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY => Map::PerCpuArray(data),
            bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH => Map::PerCpuHashMap(data),
            bpf_map_type::BPF_MAP_TYPE_LRU_PERCPU_HASH => Map::PerCpuLruHashMap(data),
            bpf_map_type::BPF_MAP_TYPE_ARRAY => Map::Array(data),
            bpf_map_type::BPF_MAP_TYPE_HASH => Map::HashMap(data),
            _ => unreachable!(),
        }
    }

    fn native_maps(mode: CounterMode) -> BTreeMap<&'static str, Map> {
        use bpf_map_type::*;
        let stats_bytes = match mode {
            CounterMode::Counts => 24,
            CounterMode::Timestamps => 40,
            CounterMode::Latency => 296,
        };
        let mut maps = BTreeMap::from([
            (
                "STATS",
                native_map(BPF_MAP_TYPE_PERCPU_ARRAY, 4, stats_bytes, 512),
            ),
            (
                "RV_COUNTS",
                native_map(BPF_MAP_TYPE_PERCPU_HASH, 16, 8, 4096),
            ),
            ("START", native_map(BPF_MAP_TYPE_HASH, 16, 288, 16384)),
            (
                "COUNTER_HEALTH",
                native_map(BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 2),
            ),
            ("EVIDENCE", native_map(BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 9)),
            ("OWNER_CTL", native_map(BPF_MAP_TYPE_ARRAY, 4, 56, 1)),
            ("COOKIE_CTL", native_map(BPF_MAP_TYPE_ARRAY, 4, 40, 1)),
            ("ROOT_CTL", native_map(BPF_MAP_TYPE_ARRAY, 4, 64, 1)),
        ]);
        Array::<_, ThreadOwnerControl>::try_from(maps.get_mut("OWNER_CTL").unwrap())
            .unwrap()
            .set(
                0,
                ThreadOwnerControl {
                    limit: 16448,
                    ..ThreadOwnerControl::default()
                },
                0,
            )
            .unwrap();
        Array::<_, ImageIdentityControl>::try_from(maps.get_mut("COOKIE_CTL").unwrap())
            .unwrap()
            .set(
                0,
                ImageIdentityControl {
                    limit: 16384,
                    ..ImageIdentityControl::default()
                },
                0,
            )
            .unwrap();
        maps
    }

    fn native_values<T: aya::Pod + Copy>(first: T, zero: T) -> PerCpuValues<T> {
        let count = aya::util::nr_cpus().unwrap();
        let mut values = vec![zero; count];
        values[0] = first;
        PerCpuValues::try_from(values).unwrap()
    }

    fn write_native(maps: &mut BTreeMap<&'static str, Map>, mode: CounterMode, later: bool) {
        let source = Scripted::sample(mode, later);
        for index in [0, 1] {
            let cell = source.stats[&index][0];
            match mode {
                CounterMode::Counts => {
                    PerCpuArray::<_, CountStats>::try_from(maps.get_mut("STATS").unwrap())
                        .unwrap()
                        .set(
                            index,
                            native_values(
                                CountStats {
                                    entered: cell.entered,
                                    returned: cell.returned,
                                    errors: cell.errors,
                                },
                                CountStats::default(),
                            ),
                            0,
                        )
                        .unwrap()
                }
                CounterMode::Timestamps => {
                    PerCpuArray::<_, TimestampStats>::try_from(maps.get_mut("STATS").unwrap())
                        .unwrap()
                        .set(
                            index,
                            native_values(
                                TimestampStats {
                                    entered: cell.entered,
                                    returned: cell.returned,
                                    errors: cell.errors,
                                    total_ns: cell.total_ns,
                                    max_ns: cell.max_ns,
                                },
                                TimestampStats::default(),
                            ),
                            0,
                        )
                        .unwrap()
                }
                CounterMode::Latency => {
                    PerCpuArray::<_, SlotStats>::try_from(maps.get_mut("STATS").unwrap())
                        .unwrap()
                        .set(index, native_values(cell, SlotStats::ZERO), 0)
                        .unwrap()
                }
            }
        }
        let mut rvs =
            PerCpuHashMap::<_, RvKey, u64>::try_from(maps.get_mut("RV_COUNTS").unwrap()).unwrap();
        for (key, values) in source.rvs {
            rvs.insert(key, native_values(values[0], 0), 0).unwrap();
        }
    }

    #[test]
    #[ignore = "requires an explicitly granted native map-only BPF lane; no attach/program load"]
    fn counter_reader_native_maps_match_all_modes() {
        // Actual Aya map creation/update/info/lookup validates the native ABI,
        // possible-CPU fold and full64 key path; a scripted source cannot.
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let pool = test_pool();
            let mut maps = native_maps(mode);
            write_native(&mut maps, mode, false);
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            let source = NativeSource::new(|name| maps.get(name), mode).unwrap();
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(7).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Initial
            );
            drop(source);
            write_native(&mut maps, mode, true);
            let source = NativeSource::new(|name| maps.get(name), mode).unwrap();
            match collector.observe(acquire(
                &source,
                NonZeroU64::new(7).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver(),
            )) {
                CounterObservation::Advanced { deltas, .. } => {
                    assert_eq!(
                        (
                            deltas[0].slot,
                            deltas[0].entered,
                            deltas[0].returned,
                            deltas[0].errors
                        ),
                        (0, 5, 4, 1)
                    );
                    assert_eq!(
                        deltas[0].rv_counts,
                        BTreeMap::from([(0, 2), (HIGH_RV, 1), (u64::MAX, 1)])
                    );
                    assert_eq!(
                        deltas[0].target,
                        AttachKey {
                            object: PinnedObjectId(1),
                            file_offset: 0x80
                        }
                    );
                    assert_eq!(
                        deltas[1].target,
                        AttachKey {
                            object: PinnedObjectId(2),
                            file_offset: 0x80
                        }
                    );
                    assert_eq!(
                        (deltas[0].total_ns, deltas[0].max_ns),
                        if mode == CounterMode::Counts {
                            (0, 0)
                        } else {
                            (40, 25)
                        }
                    );
                    assert_eq!(
                        (deltas[0].buckets[7], deltas[0].buckets[31]),
                        if mode == CounterMode::Latency {
                            (2, 2)
                        } else {
                            (0, 0)
                        }
                    );
                }
                other => panic!("actual native read failed: {other:?}"),
            }
        }
    }

    #[test]
    #[ignore = "requires an explicitly granted native map-only BPF lane; no attach/program load"]
    fn counter_reader_requires_exact_maps_and_health() {
        // Missing controls cannot inherit Inventory's absent-is-clean rule;
        // LRU or mismatched shapes cannot masquerade as lossless counters.
        use bpf_map_type::*;
        let mut maps = native_maps(CounterMode::Counts);
        for name in [
            "STATS",
            "RV_COUNTS",
            "START",
            "COUNTER_HEALTH",
            "EVIDENCE",
            "OWNER_CTL",
            "COOKIE_CTL",
            "ROOT_CTL",
        ] {
            let removed = maps.remove(name).unwrap();
            assert_eq!(
                NativeSource::new(|name| maps.get(name), CounterMode::Counts).err(),
                Some(ReadStage::Shape),
                "missing {name}"
            );
            maps.insert(name, removed);
        }
        assert_eq!(
            NativeSource::new(|name| maps.get(name), CounterMode::Latency).err(),
            Some(ReadStage::Shape)
        );
        for (name, kind, key_bytes, value_bytes, capacity) in [
            ("STATS", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 40, 512),
            ("STATS", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 24, 511),
            ("RV_COUNTS", BPF_MAP_TYPE_LRU_PERCPU_HASH, 16, 8, 4096),
            ("RV_COUNTS", BPF_MAP_TYPE_PERCPU_HASH, 8, 8, 4096),
            ("RV_COUNTS", BPF_MAP_TYPE_PERCPU_HASH, 16, 8, 4095),
            ("START", BPF_MAP_TYPE_HASH, 16, 288, 16383),
            ("COUNTER_HEALTH", BPF_MAP_TYPE_ARRAY, 4, 8, 2),
            ("COUNTER_HEALTH", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 1),
            ("EVIDENCE", BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 8),
            ("OWNER_CTL", BPF_MAP_TYPE_ARRAY, 4, 48, 1),
        ] {
            let previous = maps
                .insert(name, native_map(kind, key_bytes, value_bytes, capacity))
                .unwrap();
            assert_eq!(
                NativeSource::new(|name| maps.get(name), CounterMode::Counts).err(),
                Some(ReadStage::Shape),
                "wrong {name}"
            );
            maps.insert(name, previous);
        }
        for (index, issue) in [
            (0, CounterIssue::ProducerSaturated),
            (1, CounterIssue::Contended),
        ] {
            PerCpuArray::<_, u64>::try_from(maps.get_mut("COUNTER_HEALTH").unwrap())
                .unwrap()
                .set(index, native_values(1, 0), 0)
                .unwrap();
            let pool = test_pool();
            let source = NativeSource::new(|name| maps.get(name), CounterMode::Counts).unwrap();
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(7).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Unavailable(issue)
            );
            drop(source);
            PerCpuArray::<_, u64>::try_from(maps.get_mut("COUNTER_HEALTH").unwrap())
                .unwrap()
                .set(index, native_values(0, 0), 0)
                .unwrap();
            let source = NativeSource::new(|name| maps.get(name), CounterMode::Counts).unwrap();
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(7).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Unavailable(issue)
            );
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(8).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::GenerationChanged {
                    previous: 7,
                    current: 8
                }
            );
        }
        for failure in 0..13 {
            let owner = ThreadOwnerControl {
                limit: 16448,
                poison: u64::from(failure == 0),
                admission_failures: u64::from(failure == 1),
                ..ThreadOwnerControl::default()
            };
            let cookie = ImageIdentityControl {
                limit: 16384,
                unavailable: u64::from(failure == 2),
                ..ImageIdentityControl::default()
            };
            let root = RootAffiliationControl {
                failure_flags: u64::from(failure == 3),
                ..RootAffiliationControl::default()
            };
            Array::<_, ThreadOwnerControl>::try_from(maps.get_mut("OWNER_CTL").unwrap())
                .unwrap()
                .set(0, owner, 0)
                .unwrap();
            Array::<_, ImageIdentityControl>::try_from(maps.get_mut("COOKIE_CTL").unwrap())
                .unwrap()
                .set(0, cookie, 0)
                .unwrap();
            Array::<_, RootAffiliationControl>::try_from(maps.get_mut("ROOT_CTL").unwrap())
                .unwrap()
                .set(0, root, 0)
                .unwrap();
            for index in 0..9 {
                PerCpuArray::<_, u64>::try_from(maps.get_mut("EVIDENCE").unwrap())
                    .unwrap()
                    .set(index, native_values(u64::from(failure == 4 + index), 0), 0)
                    .unwrap();
            }
            let pool = test_pool();
            let source = NativeSource::new(|name| maps.get(name), CounterMode::Counts).unwrap();
            assert_eq!(
                CounterCollector::new(LIMITS, pool.reserver()).observe(acquire(
                    &source,
                    NonZeroU64::new(7).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Unavailable(CounterIssue::KernelEvidence),
                "native control/evidence failure {failure}"
            );
        }
    }
}
