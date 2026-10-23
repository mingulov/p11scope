//! SPDX-License-Identifier: GPL-3.0-or-later
//! Charged cumulative presentation from the existing complete counter collector.

#[cfg(test)]
mod tests {
    use super::{CounterCapture, CounterFailure};
    use crate::discovery::identity::{PinnedObjects, ReconciledModule};
    use crate::discovery::scan::{ScannedEntry, ScannedModule, ScannedTable};
    use crate::metrics::KernelEvidence;
    use crate::metrics::counter_collector::{
        CounterCell, CounterHealth, CounterLimits, CounterRead, CounterRow, ReadReservation,
        ReadStage, ReadWindow,
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
        let mut rows = Vec::with_capacity(1);
        rows.push(row);
        CounterRead::new(
            std::num::NonZeroU64::new(generation).unwrap(),
            mode,
            ReadWindow::new(Some(10), Some(20)),
            Ok(rows),
            CounterHealth::default(),
            KernelEvidence::default(),
            reservation,
        )
        .unwrap()
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
            assert_eq!(snapshot.mode(), Some(mode));
            assert_eq!(snapshot.generation(), Some(1));
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
        let mut capture = CounterCapture::new(LIMITS, pool.reserver());
        drop(capture.fresh_with(&plan, &pins, |plan, _, _, reserve| {
            Ok(read(plan, CounterMode::Counts, 1, 5, reserve))
        }));
        let current = capture.fresh_with(&plan, &pins, |plan, _, _, reserve| {
            Ok(read(plan, CounterMode::Counts, 1, 8, reserve))
        });
        let charged = pool.snapshot().charged_bytes;
        let held = current.clone();
        assert_eq!(pool.snapshot().charged_bytes, charged);
        drop(capture);
        drop(current);
        assert_eq!(pool.snapshot().charged_bytes, charged);
        assert_eq!(held.reports()[0].calls, 8);
        assert_eq!(held.deltas().unwrap()[0].returned, 3);
        drop(held);
        assert_eq!(pool.snapshot().charged_bytes, 0);
    }

    #[test]
    fn initial_unavailable_read_never_fabricates_zero_or_kernel_measurements() {
        let (_file, plan, pins) = fixture();
        let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
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
        assert_eq!(pool.snapshot().charged_bytes, 0);
    }
}
