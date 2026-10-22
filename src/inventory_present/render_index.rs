//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded numeric-offset lookups within one immutable presentation.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::caller_registry::instance_input::{
        InstanceLifecycle, RegistryInstanceId,
    };
    use crate::discovery::caller_registry::{CallerId, ModuleId};
    use crate::inventory_present::{EdgeSemanticsView, InstanceSemanticView, InstanceView};
    use crate::test_alloc::{count_allocs_during, counted_peak_during, requested_peak_during};

    fn instance(id: u32, pair: u32, state: InstanceLifecycle) -> InstanceView {
        InstanceView {
            id: RegistryInstanceId::from_raw(id),
            caller: CallerId(pair),
            module: ModuleId(pair),
            state,
            reason: None,
            first_seen_ns: 100,
            last_seen_ns: 200,
        }
    }

    fn semantic(instance: &InstanceView) -> InstanceSemanticView {
        InstanceSemanticView {
            instance: instance.id,
            caller: instance.caller,
            module: instance.module,
            api_returns: Some(1),
            saturated: false,
            historical_only_returns: 0,
            semantics: EdgeSemanticsView {
                label: "unknown (no operation evidence)",
                mechanisms: Vec::new(),
                operations: None,
            },
            lossy: false,
            reasons: Vec::new(),
        }
    }

    fn interleaved() -> (Vec<InstanceView>, Vec<InstanceSemanticView>) {
        let instances = vec![
            instance(2, 0, InstanceLifecycle::Observed),
            instance(7, 1, InstanceLifecycle::Uncertain),
            instance(11, 0, InstanceLifecycle::Retired),
            instance(4095, 1, InstanceLifecycle::Observed),
        ];
        // Original semantic-row order is independent of instance ID order.
        let mut semantics: Vec<_> = [2, 1, 0, 3]
            .into_iter()
            .map(|row| semantic(&instances[row]))
            .collect();
        semantics[1].api_returns = None;
        (instances, semantics)
    }

    fn rows(count: u32) -> (Vec<InstanceView>, Vec<InstanceSemanticView>) {
        let instances: Vec<_> = (0..count)
            .map(|id| instance(id, 0, InstanceLifecycle::Observed))
            .collect();
        let semantics = instances.iter().map(semantic).collect();
        (instances, semantics)
    }

    #[test]
    fn f7_index_keeps_original_pair_order_and_exact_references() {
        // Catch grouping by the wrong pair, sorting by instance ID instead
        // of original row, or copying/stale-binding a captured view.
        let (instances, semantics) = interleaved();
        let index = PresentationRenderIndex::build(&instances, &semantics);
        for (pair, semantic_rows, instance_rows) in [(0, [0, 2], [2, 0]), (1, [1, 3], [1, 3])] {
            let mut children =
                index.children(&instances, &semantics, CallerId(pair), ModuleId(pair));
            assert_eq!(children.len(), 2);
            for (ordinal, (semantic_row, instance_row)) in
                semantic_rows.into_iter().zip(instance_rows).enumerate()
            {
                let child = children.next().unwrap();
                assert!(std::ptr::eq(child.semantic, &semantics[semantic_row]));
                assert!(std::ptr::eq(child.instance, &instances[instance_row]));
                assert_eq!(children.len(), 1 - ordinal);
            }
            assert!(children.next().is_none());
        }
        let ids: Vec<_> = index
            .children(&instances, &semantics, CallerId(0), ModuleId(0))
            .map(|child| child.instance.id.label())
            .collect();
        assert_eq!(ids, ["i11", "i2"]);
        let first = index
            .children(&instances, &semantics, CallerId(0), ModuleId(0))
            .next()
            .unwrap();
        assert_eq!(first.instance.state, InstanceLifecycle::Retired);
        assert_eq!(
            index
                .children(&instances, &semantics, CallerId(1), ModuleId(1))
                .next()
                .unwrap()
                .semantic
                .api_returns,
            None
        );
        assert_eq!(
            index
                .children(&instances, &semantics, CallerId(99), ModuleId(99))
                .len(),
            0
        );
        assert_eq!(
            instances
                .iter()
                .map(|row| row.id.label())
                .collect::<Vec<_>>(),
            ["i2", "i7", "i11", "i4095"]
        );
        assert_eq!(
            semantics
                .iter()
                .map(|row| row.instance.label())
                .collect::<Vec<_>>(),
            ["i11", "i7", "i2", "i4095"]
        );
        let empty = PresentationRenderIndex::build(&[], &[]);
        assert_eq!(empty.heap_bytes(), 0);
        assert_eq!(empty.children(&[], &[], CallerId(0), ModuleId(0)).len(), 0);
    }

    #[test]
    fn f7_index_queries_allocate_nothing() {
        // Catch reconstructing a per-query child vector or cloned view.
        let (instances, semantics) = interleaved();
        let index = PresentationRenderIndex::build(&instances, &semantics);
        let (children_seen, allocations, bytes) = count_allocs_during(|| {
            let mut seen = 0;
            for _ in 0..100 {
                for pair in [0, 1, 99] {
                    let children =
                        index.children(&instances, &semantics, CallerId(pair), ModuleId(pair));
                    assert_eq!(children.clone().count(), children.len());
                    for child in children {
                        assert_eq!(child.semantic.instance, child.instance.id);
                        seen += 1;
                    }
                }
            }
            seen
        });
        assert_eq!(children_seen, 400);
        assert_eq!((allocations, bytes), (0, 0));
    }

    #[test]
    fn f7_index_capacity_refusal_and_clone_ownership() {
        // Catch an off-by-one cap, hidden allocation growth, or deep-cloning
        // the optional cache. Predicate denial is not real Arc OOM recovery.
        for count in [1, 4096] {
            let (instances, semantics) = rows(count);
            let (index, peak, allocations, requested) =
                counted_peak_during(|| PresentationRenderIndex::build(&instances, &semantics));
            assert!(!peak.incomplete);
            assert_eq!(peak.failed_requests, 0);
            assert_eq!(allocations, 2, "one slot Vec and one Arc payload");
            assert!(requested <= index.heap_bytes());
            assert!(peak.realloc_overlap_bytes <= index.heap_bytes());
            assert!(index.heap_bytes() <= 128 * 1024);
            assert_eq!(
                index
                    .children(&instances, &semantics, CallerId(0), ModuleId(0))
                    .count(),
                count as usize
            );
            let (clone, clone_allocations, clone_bytes) = count_allocs_during(|| index.clone());
            assert_eq!((clone_allocations, clone_bytes), (0, 0));
            assert_eq!(clone.heap_bytes(), index.heap_bytes());
            let (independent, allocations, _) =
                count_allocs_during(|| PresentationRenderIndex::build(&instances, &semantics));
            assert_eq!(allocations, 2, "a distinct snapshot owns its own cache");
            assert_eq!(independent.heap_bytes(), index.heap_bytes());
        }
        let (instances, semantics) = rows(4097);
        let (refused, allocations, bytes) =
            count_allocs_during(|| PresentationRenderIndex::build(&instances, &semantics));
        assert_eq!((allocations, bytes, refused.heap_bytes()), (0, 0, 0));
        assert_eq!(
            refused
                .children(&instances, &semantics, CallerId(0), ModuleId(0))
                .count(),
            4097,
            "refusing the cache never truncates captured rows"
        );
        let (instances, semantics) = interleaved();
        for denied_request in 0..2 {
            let mut requests = 0;
            let (refused, allocations, _) = count_allocs_during(|| {
                PresentationRenderIndex::build_with_allocation_check(
                    &instances,
                    &semantics,
                    |bytes| {
                        assert!(bytes > 0);
                        let allowed = requests != denied_request;
                        requests += 1;
                        allowed
                    },
                )
            });
            assert_eq!(requests, denied_request + 1);
            assert_eq!(allocations, denied_request);
            assert_eq!(refused.heap_bytes(), 0);
            let ids: Vec<_> = refused
                .children(&instances, &semantics, CallerId(0), ModuleId(0))
                .map(|child| child.instance.id.label())
                .collect();
            assert_eq!(ids, ["i11", "i2"]);
        }
        let mut missing = semantics;
        missing[0].instance = RegistryInstanceId::from_raw(88);
        let refused = PresentationRenderIndex::build(&instances, &missing);
        assert_eq!(refused.heap_bytes(), 0);
        assert!(
            std::panic::catch_unwind(|| {
                refused
                    .children(&instances, &missing, CallerId(0), ModuleId(0))
                    .next()
            })
            .is_err(),
            "dangling references retain the existing invariant failure"
        );
    }

    #[test]
    fn f7_index_churn_releases_old_revision_storage() {
        // Catch a global/history-growing cache and offsets reused for a
        // newer snapshot's changed physical associations.
        let (old_instances, old_semantics) = interleaved();
        let mut new_instances = old_instances.clone();
        let mut new_semantics = old_semantics.clone();
        for row in &mut new_instances {
            row.caller = CallerId(5);
            row.module = ModuleId(6);
        }
        for row in &mut new_semantics {
            row.caller = CallerId(5);
            row.module = ModuleId(6);
        }
        let (envelope, peak) = requested_peak_during(|| {
            let old = PresentationRenderIndex::build(&old_instances, &old_semantics);
            let mut envelope = 0;
            for _ in 0..100 {
                let new = PresentationRenderIndex::build(&new_instances, &new_semantics);
                envelope = old.heap_bytes() + new.heap_bytes();
                assert_eq!(
                    old.children(&old_instances, &old_semantics, CallerId(0), ModuleId(0))
                        .count(),
                    2
                );
                assert_eq!(
                    new.children(&new_instances, &new_semantics, CallerId(0), ModuleId(0))
                        .len(),
                    0
                );
                let child = new
                    .children(&new_instances, &new_semantics, CallerId(5), ModuleId(6))
                    .next()
                    .unwrap();
                assert!(std::ptr::eq(child.semantic, &new_semantics[0]));
                assert!(std::ptr::eq(child.instance, &new_instances[2]));
            }
            envelope
        });
        assert!(!peak.incomplete);
        assert!(envelope > 0);
        assert!(peak.peak_bytes > 0);
        assert_eq!(
            (peak.live_bytes, peak.live_blocks, peak.failed_requests),
            (0, 0, 0)
        );
        assert!(peak.realloc_overlap_bytes <= envelope);
    }
}
