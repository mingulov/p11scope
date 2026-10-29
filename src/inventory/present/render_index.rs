//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded numeric-offset lookups within one immutable presentation.

use super::{InstanceSemanticView, InstanceView};
use crate::discovery::caller_registry::instance_input::MAX_REGISTRY_INSTANCES;
use crate::discovery::caller_registry::{CallerId, ModuleId};
use std::mem::size_of;
use std::sync::Arc;

const ALLOCATION_PADDING: usize = 32;
const ARC_REQUEST_BYTES: usize = size_of::<SemanticIndex>() + 2 * size_of::<usize>();
const MAX_INDEX_HEAP_BYTES: usize = MAX_REGISTRY_INSTANCES * size_of::<SemanticChildSlot>()
    + ARC_REQUEST_BYTES
    + 2 * ALLOCATION_PADDING;

/// Optional optimization only: refusing its allocation retains linear reads
/// of the complete captured views, with no capture-budget or evidence change.
#[derive(Debug, Clone, Default)]
pub(crate) struct PresentationRenderIndex {
    indexed: Option<Arc<SemanticIndex>>,
}

#[derive(Debug)]
struct SemanticIndex {
    slots: Vec<SemanticChildSlot>,
}

#[derive(Debug, Clone, Copy)]
struct SemanticChildSlot {
    pair: (CallerId, ModuleId),
    semantic_row: usize,
    instance_row: usize,
}

fn heap_envelope(capacity: usize) -> Option<usize> {
    capacity
        .checked_mul(size_of::<SemanticChildSlot>())?
        .checked_add(ARC_REQUEST_BYTES)?
        .checked_add(2 * ALLOCATION_PADDING)
}

impl PresentationRenderIndex {
    pub(crate) fn build(
        instances: &[InstanceView],
        semantic_edges: &[InstanceSemanticView],
    ) -> Self {
        Self::build_checked(instances, semantic_edges, |_| true)
    }

    fn build_checked(
        instances: &[InstanceView],
        semantic_edges: &[InstanceSemanticView],
        mut allow: impl FnMut(usize) -> bool,
    ) -> Self {
        if semantic_edges.is_empty()
            || semantic_edges.len() > MAX_REGISTRY_INSTANCES
            || instances.len() > MAX_REGISTRY_INSTANCES
            || instances.windows(2).any(|pair| pair[0].id >= pair[1].id)
        {
            return Self::default();
        }
        let Some(requested) = semantic_edges
            .len()
            .checked_mul(size_of::<SemanticChildSlot>())
        else {
            return Self::default();
        };
        if !allow(requested) {
            return Self::default();
        }
        let mut slots = Vec::new();
        if slots.try_reserve_exact(semantic_edges.len()).is_err()
            || slots.capacity() > MAX_REGISTRY_INSTANCES
            || heap_envelope(slots.capacity()).is_none_or(|bytes| bytes > MAX_INDEX_HEAP_BYTES)
        {
            return Self::default();
        }
        for (semantic_row, child) in semantic_edges.iter().enumerate() {
            let Ok(instance_row) = instances.binary_search_by_key(&child.instance, |row| row.id)
            else {
                return Self::default();
            };
            slots.push(SemanticChildSlot {
                pair: (child.caller, child.module),
                semantic_row,
                instance_row,
            });
        }
        // An unstable in-place sort needs no S-sized temporary. The original
        // ordinal in the key keeps each pair's presentation order exact.
        slots.sort_unstable_by_key(|slot| (slot.pair, slot.semantic_row));
        if !allow(ARC_REQUEST_BYTES) {
            return Self::default();
        }
        // This fixed small allocation uses ordinary Arc::new. Its real OOM
        // behavior is the allocator's error path, not graceful cache refusal.
        let result = Self {
            indexed: Some(Arc::new(SemanticIndex { slots })),
        };
        debug_assert!(result.heap_bytes() <= MAX_INDEX_HEAP_BYTES);
        result
    }

    #[cfg(test)]
    fn build_with_allocation_check(
        instances: &[InstanceView],
        semantic_edges: &[InstanceSemanticView],
        allow: impl FnMut(usize) -> bool,
    ) -> Self {
        Self::build_checked(instances, semantic_edges, allow)
    }

    /// Requested allocation envelope with per-allocation padding, not RSS.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.indexed.as_ref().map_or(0, |index| {
            heap_envelope(index.slots.capacity())
                .expect("index capacity was checked before ownership")
        })
    }

    /// Slices belong to the indexed snapshot or an identically ordered clone;
    /// Presentation's accessor keeps the offsets and captured rows together.
    pub(crate) fn children<'a>(
        &'a self,
        instances: &'a [InstanceView],
        semantic_edges: &'a [InstanceSemanticView],
        caller: CallerId,
        module: ModuleId,
    ) -> SemanticChildren<'a> {
        let pair = (caller, module);
        let (source, remaining) = match &self.indexed {
            Some(index) => {
                let start = index.slots.partition_point(|slot| slot.pair < pair);
                let end = index.slots.partition_point(|slot| slot.pair <= pair);
                (
                    ChildRows::Indexed(index.slots[start..end].iter()),
                    end - start,
                )
            }
            None => (
                ChildRows::Linear {
                    rows: semantic_edges.iter(),
                    pair,
                },
                semantic_edges
                    .iter()
                    .filter(|row| (row.caller, row.module) == pair)
                    .count(),
            ),
        };
        SemanticChildren {
            instances,
            semantic_edges,
            source,
            remaining,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SemanticChild<'a> {
    pub(crate) semantic: &'a InstanceSemanticView,
    pub(crate) instance: &'a InstanceView,
}

#[derive(Clone)]
enum ChildRows<'a> {
    Indexed(std::slice::Iter<'a, SemanticChildSlot>),
    Linear {
        rows: std::slice::Iter<'a, InstanceSemanticView>,
        pair: (CallerId, ModuleId),
    },
}

/// An O(1)-clone borrowed cursor. Fallback counts matches once at creation;
/// advancing either mode allocates nothing and never drops a captured row.
#[derive(Clone)]
pub(crate) struct SemanticChildren<'a> {
    instances: &'a [InstanceView],
    semantic_edges: &'a [InstanceSemanticView],
    source: ChildRows<'a>,
    remaining: usize,
}

impl<'a> Iterator for SemanticChildren<'a> {
    type Item = SemanticChild<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let child = match &mut self.source {
            ChildRows::Indexed(slots) => {
                let slot = slots.next()?;
                SemanticChild {
                    semantic: &self.semantic_edges[slot.semantic_row],
                    instance: &self.instances[slot.instance_row],
                }
            }
            ChildRows::Linear { rows, pair } => {
                let semantic = rows.find(|row| (row.caller, row.module) == *pair)?;
                let instance = self
                    .instances
                    .iter()
                    .find(|row| row.id == semantic.instance)
                    .expect("semantic instance resolves in presentation");
                SemanticChild { semantic, instance }
            }
        };
        self.remaining -= 1;
        Some(child)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for SemanticChildren<'_> {}

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
