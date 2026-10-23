//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private preparation for independent cumulative counter collection.
//!
//! Acquisition supplies actual Session identity and complete native health.
//! Immutable row storage is shared, not deep-cloned under one charge. Each
//! returned delta batch retains its own allocation charge until its final drop.
//! Session collection generations must increase strictly on creation, using
//! checked nonzero allocation; an old Session can never be revived as new.

use super::KernelEvidence;
use crate::plan::{AttachKey, Slot};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
use p11scope_ebpf_common::{
    CountStats, CounterMode, LATENCY_BUCKETS, RvKey, SlotStats, TimestampStats,
};
use std::collections::{BTreeMap, BTreeSet};
use std::mem::{align_of, size_of};
use std::num::NonZeroU64;
use std::ops::Deref;
use std::sync::Arc;

/// Physical rows and distinct (slot, full-width RV) keys, per collector.
#[derive(Clone, Copy)]
pub(super) struct CounterLimits {
    pub(super) rows: usize,
    pub(super) rv_keys: usize,
}

/// Borrow existing wire cells only for the checked per-CPU fold. Retaining the
/// folded levels requires no boxed copy of the larger latency wire layout.
pub(super) enum CounterCell<'a> {
    Counts(&'a CountStats),
    Timestamps(&'a TimestampStats),
    Latency(&'a SlotStats),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CounterLevels {
    entered: u64,
    returned: u64,
    errors: u64,
    total_ns: u64,
    max_ns: u64,
    buckets: [u64; LATENCY_BUCKETS],
    rv_counts: BTreeMap<u64, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CounterRow {
    slot: u32,
    target: AttachKey,
    mode: CounterMode,
    levels: CounterLevels,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CounterField {
    Entered,
    Returned,
    Errors,
    TotalNs,
    MaxNs,
    Bucket(usize),
    Rv(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CounterIssue {
    Topology,
    Mode,
    GenerationRollback,
    Limits,
    ProducerSaturated,
    Contended,
    KernelEvidence,
    BankRouting,
    BankQuarantined,
    FoldOverflow(CounterField),
    Regressed { slot: u32, field: CounterField },
    Saturated { slot: u32, field: CounterField },
}

fn add(total: &mut u64, value: u64, field: CounterField) -> Result<(), CounterIssue> {
    *total = total
        .checked_add(value)
        .ok_or(CounterIssue::FoldOverflow(field))?;
    Ok(())
}

impl CounterRow {
    /// Bind a fold to the actual plan cell, independent of names/attribution.
    /// RV entries may repeat across CPUs; every fold and new key is checked.
    pub(super) fn fold<'a>(
        slot: &Slot,
        mode: CounterMode,
        cells: impl IntoIterator<Item = CounterCell<'a>>,
        rvs: impl IntoIterator<Item = (RvKey, u64)>,
        limits: CounterLimits,
    ) -> Result<Self, CounterIssue> {
        if limits.rows == 0 {
            return Err(CounterIssue::Limits);
        }
        let mut levels = CounterLevels::default();
        let mut any_cpu = false;
        for cell in cells {
            any_cpu = true;
            let (entered, returned, errors, total_ns, max_ns) = match (mode, cell) {
                (CounterMode::Counts, CounterCell::Counts(value)) => {
                    (value.entered, value.returned, value.errors, 0, 0)
                }
                (CounterMode::Timestamps, CounterCell::Timestamps(value)) => (
                    value.entered,
                    value.returned,
                    value.errors,
                    value.total_ns,
                    value.max_ns,
                ),
                (CounterMode::Latency, CounterCell::Latency(value)) => {
                    for (index, value) in value.buckets.into_iter().enumerate() {
                        add(
                            &mut levels.buckets[index],
                            value,
                            CounterField::Bucket(index),
                        )?;
                    }
                    (
                        value.entered,
                        value.returned,
                        value.errors,
                        value.total_ns,
                        value.max_ns,
                    )
                }
                _ => return Err(CounterIssue::Mode),
            };
            add(&mut levels.entered, entered, CounterField::Entered)?;
            add(&mut levels.returned, returned, CounterField::Returned)?;
            add(&mut levels.errors, errors, CounterField::Errors)?;
            add(&mut levels.total_ns, total_ns, CounterField::TotalNs)?;
            levels.max_ns = levels.max_ns.max(max_ns);
        }
        if !any_cpu {
            return Err(CounterIssue::Topology);
        }
        for (key, value) in rvs {
            if key.slot != slot.index || key._pad != 0 {
                return Err(CounterIssue::Topology);
            }
            if !levels.rv_counts.contains_key(&key.rv) && levels.rv_counts.len() >= limits.rv_keys {
                return Err(CounterIssue::Limits);
            }
            add(
                levels.rv_counts.entry(key.rv).or_default(),
                value,
                CounterField::Rv(key.rv),
            )?;
        }
        Ok(Self {
            slot: slot.index,
            target: AttachKey {
                object: slot.object,
                file_offset: slot.file_offset,
            },
            mode,
            levels,
        })
    }

    fn saturation(&self) -> Option<CounterField> {
        let levels = &self.levels;
        for (field, value) in [
            (CounterField::Entered, levels.entered),
            (CounterField::Returned, levels.returned),
            (CounterField::Errors, levels.errors),
            (CounterField::TotalNs, levels.total_ns),
        ] {
            if value == u64::MAX {
                return Some(field);
            }
        }
        for (index, &value) in levels.buckets.iter().enumerate() {
            if value == u64::MAX {
                return Some(CounterField::Bucket(index));
            }
        }
        levels
            .rv_counts
            .iter()
            .find_map(|(&rv, &value)| (value == u64::MAX).then_some(CounterField::Rv(rv)))
    }
}

/// Bounds encompass component reads, not an atomic kernel snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReadWindow {
    pub(super) started_ns: u64,
    pub(super) finished_ns: u64,
}

impl ReadWindow {
    pub(super) fn new(started_ns: Option<u64>, finished_ns: Option<u64>) -> Option<Self> {
        let (started_ns, finished_ns) = (started_ns?, finished_ns?);
        (started_ns <= finished_ns).then_some(Self {
            started_ns,
            finished_ns,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct CounterHealth {
    pub(super) saturated: bool,
    pub(super) contended: bool,
}

// The existing resources module pins Rust 1.98.1's x86-64 B-tree layout and
// allocator model. One full internal node per entry dominates retained tree
// requests; eight extra nodes cover the bounded split/root temporary chain.
// This is a conservative requested-allocation envelope, never an RSS bound.
fn tree_bytes<K, V>(entries: usize) -> Option<usize> {
    let node = 16usize
        .checked_add(11usize.checked_mul(size_of::<K>().checked_add(size_of::<V>())?)?)?
        .checked_add(12 * 8)?
        .checked_add(OWNED_ALLOCATION_PADDING)?;
    entries.checked_add(8)?.checked_mul(node)
}

fn vector_bytes<T>(capacity: usize) -> Option<usize> {
    capacity
        .checked_mul(size_of::<T>())?
        .checked_add(OWNED_ALLOCATION_PADDING)
}

/// Reserve before constructing the row Vec or any RV tree. The native reader
/// holds its separate transient reservation concurrently with this storage.
pub(super) struct ReadReservation {
    rows: usize,
    rv_keys: usize,
    storage: ResourceLease,
}

impl ReadReservation {
    pub(super) fn reserve(
        rows: usize,
        rv_keys: usize,
        reserve: &SemanticResourceReserver,
    ) -> Result<Self, ReadStage> {
        let bytes = vector_bytes::<CounterRow>(rows)
            // Include one potentially empty root per row as well as keys.
            .and_then(|bytes| {
                bytes.checked_add(tree_bytes::<u64, u64>(rv_keys.checked_add(rows)?)?)
            })
            .and_then(|bytes| bytes.checked_add(size_of::<CounterRows>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>() + OWNED_ALLOCATION_PADDING))
            .ok_or(ReadStage::Budget)?;
        Ok(Self {
            rows,
            rv_keys,
            storage: reserve.reserve(bytes).map_err(|_| ReadStage::Budget)?,
        })
    }
}

#[derive(Debug)]
struct CounterRows {
    values: Vec<CounterRow>,
    _storage: ResourceLease,
}

impl Deref for CounterRows {
    type Target = [CounterRow];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

const _: () = {
    assert!(align_of::<CounterRow>() <= 8);
    assert!(align_of::<CounterCellDelta>() <= 8);
    assert!(align_of::<CounterRows>() <= 8);
    assert!(align_of::<AttachKey>() <= 8);
};

#[derive(Debug, Clone)]
pub(super) struct CounterRead {
    generation: NonZeroU64,
    mode: CounterMode,
    window: Option<ReadWindow>,
    rows: Result<Arc<CounterRows>, CounterIssue>,
    health: CounterHealth,
    kernel: KernelEvidence,
}

impl CounterRead {
    /// A known-generation fold/limit failure is an explicit loss input. An
    /// incomplete map scrape instead supplies the outer ReadStage error.
    pub(super) fn new(
        generation: NonZeroU64,
        mode: CounterMode,
        window: Option<ReadWindow>,
        rows: Result<Vec<CounterRow>, CounterIssue>,
        health: CounterHealth,
        kernel: KernelEvidence,
        reservation: ReadReservation,
    ) -> Result<Self, ReadStage> {
        let rows = match rows {
            Ok(rows) => {
                let keys = rows.iter().try_fold(0usize, |count, row| {
                    count.checked_add(row.levels.rv_counts.len())
                });
                if rows.capacity() > reservation.rows
                    || keys.is_none_or(|keys| keys > reservation.rv_keys)
                {
                    return Err(ReadStage::Budget);
                }
                Ok(Arc::new(CounterRows {
                    values: rows,
                    _storage: reservation.storage,
                }))
            }
            Err(issue) => Err(issue),
        };
        Ok(Self {
            generation,
            mode,
            window,
            rows,
            health,
            kernel,
        })
    }

    fn validate(
        &self,
        limits: CounterLimits,
        reserve: &SemanticResourceReserver,
    ) -> Result<&[CounterRow], CollectionFailure> {
        let rows: &[CounterRow] = self
            .rows
            .as_deref()
            .map_err(|&issue| CollectionFailure::Issue(issue))?;
        // Check storage before allocating an identity set, differences or a
        // replacement baseline. RV limits count keys across all physical rows.
        if rows.len() > limits.rows {
            return Err(CounterIssue::Limits.into());
        }
        let mut keys = 0usize;
        for row in rows {
            keys = keys
                .checked_add(row.levels.rv_counts.len())
                .filter(|&keys| keys <= limits.rv_keys)
                .ok_or(CounterIssue::Limits)?;
        }
        if self.health.saturated {
            return Err(CounterIssue::ProducerSaturated.into());
        }
        if self.health.contended {
            return Err(CounterIssue::Contended.into());
        }
        let kernel = &self.kernel;
        if [
            kernel.ring_loss,
            kernel.start_insert_failures,
            kernel.unmatched_returns,
            kernel.rv_update_failures,
            kernel.cgroup_scope_failures,
            kernel.semantic_capture_failures,
            kernel.template_tail_failures,
            kernel.unregistered_mechanisms,
            kernel.abi_refusals,
            kernel.control.owner_poison,
            kernel.control.owner_admission_failures,
            kernel.control.identity_unavailable,
            kernel.control.root_failures,
        ]
        .into_iter()
        .any(|count| count != 0)
        {
            return Err(CounterIssue::KernelEvidence.into());
        }
        let _identity_storage = reserve
            .reserve(tree_bytes::<AttachKey, ()>(rows.len()).ok_or(CollectionFailure::Budget)?)
            .map_err(|_| CollectionFailure::Budget)?;
        let mut targets = BTreeSet::new();
        let mut previous = None;
        for row in rows {
            if row.mode != self.mode {
                return Err(CounterIssue::Mode.into());
            }
            if previous.is_some_and(|index| index >= row.slot) || !targets.insert(row.target) {
                return Err(CounterIssue::Topology.into());
            }
            previous = Some(row.slot);
            if let Some(field) = row.saturation() {
                return Err(CounterIssue::Saturated {
                    slot: row.slot,
                    field,
                }
                .into());
            }
        }
        Ok(rows)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadStage {
    Shape,
    Budget,
    Stats,
    Rvs,
    Health,
    KernelEvidence,
    BankRouting,
    BankQuarantined,
}

enum CollectionFailure {
    Issue(CounterIssue),
    Budget,
}

impl From<CounterIssue> for CollectionFailure {
    fn from(issue: CounterIssue) -> Self {
        Self::Issue(issue)
    }
}

/// Component-wise sampled differences. Timing/buckets are available according
/// to mode; max_ns is the current cumulative maximum, never an interval max.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CounterCellDelta {
    pub(super) slot: u32,
    pub(super) target: AttachKey,
    pub(super) mode: CounterMode,
    pub(super) entered: u64,
    pub(super) returned: u64,
    pub(super) errors: u64,
    pub(super) total_ns: u64,
    pub(super) max_ns: u64,
    pub(super) buckets: [u64; LATENCY_BUCKETS],
    pub(super) rv_counts: BTreeMap<u64, u64>,
}

/// Moving the batch preserves its charge; indexing borrows cells without
/// producing a second, uncharged Vec/tree copy.
#[derive(Debug)]
pub(super) struct CounterDeltas {
    values: Vec<CounterCellDelta>,
    _storage: ResourceLease,
}

impl Deref for CounterDeltas {
    type Target = [CounterCellDelta];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl PartialEq for CounterDeltas {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

impl Eq for CounterDeltas {}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CounterObservation {
    Initial,
    Advanced {
        deltas: CounterDeltas,
        before: Option<ReadWindow>,
        after: Option<ReadWindow>,
    },
    GenerationChanged {
        previous: u64,
        current: u64,
    },
    ReadFailed(ReadStage),
    Unavailable(CounterIssue),
}

pub(super) struct CounterCollector {
    limits: CounterLimits,
    reserve: SemanticResourceReserver,
    generation: Option<NonZeroU64>,
    baseline: Option<CounterRead>,
    issue: Option<CounterIssue>,
}

impl CounterCollector {
    pub(super) fn new(limits: CounterLimits, reserve: SemanticResourceReserver) -> Self {
        Self {
            limits,
            reserve,
            generation: None,
            baseline: None,
            issue: None,
        }
    }

    pub(super) fn observe(&mut self, source: Result<CounterRead, ReadStage>) -> CounterObservation {
        let read = match source {
            Ok(read) => read,
            Err(stage) => return CounterObservation::ReadFailed(stage),
        };
        let previous = self.generation;
        if previous.is_some_and(|generation| read.generation < generation) {
            // A stale read changes neither the current baseline nor its sticky
            // issue. The generation high water makes recovery history bounded.
            return CounterObservation::Unavailable(CounterIssue::GenerationRollback);
        }
        let same_generation = previous == Some(read.generation);
        if same_generation && let Some(issue) = self.issue {
            return CounterObservation::Unavailable(issue);
        }
        match read.validate(self.limits, &self.reserve) {
            Ok(_) => {}
            Err(CollectionFailure::Issue(issue)) => return self.latch(read.generation, issue),
            Err(CollectionFailure::Budget) => {
                return CounterObservation::ReadFailed(ReadStage::Budget);
            }
        }
        let observation = if same_generation {
            // A successful first read installs a baseline. An unsuccessful
            // first read latches an issue above and cannot reach this arm.
            let old = self
                .baseline
                .as_ref()
                .expect("healthy generation has a baseline");
            match differences(old, &read, &self.reserve) {
                Ok(deltas) => CounterObservation::Advanced {
                    deltas,
                    before: old.window,
                    after: read.window,
                },
                Err(CollectionFailure::Issue(issue)) => return self.latch(read.generation, issue),
                Err(CollectionFailure::Budget) => {
                    return CounterObservation::ReadFailed(ReadStage::Budget);
                }
            }
        } else if let Some(previous) = previous {
            CounterObservation::GenerationChanged {
                previous: previous.get(),
                current: read.generation.get(),
            }
        } else {
            CounterObservation::Initial
        };
        // The only baseline write follows every complete validation/fold.
        self.generation = Some(read.generation);
        self.baseline = Some(read);
        self.issue = None;
        observation
    }

    fn latch(&mut self, generation: NonZeroU64, issue: CounterIssue) -> CounterObservation {
        self.generation = Some(generation);
        self.issue = Some(issue);
        CounterObservation::Unavailable(issue)
    }
}

fn differences(
    old: &CounterRead,
    current: &CounterRead,
    reserve: &SemanticResourceReserver,
) -> Result<CounterDeltas, CollectionFailure> {
    if old.mode != current.mode {
        return Err(CounterIssue::Mode.into());
    }
    let old_rows = old
        .rows
        .as_deref()
        .map_err(|&issue| CollectionFailure::Issue(issue))?;
    let rows = current
        .rows
        .as_deref()
        .map_err(|&issue| CollectionFailure::Issue(issue))?;
    if rows.len() < old_rows.len() {
        return Err(CounterIssue::Topology.into());
    }
    let keys = rows
        .iter()
        .try_fold(0usize, |count, row| {
            count.checked_add(row.levels.rv_counts.len())
        })
        .ok_or(CollectionFailure::Budget)?;
    let bytes = vector_bytes::<CounterCellDelta>(rows.len())
        .and_then(|bytes| bytes.checked_add(tree_bytes::<u64, u64>(keys.checked_add(rows.len())?)?))
        .ok_or(CollectionFailure::Budget)?;
    let storage = reserve
        .reserve(bytes)
        .map_err(|_| CollectionFailure::Budget)?;
    let mut deltas = Vec::with_capacity(rows.len());
    let zero = CounterLevels::default();
    for (index, row) in rows.iter().enumerate() {
        let before = if let Some(old) = old_rows.get(index) {
            if (old.slot, old.target) != (row.slot, row.target)
                || old
                    .levels
                    .rv_counts
                    .iter()
                    .any(|(rv, &count)| count > 0 && !row.levels.rv_counts.contains_key(rv))
            {
                return Err(CounterIssue::Topology.into());
            }
            &old.levels
        } else {
            &zero
        };
        let after = &row.levels;
        let subtract = |now: u64, then: u64, field| {
            now.checked_sub(then).ok_or(CounterIssue::Regressed {
                slot: row.slot,
                field,
            })
        };
        let mut delta = CounterCellDelta {
            slot: row.slot,
            target: row.target,
            mode: row.mode,
            entered: subtract(after.entered, before.entered, CounterField::Entered)?,
            returned: subtract(after.returned, before.returned, CounterField::Returned)?,
            errors: subtract(after.errors, before.errors, CounterField::Errors)?,
            total_ns: subtract(after.total_ns, before.total_ns, CounterField::TotalNs)?,
            max_ns: after.max_ns,
            buckets: [0; LATENCY_BUCKETS],
            rv_counts: BTreeMap::new(),
        };
        subtract(after.max_ns, before.max_ns, CounterField::MaxNs)?;
        for (index, value) in delta.buckets.iter_mut().enumerate() {
            *value = subtract(
                after.buckets[index],
                before.buckets[index],
                CounterField::Bucket(index),
            )?;
        }
        for (&rv, &now) in &after.rv_counts {
            let count = subtract(
                now,
                before.rv_counts.get(&rv).copied().unwrap_or(0),
                CounterField::Rv(rv),
            )?;
            if count != 0 {
                delta.rv_counts.insert(rv, count);
            }
        }
        deltas.push(delta);
    }
    Ok(CounterDeltas {
        values: deltas,
        _storage: storage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::identity::PinnedObjectId;
    use crate::metrics::KernelEvidence;
    use crate::plan::{AttachKey, Slot};
    use p11scope_ebpf_common::{
        CountStats, CounterMode, LATENCY_BUCKETS, RvKey, SlotStats, TimestampStats,
    };
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    const LIMITS: CounterLimits = CounterLimits {
        rows: 4,
        rv_keys: 12,
    };
    const HIGH_RV: u64 = 0x1_0000_0001;

    fn slot(index: u32, object: u32, offset: u64) -> Slot {
        Slot {
            index,
            descriptor_index: 0,
            object: PinnedObjectId(object),
            object_path: "/provider.so".into(),
            file_offset: offset,
            names: vec!["unknown".into()],
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[0],
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![],
        }
    }

    fn latency(slot: &Slot, values: [u64; 6], rvs: &[(u64, u64)]) -> CounterRow {
        let [entered, returned, errors, total_ns, max_ns, bucket] = values;
        let mut buckets = [0; LATENCY_BUCKETS];
        buckets[0] = bucket;
        CounterRow::fold(
            slot,
            CounterMode::Latency,
            [CounterCell::Latency(&SlotStats {
                entered,
                returned,
                errors,
                total_ns,
                max_ns,
                buckets,
            })],
            rvs.iter().map(|&(rv, value)| {
                (
                    RvKey {
                        slot: slot.index,
                        _pad: 0,
                        rv,
                    },
                    value,
                )
            }),
            LIMITS,
        )
        .unwrap()
    }

    fn read(generation: u64, rows: Vec<CounterRow>) -> CounterRead {
        let pool = crate::semantics_edge::resources::SemanticResourcePool::reference_limit(
            32 * 1024 * 1024,
        );
        let keys = rows.iter().map(|row| row.levels.rv_counts.len()).sum();
        let reservation =
            ReadReservation::reserve(rows.capacity(), keys, &pool.reserver()).unwrap();
        CounterRead::new(
            NonZeroU64::new(generation).unwrap(),
            CounterMode::Latency,
            ReadWindow::new(Some(10), Some(20)),
            Ok(rows),
            CounterHealth::default(),
            KernelEvidence::default(),
            reservation,
        )
        .unwrap()
    }

    fn new_collector(limits: CounterLimits) -> CounterCollector {
        let pool = crate::semantics_edge::resources::SemanticResourcePool::reference_limit(
            32 * 1024 * 1024,
        );
        CounterCollector::new(limits, pool.reserver())
    }

    fn mutate_rows(read: &mut CounterRead, mutate: impl FnOnce(&mut Vec<CounterRow>)) {
        let pool = crate::semantics_edge::resources::SemanticResourcePool::reference_limit(
            32 * 1024 * 1024,
        );
        let reservation =
            ReadReservation::reserve(LIMITS.rows, LIMITS.rv_keys, &pool.reserver()).unwrap();
        let mut rows = Vec::with_capacity(LIMITS.rows);
        rows.extend(read.rows.as_ref().unwrap().iter().cloned());
        mutate(&mut rows);
        *read = CounterRead::new(
            read.generation,
            read.mode,
            read.window,
            Ok(rows),
            read.health,
            read.kernel,
            reservation,
        )
        .unwrap();
    }

    fn advanced(observation: CounterObservation) -> CounterDeltas {
        match observation {
            CounterObservation::Advanced { deltas, .. } => deltas,
            other => panic!("expected sampled differences, got {other:?}"),
        }
    }

    #[test]
    fn counter_storage_ownership_covers_two_collectors_and_deltas() {
        // Sharing a charge while deep-copying rows, refunding on an early Arc
        // drop, or returning uncharged deltas breaks this actual ownership test.
        use crate::semantics_edge::resources::SemanticResourcePool;

        fn charged(pool: &SemanticResourcePool, level: u64) -> CounterRead {
            let reservation = ReadReservation::reserve(1, 1, &pool.reserver()).unwrap();
            let row = latency(
                &slot(3, 1, 0x80),
                [level, level, 0, level * 2, 2, level],
                &[(0, level)],
            );
            CounterRead::new(
                NonZeroU64::new(7).unwrap(),
                CounterMode::Latency,
                None,
                Ok(vec![row]),
                CounterHealth::default(),
                KernelEvidence::default(),
                reservation,
            )
            .unwrap()
        }

        let pool = SemanticResourcePool::reference_limit(32 * 1024 * 1024);
        let empty = pool.snapshot().charged_bytes;
        let initial = charged(&pool, 1);
        let one_read = pool.snapshot().charged_bytes;
        assert!(one_read > empty);
        let shared = initial.clone();
        assert!(
            std::ptr::eq(
                &initial.rows.as_ref().unwrap()[0],
                &shared.rows.as_ref().unwrap()[0],
            ),
            "a clone must share the actual immutable row allocation"
        );
        assert_eq!(pool.snapshot().charged_bytes, one_read);
        let mut fast = CounterCollector::new(LIMITS, pool.reserver());
        let mut slow = CounterCollector::new(LIMITS, pool.reserver());
        assert_eq!(
            fast.observe(Ok(initial.clone())),
            CounterObservation::Initial
        );
        assert_eq!(
            slow.observe(Ok(initial.clone())),
            CounterObservation::Initial
        );
        assert_eq!(pool.snapshot().charged_bytes, one_read);

        let next = charged(&pool, 5);
        let overlapping = pool.snapshot().charged_bytes;
        assert!(
            overlapping > one_read,
            "old and new physical snapshots overlap"
        );
        let fast_delta = match fast.observe(Ok(next.clone())) {
            CounterObservation::Advanced { deltas, .. } => deltas,
            other => panic!("expected first independently charged delta: {other:?}"),
        };
        let after_fast = pool.snapshot().charged_bytes;
        assert!(after_fast > overlapping);
        let slow_delta = match slow.observe(Ok(next.clone())) {
            CounterObservation::Advanced { deltas, .. } => deltas,
            other => panic!("expected second independently charged delta: {other:?}"),
        };
        assert_eq!(fast_delta[0].returned, 4);
        assert_eq!(slow_delta[0].rv_counts, BTreeMap::from([(0, 4)]));
        let after_slow = pool.snapshot().charged_bytes;
        assert!(after_slow > after_fast);
        drop(initial);
        assert_eq!(
            pool.snapshot().charged_bytes,
            after_slow,
            "shared source still owns old storage"
        );
        drop(shared);
        assert_eq!(
            pool.snapshot().charged_bytes,
            after_slow - (one_read - empty)
        );
        drop(next);
        let before_collectors_drop = pool.snapshot().charged_bytes;
        drop(fast);
        assert_eq!(pool.snapshot().charged_bytes, before_collectors_drop);
        drop(slow);
        let deltas_only = pool.snapshot().charged_bytes;
        assert!(
            deltas_only > empty,
            "returned deltas remain charged beyond both collectors"
        );
        drop(fast_delta);
        assert!(pool.snapshot().charged_bytes > empty);
        drop(slow_delta);
        assert_eq!(pool.snapshot().charged_bytes, empty);

        // Delta-allocation refusal is transactional, not a sticky producer
        // failure: releasing budget permits a complete telescoping retry.
        let mut collector = CounterCollector::new(LIMITS, pool.reserver());
        assert_eq!(
            collector.observe(Ok(charged(&pool, 1))),
            CounterObservation::Initial
        );
        let later = charged(&pool, 5);
        let held = pool.snapshot().charged_bytes;
        pool.reference_set_limit(held + tree_bytes::<AttachKey, ()>(1).unwrap());
        assert_eq!(
            collector.observe(Ok(later.clone())),
            CounterObservation::ReadFailed(ReadStage::Budget)
        );
        assert_eq!(pool.snapshot().charged_bytes, held);
        pool.reference_set_limit(32 * 1024 * 1024);
        match collector.observe(Ok(later)) {
            CounterObservation::Advanced { deltas, .. } => {
                assert_eq!((deltas[0].entered, deltas[0].returned), (4, 4));
                assert_eq!(deltas[0].rv_counts, BTreeMap::from([(0, 4)]));
            }
            other => panic!("budget failure advanced or poisoned the baseline: {other:?}"),
        }
        drop(collector);
        assert_eq!(pool.snapshot().charged_bytes, empty);
    }

    #[test]
    fn counter_collectors_telescope_all_components_across_failure_and_generation() {
        // A collector which clears maps, drops full-width RVs/buckets, advances
        // on failure or indexes new rows by vector position breaks this ledger.
        let first = slot(3, 1, 0x80);
        let appended = slot(19, 2, 0x90);
        let initial = read(
            7,
            vec![latency(
                &first,
                [10, 8, 1, 80, 20, 8],
                &[(0, 7), (HIGH_RV, 1)],
            )],
        );
        let middle = read(
            7,
            vec![
                latency(
                    &first,
                    [16, 13, 2, 150, 35, 13],
                    &[(0, 10), (HIGH_RV, 2), (u64::MAX, 1)],
                ),
                latency(&appended, [3, 3, 0, 12, 4, 3], &[(0, 3)]),
            ],
        );
        let final_read = read(
            7,
            vec![
                latency(
                    &first,
                    [30, 24, 4, 300, 40, 24],
                    &[(0, 18), (HIGH_RV, 4), (u64::MAX, 2)],
                ),
                latency(&appended, [8, 8, 0, 40, 7, 8], &[(0, 8)]),
            ],
        );
        let mut fast = new_collector(LIMITS);
        let mut slow = new_collector(LIMITS);
        assert_eq!(
            fast.observe(Ok(initial.clone())),
            CounterObservation::Initial
        );
        assert_eq!(slow.observe(Ok(initial)), CounterObservation::Initial);
        let a = advanced(fast.observe(Ok(middle)));
        assert_eq!(
            slow.observe(Err(ReadStage::Stats)),
            CounterObservation::ReadFailed(ReadStage::Stats)
        );
        let b = advanced(fast.observe(Ok(final_read.clone())));
        let together = advanced(slow.observe(Ok(final_read)));
        assert_eq!(together[0].mode, CounterMode::Latency);
        assert_eq!(
            (a[0].slot, a[0].target),
            (
                3,
                AttachKey {
                    object: PinnedObjectId(1),
                    file_offset: 0x80
                }
            )
        );
        assert_eq!(
            (
                a[0].entered,
                a[0].returned,
                a[0].errors,
                a[0].total_ns,
                a[0].max_ns,
                a[0].buckets[0]
            ),
            (6, 5, 1, 70, 35, 5)
        );
        assert_eq!(
            a[0].rv_counts,
            BTreeMap::from([(0, 3), (HIGH_RV, 1), (u64::MAX, 1)])
        );
        assert_eq!(
            (
                b[0].entered,
                b[0].returned,
                b[0].errors,
                b[0].total_ns,
                b[0].max_ns,
                b[0].buckets[0]
            ),
            (14, 11, 2, 150, 40, 11)
        );
        assert_eq!(
            b[0].rv_counts,
            BTreeMap::from([(0, 8), (HIGH_RV, 2), (u64::MAX, 1)])
        );
        assert_eq!(
            (
                together[0].entered,
                together[0].returned,
                together[0].errors,
                together[0].total_ns,
                together[0].max_ns,
                together[0].buckets[0]
            ),
            (20, 16, 3, 220, 40, 16)
        );
        assert_eq!(
            together[0].rv_counts,
            BTreeMap::from([(0, 11), (HIGH_RV, 3), (u64::MAX, 2)])
        );
        assert_eq!(
            (
                a[1].slot,
                a[1].returned,
                b[1].returned,
                together[1].returned
            ),
            (19, 3, 5, 8)
        );
        assert_eq!(together[1].rv_counts, BTreeMap::from([(0, 8)]));
        assert_eq!(
            fast.observe(Ok(read(
                8,
                vec![latency(&first, [1, 1, 0, 2, 2, 1], &[(0, 1)])]
            ))),
            CounterObservation::GenerationChanged {
                previous: 7,
                current: 8
            }
        );
        let stale = fast.observe(Ok(read(
            7,
            vec![latency(&first, [100, 100, 0, 100, 2, 100], &[(0, 100)])],
        )));
        assert_eq!(
            stale,
            CounterObservation::Unavailable(CounterIssue::GenerationRollback)
        );
        let continuation = advanced(fast.observe(Ok(read(
            8,
            vec![latency(&first, [4, 4, 0, 8, 3, 4], &[(0, 4)])],
        ))));
        assert_eq!(
            (
                continuation[0].entered,
                continuation[0].returned,
                continuation[0].total_ns
            ),
            (3, 3, 6)
        );
        assert_eq!(continuation[0].rv_counts, BTreeMap::from([(0, 3)]));
    }

    #[test]
    fn counter_read_failure_is_transactional_and_topology_is_append_only() {
        // Failed map components cannot advance the baseline. Same-generation
        // row substitution/reordering/removal and lost positive RV keys latch.
        let first = slot(3, 1, 0x80);
        let second = slot(19, 2, 0x90);
        let before = read(
            7,
            vec![
                latency(&first, [10, 8, 1, 80, 20, 8], &[(0, 7), (HIGH_RV, 1)]),
                latency(&second, [2, 2, 0, 4, 2, 2], &[(0, 2)]),
            ],
        );
        let after = read(
            7,
            vec![
                latency(&first, [20, 15, 2, 150, 30, 15], &[(0, 13), (HIGH_RV, 2)]),
                latency(&second, [3, 3, 0, 6, 2, 3], &[(0, 3)]),
            ],
        );
        for stage in [
            ReadStage::Stats,
            ReadStage::Rvs,
            ReadStage::Health,
            ReadStage::KernelEvidence,
        ] {
            let mut collector = new_collector(LIMITS);
            assert_eq!(
                collector.observe(Ok(before.clone())),
                CounterObservation::Initial
            );
            assert_eq!(
                collector.observe(Err(stage)),
                CounterObservation::ReadFailed(stage)
            );
            let delta = advanced(collector.observe(Ok(after.clone())));
            assert_eq!(
                (delta[0].entered, delta[0].returned, delta[0].buckets[0]),
                (10, 7, 7)
            );
            assert_eq!(delta[0].rv_counts, BTreeMap::from([(0, 6), (HIGH_RV, 1)]));
        }
        for mutation in 0..5 {
            let mut collector = new_collector(LIMITS);
            collector.observe(Ok(before.clone()));
            let mut bad = after.clone();
            mutate_rows(&mut bad, |rows| match mutation {
                0 => {
                    rows.pop();
                }
                1 => rows.swap(0, 1),
                2 => rows[0].target.file_offset += 8,
                3 => {
                    rows[0].levels.rv_counts.remove(&HIGH_RV);
                }
                4 => rows[0].slot = 4,
                _ => unreachable!(),
            });
            assert_eq!(
                collector.observe(Ok(bad)),
                CounterObservation::Unavailable(CounterIssue::Topology)
            );
            assert_eq!(
                collector.observe(Ok(after.clone())),
                CounterObservation::Unavailable(CounterIssue::Topology)
            );
            let mut replacement = after.clone();
            replacement.generation = NonZeroU64::new(8).unwrap();
            assert_eq!(
                collector.observe(Ok(replacement)),
                CounterObservation::GenerationChanged {
                    previous: 7,
                    current: 8
                }
            );
        }
        // Mutable display/attribution metadata is not physical identity.
        let mut renamed = first.clone();
        renamed.names = vec!["new alias".into()];
        renamed.object_path = "/renamed.so".into();
        renamed.module_ids = vec![crate::plan::ModuleId(3), crate::plan::ModuleId(4)];
        let mut collector = new_collector(LIMITS);
        collector.observe(Ok(read(
            1,
            vec![latency(&first, [1, 1, 0, 2, 2, 1], &[(0, 1)])],
        )));
        let delta = advanced(collector.observe(Ok(read(
            1,
            vec![latency(&renamed, [2, 2, 0, 4, 2, 2], &[(0, 2)])],
        ))));
        assert_eq!((delta[0].slot, delta[0].returned), (3, 1));
        let duplicate_target = read(
            1,
            vec![
                latency(&first, [3, 3, 0, 6, 2, 3], &[(0, 3)]),
                latency(&slot(19, 1, 0x80), [1, 1, 0, 1, 1, 1], &[(0, 1)]),
            ],
        );
        assert_eq!(
            collector.observe(Ok(duplicate_target)),
            CounterObservation::Unavailable(CounterIssue::Topology)
        );
        let mut collector = new_collector(LIMITS);
        collector.observe(Ok(before));
        let mut wrong_mode = after;
        wrong_mode.mode = CounterMode::Counts;
        assert_eq!(
            collector.observe(Ok(wrong_mode)),
            CounterObservation::Unavailable(CounterIssue::Mode)
        );

        let counts = || {
            CounterRow::fold(
                &first,
                CounterMode::Counts,
                [CounterCell::Counts(&CountStats {
                    entered: 3,
                    returned: 2,
                    errors: 1,
                })],
                [],
                LIMITS,
            )
            .unwrap()
        };
        let mut collector = new_collector(LIMITS);
        collector.observe(Ok(read(
            7,
            vec![latency(&first, [1, 1, 0, 1, 1, 1], &[(0, 1)])],
        )));
        let replacement = CounterRead::new(
            NonZeroU64::new(7).unwrap(),
            CounterMode::Counts,
            None,
            Ok(vec![counts()]),
            CounterHealth::default(),
            KernelEvidence::default(),
            ReadReservation::reserve(
                1,
                0,
                &crate::semantics_edge::resources::SemanticResourcePool::reference_limit(
                    32 * 1024 * 1024,
                )
                .reserver(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            collector.observe(Ok(replacement.clone())),
            CounterObservation::Unavailable(CounterIssue::Mode)
        );
        let mut replacement = replacement;
        replacement.generation = NonZeroU64::new(8).unwrap();
        assert_eq!(
            collector.observe(Ok(replacement)),
            CounterObservation::GenerationChanged {
                previous: 7,
                current: 8
            }
        );
    }

    #[test]
    fn counter_health_and_fold_overflow_never_claim_exact_deltas() {
        // Unhealthy first samples must never become Initial, nor may a later
        // healthy-looking sample erase same-generation loss or failed bounds.
        let first = slot(3, 1, 0x80);
        let healthy = read(7, vec![latency(&first, [1, 1, 0, 2, 2, 1], &[(0, 1)])]);
        for issue in [
            CounterIssue::ProducerSaturated,
            CounterIssue::Contended,
            CounterIssue::KernelEvidence,
            CounterIssue::Limits,
        ] {
            let mut bad = healthy.clone();
            match issue {
                CounterIssue::ProducerSaturated => bad.health.saturated = true,
                CounterIssue::Contended => bad.health.contended = true,
                CounterIssue::KernelEvidence => bad.kernel.rv_update_failures = 1,
                CounterIssue::Limits => bad.rows = Err(CounterIssue::Limits),
                _ => unreachable!(),
            }
            let mut collector = new_collector(LIMITS);
            assert_eq!(
                collector.observe(Ok(bad)),
                CounterObservation::Unavailable(issue)
            );
            assert_eq!(
                collector.observe(Ok(healthy.clone())),
                CounterObservation::Unavailable(issue)
            );
            let mut replacement = healthy.clone();
            replacement.generation = NonZeroU64::new(8).unwrap();
            assert_eq!(
                collector.observe(Ok(replacement)),
                CounterObservation::GenerationChanged {
                    previous: 7,
                    current: 8
                }
            );
            let stale = collector.observe(Ok(healthy.clone()));
            assert_eq!(
                stale,
                CounterObservation::Unavailable(CounterIssue::GenerationRollback),
                "a clean replay must not revive generation 7's {issue:?}"
            );
            let mut continued = healthy.clone();
            continued.generation = NonZeroU64::new(8).unwrap();
            assert!(matches!(
                collector.observe(Ok(continued.clone())),
                CounterObservation::Advanced { .. }
            ));
            continued.health.saturated = true;
            assert_eq!(
                collector.observe(Ok(continued)),
                CounterObservation::Unavailable(CounterIssue::ProducerSaturated)
            );
            assert_eq!(
                collector.observe(Ok(healthy.clone())),
                CounterObservation::Unavailable(CounterIssue::GenerationRollback)
            );
            let mut current = healthy.clone();
            current.generation = NonZeroU64::new(8).unwrap();
            assert_eq!(
                collector.observe(Ok(current)),
                CounterObservation::Unavailable(CounterIssue::ProducerSaturated)
            );
        }
        let mut huge_bucket = [0; LATENCY_BUCKETS];
        huge_bucket[0] = u64::MAX;
        let mut one_bucket = [0; LATENCY_BUCKETS];
        one_bucket[0] = 1;
        let folds = [
            (
                CounterField::Entered,
                CounterRow::fold(
                    &first,
                    CounterMode::Counts,
                    [
                        CounterCell::Counts(&CountStats {
                            entered: u64::MAX,
                            ..CountStats::default()
                        }),
                        CounterCell::Counts(&CountStats {
                            entered: 1,
                            ..CountStats::default()
                        }),
                    ],
                    [],
                    LIMITS,
                ),
            ),
            (
                CounterField::Rv(HIGH_RV),
                CounterRow::fold(
                    &first,
                    CounterMode::Counts,
                    [CounterCell::Counts(&CountStats::default())],
                    [
                        (
                            RvKey {
                                slot: 3,
                                _pad: 0,
                                rv: HIGH_RV,
                            },
                            u64::MAX,
                        ),
                        (
                            RvKey {
                                slot: 3,
                                _pad: 0,
                                rv: HIGH_RV,
                            },
                            1,
                        ),
                    ],
                    LIMITS,
                ),
            ),
            (
                CounterField::Bucket(0),
                CounterRow::fold(
                    &first,
                    CounterMode::Latency,
                    [
                        CounterCell::Latency(&SlotStats {
                            buckets: huge_bucket,
                            ..SlotStats::ZERO
                        }),
                        CounterCell::Latency(&SlotStats {
                            buckets: one_bucket,
                            ..SlotStats::ZERO
                        }),
                    ],
                    [],
                    LIMITS,
                ),
            ),
        ];
        for (field, folded) in folds {
            assert_eq!(
                folded.as_ref().unwrap_err(),
                &CounterIssue::FoldOverflow(field)
            );
            let mut sample = healthy.clone();
            sample.rows = Err(*folded.as_ref().unwrap_err());
            let mut collector = new_collector(LIMITS);
            assert_eq!(
                collector.observe(Ok(sample)),
                CounterObservation::Unavailable(CounterIssue::FoldOverflow(field))
            );
            assert_eq!(
                collector.observe(Ok(healthy.clone())),
                CounterObservation::Unavailable(CounterIssue::FoldOverflow(field))
            );
        }
        let limited = CounterLimits {
            rows: 1,
            rv_keys: 1,
        };
        let mut collector = new_collector(limited);
        collector.observe(Ok(healthy.clone()));
        let mut too_many = healthy.clone();
        mutate_rows(&mut too_many, |rows| {
            rows.push(latency(&slot(19, 2, 0x90), [1, 1, 0, 1, 1, 1], &[(0, 1)]))
        });
        assert_eq!(
            collector.observe(Ok(too_many)),
            CounterObservation::Unavailable(CounterIssue::Limits)
        );
        assert_eq!(
            collector
                .baseline
                .as_ref()
                .unwrap()
                .rows
                .as_ref()
                .unwrap()
                .len(),
            1
        );
        let mut collector = new_collector(limited);
        let too_many_keys = read(
            7,
            vec![latency(&first, [2, 2, 0, 2, 1, 2], &[(0, 1), (HIGH_RV, 1)])],
        );
        assert_eq!(
            collector.observe(Ok(too_many_keys)),
            CounterObservation::Unavailable(CounterIssue::Limits)
        );
        assert!(collector.baseline.is_none());
        let mut collector = new_collector(CounterLimits {
            rows: 2,
            rv_keys: 1,
        });
        let keys_across_rows = read(
            7,
            vec![
                latency(&first, [1, 1, 0, 1, 1, 1], &[(0, 1)]),
                latency(&slot(19, 2, 0x90), [1, 1, 0, 1, 1, 1], &[(0, 1)]),
            ],
        );
        assert_eq!(
            collector.observe(Ok(keys_across_rows)),
            CounterObservation::Unavailable(CounterIssue::Limits)
        );
        assert!(collector.baseline.is_none());
        let mut informational = healthy;
        informational.kernel.control.identity_budget_exhausted = true;
        assert_eq!(
            new_collector(LIMITS).observe(Ok(informational)),
            CounterObservation::Initial
        );

        // Existing START/RV/native-control loss remains additional to the
        // broad-counter health flags. No clean first baseline hides it.
        let failures: [fn(&mut KernelEvidence); 13] = [
            |k| k.ring_loss = 1,
            |k| k.start_insert_failures = 1,
            |k| k.unmatched_returns = 1,
            |k| k.rv_update_failures = 1,
            |k| k.cgroup_scope_failures = 1,
            |k| k.semantic_capture_failures = 1,
            |k| k.template_tail_failures = 1,
            |k| k.unregistered_mechanisms = 1,
            |k| k.abi_refusals = 1,
            |k| k.control.owner_poison = 1,
            |k| k.control.owner_admission_failures = 1,
            |k| k.control.identity_unavailable = 1,
            |k| k.control.root_failures = 1,
        ];
        for fail in failures {
            let mut sample = read(7, vec![]);
            fail(&mut sample.kernel);
            assert_eq!(
                new_collector(LIMITS).observe(Ok(sample)),
                CounterObservation::Unavailable(CounterIssue::KernelEvidence)
            );
        }
    }

    #[test]
    fn counter_read_window_does_not_assert_cross_map_atomicity() {
        // Rejecting returned>entered, RV/STATS skew or a bad clock would turn
        // non-atomic component reads into a fictitious atomicity requirement.
        let first = slot(3, 1, 0x80);
        let mut collector = new_collector(LIMITS);
        collector.observe(Ok(read(
            7,
            vec![latency(&first, [2, 3, 0, 10, 4, 6], &[(0, 8)])],
        )));
        let mut later = read(7, vec![latency(&first, [4, 7, 0, 20, 5, 10], &[(0, 9)])]);
        later.window = ReadWindow::new(Some(30), Some(40));
        match collector.observe(Ok(later)) {
            CounterObservation::Advanced {
                deltas,
                before,
                after,
            } => {
                assert_eq!(
                    (deltas[0].entered, deltas[0].returned, deltas[0].buckets[0]),
                    (2, 4, 4)
                );
                assert_eq!(deltas[0].rv_counts, BTreeMap::from([(0, 1)]));
                assert_eq!(
                    before,
                    Some(ReadWindow {
                        started_ns: 10,
                        finished_ns: 20
                    })
                );
                assert_eq!(
                    after,
                    Some(ReadWindow {
                        started_ns: 30,
                        finished_ns: 40
                    })
                );
            }
            other => panic!("component samples are usable: {other:?}"),
        }
        for bounds in [(None, Some(50)), (Some(60), Some(50))] {
            let mut next = read(7, vec![latency(&first, [5, 8, 0, 21, 5, 11], &[(0, 10)])]);
            next.window = ReadWindow::new(bounds.0, bounds.1);
            assert!(next.window.is_none());
            match collector.observe(Ok(next)) {
                CounterObservation::Advanced { after, .. } => assert_eq!(after, None),
                other => panic!("unknown clock must not fabricate a zero interval: {other:?}"),
            }
        }
        assert_eq!(
            ReadWindow::new(Some(50), Some(50)),
            Some(ReadWindow {
                started_ns: 50,
                finished_ns: 50
            })
        );
    }

    #[test]
    fn entered_below_returned_regresses_instead_of_clamping_to_zero() {
        let first = slot(3, 1, 0x80);
        let mut collector = new_collector(LIMITS);
        collector.observe(Ok(read(
            7,
            vec![latency(&first, [10, 10, 0, 10, 1, 10], &[(0, 10)])],
        )));
        assert_eq!(
            collector.observe(Ok(read(
                7,
                vec![latency(&first, [9, 10, 0, 10, 1, 10], &[(0, 10)])]
            ))),
            CounterObservation::Unavailable(CounterIssue::Regressed {
                slot: 3,
                field: CounterField::Entered
            })
        );
        for (field, values, rv) in [
            (CounterField::Returned, [10, 9, 2, 20, 5, 10], 10),
            (CounterField::Errors, [10, 10, 1, 20, 5, 10], 10),
            (CounterField::TotalNs, [10, 10, 2, 19, 5, 10], 10),
            (CounterField::MaxNs, [10, 10, 2, 20, 4, 10], 10),
            (CounterField::Bucket(0), [10, 10, 2, 20, 5, 9], 10),
            (CounterField::Rv(HIGH_RV), [10, 10, 2, 20, 5, 10], 9),
        ] {
            let mut collector = new_collector(LIMITS);
            collector.observe(Ok(read(
                7,
                vec![latency(&first, [10, 10, 2, 20, 5, 10], &[(HIGH_RV, 10)])],
            )));
            assert_eq!(
                collector.observe(Ok(read(7, vec![latency(&first, values, &[(HIGH_RV, rv)])]))),
                CounterObservation::Unavailable(CounterIssue::Regressed { slot: 3, field })
            );
        }
    }

    #[test]
    fn grown_rows_saturate_before_any_baseline_lookup() {
        let first = slot(3, 1, 0x80);
        let mut collector = new_collector(LIMITS);
        let old = latency(&first, [1, 1, 0, 1, 1, 1], &[(0, 1)]);
        collector.observe(Ok(read(7, vec![old.clone()])));
        assert_eq!(
            collector.observe(Ok(read(
                7,
                vec![
                    old,
                    latency(&slot(19, 2, 0x90), [u64::MAX, 1, 0, 1, 1, 1], &[(0, 1)])
                ]
            ))),
            CounterObservation::Unavailable(CounterIssue::Saturated {
                slot: 19,
                field: CounterField::Entered
            })
        );
        for (field, values, rv) in [
            (CounterField::Returned, [1, u64::MAX, 0, 1, 1, 1], 1),
            (CounterField::Errors, [1, 1, u64::MAX, 1, 1, 1], 1),
            (CounterField::TotalNs, [1, 1, 0, u64::MAX, 1, 1], 1),
            (CounterField::Bucket(0), [1, 1, 0, 1, 1, u64::MAX], 1),
            (CounterField::Rv(HIGH_RV), [1, 1, 0, 1, 1, 1], u64::MAX),
        ] {
            let sample = read(7, vec![latency(&first, values, &[(HIGH_RV, rv)])]);
            assert_eq!(
                new_collector(LIMITS).observe(Ok(sample)),
                CounterObservation::Unavailable(CounterIssue::Saturated { slot: 3, field })
            );
        }
    }

    #[test]
    fn folds_use_real_mode_layouts_and_keep_cumulative_maxima() {
        let first = slot(3, 1, 0x80);
        let counts = CounterRow::fold(
            &first,
            CounterMode::Counts,
            [
                CounterCell::Counts(&CountStats {
                    entered: 3,
                    returned: 2,
                    errors: 1,
                }),
                CounterCell::Counts(&CountStats {
                    entered: 4,
                    returned: 3,
                    errors: 0,
                }),
            ],
            [],
            LIMITS,
        )
        .unwrap();
        assert_eq!(
            (
                counts.levels.entered,
                counts.levels.returned,
                counts.levels.errors,
                counts.levels.total_ns,
                counts.levels.max_ns,
                counts.levels.buckets
            ),
            (7, 5, 1, 0, 0, [0; LATENCY_BUCKETS])
        );
        let timed = CounterRow::fold(
            &first,
            CounterMode::Timestamps,
            [
                CounterCell::Timestamps(&TimestampStats {
                    entered: 3,
                    returned: 2,
                    errors: 1,
                    total_ns: 9,
                    max_ns: 6,
                }),
                CounterCell::Timestamps(&TimestampStats {
                    entered: 4,
                    returned: 3,
                    errors: 0,
                    total_ns: 12,
                    max_ns: 8,
                }),
            ],
            [],
            LIMITS,
        )
        .unwrap();
        assert_eq!(
            (
                timed.levels.entered,
                timed.levels.returned,
                timed.levels.errors,
                timed.levels.total_ns,
                timed.levels.max_ns,
                timed.levels.buckets
            ),
            (7, 5, 1, 21, 8, [0; LATENCY_BUCKETS])
        );
        // Exercise nonzero cells away from bucket zero through both the real
        // per-CPU fold and the collector's full-array difference.
        let mut early = [0; LATENCY_BUCKETS];
        early[7] = 2;
        early[LATENCY_BUCKETS - 1] = 3;
        let mut left = [0; LATENCY_BUCKETS];
        left[7] = 5;
        left[LATENCY_BUCKETS - 1] = 6;
        let mut right = [0; LATENCY_BUCKETS];
        right[7] = 7;
        right[LATENCY_BUCKETS - 1] = 8;
        let before = CounterRow::fold(
            &first,
            CounterMode::Latency,
            [CounterCell::Latency(&SlotStats {
                entered: 5,
                returned: 5,
                errors: 0,
                total_ns: 10,
                max_ns: 2,
                buckets: early,
            })],
            [(
                RvKey {
                    slot: 3,
                    _pad: 0,
                    rv: 0,
                },
                5,
            )],
            LIMITS,
        )
        .unwrap();
        let after = CounterRow::fold(
            &first,
            CounterMode::Latency,
            [
                CounterCell::Latency(&SlotStats {
                    entered: 11,
                    returned: 11,
                    errors: 0,
                    total_ns: 22,
                    max_ns: 3,
                    buckets: left,
                }),
                CounterCell::Latency(&SlotStats {
                    entered: 15,
                    returned: 15,
                    errors: 0,
                    total_ns: 30,
                    max_ns: 4,
                    buckets: right,
                }),
            ],
            [
                (
                    RvKey {
                        slot: 3,
                        _pad: 0,
                        rv: 0,
                    },
                    11,
                ),
                (
                    RvKey {
                        slot: 3,
                        _pad: 0,
                        rv: 0,
                    },
                    15,
                ),
            ],
            LIMITS,
        )
        .unwrap();
        let mut collector = new_collector(LIMITS);
        assert_eq!(
            collector.observe(Ok(read(7, vec![before]))),
            CounterObservation::Initial
        );
        let delta = advanced(collector.observe(Ok(read(7, vec![after.clone()]))));
        let mut expected = [0; LATENCY_BUCKETS];
        expected[7] = 10;
        expected[LATENCY_BUCKETS - 1] = 11;
        assert_eq!(delta[0].buckets, expected);
        assert_eq!(
            (delta[0].returned, delta[0].total_ns, delta[0].max_ns),
            (21, 42, 4)
        );
        assert_eq!(delta[0].rv_counts, BTreeMap::from([(0, 21)]));
        let mut regressed = after;
        regressed.levels.buckets[LATENCY_BUCKETS - 1] = 13;
        assert_eq!(
            collector.observe(Ok(read(7, vec![regressed]))),
            CounterObservation::Unavailable(CounterIssue::Regressed {
                slot: 3,
                field: CounterField::Bucket(LATENCY_BUCKETS - 1)
            })
        );
        assert_eq!(
            CounterRow::fold(
                &first,
                CounterMode::Counts,
                [CounterCell::Timestamps(&TimestampStats::default())],
                [],
                LIMITS
            )
            .unwrap_err(),
            CounterIssue::Mode
        );
        assert_eq!(
            CounterRow::fold(
                &first,
                CounterMode::Counts,
                [CounterCell::Counts(&CountStats::default())],
                [(
                    RvKey {
                        slot: 19,
                        _pad: 0,
                        rv: HIGH_RV
                    },
                    1
                )],
                LIMITS
            )
            .unwrap_err(),
            CounterIssue::Topology
        );
        assert_eq!(
            CounterRow::fold(
                &first,
                CounterMode::Counts,
                [CounterCell::Counts(&CountStats::default())],
                [(
                    RvKey {
                        slot: 3,
                        _pad: 1,
                        rv: HIGH_RV
                    },
                    1
                )],
                LIMITS
            )
            .unwrap_err(),
            CounterIssue::Topology
        );
        assert_eq!(
            CounterRow::fold(
                &first,
                CounterMode::Counts,
                std::iter::empty::<CounterCell<'_>>(),
                [],
                LIMITS
            )
            .unwrap_err(),
            CounterIssue::Topology
        );
        assert_eq!(
            CounterRow::fold(
                &first,
                CounterMode::Counts,
                [CounterCell::Counts(&CountStats::default())],
                [
                    (
                        RvKey {
                            slot: 3,
                            _pad: 0,
                            rv: 0
                        },
                        1
                    ),
                    (
                        RvKey {
                            slot: 3,
                            _pad: 0,
                            rv: HIGH_RV
                        },
                        1
                    )
                ],
                CounterLimits {
                    rows: 1,
                    rv_keys: 1
                }
            )
            .unwrap_err(),
            CounterIssue::Limits
        );
        assert_eq!(
            CounterRow::fold(
                &first,
                CounterMode::Counts,
                [CounterCell::Counts(&CountStats::default())],
                [],
                CounterLimits {
                    rows: 0,
                    rv_keys: 0
                }
            )
            .unwrap_err(),
            CounterIssue::Limits
        );
    }
}
