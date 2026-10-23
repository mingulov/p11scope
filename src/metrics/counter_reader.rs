//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private native counter acquisition; no public selector or reader activation.

use super::counter_collector::{
    CounterCell, CounterField, CounterHealth, CounterIssue, CounterLimits, CounterRead, CounterRow,
    ReadReservation, ReadStage, ReadWindow,
};
use super::{KernelControl, KernelEvidence, saturating_total};
use crate::attach::Session;
use crate::plan::{AttachPlan, Slot};
use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, SemanticResourceReserver};
use aya::maps::{Array, Map, MapData, MapType, PerCpuArray, PerCpuHashMap};
use p11scope_ebpf_common::{
    CallStart, CountStats, CounterMode, EVIDENCE_ABI_REFUSALS, EVIDENCE_CELLS,
    EVIDENCE_CGROUP_SCOPE_FAILURES, EVIDENCE_RING_LOSS, EVIDENCE_RV_UPDATE_FAILURES,
    EVIDENCE_SEMANTIC_CAPTURE_FAILURES, EVIDENCE_START_INSERT_FAILURES,
    EVIDENCE_TEMPLATE_TAIL_FAILURES, EVIDENCE_UNMATCHED_RETURNS, EVIDENCE_UNREGISTERED_MECHANISMS,
    IMAGE_IDENTITY_TICKET_LIMIT, ImageIdentityControl, RootAffiliationControl, RvKey, SlotStats,
    StartKey, ThreadOwnerControl, TimestampStats,
};
use std::mem::size_of;
use std::num::NonZeroU64;

// These are the actual unselected artifact bounds, independent of the 8192
// planning ceiling or any Detailed SMALL/WIDE configuration.
const NATIVE_SLOTS: usize = 512;
const NATIVE_RVS: usize = 4096;
const NATIVE_STARTS: u32 = 16384;

/// Real Session identity only. A legacy Detailed/Inventory Session lacks the
/// required counter health/shape and refuses; this adds no counter loader.
#[allow(dead_code)] // Staged Session bridge; no counter loader/selector is active.
pub(super) fn read(
    session: &Session,
    plan: &AttachPlan,
    mode: CounterMode,
    limits: CounterLimits,
    reserve: &SemanticResourceReserver,
) -> Result<CounterRead, ReadStage> {
    let source = NativeSource::new(|name| session.ebpf.map(name), mode)?;
    acquire(
        &source,
        session.counter_collection_generation(),
        plan,
        limits,
        reserve,
    )
}

/// Private Counts-only bank bridge. The view shares the original map handles
/// and leases; creating a scrape opens no inner-map FD or new cursor.
#[allow(dead_code)] // Unselected two-cell proof; no public/runtime reader activation.
pub(super) fn read_banked(
    session: &Session,
    plan: &AttachPlan,
    objects: &crate::discovery::identity::PinnedObjects,
    limits: CounterLimits,
    reserve: &SemanticResourceReserver,
) -> Result<CounterRead, ReadStage> {
    let binding = session
        .counter_reader_binding()
        .map_err(bank_read_stage)?
        .ok_or(ReadStage::Shape)?;
    read_bound(binding, plan, objects, limits, reserve)
}

fn bank_read_stage(failure: crate::attach::counter_banks::BankRefusal) -> ReadStage {
    use crate::attach::counter_banks::BankRefusal;
    match failure {
        BankRefusal::Quarantined => ReadStage::BankQuarantined,
        _ => ReadStage::BankRouting,
    }
}

/// Acquires fresh rows from the exact prepared native owner. Limits and
/// reservation remain explicit inputs owned by the capture/admission caller.
pub(super) fn read_bound(
    binding: crate::attach::counter_banks::CounterReaderBinding<'_>,
    plan: &AttachPlan,
    objects: &crate::discovery::identity::PinnedObjects,
    limits: CounterLimits,
    reserve: &SemanticResourceReserver,
) -> Result<CounterRead, ReadStage> {
    let session = binding.session();
    let view = session
        .counter_bank_view(plan, objects)
        .map_err(bank_read_stage)?;
    let native = NativeSource::new(|name| session.ebpf.map(name), binding.mode())?;
    let fault = session
        .ebpf
        .map("COUNTER_BANK_FAULT")
        .ok_or(ReadStage::Health)?;
    shape(fault, MapType::PerCpuArray, 4, 8, 1)?;
    let source = BankedSource {
        native,
        view: &view,
        ebpf: &session.ebpf,
        fault: PerCpuArray::try_from(fault).map_err(|_| ReadStage::Health)?,
    };
    acquire(&source, binding.generation(), plan, limits, reserve)
}

/// Only I/O is replaceable: acquisition ordering, limits, precharge and checked
/// folds are shared with the native adapter. No method clears/writes a map.
trait CounterSource {
    fn mode(&self) -> CounterMode;
    fn possible_cpus(&self) -> usize;
    fn routing(&self) -> Result<Option<CounterIssue>, ReadStage> {
        Ok(None)
    }
    fn rv_keys(&self) -> impl Iterator<Item = Result<RvKey, ReadStage>> + '_;
    fn rv_total(&self, key: &RvKey) -> Result<Result<u64, CounterIssue>, ReadStage>;
    fn fold_row(
        &self,
        slot: &Slot,
        rvs: &[(RvKey, u64)],
        limits: CounterLimits,
    ) -> Result<Result<CounterRow, CounterIssue>, ReadStage>;
    fn health(&self) -> Result<CounterHealth, ReadStage>;
    fn kernel(&self) -> Result<KernelEvidence, ReadStage>;
    fn now(&self) -> Option<u64>;
}

fn transient_bytes(mode: CounterMode, cpus: usize, rv_keys: usize) -> Option<usize> {
    // Aya allocates an aligned raw per-CPU buffer, then grows a Vec from zero
    // before boxing it. For these <=1024B values Rust's minimum capacity is 4;
    // count raw+old/new typed requests and boxing overlap conservatively.
    // RV staging is reserved exactly; unstable sorting has no heap scratch.
    let value = usize::try_from(mode.stats_bytes())
        .ok()?
        .checked_next_multiple_of(8)?;
    let capacity = cpus.checked_next_power_of_two()?.max(4);
    let cells = cpus.checked_mul(2)?.checked_add(capacity.checked_mul(2)?)?;
    value
        .checked_mul(cells)?
        .checked_add(rv_keys.checked_mul(size_of::<(RvKey, u64)>())?)?
        .checked_add(5 * OWNED_ALLOCATION_PADDING)
}

fn acquire(
    source: &impl CounterSource,
    generation: NonZeroU64,
    plan: &AttachPlan,
    limits: CounterLimits,
    reserve: &SemanticResourceReserver,
) -> Result<CounterRead, ReadStage> {
    let started = source.now();
    if limits.rows > NATIVE_SLOTS
        || limits.rv_keys > NATIVE_RVS
        || plan.slots.len() > limits.rows
        || source.possible_cpus() == 0
        || plan.slots.iter().enumerate().any(|(index, slot)| {
            slot.index as usize != index
                || plan.slots[..index].iter().any(|previous| {
                    (previous.object, previous.file_offset) == (slot.object, slot.file_offset)
                })
        })
    {
        return Err(ReadStage::Shape);
    }
    let _transient = reserve
        .reserve(
            transient_bytes(source.mode(), source.possible_cpus(), limits.rv_keys)
                .ok_or(ReadStage::Budget)?,
        )
        .map_err(|_| ReadStage::Budget)?;
    let storage = ReadReservation::reserve(plan.slots.len(), limits.rv_keys, reserve)?;
    let mut rvs = Vec::with_capacity(limits.rv_keys);
    let mut issue = source.routing()?;
    // Do not use Aya's combined MapIter: it can internally skip missing keys
    // without exposing an iteration bound. Each key and lookup is explicit.
    if issue.is_none() {
        for key in source.rv_keys().take(limits.rv_keys + 1) {
            let key = key?;
            if rvs.len() == limits.rv_keys {
                issue = Some(CounterIssue::Limits);
                break;
            }
            if key._pad != 0 || !plan.slots.iter().any(|slot| slot.index == key.slot) {
                issue = Some(CounterIssue::Topology);
                break;
            }
            match source.rv_total(&key)? {
                Ok(total) => rvs.push((key, total)),
                Err(failure) => {
                    issue = Some(failure);
                    break;
                }
            }
        }
    }
    rvs.sort_unstable_by_key(|(key, _)| (key.slot, key.rv));
    if issue.is_none()
        && rvs
            .windows(2)
            .any(|pair| (pair[0].0.slot, pair[0].0.rv) == (pair[1].0.slot, pair[1].0.rv))
    {
        issue = Some(CounterIssue::Topology);
    }
    let rows = if let Some(issue) = issue {
        Err(issue)
    } else {
        let mut rows = Vec::with_capacity(plan.slots.len());
        let mut start = 0;
        for slot in &plan.slots {
            let end = start + rvs[start..].partition_point(|(key, _)| key.slot == slot.index);
            match source.fold_row(slot, &rvs[start..end], limits)? {
                Ok(row) => rows.push(row),
                Err(failure) => {
                    issue = Some(failure);
                    break;
                }
            }
            start = end;
        }
        issue.map_or(Ok(rows), Err)
    };
    // Required health is additional to START/RV/owner evidence. Even a known
    // fold/topology failure never fabricates successful missing-map reads.
    let health = source.health()?;
    let kernel = source.kernel()?;
    let rows = source.routing()?.map_or(rows, Err);
    let window = ReadWindow::new(started, source.now());
    CounterRead::new(
        generation,
        source.mode(),
        window,
        rows,
        health,
        kernel,
        storage,
    )
}

enum NativeStats<'a> {
    Counts(PerCpuArray<&'a MapData, CountStats>),
    Timestamps(PerCpuArray<&'a MapData, TimestampStats>),
    Latency(PerCpuArray<&'a MapData, SlotStats>),
}

struct NativeSource<'a> {
    mode: CounterMode,
    cpus: usize,
    stats: NativeStats<'a>,
    rvs: PerCpuHashMap<&'a MapData, RvKey, u64>,
    health: PerCpuArray<&'a MapData, u64>,
    evidence: PerCpuArray<&'a MapData, u64>,
    owner: Array<&'a MapData, ThreadOwnerControl>,
    cookie: Array<&'a MapData, ImageIdentityControl>,
    root: Array<&'a MapData, RootAffiliationControl>,
}

struct BankedSource<'a> {
    native: NativeSource<'a>,
    view: &'a crate::attach::counter_banks::CounterBankView,
    ebpf: &'a aya::Ebpf,
    fault: PerCpuArray<&'a MapData, u64>,
}

impl CounterSource for BankedSource<'_> {
    fn mode(&self) -> CounterMode {
        CounterMode::Counts
    }
    fn possible_cpus(&self) -> usize {
        self.native.cpus
    }
    fn routing(&self) -> Result<Option<CounterIssue>, ReadStage> {
        use crate::attach::counter_banks::BankReadStatus;
        let status = self
            .view
            .routing(self.ebpf)
            .map_err(|_| ReadStage::BankRouting)?;
        // This additional sticky native map is always sampled, independently
        // of ordinary counter health and all KernelEvidence/control cells.
        let values = self.fault.get(&0, 0).map_err(|_| ReadStage::Health)?;
        self.native.cpu_count(values.len(), ReadStage::Health)?;
        Ok(match status {
            BankReadStatus::Quarantined => Some(CounterIssue::BankQuarantined),
            BankReadStatus::Routing => Some(CounterIssue::BankRouting),
            BankReadStatus::Healthy if values.iter().any(|&value| value != 0) => {
                Some(CounterIssue::BankRouting)
            }
            BankReadStatus::Healthy => None,
        })
    }
    fn rv_keys(&self) -> impl Iterator<Item = Result<RvKey, ReadStage>> + '_ {
        self.native.rv_keys()
    }
    fn rv_total(&self, key: &RvKey) -> Result<Result<u64, CounterIssue>, ReadStage> {
        self.native.rv_total(key)
    }
    fn fold_row(
        &self,
        slot: &Slot,
        rvs: &[(RvKey, u64)],
        limits: CounterLimits,
    ) -> Result<Result<CounterRow, CounterIssue>, ReadStage> {
        let map = self.view.bank(slot.index).ok_or(ReadStage::Stats)?;
        shape(map, MapType::PerCpuArray, 4, 24, 1)?;
        let stats: PerCpuArray<_, CountStats> =
            PerCpuArray::try_from(map).map_err(|_| ReadStage::Stats)?;
        // Global physical slot chooses its retained bank. Only the actual
        // one-cell inner index is zero; RV keys retain the global slot/full64.
        let values = stats.get(&0, 0).map_err(|_| ReadStage::Stats)?;
        self.native.cpu_count(values.len(), ReadStage::Stats)?;
        Ok(CounterRow::fold(
            slot,
            CounterMode::Counts,
            values.iter().map(CounterCell::Counts),
            rvs.iter().copied(),
            limits,
        ))
    }
    fn health(&self) -> Result<CounterHealth, ReadStage> {
        self.native.health()
    }
    fn kernel(&self) -> Result<KernelEvidence, ReadStage> {
        self.native.kernel()
    }
    fn now(&self) -> Option<u64> {
        self.native.now()
    }
}

fn shape(
    map: &Map,
    kind: MapType,
    key: usize,
    value: usize,
    capacity: u32,
) -> Result<(), ReadStage> {
    let data = match map {
        Map::PerCpuArray(data)
        | Map::PerCpuHashMap(data)
        | Map::Array(data)
        | Map::HashMap(data) => data,
        _ => return Err(ReadStage::Shape),
    };
    let info = data.info().map_err(|_| ReadStage::Shape)?;
    if info.map_type().map_err(|_| ReadStage::Shape)? != kind
        || info.key_size() as usize != key
        || info.value_size() as usize != value
        || info.max_entries() != capacity
        || info.map_flags() != 0
    {
        return Err(ReadStage::Shape);
    }
    Ok(())
}

impl<'a> NativeSource<'a> {
    fn new(lookup: impl Fn(&str) -> Option<&'a Map>, mode: CounterMode) -> Result<Self, ReadStage> {
        let required = |name| lookup(name).ok_or(ReadStage::Shape);
        let stats = required("STATS")?;
        let rvs = required("RV_COUNTS")?;
        let starts = required("START")?;
        let health = required("COUNTER_HEALTH")?;
        let evidence = required("EVIDENCE")?;
        let owner = required("OWNER_CTL")?;
        let cookie = required("COOKIE_CTL")?;
        let root = required("ROOT_CTL")?;
        shape(
            stats,
            MapType::PerCpuArray,
            4,
            mode.stats_bytes() as usize,
            NATIVE_SLOTS as u32,
        )?;
        shape(
            rvs,
            MapType::PerCpuHash,
            size_of::<RvKey>(),
            8,
            NATIVE_RVS as u32,
        )?;
        shape(
            starts,
            MapType::Hash,
            size_of::<StartKey>(),
            size_of::<CallStart>(),
            NATIVE_STARTS,
        )?;
        shape(health, MapType::PerCpuArray, 4, 8, 2)?;
        shape(evidence, MapType::PerCpuArray, 4, 8, EVIDENCE_CELLS)?;
        shape(owner, MapType::Array, 4, size_of::<ThreadOwnerControl>(), 1)?;
        shape(
            cookie,
            MapType::Array,
            4,
            size_of::<ImageIdentityControl>(),
            1,
        )?;
        shape(
            root,
            MapType::Array,
            4,
            size_of::<RootAffiliationControl>(),
            1,
        )?;
        let cpus = aya::util::nr_cpus().map_err(|_| ReadStage::Shape)?;
        if cpus == 0 {
            return Err(ReadStage::Shape);
        }
        Ok(Self {
            mode,
            cpus,
            stats: match mode {
                CounterMode::Counts => {
                    NativeStats::Counts(PerCpuArray::try_from(stats).map_err(|_| ReadStage::Shape)?)
                }
                CounterMode::Timestamps => NativeStats::Timestamps(
                    PerCpuArray::try_from(stats).map_err(|_| ReadStage::Shape)?,
                ),
                CounterMode::Latency => NativeStats::Latency(
                    PerCpuArray::try_from(stats).map_err(|_| ReadStage::Shape)?,
                ),
            },
            rvs: PerCpuHashMap::try_from(rvs).map_err(|_| ReadStage::Shape)?,
            health: PerCpuArray::try_from(health).map_err(|_| ReadStage::Shape)?,
            evidence: PerCpuArray::try_from(evidence).map_err(|_| ReadStage::Shape)?,
            owner: Array::try_from(owner).map_err(|_| ReadStage::Shape)?,
            cookie: Array::try_from(cookie).map_err(|_| ReadStage::Shape)?,
            root: Array::try_from(root).map_err(|_| ReadStage::Shape)?,
        })
    }

    fn cpu_count(&self, count: usize, stage: ReadStage) -> Result<(), ReadStage> {
        if count == self.cpus {
            Ok(())
        } else {
            Err(stage)
        }
    }
}

impl CounterSource for NativeSource<'_> {
    fn mode(&self) -> CounterMode {
        self.mode
    }
    fn possible_cpus(&self) -> usize {
        self.cpus
    }
    fn rv_keys(&self) -> impl Iterator<Item = Result<RvKey, ReadStage>> + '_ {
        self.rvs.keys().map(|key| key.map_err(|_| ReadStage::Rvs))
    }
    fn rv_total(&self, key: &RvKey) -> Result<Result<u64, CounterIssue>, ReadStage> {
        let values = self.rvs.get(key, 0).map_err(|_| ReadStage::Rvs)?;
        self.cpu_count(values.len(), ReadStage::Rvs)?;
        Ok(values.iter().try_fold(0u64, |total, &value| {
            total
                .checked_add(value)
                .ok_or(CounterIssue::FoldOverflow(CounterField::Rv(key.rv)))
        }))
    }
    fn fold_row(
        &self,
        slot: &Slot,
        rvs: &[(RvKey, u64)],
        limits: CounterLimits,
    ) -> Result<Result<CounterRow, CounterIssue>, ReadStage> {
        let rvs = || rvs.iter().copied();
        Ok(match &self.stats {
            NativeStats::Counts(stats) => {
                let values = stats.get(&slot.index, 0).map_err(|_| ReadStage::Stats)?;
                self.cpu_count(values.len(), ReadStage::Stats)?;
                CounterRow::fold(
                    slot,
                    self.mode,
                    values.iter().map(CounterCell::Counts),
                    rvs(),
                    limits,
                )
            }
            NativeStats::Timestamps(stats) => {
                let values = stats.get(&slot.index, 0).map_err(|_| ReadStage::Stats)?;
                self.cpu_count(values.len(), ReadStage::Stats)?;
                CounterRow::fold(
                    slot,
                    self.mode,
                    values.iter().map(CounterCell::Timestamps),
                    rvs(),
                    limits,
                )
            }
            NativeStats::Latency(stats) => {
                let values = stats.get(&slot.index, 0).map_err(|_| ReadStage::Stats)?;
                self.cpu_count(values.len(), ReadStage::Stats)?;
                CounterRow::fold(
                    slot,
                    self.mode,
                    values.iter().map(CounterCell::Latency),
                    rvs(),
                    limits,
                )
            }
        })
    }
    fn health(&self) -> Result<CounterHealth, ReadStage> {
        let read = |index| -> Result<bool, ReadStage> {
            let values = self.health.get(&index, 0).map_err(|_| ReadStage::Health)?;
            self.cpu_count(values.len(), ReadStage::Health)?;
            Ok(values.iter().any(|&value| value != 0))
        };
        Ok(CounterHealth {
            saturated: read(0)?,
            contended: read(1)?,
        })
    }
    fn kernel(&self) -> Result<KernelEvidence, ReadStage> {
        let owner = self
            .owner
            .get(&0, 0)
            .map_err(|_| ReadStage::KernelEvidence)?;
        let cookie = self
            .cookie
            .get(&0, 0)
            .map_err(|_| ReadStage::KernelEvidence)?;
        let root = self
            .root
            .get(&0, 0)
            .map_err(|_| ReadStage::KernelEvidence)?;
        if owner.limit != u64::from(NATIVE_STARTS) + 64
            || cookie.limit != IMAGE_IDENTITY_TICKET_LIMIT
        {
            return Err(ReadStage::KernelEvidence);
        }
        let read = |index| -> Result<u64, ReadStage> {
            let values = self
                .evidence
                .get(&index, 0)
                .map_err(|_| ReadStage::KernelEvidence)?;
            self.cpu_count(values.len(), ReadStage::KernelEvidence)?;
            Ok(saturating_total(values.iter().copied()))
        };
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
            control: KernelControl::from_cells(Some(owner), Some(cookie), Some(root)),
        })
    }
    fn now(&self) -> Option<u64> {
        crate::attach::monotonic_ns()
    }
}

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
        routing: Option<CounterIssue>,
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
                routing: None,
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
        fn routing(&self) -> Result<Option<CounterIssue>, ReadStage> {
            Ok(self.routing)
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
    fn banked_reader_preserves_physical_prefix_and_routing_health() {
        let pool = test_pool();
        let mut collector = CounterCollector::new(LIMITS, pool.reserver());
        assert_eq!(
            collector.observe(acquire(
                &Scripted::sample(CounterMode::Counts, false),
                NonZeroU64::new(5).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver(),
            )),
            CounterObservation::Initial,
        );
        match collector.observe(acquire(
            &Scripted::sample(CounterMode::Counts, true),
            NonZeroU64::new(5).unwrap(),
            &plan(),
            LIMITS,
            &pool.reserver(),
        )) {
            CounterObservation::Advanced { deltas, .. } => {
                assert_eq!((deltas[0].entered, deltas[0].returned), (5, 4));
                assert_eq!(deltas[0].target.object, PinnedObjectId(1));
                assert_eq!(deltas[1].target.object, PinnedObjectId(2));
                assert_eq!(deltas[0].rv_counts.get(&HIGH_RV), Some(&1));
            }
            other => panic!("two real physical rows must remain distinct: {other:?}"),
        }
        for issue in [CounterIssue::BankRouting, CounterIssue::BankQuarantined] {
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            let mut damaged = Scripted::sample(CounterMode::Counts, true);
            damaged.routing = Some(issue);
            let read = acquire(
                &damaged,
                NonZeroU64::new(6).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver(),
            )
            .unwrap();
            assert_eq!(
                damaged.rv_reads.get(),
                0,
                "known poisoned routing must not sample rows"
            );
            assert_eq!(
                damaged.accesses.get(),
                2,
                "health and kernel controls still read"
            );
            assert_eq!(
                collector.observe(Ok(read)),
                CounterObservation::Unavailable(issue)
            );
            assert_eq!(
                collector.observe(acquire(
                    &Scripted::sample(CounterMode::Counts, true),
                    NonZeroU64::new(6).unwrap(),
                    &plan(),
                    LIMITS,
                    &pool.reserver(),
                )),
                CounterObservation::Unavailable(issue),
                "same-generation clean cells cannot erase routing/quarantine loss",
            );
        }
        let mut damaged = Scripted::sample(CounterMode::Counts, true);
        damaged.routing = Some(CounterIssue::BankRouting);
        damaged.fail = Some(ReadStage::KernelEvidence);
        assert!(matches!(
            acquire(
                &damaged,
                NonZeroU64::new(7).unwrap(),
                &plan(),
                LIMITS,
                &pool.reserver()
            ),
            Err(ReadStage::KernelEvidence),
        ));
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

    fn native_pair_values<T: aya::Pod + Copy>(ends: [T; 2], zero: T) -> PerCpuValues<T> {
        let count = aya::util::nr_cpus().unwrap();
        assert!(
            count >= 2,
            "native counter positives require at least two possible CPUs"
        );
        let mut values = vec![zero; count];
        values[0] = ends[0];
        values[count - 1] = ends[1];
        PerCpuValues::try_from(values).unwrap()
    }

    fn write_native(maps: &mut BTreeMap<&'static str, Map>, mode: CounterMode, later: bool) {
        let source = Scripted::sample(mode, later);
        for index in [0, 1] {
            let mut first = source.stats[&index][0];
            let mut last = SlotStats::ZERO;
            if index == 0 {
                // Preserve literal aggregate 3/5/1/50/20 -> 8/9/2/90/25,
                // but require the reader to consume a nonzero last CPU.
                last.entered = if later { 3 } else { 1 };
                last.returned = if later { 4 } else { 2 };
                last.errors = u64::from(later);
                last.total_ns = if later { 30 } else { 20 };
                last.max_ns = if later { 18 } else { 15 };
                last.buckets[7] = if later { 2 } else { 1 };
                last.buckets[31] = if later { 2 } else { 1 };
                first.entered -= last.entered;
                first.returned -= last.returned;
                first.errors -= last.errors;
                first.total_ns -= last.total_ns;
                first.buckets[7] -= last.buckets[7];
                first.buckets[31] -= last.buckets[31];
            } else {
                last = first;
                first = SlotStats::ZERO;
            }
            let cells = [first, last];
            match mode {
                CounterMode::Counts => {
                    PerCpuArray::<_, CountStats>::try_from(maps.get_mut("STATS").unwrap())
                        .unwrap()
                        .set(
                            index,
                            native_pair_values(
                                cells.map(|cell| CountStats {
                                    entered: cell.entered,
                                    returned: cell.returned,
                                    errors: cell.errors,
                                }),
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
                            native_pair_values(
                                cells.map(|cell| TimestampStats {
                                    entered: cell.entered,
                                    returned: cell.returned,
                                    errors: cell.errors,
                                    total_ns: cell.total_ns,
                                    max_ns: cell.max_ns,
                                }),
                                TimestampStats::default(),
                            ),
                            0,
                        )
                        .unwrap()
                }
                CounterMode::Latency => {
                    PerCpuArray::<_, SlotStats>::try_from(maps.get_mut("STATS").unwrap())
                        .unwrap()
                        .set(index, native_pair_values(cells, SlotStats::ZERO), 0)
                        .unwrap()
                }
            }
        }
        let mut rvs =
            PerCpuHashMap::<_, RvKey, u64>::try_from(maps.get_mut("RV_COUNTS").unwrap()).unwrap();
        for (key, values) in source.rvs {
            let last = if later && key.rv != HIGH_RV { 2 } else { 1 };
            rvs.insert(key, native_pair_values([values[0] - last, last], 0), 0)
                .unwrap();
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
                .set(index, native_pair_values([0, 1], 0), 0)
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

    #[test]
    #[ignore = "requires explicitly prebuilt LP64 counter-banks fixtures and authorized native attach"]
    fn counter_bank_session_old_return_survives_append_lp64() {
        use crate::attach::Scope;
        use crate::attach::counter_banks::{BankPublication, BankReservation};
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::path::{Path, PathBuf};
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        struct OwnedFixture(Child);
        impl Drop for OwnedFixture {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        impl OwnedFixture {
            fn token(&mut self, expected: &str) {
                let deadline = Instant::now() + Duration::from_secs(5);
                let output = self.0.stdout.as_mut().unwrap();
                let mut line = Vec::new();
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    assert!(
                        !remaining.is_zero(),
                        "owned counter fixture barrier timed out"
                    );
                    let mut poll = libc::pollfd {
                        fd: output.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let millis = i32::try_from(remaining.as_millis().max(1)).unwrap();
                    // SAFETY: one initialized pollfd is live for the finite call.
                    let ready = unsafe { libc::poll(&mut poll, 1, millis) };
                    if ready < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    assert!(ready > 0, "owned fixture did not reach its next barrier");
                    let mut byte = [0u8; 1];
                    output.read_exact(&mut byte).unwrap();
                    if byte[0] == b'\n' {
                        break;
                    }
                    assert!(line.len() < 16, "fixture emits only finite protocol tokens");
                    line.push(byte[0]);
                }
                assert_eq!(line, expected.as_bytes());
            }
            fn command(&mut self, byte: u8) {
                self.0.stdin.as_mut().unwrap().write_all(&[byte]).unwrap();
            }
        }

        assert_eq!(
            env!("P11SCOPE_COUNTER_BANK_PROOF_ENABLED"),
            "1",
            "actual proof artifact is required"
        );
        let provider = PathBuf::from(
            std::env::var_os("P11SCOPE_COUNTER_BANK_FIXTURE_PROVIDER")
                .expect("prebuild tests/fixtures/counter-banks.c with -DCOUNTER_BANK_PROVIDER"),
        );
        let workload = PathBuf::from(
            std::env::var_os("P11SCOPE_COUNTER_BANK_FIXTURE_WORKLOAD")
                .expect("prebuild the same fixture's dlopen/pthread driver"),
        );
        let mut file = std::fs::File::open(&provider).unwrap();
        let elf = p11scope_manifest::elf::ElfSnapshot::read(&file).unwrap();
        assert_eq!(elf.abi(), p11scope_manifest::elf::ElfAbi::Lp64);
        let old_offset = elf
            .defined_symbol("counter_bank_old")
            .unwrap()
            .unwrap()
            .file_offset;
        let hot_offset = elf
            .defined_symbol("counter_bank_hot")
            .unwrap()
            .unwrap()
            .file_offset;
        assert_ne!(old_offset, hot_offset);
        assert!(elf.is_executable_offset(old_offset) && elf.is_executable_offset(hot_offset));
        let mut provider_bytes = Vec::new();
        file.read_to_end(&mut provider_bytes).unwrap();
        use sha2::Digest;
        let digest: String = sha2::Sha256::digest(&provider_bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        // Fixture-only explicit pin: real opened file/metadata/digest/ELF
        // offsets. This cell grants no discovery or semantic authority.
        let pins =
            crate::discovery::identity::test_fixture::real_scan_pin(&provider, None, 1, &digest);
        let object = pins.pinned().next().unwrap().id;
        use std::os::unix::fs::MetadataExt;
        let selected = file.metadata().unwrap();
        let pinned = pins.file_for(object).unwrap().metadata().unwrap();
        assert_eq!(
            (selected.dev(), selected.ino()),
            (pinned.dev(), pinned.ino())
        );
        let mut old = slot(0, 0);
        old.object = object;
        old.object_path = provider.to_string_lossy().into_owned();
        old.file_offset = old_offset;
        old.names = vec!["counter_bank_old".into()];
        let mut hot = old.clone();
        hot.index = 1;
        hot.file_offset = hot_offset;
        hot.names = vec!["counter_bank_hot".into()];
        let policy =
            crate::plan::AdmissionPolicy::counters(crate::capacity::CounterBudget::new(2).unwrap());
        let first = AttachPlan::from_slots_with_policy(vec![old.clone()], policy).unwrap();
        let grown = AttachPlan::from_slots_with_policy(vec![old, hot], policy).unwrap();

        let child = Command::new(&workload)
            .arg(&provider)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut fixture = OwnedFixture(child);
        fixture.token("READY");
        let cpus = aya::util::nr_cpus().unwrap();
        let pool = SemanticResourcePool::reference_limit(512 * 1024 * 1024);
        let base = BankReservation {
            retained_bytes: 128 * 1024 * 1024,
            transient_bytes: 64 * 1024 * 1024,
            metadata_bytes: 32 * 1024 * 1024,
            file_descriptors: cpus.checked_mul(4).unwrap() + 512,
        };
        let stage = BankReservation {
            retained_bytes: 1024 * 1024,
            transient_bytes: 1024 * 1024,
            metadata_bytes: 256 * 1024,
            file_descriptors: cpus.checked_mul(8).unwrap() + 16,
        };
        let bytes = std::fs::read(
            Path::new(env!("OUT_DIR")).join("counter-bank-proof/p11scope-ebpf-counts-bank-proof"),
        )
        .unwrap();
        let mut session = Session::prepare_counter_banks(
            &Scope::Pid(fixture.0.id()),
            &bytes,
            base,
            &pool.reserver(),
        )
        .unwrap();
        let limits = CounterLimits {
            rows: 2,
            rv_keys: 4,
        };
        let BankPublication::Published {
            transaction: old_transaction,
            mask: 1,
        } = session.stage_counter_banks(&first, &pins, stage, &pool.reserver())
        else {
            panic!("first actual bank did not publish");
        };
        let binding = session.counter_reader_binding().unwrap().unwrap();
        assert_eq!(binding.mode(), CounterMode::Counts);
        assert_eq!(
            binding.generation(),
            session.counter_collection_generation()
        );
        assert_eq!(binding.logical_slots(), 512);
        assert_eq!(binding.rv_keys(), 4096);
        assert_eq!(binding.start_rows(), 16384);
        assert_eq!(binding.possible_cpus(), cpus);
        assert!(read_bound(binding, &first, &pins, limits, &pool.reserver()).is_ok());
        let foreign = crate::discovery::identity::test_fixture::real_scan_pin(
            Path::new("/usr/bin/true"),
            None,
            1,
            "foreign-provider-content",
        );
        assert!(
            matches!(
                read_bound(
                    session.counter_reader_binding().unwrap().unwrap(),
                    &first,
                    &foreign,
                    limits,
                    &pool.reserver(),
                ),
                Err(ReadStage::BankRouting)
            ),
            "a present binding must still validate the actual provider plan"
        );
        let mut collector = CounterCollector::new(limits, pool.reserver());
        assert_eq!(
            collector.observe(read_banked(
                &session,
                &first,
                &pins,
                limits,
                &pool.reserver()
            )),
            CounterObservation::Initial
        );

        fixture.command(b'S');
        fixture.token("HELD");
        let starts: aya::maps::HashMap<_, StartKey, CallStart> =
            aya::maps::HashMap::try_from(session.ebpf.map("START").unwrap()).unwrap();
        let keys: Vec<_> = starts.keys().take(2).collect::<Result<_, _>>().unwrap();
        assert_eq!(
            keys.len(),
            1,
            "a genuine old START is held across publication"
        );
        assert_eq!(keys[0].slot, 0);
        assert_eq!(starts.get(&keys[0], 0).unwrap().object_required, 0);
        match collector.observe(read_banked(
            &session,
            &first,
            &pins,
            limits,
            &pool.reserver(),
        )) {
            CounterObservation::Advanced { deltas, .. } => {
                assert_eq!((deltas[0].entered, deltas[0].returned), (1, 0))
            }
            other => panic!("actual held entry was not collected: {other:?}"),
        }
        let BankPublication::Published {
            transaction: new_transaction,
            mask: 2,
        } = session.stage_counter_banks(&grown, &pins, stage, &pool.reserver())
        else {
            panic!("actual append did not publish");
        };
        assert!(new_transaction > old_transaction);
        fixture.command(b'H');
        fixture.token("HOT");
        match collector.observe(read_banked(
            &session,
            &grown,
            &pins,
            limits,
            &pool.reserver(),
        )) {
            CounterObservation::Advanced { deltas, .. } => {
                assert_eq!((deltas[0].entered, deltas[0].returned), (0, 0));
                assert_eq!(
                    (deltas[1].entered, deltas[1].returned, deltas[1].errors),
                    (1, 1, 1)
                );
                assert_eq!(deltas[1].rv_counts.get(&0x1_0000_0204), Some(&1));
            }
            other => panic!("actual new hot bank was not collected: {other:?}"),
        }
        fixture.command(b'R');
        fixture.token("DONE");
        assert!(fixture.0.wait().unwrap().success());
        match collector.observe(read_banked(
            &session,
            &grown,
            &pins,
            limits,
            &pool.reserver(),
        )) {
            CounterObservation::Advanced { deltas, .. } => {
                assert_eq!(
                    (deltas[0].entered, deltas[0].returned, deltas[0].errors),
                    (0, 1, 0)
                );
                assert_eq!(deltas[0].rv_counts.get(&0x204), Some(&1));
                assert_eq!((deltas[1].entered, deltas[1].returned), (0, 0));
            }
            other => panic!("old-bank return did not survive the new transaction: {other:?}"),
        }
        session.stop_gate().request_stop();
        session
            .detach_producers_driven(|| false, &mut Vec::new())
            .unwrap();
        assert!(session.producers_detached());
        assert!(session.stop_gate().quiescent());
        let starts: aya::maps::HashMap<_, StartKey, CallStart> =
            aya::maps::HashMap::try_from(session.ebpf.map("START").unwrap()).unwrap();
        assert!(starts.keys().next().is_none());
        let owner =
            Array::<_, ThreadOwnerControl>::try_from(session.ebpf.map("OWNER_CTL").unwrap())
                .unwrap()
                .get(&0, 0)
                .unwrap();
        assert_eq!(
            (owner.outstanding, owner.poison, owner.abandoned_start),
            (0, 0, 0)
        );
        // No quiet optional NULL is counted as settlement; the actual old
        // START, full64 RV, both return credits and native cleanup were read.
        drop(collector);
        drop(session);
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH,
            "actual native owners and collected storage refund only after drop"
        );
    }
}
