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

/// The exact check behind a [`ReadStage::Shape`]. One variant per refusal
/// origin, so diagnostics name the failing gate; the public refusal token
/// stays undifferentiated. The shared map-shape helper takes the caller's
/// variant, so each checked map keeps its own cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReaderShapeCause {
    BankInnerShape,
    BindingAbsent,
    CookieMapMissing,
    CookieShape,
    CookieView,
    CpuCountMismatch,
    CpuCountUnavailable,
    DuplicateTargets,
    EvidenceMapMissing,
    EvidenceShape,
    EvidenceView,
    FaultShape,
    HealthMapMissing,
    HealthShape,
    HealthView,
    OwnerMapMissing,
    OwnerShape,
    OwnerView,
    PlanLimitsMismatch,
    PublishedIndexDuplicate,
    PublishedIndexMissing,
    RootMapMissing,
    RootShape,
    RootView,
    RvKeysOverflow,
    RvMapMissing,
    RvShape,
    RvView,
    SnapshotModeMismatch,
    StartsMapMissing,
    StartsShape,
    StatsMapMissing,
    StatsShape,
    StatsViewCounts,
    StatsViewLatency,
    StatsViewTimestamps,
}

impl ReaderShapeCause {
    pub(super) const ALL: [Self; 36] = [
        Self::BankInnerShape,
        Self::BindingAbsent,
        Self::CookieMapMissing,
        Self::CookieShape,
        Self::CookieView,
        Self::CpuCountMismatch,
        Self::CpuCountUnavailable,
        Self::DuplicateTargets,
        Self::EvidenceMapMissing,
        Self::EvidenceShape,
        Self::EvidenceView,
        Self::FaultShape,
        Self::HealthMapMissing,
        Self::HealthShape,
        Self::HealthView,
        Self::OwnerMapMissing,
        Self::OwnerShape,
        Self::OwnerView,
        Self::PlanLimitsMismatch,
        Self::PublishedIndexDuplicate,
        Self::PublishedIndexMissing,
        Self::RootMapMissing,
        Self::RootShape,
        Self::RootView,
        Self::RvKeysOverflow,
        Self::RvMapMissing,
        Self::RvShape,
        Self::RvView,
        Self::SnapshotModeMismatch,
        Self::StartsMapMissing,
        Self::StartsShape,
        Self::StatsMapMissing,
        Self::StatsShape,
        Self::StatsViewCounts,
        Self::StatsViewLatency,
        Self::StatsViewTimestamps,
    ];
}

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

/// Private bank bridge for every prepared counter mode. The view shares the
/// original map handles and leases; creating a scrape opens no inner-map FD
/// or new cursor.
#[allow(dead_code)] // Private validated bank bridge; no public/runtime reader activation.
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
        .ok_or(ReadStage::Shape(ReaderShapeCause::BindingAbsent))?;
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
        .counter_bank_view(plan, objects, reserve)
        .map_err(bank_read_stage)?;
    // Bank objects carry the legacy 24-byte aggregate template in every
    // mode; only the bank cells vary. The read mode still comes from the
    // prepared binding.
    let native = NativeSource::with_bounds(
        |name| session.ebpf.map(name),
        binding.mode(),
        CounterMode::Counts,
        binding.rv_keys(),
        binding.start_rows(),
        Some(binding.possible_cpus()),
    )?;
    let fault = session
        .ebpf
        .map("COUNTER_BANK_FAULT")
        .ok_or(ReadStage::Health)?;
    shape(
        fault,
        MapType::PerCpuArray,
        4,
        8,
        1,
        ReaderShapeCause::FaultShape,
    )?;
    let source = BankedSource {
        native,
        view: &view,
        ebpf: &session.ebpf,
        fault: PerCpuArray::try_from(fault).map_err(|_| ReadStage::Health)?,
        plan,
        objects,
    };
    acquire(&source, binding.generation(), plan, limits, reserve)
}

/// Only I/O is replaceable: acquisition ordering, limits, precharge and checked
/// folds are shared with the native adapter. No method clears/writes a map.
trait CounterSource {
    fn mode(&self) -> CounterMode;
    fn possible_cpus(&self) -> usize;
    fn published_snapshot(
        &self,
    ) -> Option<&crate::attach::counter_banks::CounterPublishedSnapshot> {
        None
    }
    fn routing(&self) -> Result<Option<CounterIssue>, ReadStage> {
        Ok(None)
    }
    fn rv_exhausted(&self) -> Result<bool, ReadStage> {
        Ok(false)
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
    let published = source.published_snapshot(); // Borrow once; never clone a view or its lease.
    let (logical_slots, rv_limit, row_count) = match published {
        Some(snapshot) => {
            if source.mode() != snapshot.mode()
                || source.possible_cpus() != snapshot.possible_cpus()
            {
                return Err(ReadStage::Shape(ReaderShapeCause::SnapshotModeMismatch));
            }
            snapshot.validate_plan(plan).map_err(bank_read_stage)?;
            (
                snapshot.logical_slots(),
                snapshot.rv_keys(),
                snapshot.original_indices().len(),
            )
        }
        None => (NATIVE_SLOTS, NATIVE_RVS, plan.slots.len()),
    };
    if limits.rows > logical_slots
        || limits.rv_keys > rv_limit
        || row_count > limits.rows
        || plan.slots.len() > logical_slots
        || source.possible_cpus() == 0
        || plan
            .slots
            .iter()
            .enumerate()
            .any(|(index, slot)| slot.index as usize != index)
    {
        return Err(ReadStage::Shape(ReaderShapeCause::PlanLimitsMismatch));
    }
    let transient = transient_bytes(source.mode(), source.possible_cpus(), limits.rv_keys)
        .and_then(|n| n.checked_add(logical_slots))
        .and_then(|n| n.checked_add(row_count.checked_mul(size_of::<crate::plan::AttachKey>())?))
        .and_then(|n| n.checked_add(2 * OWNED_ALLOCATION_PADDING))
        .ok_or(ReadStage::Budget)?;
    let _transient = reserve.reserve(transient).map_err(|_| ReadStage::Budget)?;
    let storage = ReadReservation::reserve(row_count, limits.rv_keys, reserve)?;
    let mut membership = vec![0u8; logical_slots];
    let mut targets = Vec::with_capacity(row_count);
    if let Some(snapshot) = published {
        for &index in snapshot.original_indices() {
            let slot = plan
                .slots
                .get(index as usize)
                .ok_or(ReadStage::Shape(ReaderShapeCause::PublishedIndexMissing))?;
            if membership[index as usize] != 0 {
                return Err(ReadStage::Shape(ReaderShapeCause::PublishedIndexDuplicate));
            }
            membership[index as usize] = 1;
            targets.push(crate::plan::AttachKey {
                object: slot.object,
                file_offset: slot.file_offset,
            });
        }
    } else {
        for slot in &plan.slots {
            membership[slot.index as usize] = 1;
            targets.push(crate::plan::AttachKey {
                object: slot.object,
                file_offset: slot.file_offset,
            });
        }
    }
    targets.sort_unstable();
    if targets.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ReadStage::Shape(ReaderShapeCause::DuplicateTargets));
    }

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
            if key._pad != 0 || membership.get(key.slot as usize) != Some(&1) {
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
        let mut rows = Vec::with_capacity(row_count);
        let mut start = 0;
        // One dense original-index scan plus one advancing RV cursor. Holes
        // cannot create rows or accept RVs, and published inactivity is kept.
        for slot in plan
            .slots
            .iter()
            .filter(|slot| membership[slot.index as usize] != 0)
        {
            let mut end = start;
            while end < rvs.len() && rvs[end].0.slot == slot.index {
                end += 1;
            }
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
    plan: &'a AttachPlan,
    objects: &'a crate::discovery::identity::PinnedObjects,
}

impl CounterSource for BankedSource<'_> {
    fn mode(&self) -> CounterMode {
        self.native.mode
    }
    fn possible_cpus(&self) -> usize {
        self.native.cpus
    }
    fn published_snapshot(
        &self,
    ) -> Option<&crate::attach::counter_banks::CounterPublishedSnapshot> {
        Some(self.view.snapshot())
    }
    fn routing(&self) -> Result<Option<CounterIssue>, ReadStage> {
        use crate::attach::counter_banks::{
            BANK_ROUTE_FAULT, BANK_RV_FAULT, BANK_SCOPE_FAULT, BANK_START_FAULT, BankReadStatus,
        };
        let status = self
            .view
            .routing(self.ebpf, self.plan, self.objects)
            .map_err(|_| ReadStage::BankRouting)?;
        // This additional sticky native map is always sampled, independently
        // of ordinary counter health and all KernelEvidence/control cells.
        let values = self.fault.get(&0, 0).map_err(|_| ReadStage::Health)?;
        self.native.cpu_count(values.len(), ReadStage::Health)?;
        let bits = values.iter().fold(0u64, |bits, &value| bits | value);
        let fatal = BANK_ROUTE_FAULT | BANK_START_FAULT | BANK_SCOPE_FAULT;
        Ok(match status {
            BankReadStatus::Quarantined => Some(CounterIssue::BankQuarantined),
            BankReadStatus::Routing => Some(CounterIssue::BankRouting),
            BankReadStatus::Healthy if bits & fatal != 0 => Some(CounterIssue::BankRouting),
            // An RV-only fault keeps endpoint counts exact; the RV table is a
            // lower bound reported via `rv_exhausted`, and existing keys keep
            // counting.
            BankReadStatus::Healthy if bits & !BANK_RV_FAULT == 0 => None,
            BankReadStatus::Healthy => Some(CounterIssue::BankRouting),
        })
    }
    fn rv_exhausted(&self) -> Result<bool, ReadStage> {
        use crate::attach::counter_banks::BANK_RV_FAULT;
        let values = self.fault.get(&0, 0).map_err(|_| ReadStage::Health)?;
        self.native.cpu_count(values.len(), ReadStage::Health)?;
        Ok(values.iter().fold(0u64, |bits, &value| bits | value) & BANK_RV_FAULT != 0)
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
        let (map, cell) = self.view.bank_cell(slot.index).ok_or(ReadStage::Stats)?;
        let cells = if self.view.snapshot().logical_slots() == 8192 {
            512
        } else {
            1
        };
        // The original logical slot selects its retained bank and cell;
        // RV and START identities retain that original slot and full64 RV.
        // The cell width comes from the prepared mode, matching the bank.
        let mode = self.mode();
        shape(
            map,
            MapType::PerCpuArray,
            4,
            mode.stats_bytes() as usize,
            cells,
            ReaderShapeCause::BankInnerShape,
        )?;
        let rvs = || rvs.iter().copied();
        Ok(match mode {
            CounterMode::Counts => {
                let stats: PerCpuArray<_, CountStats> =
                    PerCpuArray::try_from(map).map_err(|_| ReadStage::Stats)?;
                let values = stats.get(&cell, 0).map_err(|_| ReadStage::Stats)?;
                self.native.cpu_count(values.len(), ReadStage::Stats)?;
                CounterRow::fold(
                    slot,
                    mode,
                    values.iter().map(CounterCell::Counts),
                    rvs(),
                    limits,
                )
            }
            CounterMode::Timestamps => {
                let stats: PerCpuArray<_, TimestampStats> =
                    PerCpuArray::try_from(map).map_err(|_| ReadStage::Stats)?;
                let values = stats.get(&cell, 0).map_err(|_| ReadStage::Stats)?;
                self.native.cpu_count(values.len(), ReadStage::Stats)?;
                CounterRow::fold(
                    slot,
                    mode,
                    values.iter().map(CounterCell::Timestamps),
                    rvs(),
                    limits,
                )
            }
            CounterMode::Latency => {
                let stats: PerCpuArray<_, SlotStats> =
                    PerCpuArray::try_from(map).map_err(|_| ReadStage::Stats)?;
                let values = stats.get(&cell, 0).map_err(|_| ReadStage::Stats)?;
                self.native.cpu_count(values.len(), ReadStage::Stats)?;
                CounterRow::fold(
                    slot,
                    mode,
                    values.iter().map(CounterCell::Latency),
                    rvs(),
                    limits,
                )
            }
        })
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
    cause: ReaderShapeCause,
) -> Result<(), ReadStage> {
    let data = match map {
        Map::PerCpuArray(data)
        | Map::PerCpuHashMap(data)
        | Map::Array(data)
        | Map::HashMap(data) => data,
        _ => return Err(ReadStage::Shape(cause)),
    };
    let info = data.info().map_err(|_| ReadStage::Shape(cause))?;
    if info.map_type().map_err(|_| ReadStage::Shape(cause))? != kind
        || info.key_size() as usize != key
        || info.value_size() as usize != value
        || info.max_entries() != capacity
        || info.map_flags() != 0
    {
        return Err(ReadStage::Shape(cause));
    }
    Ok(())
}

/// Selects the stats template for the typed stats view. Bank objects carry
/// the legacy 24-byte aggregate in every mode; only the bank cells vary with
/// the read mode, so the view follows the aggregate template, never the mode.
fn stats_view_shape(_mode: CounterMode, stats_shape: CounterMode) -> CounterMode {
    stats_shape
}

impl<'a> NativeSource<'a> {
    fn new(lookup: impl Fn(&str) -> Option<&'a Map>, mode: CounterMode) -> Result<Self, ReadStage> {
        // Fixed native artifacts carry a per-mode STATS template.
        Self::with_bounds(lookup, mode, mode, NATIVE_RVS, NATIVE_STARTS, None)
    }

    fn with_bounds(
        lookup: impl Fn(&str) -> Option<&'a Map>,
        mode: CounterMode,
        stats_shape: CounterMode,
        rv_keys: usize,
        start_rows: u32,
        expected_cpus: Option<usize>,
    ) -> Result<Self, ReadStage> {
        let stats = lookup("STATS").ok_or(ReadStage::Shape(ReaderShapeCause::StatsMapMissing))?;
        let rvs = lookup("RV_COUNTS").ok_or(ReadStage::Shape(ReaderShapeCause::RvMapMissing))?;
        let starts = lookup("START").ok_or(ReadStage::Shape(ReaderShapeCause::StartsMapMissing))?;
        let health =
            lookup("COUNTER_HEALTH").ok_or(ReadStage::Shape(ReaderShapeCause::HealthMapMissing))?;
        let evidence =
            lookup("EVIDENCE").ok_or(ReadStage::Shape(ReaderShapeCause::EvidenceMapMissing))?;
        let owner =
            lookup("OWNER_CTL").ok_or(ReadStage::Shape(ReaderShapeCause::OwnerMapMissing))?;
        let cookie =
            lookup("COOKIE_CTL").ok_or(ReadStage::Shape(ReaderShapeCause::CookieMapMissing))?;
        let root = lookup("ROOT_CTL").ok_or(ReadStage::Shape(ReaderShapeCause::RootMapMissing))?;
        shape(
            stats,
            MapType::PerCpuArray,
            4,
            stats_shape.stats_bytes() as usize,
            NATIVE_SLOTS as u32,
            ReaderShapeCause::StatsShape,
        )?;
        shape(
            rvs,
            MapType::PerCpuHash,
            size_of::<RvKey>(),
            8,
            u32::try_from(rv_keys)
                .map_err(|_| ReadStage::Shape(ReaderShapeCause::RvKeysOverflow))?,
            ReaderShapeCause::RvShape,
        )?;
        shape(
            starts,
            MapType::Hash,
            size_of::<StartKey>(),
            size_of::<CallStart>(),
            start_rows,
            ReaderShapeCause::StartsShape,
        )?;
        shape(
            health,
            MapType::PerCpuArray,
            4,
            8,
            2,
            ReaderShapeCause::HealthShape,
        )?;
        shape(
            evidence,
            MapType::PerCpuArray,
            4,
            8,
            EVIDENCE_CELLS,
            ReaderShapeCause::EvidenceShape,
        )?;
        shape(
            owner,
            MapType::Array,
            4,
            size_of::<ThreadOwnerControl>(),
            1,
            ReaderShapeCause::OwnerShape,
        )?;
        shape(
            cookie,
            MapType::Array,
            4,
            size_of::<ImageIdentityControl>(),
            1,
            ReaderShapeCause::CookieShape,
        )?;
        shape(
            root,
            MapType::Array,
            4,
            size_of::<RootAffiliationControl>(),
            1,
            ReaderShapeCause::RootShape,
        )?;
        let cpus = aya::util::nr_cpus()
            .map_err(|_| ReadStage::Shape(ReaderShapeCause::CpuCountUnavailable))?;
        if cpus == 0 || expected_cpus.is_some_and(|expected| expected != cpus) {
            return Err(ReadStage::Shape(ReaderShapeCause::CpuCountMismatch));
        }
        Ok(Self {
            mode,
            cpus,
            stats: match stats_view_shape(mode, stats_shape) {
                CounterMode::Counts => NativeStats::Counts(
                    PerCpuArray::try_from(stats)
                        .map_err(|_| ReadStage::Shape(ReaderShapeCause::StatsViewCounts))?,
                ),
                CounterMode::Timestamps => NativeStats::Timestamps(
                    PerCpuArray::try_from(stats)
                        .map_err(|_| ReadStage::Shape(ReaderShapeCause::StatsViewTimestamps))?,
                ),
                CounterMode::Latency => NativeStats::Latency(
                    PerCpuArray::try_from(stats)
                        .map_err(|_| ReadStage::Shape(ReaderShapeCause::StatsViewLatency))?,
                ),
            },
            rvs: PerCpuHashMap::try_from(rvs)
                .map_err(|_| ReadStage::Shape(ReaderShapeCause::RvView))?,
            health: PerCpuArray::try_from(health)
                .map_err(|_| ReadStage::Shape(ReaderShapeCause::HealthView))?,
            evidence: PerCpuArray::try_from(evidence)
                .map_err(|_| ReadStage::Shape(ReaderShapeCause::EvidenceView))?,
            owner: Array::try_from(owner)
                .map_err(|_| ReadStage::Shape(ReaderShapeCause::OwnerView))?,
            cookie: Array::try_from(cookie)
                .map_err(|_| ReadStage::Shape(ReaderShapeCause::CookieView))?,
            root: Array::try_from(root)
                .map_err(|_| ReadStage::Shape(ReaderShapeCause::RootView))?,
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

    #[test]
    fn reader_shape_causes_are_distinct_and_complete() {
        let mut seen = Vec::with_capacity(ReaderShapeCause::ALL.len());
        for cause in ReaderShapeCause::ALL {
            assert!(
                !seen.contains(&cause),
                "duplicate reader shape cause: {cause:?}"
            );
            seen.push(cause);
        }
        assert_eq!(
            ReaderShapeCause::ALL.len(),
            36,
            "every new cause variant must join ALL"
        );
    }

    #[test]
    fn banked_stats_view_follows_the_aggregate_template() {
        // Fixed native artifacts carry a per-mode STATS template, so the
        // view shape equals the mode there.
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            assert_eq!(stats_view_shape(mode, mode), mode, "{mode:?}");
        }
        // Bank objects carry the legacy 24-byte aggregate template in every
        // mode; only the bank cells vary. The typed view must follow the
        // aggregate template, never the cell mode: a timestamps/latency view
        // over the 24-byte map refuses with a shape error.
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            assert_eq!(
                stats_view_shape(mode, CounterMode::Counts),
                CounterMode::Counts,
                "{mode:?} banked read over the legacy aggregate"
            );
        }
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
        rv_lookup: Option<BTreeMap<(u32, u64), [u64; 2]>>,
        published: Option<crate::attach::counter_banks::CounterPublishedSnapshot>,
        health: CounterHealth,
        kernel: KernelEvidence,
        routing: Option<CounterIssue>,
        fault_bits: u64,
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
                rv_lookup: None,
                published: None,
                health: CounterHealth::default(),
                kernel: KernelEvidence::default(),
                fail: None,
                routing: None,
                fault_bits: 0,
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
        fn published_snapshot(
            &self,
        ) -> Option<&crate::attach::counter_banks::CounterPublishedSnapshot> {
            self.published.as_ref()
        }
        fn routing(&self) -> Result<Option<CounterIssue>, ReadStage> {
            use crate::attach::counter_banks::{
                BANK_ROUTE_FAULT, BANK_SCOPE_FAULT, BANK_START_FAULT,
            };
            if self.fault_bits & (BANK_ROUTE_FAULT | BANK_START_FAULT | BANK_SCOPE_FAULT) != 0 {
                return Ok(Some(CounterIssue::BankRouting));
            }
            Ok(self.routing)
        }
        fn rv_exhausted(&self) -> Result<bool, ReadStage> {
            use crate::attach::counter_banks::BANK_RV_FAULT;
            Ok(self.fault_bits & BANK_RV_FAULT != 0)
        }
        fn rv_keys(&self) -> impl Iterator<Item = Result<RvKey, ReadStage>> + '_ {
            self.rvs.iter().map(|(key, _)| Ok(*key))
        }
        fn rv_total(&self, wanted: &RvKey) -> Result<Result<u64, CounterIssue>, ReadStage> {
            self.rv_reads.set(self.rv_reads.get() + 1);
            self.access(ReadStage::Rvs)?;
            let values = if let Some(lookup) = &self.rv_lookup {
                lookup.get(&(wanted.slot, wanted.rv)).unwrap()
            } else {
                &self
                    .rvs
                    .iter()
                    .find(|(key, _)| (key.slot, key.rv) == (wanted.slot, wanted.rv))
                    .unwrap()
                    .1
            };
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
    fn banked_acquisition_rejects_hole_rvs_and_missing_published_rows() {
        for hole_rv in [true, false] {
            let (_dir, history, snapshot, pool) =
                crate::attach::counter_banks::tests::growth_snapshot_fixture(false);
            assert_eq!(snapshot.original_indices(), [0, 2]);
            let mut source = Scripted::sample(CounterMode::Counts, false);
            let last_stats = source.stats.remove(&1).unwrap();
            source.stats.insert(2, last_stats);
            source.rvs.push((key(2, 0x1_0000_0204), [1, 0]));
            source.published = Some(snapshot);
            let limits = CounterLimits {
                rows: 3,
                rv_keys: 12,
            };
            let generation = NonZeroU64::new(19).unwrap();
            let mut collector = CounterCollector::new(limits, pool.reserver());
            let initial = acquire(&source, generation, &history, limits, &pool.reserver()).unwrap();
            assert_eq!(
                initial
                    .view()
                    .rows
                    .unwrap()
                    .iter()
                    .map(|row| row.view().slot)
                    .collect::<Vec<_>>(),
                [0, 2]
            );
            assert_eq!(collector.observe(Ok(initial)), CounterObservation::Initial);
            let charged = pool.snapshot().charged_bytes;
            source.accesses.set(0);
            source.rv_reads.set(0);
            if hole_rv {
                source.rvs.push((key(1, 0), [0, 0]));
            } else {
                source.stats.remove(&2);
            }
            let observed = collector.observe(acquire(
                &source,
                generation,
                &history,
                limits,
                &pool.reserver(),
            ));
            assert_eq!(
                observed,
                if hole_rv {
                    CounterObservation::Unavailable(CounterIssue::Topology)
                } else {
                    CounterObservation::ReadFailed(ReadStage::Stats)
                }
            );
            let baseline = collector.current().unwrap().view();
            let rows = baseline.rows.unwrap();
            assert_eq!(
                rows.iter()
                    .map(|row| (row.view().slot, row.view().entered, row.view().returned))
                    .collect::<Vec<_>>(),
                [(0, 3, 5), (2, 1, 1)],
                "failed acquisition must retain the complete physical baseline"
            );
            assert_eq!(rows[0].view().rv_counts.get(&HIGH_RV), Some(&1));
            assert_eq!(rows[1].view().rv_counts.get(&0x1_0000_0204), Some(&1));
            assert_eq!(pool.snapshot().charged_bytes, charged);
        }
    }

    #[test]
    fn banked_acquisition_uses_validated_bounds_and_charged_membership() {
        let (_dir, history, snapshot, _owner_pool) =
            crate::attach::counter_banks::tests::growth_snapshot_fixture(true);
        assert_eq!(snapshot.original_indices(), [0, 8191]);
        assert_eq!(
            (
                snapshot.logical_slots(),
                snapshot.rv_keys(),
                snapshot.start_rows(),
                snapshot.possible_cpus()
            ),
            (8192, 65536, 16384, 2)
        );
        let mut source = Scripted::sample(CounterMode::Counts, false);
        let last_stats = source.stats.remove(&1).unwrap();
        source.stats.insert(8191, last_stats);
        source.rvs = (0..65536)
            .map(|ordinal| {
                let slot = if ordinal < 32768 { 0 } else { 8191 };
                let rv = match ordinal {
                    0 => 7,
                    1 => 0x1_0000_0007,
                    _ => 0x2_0000_0000 + ordinal,
                };
                (key(slot, rv), [1, 0])
            })
            .collect();
        source.rv_lookup = Some(
            source
                .rvs
                .iter()
                .map(|(key, values)| ((key.slot, key.rv), *values))
                .collect(),
        );
        source.published = Some(snapshot);
        let limits = CounterLimits {
            rows: 8192,
            rv_keys: 65536,
        };
        let pool = test_pool();
        let baseline = pool.snapshot().charged_bytes;
        // Probe the separate existing row-storage component. The independent
        // transient lower bound below includes 8192 direct membership bytes.
        let storage = ReadReservation::reserve(2, 65536, &pool.reserver()).unwrap();
        let row_storage = pool.snapshot().charged_bytes - baseline;
        drop(storage);
        let read = acquire(
            &source,
            NonZeroU64::new(23).unwrap(),
            &history,
            limits,
            &pool.reserver(),
        )
        .unwrap();
        let view = read.view();
        let rows = view.rows.unwrap();
        assert_eq!(
            rows.iter().map(|row| row.view().slot).collect::<Vec<_>>(),
            [0, 8191]
        );
        assert_eq!(
            (
                rows[0].view().rv_counts.len(),
                rows[1].view().rv_counts.len()
            ),
            (32768, 32768)
        );
        assert_eq!(rows[0].view().rv_counts.get(&7), Some(&1));
        assert_eq!(rows[0].view().rv_counts.get(&0x1_0000_0007), Some(&1));
        assert_eq!(
            pool.snapshot().charged_bytes,
            baseline + row_storage,
            "only the two authoritative rows retain storage, despite the 8192-position span"
        );
        // 65536*(16-byte key+8-byte total)  + 288 per-CPU scratch  + 160 padding;
        // this old transient allowance does not pay for 8192 membership bytes.
        assert!(pool.snapshot().peak_charged_bytes >= baseline + row_storage + 1_573_312 + 8192);
        drop(read);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
        let refused = SemanticResourcePool::reference_limit(baseline + row_storage + 1_573_312);
        source.accesses.set(0);
        source.rv_reads.set(0);
        assert_eq!(
            acquire(
                &source,
                NonZeroU64::new(23).unwrap(),
                &history,
                limits,
                &refused.reserver()
            )
            .err(),
            Some(ReadStage::Budget)
        );
        assert_eq!((source.accesses.get(), source.rv_reads.get()), (0, 0));
        for bad in [
            CounterLimits {
                rows: 8193,
                rv_keys: 65536,
            },
            CounterLimits {
                rows: 8192,
                rv_keys: 65537,
            },
        ] {
            assert_eq!(
                acquire(
                    &source,
                    NonZeroU64::new(23).unwrap(),
                    &history,
                    bad,
                    &pool.reserver()
                )
                .err(),
                Some(ReadStage::Shape(ReaderShapeCause::PlanLimitsMismatch))
            );
        }
        for cpus in [0, 3] {
            source.cpus = cpus;
            assert_eq!(
                acquire(
                    &source,
                    NonZeroU64::new(23).unwrap(),
                    &history,
                    limits,
                    &pool.reserver()
                )
                .err(),
                Some(ReadStage::Shape(ReaderShapeCause::SnapshotModeMismatch)),
                "possible CPUs {cpus} against a 2-CPU preparation"
            );
        }
        source.cpus = 2;
        source.mode = CounterMode::Timestamps;
        assert_eq!(
            acquire(
                &source,
                NonZeroU64::new(23).unwrap(),
                &history,
                limits,
                &pool.reserver()
            )
            .err(),
            Some(ReadStage::Shape(ReaderShapeCause::SnapshotModeMismatch))
        );
        assert!(transient_bytes(CounterMode::Counts, usize::MAX, 65536).is_none());
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let fixed = Scripted::sample(mode, false);
            assert_eq!(
                acquire(
                    &fixed,
                    NonZeroU64::new(23).unwrap(),
                    &plan(),
                    limits,
                    &pool.reserver()
                )
                .err(),
                Some(ReadStage::Shape(ReaderShapeCause::PlanLimitsMismatch)),
                "format2 bounds must not broaden any ordinary fixed artifact"
            );
        }
    }

    #[test]
    fn banked_source_reports_prepared_mode_and_refuses_mismatch() {
        use crate::attach::counter_banks::tests::growth_snapshot_fixture_for;
        let modes = [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ];
        for mode in modes {
            let (_dir, history, snapshot, pool) = growth_snapshot_fixture_for(mode, false);
            assert_eq!(snapshot.original_indices(), [0, 2]);
            let mut source = Scripted::sample(mode, false);
            let last_stats = source.stats.remove(&1).unwrap();
            source.stats.insert(2, last_stats);
            source.rvs.push((key(2, 0x1_0000_0204), [1, 0]));
            source.published = Some(snapshot);
            let read = acquire(
                &source,
                NonZeroU64::new(41).unwrap(),
                &history,
                LIMITS,
                &pool.reserver(),
            )
            .unwrap();
            let view = read.view();
            assert_eq!(view.mode, mode);
            let rows = view.rows.unwrap();
            assert_eq!(
                rows.iter().map(|row| row.view().slot).collect::<Vec<_>>(),
                [0, 2]
            );
            assert!(rows.iter().all(|row| row.view().mode == mode));
        }
        for prepared in modes {
            for requested in modes {
                if requested == prepared {
                    continue;
                }
                let (_dir, history, snapshot, pool) = growth_snapshot_fixture_for(prepared, false);
                let mut source = Scripted::sample(requested, false);
                let last_stats = source.stats.remove(&1).unwrap();
                source.stats.insert(2, last_stats);
                source.published = Some(snapshot);
                assert_eq!(
                    acquire(
                        &source,
                        NonZeroU64::new(41).unwrap(),
                        &history,
                        LIMITS,
                        &pool.reserver(),
                    )
                    .err(),
                    Some(ReadStage::Shape(ReaderShapeCause::SnapshotModeMismatch)),
                    "{requested:?} source against {prepared:?} preparation"
                );
            }
        }
    }

    fn banked_scripted_sample(
        snapshot: crate::attach::counter_banks::CounterPublishedSnapshot,
        later: bool,
    ) -> Scripted {
        let mut source = Scripted::sample(CounterMode::Counts, later);
        let last_stats = source.stats.remove(&1).unwrap();
        source.stats.insert(2, last_stats);
        source
            .rvs
            .push((key(2, 0x1_0000_0204), [if later { 2 } else { 1 }, 0]));
        source.published = Some(snapshot);
        source
    }

    #[test]
    fn banked_reader_preserves_physical_prefix_and_routing_health() {
        let (_dir, history, snapshot, pool) =
            crate::attach::counter_banks::tests::growth_snapshot_fixture(false);
        let mut collector = CounterCollector::new(LIMITS, pool.reserver());
        let mut source = banked_scripted_sample(snapshot, false);
        assert_eq!(
            collector.observe(acquire(
                &source,
                NonZeroU64::new(5).unwrap(),
                &history,
                LIMITS,
                &pool.reserver()
            )),
            CounterObservation::Initial
        );
        source = banked_scripted_sample(source.published.take().unwrap(), true);
        match collector.observe(acquire(
            &source,
            NonZeroU64::new(5).unwrap(),
            &history,
            LIMITS,
            &pool.reserver(),
        )) {
            CounterObservation::Advanced { deltas, .. } => {
                assert_eq!((deltas[0].slot, deltas[1].slot), (0, 2));
                assert_eq!((deltas[0].entered, deltas[0].returned), (5, 4));
                assert_eq!(deltas[0].target.object, PinnedObjectId(0));
                assert_eq!(deltas[1].target.object, PinnedObjectId(1));
                assert_eq!(deltas[0].rv_counts.get(&HIGH_RV), Some(&1));
                assert_eq!(deltas[1].rv_counts.get(&0x1_0000_0204), Some(&1));
            }
            other => panic!("actual published physical rows must remain distinct: {other:?}"),
        }
        for issue in [CounterIssue::BankRouting, CounterIssue::BankQuarantined] {
            let (_dir, history, snapshot, pool) =
                crate::attach::counter_banks::tests::growth_snapshot_fixture(false);
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            let mut source = banked_scripted_sample(snapshot, false);
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(6).unwrap(),
                    &history,
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Initial
            );
            source = banked_scripted_sample(source.published.take().unwrap(), true);
            source.routing = Some(issue);
            let read = acquire(
                &source,
                NonZeroU64::new(6).unwrap(),
                &history,
                LIMITS,
                &pool.reserver(),
            )
            .unwrap();
            assert_eq!(
                source.rv_reads.get(),
                0,
                "poisoned Some(snapshot) routing must not sample rows"
            );
            assert_eq!(
                source.accesses.get(),
                2,
                "banked routing still requires both health and kernel reads"
            );
            assert_eq!(
                collector.observe(Ok(read)),
                CounterObservation::Unavailable(issue)
            );
            let baseline = collector.current().unwrap().view();
            assert_eq!(
                baseline
                    .rows
                    .unwrap()
                    .iter()
                    .map(|row| (row.view().slot, row.view().returned))
                    .collect::<Vec<_>>(),
                [(0, 5), (2, 1)]
            );
            source = banked_scripted_sample(source.published.take().unwrap(), true);
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(6).unwrap(),
                    &history,
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Unavailable(issue),
                "same-owner clean banked reads cannot erase routing loss"
            );
        }
        for stage in [ReadStage::Health, ReadStage::KernelEvidence] {
            let (_dir, history, snapshot, pool) =
                crate::attach::counter_banks::tests::growth_snapshot_fixture(false);
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            let mut source = banked_scripted_sample(snapshot, false);
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(7).unwrap(),
                    &history,
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Initial
            );
            source = banked_scripted_sample(source.published.take().unwrap(), true);
            source.routing = Some(CounterIssue::BankRouting);
            source.fail = Some(stage);
            let failed = acquire(
                &source,
                NonZeroU64::new(7).unwrap(),
                &history,
                LIMITS,
                &pool.reserver(),
            );
            assert_eq!(failed.as_ref().err(), Some(&stage));
            assert_eq!(source.rv_reads.get(), 0);
            assert_eq!(
                source.accesses.get(),
                if stage == ReadStage::Health { 1 } else { 2 }
            );
            assert_eq!(
                collector.observe(failed),
                CounterObservation::ReadFailed(stage)
            );
            assert_eq!(
                collector
                    .current()
                    .unwrap()
                    .view()
                    .rows
                    .unwrap()
                    .iter()
                    .map(|row| (row.view().slot, row.view().returned))
                    .collect::<Vec<_>>(),
                [(0, 5), (2, 1)]
            );
            source = banked_scripted_sample(source.published.take().unwrap(), true);
            match collector.observe(acquire(
                &source,
                NonZeroU64::new(7).unwrap(),
                &history,
                LIMITS,
                &pool.reserver(),
            )) {
                CounterObservation::Advanced { deltas, .. } => {
                    assert_eq!((deltas[0].entered, deltas[0].returned), (5, 4))
                }
                other => panic!("banked failed mandatory read changed the baseline: {other:?}"),
            }
        }
        for saturated in [true, false] {
            let (_dir, history, snapshot, pool) =
                crate::attach::counter_banks::tests::growth_snapshot_fixture(false);
            let mut collector = CounterCollector::new(LIMITS, pool.reserver());
            let mut source = banked_scripted_sample(snapshot, false);
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(8).unwrap(),
                    &history,
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Initial
            );
            source = banked_scripted_sample(source.published.take().unwrap(), true);
            if saturated {
                source.health.saturated = true;
            } else {
                source.kernel.rv_update_failures = 1;
            }
            let expected = if saturated {
                CounterIssue::ProducerSaturated
            } else {
                CounterIssue::KernelEvidence
            };
            assert_eq!(
                collector.observe(acquire(
                    &source,
                    NonZeroU64::new(8).unwrap(),
                    &history,
                    LIMITS,
                    &pool.reserver()
                )),
                CounterObservation::Unavailable(expected)
            );
            assert_eq!(
                collector
                    .current()
                    .unwrap()
                    .view()
                    .rows
                    .unwrap()
                    .iter()
                    .map(|row| row.view().returned)
                    .collect::<Vec<_>>(),
                [5, 1]
            );
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
            let expected = match name {
                "STATS" => ReaderShapeCause::StatsMapMissing,
                "RV_COUNTS" => ReaderShapeCause::RvMapMissing,
                "START" => ReaderShapeCause::StartsMapMissing,
                "COUNTER_HEALTH" => ReaderShapeCause::HealthMapMissing,
                "EVIDENCE" => ReaderShapeCause::EvidenceMapMissing,
                "OWNER_CTL" => ReaderShapeCause::OwnerMapMissing,
                "COOKIE_CTL" => ReaderShapeCause::CookieMapMissing,
                _ => ReaderShapeCause::RootMapMissing,
            };
            assert_eq!(
                NativeSource::new(|name| maps.get(name), CounterMode::Counts).err(),
                Some(ReadStage::Shape(expected)),
                "missing {name}"
            );
            maps.insert(name, removed);
        }
        assert_eq!(
            NativeSource::new(|name| maps.get(name), CounterMode::Latency).err(),
            Some(ReadStage::Shape(ReaderShapeCause::StatsShape))
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
            let expected = match name {
                "STATS" => ReaderShapeCause::StatsShape,
                "RV_COUNTS" => ReaderShapeCause::RvShape,
                "START" => ReaderShapeCause::StartsShape,
                "COUNTER_HEALTH" => ReaderShapeCause::HealthShape,
                "EVIDENCE" => ReaderShapeCause::EvidenceShape,
                _ => ReaderShapeCause::OwnerShape,
            };
            assert_eq!(
                NativeSource::new(|name| maps.get(name), CounterMode::Counts).err(),
                Some(ReadStage::Shape(expected)),
                "wrong {name}"
            );
            maps.insert(name, previous);
        }
        // Banked timing reads share the legacy 24-byte aggregate template
        // (the fixture above): the typed view must accept it in every mode.
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            assert!(
                NativeSource::with_bounds(
                    |name| maps.get(name),
                    mode,
                    CounterMode::Counts,
                    4096,
                    16384,
                    None,
                )
                .is_ok(),
                "{mode:?} banked read over the legacy aggregate"
            );
        }
        // The aggregate shape check follows the template, not the mode.
        assert_eq!(
            NativeSource::with_bounds(
                |name| maps.get(name),
                CounterMode::Timestamps,
                CounterMode::Timestamps,
                4096,
                16384,
                None,
            )
            .err(),
            Some(ReadStage::Shape(ReaderShapeCause::StatsShape))
        );
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

    struct OwnedFixture(std::process::Child);
    impl Drop for OwnedFixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    impl OwnedFixture {
        fn token(&mut self, expected: &str) {
            use std::io::Read;
            use std::os::fd::AsRawFd;
            use std::time::{Duration, Instant};
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
            use std::io::Write;
            self.0.stdin.as_mut().unwrap().write_all(&[byte]).unwrap();
        }
    }

    fn old_return_survives_append_with_mode(mode: CounterMode) {
        use crate::attach::Scope;
        use crate::attach::counter_banks::{BankPublication, BankReservation};
        use std::io::Read;
        use std::path::{Path, PathBuf};
        use std::process::{Command, Stdio};

        assert_eq!(
            env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"),
            "1",
            "actual counter objects are required"
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
        let policy = crate::plan::AdmissionPolicy::counters(
            crate::capacity::CounterBudget::new(8192).unwrap(),
        );
        let mut history = AttachPlan::from_slots_with_policy(vec![old.clone()], policy).unwrap();
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
        let stage = stage_envelope_for_range(
            mode,
            cpus,
            &grown.slots,
            provider_copy_charge(&pins, &grown.slots),
            false,
        );
        let bytes = std::fs::read(Path::new(env!("OUT_DIR")).join(format!(
            "counter-bank-growth-v2/p11scope-ebpf-{}-bank-growth-v2",
            mode.name()
        )))
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
            extent,
        } = session.stage_counter_banks(&mut history, &pins, stage, &pool.reserver())
        else {
            panic!("first actual bank did not publish");
        };
        assert_eq!((extent.first, extent.end), (0, 1));
        assert_eq!(history.counter_consumed_end(), 1);
        let binding = session.counter_reader_binding().unwrap().unwrap();
        assert_eq!(binding.mode(), mode);
        assert_eq!(
            binding.generation(),
            session.counter_collection_generation()
        );
        assert_eq!(binding.logical_slots(), 8192);
        assert_eq!(binding.rv_keys(), 65536);
        assert_eq!(binding.start_rows(), 16384);
        assert_eq!(binding.possible_cpus(), cpus);
        assert!(read_bound(binding, &history, &pins, limits, &pool.reserver()).is_ok());
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
                    &history,
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
                &history,
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
        let held = starts.get(&keys[0], 0).unwrap();
        assert_eq!(held.object_required, 0);
        if mode.has_timing() {
            assert_ne!(held.ts_ns, 0, "a timing START holds the entry clock");
        } else {
            assert_eq!(held.ts_ns, 0);
        }
        match collector.observe(read_banked(
            &session,
            &history,
            &pins,
            limits,
            &pool.reserver(),
        )) {
            CounterObservation::Advanced { deltas, .. } => {
                assert_eq!((deltas[0].entered, deltas[0].returned), (1, 0));
                assert_eq!(deltas[0].mode, mode);
                assert_eq!((deltas[0].total_ns, deltas[0].max_ns), (0, 0));
                assert_eq!(deltas[0].buckets.iter().sum::<u64>(), 0);
            }
            other => panic!("actual held entry was not collected: {other:?}"),
        }
        let delta = history.extend_exact(grown).unwrap();
        assert_eq!(
            delta.new.iter().map(|slot| slot.index).collect::<Vec<_>>(),
            [1]
        );
        assert!(delta.replace.is_empty() && delta.retire.is_empty());
        let BankPublication::Published {
            transaction: new_transaction,
            extent,
        } = session.stage_counter_banks(&mut history, &pins, stage, &pool.reserver())
        else {
            panic!("actual append did not publish");
        };
        assert_eq!((extent.first, extent.end), (1, 2));
        assert_eq!(history.counter_consumed_end(), 2);
        assert!(new_transaction > old_transaction);
        fixture.command(b'H');
        fixture.token("HOT");
        let hot_max = match collector.observe(read_banked(
            &session,
            &history,
            &pins,
            limits,
            &pool.reserver(),
        )) {
            CounterObservation::Advanced { deltas, .. } => {
                assert_eq!((deltas[0].entered, deltas[0].returned), (0, 0));
                assert_eq!(deltas[0].mode, mode);
                assert_eq!((deltas[0].total_ns, deltas[0].max_ns), (0, 0));
                assert_eq!(deltas[0].buckets.iter().sum::<u64>(), 0);
                assert_eq!(
                    (deltas[1].entered, deltas[1].returned, deltas[1].errors),
                    (1, 1, 1)
                );
                assert_eq!(deltas[1].rv_counts.get(&0x1_0000_0204), Some(&1));
                assert_eq!(deltas[1].mode, mode);
                assert_eq!(
                    deltas[1].total_ns, deltas[1].max_ns,
                    "a single completion carries one span"
                );
                if mode.has_histogram() {
                    assert_eq!(deltas[1].buckets.iter().sum::<u64>(), 1);
                } else {
                    assert_eq!(deltas[1].buckets.iter().sum::<u64>(), 0);
                }
                deltas[1].max_ns
            }
            other => panic!("actual new hot bank was not collected: {other:?}"),
        };
        fixture.command(b'R');
        fixture.token("DONE");
        assert!(fixture.0.wait().unwrap().success());
        let (old_total, old_max, old_buckets) = match collector.observe(read_banked(
            &session,
            &history,
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
                assert_eq!(deltas[0].mode, mode);
                assert_eq!(
                    deltas[0].total_ns, deltas[0].max_ns,
                    "the held call contributes one span"
                );
                if mode.has_timing() {
                    assert!(
                        deltas[0].total_ns > 0 && deltas[0].max_ns > 0,
                        "the held call spans the append"
                    );
                } else {
                    assert_eq!((deltas[0].total_ns, deltas[0].max_ns), (0, 0));
                }
                let old_buckets = if mode.has_histogram() {
                    assert_eq!(deltas[0].buckets.iter().sum::<u64>(), 1);
                    1
                } else {
                    assert_eq!(deltas[0].buckets.iter().sum::<u64>(), 0);
                    0
                };
                assert_eq!((deltas[1].entered, deltas[1].returned), (0, 0));
                assert_eq!(deltas[1].mode, mode);
                assert_eq!(deltas[1].total_ns, 0);
                assert_eq!(
                    deltas[1].max_ns, hot_max,
                    "the cumulative hot max survives the final observation"
                );
                assert_eq!(deltas[1].buckets.iter().sum::<u64>(), 0);
                (deltas[0].total_ns, deltas[0].max_ns, old_buckets)
            }
            other => panic!("old-bank return did not survive the new transaction: {other:?}"),
        };
        eprintln!(
            "{}_OLD_RETURN_SURVIVED total_ns={old_total} max_ns={old_max} buckets={old_buckets}",
            mode.name().to_uppercase(),
        );
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

    #[test]
    #[ignore = "requires explicitly prebuilt LP64 counter-banks fixtures and authorized native attach"]
    fn counter_bank_session_old_return_survives_append_lp64() {
        old_return_survives_append_with_mode(CounterMode::Counts);
    }

    #[test]
    #[ignore = "requires explicitly prebuilt LP64 counter-banks fixtures, validated timestamps and latency format2 objects, and authorized native attach; runs a counts-null twin first"]
    fn counter_bank_session_timing_old_return_survives_append_lp64() {
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            old_return_survives_append_with_mode(mode);
        }
    }

    const GROWTH_ENDPOINTS: usize = 8192;
    const GROWTH_RVS: [u64; 3] = [0, 0x204, 0x1_0000_0204];

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct GrowthLedgerRow {
        entered: u64,
        returned: u64,
        errors: u64,
        rvs: [u64; 3],
        other: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct GrowthHotRange {
        index: usize,
        first: u64,
        count: u64,
        completed: u64,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct GrowthLedger {
        rows: Vec<GrowthLedgerRow>,
        hot: Option<GrowthHotRange>,
    }

    impl GrowthLedger {
        fn empty() -> Self {
            Self {
                rows: vec![GrowthLedgerRow::default(); GROWTH_ENDPOINTS],
                hot: None,
            }
        }

        fn call(&mut self, index: usize, rv: u64) {
            let row = &mut self.rows[index];
            row.entered += 1;
            row.returned += 1;
            row.errors += u64::from(rv != 0 && rv != 0x204);
            if let Some(kind) = GROWTH_RVS.iter().position(|&known| known == rv) {
                row.rvs[kind] += 1;
            } else {
                row.other += 1;
            }
        }

        fn totals(&self) -> [u64; 3] {
            self.rows.iter().fold([0u64; 3], |totals, row| {
                [
                    totals[0].checked_add(row.entered).unwrap(),
                    totals[1].checked_add(row.returned).unwrap(),
                    totals[2].checked_add(row.errors).unwrap(),
                ]
            })
        }

        fn rv_counts(&self, index: usize) -> BTreeMap<u64, u64> {
            let row = self.rows[index];
            let mut result: BTreeMap<_, _> = GROWTH_RVS
                .into_iter()
                .zip(row.rvs)
                .filter(|(_, count)| *count != 0)
                .collect();
            if let Some(hot) = self.hot.filter(|hot| hot.index == index) {
                assert_eq!(hot.count, hot.completed);
                assert_eq!(row.other, hot.completed);
                for ordinal in 0..hot.completed {
                    let rv = hot.first.checked_add(ordinal).unwrap();
                    assert!(!GROWTH_RVS.contains(&rv));
                    assert!(result.insert(rv, 1).is_none());
                }
            } else {
                assert_eq!(row.other, 0);
            }
            result
        }
    }

    // Reuse the existing five-second barrier budget for a WHOLE command or
    // ledger and child exit. Producer close shares the original case budget.
    const GROWTH_OPERATION_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
    const GROWTH_CASE_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
    // Singles teardown closes every link serially (about 50 ms each on the
    // 6.6 guest and the 7.0 host): correct and finite, not fast. Its case
    // budget adds a per-link close allowance at twice that rate.
    const GROWTH_SINGLES_CLOSE_PER_LINK: std::time::Duration =
        std::time::Duration::from_millis(100);

    fn growth_reap_until(
        child: &mut std::process::Child,
        deadline: std::time::Instant,
    ) -> std::io::Result<Option<std::process::ExitStatus>> {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(Some(status)),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
                Ok(None) => {}
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
        }
    }

    /// Lowest soft RLIMIT_NOFILE a growth run stages under: two retained
    /// links per endpoint, plus one worst fresh-extent charge and slack for
    /// session maps, fixtures and pipes. Small hosts (soft 1024) refuse the
    /// first 512-endpoint stage without it (1026 > 1024); the product check
    /// is correct, so the cell provides the OS budget it stages against.
    fn growth_fd_soft_floor(final_count: usize) -> u64 {
        // Two retained links per endpoint, plus one worst fresh-extent
        // charge (512 endpoints: 512 * 2 links + 1 bank + 1 transient) and
        // slack for session maps, fixtures and pipes.
        (2 * final_count as u64) + 4096
    }

    fn ensure_fd_budget_with(
        need: u64,
        get: impl FnOnce() -> std::io::Result<(u64, u64)>,
        set: impl FnOnce(u64, u64) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let (soft, hard) = get()?;
        if soft >= need {
            return Ok(());
        }
        if hard >= need {
            return set(need, hard);
        }
        set(need, need)
    }

    // rlim_t is 32-bit on ia32, so the u64 casts are needed off LP64.
    #[allow(clippy::unnecessary_cast)]
    fn ensure_growth_fd_budget(final_count: usize) {
        let need = growth_fd_soft_floor(final_count);
        ensure_fd_budget_with(
            need,
            || {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // SAFETY: getrlimit writes one initialized rlimit; no limit changes.
                if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok((limit.rlim_cur as u64, limit.rlim_max as u64))
            },
            |soft, hard| {
                let limit = libc::rlimit {
                    rlim_cur: soft as libc::rlim_t,
                    rlim_max: hard as libc::rlim_t,
                };
                // SAFETY: setrlimit only raises this process's NOFILE caps to
                // the growth run's staged budget; it never lowers a limit.
                if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "growth run needs soft RLIMIT_NOFILE {need} for {final_count} endpoints: {error}"
            )
        });
    }

    struct GrowthDriver {
        child: std::process::Child,
        output: std::process::ChildStdout,
        buffered: std::collections::VecDeque<u8>,
        operation_deadline: std::time::Instant,
    }

    impl Drop for GrowthDriver {
        fn drop(&mut self) {
            let pid = self.child.id();
            let cleanup = match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {
                    let _ = self.child.kill();
                    growth_reap_until(
                        &mut self.child,
                        std::time::Instant::now() + GROWTH_OPERATION_BUDGET,
                    )
                }
                Err(error) => Err(error),
            };
            if !matches!(cleanup, Ok(Some(_))) {
                eprintln!(
                    "owned Counts growth fixture PID {pid} remains pending after bounded kill/reap; cleanup unproved: {cleanup:?}"
                );
                if !std::thread::panicking() {
                    panic!("owned Counts growth fixture PID {pid} cleanup unproved");
                }
            }
        }
    }

    impl GrowthDriver {
        fn spawn(workload: &std::path::Path, provider: &std::path::Path) -> Self {
            use std::process::{Command, Stdio};
            let child = Command::new(workload)
                .arg(provider)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
            Self::from_child(child)
        }

        fn from_child(mut child: std::process::Child) -> Self {
            let output = child.stdout.take().unwrap();
            let mut fixture = Self {
                child,
                output,
                buffered: std::collections::VecDeque::new(),
                operation_deadline: std::time::Instant::now() + GROWTH_OPERATION_BUDGET,
            };
            fixture.expect("READY 1 8192");
            fixture
        }

        fn wait_after_done(&mut self) {
            let pid = self.child.id();
            let status = growth_reap_until(
                &mut self.child,
                std::time::Instant::now() + GROWTH_OPERATION_BUDGET,
            )
            .unwrap_or_else(|error| {
                panic!("owned fixture PID {pid} exit read failed; cleanup unproved: {error}")
            })
            .unwrap_or_else(|| {
                panic!("owned fixture PID {pid} failed to exit after DONE; cleanup unproved")
            });
            assert!(
                status.success(),
                "owned fixture PID {pid} failed after DONE: {status}"
            );
        }

        fn line(&mut self) -> String {
            use std::io::Read;
            use std::os::fd::AsRawFd;
            let mut line = Vec::new();
            loop {
                let remaining = self
                    .operation_deadline
                    .saturating_duration_since(std::time::Instant::now());
                assert!(
                    !remaining.is_zero(),
                    "owned growth fixture whole-operation deadline expired"
                );
                if let Some(byte) = self.buffered.pop_front() {
                    if byte == b'\n' {
                        return String::from_utf8(line).unwrap();
                    }
                    assert!(byte != 0 && byte != b'\r' && line.len() < 256);
                    line.push(byte);
                    continue;
                }
                let mut poll = libc::pollfd {
                    fd: self.output.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one initialized pollfd is live throughout this bounded call.
                let ready = unsafe {
                    libc::poll(
                        &mut poll,
                        1,
                        i32::try_from(remaining.as_millis().max(1)).unwrap(),
                    )
                };
                if ready < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                assert!(
                    ready > 0,
                    "owned growth fixture did not reach its next barrier"
                );
                let mut chunk = [0u8; 4096];
                match self.output.read(&mut chunk) {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => {
                        let count = result.unwrap();
                        assert!(
                            count != 0,
                            "owned growth fixture exited before its next barrier"
                        );
                        self.buffered.extend(&chunk[..count]);
                    }
                }
            }
        }

        fn expect(&mut self, expected: &str) {
            assert_eq!(self.line(), expected);
        }

        fn command(&mut self, command: &str) {
            use std::io::Write;
            assert!(command.is_ascii() && command.len() < 79 && !command.contains('\n'));
            self.operation_deadline = std::time::Instant::now() + GROWTH_OPERATION_BUDGET;
            writeln!(self.child.stdin.as_mut().unwrap(), "{command}").unwrap();
        }

        fn ledger(&mut self) -> GrowthLedger {
            self.command("LEDGER");
            self.expect("LEDGER_BEGIN 8192");
            let mut ledger = GrowthLedger::empty();
            for (index, row) in ledger.rows.iter_mut().enumerate() {
                let line = self.line();
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                assert_eq!(fields.len(), 9);
                assert_eq!(fields[0], "ROW");
                let values: Vec<u64> = fields[1..].iter().map(|s| s.parse().unwrap()).collect();
                assert_eq!(values[0], index as u64);
                *row = GrowthLedgerRow {
                    entered: values[1],
                    returned: values[2],
                    errors: values[3],
                    rvs: [values[4], values[5], values[6]],
                    other: values[7],
                };
            }
            let mut line = self.line();
            if line.starts_with("HOT_RV_LEDGER ") {
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                assert_eq!(fields.len(), 5);
                ledger.hot = Some(GrowthHotRange {
                    index: fields[1].parse().unwrap(),
                    first: u64::from_str_radix(fields[2], 16).unwrap(),
                    count: fields[3].parse().unwrap(),
                    completed: fields[4].parse().unwrap(),
                });
                line = self.line();
            }
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(fields.len(), 4);
            assert_eq!(fields[0], "LEDGER_END");
            let totals: Vec<u64> = fields[1..].iter().map(|s| s.parse().unwrap()).collect();
            assert_eq!(totals, ledger.totals());
            ledger
        }
    }

    // Native invocation also requires an outer exact-test 60s deadline and
    // owned-child kill/reap on failure. Native FD teardown can outlast this
    // helper's failure. An outer timeout is FAIL / cleanup unproved, never
    // successful qualification or permission to retry.
    fn assert_native_growth_backend(
        session: &Session,
        backend: crate::attach::AttachBackend,
        static_attached: bool,
    ) {
        if backend != crate::attach::AttachBackend::Multi {
            return;
        }
        let evidence = session.attach_backend_evidence();
        assert_eq!(evidence.selection, "multi");
        assert!(evidence.fallback.is_none());
        assert_eq!(evidence.scope_filter, Some("kernel-pid+bpf"));
        assert_eq!(session.static_multi_attached(), static_attached);
    }

    /// Headroom above the estimated staged requirement on each byte leg
    /// of the counter stage envelope. The estimate already runs the real
    /// accounting; this covers bound slack and future drift.
    const STAGE_HEADROOM: usize = 32 * 1024 * 1024;

    /// Cell slot-shape mirror for envelope tests: one provider object, a
    /// provider-length path, one caller-named symbol per slot, like the
    /// growth and old-return cells build. Identity still comes from pins.
    fn envelope_shape_slots(
        count: usize,
        name: impl Fn(usize) -> String,
    ) -> (
        tempfile::TempDir,
        crate::discovery::identity::PinnedObjects,
        Vec<Slot>,
    ) {
        use crate::discovery::identity::test_fixture::real_scan_pin;
        use sha2::Digest;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("counter-growth-provider.so");
        let bytes = b"counter growth provider fixture";
        std::fs::write(&path, bytes).unwrap();
        let digest = p11scope_manifest::identity::hex(&sha2::Sha256::digest(bytes));
        let pins = real_scan_pin(&path, None, 1, &digest);
        let object = pins.pinned().next().unwrap().id;
        // Same length as the cell provider paths, so the per-slot path
        // charge matches the cells' class.
        let object_path =
            "/home/user/.cache/p11scope-vng/a2dev-ba4a/cells/counter-growth-provider.so".to_owned();
        assert_eq!(object_path.len(), 74);
        let slots = (0..count)
            .map(|i| {
                let mut target = slot(i as u32, 0);
                target.object = object;
                target.object_path = object_path.clone();
                target.file_offset = 0x80 + 16 * i as u64;
                target.names = vec![name(i)];
                target.aliased = false;
                target
            })
            .collect();
        (dir, pins, slots)
    }

    /// The same provider-copy charge `NativeIo` levies, summed over slots.
    fn provider_copy_charge(
        pins: &crate::discovery::identity::PinnedObjects,
        slots: &[Slot],
    ) -> usize {
        slots
            .iter()
            .try_fold(0usize, |bytes, slot| {
                bytes.checked_add(
                    pins.retained_target_copy_allocation_charge(slot.object)?
                        .checked_mul(4)?,
                )
            })
            .expect("fixture provider charges fit")
    }

    /// The counter cells' stage envelope: the estimated staged requirement
    /// over the whole endpoint range — which dominates every smaller stage
    /// by construction — plus headroom on each byte leg. The estimator
    /// inputs dominate production: every spanned bank, twice the staged
    /// positions capacity, the full provider-copy sum, and (Multi) twice
    /// the endpoint count for links. FDs need no headroom: the whole-range
    /// fresh extent already dominates every stage's charge.
    fn stage_envelope_for_range(
        mode: CounterMode,
        cpus: usize,
        slots: &[Slot],
        provider_copies: usize,
        multi: bool,
    ) -> crate::attach::counter_banks::BankReservation {
        use crate::attach::counter_banks::tests::estimate_counter_stage_reservation;
        let bound = slots.len();
        let required = estimate_counter_stage_reservation(
            mode,
            16,
            512,
            slots,
            0,
            bound as u32,
            2 * bound,
            cpus,
            bound.div_ceil(512),
            provider_copies,
            multi.then_some((2 * bound, 2 * bound)),
        )
        .expect("stage envelope inputs are finite");
        crate::attach::counter_banks::BankReservation {
            retained_bytes: required
                .retained_bytes
                .checked_add(STAGE_HEADROOM)
                .expect("retained stage envelope fits"),
            transient_bytes: required
                .transient_bytes
                .checked_add(STAGE_HEADROOM)
                .expect("transient stage envelope fits"),
            metadata_bytes: required
                .metadata_bytes
                .checked_add(STAGE_HEADROOM)
                .expect("metadata stage envelope fits"),
            file_descriptors: required.file_descriptors,
        }
    }

    #[test]
    fn growth_stage_envelope_covers_real_staged_requirements() {
        use crate::attach::counter_banks::tests::estimate_counter_stage_reservation;
        let (_dir, pins, slots) = envelope_shape_slots(GROWTH_ENDPOINTS, |i| {
            format!("counter_bank_growth_e{i:04x}")
        });
        let provider_all = provider_copy_charge(&pins, &slots);
        // The cells' three true stages: slots staged, fresh extent,
        // pre-stage positions capacity, fresh banks, and (Multi) pre-stage
        // link length/capacity by construction.
        let stages = [
            (512usize, 0u32, 512u32, 0usize, 1usize, (0usize, 0usize)),
            (513, 512, 513, 512, 1, (1024, 1024)),
            (8192, 513, 8192, 513, 14, (1026, 1026)),
        ];
        let mut failures = Vec::new();
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            for cpus in [12usize, 256] {
                for multi in [false, true] {
                    let envelope =
                        stage_envelope_for_range(mode, cpus, &slots, provider_all, multi);
                    for (all, first, end, old_capacity, new_banks, links) in stages {
                        let required = estimate_counter_stage_reservation(
                            mode,
                            16,
                            512,
                            &slots[..all],
                            first,
                            end,
                            old_capacity,
                            cpus,
                            new_banks,
                            provider_copy_charge(&pins, &slots[first as usize..end as usize]),
                            multi.then_some(links),
                        )
                        .unwrap();
                        let context =
                            format!("growth {mode:?} P={cpus} multi={multi} stage {first}..{end}");
                        for (field, have, need) in [
                            ("retained", envelope.retained_bytes, required.retained_bytes),
                            (
                                "transient",
                                envelope.transient_bytes,
                                required.transient_bytes,
                            ),
                            ("metadata", envelope.metadata_bytes, required.metadata_bytes),
                            ("fds", envelope.file_descriptors, required.file_descriptors),
                        ] {
                            if have < need {
                                failures.push(format!("{context}: {field} {have} < {need}"));
                            }
                        }
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "stage envelope shortfalls:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn old_return_stage_envelope_covers_real_staged_requirements() {
        use crate::attach::counter_banks::tests::estimate_counter_stage_reservation;
        let (_dir, pins, slots) = envelope_shape_slots(2, |i| {
            ["counter_bank_old", "counter_bank_hot"][i].to_owned()
        });
        let provider_all = provider_copy_charge(&pins, &slots);
        let stages = [(1usize, 0u32, 1u32, 0usize, 1usize), (2, 1, 2, 1, 0)];
        let mut failures = Vec::new();
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            for cpus in [12usize, 256] {
                let envelope = stage_envelope_for_range(mode, cpus, &slots, provider_all, false);
                for (all, first, end, old_capacity, new_banks) in stages {
                    let required = estimate_counter_stage_reservation(
                        mode,
                        16,
                        512,
                        &slots[..all],
                        first,
                        end,
                        old_capacity,
                        cpus,
                        new_banks,
                        provider_copy_charge(&pins, &slots[first as usize..end as usize]),
                        None,
                    )
                    .unwrap();
                    let context = format!("old-return {mode:?} P={cpus} stage {first}..{end}");
                    for (field, have, need) in [
                        ("retained", envelope.retained_bytes, required.retained_bytes),
                        (
                            "transient",
                            envelope.transient_bytes,
                            required.transient_bytes,
                        ),
                        ("metadata", envelope.metadata_bytes, required.metadata_bytes),
                        ("fds", envelope.file_descriptors, required.file_descriptors),
                    ] {
                        if have < need {
                            failures.push(format!("{context}: {field} {have} < {need}"));
                        }
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "stage envelope shortfalls:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn stage_reservation_check_refuses_below_requirement() {
        use crate::attach::counter_banks::{
            BankRefusal, BankReservation, check_counter_stage_reservation,
            tests::estimate_counter_stage_reservation,
        };
        let (_dir, pins, slots) = envelope_shape_slots(GROWTH_ENDPOINTS, |i| {
            format!("counter_bank_growth_e{i:04x}")
        });
        // A real requirement (the first RED row: counts at P=12, final growth stage).
        let required = estimate_counter_stage_reservation(
            CounterMode::Counts,
            16,
            512,
            &slots,
            513,
            8192,
            513,
            12,
            14,
            provider_copy_charge(&pins, &slots[513..]),
            None,
        )
        .unwrap();
        let need = (
            required.retained_bytes,
            required.transient_bytes,
            required.metadata_bytes,
            required.file_descriptors,
        );
        assert!(
            need.0 > 0 && need.1 > 0 && need.2 > 0 && need.3 > 0,
            "the twin needs a nonzero requirement: {need:?}"
        );
        assert!(
            check_counter_stage_reservation(required, need).is_ok(),
            "exact fit admits"
        );
        for (field, short) in [
            (
                "retained",
                BankReservation {
                    retained_bytes: need.0 - 1,
                    ..required
                },
            ),
            (
                "transient",
                BankReservation {
                    transient_bytes: need.1 - 1,
                    ..required
                },
            ),
            (
                "metadata",
                BankReservation {
                    metadata_bytes: need.2 - 1,
                    ..required
                },
            ),
            (
                "file descriptors",
                BankReservation {
                    file_descriptors: need.3 - 1,
                    ..required
                },
            ),
        ] {
            assert_eq!(
                check_counter_stage_reservation(short, need),
                Err(BankRefusal::Budget),
                "{field} minus one refuses"
            );
        }
    }

    /// Assert the staged extent published. A mismatch names the actual
    /// publication (variant, extent, refusal) instead of failing silent.
    fn assert_growth_published(
        publication: crate::attach::counter_banks::BankPublication,
        first: u32,
        end: u32,
    ) {
        use crate::attach::counter_banks::{BankExtent, BankPublication};
        assert!(
            matches!(publication, BankPublication::Published { extent, .. } if extent == BankExtent { first, end }),
            "growth publication for {first}..{end}: {publication:?}"
        );
    }

    #[test]
    fn growth_publication_mismatch_names_variant_extent_and_refusal() {
        use crate::attach::counter_banks::{BankExtent, BankPublication, BankRefusal};
        let mismatches: [(BankPublication, &[&str]); 3] = [
            (
                BankPublication::RolledBack {
                    transaction: 7,
                    extent: BankExtent {
                        first: 513,
                        end: 8192,
                    },
                    reason: BankRefusal::Budget,
                },
                &["RolledBack", "513", "8192", "Budget"],
            ),
            (
                BankPublication::Refused(BankRefusal::Budget),
                &["Refused", "Budget"],
            ),
            (
                BankPublication::Published {
                    transaction: 7,
                    extent: BankExtent { first: 0, end: 512 },
                },
                &["Published", "512"],
            ),
        ];
        for (publication, expected) in mismatches {
            let message = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_growth_published(publication, 513, 8192);
            }))
            .expect_err("a mismatched publication must panic");
            let text = message
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| message.downcast_ref::<&str>().map(|text| text.to_string()))
                .expect("panic carries its message");
            for word in expected {
                assert!(text.contains(word), "mismatch message names {word}: {text}");
            }
        }
        assert_growth_published(
            BankPublication::Published {
                transaction: 7,
                extent: BankExtent {
                    first: 513,
                    end: 8192,
                },
            },
            513,
            8192,
        );
    }

    #[test]
    fn counter_terminal_transient_matches_reader() {
        use crate::attach::counter_banks::counter_read_transient_bytes;
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            for cpus in [1usize, 2, 12, 256] {
                for (rv_keys, logical_slots, row_count) in
                    [(12usize, 8192usize, 512usize), (65536, 8192, 8192)]
                {
                    let expected = transient_bytes(mode, cpus, rv_keys)
                        .and_then(|n| n.checked_add(logical_slots))
                        .and_then(|n| {
                            n.checked_add(
                                row_count.checked_mul(size_of::<crate::plan::AttachKey>())?,
                            )
                        })
                        .and_then(|n| n.checked_add(2 * OWNED_ALLOCATION_PADDING))
                        .unwrap();
                    assert_eq!(
                        counter_read_transient_bytes(mode, cpus, rv_keys, logical_slots, row_count)
                            .unwrap(),
                        expected,
                        "{mode:?} P={cpus} rv={rv_keys} rows={row_count}"
                    );
                }
            }
        }
    }

    #[test]
    fn counter_terminal_storage_dominates_read_reservation() {
        use crate::attach::counter_banks::counter_read_storage_bytes;
        use crate::metrics::counter_collector::CounterRow;
        assert!(
            size_of::<CounterRow>() <= 1024,
            "the per-row bound must dominate CounterRow"
        );
        for (rows, rv_keys) in [(2usize, 4usize), (512, 12), (8192, 65536)] {
            let pool = test_pool();
            let baseline = pool.snapshot().charged_bytes;
            let storage =
                ReadReservation::reserve(rows, rv_keys, &pool.reserver()).unwrap();
            let actual = pool.snapshot().charged_bytes - baseline;
            drop(storage);
            let bound = counter_read_storage_bytes(rows, rv_keys).unwrap();
            assert!(
                bound >= actual,
                "storage bound {bound} must dominate actual {actual} for {rows} rows {rv_keys} RVs"
            );
        }
    }

    #[test]
    fn counter_rv_exhaustion_is_lower_bound_and_keeps_endpoint_counts() {
        use crate::attach::counter_banks::BANK_RV_FAULT;
        let (_dir, history, snapshot, pool) =
            crate::attach::counter_banks::tests::growth_snapshot_fixture(false);
        assert_eq!(snapshot.original_indices(), [0, 2]);
        let mut first = Scripted::sample(CounterMode::Counts, false);
        let last_stats = first.stats.remove(&1).unwrap();
        first.stats.insert(2, last_stats);
        first.rvs.push((key(2, 0x1_0000_0204), [1, 0]));
        first.fault_bits = BANK_RV_FAULT;
        first.published = Some(snapshot);
        let limits = CounterLimits { rows: 3, rv_keys: 12 };
        let generation = NonZeroU64::new(41).unwrap();
        assert!(first.rv_exhausted().unwrap(), "the RV fault marks a lower bound");
        let read = acquire(&first, generation, &history, limits, &pool.reserver()).unwrap();
        let rows = read.view().rows.unwrap();
        assert_eq!(
            rows.iter().map(|row| (row.view().slot, row.view().entered, row.view().returned, row.view().errors)).collect::<Vec<_>>(),
            [(0, 3, 5, 1), (2, 1, 1, 0)],
            "entered/returned/errors stay exact under RV exhaustion"
        );
        assert_eq!(rows[0].view().rv_counts.get(&HIGH_RV), Some(&1));
        assert_eq!(rows[1].view().rv_counts.get(&0x1_0000_0204), Some(&1));
        let mut collector = CounterCollector::new(limits, pool.reserver());
        assert_eq!(collector.observe(Ok(read)), CounterObservation::Initial);
        let (_dir2, history2, snapshot2, _) =
            crate::attach::counter_banks::tests::growth_snapshot_fixture(false);
        assert_eq!(history2.slots.len(), history.slots.len());
        let mut second = Scripted::sample(CounterMode::Counts, true);
        let last_stats = second.stats.remove(&1).unwrap();
        second.stats.insert(2, last_stats);
        second.rvs.push((key(2, 0x1_0000_0204), [2, 0]));
        second.fault_bits = BANK_RV_FAULT;
        second.published = Some(snapshot2);
        assert!(second.rv_exhausted().unwrap());
        let read2 = acquire(&second, generation, &history, limits, &pool.reserver()).unwrap();
        let rows2 = read2.view().rows.unwrap();
        assert_eq!(
            rows2.iter().map(|row| (row.view().slot, row.view().entered, row.view().returned)).collect::<Vec<_>>(),
            [(0, 8, 9), (2, 2, 2)],
            "existing keys keep counting"
        );
        assert_eq!(rows2[0].view().rv_counts.get(&HIGH_RV), Some(&2));
        match collector.observe(Ok(read2)) {
            CounterObservation::Advanced { deltas, .. } => {
                assert_eq!((deltas[0].entered, deltas[0].returned), (5, 4));
                assert_eq!(deltas[0].rv_counts.get(&HIGH_RV), Some(&1));
            }
            other => panic!("exhaustion must not stop existing keys: {other:?}"),
        }
    }

    struct NativeGrowthRun {
        // Kill/reap an owned blocked driver before the Session drops on failure.
        fixture: GrowthDriver,
        session: Session,
        collector: CounterCollector,
        pins: crate::discovery::identity::PinnedObjects,
        slots: Vec<Slot>,
        extra: Slot,
        history: AttachPlan,
        pool: SemanticResourcePool,
        limits: CounterLimits,
        stage: crate::attach::counter_banks::BankReservation,
        expected: GrowthLedger,
        previous: Option<GrowthLedger>,
        case_deadline: std::time::Instant,
        case_budget: std::time::Duration,
        mode: CounterMode,
    }

    impl NativeGrowthRun {
        fn new_with_backend_and_mode(
            final_count: usize,
            case_deadline: std::time::Instant,
            backend: crate::attach::AttachBackend,
            mode: CounterMode,
        ) -> Self {
            use crate::attach::counter_banks::{BankPublication, BankReservation};
            use sha2::Digest;
            use std::io::Read;
            use std::os::unix::fs::MetadataExt;
            use std::path::{Path, PathBuf};
            assert!(matches!(final_count, 513 | 8192));
            assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"), "1");
            assert_eq!(
                env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
                "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
            );
            ensure_growth_fd_budget(final_count);
            let provider = PathBuf::from(
                std::env::var_os("P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER")
                    .expect("prebuild counter-bank-growth.c with -DCOUNTER_BANK_GROWTH_PROVIDER"),
            );
            let workload = PathBuf::from(
                std::env::var_os("P11SCOPE_COUNTER_GROWTH_FIXTURE_WORKLOAD")
                    .expect("prebuild counter-bank-growth.c's LP64 dlopen/pthread driver"),
            );
            let mut file = std::fs::File::open(&provider).unwrap();
            let elf = p11scope_manifest::elf::ElfSnapshot::read(&file).unwrap();
            assert_eq!(elf.abi(), p11scope_manifest::elf::ElfAbi::Lp64);
            // One batch symbol walk/index, rather than 8192 defined_symbol parses.
            let wanted: Vec<_> = (0..GROWTH_ENDPOINTS)
                .map(|i| format!("counter_bank_growth_e{i:04x}"))
                .collect();
            let borrowed: Vec<_> = wanted.iter().map(String::as_str).collect();
            let mut index = elf.exports_matching(&borrowed).unwrap();
            index.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(index.len(), GROWTH_ENDPOINTS);
            let mut offsets = Vec::with_capacity(GROWTH_ENDPOINTS);
            for ((name, offset), wanted) in index.iter().zip(&wanted) {
                assert_eq!(name, wanted);
                assert!(elf.is_executable_offset(*offset));
                offsets.push(*offset);
            }
            let mut unique = offsets.clone();
            unique.sort_unstable();
            assert!(
                unique.windows(2).all(|pair| pair[0] != pair[1]),
                "8192 real distinct physical endpoints are required"
            );
            // This source-defined LOCAL FUNC is a separate real executable body,
            // never a fabricated offset, an alias, or an extra accepted link.
            let extra_offset = elf
                .defined_symbol("endpoint_body")
                .unwrap()
                .expect("provider's actual endpoint_body FUNC")
                .file_offset;
            assert!(elf.is_executable_offset(extra_offset));
            assert!(unique.binary_search(&extra_offset).is_err());
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            let digest = p11scope_manifest::identity::hex(&sha2::Sha256::digest(&bytes));
            let pins = crate::discovery::identity::test_fixture::real_scan_pin(
                &provider, None, 1, &digest,
            );
            let object = pins.pinned().next().unwrap().id;
            let selected = file.metadata().unwrap();
            let pinned = pins.file_for(object).unwrap().metadata().unwrap();
            assert_eq!(
                (selected.dev(), selected.ino()),
                (pinned.dev(), pinned.ino())
            );
            let slots: Vec<_> = offsets
                .into_iter()
                .enumerate()
                .map(|(i, offset)| {
                    let mut target = slot(i as u32, 0);
                    target.object = object;
                    target.object_path = provider.to_string_lossy().into_owned();
                    target.file_offset = offset;
                    target.names = vec![wanted[i].clone()];
                    target.aliased = false;
                    target
                })
                .collect();
            let mut extra = slots[0].clone();
            extra.file_offset = extra_offset;
            extra.names = vec!["endpoint_body".into()];
            let fixture = GrowthDriver::spawn(&workload, &provider);
            let policy = crate::plan::AdmissionPolicy::counters(
                crate::capacity::CounterBudget::new(8192).unwrap(),
            );
            let mut history =
                AttachPlan::from_slots_with_policy(slots[..512].to_vec(), policy).unwrap();
            let cpus = aya::util::nr_cpus().unwrap();
            let pool = SemanticResourcePool::reference_limit(2 * 1024 * 1024 * 1024);
            let base = BankReservation {
                retained_bytes: 128 * 1024 * 1024,
                transient_bytes: 64 * 1024 * 1024,
                metadata_bytes: 32 * 1024 * 1024,
                file_descriptors: cpus.checked_mul(4).unwrap() + 512,
            };
            // Caller envelopes only: no OS limit is changed. Resource admission
            // is a separate controller gate before this ignored cell can run.
            let stage = stage_envelope_for_range(
                mode,
                cpus,
                &slots,
                provider_copy_charge(&pins, &slots),
                backend == crate::attach::AttachBackend::Multi,
            );
            let artifact = std::fs::read(Path::new(env!("OUT_DIR")).join(format!(
                "counter-bank-growth-v2/p11scope-ebpf-{}-bank-growth-v2",
                mode.name()
            )))
            .unwrap();
            let scope = crate::attach::Scope::Pid(fixture.child.id());
            let mut session = match backend {
                crate::attach::AttachBackend::Singles => {
                    Session::prepare_counter_banks(&scope, &artifact, base, &pool.reserver())
                }
                crate::attach::AttachBackend::Multi => Session::prepare_counter_banks_with_backend(
                    &scope,
                    &artifact,
                    base,
                    &pool.reserver(),
                    backend,
                ),
            }
            .unwrap();
            assert_native_growth_backend(&session, backend, false);
            let publication =
                session.stage_counter_banks(&mut history, &pins, stage, &pool.reserver());
            assert!(
                matches!(
                    publication,
                    BankPublication::Published {
                        extent: crate::attach::counter_banks::BankExtent { first: 0, end: 512 },
                        ..
                    }
                ),
                "first growth publication: {publication:?}"
            );
            assert_native_growth_backend(&session, backend, true);
            let limits = CounterLimits {
                rows: final_count,
                rv_keys: 65536,
            };
            let mut run = Self {
                fixture,
                session,
                collector: CounterCollector::new(limits, pool.reserver()),
                pins,
                slots,
                extra,
                history,
                pool,
                limits,
                stage,
                expected: GrowthLedger::empty(),
                previous: None,
                case_deadline,
                case_budget: growth_case_budget(backend, final_count),
                mode,
            };
            run.checkpoint();
            run
        }

        fn checkpoint(&mut self) {
            let actual = self.fixture.ledger();
            assert_eq!(
                actual.hot, self.expected.hot,
                "independent hot-RV completion"
            );
            assert_eq!(
                actual.totals(),
                self.expected.totals(),
                "independent completion totals"
            );
            for (index, (actual, expected)) in
                actual.rows.iter().zip(&self.expected.rows).enumerate()
            {
                assert_eq!(actual, expected, "independent driver row {index}");
            }
            self.sample();
        }

        fn sample(&mut self) {
            let count = self.history.slots.len();
            assert!(
                self.expected.rows[count..]
                    .iter()
                    .all(|row| *row == GrowthLedgerRow::default())
            );
            let read = read_banked(
                &self.session,
                &self.history,
                &self.pins,
                self.limits,
                &self.pool.reserver(),
            )
            .unwrap();
            {
                let view = read.view();
                assert_eq!(view.health, CounterHealth::default());
                assert_eq!(view.kernel, KernelEvidence::default());
                let rows = view.rows.unwrap();
                assert_eq!(rows.len(), count);
                let mut totals = [0u64; 3];
                for (index, row) in rows.iter().enumerate() {
                    let actual = row.view();
                    let expected = self.expected.rows[index];
                    assert_eq!(actual.slot as usize, index);
                    assert_eq!(
                        actual.target,
                        AttachKey {
                            object: self.history.slots[index].object,
                            file_offset: self.history.slots[index].file_offset
                        }
                    );
                    assert_eq!(
                        (actual.entered, actual.returned, actual.errors),
                        (expected.entered, expected.returned, expected.errors),
                        "native cumulative row {index}"
                    );
                    assert_eq!(
                        *actual.rv_counts,
                        self.expected.rv_counts(index),
                        "full64 native RV row {index}"
                    );
                    match self.mode {
                        CounterMode::Counts => {
                            assert_eq!((actual.total_ns, actual.max_ns), (0, 0));
                            assert!(actual.buckets.iter().all(|&value| value == 0));
                        }
                        CounterMode::Timestamps => {
                            assert!(
                                actual.total_ns >= actual.max_ns,
                                "native cumulative timing row {index}"
                            );
                            assert!(actual.buckets.iter().all(|&value| value == 0));
                        }
                        CounterMode::Latency => {
                            assert!(
                                actual.total_ns >= actual.max_ns,
                                "native cumulative timing row {index}"
                            );
                            assert_eq!(
                                actual.buckets.iter().sum::<u64>(),
                                actual.returned,
                                "each native completion lands in exactly one bucket, row {index}"
                            );
                        }
                    }
                    totals[0] += actual.entered;
                    totals[1] += actual.returned;
                    totals[2] += actual.errors;
                }
                assert_eq!(totals, self.expected.totals());
            }
            let observation = self.collector.observe(Ok(read));
            if let Some(previous) = &self.previous {
                let CounterObservation::Advanced { deltas, .. } = observation else {
                    panic!("complete actual growth collection: {observation:?}");
                };
                assert_eq!(deltas.len(), count);
                for (index, delta) in deltas.iter().enumerate() {
                    let before = previous.rows[index];
                    let after = self.expected.rows[index];
                    assert_eq!(delta.slot as usize, index);
                    assert_eq!(
                        (delta.entered, delta.returned, delta.errors),
                        (
                            after.entered - before.entered,
                            after.returned - before.returned,
                            after.errors - before.errors
                        ),
                        "native delta row {index}"
                    );
                    let old_rvs = previous.rv_counts(index);
                    let expected_rvs: BTreeMap<_, _> = self
                        .expected
                        .rv_counts(index)
                        .into_iter()
                        .filter_map(|(rv, now)| {
                            let difference = now - old_rvs.get(&rv).copied().unwrap_or(0);
                            (difference != 0).then_some((rv, difference))
                        })
                        .collect();
                    assert_eq!(delta.rv_counts, expected_rvs, "full64 delta row {index}");
                }
            } else {
                assert_eq!(observation, CounterObservation::Initial);
            }
            self.previous = Some(self.expected.clone());
            eprintln!(
                "{}_GROWTH_CHECKPOINT published={count} totals={:?}",
                self.mode.name().to_uppercase(),
                self.expected.totals()
            );
        }

        fn held_start(&self) -> (u64, u32, u64) {
            let starts: aya::maps::HashMap<_, StartKey, CallStart> =
                aya::maps::HashMap::try_from(self.session.ebpf.map("START").unwrap()).unwrap();
            let keys: Vec<_> = starts.keys().take(2).collect::<Result<_, _>>().unwrap();
            assert_eq!(keys.len(), 1, "one actual old START must remain held");
            assert_eq!((keys[0].slot, keys[0]._pad), (0, 0));
            let start = starts.get(&keys[0], 0).unwrap();
            assert_eq!(start.object_required, 0);
            if self.mode.has_timing() {
                assert_ne!(start.ts_ns, 0, "a timing START holds the entry clock");
            } else {
                assert_eq!(start.ts_ns, 0);
            }
            (keys[0].pid_tgid, keys[0].slot, start.slot_id)
        }

        fn assert_held_timing(&self) {
            // The row-0 call was held from START to RELEASE across the whole
            // run: its single completion carries a multi-syscall span on the
            // nanosecond clock, so cumulative total and max are both live.
            let read = read_banked(
                &self.session,
                &self.history,
                &self.pins,
                self.limits,
                &self.pool.reserver(),
            )
            .unwrap();
            let view = read.view();
            assert_eq!(view.mode, self.mode);
            let rows = view.rows.unwrap();
            let first = rows[0].view();
            assert_eq!(first.slot, 0);
            assert!(first.entered > 0 && first.returned > 0);
            assert!(
                first.total_ns > 0 && first.max_ns > 0,
                "the whole-run held call carries live timing"
            );
            if self.mode.has_histogram() {
                assert_eq!(
                    first.buckets.iter().sum::<u64>(),
                    first.returned,
                    "every row-0 completion lands in exactly one bucket"
                );
            }
        }

        fn bank_ids(&self) -> Vec<u32> {
            let view = self
                .session
                .counter_bank_view(&self.history, &self.pins, &self.pool.reserver())
                .unwrap();
            (0..self.history.slots.len())
                .step_by(512)
                .map(|index| {
                    let (Map::PerCpuArray(data), cell) = view.bank_cell(index as u32).unwrap()
                    else {
                        panic!("retained per-CPU bank required");
                    };
                    assert_eq!(cell, 0);
                    data.info().unwrap().id()
                })
                .collect()
        }

        fn grow(&mut self, end: usize) {
            let first = self.history.slots.len();
            let ids = self.bank_ids();
            let candidate = AttachPlan::from_slots_with_policy(
                self.slots[..end].to_vec(),
                self.history.admission_policy(),
            )
            .unwrap();
            let delta = self.history.extend_exact(candidate).unwrap();
            assert_eq!(delta.new.len(), end - first);
            assert!(delta.retire.is_empty() && delta.replace.is_empty());
            let publication = self.session.stage_counter_banks(
                &mut self.history,
                &self.pins,
                self.stage,
                &self.pool.reserver(),
            );
            assert_growth_published(publication, first as u32, end as u32);
            assert_eq!(self.history.counter_consumed_end() as usize, end);
            let after = self.bank_ids();
            assert_eq!(after[..ids.len()], ids);
            assert_eq!(
                after
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                after.len()
            );
        }

        fn step(&mut self, index: usize) {
            let rv = GROWTH_RVS[index % 3];
            self.fixture.command(&format!("STEP {index}"));
            self.fixture.expect(&format!("STEP {index} {rv:016x}"));
            self.expected.call(index, rv);
            self.checkpoint();
        }

        fn refuse_n_plus_one(&mut self) {
            assert_eq!(self.history.slots.len(), GROWTH_ENDPOINTS);
            let before = self.history.clone();
            let ids = self.bank_ids();
            let charge = self.pool.snapshot().charged_bytes;
            // One real new physical helper plus 8192 retained original cells is
            // a lifetime demand of 8193 even if the fresh snapshot lists only it.
            let candidate = AttachPlan::from_slots_with_policy(
                vec![self.extra.clone()],
                self.history.admission_policy(),
            )
            .unwrap();
            let error = self.history.extend_exact(candidate).unwrap_err();
            assert!(
                error.contains("8193") && error.contains("8192") && error.contains("counter"),
                "{error}"
            );
            assert!(
                self.history == before,
                "N+1 refusal is atomic before native work"
            );
            assert_eq!(self.history.counter_consumed_end(), 8192);
            assert_eq!(self.pool.snapshot().charged_bytes, charge);
            assert_eq!(self.bank_ids(), ids);
            self.checkpoint();
        }

        fn finish(mut self) {
            self.fixture.command("RELEASE");
            self.fixture.expect("RELEASED 0 0000000000000204");
            self.expected.rows[0].returned += 1;
            self.expected.rows[0].rvs[1] += 1;
            self.checkpoint();
            let count = self.history.slots.len();
            assert!(
                self.expected.rows[..count]
                    .iter()
                    .all(|row| row.entered > 0 && row.returned > 0)
            );
            self.fixture.command("QUIT");
            self.fixture.expect(&format!("DONE {count}"));
            self.fixture.wait_after_done();
            self.sample(); // No extra credit or hidden health failure on driver exit.
            if self.mode.has_timing() {
                self.assert_held_timing();
            }
            self.session.stop_gate().request_stop();
            // Normal stop uses only what remains of the original whole-case
            // budget. Driver commands/reap retain their separate 5s bounds.
            let case_deadline = self.case_deadline;
            let mut progress = Vec::new();
            self.session
                .detach_producers_driven(
                    || std::time::Instant::now() >= case_deadline,
                    &mut progress,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "producer close failed or exceeded the original case deadline; cleanup unproved: {error:#}\ncleanup progress:\n{}",
                        String::from_utf8_lossy(&progress)
                    )
                });
            assert!(self.session.producers_detached() && self.session.stop_gate().quiescent());
            let starts: aya::maps::HashMap<_, StartKey, CallStart> =
                aya::maps::HashMap::try_from(self.session.ebpf.map("START").unwrap()).unwrap();
            assert!(starts.keys().next().is_none());
            let owner = Array::<_, ThreadOwnerControl>::try_from(
                self.session.ebpf.map("OWNER_CTL").unwrap(),
            )
            .unwrap()
            .get(&0, 0)
            .unwrap();
            assert_eq!(
                (owner.outstanding, owner.poison, owner.abandoned_start),
                (0, 0, 0)
            );
            let banks = self.bank_ids().len();
            eprintln!(
                "{}_GROWTH_POPULATION allocated={count} published={count} exercised={count} banks={banks} ledger_completed={}",
                self.mode.name().to_uppercase(),
                self.expected.totals()[1]
            );
            drop(self.collector);
            drop(self.session);
            assert_eq!(
                self.pool.snapshot().charged_bytes,
                SEMANTIC_TRANSITION_SCRATCH
            );
            let started = self
                .case_deadline
                .checked_sub(self.case_budget)
                .expect("case deadline follows its budget");
            let elapsed = std::time::Instant::now().saturating_duration_since(started);
            assert!(
                std::time::Instant::now() < self.case_deadline,
                "native growth case exceeded its original {:?} budget after {elapsed:?}",
                self.case_budget
            );
        }
    }

    fn native_growth_population(final_count: usize) {
        native_growth_population_with_backend(final_count, crate::attach::AttachBackend::Singles);
    }

    fn native_growth_population_with_backend(
        final_count: usize,
        backend: crate::attach::AttachBackend,
    ) {
        native_growth_population_with_backend_and_mode(final_count, backend, CounterMode::Counts);
    }

    /// Whole-case budget for a growth cell. Singles teardown closes every
    /// link serially, so its budget adds a per-link close allowance to the
    /// case budget; Multi keeps the flat case budget.
    fn growth_case_budget(
        backend: crate::attach::AttachBackend,
        final_count: usize,
    ) -> std::time::Duration {
        match backend {
            crate::attach::AttachBackend::Singles => {
                // Two links per endpoint plus the bank, keepalive and lifecycle links.
                let links = u32::try_from(2 * final_count + 3).expect("growth link count fits u32");
                GROWTH_CASE_BUDGET + GROWTH_SINGLES_CLOSE_PER_LINK * links
            }
            crate::attach::AttachBackend::Multi => GROWTH_CASE_BUDGET,
        }
    }

    #[test]
    fn growth_case_budget_derives_singles_deadline_from_links() {
        use crate::attach::AttachBackend;
        use std::time::Duration;
        // Singles: the 60 s case budget plus 100 ms per link (two per
        // endpoint plus the bank, keepalive and lifecycle links).
        assert_eq!(
            growth_case_budget(AttachBackend::Singles, 513),
            Duration::from_secs(60) + Duration::from_millis(100) * 1029
        );
        assert_eq!(
            growth_case_budget(AttachBackend::Singles, 8192),
            Duration::from_secs(60) + Duration::from_millis(100) * 16387
        );
        // Multi: the flat 60 s case budget, unchanged.
        assert_eq!(
            growth_case_budget(AttachBackend::Multi, 513),
            Duration::from_secs(60)
        );
        assert_eq!(
            growth_case_budget(AttachBackend::Multi, 8192),
            Duration::from_secs(60)
        );
    }

    fn native_growth_population_with_backend_and_mode(
        final_count: usize,
        backend: crate::attach::AttachBackend,
        mode: CounterMode,
    ) {
        let budget = growth_case_budget(backend, final_count);
        let case_deadline = std::time::Instant::now() + budget;
        let mut run =
            NativeGrowthRun::new_with_backend_and_mode(final_count, case_deadline, backend, mode);
        run.fixture.command("START");
        run.fixture.expect("HELD 0");
        run.expected.rows[0].entered += 1;
        let held = run.held_start();
        run.checkpoint();
        run.step(511);
        run.grow(513);
        assert_native_growth_backend(&run.session, backend, true);
        assert_eq!(run.held_start(), held);
        run.checkpoint();
        run.step(512);
        if final_count == GROWTH_ENDPOINTS {
            run.grow(GROWTH_ENDPOINTS);
            assert_native_growth_backend(&run.session, backend, true);
            assert_eq!(run.held_start(), held);
            run.checkpoint();
            run.step(8191);
            assert_eq!(run.bank_ids().len(), 16);
        } else {
            assert_eq!(run.bank_ids().len(), 2);
        }
        run.fixture.command(&format!("RUN 0 {final_count}"));
        run.fixture.expect(&format!("RAN 0 {final_count}"));
        for index in 0..final_count {
            run.expected.call(index, GROWTH_RVS[index % 3]);
        }
        run.checkpoint();
        // A three-value full64 range is useful traffic, not RV/START exhaustion.
        let index = final_count - 1;
        let first = 0x2_0000_0204;
        run.fixture
            .command(&format!("HOT_RV {index} {first:016x} 3"));
        run.fixture
            .expect(&format!("HOT_RV {index} {first:016x} 3"));
        for rv in first..first + 3 {
            run.expected.call(index, rv);
        }
        run.expected.hot = Some(GrowthHotRange {
            index,
            first,
            count: 3,
            completed: 3,
        });
        assert_eq!(run.held_start(), held);
        run.checkpoint();
        if final_count == GROWTH_ENDPOINTS {
            run.refuse_n_plus_one();
        }
        run.finish();
    }

    #[test]
    fn counter_growth_helper_deadlines_refuse_incomplete_cleanup() {
        use std::process::{Command, Stdio};
        use std::time::Instant;
        let child = Command::new("/bin/sh")
            .args(["-c", "printf 'READY 1 8192\n'; IFS= read -r unused"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut fixture = GrowthDriver::from_child(child);
        // A whole-operation deadline expires even with a buffered ledger row;
        // another line must not acquire a fresh five-second allowance.
        fixture.buffered.extend(b"ROW 0 0 0 0 0 0 0 0\n");
        fixture.operation_deadline = Instant::now();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.line())).is_err());
        fixture.operation_deadline = Instant::now() + GROWTH_OPERATION_BUDGET;
        fixture.expect("ROW 0 0 0 0 0 0 0 0");
        assert!(
            growth_reap_until(&mut fixture.child, Instant::now())
                .unwrap()
                .is_none(),
            "a pending child is not successful exit proof"
        );
        fixture.child.kill().unwrap();
        assert!(
            growth_reap_until(&mut fixture.child, Instant::now() + GROWTH_OPERATION_BUDGET)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    #[ignore = "requires prebuilt LP64 growth fixtures, selected format2 object, and authorized 513-endpoint native attachment"]
    fn counter_bank_session_boundary_511_512_counts_growth_lp64() {
        native_growth_population(513);
    }

    #[test]
    #[ignore = "requires prebuilt LP64 growth fixtures, selected format2 object, proven kernel Multi PID filtering, and authorized 513-endpoint native Multi attachment"]
    fn counter_bank_session_boundary_511_512_counts_growth_multi_lp64() {
        native_growth_population_with_backend(513, crate::attach::AttachBackend::Multi);
    }

    #[test]
    #[ignore = "requires prebuilt LP64 growth fixtures and separate FD/memory/native admission for 8192 distinct endpoints after the boundary pilot"]
    fn counter_bank_session_useful_8192_counts_growth_lp64() {
        native_growth_population(8192);
    }

    #[test]
    #[ignore = "requires prebuilt LP64 growth fixtures, selected format2 object, and separate FD/memory/native admission for 8192 distinct endpoints after the qualified Multi513 pilot"]
    fn counter_bank_session_useful_8192_counts_growth_multi_lp64() {
        native_growth_population_with_backend(8192, crate::attach::AttachBackend::Multi);
    }

    #[test]
    #[ignore = "requires LP64 counter-bank-growth fixtures, validated timestamps format2 object, functional kernel Multi attachment, and authorized native Multi staging"]
    fn counter_bank_session_boundary_511_512_timestamps_growth_lp64() {
        native_growth_population_with_backend_and_mode(
            513,
            crate::attach::AttachBackend::Multi,
            CounterMode::Timestamps,
        );
    }

    #[test]
    #[ignore = "requires LP64 counter-bank-growth fixtures, validated latency format2 object, functional kernel Multi attachment, and authorized native Multi staging"]
    fn counter_bank_session_boundary_511_512_latency_growth_lp64() {
        native_growth_population_with_backend_and_mode(
            513,
            crate::attach::AttachBackend::Multi,
            CounterMode::Latency,
        );
    }

    #[test]
    #[ignore = "requires prebuilt LP64 growth fixtures, validated timestamps format2 object, and separate FD/memory/native admission for 8192 distinct timestamp endpoints after the boundary pilot"]
    fn counter_bank_session_useful_8192_timestamps_growth_multi_lp64() {
        native_growth_population_with_backend_and_mode(
            8192,
            crate::attach::AttachBackend::Multi,
            CounterMode::Timestamps,
        );
    }

    #[test]
    #[ignore = "requires prebuilt LP64 growth fixtures, validated latency format2 object, and separate FD/memory/native admission for 8192 distinct latency endpoints after the boundary pilot"]
    fn counter_bank_session_useful_8192_latency_growth_multi_lp64() {
        native_growth_population_with_backend_and_mode(
            8192,
            crate::attach::AttachBackend::Multi,
            CounterMode::Latency,
        );
    }

    #[test]
    fn growth_fd_floor_covers_retained_links_and_stage_charge() {
        assert_eq!(growth_fd_soft_floor(513), 5122);
        assert_eq!(growth_fd_soft_floor(8192), 20480);
        // The 8192-run peak: 15 prior stages retain 15360 links, the last
        // stage charges 512 * 2 + 1 + 1 = 1026 more, and session maps,
        // fixtures and pipes hold under 100.
        assert!(growth_fd_soft_floor(8192) > 15360 + 1026 + 100);
        // The 513-run first stage (1026) exceeds a small host's default
        // soft limit of 1024, which is why the cell raises it.
        assert!(growth_fd_soft_floor(513) > 1026);
    }

    #[test]
    fn growth_fd_budget_raises_soft_only_when_short() {
        use std::cell::Cell;
        // Soft already suffices: no setrlimit call.
        let calls = Cell::new(0);
        ensure_fd_budget_with(
            1026,
            || Ok((524288, 524288)),
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 0);
        // Soft short, hard sufficient: raise soft only.
        let seen = Cell::new((0, 0));
        ensure_fd_budget_with(
            5122,
            || Ok((1024, 524288)),
            |soft, hard| {
                seen.set((soft, hard));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen.get(), (5122, 524288));
        // Hard short too: raise both (the privileged cell runs as root).
        let seen = Cell::new((0, 0));
        ensure_fd_budget_with(
            5122,
            || Ok((1024, 1024)),
            |soft, hard| {
                seen.set((soft, hard));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen.get(), (5122, 5122));
        // A failed raise surfaces; the cell turns it into a loud panic.
        let failed = ensure_fd_budget_with(
            5122,
            || Ok((1024, 1024)),
            |_, _| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        );
        assert!(failed.is_err());
    }

    #[test]
    #[ignore = "requires prebuilt LP64 growth fixtures and a kernel that rejects the counter-bank object as too complex (E2BIG at load)"]
    fn counter_bank_session_verifier_complexity_refuses_clean_lp64() {
        use crate::attach::counter_banks::BankReservation;
        use std::path::{Path, PathBuf};
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"), "1");
        assert_eq!(
            env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
        );
        let provider = PathBuf::from(
            std::env::var_os("P11SCOPE_COUNTER_GROWTH_FIXTURE_PROVIDER")
                .expect("prebuild counter-bank-growth.c with -DCOUNTER_BANK_GROWTH_PROVIDER"),
        );
        let workload = PathBuf::from(
            std::env::var_os("P11SCOPE_COUNTER_GROWTH_FIXTURE_WORKLOAD")
                .expect("prebuild counter-bank-growth.c's LP64 dlopen/pthread driver"),
        );
        let fixture = GrowthDriver::spawn(&workload, &provider);
        let cpus = aya::util::nr_cpus().unwrap();
        let pool = SemanticResourcePool::reference_limit(2 * 1024 * 1024 * 1024);
        let base = BankReservation {
            retained_bytes: 128 * 1024 * 1024,
            transient_bytes: 64 * 1024 * 1024,
            metadata_bytes: 32 * 1024 * 1024,
            file_descriptors: cpus.checked_mul(4).unwrap() + 512,
        };
        let artifact = std::fs::read(
            Path::new(env!("OUT_DIR"))
                .join("counter-bank-growth-v2/p11scope-ebpf-counts-bank-growth-v2"),
        )
        .unwrap();
        let scope = crate::attach::Scope::Pid(fixture.child.id());
        match Session::prepare_counter_banks(&scope, &artifact, base, &pool.reserver()) {
            Ok(_) => panic!(
                "this refusal cell runs only where the kernel rejects the counter object with E2BIG; preparation succeeded"
            ),
            Err(error) => {
                let full = format!("{error:#}");
                if full.contains("helper 181") {
                    panic!(
                        "this cell needs a kernel with bpf_loop that still rejects the object; the old-kernel refusal cell owns pre-5.17 kernels: {full}"
                    );
                }
                let text = error.to_string();
                assert_eq!(
                    text,
                    "counter-mode-unavailable-on-kernel: the kernel verifier rejected a counter program as too complex (E2BIG)",
                    "{full}"
                );
                assert!(text.len() < 512, "refusal must stay finite: {text}");
                assert!(
                    !text.contains("Processed") && !text.contains("insn"),
                    "no raw verifier log may survive: {text}"
                );
            }
        }
    }
}
