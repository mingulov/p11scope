//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private counter publication, retained native custody and charged collection.

use super::{BpfLoopVerdict, CapturePolicy, Scope, Session};
use crate::discovery::identity::{PinnedObjects, RetainedInventoryTarget};
use crate::plan::{AttachKey, AttachPlan, Slot};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
use anyhow::{Context, Result, ensure};
use aya::Ebpf;
use aya::maps::{HashMap, HashOfMaps, Map, MapData, MapError, MapType};
use aya::programs::UProbe;
use p11scope_ebpf_common::CounterMode;
use std::mem::size_of;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) const BANK_CONFIG: u64 = 0x1800_0102;
const COUNTS_GROWTH_V2_CONFIG: u64 = 0x0200_0018_0010_0200;
const TIMESTAMPS_GROWTH_V2_CONFIG: u64 = 0x0200_0028_0010_0200;
const LATENCY_GROWTH_V2_CONFIG: u64 = 0x0200_0128_0010_0200;
const BANKS: usize = 2;
const GROWTH_BANKS: usize = 16;
pub(super) const PROGRAMS: [&str; 2] = ["p11_counter_bank_entry", "p11_counter_bank_return"];

/// Sticky `COUNTER_BANK_FAULT` bits, matching the native bank programs.
/// Route/start/scope faults fail the read; an RV-only fault keeps endpoint
/// counts exact while the RV table is a lower bound.
pub(crate) const BANK_ROUTE_FAULT: u64 = 1;
pub(crate) const BANK_START_FAULT: u64 = 2;
pub(crate) const BANK_RV_FAULT: u64 = 4;
pub(crate) const BANK_SCOPE_FAULT: u64 = 8;

/// Caller-requested allocation envelope. Payload capacities and this explicit
/// metadata allowance are charged; neither is process RSS or a guarantee of
/// total kernel memory. FD slots are a caller reservation, not an OS limit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BankReservation {
    pub(crate) retained_bytes: usize,
    pub(crate) transient_bytes: usize,
    pub(crate) metadata_bytes: usize,
    pub(crate) file_descriptors: usize,
}

impl BankReservation {
    fn charges(self) -> Result<(usize, usize), BankRefusal> {
        if self.retained_bytes == 0
            || self.transient_bytes == 0
            || self.metadata_bytes == 0
            || self.file_descriptors == 0
        {
            return Err(BankRefusal::Budget);
        }
        Ok((
            self.retained_bytes
                .checked_add(self.metadata_bytes)
                .ok_or(BankRefusal::Budget)?,
            self.transient_bytes,
        ))
    }
}

// Mirrors the already-verified native proof layouts, without changing that ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BankMetadata {
    pub(crate) transaction: u64,
    pub(crate) mask: u64,
    pub(crate) logical_slot: u32,
    pub(crate) cells: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BankCommit {
    pub(crate) mask: u64,
    pub(crate) configuration: u64,
}

// SAFETY: repr(C), fully initialized integer fields, with no padding or pointers.
unsafe impl aya::Pod for BankMetadata {}
// SAFETY: repr(C), two initialized u64 fields, with no padding or pointers.
unsafe impl aya::Pod for BankCommit {}
const _: () = {
    assert!(size_of::<BankMetadata>() == 24);
    assert!(size_of::<BankCommit>() == 16);
};

/// Format2 records remain distinct from the independently validated format1 ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CountsBankRoute {
    transaction: u64,
    first: u32,
    end: u32,
    bank: u32,
    cell: u32,
    inner_id: u32,
    reserved_zero: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CountsBankCommit {
    first: u32,
    end: u32,
    configuration: u64,
}

// SAFETY: repr(C), initialized integers only; the checks below exclude padding.
unsafe impl aya::Pod for CountsBankRoute {}
// SAFETY: repr(C), initialized integers only; the checks below exclude padding.
unsafe impl aya::Pod for CountsBankCommit {}
const _: () = {
    use std::mem::offset_of;
    assert!(size_of::<CountsBankRoute>() == 32);
    assert!(offset_of!(CountsBankRoute, transaction) == 0);
    assert!(offset_of!(CountsBankRoute, first) == 8);
    assert!(offset_of!(CountsBankRoute, end) == 12);
    assert!(offset_of!(CountsBankRoute, bank) == 16);
    assert!(offset_of!(CountsBankRoute, cell) == 20);
    assert!(offset_of!(CountsBankRoute, inner_id) == 24);
    assert!(offset_of!(CountsBankRoute, reserved_zero) == 28);
    assert!(size_of::<CountsBankCommit>() == 16);
    assert!(offset_of!(CountsBankCommit, first) == 0);
    assert!(offset_of!(CountsBankCommit, end) == 4);
    assert!(offset_of!(CountsBankCommit, configuration) == 8);
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BankExtent {
    pub(crate) first: u32,
    pub(crate) end: u32,
}

impl BankExtent {
    fn checked(first: u32, end: u32, limit: u32) -> Result<Self, BankRefusal> {
        if first >= end || end > limit {
            return Err(BankRefusal::Shape(BankShapeCause::ExtentBounds));
        }
        Ok(Self { first, end })
    }

    fn len(self) -> usize {
        (self.end - self.first) as usize
    }

    fn legacy_mask(self) -> Result<u64, BankRefusal> {
        Self::checked(self.first, self.end, BANKS as u32)?;
        Ok(((1u64 << self.end) - 1) & !((1u64 << self.first) - 1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BankGeometry {
    mode: CounterMode,
    banks: u32,
    cells: u32,
    configuration: u64,
}

impl BankGeometry {
    fn legacy() -> Self {
        Self {
            mode: CounterMode::Counts,
            banks: 2,
            cells: 1,
            configuration: BANK_CONFIG,
        }
    }

    fn checked(mode: CounterMode, banks: u32, cells: u32) -> Result<Self, BankRefusal> {
        if (banks, cells) != (16, 512) || banks.checked_mul(cells) != Some(8192) {
            return Err(BankRefusal::Shape(BankShapeCause::GeometryDims));
        }
        Ok(Self {
            mode,
            banks,
            cells,
            configuration: match mode {
                CounterMode::Counts => COUNTS_GROWTH_V2_CONFIG,
                CounterMode::Timestamps => TIMESTAMPS_GROWTH_V2_CONFIG,
                CounterMode::Latency => LATENCY_GROWTH_V2_CONFIG,
            },
        })
    }

    fn mode(self) -> CounterMode {
        self.mode
    }

    fn is_legacy(self) -> bool {
        self == Self::legacy()
    }

    fn validate(self) -> Result<(), BankRefusal> {
        if self.is_legacy() || Self::checked(self.mode, self.banks, self.cells) == Ok(self) {
            Ok(())
        } else {
            Err(BankRefusal::Shape(BankShapeCause::GeometryInvalid))
        }
    }

    fn selected(profile: &str) -> Result<Self, BankRefusal> {
        match profile {
            "counts-bank-proof" => Ok(Self::legacy()),
            "counts-bank-growth-v2" => Self::checked(CounterMode::Counts, 16, 512),
            "timestamps-bank-growth-v2" => Self::checked(CounterMode::Timestamps, 16, 512),
            "latency-bank-growth-v2" => Self::checked(CounterMode::Latency, 16, 512),
            _ => Err(BankRefusal::Shape(BankShapeCause::UnknownProfile)),
        }
    }

    fn logical_slots(self) -> usize {
        if self.is_legacy() {
            512
        } else {
            self.limit() as usize
        }
    }

    fn rv_keys(self) -> usize {
        if self.is_legacy() { 4096 } else { 65536 }
    }

    fn limit(self) -> u32 {
        // Both constructors accept only the two closed, checked geometries.
        self.banks * self.cells
    }

    fn locate(self, slot: u32) -> Result<(u32, u32), BankRefusal> {
        if slot >= self.limit() {
            return Err(BankRefusal::Shape(BankShapeCause::SlotOutsideLimit));
        }
        Ok((slot / self.cells, slot % self.cells))
    }

    fn bank_payload_bytes(self, cpus: usize) -> Result<usize, BankRefusal> {
        if cpus == 0 {
            return Err(BankRefusal::Topology);
        }
        (self.cells as usize)
            .checked_mul(self.mode.stats_bytes() as usize)
            .and_then(|bytes| bytes.checked_mul(cpus))
            .ok_or(BankRefusal::Budget)
    }
}

/// Per-capture kernel map memory cap, default 256 MiB. It covers the fixed
/// precharge (RV keys, START, STATS) plus every bank. This is kernel map
/// bytes, not RSS. No CLI override in v0.5.0.
pub(crate) const COUNTER_MAP_MEMORY_LIMIT: usize = 256 * 1024 * 1024;

/// Fixed kernel map bytes: RV_COUNTS plus START plus STATS, with P possible
/// CPUs. RV is a preallocated PERCPU_HASH charged like `configured_payload`
/// for type 5 (key plus aligned value times P, times entries); START is a
/// plain HASH like type 1; STATS is a PERCPU_ARRAY like type 6. The aggregate
/// template stays 24 bytes in every mode; only bank cells vary. Growth
/// constants dominate legacy (RV 4096), which never occurs in production.
pub(crate) fn counter_fixed_map_bytes(cpus: usize) -> Result<usize, BankRefusal> {
    if cpus == 0 {
        return Err(BankRefusal::Topology);
    }
    let rv = 16usize
        .checked_add(8usize.checked_mul(cpus).ok_or(BankRefusal::Budget)?)
        .and_then(|per| per.checked_mul(65536))
        .ok_or(BankRefusal::Budget)?;
    let start = 304usize.checked_mul(16384).ok_or(BankRefusal::Budget)?;
    let stats = 4usize
        .checked_add(24usize.checked_mul(cpus).ok_or(BankRefusal::Budget)?)
        .and_then(|per| per.checked_mul(512))
        .ok_or(BankRefusal::Budget)?;
    rv.checked_add(start)
        .and_then(|total| total.checked_add(stats))
        .ok_or(BankRefusal::Budget)
}

/// Per-bank kernel map bytes for a counter mode: 512 cells times the
/// mode value size times P possible CPUs. This reuses the same
/// `bank_payload_bytes` the staging charge uses, never a second formula.
pub(crate) fn counter_bank_map_bytes(mode: CounterMode, cpus: usize) -> Result<usize, BankRefusal> {
    BankGeometry::checked(mode, 16, 512)?.bank_payload_bytes(cpus)
}

/// Affordable bank count under the memory cap, capped at the 16-bank
/// geometry. Zero means the fixed precharge alone exceeds the cap.
pub(crate) fn counter_affordable_banks(
    mode: CounterMode,
    cpus: usize,
) -> Result<usize, BankRefusal> {
    let fixed = counter_fixed_map_bytes(cpus)?;
    let per_bank = counter_bank_map_bytes(mode, cpus)?;
    if fixed > COUNTER_MAP_MEMORY_LIMIT {
        return Ok(0);
    }
    if per_bank == 0 {
        return Err(BankRefusal::Budget);
    }
    Ok(((COUNTER_MAP_MEMORY_LIMIT - fixed) / per_bank).min(GROWTH_BANKS))
}

/// Affordable endpoint ceiling under the memory cap: banks times 512.
pub(crate) fn counter_affordable_endpoints(
    mode: CounterMode,
    cpus: usize,
) -> Result<usize, BankRefusal> {
    counter_affordable_banks(mode, cpus)?
        .checked_mul(512)
        .ok_or(BankRefusal::Budget)
}

/// Growth-gate check for a total bank count: fixed plus banks times
/// per-bank must fit the cap, else an atomic `BudgetExhausted` refusal
/// naming the `counter-memory-limit` token with needed and available bytes.
pub(crate) fn check_counter_map_memory(
    mode: CounterMode,
    cpus: usize,
    total_banks: usize,
) -> Result<(), BankRefusal> {
    check_counter_map_memory_for_geometry(BankGeometry::checked(mode, 16, 512)?, cpus, total_banks)
}

fn check_counter_map_memory_for_geometry(
    geometry: BankGeometry,
    cpus: usize,
    total_banks: usize,
) -> Result<(), BankRefusal> {
    geometry.validate()?;
    if total_banks > GROWTH_BANKS {
        return Err(BankRefusal::Shape(BankShapeCause::GeometryDims));
    }
    let fixed = counter_fixed_map_bytes(cpus)?;
    let per_bank = geometry.bank_payload_bytes(cpus)?;
    let banks_bytes = total_banks
        .checked_mul(per_bank)
        .ok_or(BankRefusal::Budget)?;
    let needed = fixed.checked_add(banks_bytes).ok_or(BankRefusal::Budget)?;
    if needed > COUNTER_MAP_MEMORY_LIMIT {
        return Err(BankRefusal::BudgetExhausted {
            resource: "counter-memory-limit",
            needed: u64::try_from(needed).map_err(|_| BankRefusal::Budget)?,
            available: u64::try_from(COUNTER_MAP_MEMORY_LIMIT).map_err(|_| BankRefusal::Budget)?,
        });
    }
    Ok(())
}

/// Preflight for a requested endpoint count: refuses with the
/// `counter-memory-limit` token naming the mode, P, fixed bytes, per-bank
/// bytes and the affordable endpoint ceiling.
pub(crate) fn check_counter_endpoints_fit(
    mode: CounterMode,
    cpus: usize,
    endpoints: usize,
) -> Result<(), String> {
    let fixed = counter_fixed_map_bytes(cpus)
        .map_err(|reason| format!("counter-memory-limit: cannot size fixed maps: {reason:?}"))?;
    let per_bank = counter_bank_map_bytes(mode, cpus)
        .map_err(|reason| format!("counter-memory-limit: cannot size banks: {reason:?}"))?;
    let ceiling = counter_affordable_endpoints(mode, cpus)
        .map_err(|reason| format!("counter-memory-limit: cannot size ceiling: {reason:?}"))?;
    if endpoints > ceiling {
        return Err(format!(
            "counter-memory-limit: mode {} P {cpus} fixed {fixed} bytes per-bank {per_bank} bytes affordable ceiling {ceiling} endpoints (requested {endpoints})",
            mode.name()
        ));
    }
    Ok(())
}

/// Read transient bytes for a counter scrape: the per-CPU scratch plus RV
/// staging plus membership and target checks. This replicates the reader's
/// `transient_bytes` plus its acquire extras exactly; the reader test pins
/// equality for every mode and CPU count.
pub(crate) fn counter_read_transient_bytes(
    mode: CounterMode,
    cpus: usize,
    rv_keys: usize,
    logical_slots: usize,
    row_count: usize,
) -> Result<usize, BankRefusal> {
    use p11scope_ebpf_common::RvKey;
    if cpus == 0 {
        return Err(BankRefusal::Topology);
    }
    let value = usize::try_from(mode.stats_bytes())
        .ok()
        .and_then(|value| value.checked_next_multiple_of(8))
        .ok_or(BankRefusal::Budget)?;
    let capacity = cpus
        .checked_next_power_of_two()
        .ok_or(BankRefusal::Budget)?
        .max(4);
    let cells = cpus
        .checked_mul(2)
        .and_then(|n| n.checked_add(capacity.checked_mul(2)?))
        .ok_or(BankRefusal::Budget)?;
    value
        .checked_mul(cells)
        .and_then(|n| n.checked_add(rv_keys.checked_mul(size_of::<(RvKey, u64)>())?))
        .and_then(|n| n.checked_add(5 * OWNED_ALLOCATION_PADDING))
        .and_then(|n| n.checked_add(logical_slots))
        .and_then(|n| n.checked_add(row_count.checked_mul(size_of::<AttachKey>())?))
        .and_then(|n| n.checked_add(2 * OWNED_ALLOCATION_PADDING))
        .ok_or(BankRefusal::Budget)
}

/// Conservative upper bound for one `ReadReservation` (row Vec plus RV
/// trees plus view overhead). The per-row 1024 bytes dominate `CounterRow`;
/// the tree formula matches the collector's node bound for `u64,u64`.
pub(crate) fn counter_read_storage_bytes(
    rows: usize,
    rv_keys: usize,
) -> Result<usize, BankRefusal> {
    let vector = rows
        .checked_mul(1024)
        .and_then(|n| n.checked_add(OWNED_ALLOCATION_PADDING))
        .ok_or(BankRefusal::Budget)?;
    let node = 16usize
        .checked_add(11usize.checked_mul(16).ok_or(BankRefusal::Budget)?)
        .and_then(|n| n.checked_add(12 * 8))
        .and_then(|n| n.checked_add(OWNED_ALLOCATION_PADDING))
        .ok_or(BankRefusal::Budget)?;
    let tree = rv_keys
        .checked_add(rows)
        .and_then(|entries| entries.checked_add(8))
        .and_then(|entries| entries.checked_mul(node))
        .ok_or(BankRefusal::Budget)?;
    vector
        .checked_add(tree)
        .and_then(|n| n.checked_add(1024))
        .ok_or(BankRefusal::Budget)
}

/// Snapshot bytes for a published selection: rows plus indices plus
/// endpoint evidence plus the physical prefix and view overhead. Shared by
/// the live snapshot and the terminal reserve, so both move together.
pub(crate) fn counter_snapshot_bytes_for(
    published: usize,
    positions: usize,
) -> Result<usize, BankRefusal> {
    published
        .checked_mul(size_of::<PublishedRow>() + size_of::<u32>() + size_of::<(u64, u64, u64)>())
        .and_then(|n| n.checked_add(positions.checked_mul(size_of::<AttachKey>() + 1)?))
        .and_then(|n| n.checked_add(size_of::<CounterBankView>() + 5 * OWNED_ALLOCATION_PADDING))
        .ok_or(BankRefusal::Budget)
}

/// Terminal close bookkeeping: link retire, map close and keepalive drop.
/// Fixed 1 MiB upper bound; the terminal hold keeps it unspendable too.
pub(crate) const COUNTER_TERMINAL_CLEANUP_BYTES: usize = 1024 * 1024;

/// Terminal-read lease for the ceiling: storage plus transient at
/// (8192 rows, 65536 RV keys, P possible CPUs) plus the snapshot and
/// cleanup bookkeeping. Growth can never spend it.
pub(crate) fn counter_terminal_reserve_bytes(
    mode: CounterMode,
    cpus: usize,
) -> Result<usize, BankRefusal> {
    let storage = counter_read_storage_bytes(8192, 65536)?;
    let transient = counter_read_transient_bytes(mode, cpus, 65536, 8192, 8192)?;
    let snapshot = counter_snapshot_bytes_for(8192, 8192)?;
    storage
        .checked_add(transient)
        .and_then(|n| n.checked_add(snapshot))
        .and_then(|n| n.checked_add(COUNTER_TERMINAL_CLEANUP_BYTES))
        .ok_or(BankRefusal::Budget)
}

/// Typed counter budgets view. No public output yet; A2.10 renders it.
/// Endpoints come from the directory, RV/START limits from the geometry,
/// RV used from the reader's bounded iteration, FD soft from the OS, memory
/// from the fixed precharge plus allocated banks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterEndpointBudgets {
    pub published: usize,
    pub holes: usize,
    pub ceiling: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterRvBudgets {
    pub used: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterStartBudgets {
    pub limit: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterFdBudgets {
    pub projected: usize,
    pub soft: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterMemoryBudgets {
    pub charged: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterBudgets {
    pub endpoints: CounterEndpointBudgets,
    pub rv_keys: CounterRvBudgets,
    pub start: CounterStartBudgets,
    pub fd: CounterFdBudgets,
    pub memory: CounterMemoryBudgets,
}

/// One private per-mode bank artifact of the default build. The load cell
/// stages each mode's sixteen inner maps from this table; preparation
/// selects the same embedded bytes by identity.
#[derive(Clone, Copy, Debug)]
#[cfg(test)]
struct BankModeArtifact {
    token: &'static str,
    object: &'static str,
    value_bytes: u32,
    configuration: u64,
}

#[cfg(test)]
const BANK_MODE_ARTIFACTS: [BankModeArtifact; 3] = [
    BankModeArtifact {
        token: "counts-bank-growth-v2",
        object: "p11scope-ebpf-counts-bank-growth-v2",
        value_bytes: 24,
        configuration: COUNTS_GROWTH_V2_CONFIG,
    },
    BankModeArtifact {
        token: "timestamps-bank-growth-v2",
        object: "p11scope-ebpf-timestamps-bank-growth-v2",
        value_bytes: 40,
        configuration: TIMESTAMPS_GROWTH_V2_CONFIG,
    },
    BankModeArtifact {
        token: "latency-bank-growth-v2",
        object: "p11scope-ebpf-latency-bank-growth-v2",
        value_bytes: 296,
        configuration: LATENCY_GROWTH_V2_CONFIG,
    },
];

#[cfg(test)]
fn bank_mode_artifact(token: &str) -> Result<BankModeArtifact, BankRefusal> {
    BANK_MODE_ARTIFACTS
        .iter()
        .find(|artifact| artifact.token == token)
        .copied()
        .ok_or(BankRefusal::Shape(BankShapeCause::TestArtifactUnknown))
}

/// The emitted growth token for a counter mode. Preparation admits a mode
/// only when its token is among the emitted outputs.
fn bank_growth_token(mode: CounterMode) -> &'static str {
    match mode {
        CounterMode::Counts => "counts-bank-growth-v2",
        CounterMode::Timestamps => "timestamps-bank-growth-v2",
        CounterMode::Latency => "latency-bank-growth-v2",
    }
}

fn production_geometry_for(object: &[u8], outputs: &str) -> Result<BankGeometry, BankRefusal> {
    if outputs == "counts-bank-proof" {
        return Ok(BankGeometry::legacy());
    }
    let mut selected = None;
    for mode in [
        CounterMode::Counts,
        CounterMode::Timestamps,
        CounterMode::Latency,
    ] {
        if object == counter_object_for_mode(mode) {
            if selected.is_some() {
                return Err(BankRefusal::Shape(BankShapeCause::ObjectAmbiguous));
            }
            selected = Some(mode);
        }
    }
    let mode = selected.ok_or(BankRefusal::Shape(BankShapeCause::ObjectUnknown))?;
    if !outputs
        .split(',')
        .any(|token| token == bank_growth_token(mode))
    {
        return Err(BankRefusal::Shape(BankShapeCause::TokenNotEmitted));
    }
    BankGeometry::selected(bank_growth_token(mode))
}

/// Deterministic build gate, checked before the kernel probe: builds that
/// omit counter objects (`=0`, SMALL, WIDE) refuse every mode with
/// `counter-mode-unavailable-in-build`. build.rs already folds WIDE into the
/// emitted `ENABLED` flag, so this gate reads only the emitted pair. P0 and
/// unsafe-compiled builds embed identical bytes and pass.
fn check_counter_build(enabled: &str, outputs: &str) -> Result<(), String> {
    if enabled != "1" {
        return Err("counter-mode-unavailable-in-build: this build omits counter objects".into());
    }
    if outputs.is_empty() {
        return Err("counter-mode-unavailable-in-build: counter objects were not emitted".into());
    }
    Ok(())
}

/// The embedded bank object for a counter mode. The Session pins its
/// selected object bytes to this embedded copy; omitted builds carry empty
/// statics and refuse through [`check_counter_build`] before any use.
pub(crate) fn counter_object_for_mode(mode: CounterMode) -> &'static [u8] {
    match mode {
        CounterMode::Counts => crate::EBPF_COUNTER_COUNTS_OBJECT,
        CounterMode::Timestamps => crate::EBPF_COUNTER_TIMESTAMPS_OBJECT,
        CounterMode::Latency => crate::EBPF_COUNTER_LATENCY_OBJECT,
    }
}

struct StagedExtent {
    transaction: NonZeroU64,
    commit: CountsBankCommit,
    routes: Vec<(u32, CountsBankRoute)>,
    bank_ids: Vec<(u32, u32)>,
}

impl StagedExtent {
    #[cfg(test)]
    fn checked(
        transaction: NonZeroU64,
        commit: CountsBankCommit,
        routes: Vec<(u32, CountsBankRoute)>,
        bank_ids: Vec<(u32, u32)>,
    ) -> Result<Self, BankRefusal> {
        Self::checked_with(
            BankGeometry::checked(CounterMode::Counts, 16, 512)?,
            transaction,
            commit,
            routes,
            bank_ids,
        )
    }

    fn checked_with(
        geometry: BankGeometry,
        transaction: NonZeroU64,
        commit: CountsBankCommit,
        routes: Vec<(u32, CountsBankRoute)>,
        bank_ids: Vec<(u32, u32)>,
    ) -> Result<Self, BankRefusal> {
        let extent = BankExtent::checked(commit.first, commit.end, geometry.limit())?;
        let first_bank = geometry.locate(extent.first)?.0;
        let last_bank = geometry.locate(extent.end - 1)?.0;
        if commit.configuration != geometry.configuration
            || routes.len() != extent.len()
            || bank_ids.len() != (last_bank - first_bank + 1) as usize
        {
            return Err(BankRefusal::Shape(BankShapeCause::StagedExtentMismatch));
        }
        for (index, &(bank, id)) in bank_ids.iter().enumerate() {
            if bank != first_bank + index as u32
                || id == 0
                || bank_ids[..index].iter().any(|(_, old)| *old == id)
            {
                return Err(BankRefusal::Ownership);
            }
        }
        for (index, &(slot, route)) in routes.iter().enumerate() {
            if slot != extent.first + index as u32
                || route.transaction != transaction.get()
                || (route.first, route.end) != (extent.first, extent.end)
                || (route.bank, route.cell) != geometry.locate(slot)?
                || route.reserved_zero != 0
                || bank_ids[(route.bank - first_bank) as usize].1 != route.inner_id
            {
                return Err(BankRefusal::Ownership);
            }
        }
        Ok(Self {
            transaction,
            commit,
            routes,
            bank_ids,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CandidateCheck {
    Exact,
    Contradictory,
    Unreadable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitObservation {
    Absent,
    Exact,
    Contradictory,
    Unreadable,
}

/// The exact check behind a [`BankRefusal::Shape`]. One variant per refusal
/// origin, so diagnostics name the failing gate; the public refusal token
/// stays undifferentiated. Name-parameterized map funnels share the per-map
/// variants through a map-name mapper; every other site owns its variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BankShapeCause {
    AttachEndOverflow,
    AttachWithoutBanks,
    BankIndexOutsideGeometry,
    BanksMissingForView,
    BanksOuterShape,
    BindingGeometryChanged,
    CommitShape,
    ExtentBounds,
    FaultShape,
    GeometryDims,
    GeometryInvalid,
    HealthShape,
    InnerTemplateMissing,
    InnerTemplateShape,
    InsertCommitMissing,
    InsertCommitViewGrowth,
    InsertCommitViewLegacy,
    InsertInnerHeldVariant,
    InsertInnerOuterMissing,
    InsertInnerOuterView,
    InsertRouteMetaMissing,
    InsertRouteMetaViewGrowth,
    InsertRouteMetaViewLegacy,
    LegacyCommitConfig,
    LegacyRouteFields,
    MetaMapMissing,
    MetaShape,
    MetaViewGrowth,
    MetaViewLegacy,
    ObjectAmbiguous,
    ObjectUnknown,
    OuterNotHashOfMaps,
    PlanBudgetMismatch,
    PlanNotCounters,
    RemoveBankOuterMissing,
    RemoveBankOuterView,
    RemoveRouteMetaMissing,
    RemoveRouteMetaViewGrowth,
    RemoveRouteMetaViewLegacy,
    RoutingHeldVariant,
    RoutingRetainedBank,
    RvShape,
    SlotFileShape,
    SlotOutsideLimit,
    SnapshotGeometryChanged,
    StagedExtentMismatch,
    StagedGeometryChanged,
    StagedWithoutBanks,
    StartShape,
    StatsShape,
    TestArtifactUnknown,
    TestLegacyIndexInvalid,
    TestNonLegacyMask,
    TestReaderMetadataUnknown,
    TokenNotEmitted,
    UnknownMapShape,
    UnknownProfile,
    VerifyRetainedBank,
}

impl BankShapeCause {
    pub(crate) const ALL: [Self; 58] = [
        Self::AttachEndOverflow,
        Self::AttachWithoutBanks,
        Self::BankIndexOutsideGeometry,
        Self::BanksMissingForView,
        Self::BanksOuterShape,
        Self::BindingGeometryChanged,
        Self::CommitShape,
        Self::ExtentBounds,
        Self::FaultShape,
        Self::GeometryDims,
        Self::GeometryInvalid,
        Self::HealthShape,
        Self::InnerTemplateMissing,
        Self::InnerTemplateShape,
        Self::InsertCommitMissing,
        Self::InsertCommitViewGrowth,
        Self::InsertCommitViewLegacy,
        Self::InsertInnerHeldVariant,
        Self::InsertInnerOuterMissing,
        Self::InsertInnerOuterView,
        Self::InsertRouteMetaMissing,
        Self::InsertRouteMetaViewGrowth,
        Self::InsertRouteMetaViewLegacy,
        Self::LegacyCommitConfig,
        Self::LegacyRouteFields,
        Self::MetaMapMissing,
        Self::MetaShape,
        Self::MetaViewGrowth,
        Self::MetaViewLegacy,
        Self::ObjectAmbiguous,
        Self::ObjectUnknown,
        Self::OuterNotHashOfMaps,
        Self::PlanBudgetMismatch,
        Self::PlanNotCounters,
        Self::RemoveBankOuterMissing,
        Self::RemoveBankOuterView,
        Self::RemoveRouteMetaMissing,
        Self::RemoveRouteMetaViewGrowth,
        Self::RemoveRouteMetaViewLegacy,
        Self::RoutingHeldVariant,
        Self::RoutingRetainedBank,
        Self::RvShape,
        Self::SlotFileShape,
        Self::SlotOutsideLimit,
        Self::SnapshotGeometryChanged,
        Self::StagedExtentMismatch,
        Self::StagedGeometryChanged,
        Self::StagedWithoutBanks,
        Self::StartShape,
        Self::StatsShape,
        Self::TestArtifactUnknown,
        Self::TestLegacyIndexInvalid,
        Self::TestNonLegacyMask,
        Self::TestReaderMetadataUnknown,
        Self::TokenNotEmitted,
        Self::UnknownMapShape,
        Self::UnknownProfile,
        Self::VerifyRetainedBank,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BankRefusal {
    Shape(BankShapeCause),
    Topology,
    Allocated,
    Exhausted,
    Budget,
    /// A resource-exhaustion refusal that names what ran out: the resource,
    /// the needed total and the available budget, all finite. Only checks
    /// that compare a need against a limit use it; arithmetic-overflow and
    /// reserver refusals stay bare `Budget`.
    BudgetExhausted {
        resource: &'static str,
        needed: u64,
        available: u64,
    },
    Native,
    Ownership,
    Links,
    Commit,
    Quarantined,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitAck {
    Absent,
    Present(BankCommit),
    Unreadable,
}

#[derive(Clone, Copy, Debug)]
enum FdLimit {
    Finite(u64),
    Unlimited,
}

#[derive(Clone, Copy, Debug)]
struct FdSnapshot {
    soft_limit: FdLimit,
    observed_open: u64,
}

fn check_fd_headroom_with(
    required: usize,
    read: impl FnOnce() -> Result<FdSnapshot, BankRefusal>,
) -> Result<(), BankRefusal> {
    let required = u64::try_from(required)
        .ok()
        .filter(|&n| n != 0)
        .ok_or(BankRefusal::Budget)?;
    let snapshot = read()?;
    let total = snapshot
        .observed_open
        .checked_add(required)
        .ok_or(BankRefusal::Budget)?;
    match snapshot.soft_limit {
        FdLimit::Finite(limit) if total > limit => Err(BankRefusal::BudgetExhausted {
            resource: "file descriptors",
            needed: total,
            available: limit,
        }),
        _ => Ok(()),
    }
}

fn read_fd_snapshot() -> Result<FdSnapshot, BankRefusal> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one initialized writable rlimit; no limit changes.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(BankRefusal::Native);
    }
    let soft_limit = if limit.rlim_cur == libc::RLIM_INFINITY {
        FdLimit::Unlimited
    } else {
        FdLimit::Finite(limit.rlim_cur)
    };
    let entries = std::fs::read_dir("/proc/self/fd").map_err(|_| BankRefusal::Native)?;
    let mut observed_open = 0u64;
    for entry in entries {
        entry.map_err(|_| BankRefusal::Native)?;
        observed_open = observed_open.checked_add(1).ok_or(BankRefusal::Budget)?;
    }
    // The enumeration FD was counted conservatively and has now closed.
    Ok(FdSnapshot {
        soft_limit,
        observed_open,
    })
}

#[allow(clippy::too_many_arguments)] // One checked accounting function for directory and native ownership.
fn stage_requirements(
    geometry: BankGeometry,
    all_slots: &[Slot],
    fresh: BankExtent,
    old_capacity: usize,
    cpus: usize,
    new_banks: usize,
    provider_copies: usize,
    slot_copies: usize,
) -> Result<(usize, usize, usize, usize), BankRefusal> {
    geometry.validate()?;
    let value_bytes = geometry.mode().stats_bytes() as usize;
    let payload = geometry
        .bank_payload_bytes(cpus)?
        .checked_mul(new_banks)
        .ok_or(BankRefusal::Budget)?;
    let copies = all_slots[fresh.first as usize..fresh.end as usize]
        .iter()
        .try_fold(0usize, |bytes, slot| {
            bytes.checked_add(stage_slot_bytes(slot)?.checked_mul(slot_copies)?)
        })
        .and_then(|bytes| bytes.checked_add(provider_copies))
        .ok_or(BankRefusal::Budget)?;
    let table = all_slots
        .len()
        .checked_add(old_capacity)
        .and_then(|n| n.checked_mul(size_of::<BankPosition>()))
        .ok_or(BankRefusal::Budget)?;
    let side_node = 16
        + 11 * size_of::<(u32, super::ProbeSide)>()
        + 12 * size_of::<usize>()
        + OWNED_ALLOCATION_PADDING;
    let side_scratch = all_slots
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_mul(side_node))
        .ok_or(BankRefusal::Budget)?;
    let metadata = fresh
        .len()
        .checked_mul(2 * size_of::<(u32, CountsBankRoute)>())
        .and_then(|bytes| {
            bytes.checked_add(
                all_slots
                    .len()
                    .checked_mul(size_of::<AttachKey>() + size_of::<(u64, u64, u64)>())?,
            )
        })
        .and_then(|bytes| bytes.checked_add((fresh.first as usize).checked_mul(size_of::<u32>())?))
        .and_then(|bytes| {
            bytes.checked_add(
                (geometry.banks as usize)
                    .checked_mul(2 * size_of::<(u32, u32)>() + size_of::<Option<u32>>())?,
            )
        })
        .and_then(|bytes| bytes.checked_add(side_scratch))
        .and_then(|bytes| {
            bytes.checked_add(size_of::<StagedExtent>() + 16 * OWNED_ALLOCATION_PADDING)
        })
        .ok_or(BankRefusal::Budget)?;
    let retained = payload
        .checked_add(copies)
        .and_then(|n| n.checked_add(table))
        .ok_or(BankRefusal::Budget)?;
    let transient = copies
        .checked_add(table)
        .and_then(|n| n.checked_add(metadata.checked_mul(2)?))
        .and_then(|n| n.checked_add(cpus.checked_mul(4 * value_bytes)?))
        .ok_or(BankRefusal::Budget)?;
    // NativeIo admits only OneProcess: Singles retains two BPF-link FDs
    // per endpoint, with one transient perf FD during sequential attachment.
    // Multi can bisect to the same two-leaf-per-endpoint maximum and needs
    // no perf FD, so this same bound conservatively admits either backend.
    // Provider owners share Arc<File>; observed_open already counts old maps,
    // links and providers. Map bytes above still cover every possible CPU.
    // A different scope needs its own FD fanout bound before admission.
    // The caller reservation and readonly OS check remain independent; neither
    // atomically reserves FDs, and later EMFILE uses paid rollback/custody.
    let fds = fresh
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(new_banks))
        .and_then(|n| n.checked_add(1))
        .ok_or(BankRefusal::Budget)?;
    Ok((retained, transient, metadata, fds))
}

/// The four-field envelope comparison both staging prechecks apply: the
/// envelope must cover the required retained, transient, metadata and FD
/// charges, else the stage refuses `Budget`.
pub(crate) fn check_counter_stage_reservation(
    envelope: BankReservation,
    required: (usize, usize, usize, usize),
) -> Result<(), BankRefusal> {
    if envelope.retained_bytes < required.0
        || envelope.transient_bytes < required.1
        || envelope.metadata_bytes < required.2
        || envelope.file_descriptors < required.3
    {
        return Err(BankRefusal::Budget);
    }
    Ok(())
}

fn counter_allocation_bytes<T>(items: usize) -> Option<usize> {
    if items == 0 {
        Some(0)
    } else {
        items
            .checked_mul(size_of::<T>())?
            .checked_add(OWNED_ALLOCATION_PADDING)
    }
}

fn counter_vec_peak_bytes<T>(items: usize) -> Option<usize> {
    if items == 0 {
        return Some(0);
    }
    // Grow-by-two Vec backing, including simultaneous old/new requests and
    // the largest minimum nonzero capacity (u8's eight elements).
    items
        .max(8)
        .checked_mul(3)?
        .checked_mul(size_of::<T>())?
        .checked_add(3 * OWNED_ALLOCATION_PADDING)
}

fn counter_tree_bytes<K, V>(items: usize) -> Option<usize> {
    // Same pinned Rust1.99.1 B=6 internal-node bound as resources.rs. One
    // whole internal node per entry also dominates a sparse root/leaf tree.
    if std::mem::align_of::<K>() > 8 || std::mem::align_of::<V>() > 8 {
        return None;
    }
    let node = size_of::<K>()
        .checked_add(size_of::<V>())?
        .checked_mul(11)?
        .checked_add(16 + 12 * size_of::<usize>())?
        .checked_next_multiple_of(8)?
        .checked_add(OWNED_ALLOCATION_PADDING)?;
    items.checked_mul(node)
}

/// Additional Multi storage, beyond the common Counts stage: retained registry
/// backing, transient grouping/attach/rollback work, and retained leaf metadata.
/// This borrows caller facts and performs no allocation or native operation.
fn counter_multi_requirements(
    fresh: &[Slot],
    old_link_len: usize,
    old_link_capacity: usize,
) -> Result<(usize, usize, usize), BankRefusal> {
    if fresh.is_empty() || old_link_len > old_link_capacity {
        return Err(BankRefusal::Budget);
    }
    (|| -> Option<(usize, usize, usize)> {
        let count = fresh.len();
        let leaves = count.checked_mul(2)?;
        let new_len = old_link_len.checked_add(leaves)?;
        // Generic whole-bundle rollback rebuilds the retained Vec by pushing;
        // its backing must remain paid even after every candidate FD closes.
        let rollback_capacity = old_link_len.max(4).checked_mul(2)?;
        let retained_capacity = old_link_capacity.max(new_len).max(rollback_capacity);
        let retained = counter_allocation_bytes::<super::RegisteredLink>(retained_capacity)?;
        let metadata = leaves.checked_mul(
            size_of::<u32>()
                .checked_add(size_of::<std::os::fd::OwnedFd>())?
                .checked_add(2 * OWNED_ALLOCATION_PADDING)?
                .checked_add(size_of::<super::OwnedLink>() + OWNED_ALLOCATION_PADDING)?
                // attach_failures retains bounded per-site text. Three tuple
                // requests per entry dominate cumulative Vec growth/overlap;
                // earlier consumed extents keep their same metadata payment.
                .checked_add(super::COUNTER_GROUP_DIAGNOSTIC_BYTES + OWNED_ALLOCATION_PADDING)?
                .checked_add(3 * size_of::<(u32, String)>() + 3 * OWNED_ALLOCATION_PADDING)?,
        )?;

        let groups = counter_vec_peak_bytes::<super::StaticGroup>(count)?;
        let paths =
            count.checked_mul(super::COUNTER_ATTACH_PATH_BYTES + OWNED_ALLOCATION_PADDING)?;
        let build = counter_tree_bytes::<
            (std::path::PathBuf, &'static str),
            Vec<super::StaticGroupMember>,
        >(count)?
        .checked_add(groups)?
        .checked_add(counter_vec_peak_bytes::<super::StaticGroupMember>(leaves)?)?
        .checked_add(count.checked_mul(2 * OWNED_ALLOCATION_PADDING)?)?
        .checked_add(paths.checked_mul(2)?)?;
        // Group building ends before cookie/program indexes and bisect work
        // begin. Charge their maximum, rather than summing disjoint phases.
        let live_members =
            counter_allocation_bytes::<super::StaticGroupMember>(count.checked_mul(4)?)?
                .checked_add(count.checked_mul(OWNED_ALLOCATION_PADDING)?)?;
        let runtime = [
            groups,
            live_members,
            paths,
            counter_tree_bytes::<u64, u32>(count)?,
            counter_tree_bytes::<&'static str, ()>(2)?,
            counter_tree_bytes::<&'static str, std::os::fd::RawFd>(2)?,
            counter_tree_bytes::<usize, ()>(count)?,
            counter_vec_peak_bytes::<(u64, u64)>(count.checked_mul(4)?)?,
            counter_vec_peak_bytes::<&super::StaticGroupMember>(count)?,
            counter_vec_peak_bytes::<usize>(count.checked_mul(3)?)?,
            counter_vec_peak_bytes::<Vec<usize>>(count)?,
            counter_vec_peak_bytes::<p11scope_bpf_multi::RefusedSite>(leaves)?,
            counter_vec_peak_bytes::<super::SlotCompletion>(count)?,
            counter_vec_peak_bytes::<super::MultiLinkBundle<()>>(leaves)?,
            counter_vec_peak_bytes::<super::pid_continuity::AttachRound>(count)?,
            counter_vec_peak_bytes::<u32>(count.checked_mul(4)?)?,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| sum.checked_add(bytes))?;
        let deep_members = fresh.iter().try_fold(0usize, |sum, slot| {
            // Inline Slot fields already live in the member Vec above. Moving
            // or sorting that Vec never clones its owned string backing.
            sum.checked_add(stage_slot_bytes(slot)?.checked_sub(size_of::<Slot>())?)
        })?;
        let rollback = [
            counter_vec_peak_bytes::<super::RegisteredLink>(new_len.checked_mul(2)?)?,
            counter_vec_peak_bytes::<bool>(new_len)?,
            counter_tree_bytes::<u32, ()>(leaves)?,
            counter_allocation_bytes::<super::RegisteredLink>(old_link_capacity)?,
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| sum.checked_add(bytes))?;
        let transient = build.max(runtime).checked_add(deep_members)?.max(rollback);
        Some((retained, transient, metadata))
    })()
    .ok_or(BankRefusal::Budget)
}

fn check_counter_multi_reservation(
    envelope: BankReservation,
    base: (usize, usize, usize, usize),
    fresh: &[Slot],
    old_link_len: usize,
    old_link_capacity: usize,
) -> Result<(), BankRefusal> {
    let extra = counter_multi_requirements(fresh, old_link_len, old_link_capacity)?;
    let retained = base.0.checked_add(extra.0).ok_or(BankRefusal::Budget)?;
    let transient = base.1.checked_add(extra.1).ok_or(BankRefusal::Budget)?;
    let metadata = base.2.checked_add(extra.2).ok_or(BankRefusal::Budget)?;
    if envelope.retained_bytes < retained
        || envelope.transient_bytes < transient
        || envelope.metadata_bytes < metadata
        || envelope.file_descriptors < base.3
    {
        return Err(BankRefusal::Budget);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BankPublication {
    Published {
        transaction: u64,
        extent: BankExtent,
    },
    RolledBack {
        transaction: u64,
        extent: BankExtent,
        reason: BankRefusal,
    },
    Quarantined {
        transaction: u64,
        extent: BankExtent,
    },
    Refused(BankRefusal),
}

/// Native operations sit below the production transaction. No operation may
/// replace a key or discard ownership when it reports an uncertain result.
trait BankIo {
    fn possible_cpus(&self) -> usize;
    fn validate_targets(
        &mut self,
        slots: &[Slot],
        published: &[u32],
        fresh: BankExtent,
        old_capacity: usize,
    ) -> Result<(), BankRefusal>;
    fn retain_charge(&mut self, charge: ResourceLease);
    fn allocate_bank(&mut self, bank: u32, all_slots: &[Slot]) -> Result<u32, BankRefusal>;
    fn insert_inner(&mut self, bank: u32, expected_id: u32) -> Result<(), BankRefusal>;
    fn insert_route(&mut self, slot: u32, route: CountsBankRoute) -> Result<(), BankRefusal>;
    fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal>;
    fn verify_candidate(
        &mut self,
        expected: &StagedExtent,
        all_slots: &[Slot],
        published: &[u32],
    ) -> CandidateCheck;
    fn insert_commit(
        &mut self,
        transaction: u64,
        commit: CountsBankCommit,
    ) -> Result<(), BankRefusal>;
    fn observe_commit(&mut self, transaction: u64, expected: CountsBankCommit)
    -> CommitObservation;
    fn remove_route_owned(
        &mut self,
        slot: u32,
        expected: CountsBankRoute,
    ) -> Result<(), BankRefusal>;
    fn remove_new_bank_owned(&mut self, bank: u32, expected_id: u32) -> Result<(), BankRefusal>;
    fn retire_links(&mut self, slots: &[Slot]) -> Result<(), BankRefusal>;
}

#[derive(Clone, Copy)]
enum PositionState {
    Pending,
    Published(CountsBankRoute),
    NeverPublishedRetired,
}

#[derive(Clone, Copy)]
struct BankPosition {
    key: AttachKey,
    state: PositionState,
}

struct BankDirectory {
    geometry: BankGeometry,
    positions: Vec<BankPosition>,
    bank_ids: Vec<Option<u32>>,
    next_transaction: Option<NonZeroU64>,
    quarantined: bool,
    budget: Option<crate::capacity::CounterBudget>,
}

impl Default for BankDirectory {
    fn default() -> Self {
        Self {
            geometry: BankGeometry::legacy(),
            positions: Vec::new(),
            bank_ids: Vec::new(),
            next_transaction: NonZeroU64::new(1),
            quarantined: false,
            budget: None,
        }
    }
}

fn physical(slot: &Slot) -> AttachKey {
    AttachKey {
        object: slot.object,
        file_offset: slot.file_offset,
    }
}

/// Local pin IDs are labels, never cross-store provider identity. The same
/// allocation-free guard protects staging and the reader's row labels.
#[cfg(test)]
fn validate_provider_slots<'a>(
    slots: &[Slot],
    objects: &PinnedObjects,
    published: u64,
    mut retained: impl FnMut(u32) -> Option<&'a RetainedInventoryTarget>,
) -> Result<(), BankRefusal> {
    if slots.len() > BANKS || published & !((1u64 << slots.len()) - 1) != 0 {
        return Err(BankRefusal::Ownership);
    }
    let mut endpoints = [None; BANKS];
    for (index, slot) in slots.iter().enumerate() {
        if slot.index as usize != index
            || objects.abi_for(slot.object) != Some(p11scope_manifest::elf::ElfAbi::Lp64)
            || objects.object_unchanged(slot.object) != Ok(true)
        {
            return Err(BankRefusal::Ownership);
        }
        if published & (1 << index) != 0 {
            let held = retained(slot.index).ok_or(BankRefusal::Ownership)?;
            if held.check_unchanged() != Ok(true) || !held.same_object_as(objects, slot.object) {
                return Err(BankRefusal::Ownership);
            }
        }
        let file = objects
            .file_for(slot.object)
            .ok_or(BankRefusal::Ownership)?;
        let metadata = file.metadata().map_err(|_| BankRefusal::Ownership)?;
        let endpoint = (metadata.dev(), metadata.ino(), slot.file_offset);
        if endpoints[..index].contains(&Some(endpoint)) {
            return Err(BankRefusal::Ownership);
        }
        endpoints[index] = Some(endpoint);
    }
    Ok(())
}

fn retained_binding(
    slot: &Slot,
    plan: Option<&AttachPlan>,
    objects: Option<&PinnedObjects>,
    held: &RetainedInventoryTarget,
) -> Result<(u64, u64, u64), BankRefusal> {
    if held.abi() != p11scope_manifest::elf::ElfAbi::Lp64 || held.check_unchanged() != Ok(true) {
        return Err(BankRefusal::Ownership);
    }
    let (file, digest) = held.borrowed_file_and_digest();
    if digest.is_empty() {
        return Err(BankRefusal::Ownership);
    }
    if let Some(objects) = objects
        && objects.summary(slot.object).is_some()
        && (objects.object_unchanged(slot.object) != Ok(true)
            || !held.same_object_as(objects, slot.object))
    {
        return Err(BankRefusal::Ownership);
    }
    if let Some(expected) = plan.and_then(|plan| plan.borrowed_target_object_of(slot)) {
        let key = held.object_key();
        if expected.dev != (key.device.major, key.device.minor)
            || expected.ino != key.inode
            || expected.sha256.as_deref() != Some(digest)
        {
            return Err(BankRefusal::Ownership);
        }
    }
    let metadata = file.metadata().map_err(|_| BankRefusal::Ownership)?;
    Ok((metadata.dev(), metadata.ino(), slot.file_offset))
}

fn validate_provider_union(
    all_slots: &[Slot],
    published: &[u32],
    fresh: BankExtent,
    objects: &PinnedObjects,
    custody: &NativeCustody,
    require_fresh_retained: bool,
) -> Result<(), BankRefusal> {
    let mut endpoints = Vec::with_capacity(all_slots.len());
    let mut old = published.iter().copied().peekable();
    for slot in all_slots {
        if old.peek() == Some(&slot.index) {
            old.next();
            let held = custody
                .providers
                .get(slot.index as usize)
                .and_then(Option::as_ref)
                .ok_or(BankRefusal::Ownership)?;
            endpoints.push(retained_binding(slot, None, Some(objects), held)?);
        } else if (fresh.first..fresh.end).contains(&slot.index) {
            if require_fresh_retained {
                let held = custody
                    .providers
                    .get(slot.index as usize)
                    .and_then(Option::as_ref)
                    .ok_or(BankRefusal::Ownership)?;
                endpoints.push(retained_binding(slot, None, Some(objects), held)?);
                continue;
            }
            if objects.abi_for(slot.object) != Some(p11scope_manifest::elf::ElfAbi::Lp64)
                || objects.object_unchanged(slot.object) != Ok(true)
            {
                return Err(BankRefusal::Ownership);
            }
            let metadata = objects
                .file_for(slot.object)
                .ok_or(BankRefusal::Ownership)?
                .metadata()
                .map_err(|_| BankRefusal::Ownership)?;
            endpoints.push((metadata.dev(), metadata.ino(), slot.file_offset));
        }
        // Neither a published position nor the fresh extent: Directory has
        // positively classified this historical cell as never published.
    }
    if old.next().is_some() {
        return Err(BankRefusal::Ownership);
    }
    endpoints.sort_unstable();
    if endpoints.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BankRefusal::Ownership);
    }
    Ok(())
}

impl BankDirectory {
    #[cfg(test)]
    fn growth_v2_for(mode: CounterMode) -> Self {
        Self {
            geometry: BankGeometry::checked(mode, 16, 512).expect("closed growth geometry"),
            ..Self::default()
        }
    }

    #[cfg(test)]
    fn counts_growth_v2() -> Self {
        Self::growth_v2_for(CounterMode::Counts)
    }

    fn allocated_high_water(&self) -> usize {
        self.positions.len()
    }

    fn published_indices(&self) -> impl Iterator<Item = u32> + '_ {
        self.positions
            .iter()
            .enumerate()
            .filter_map(|(index, position)| {
                matches!(position.state, PositionState::Published(_)).then_some(index as u32)
            })
    }

    #[cfg(test)]
    fn legacy_published_mask(&self) -> Result<u64, BankRefusal> {
        if !self.geometry.is_legacy() {
            return Err(BankRefusal::Shape(BankShapeCause::TestNonLegacyMask));
        }
        legacy_indices_mask(self.published_indices())
    }

    fn validate_plan(&self, plan: &AttachPlan) -> Result<(), BankRefusal> {
        let crate::plan::AdmissionPolicy::Counters(budget) = plan.admission_policy() else {
            return Err(BankRefusal::Shape(BankShapeCause::PlanNotCounters));
        };
        if budget.validate_count(plan.slots.len()).is_err()
            || plan.slots.len() > self.geometry.limit() as usize
        {
            return Err(BankRefusal::Shape(BankShapeCause::PlanBudgetMismatch));
        }
        if self.budget.is_some_and(|old| old != budget)
            || plan.counter_consumed_end() as usize != self.positions.len()
            || plan.slots.len() < self.positions.len()
            || plan.slots.iter().enumerate().any(|(index, slot)| {
                slot.index as usize != index
                    || (index >= self.positions.len() && !plan.is_active(slot.index))
                    || self
                        .positions
                        .get(index)
                        .is_some_and(|old| old.key != physical(slot))
            })
        {
            return Err(BankRefusal::Topology);
        }
        Ok(())
    }

    fn validate_read_plan(&self, plan: &AttachPlan) -> Result<(), BankRefusal> {
        if self.quarantined {
            return Err(BankRefusal::Quarantined);
        }
        if !matches!(plan.admission_policy(), crate::plan::AdmissionPolicy::Counters(budget) if Some(budget) == self.budget)
            || plan.slots.len() > self.positions.len()
            || (!self.geometry.is_legacy() && plan.slots.len() != self.positions.len())
        {
            return Err(BankRefusal::Topology);
        }
        for (index, position) in self.positions.iter().enumerate() {
            let slot = plan.slots.get(index);
            if slot
                .is_some_and(|slot| slot.index as usize != index || physical(slot) != position.key)
            {
                return Err(BankRefusal::Topology);
            }
            match position.state {
                PositionState::Published(_) if slot.is_some() => {}
                PositionState::NeverPublishedRetired
                    if slot.is_none()
                        || (!self.geometry.is_legacy() && !plan.is_active(index as u32)) => {}
                _ => return Err(BankRefusal::Topology),
            }
        }
        Ok(())
    }

    fn validate_reservation(
        &self,
        plan: &AttachPlan,
        extent: BankExtent,
        reservation: BankReservation,
        cpus: usize,
    ) -> Result<(), BankRefusal> {
        let new_banks = (0..self.geometry.banks as usize)
            .filter(|&bank| {
                self.bank_ids.get(bank).copied().flatten().is_none()
                    && bank >= (extent.first / self.geometry.cells) as usize
                    && bank <= ((extent.end - 1) / self.geometry.cells) as usize
            })
            .count();
        let (retained, transient, metadata, fds) = stage_requirements(
            self.geometry,
            &plan.slots,
            extent,
            self.positions.capacity(),
            cpus,
            new_banks,
            0,
            4,
        )?;
        check_counter_stage_reservation(reservation, (retained, transient, metadata, fds))
    }

    fn stage_with(
        &mut self,
        io: &mut impl BankIo,
        plan: &mut AttachPlan,
        reservation: BankReservation,
        reserve: &SemanticResourceReserver,
    ) -> BankPublication {
        if self.quarantined {
            return BankPublication::Refused(BankRefusal::Quarantined);
        }
        if let Err(reason) = self.validate_plan(plan) {
            return BankPublication::Refused(reason);
        }
        let first = self.allocated_high_water() as u32;
        let end = plan.slots.len() as u32;
        if first == end
            || self.positions.iter().enumerate().any(|(index, position)| {
                matches!(position.state, PositionState::NeverPublishedRetired)
                    && (self.geometry.is_legacy() || plan.is_active(index as u32))
            })
        {
            return BankPublication::Refused(BankRefusal::Allocated);
        }
        let extent = match BankExtent::checked(first, end, self.geometry.limit()) {
            Ok(extent) => extent,
            Err(reason) => return BankPublication::Refused(reason),
        };
        let Some(transaction) = self.next_transaction else {
            return BankPublication::Refused(BankRefusal::Exhausted);
        };
        let (retained, transient) = match reservation.charges() {
            Ok(bytes) => bytes,
            Err(reason) => return BankPublication::Refused(reason),
        };
        if let Err(reason) =
            self.validate_reservation(plan, extent, reservation, io.possible_cpus())
        {
            return BankPublication::Refused(reason);
        }
        let existing_banks = self.bank_ids.iter().flatten().count();
        let new_banks = (0..self.geometry.banks as usize)
            .filter(|&bank| {
                self.bank_ids.get(bank).copied().flatten().is_none()
                    && bank >= (extent.first / self.geometry.cells) as usize
                    && bank <= ((extent.end - 1) / self.geometry.cells) as usize
            })
            .count();
        let total_after = match existing_banks.checked_add(new_banks) {
            Some(total) => total,
            None => return BankPublication::Refused(BankRefusal::Budget),
        };
        if let Err(reason) =
            check_counter_map_memory_for_geometry(self.geometry, io.possible_cpus(), total_after)
        {
            return BankPublication::Refused(reason);
        }
        let charge = match reserve.reserve(retained) {
            Ok(charge) => charge,
            Err(_) => return BankPublication::Refused(BankRefusal::Budget),
        };
        let _scratch = match reserve.reserve(transient) {
            Ok(charge) => charge,
            Err(_) => return BankPublication::Refused(BankRefusal::Budget),
        };
        // Every allocation below is within the precharged request envelope.
        // Exclude ONLY positively never-published holes from uniqueness.
        let mut keys = Vec::with_capacity(plan.slots.len());
        for slot in &plan.slots {
            if self
                .positions
                .get(slot.index as usize)
                .is_some_and(|position| {
                    matches!(position.state, PositionState::NeverPublishedRetired)
                })
            {
                continue;
            }
            keys.push(physical(slot));
        }
        keys.sort_unstable();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return BankPublication::Refused(BankRefusal::Topology);
        }
        let mut published = Vec::with_capacity(self.positions.len());
        published.extend(self.published_indices());
        if let Err(reason) =
            io.validate_targets(&plan.slots, &published, extent, self.positions.capacity())
        {
            return BankPublication::Refused(reason);
        }
        let slots = plan.slots[first as usize..end as usize].to_vec();
        let mut positions = Vec::with_capacity(plan.slots.len());
        positions.extend_from_slice(&self.positions);
        positions.extend(slots.iter().map(|slot| BankPosition {
            key: physical(slot),
            state: PositionState::Pending,
        }));
        let mut routes = Vec::with_capacity(extent.len());
        let mut ids = Vec::with_capacity(self.geometry.banks as usize);
        let mut inserted_routes = Vec::with_capacity(extent.len());
        let mut inserted_banks = Vec::with_capacity(self.geometry.banks as usize);
        let mut bank_ids = Vec::with_capacity(self.geometry.banks as usize);
        bank_ids.extend_from_slice(&self.bank_ids);
        bank_ids.resize(self.geometry.banks as usize, None);
        let commit = CountsBankCommit {
            first,
            end,
            configuration: self.geometry.configuration,
        };
        if io.observe_commit(transaction.get(), commit) != CommitObservation::Absent {
            self.quarantined = true;
            return BankPublication::Refused(BankRefusal::Quarantined);
        }
        if plan.consume_counter_extent(first, end).is_err() {
            return BankPublication::Refused(BankRefusal::Topology);
        }
        // Once native work may start, this same plan and directory retain the
        // consumed extent even if a clean rollback never publishes it.
        io.retain_charge(charge);
        self.positions = positions;
        self.budget = match plan.admission_policy() {
            crate::plan::AdmissionPolicy::Counters(budget) => Some(budget),
            _ => unreachable!("validated counter policy"),
        };
        self.next_transaction = transaction.get().checked_add(1).and_then(NonZeroU64::new);
        let mut links_attempted = false;
        let mut commit_attempted = false;
        let mut candidate = None;
        let result = (|| {
            let first_bank = self.geometry.locate(first)?.0;
            let last_bank = self.geometry.locate(end - 1)?.0;
            for bank in first_bank..=last_bank {
                let id = match bank_ids[bank as usize] {
                    Some(id) => id,
                    None => {
                        let id = io.allocate_bank(bank, &plan.slots)?;
                        if id == 0 || bank_ids.iter().flatten().any(|old| *old == id) {
                            return Err(BankRefusal::Quarantined);
                        }
                        io.insert_inner(bank, id)?;
                        inserted_banks.push((bank, id));
                        bank_ids[bank as usize] = Some(id);
                        id
                    }
                };
                ids.push((bank, id));
            }
            for slot in &slots {
                let (bank, cell) = self.geometry.locate(slot.index)?;
                let route = CountsBankRoute {
                    transaction: transaction.get(),
                    first,
                    end,
                    bank,
                    cell,
                    inner_id: bank_ids[bank as usize].ok_or(BankRefusal::Ownership)?,
                    reserved_zero: 0,
                };
                io.insert_route(slot.index, route)?;
                inserted_routes.push((slot.index, route));
                routes.push((slot.index, route));
            }
            links_attempted = true;
            io.attach_inactive(&slots)?;
            let expected =
                StagedExtent::checked_with(self.geometry, transaction, commit, routes, ids)
                    .map_err(|_| BankRefusal::Quarantined)?;
            if io.verify_candidate(&expected, &plan.slots, &published) != CandidateCheck::Exact {
                return Err(BankRefusal::Quarantined);
            }
            commit_attempted = true;
            let result = io.insert_commit(expected.transaction.get(), expected.commit);
            candidate = Some(expected);
            result
        })();
        if commit_attempted {
            let Some(expected) = candidate.as_ref() else {
                return self.quarantine(transaction.get(), extent);
            };
            // Even a confirmed absent commit permits rollback only while the
            // complete candidate still has its original ownership facts.
            if io.verify_candidate(expected, &plan.slots, &published) != CandidateCheck::Exact {
                return self.quarantine(transaction.get(), extent);
            }
        }
        if result == Err(BankRefusal::Quarantined) {
            return self.quarantine(transaction.get(), extent);
        }
        match io.observe_commit(transaction.get(), commit) {
            CommitObservation::Exact if commit_attempted => {
                let Some(expected) = candidate else {
                    return self.quarantine(transaction.get(), extent);
                };
                for &(slot, route) in &expected.routes {
                    self.positions[slot as usize].state = PositionState::Published(route);
                }
                self.bank_ids = bank_ids;
                BankPublication::Published {
                    transaction: transaction.get(),
                    extent,
                }
            }
            CommitObservation::Absent => {
                let mut clean = true;
                for &(slot, route) in inserted_routes.iter().rev() {
                    clean &= io.remove_route_owned(slot, route).is_ok();
                }
                if links_attempted {
                    clean &= io.retire_links(&slots).is_ok();
                }
                for &(bank, id) in inserted_banks.iter().rev() {
                    clean &= io.remove_new_bank_owned(bank, id).is_ok();
                }
                if !clean {
                    return self.quarantine(transaction.get(), extent);
                }
                for position in &mut self.positions[first as usize..end as usize] {
                    position.state = PositionState::NeverPublishedRetired;
                }
                for slot in first..end {
                    plan.deactivate(slot);
                }
                BankPublication::RolledBack {
                    transaction: transaction.get(),
                    extent,
                    reason: result.err().unwrap_or(BankRefusal::Commit),
                }
            }
            _ => self.quarantine(transaction.get(), extent),
        }
    }

    fn quarantine(&mut self, transaction: u64, extent: BankExtent) -> BankPublication {
        self.quarantined = true;
        BankPublication::Quarantined {
            transaction,
            extent,
        }
    }
}

#[cfg(test)]
fn legacy_indices_mask(indices: impl IntoIterator<Item = u32>) -> Result<u64, BankRefusal> {
    let mut mask = 0;
    for index in indices {
        if index >= BANKS as u32 || mask & (1 << index) != 0 {
            return Err(BankRefusal::Shape(BankShapeCause::TestLegacyIndexInvalid));
        }
        mask |= 1 << index;
    }
    Ok(mask)
}

fn legacy_commit(commit: CountsBankCommit) -> Result<BankCommit, BankRefusal> {
    if commit.configuration != BANK_CONFIG {
        return Err(BankRefusal::Shape(BankShapeCause::LegacyCommitConfig));
    }
    let extent = BankExtent::checked(commit.first, commit.end, BANKS as u32)?;
    Ok(BankCommit {
        mask: extent.legacy_mask()?,
        configuration: BANK_CONFIG,
    })
}

fn legacy_route(slot: u32, route: CountsBankRoute) -> Result<BankMetadata, BankRefusal> {
    let extent = BankExtent::checked(route.first, route.end, BANKS as u32)?;
    if route.transaction == 0
        || route.bank != slot
        || route.cell != 0
        || route.inner_id == 0
        || route.reserved_zero != 0
        || slot < extent.first
        || slot >= extent.end
    {
        return Err(BankRefusal::Shape(BankShapeCause::LegacyRouteFields));
    }
    Ok(BankMetadata {
        transaction: route.transaction,
        mask: extent.legacy_mask()?,
        logical_slot: slot,
        cells: 1,
    })
}

fn stage_slot_bytes(slot: &Slot) -> Option<usize> {
    size_of::<Slot>()
        .checked_add(8 * OWNED_ALLOCATION_PADDING)?
        .checked_add(slot.object_path.capacity())?
        .checked_add(slot.names.capacity().checked_mul(size_of::<String>())?)?
        .checked_add(
            slot.module_ids
                .capacity()
                .checked_mul(size_of::<crate::plan::ModuleId>())?,
        )?
        .checked_add(slot.names.iter().try_fold(0usize, |sum, name| {
            sum.checked_add(name.capacity())?
                .checked_add(OWNED_ALLOCATION_PADDING)
        })?)
}

pub(crate) struct BankHandle {
    pub(crate) map: Map,
    id: u32,
}

struct NativeCustody {
    banks: [Option<Arc<BankHandle>>; GROWTH_BANKS],
    providers: Vec<Option<RetainedInventoryTarget>>,
    // Last: all native handles and retained identity drop before their charges.
    charges: Vec<ResourceLease>,
}

impl NativeCustody {
    fn retain_charge(&mut self, charge: ResourceLease) {
        assert!(
            self.charges.len() < self.charges.capacity(),
            "preflight reserves every consumed extent holder"
        );
        self.charges.push(charge);
    }

    fn retain_targets(
        &mut self,
        slots: &[Slot],
        objects: &PinnedObjects,
    ) -> Result<(), BankRefusal> {
        for slot in slots {
            if self
                .providers
                .get(slot.index as usize)
                .is_none_or(Option::is_some)
                || objects.abi_for(slot.object) != Some(p11scope_manifest::elf::ElfAbi::Lp64)
                || objects.object_unchanged(slot.object) != Ok(true)
            {
                return Err(BankRefusal::Ownership);
            }
        }
        for slot in slots {
            self.providers[slot.index as usize] = Some(
                objects
                    .retain_inventory_target(slot.object)
                    .map_err(|_| BankRefusal::Ownership)?,
            );
        }
        Ok(())
    }
}

/// Shared by Session and every actual transferred link, including uncertain
/// close/abandonment. The same owner covers all maps, identities and attempts.
pub(crate) struct CounterKeepalive {
    custody: Mutex<NativeCustody>,
    _base: ResourceLease,
}

impl CounterKeepalive {
    pub(crate) fn precharge(reserve: &SemanticResourceReserver, bytes: usize) -> Result<Arc<Self>> {
        Self::precharge_with_geometry(reserve, bytes, BankGeometry::legacy())
    }

    // One checked holder formula serves standalone precharge and preparation's
    // map/custody overlap. The latter already counts Self in its inline floor.
    fn allocation_bytes(geometry: BankGeometry) -> Result<usize> {
        geometry
            .validate()
            .map_err(|_| anyhow::anyhow!("unsupported counter geometry"))?;
        (geometry.limit() as usize)
            .checked_mul(size_of::<Option<RetainedInventoryTarget>>() + size_of::<ResourceLease>())
            .and_then(|n| {
                n.checked_add(
                    size_of::<Self>() + 2 * size_of::<usize>() + 3 * OWNED_ALLOCATION_PADDING,
                )
            })
            .context("counter custody capacity overflow")
    }

    fn precharge_with_geometry(
        reserve: &SemanticResourceReserver,
        bytes: usize,
        geometry: BankGeometry,
    ) -> Result<Arc<Self>> {
        let required = Self::allocation_bytes(geometry)?;
        let positions = geometry.limit() as usize;
        ensure!(
            bytes >= required,
            "counter custody reservation is smaller than its bounded holders"
        );
        let charge = reserve
            .reserve(bytes)
            .map_err(|_| anyhow::anyhow!("counter custody reservation refused"))?;
        let mut providers = Vec::with_capacity(positions);
        providers.resize_with(positions, || None);
        Ok(Arc::new(Self {
            custody: Mutex::new(NativeCustody {
                banks: std::array::from_fn(|_| None),
                providers,
                charges: Vec::with_capacity(positions),
            }),
            _base: charge,
        }))
    }
}

pub(super) struct CounterBanks {
    directory: Arc<Mutex<BankDirectory>>,
    pub(super) keepalive: Arc<CounterKeepalive>,
    cpus: usize,
    geometry: BankGeometry,
    backend: super::AttachBackend,
    // Immutable geometry avoids reentering the Directory lock during stage.
    link_staging: Arc<AtomicU64>,
    terminal: Option<ResourceLease>,
}

pub(super) struct CounterPreparation<'a> {
    pub(super) object: &'a [u8],
    pub(super) banks: CounterBanks,
    // Common loading/parsing and the pre-existing Session preparation execute
    // while the caller's explicit transient envelope is reserved.
    _scratch: ResourceLease,
}

fn configured_payload(map: &aya_obj::Map, cpus: usize) -> Option<usize> {
    let entries = map.max_entries() as usize;
    let key = map.key_size() as usize;
    let value = map.value_size() as usize;
    let bytes = match map.map_type() {
        1 | 2 | 3 | 8 | 9 | 12 | 13 => key.checked_add(value)?.checked_mul(entries)?,
        5 | 6 => key
            .checked_add(value.checked_next_multiple_of(8)?.checked_mul(cpus)?)?
            .checked_mul(entries)?,
        27 => entries,
        // TASK_STORAGE is dynamic, with the existing native owner reservation
        // ceiling; this is configured data capacity, not kernel slab usage.
        29 => key.checked_add(value)?.checked_mul(16_384 + 64)?,
        _ => return None,
    };
    match map.inner() {
        Some(inner) => bytes.checked_add(configured_payload(&inner, cpus)?),
        None => Some(bytes),
    }
}

impl<'a> CounterPreparation<'a> {
    fn new(
        object: &'a [u8],
        envelope: BankReservation,
        reserve: &SemanticResourceReserver,
    ) -> Result<Self> {
        Self::new_with_backend(object, envelope, reserve, super::AttachBackend::Singles)
    }

    fn new_with_backend(
        object: &'a [u8],
        envelope: BankReservation,
        reserve: &SemanticResourceReserver,
        backend: super::AttachBackend,
    ) -> Result<Self> {
        Self::new_with_backend_and_probe(
            object,
            envelope,
            reserve,
            backend,
            super::kernel_bpf_loop_probe,
        )
    }

    fn new_with_backend_and_probe(
        object: &'a [u8],
        envelope: BankReservation,
        reserve: &SemanticResourceReserver,
        backend: super::AttachBackend,
        probe: impl FnOnce() -> BpfLoopVerdict,
    ) -> Result<Self> {
        // Deterministic build checks run before the kernel probe, so a WIDE
        // build on an old kernel reports the build refusal, not the kernel
        // token. Omitted objects (`=0`, SMALL, WIDE) refuse every mode here.
        check_counter_build(
            env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"),
            env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
        )
        .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;
        // The 8192 owner cleanup calls helper 181 (bpf_loop, Linux 5.17+):
        // a kernel proven to lack it cannot run counter bank objects, so
        // preparation refuses before charging anything. An unproven probe
        // (no BPF privilege, unexpected errors) defers to the real load.
        match probe() {
            BpfLoopVerdict::Available | BpfLoopVerdict::Unknown(_) => {}
            BpfLoopVerdict::Unavailable(reason) => {
                anyhow::bail!("counter-mode-unavailable-on-kernel: {reason}")
            }
        }
        // The Session loads the embedded object for its mode: byte identity
        // against the embedded bank objects selects the mode (growth geometry
        // only; legacy has no embedded copy and never occurs in production).
        let geometry = production_geometry_for(object, env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"))
            .map_err(|_| anyhow::anyhow!("unsupported private counter artifact profile"))?;
        let (retained, transient) = envelope
            .charges()
            .map_err(|_| anyhow::anyhow!("invalid counter reservation"))?;
        let keepalive = if geometry.is_legacy() {
            CounterKeepalive::precharge(reserve, retained)?
        } else {
            CounterKeepalive::precharge_with_geometry(reserve, retained, geometry)?
        };
        let scratch = reserve
            .reserve(transient)
            .map_err(|_| anyhow::anyhow!("counter load overlap reservation refused"))?;
        // The caller bounds this parser/loader overlap explicitly. A raw byte
        // length is a necessary input bound, never an exact allocator estimate.
        ensure!(
            transient
                >= object
                    .len()
                    .checked_mul(32)
                    .context("counter parser bound overflow")?,
            "counter parser/loader transient reservation is too small"
        );
        let cpus = aya::util::nr_cpus().map_err(|(path, error)| {
            anyhow::Error::new(error).context(format!("reading possible counter CPUs at {path}"))
        })?;
        ensure!(
            cpus != 0,
            "private counter preparation requires possible CPUs"
        );
        check_counter_endpoints_fit(geometry.mode(), cpus, 1)
            .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;
        let terminal_bytes = counter_terminal_reserve_bytes(geometry.mode(), cpus)
            .map_err(|_| anyhow::anyhow!("counter terminal reserve overflow"))?;
        let terminal = reserve
            .reserve(terminal_bytes)
            .map_err(|_| anyhow::anyhow!("counter terminal reserve refused"))?;
        let parsed = aya_obj::Object::parse(object).context("parsing selected counter artifact")?;
        // Parse and validate actual maps/template before common loading can
        // attach lifecycle roots. An emitted token alone grants no shape.
        validate_object_maps(geometry, |name| parsed.maps.get(name))
            .map_err(|_| anyhow::anyhow!("unsupported private counter artifact profile"))?;
        ensure!(
            PROGRAMS
                .iter()
                .all(|name| parsed.programs.contains_key(*name)),
            "selected object lacks the exact private counter bank roots"
        );
        let payload = parsed
            .maps
            .values()
            .try_fold(0usize, |total, map| {
                total.checked_add(configured_payload(map, cpus)?)
            })
            .context("unsupported counter payload shape or checked overflow")?;
        let payload = if geometry.is_legacy() {
            payload
                .checked_add(
                    cpus.checked_mul(24 * BANKS)
                        .context("bank payload overflow")?,
                )
                .context("counter payload overflow")?
        } else {
            payload
        }; // Format2 real banks are precharged by each stage.
        let payload_floor = payload
            .checked_add(
                size_of::<CounterBanks>()
                    + size_of::<CounterKeepalive>()
                    + size_of::<Session>()
                    + 16 * OWNED_ALLOCATION_PADDING,
            )
            .context("counter retained bound overflow")?;
        ensure!(
            envelope.retained_bytes >= payload_floor,
            "counter retained reservation is smaller than configured data capacity"
        );
        let combined_floor = payload_floor
            .checked_sub(size_of::<CounterKeepalive>())
            .and_then(|bytes| bytes.checked_add(CounterKeepalive::allocation_bytes(geometry).ok()?))
            .context("counter map/custody overlap bound overflow")?;
        ensure!(
            retained >= combined_floor,
            "counter retained and metadata reservation cannot cover maps and custody together"
        );
        let descriptors = parsed
            .maps
            .len()
            .checked_add(parsed.programs.len())
            .and_then(|n| n.checked_add(cpus.checked_mul(4)?.checked_add(32)?))
            .context("counter descriptor bound overflow")?;
        ensure!(
            envelope.file_descriptors >= descriptors,
            "counter FD reservation is too small"
        );
        drop(parsed);
        Ok(Self {
            object,
            banks: CounterBanks {
                directory: Arc::new(Mutex::new(BankDirectory {
                    geometry,
                    ..BankDirectory::default()
                })),
                keepalive,
                cpus,
                geometry,
                backend,
                link_staging: Arc::new(AtomicU64::new(0)),
                terminal: Some(terminal),
            },
            _scratch: scratch,
        })
    }

    pub(super) fn validate_and_load(
        &self,
        ebpf: &mut Ebpf,
        backend: super::AttachBackend,
    ) -> Result<()> {
        self.banks
            .validate_backend(backend)
            .map_err(|_| anyhow::anyhow!("private counter preparation backend mismatch"))?;
        validate_maps(ebpf, self.banks.geometry)
            .map_err(|failure| anyhow::anyhow!("private counter map refusal: {failure:?}"))?;
        // No caller or lifecycle link exists yet, and all routing maps are
        // required empty. A foreign/stale key never activates staging early.
        for name in ["COUNTER_BANKS", "COUNTER_BANK_META", "COUNTER_BANK_COMMIT"] {
            let empty = match name {
                "COUNTER_BANKS" => {
                    HashOfMaps::<_, u32>::try_from(ebpf.map(name).context("counter outer map")?)?
                        .keys()
                        .next()
                        .is_none()
                }
                "COUNTER_BANK_META" if self.banks.geometry.is_legacy() => {
                    HashMap::<_, u32, BankMetadata>::try_from(
                        ebpf.map(name).context("counter metadata map")?,
                    )?
                    .keys()
                    .next()
                    .is_none()
                }
                "COUNTER_BANK_META" => HashMap::<_, u32, CountsBankRoute>::try_from(
                    ebpf.map(name).context("counter metadata map")?,
                )?
                .keys()
                .next()
                .is_none(),
                _ if self.banks.geometry.is_legacy() => HashMap::<_, u64, BankCommit>::try_from(
                    ebpf.map(name).context("counter commit map")?,
                )?
                .keys()
                .next()
                .is_none(),
                _ => HashMap::<_, u64, CountsBankCommit>::try_from(
                    ebpf.map(name).context("counter commit map")?,
                )?
                .keys()
                .next()
                .is_none(),
            };
            ensure!(empty, "private counter routing maps must begin empty");
        }
        for program in PROGRAMS {
            let root: &mut UProbe = ebpf
                .program_mut(program)
                .context("private counter root")?
                .try_into()?;
            if super::loads_with_multi_flag(backend, program) {
                root.load_multi()
            } else {
                root.load()
            }
            .with_context(|| format!("loading private counter root {program}"))?;
        }
        Ok(())
    }
}

fn map_data(map: &Map, cause: BankShapeCause) -> Result<&MapData, BankRefusal> {
    match map {
        Map::HashOfMaps(data)
        | Map::Array(data)
        | Map::HashMap(data)
        | Map::PerCpuArray(data)
        | Map::PerCpuHashMap(data) => Ok(data),
        _ => Err(BankRefusal::Shape(cause)),
    }
}

fn exact_map(
    ebpf: &Ebpf,
    name: &str,
    kind: MapType,
    key: u32,
    value: u32,
    entries: u32,
    flags: u32,
) -> Result<(), BankRefusal> {
    let cause = profile_map_cause(name);
    let data = map_data(ebpf.map(name).ok_or(BankRefusal::Shape(cause))?, cause)?;
    let actual = super::read_map_metadata(name, data).map_err(|_| BankRefusal::Shape(cause))?;
    super::compare_map_metadata(
        name,
        actual,
        super::map_metadata(kind, key, value, entries, flags),
    )
    .map_err(|_| BankRefusal::Shape(cause))
}

fn exact_map_metadata(
    map: &Map,
    kind: MapType,
    key: u32,
    value: u32,
    entries: u32,
    flags: u32,
    cause: BankShapeCause,
) -> Result<(), BankRefusal> {
    let actual = super::read_map_metadata("retained counter bank", map_data(map, cause)?)
        .map_err(|_| BankRefusal::Native)?;
    super::compare_map_metadata(
        "retained counter bank",
        actual,
        super::map_metadata(kind, key, value, entries, flags),
    )
    .map_err(|_| BankRefusal::Shape(cause))
}

fn validate_maps(ebpf: &Ebpf, geometry: BankGeometry) -> Result<(), BankRefusal> {
    validate_maps_for(geometry, |name| {
        let cause = profile_map_cause(name);
        let data = map_data(ebpf.map(name).ok_or(BankRefusal::Shape(cause))?, cause)?;
        super::read_map_metadata(name, data).map_err(|_| BankRefusal::Shape(cause))
    })
}

#[cfg(test)]
fn validate_maps_with(
    metadata: impl FnMut(&str) -> Result<super::ExactMapMetadata, BankRefusal>,
) -> Result<(), BankRefusal> {
    validate_maps_for(BankGeometry::legacy(), metadata)
}

fn profile_maps(geometry: BankGeometry) -> &'static [(&'static str, super::ExactMapMetadata)] {
    if geometry.is_legacy() {
        &FORMAT1_MAPS
    } else {
        &FORMAT2_MAPS
    }
}

/// The shape cause for a profile-map check, by map name. The
/// name-parameterized validation funnels (live, binding and object-parse)
/// share these per-map causes; the map identity is the diagnostic payload.
fn profile_map_cause(name: &str) -> BankShapeCause {
    match name {
        "COUNTER_BANKS" => BankShapeCause::BanksOuterShape,
        "COUNTER_BANK_META" => BankShapeCause::MetaShape,
        "COUNTER_BANK_COMMIT" => BankShapeCause::CommitShape,
        "COUNTER_BANK_FAULT" => BankShapeCause::FaultShape,
        "COUNTER_HEALTH" => BankShapeCause::HealthShape,
        "STATS" => BankShapeCause::StatsShape,
        "RV_COUNTS" => BankShapeCause::RvShape,
        "START" => BankShapeCause::StartShape,
        "SLOT_FILE" => BankShapeCause::SlotFileShape,
        _ => BankShapeCause::UnknownMapShape,
    }
}

fn validate_maps_for(
    geometry: BankGeometry,
    mut metadata: impl FnMut(&str) -> Result<super::ExactMapMetadata, BankRefusal>,
) -> Result<(), BankRefusal> {
    geometry.validate()?;
    for &(name, expected) in profile_maps(geometry) {
        super::compare_map_metadata(name, metadata(name)?, expected)
            .map_err(|_| BankRefusal::Shape(profile_map_cause(name)))?;
    }
    Ok(())
}

const FORMAT1_MAPS: [(&str, super::ExactMapMetadata); 8] = [
    (
        "COUNTER_BANKS",
        super::map_metadata(MapType::HashOfMaps, 4, 4, 2, 128),
    ),
    (
        "COUNTER_BANK_META",
        super::map_metadata(MapType::Hash, 4, 24, 2, 128),
    ),
    (
        "COUNTER_BANK_COMMIT",
        super::map_metadata(MapType::Hash, 8, 16, 2, 128),
    ),
    (
        "COUNTER_BANK_FAULT",
        super::map_metadata(MapType::PerCpuArray, 4, 8, 1, 0),
    ),
    (
        "COUNTER_HEALTH",
        super::map_metadata(MapType::PerCpuArray, 4, 8, 2, 0),
    ),
    (
        "STATS",
        super::map_metadata(MapType::PerCpuArray, 4, 24, 512, 0),
    ),
    (
        "RV_COUNTS",
        super::map_metadata(MapType::PerCpuHash, 16, 8, 4096, 0),
    ),
    (
        "START",
        super::map_metadata(
            MapType::Hash,
            16,
            size_of::<p11scope_ebpf_common::CallStart>() as u32,
            16384,
            0,
        ),
    ),
];

const FORMAT2_MAPS: [(&str, super::ExactMapMetadata); 9] = [
    (
        "COUNTER_BANKS",
        super::map_metadata(MapType::HashOfMaps, 4, 4, 16, 128),
    ),
    (
        "COUNTER_BANK_META",
        super::map_metadata(MapType::Hash, 4, 32, 8192, 128),
    ),
    (
        "COUNTER_BANK_COMMIT",
        super::map_metadata(MapType::Hash, 8, 16, 8192, 128),
    ),
    (
        "COUNTER_BANK_FAULT",
        super::map_metadata(MapType::PerCpuArray, 4, 8, 1, 0),
    ),
    (
        "COUNTER_HEALTH",
        super::map_metadata(MapType::PerCpuArray, 4, 8, 2, 0),
    ),
    (
        "STATS",
        super::map_metadata(MapType::PerCpuArray, 4, 24, 512, 0),
    ),
    (
        "RV_COUNTS",
        super::map_metadata(MapType::PerCpuHash, 16, 8, 65536, 0),
    ),
    (
        "START",
        super::map_metadata(MapType::Hash, 16, 288, 16384, 0),
    ),
    (
        "SLOT_FILE",
        super::map_metadata(MapType::Array, 4, 4, 8192, 128),
    ),
];

#[cfg(test)]
fn validate_format1_object_maps<'a>(
    map: impl FnMut(&str) -> Option<&'a aya_obj::Map>,
) -> Result<(), BankRefusal> {
    validate_object_maps(BankGeometry::legacy(), map)
}

fn validate_object_maps<'a>(
    geometry: BankGeometry,
    mut map: impl FnMut(&str) -> Option<&'a aya_obj::Map>,
) -> Result<(), BankRefusal> {
    geometry.validate()?;
    for &(name, expected) in profile_maps(geometry) {
        let actual = map(name).ok_or(BankRefusal::Shape(profile_map_cause(name)))?;
        if (
            actual.map_type(),
            actual.key_size(),
            actual.value_size(),
            actual.max_entries(),
            actual.map_flags(),
        ) != (
            expected.map_type as u32,
            expected.key_size,
            expected.value_size,
            expected.max_entries,
            expected.flags,
        ) {
            return Err(BankRefusal::Shape(profile_map_cause(name)));
        }
    }
    let inner = map("COUNTER_BANKS")
        .and_then(aya_obj::Map::inner)
        .ok_or(BankRefusal::Shape(BankShapeCause::InnerTemplateMissing))?;
    if (
        inner.map_type(),
        inner.key_size(),
        inner.value_size(),
        inner.max_entries(),
        inner.map_flags(),
    ) != (
        6,
        4,
        geometry.mode().stats_bytes() as u32,
        geometry.cells,
        0,
    ) || inner.inner().is_some()
    {
        return Err(BankRefusal::Shape(BankShapeCause::InnerTemplateShape));
    }
    Ok(())
}

/// Map-of-maps lookup returns an ID. Borrow the retained outer FD directly;
/// unlike HashOfMaps::get this does not open another inner FD on each scrape.
fn outer_id(ebpf: &Ebpf, geometry: BankGeometry, key: u32) -> Result<Option<u32>, BankRefusal> {
    // Pin buffer sizes at this raw-syscall seam even if another crate-private
    // caller has replaced an Ebpf map since the original preparation.
    exact_map(
        ebpf,
        "COUNTER_BANKS",
        MapType::HashOfMaps,
        4,
        4,
        geometry.banks,
        128,
    )?;
    let Some(Map::HashOfMaps(data)) = ebpf.map("COUNTER_BANKS") else {
        return Err(BankRefusal::Shape(BankShapeCause::OuterNotHashOfMaps));
    };
    let mut value = 0u32;
    let attr = super::BpfMapElementAttr {
        map_fd: data.fd().as_fd().as_raw_fd() as u32,
        key: (&key as *const u32) as u64,
        value: (&mut value as *mut u32) as u64,
        ..Default::default()
    };
    match super::bpf_map_element_syscall(
        super::BPF_MAP_LOOKUP_ELEM,
        &attr,
        size_of::<super::BpfMapElementAttr>(),
    ) {
        Ok(()) => Ok(Some(value)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(_) => Err(BankRefusal::Quarantined),
    }
}

fn observe_route(
    ebpf: &Ebpf,
    geometry: BankGeometry,
    slot: u32,
    expected: CountsBankRoute,
) -> Result<Option<bool>, BankRefusal> {
    let map = ebpf
        .map("COUNTER_BANK_META")
        .ok_or(BankRefusal::Shape(BankShapeCause::MetaMapMissing))?;
    if geometry.is_legacy() {
        let map: HashMap<_, u32, BankMetadata> = HashMap::try_from(map)
            .map_err(|_| BankRefusal::Shape(BankShapeCause::MetaViewLegacy))?;
        match map.get(&slot, 0) {
            Ok(actual) => Ok(Some(actual == legacy_route(slot, expected)?)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(_) => Err(BankRefusal::Native),
        }
    } else {
        let map: HashMap<_, u32, CountsBankRoute> = HashMap::try_from(map)
            .map_err(|_| BankRefusal::Shape(BankShapeCause::MetaViewGrowth))?;
        match map.get(&slot, 0) {
            Ok(actual) => Ok(Some(actual == expected)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(_) => Err(BankRefusal::Native),
        }
    }
}

fn observe_native_commit(
    ebpf: &Ebpf,
    geometry: BankGeometry,
    transaction: u64,
    expected: CountsBankCommit,
) -> CommitObservation {
    let Some(map) = ebpf.map("COUNTER_BANK_COMMIT") else {
        return CommitObservation::Unreadable;
    };
    if geometry.is_legacy() {
        let Ok(expected) = legacy_commit(expected) else {
            return CommitObservation::Contradictory;
        };
        let Ok(map): Result<HashMap<_, u64, BankCommit>, _> = HashMap::try_from(map) else {
            return CommitObservation::Contradictory;
        };
        match map.get(&transaction, 0) {
            Ok(actual) if actual == expected => CommitObservation::Exact,
            Ok(_) => CommitObservation::Contradictory,
            Err(MapError::KeyNotFound) => CommitObservation::Absent,
            Err(_) => CommitObservation::Unreadable,
        }
    } else {
        let Ok(map): Result<HashMap<_, u64, CountsBankCommit>, _> = HashMap::try_from(map) else {
            return CommitObservation::Contradictory;
        };
        match map.get(&transaction, 0) {
            Ok(actual) if actual == expected => CommitObservation::Exact,
            Ok(_) => CommitObservation::Contradictory,
            Err(MapError::KeyNotFound) => CommitObservation::Absent,
            Err(_) => CommitObservation::Unreadable,
        }
    }
}

struct NativeIo<'a> {
    session: &'a mut Session,
    objects: &'a PinnedObjects,
    custody: &'a mut NativeCustody,
    cpus: usize,
    geometry: BankGeometry,
    reservation: BankReservation,
}

impl BankIo for NativeIo<'_> {
    fn possible_cpus(&self) -> usize {
        self.cpus
    }

    fn validate_targets(
        &mut self,
        slots: &[Slot],
        published: &[u32],
        fresh: BankExtent,
        old_capacity: usize,
    ) -> Result<(), BankRefusal> {
        if self.session.mutation_stopped()
            || self
                .session
                .counter_banks
                .as_ref()
                .is_none_or(|banks| banks.validate_backend(self.session.backend).is_err())
            || !matches!(
                self.session.uprobe_scope,
                aya::programs::uprobe::UProbeScope::OneProcess(_)
            )
            || self.objects.check_unchanged() != Ok(true)
            || aya::util::nr_cpus().ok() != Some(self.cpus)
        {
            return Err(BankRefusal::Topology);
        }
        validate_maps(&self.session.ebpf, self.geometry)?;
        if self.custody.charges.len() == self.custody.charges.capacity() {
            return Err(BankRefusal::Budget);
        }
        let new_banks = (fresh.first / self.geometry.cells..=(fresh.end - 1) / self.geometry.cells)
            .filter(|&bank| self.custody.banks[bank as usize].is_none())
            .count();
        let provider_copies = slots[fresh.first as usize..fresh.end as usize]
            .iter()
            .try_fold(0usize, |bytes, slot| {
                if self.session.has_slot_link(slot.index)
                    || self
                        .custody
                        .providers
                        .get(slot.index as usize)
                        .is_none_or(Option::is_some)
                {
                    return None;
                }
                bytes.checked_add(
                    self.objects
                        .retained_target_copy_allocation_charge(slot.object)?
                        .checked_mul(4)?,
                )
            })
            .ok_or(BankRefusal::Budget)?;
        let (retained, transient, metadata, fds) = stage_requirements(
            self.geometry,
            slots,
            fresh,
            old_capacity,
            self.cpus,
            new_banks,
            provider_copies,
            16,
        )?;
        check_counter_stage_reservation(self.reservation, (retained, transient, metadata, fds))?;
        if self.session.backend == super::AttachBackend::Multi {
            check_counter_multi_reservation(
                self.reservation,
                (retained, transient, metadata, fds),
                &slots[fresh.first as usize..fresh.end as usize],
                self.session.links.len(),
                self.session.links.capacity(),
            )?;
        }
        check_fd_headroom_with(fds, read_fd_snapshot)?;
        validate_provider_union(slots, published, fresh, self.objects, self.custody, false)
    }

    fn retain_charge(&mut self, charge: ResourceLease) {
        self.custody.retain_charge(charge);
    }

    fn allocate_bank(&mut self, bank: u32, _: &[Slot]) -> Result<u32, BankRefusal> {
        let index = bank as usize;
        if bank >= self.geometry.banks {
            return Err(BankRefusal::Shape(BankShapeCause::BankIndexOutsideGeometry));
        }
        if self.custody.banks[index].is_some() {
            return Err(BankRefusal::Allocated);
        }
        let object = aya_obj::Map::new_from_params(
            6,
            4,
            self.geometry.mode().stats_bytes() as u32,
            self.geometry.cells,
            0,
        );
        let data =
            MapData::create(object, "p11_counter_bank", None).map_err(|_| BankRefusal::Native)?;
        let info = data.info().map_err(|_| BankRefusal::Native)?;
        let id = info.id();
        if id == 0 || self.custody.banks.iter().flatten().any(|old| old.id == id) {
            return Err(BankRefusal::Ownership);
        }
        self.custody.banks[index] = Some(Arc::new(BankHandle {
            map: Map::PerCpuArray(data),
            id,
        }));
        Ok(id)
    }

    fn insert_inner(&mut self, bank: u32, expected_id: u32) -> Result<(), BankRefusal> {
        let held = self
            .custody
            .banks
            .get(bank as usize)
            .and_then(Option::as_ref)
            .ok_or(BankRefusal::Ownership)?;
        if held.id != expected_id {
            return Err(BankRefusal::Quarantined);
        }
        let mut outer: HashOfMaps<_, u32> = HashOfMaps::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANKS")
                .ok_or(BankRefusal::Shape(BankShapeCause::InsertInnerOuterMissing))?,
        )
        .map_err(|_| BankRefusal::Shape(BankShapeCause::InsertInnerOuterView))?;
        let result = outer.insert(
            bank,
            map_data(&held.map, BankShapeCause::InsertInnerHeldVariant)?,
            super::BPF_NOEXIST,
        );
        match outer_id(&self.session.ebpf, self.geometry, bank)? {
            Some(id) if id == expected_id && result.is_ok() => Ok(()),
            None if result.is_err() => {
                // No outer key or links ever exposed this positively created map.
                self.custody.banks[bank as usize] = None;
                Err(BankRefusal::Native)
            }
            _ => Err(BankRefusal::Quarantined),
        }
    }

    fn insert_route(&mut self, slot: u32, route: CountsBankRoute) -> Result<(), BankRefusal> {
        if self
            .custody
            .banks
            .get(route.bank as usize)
            .and_then(Option::as_ref)
            .is_none_or(|bank| bank.id != route.inner_id)
        {
            return Err(BankRefusal::Quarantined);
        }
        let map = self
            .session
            .ebpf
            .map_mut("COUNTER_BANK_META")
            .ok_or(BankRefusal::Shape(BankShapeCause::InsertRouteMetaMissing))?;
        let result = if self.geometry.is_legacy() {
            let mut map: HashMap<_, u32, BankMetadata> = HashMap::try_from(map)
                .map_err(|_| BankRefusal::Shape(BankShapeCause::InsertRouteMetaViewLegacy))?;
            map.insert(slot, legacy_route(slot, route)?, super::BPF_NOEXIST)
        } else {
            let mut map: HashMap<_, u32, CountsBankRoute> = HashMap::try_from(map)
                .map_err(|_| BankRefusal::Shape(BankShapeCause::InsertRouteMetaViewGrowth))?;
            map.insert(slot, route, super::BPF_NOEXIST)
        };
        match observe_route(&self.session.ebpf, self.geometry, slot, route) {
            Ok(Some(true)) if result.is_ok() => Ok(()),
            Ok(None) if result.is_err() => Err(BankRefusal::Native),
            _ => Err(BankRefusal::Quarantined),
        }
    }

    fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
        self.custody.retain_targets(slots, self.objects)?;
        let first = slots.first().ok_or(BankRefusal::Topology)?.index;
        let end = slots
            .last()
            .ok_or(BankRefusal::Topology)?
            .index
            .checked_add(1)
            .ok_or(BankRefusal::Shape(BankShapeCause::AttachEndOverflow))?;
        let banks = self
            .session
            .counter_banks
            .as_ref()
            .ok_or(BankRefusal::Shape(BankShapeCause::AttachWithoutBanks))?;
        let _stage = banks.begin_link_stage((u64::from(first) << 32) | u64::from(end))?;
        let (failed, mut completed) = self
            .session
            .attach_targets(slots, self.objects)
            .map_err(|_| BankRefusal::Links)?;
        completed.sort_unstable_by_key(|(slot, _)| *slot);
        let sides = self.session.current_static_sides();
        if !failed.is_empty()
            || completed.len() != slots.len()
            || !completed
                .iter()
                .map(|(slot, _)| *slot)
                .eq(slots.iter().map(|slot| slot.index))
            || self.objects.check_unchanged() != Ok(true)
            || slots.iter().any(|slot| {
                !sides.contains(&(slot.index, super::ProbeSide::Entry))
                    || !sides.contains(&(slot.index, super::ProbeSide::Return))
            })
        {
            return Err(BankRefusal::Links);
        }
        Ok(())
    }

    fn verify_candidate(
        &mut self,
        expected: &StagedExtent,
        all_slots: &[Slot],
        published: &[u32],
    ) -> CandidateCheck {
        if validate_maps(&self.session.ebpf, self.geometry).is_err()
            || self.session.mutation_stopped()
            || self
                .session
                .counter_banks
                .as_ref()
                .is_none_or(|banks| banks.validate_backend(self.session.backend).is_err())
            || !matches!(
                self.session.uprobe_scope,
                aya::programs::uprobe::UProbeScope::OneProcess(_)
            )
            || self.objects.check_unchanged() != Ok(true)
        {
            return CandidateCheck::Contradictory;
        }
        if aya::util::nr_cpus().ok() != Some(self.cpus) {
            return CandidateCheck::Unreadable;
        }
        let fresh = BankExtent {
            first: expected.commit.first,
            end: expected.commit.end,
        };
        if validate_provider_union(
            all_slots,
            published,
            fresh,
            self.objects,
            self.custody,
            true,
        )
        .is_err()
        {
            return CandidateCheck::Contradictory;
        }
        let sides = self.session.current_static_sides();
        for &(bank, id) in &expected.bank_ids {
            let Some(held) = self
                .custody
                .banks
                .get(bank as usize)
                .and_then(Option::as_ref)
            else {
                return CandidateCheck::Contradictory;
            };
            // The candidate cause never escapes as a refusal here: a foreign
            // variant contradicts the candidate instead.
            let Ok(data) = map_data(&held.map, BankShapeCause::VerifyRetainedBank) else {
                return CandidateCheck::Contradictory;
            };
            let Ok(info) = data.info() else {
                return CandidateCheck::Unreadable;
            };
            if held.id != id
                || info.id() != id
                || exact_map_metadata(
                    &held.map,
                    MapType::PerCpuArray,
                    4,
                    self.geometry.mode().stats_bytes() as u32,
                    self.geometry.cells,
                    0,
                    BankShapeCause::VerifyRetainedBank,
                )
                .is_err()
            {
                return CandidateCheck::Contradictory;
            }
            match outer_id(&self.session.ebpf, self.geometry, bank) {
                Ok(Some(actual)) if actual == id => {}
                Ok(_) => return CandidateCheck::Contradictory,
                Err(_) => return CandidateCheck::Unreadable,
            }
        }
        for &(slot, route) in &expected.routes {
            if !sides.contains(&(slot, super::ProbeSide::Entry))
                || !sides.contains(&(slot, super::ProbeSide::Return))
            {
                return CandidateCheck::Contradictory;
            }
            match observe_route(&self.session.ebpf, self.geometry, slot, route) {
                Ok(Some(true)) => {}
                Ok(_) => return CandidateCheck::Contradictory,
                Err(_) => return CandidateCheck::Unreadable,
            }
        }
        CandidateCheck::Exact
    }

    fn insert_commit(
        &mut self,
        transaction: u64,
        commit: CountsBankCommit,
    ) -> Result<(), BankRefusal> {
        let map = self
            .session
            .ebpf
            .map_mut("COUNTER_BANK_COMMIT")
            .ok_or(BankRefusal::Shape(BankShapeCause::InsertCommitMissing))?;
        if self.geometry.is_legacy() {
            let mut map: HashMap<_, u64, BankCommit> = HashMap::try_from(map)
                .map_err(|_| BankRefusal::Shape(BankShapeCause::InsertCommitViewLegacy))?;
            map.insert(transaction, legacy_commit(commit)?, super::BPF_NOEXIST)
                .map_err(|_| BankRefusal::Commit)
        } else {
            let mut map: HashMap<_, u64, CountsBankCommit> = HashMap::try_from(map)
                .map_err(|_| BankRefusal::Shape(BankShapeCause::InsertCommitViewGrowth))?;
            map.insert(transaction, commit, super::BPF_NOEXIST)
                .map_err(|_| BankRefusal::Commit)
        }
    }

    fn observe_commit(
        &mut self,
        transaction: u64,
        expected: CountsBankCommit,
    ) -> CommitObservation {
        observe_native_commit(&self.session.ebpf, self.geometry, transaction, expected)
    }

    fn remove_route_owned(
        &mut self,
        slot: u32,
        expected: CountsBankRoute,
    ) -> Result<(), BankRefusal> {
        if self
            .custody
            .banks
            .get(expected.bank as usize)
            .and_then(Option::as_ref)
            .is_none_or(|bank| bank.id != expected.inner_id)
            || observe_route(&self.session.ebpf, self.geometry, slot, expected)? != Some(true)
        {
            return Err(BankRefusal::Ownership);
        }
        let map = self
            .session
            .ebpf
            .map_mut("COUNTER_BANK_META")
            .ok_or(BankRefusal::Shape(BankShapeCause::RemoveRouteMetaMissing))?;
        if self.geometry.is_legacy() {
            let mut map: HashMap<_, u32, BankMetadata> = HashMap::try_from(map)
                .map_err(|_| BankRefusal::Shape(BankShapeCause::RemoveRouteMetaViewLegacy))?;
            map.remove(&slot).map_err(|_| BankRefusal::Ownership)
        } else {
            let mut map: HashMap<_, u32, CountsBankRoute> = HashMap::try_from(map)
                .map_err(|_| BankRefusal::Shape(BankShapeCause::RemoveRouteMetaViewGrowth))?;
            map.remove(&slot).map_err(|_| BankRefusal::Ownership)
        }
    }

    fn remove_new_bank_owned(&mut self, bank: u32, expected_id: u32) -> Result<(), BankRefusal> {
        if self
            .custody
            .banks
            .get(bank as usize)
            .and_then(Option::as_ref)
            .is_none_or(|held| held.id != expected_id)
            || outer_id(&self.session.ebpf, self.geometry, bank)? != Some(expected_id)
        {
            return Err(BankRefusal::Ownership);
        }
        let mut outer: HashOfMaps<_, u32> = HashOfMaps::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANKS")
                .ok_or(BankRefusal::Shape(BankShapeCause::RemoveBankOuterMissing))?,
        )
        .map_err(|_| BankRefusal::Shape(BankShapeCause::RemoveBankOuterView))?;
        outer.remove(&bank).map_err(|_| BankRefusal::Ownership)?;
        if outer_id(&self.session.ebpf, self.geometry, bank)?.is_some() {
            return Err(BankRefusal::Ownership);
        }
        self.custody.banks[bank as usize] = None;
        Ok(())
    }

    fn retire_links(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
        let outcome = self
            .session
            .detach_failed_slots(slots)
            .map_err(|_| BankRefusal::Links)?;
        if outcome.pending.is_some()
            || !outcome.rebuild_failures.is_empty()
            || slots
                .iter()
                .any(|slot| self.session.has_slot_link(slot.index))
            || !self.session.detach_failures.is_empty()
        {
            return Err(BankRefusal::Links);
        }
        Ok(())
    }
}

/// Maps a kernel verifier-budget rejection during counter preparation to
/// the named counter-mode refusal. Only a genuine BPF_PROG_LOAD E2BIG (the
/// program is too complex for this kernel's verifier) is rewritten, with a
/// finite reason that never embeds the raw verifier log; every other error
/// passes through unchanged. Detection walks the io errors in the chain: a
/// program-load failure carries its syscall errno as the chain source, so no
/// direct match on the loader's private error shape is needed at this seam.
fn map_counter_verifier_budget_refusal(error: anyhow::Error) -> anyhow::Error {
    let budget = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| super::is_verifier_budget_errno(io.raw_os_error()))
    });
    if budget {
        anyhow::anyhow!(
            "counter-mode-unavailable-on-kernel: the kernel verifier rejected a counter program as too complex (E2BIG)"
        )
    } else {
        error
    }
}

impl Session {
    /// A new private Session only, with its backend fixed before root loading.
    pub(crate) fn prepare_counter_banks_with_backend(
        scope: &Scope,
        object: &[u8],
        reservation: BankReservation,
        reserve: &SemanticResourceReserver,
        backend: super::AttachBackend,
    ) -> Result<Self> {
        match backend {
            super::AttachBackend::Singles => {
                Self::prepare_counter_banks(scope, object, reservation, reserve)
            }
            super::AttachBackend::Multi => {
                ensure!(
                    matches!(scope, Scope::Pid(pid) if *pid != 0),
                    "private bank proof requires one PID scope"
                );
                let preparation =
                    CounterPreparation::new_with_backend(object, reservation, reserve, backend)?;
                let selected = super::select_session_backend(
                    super::BackendSelection::Multi,
                    true,
                    super::multi_functional_probe,
                    super::kernel_multi_pid_filter,
                )?;
                preparation
                    .banks
                    .validate_backend(selected.backend)
                    .map_err(|_| anyhow::anyhow!("private counter preparation backend mismatch"))?;
                let counter_mode = preparation.banks.geometry_mode();
                let (mut session, prepared_instance) = Self::prepare_inner_unlinked_with_object(
                    scope,
                    CapturePolicy::Counter(counter_mode),
                    None,
                    None,
                    None,
                    backend,
                    None,
                    Some(preparation),
                )
                .map_err(map_counter_verifier_budget_refusal)?;
                let banks = session
                    .counter_banks
                    .as_ref()
                    .context("private counter owner")?;
                banks
                    .validate_unlinked_backend(session.backend, &session.links)
                    .map_err(|_| {
                        anyhow::anyhow!("private counter backend or active registry mismatch")
                    })?;
                session.selection = super::BackendSelection::Multi;
                session.links = super::activate_after_preparation_with(Ok(()), || {
                    super::attach_lifecycle_with(
                        &mut session.ebpf,
                        Self::attach_lifecycle_program,
                        |ebpf, _, link| super::detach_registered_link(ebpf, link),
                    )
                })?;
                session.instance = super::InstanceTracking::start(
                    &mut session.ebpf,
                    &session.image_coverage,
                    prepared_instance,
                );
                Ok(session)
            }
        }
    }

    /// Private, explicit proof constructor; no Engine/run/selector calls it.
    pub(crate) fn prepare_counter_banks(
        scope: &Scope,
        object: &[u8],
        reservation: BankReservation,
        reserve: &SemanticResourceReserver,
    ) -> Result<Self> {
        ensure!(
            matches!(scope, Scope::Pid(pid) if *pid != 0),
            "private bank proof requires one PID scope"
        );
        let preparation = CounterPreparation::new(object, reservation, reserve)?;
        let counter_mode = preparation.banks.geometry_mode();
        let (mut session, prepared_instance) = Self::prepare_inner_unlinked_with_object(
            scope,
            CapturePolicy::Counter(counter_mode),
            None,
            None,
            None,
            super::AttachBackend::Singles,
            None,
            Some(preparation),
        )
        .map_err(map_counter_verifier_budget_refusal)?;
        // The keepalive is already in Session before the first real producer.
        session.links = super::activate_after_preparation_with(Ok(()), || {
            super::attach_lifecycle_with(
                &mut session.ebpf,
                Self::attach_lifecycle_program,
                |ebpf, _, link| super::detach_registered_link(ebpf, link),
            )
        })?;
        session.instance = super::InstanceTracking::start(
            &mut session.ebpf,
            &session.image_coverage,
            prepared_instance,
        );
        Ok(session)
    }

    pub(crate) fn stage_counter_banks(
        &mut self,
        plan: &mut AttachPlan,
        objects: &PinnedObjects,
        reservation: BankReservation,
        reserve: &SemanticResourceReserver,
    ) -> BankPublication {
        let Some(banks) = &self.counter_banks else {
            return BankPublication::Refused(BankRefusal::Shape(
                BankShapeCause::StagedWithoutBanks,
            ));
        };
        let directory = Arc::clone(&banks.directory);
        let keepalive = Arc::clone(&banks.keepalive);
        let cpus = banks.cpus;
        let geometry = banks.geometry;
        let Ok(mut directory) = directory.lock() else {
            return BankPublication::Refused(BankRefusal::Quarantined);
        };
        if directory.geometry != geometry {
            return BankPublication::Refused(BankRefusal::Shape(
                BankShapeCause::StagedGeometryChanged,
            ));
        }
        let Ok(mut custody) = keepalive.custody.lock() else {
            return BankPublication::Refused(BankRefusal::Quarantined);
        };
        let mut native = NativeIo {
            session: self,
            objects,
            custody: &mut custody,
            cpus,
            geometry,
            reservation,
        };
        directory.stage_with(&mut native, plan, reservation, reserve)
    }
}

impl CounterBanks {
    pub(super) fn geometry_mode(&self) -> CounterMode {
        self.geometry.mode()
    }

    fn budgets(&self, rv_used: usize) -> Result<CounterBudgets, BankRefusal> {
        let directory = self
            .directory
            .lock()
            .map_err(|_| BankRefusal::Quarantined)?;
        if directory.geometry != self.geometry {
            return Err(BankRefusal::Shape(BankShapeCause::SnapshotGeometryChanged));
        }
        self.geometry.validate()?;
        let published = directory.published_indices().count();
        let holes = directory
            .positions
            .iter()
            .filter(|position| matches!(position.state, PositionState::NeverPublishedRetired))
            .count();
        let ceiling = self.geometry.limit() as usize;
        let rv_limit = self.geometry.rv_keys();
        if rv_used > rv_limit {
            return Err(BankRefusal::Topology);
        }
        let allocated_banks = directory.bank_ids.iter().flatten().count();
        let projected = published
            .checked_mul(2)
            .and_then(|n| n.checked_add(allocated_banks))
            .and_then(|n| n.checked_add(1))
            .ok_or(BankRefusal::Budget)?;
        let soft = match read_fd_snapshot()?.soft_limit {
            FdLimit::Finite(limit) => Some(limit),
            FdLimit::Unlimited => None,
        };
        let fixed = counter_fixed_map_bytes(self.cpus)?;
        let per_bank = self.geometry.bank_payload_bytes(self.cpus)?;
        let charged = fixed
            .checked_add(
                allocated_banks
                    .checked_mul(per_bank)
                    .ok_or(BankRefusal::Budget)?,
            )
            .ok_or(BankRefusal::Budget)?;
        Ok(CounterBudgets {
            endpoints: CounterEndpointBudgets {
                published,
                holes,
                ceiling,
            },
            rv_keys: CounterRvBudgets {
                used: rv_used,
                limit: rv_limit,
            },
            start: CounterStartBudgets { limit: 16384 },
            fd: CounterFdBudgets { projected, soft },
            memory: CounterMemoryBudgets {
                charged,
                limit: COUNTER_MAP_MEMORY_LIMIT,
            },
        })
    }

    pub(super) fn validate_backend(
        &self,
        backend: super::AttachBackend,
    ) -> Result<(), BankRefusal> {
        if self.backend == backend {
            Ok(())
        } else {
            Err(BankRefusal::Topology)
        }
    }

    fn validate_unlinked_backend(
        &self,
        backend: super::AttachBackend,
        links: &[super::RegisteredLink],
    ) -> Result<(), BankRefusal> {
        self.validate_backend(backend)?;
        if links.is_empty() {
            Ok(())
        } else {
            Err(BankRefusal::Allocated)
        }
    }

    fn begin_link_stage(&self, word: u64) -> Result<LinkStage, BankRefusal> {
        let first = (word >> 32) as u32;
        let end = word as u32;
        BankExtent::checked(first, end, self.geometry.limit())
            .map_err(|_| BankRefusal::Quarantined)?;
        if self
            .link_staging
            .compare_exchange(0, word, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return Err(BankRefusal::Quarantined);
        }
        Ok(LinkStage(Arc::clone(&self.link_staging)))
    }

    pub(super) fn permits_link_stage(&self, slots: &[Slot]) -> bool {
        let word = self.link_staging.load(Ordering::Relaxed);
        let first = (word >> 32) as u32;
        let end = word as u32;
        let Ok(extent) = BankExtent::checked(first, end, self.geometry.limit()) else {
            return false;
        };
        slots.len() == extent.len()
            && slots
                .iter()
                .enumerate()
                .all(|(offset, slot)| slot.index == first + offset as u32)
    }
}

struct LinkStage(Arc<AtomicU64>);
impl Drop for LinkStage {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

pub(super) fn retain_link(
    link: super::OwnedLink,
    keepalive: Option<&Arc<CounterKeepalive>>,
) -> super::OwnedLink {
    match keepalive {
        Some(keepalive) => link.retain_counter(Arc::clone(keepalive)),
        None => link,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BankReadStatus {
    Healthy,
    Routing,
    Quarantined,
}

/// The mode comes only from the prepared bank geometry word. It is never
/// inferred from a caller's requested mode, a map's name, or a value size.
#[derive(Clone, Copy)]
struct CounterReaderProfile {
    cpus: usize,
    geometry: BankGeometry,
}

impl CounterReaderProfile {
    fn mode(&self) -> CounterMode {
        self.geometry.mode()
    }
    fn logical_slots(&self) -> usize {
        self.geometry.logical_slots()
    }
    fn rv_keys(&self) -> usize {
        self.geometry.rv_keys()
    }
    fn start_rows(&self) -> u32 {
        16384
    }
    fn possible_cpus(&self) -> usize {
        self.cpus
    }
}

fn reader_profile_with(
    banks: Option<&CounterBanks>,
    metadata: impl FnMut(&str) -> Result<super::ExactMapMetadata, BankRefusal>,
    possible_cpus: impl FnOnce() -> Result<usize, BankRefusal>,
) -> Result<Option<CounterReaderProfile>, BankRefusal> {
    let Some(banks) = banks else { return Ok(None) };
    let directory = banks
        .directory
        .lock()
        .map_err(|_| BankRefusal::Quarantined)?;
    if directory.quarantined {
        return Err(BankRefusal::Quarantined);
    }
    if directory.geometry != banks.geometry {
        return Err(BankRefusal::Shape(BankShapeCause::BindingGeometryChanged));
    }
    directory.geometry.validate()?;
    drop(directory);
    let cpus = possible_cpus()?;
    if cpus == 0 || cpus != banks.cpus {
        return Err(BankRefusal::Topology);
    }
    validate_maps_for(banks.geometry, metadata)?;
    Ok(Some(CounterReaderProfile {
        cpus,
        geometry: banks.geometry,
    }))
}

/// A fresh-read borrow of the original prepared Session. It cannot be made
/// from a CLI mode and cannot survive a mutable growth operation on Session.
/// Collection identity only: this grants no capture or admission authority.
pub(crate) struct CounterReaderBinding<'s> {
    session: &'s Session,
    profile: CounterReaderProfile,
}

impl<'s> CounterReaderBinding<'s> {
    pub(crate) fn mode(&self) -> CounterMode {
        self.profile.mode()
    }
    pub(crate) fn generation(&self) -> NonZeroU64 {
        self.session.counter_collection_generation()
    }
    pub(crate) fn logical_slots(&self) -> usize {
        self.profile.logical_slots()
    }
    pub(crate) fn rv_keys(&self) -> usize {
        self.profile.rv_keys()
    }
    pub(crate) fn start_rows(&self) -> u32 {
        self.profile.start_rows()
    }
    pub(crate) fn possible_cpus(&self) -> usize {
        self.profile.possible_cpus()
    }
    pub(crate) fn session(&self) -> &'s Session {
        self.session
    }
}

impl Session {
    /// None means actual legacy state only. A present counter owner never
    /// falls back to legacy acquisition after shape, topology or health refusal.
    pub(crate) fn counter_reader_binding(
        &self,
    ) -> Result<Option<CounterReaderBinding<'_>>, BankRefusal> {
        reader_profile_with(
            self.counter_banks.as_ref(),
            |name| {
                let cause = profile_map_cause(name);
                let data = map_data(self.ebpf.map(name).ok_or(BankRefusal::Shape(cause))?, cause)?;
                super::read_map_metadata(name, data).map_err(|_| BankRefusal::Native)
            },
            || aya::util::nr_cpus().map_err(|_| BankRefusal::Native),
        )
        .map(|profile| {
            profile.map(|profile| CounterReaderBinding {
                session: self,
                profile,
            })
        })
    }
}

#[derive(Clone, Copy)]
struct PublishedRow {
    index: u32,
    key: AttachKey,
    route: CountsBankRoute,
}

/// Charged read-only Directory selection. This grants neither native-map
/// health nor capture authority; the native view must verify both scrapes.
pub(crate) struct CounterPublishedSnapshot {
    profile: CounterReaderProfile,
    high_water: usize,
    budget: crate::capacity::CounterBudget,
    rows: Vec<PublishedRow>,
    indices: Vec<u32>,
    selected: Vec<u8>,
    physical_prefix: Vec<AttachKey>,
    keepalive: Arc<CounterKeepalive>,
    _storage: ResourceLease,
}

impl CounterPublishedSnapshot {
    pub(crate) fn mode(&self) -> CounterMode {
        self.profile.mode()
    }
    pub(crate) fn original_indices(&self) -> &[u32] {
        &self.indices
    }
    pub(crate) fn logical_slots(&self) -> usize {
        self.profile.logical_slots()
    }
    pub(crate) fn rv_keys(&self) -> usize {
        self.profile.rv_keys()
    }
    pub(crate) fn start_rows(&self) -> u32 {
        self.profile.start_rows()
    }
    pub(crate) fn possible_cpus(&self) -> usize {
        self.profile.possible_cpus()
    }

    pub(crate) fn validate_plan(&self, plan: &AttachPlan) -> Result<(), BankRefusal> {
        self.validate_binding(plan, None)
    }

    fn validate_binding(
        &self,
        plan: &AttachPlan,
        objects: Option<&PinnedObjects>,
    ) -> Result<(), BankRefusal> {
        if plan.slots.len() != self.high_water
            || plan.counter_consumed_end() as usize != self.high_water
            || !matches!(plan.admission_policy(), crate::plan::AdmissionPolicy::Counters(budget) if budget == self.budget)
            || plan.slots.iter().enumerate().any(|(index, slot)| {
                slot.index as usize != index || physical(slot) != self.physical_prefix[index]
            })
        {
            return Err(BankRefusal::Topology);
        }
        let custody = self
            .keepalive
            .custody
            .lock()
            .map_err(|_| BankRefusal::Quarantined)?;
        for row in &self.rows {
            let slot = &plan.slots[row.index as usize];
            if physical(slot) != row.key {
                return Err(BankRefusal::Topology);
            }
            let held = custody
                .providers
                .get(row.index as usize)
                .and_then(Option::as_ref)
                .ok_or(BankRefusal::Ownership)?;
            retained_binding(slot, Some(plan), objects, held)?;
        }
        Ok(())
    }
}

impl CounterBanks {
    fn published_snapshot(
        &self,
        plan: &AttachPlan,
        objects: &PinnedObjects,
        reserve: &SemanticResourceReserver,
    ) -> Result<CounterPublishedSnapshot, BankRefusal> {
        // One lock order, entered here exactly once. Native staging never
        // reenters this helper while it holds the Directory/custody locks.
        let directory = self
            .directory
            .lock()
            .map_err(|_| BankRefusal::Quarantined)?;
        if directory.geometry != self.geometry {
            return Err(BankRefusal::Shape(BankShapeCause::SnapshotGeometryChanged));
        }
        directory.validate_read_plan(plan)?;
        if plan.slots.len() != directory.positions.len()
            || plan.counter_consumed_end() as usize != directory.positions.len()
        {
            return Err(BankRefusal::Topology);
        }
        let count = directory.published_indices().count();
        let bytes = counter_snapshot_bytes_for(count, directory.positions.len())?;
        let storage = reserve.reserve(bytes).map_err(|_| BankRefusal::Budget)?;
        let custody = self
            .keepalive
            .custody
            .lock()
            .map_err(|_| BankRefusal::Quarantined)?;
        let mut rows = Vec::with_capacity(count);
        let mut indices = Vec::with_capacity(count);
        let mut selected = vec![0; directory.positions.len()];
        let physical_prefix = directory
            .positions
            .iter()
            .map(|position| position.key)
            .collect();
        let mut endpoints = Vec::with_capacity(count);
        for index in directory.published_indices() {
            let slot = &plan.slots[index as usize];
            let held = custody
                .providers
                .get(index as usize)
                .and_then(Option::as_ref)
                .ok_or(BankRefusal::Ownership)?;
            endpoints.push(retained_binding(slot, Some(plan), Some(objects), held)?);
            let PositionState::Published(route) = directory.positions[index as usize].state else {
                unreachable!("published iterator")
            };
            rows.push(PublishedRow {
                index,
                key: physical(slot),
                route,
            });
            indices.push(index);
            selected[index as usize] = 1;
        }
        endpoints.sort_unstable();
        if endpoints.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BankRefusal::Ownership);
        }
        Ok(CounterPublishedSnapshot {
            profile: CounterReaderProfile {
                cpus: self.cpus,
                geometry: self.geometry,
            },
            high_water: directory.positions.len(),
            budget: directory.budget.ok_or(BankRefusal::Topology)?,
            rows,
            indices,
            selected,
            physical_prefix,
            keepalive: Arc::clone(&self.keepalive),
            _storage: storage,
        })
    }
}

/// The maps share retained handles; no scrape opens get-by-ID descriptors.
pub(crate) struct CounterBankView {
    banks: [Option<Arc<BankHandle>>; GROWTH_BANKS],
    snapshot: CounterPublishedSnapshot,
}

impl CounterBankView {
    pub(crate) fn snapshot(&self) -> &CounterPublishedSnapshot {
        &self.snapshot
    }

    pub(crate) fn bank_cell(&self, slot: u32) -> Option<(&Map, u32)> {
        if self.snapshot.selected.get(slot as usize) != Some(&1) {
            return None;
        }
        let (bank, cell) = self.snapshot.profile.geometry.locate(slot).ok()?;
        Some((&self.banks.get(bank as usize)?.as_ref()?.map, cell))
    }

    pub(crate) fn routing(
        &self,
        ebpf: &Ebpf,
        plan: &AttachPlan,
        objects: &PinnedObjects,
    ) -> Result<BankReadStatus, BankRefusal> {
        let geometry = self.snapshot.profile.geometry;
        validate_maps(ebpf, geometry)?;
        match self.snapshot.validate_binding(plan, Some(objects)) {
            Ok(()) => {}
            Err(BankRefusal::Quarantined) => return Ok(BankReadStatus::Quarantined),
            Err(_) => return Ok(BankReadStatus::Routing),
        }
        let mut checked = [false; GROWTH_BANKS];
        let mut last_commit = None;
        for row in &self.snapshot.rows {
            let route = row.route;
            let Some(held) = self.banks.get(route.bank as usize).and_then(Option::as_ref) else {
                return Ok(BankReadStatus::Routing);
            };
            if held.id != route.inner_id {
                return Ok(BankReadStatus::Routing);
            }
            if !checked[route.bank as usize] {
                if exact_map_metadata(
                    &held.map,
                    MapType::PerCpuArray,
                    4,
                    geometry.mode().stats_bytes() as u32,
                    geometry.cells,
                    0,
                    BankShapeCause::RoutingRetainedBank,
                )
                .is_err()
                    || map_data(&held.map, BankShapeCause::RoutingHeldVariant)?
                        .info()
                        .map_err(|_| BankRefusal::Native)?
                        .id()
                        != held.id
                    || outer_id(ebpf, geometry, route.bank)? != Some(held.id)
                {
                    return Ok(BankReadStatus::Routing);
                }
                checked[route.bank as usize] = true;
            }
            if observe_route(ebpf, geometry, row.index, route)? != Some(true) {
                return Ok(BankReadStatus::Routing);
            }
            let expected = CountsBankCommit {
                first: route.first,
                end: route.end,
                configuration: geometry.configuration,
            };
            if last_commit != Some((route.transaction, expected)) {
                if observe_native_commit(ebpf, geometry, route.transaction, expected)
                    != CommitObservation::Exact
                {
                    return Ok(BankReadStatus::Routing);
                }
                last_commit = Some((route.transaction, expected));
            }
        }
        Ok(BankReadStatus::Healthy)
    }
}

impl Session {
    pub(crate) fn counter_bank_view(
        &self,
        plan: &AttachPlan,
        objects: &PinnedObjects,
        reserve: &SemanticResourceReserver,
    ) -> Result<CounterBankView, BankRefusal> {
        let banks = self
            .counter_banks
            .as_ref()
            .ok_or(BankRefusal::Shape(BankShapeCause::BanksMissingForView))?;
        let snapshot = banks.published_snapshot(plan, objects, reserve)?;
        let custody = banks
            .keepalive
            .custody
            .lock()
            .map_err(|_| BankRefusal::Quarantined)?;
        Ok(CounterBankView {
            banks: custody.banks.clone(),
            snapshot,
        })
    }

    pub(crate) fn counter_budgets(&self, rv_used: usize) -> Result<CounterBudgets, BankRefusal> {
        self.counter_banks
            .as_ref()
            .ok_or(BankRefusal::Shape(BankShapeCause::BanksMissingForView))?
            .budgets(rv_used)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::discovery::identity::PinnedObjectId;
    use crate::plan::{AttachPlan, Slot};
    use crate::semantics_edge::resources::{
        ResourceLease, SEMANTIC_TRANSITION_SCRATCH, SemanticResourcePool,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn slot(index: u32, object: u32) -> Slot {
        Slot {
            index,
            descriptor_index: 0,
            object: PinnedObjectId(object),
            object_path: "/owned-provider.so".into(),
            file_offset: 0x80,
            names: vec!["C_Initialize".into()],
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[0],
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![],
        }
    }

    fn plan(count: u32) -> AttachPlan {
        AttachPlan::from_slots_with_policy(
            (0..count).map(|index| slot(index, index + 1)).collect(),
            crate::plan::AdmissionPolicy::counters(
                crate::capacity::CounterBudget::new(8192).unwrap(),
            ),
        )
        .unwrap()
    }

    fn reservation() -> BankReservation {
        BankReservation {
            retained_bytes: 64 * 1024,
            transient_bytes: 128 * 1024,
            metadata_bytes: 8 * 1024,
            file_descriptors: 32,
        }
    }

    // Format2 tests replace only native map/link/provider I/O. The existing
    // production BankDirectory::stage_with remains the publication algorithm.
    #[derive(Clone, Copy, Debug)]
    enum GrowthDamage {
        RouteId,
        OuterId,
        Provider,
        EntrySide,
        ReturnSide,
        Unreadable,
    }

    #[derive(Default)]
    struct GrowthIo<'a> {
        pool: Option<&'a SemanticResourcePool>,
        charged_before: usize,
        cpus: usize,
        trace: Vec<&'static str>,
        maps: BTreeMap<u32, u32>,
        outer: BTreeMap<u32, u32>,
        routes: BTreeMap<u32, CountsBankRoute>,
        commits: BTreeMap<u64, CountsBankCommit>,
        providers: BTreeSet<u32>,
        entries: BTreeSet<u32>,
        returns: BTreeSet<u32>,
        held: Vec<ResourceLease>,
        target_store: Option<&'a PinnedObjects>,
        provider_owner: Option<&'a Mutex<NativeCustody>>,
        checks: usize,
        damage: Option<(usize, GrowthDamage)>,
        target_refusal: Option<BankRefusal>,
        fd_preflight: Option<(usize, Result<FdSnapshot, BankRefusal>)>,
        fd_stage_snapshot: Option<Result<FdSnapshot, BankRefusal>>,
        counter_multi_storage: Option<(&'a mut Vec<super::super::RegisteredLink>, BankReservation)>,
        failure: Option<&'static str>,
        initial_unreadable: bool,
        commit_absent: bool,
        commit_wrong: bool,
        commit_unreadable: bool,
        attempted: BTreeSet<u64>,
    }

    impl<'a> GrowthIo<'a> {
        fn new(pool: &'a SemanticResourcePool) -> Self {
            Self {
                pool: Some(pool),
                charged_before: pool.snapshot().charged_bytes,
                cpus: 2,
                ..Self::default()
            }
        }

        fn next_stage(&mut self) {
            self.trace.clear();
            self.checks = 0;
            self.charged_before = self.pool.unwrap().snapshot().charged_bytes;
        }

        fn require_precharge(&self) {
            assert!(
                self.pool.unwrap().snapshot().charged_bytes > self.charged_before,
                "actual reservation must precede native reads/mutation"
            );
        }
    }

    impl BankIo for GrowthIo<'_> {
        fn possible_cpus(&self) -> usize {
            self.cpus
        }

        fn validate_targets(
            &mut self,
            slots: &[Slot],
            published: &[u32],
            fresh: BankExtent,
            old_capacity: usize,
        ) -> Result<(), BankRefusal> {
            self.require_precharge();
            self.trace.push("validate");
            assert!(published.iter().all(|slot| self.routes.contains_key(slot)));
            if let Some(reason) = self.target_refusal {
                return Err(reason);
            }
            if let Some((required, snapshot)) = self.fd_preflight.take() {
                check_fd_headroom_with(required, || {
                    self.trace.push("fd-query");
                    snapshot
                })?;
            }
            if let Some(snapshot) = self.fd_stage_snapshot.take() {
                // Replace only the readonly OS query. Consume the same actual
                // charge calculation NativeIo uses, with this fixture's maps.
                let geometry = BankGeometry::checked(CounterMode::Counts, 16, 512)?;
                let new_banks = (fresh.first / geometry.cells..=(fresh.end - 1) / geometry.cells)
                    .filter(|bank| !self.maps.contains_key(bank))
                    .count();
                let (_, _, _, required) = stage_requirements(
                    geometry,
                    slots,
                    fresh,
                    old_capacity,
                    self.cpus,
                    new_banks,
                    0,
                    16,
                )?;
                check_fd_headroom_with(required, || {
                    self.trace.push("fd-query");
                    snapshot
                })?;
            }
            if let Some((links, envelope)) = &self.counter_multi_storage {
                let geometry = BankGeometry::checked(CounterMode::Counts, 16, 512)?;
                let new_banks = (fresh.first / geometry.cells..=(fresh.end - 1) / geometry.cells)
                    .filter(|bank| !self.maps.contains_key(bank))
                    .count();
                let fresh_slots = &slots[fresh.first as usize..fresh.end as usize];
                let provider_copies = fresh_slots
                    .iter()
                    .try_fold(0usize, |bytes, slot| {
                        bytes.checked_add(
                            self.target_store?
                                .retained_target_copy_allocation_charge(slot.object)?
                                .checked_mul(4)?,
                        )
                    })
                    .ok_or(BankRefusal::Budget)?;
                let base = stage_requirements(
                    geometry,
                    slots,
                    fresh,
                    old_capacity,
                    self.cpus,
                    new_banks,
                    provider_copies,
                    16,
                )?;
                check_counter_multi_reservation(
                    *envelope,
                    base,
                    fresh_slots,
                    links.len(),
                    links.capacity(),
                )?;
            }
            Ok(())
        }

        fn retain_charge(&mut self, charge: ResourceLease) {
            self.trace.push("retain");
            if let Some(owner) = self.provider_owner {
                owner.lock().unwrap().retain_charge(charge);
            } else {
                self.held.push(charge);
            }
        }

        fn allocate_bank(&mut self, bank: u32, all_slots: &[Slot]) -> Result<u32, BankRefusal> {
            self.require_precharge();
            self.trace.push("allocate");
            assert!(
                all_slots
                    .iter()
                    .enumerate()
                    .all(|(index, slot)| slot.index as usize == index)
            );
            if self.failure == Some("allocate-cut") {
                panic!("cut at the first native allocation boundary");
            }
            if self.failure == Some("allocate") {
                return Err(BankRefusal::Native);
            }
            assert!(bank < 16 && !self.maps.contains_key(&bank));
            let id = 101 + bank;
            self.maps.insert(bank, id);
            Ok(id)
        }

        fn insert_inner(&mut self, bank: u32, expected_id: u32) -> Result<(), BankRefusal> {
            self.trace.push("inner");
            assert_eq!(self.maps.get(&bank), Some(&expected_id));
            assert!(self.outer.insert(bank, expected_id).is_none());
            Ok(())
        }

        fn insert_route(&mut self, slot: u32, route: CountsBankRoute) -> Result<(), BankRefusal> {
            self.trace.push("route");
            assert!(self.routes.insert(slot, route).is_none());
            self.providers.insert(slot);
            Ok(())
        }

        fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
            assert!(slots.iter().all(|slot| {
                !self
                    .commits
                    .contains_key(&self.routes[&slot.index].transaction)
            }));
            if let Some((links, _)) = &mut self.counter_multi_storage {
                super::super::reserve_counter_multi_link_capacity(links, slots.len())?;
            }
            if let Some(owner) = self.provider_owner {
                let mut custody = owner.lock().unwrap();
                custody.retain_targets(slots, self.target_store.unwrap())?;
                assert!(
                    slots
                        .iter()
                        .all(|slot| custody.providers[slot.index as usize].is_some())
                );
                self.trace.push("retain-provider");
            }
            self.trace.push("return");
            self.returns.extend(slots.iter().map(|slot| slot.index));
            self.trace.push("entry");
            if self.failure == Some("entry") {
                return Err(BankRefusal::Links);
            }
            self.entries.extend(slots.iter().map(|slot| slot.index));
            Ok(())
        }

        fn verify_candidate(
            &mut self,
            expected: &StagedExtent,
            all_slots: &[Slot],
            _published: &[u32],
        ) -> CandidateCheck {
            self.trace.push("verify");
            assert_eq!(all_slots.len(), expected.commit.end as usize);
            assert!(
                all_slots
                    .iter()
                    .enumerate()
                    .all(|(index, slot)| slot.index as usize == index)
            );
            self.checks += 1;
            if let Some((at, damage)) = self.damage
                && at == self.checks
            {
                let (slot, route) = *expected.routes.last().unwrap();
                match damage {
                    GrowthDamage::RouteId => self.routes.get_mut(&slot).unwrap().inner_id = 999,
                    GrowthDamage::OuterId => {
                        self.outer.insert(route.bank, 999);
                    }
                    GrowthDamage::Provider => {
                        self.providers.remove(&slot);
                    }
                    GrowthDamage::EntrySide => {
                        self.entries.remove(&slot);
                    }
                    GrowthDamage::ReturnSide => {
                        self.returns.remove(&slot);
                    }
                    GrowthDamage::Unreadable => return CandidateCheck::Unreadable,
                }
            }
            for (slot, route) in &expected.routes {
                if self.routes.get(slot) != Some(route)
                    || self.maps.get(&route.bank) != Some(&route.inner_id)
                    || self.outer.get(&route.bank) != Some(&route.inner_id)
                    || !expected.bank_ids.contains(&(route.bank, route.inner_id))
                    || !self.providers.contains(slot)
                    || !self.entries.contains(slot)
                    || !self.returns.contains(slot)
                {
                    return CandidateCheck::Contradictory;
                }
            }
            CandidateCheck::Exact
        }

        fn insert_commit(
            &mut self,
            transaction: u64,
            commit: CountsBankCommit,
        ) -> Result<(), BankRefusal> {
            self.trace.push("commit");
            self.attempted.insert(transaction);
            if self.commit_absent {
                return Err(BankRefusal::Commit);
            }
            let stored = if self.commit_wrong {
                CountsBankCommit {
                    configuration: commit.configuration ^ 1,
                    ..commit
                }
            } else {
                commit
            };
            assert!(self.commits.insert(transaction, stored).is_none());
            Ok(())
        }

        fn observe_commit(
            &mut self,
            transaction: u64,
            expected: CountsBankCommit,
        ) -> CommitObservation {
            self.require_precharge();
            self.trace.push("observe");
            if self.initial_unreadable && !self.attempted.contains(&transaction) {
                return CommitObservation::Unreadable;
            }
            if self.commit_unreadable && self.attempted.contains(&transaction) {
                return CommitObservation::Unreadable;
            }
            match self.commits.get(&transaction) {
                None => CommitObservation::Absent,
                Some(actual) if *actual == expected => CommitObservation::Exact,
                Some(_) => CommitObservation::Contradictory,
            }
        }

        fn remove_route_owned(
            &mut self,
            slot: u32,
            expected: CountsBankRoute,
        ) -> Result<(), BankRefusal> {
            self.trace.push("remove-route");
            assert_eq!(self.routes.remove(&slot), Some(expected));
            self.providers.remove(&slot);
            Ok(())
        }

        fn remove_new_bank_owned(
            &mut self,
            bank: u32,
            expected_id: u32,
        ) -> Result<(), BankRefusal> {
            self.trace.push("remove-bank");
            assert_eq!(self.outer.remove(&bank), Some(expected_id));
            assert_eq!(self.maps.remove(&bank), Some(expected_id));
            Ok(())
        }

        fn retire_links(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
            self.trace.push("retire-entry");
            if self.failure == Some("retire") {
                return Err(BankRefusal::Links);
            }
            for slot in slots {
                self.entries.remove(&slot.index);
            }
            self.trace.push("retire-return");
            for slot in slots {
                self.returns.remove(&slot.index);
            }
            Ok(())
        }
    }

    fn growth_reservation() -> BankReservation {
        BankReservation {
            retained_bytes: 1024 * 1024,
            transient_bytes: 2 * 1024 * 1024,
            metadata_bytes: 64 * 1024,
            file_descriptors: 128,
        }
    }

    #[test]
    fn bank_shape_causes_are_distinct_and_complete() {
        let mut seen = Vec::with_capacity(BankShapeCause::ALL.len());
        for cause in BankShapeCause::ALL {
            assert!(
                !seen.contains(&cause),
                "duplicate bank shape cause: {cause:?}"
            );
            seen.push(cause);
        }
        assert_eq!(
            BankShapeCause::ALL.len(),
            58,
            "every new cause variant must join ALL"
        );
    }

    #[test]
    fn embedded_bank_objects_match_reader_expectations() {
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") != "1" {
            assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"), "");
            for mode in [
                CounterMode::Counts,
                CounterMode::Timestamps,
                CounterMode::Latency,
            ] {
                assert!(
                    counter_object_for_mode(mode).is_empty(),
                    "{mode:?} must be omitted when disabled"
                );
            }
            return;
        }
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let embedded = counter_object_for_mode(mode);
            assert!(!embedded.is_empty(), "{mode:?} embedded object is empty");
            // The privileged cells read the staged OUT_DIR bytes; they must
            // equal the bytes the build embeds.
            let staged = std::fs::read(std::path::Path::new(env!("OUT_DIR")).join(format!(
                "counter-bank-growth-v2/p11scope-ebpf-{}-bank-growth-v2",
                mode.name()
            )))
            .unwrap();
            assert_eq!(embedded, &staged[..], "{mode:?} staged bytes differ");
            let object = aya_obj::Object::parse(embedded).unwrap();
            let geometry = BankGeometry::checked(mode, 16, 512).unwrap();
            validate_object_maps(geometry, |name| object.maps.get(name)).unwrap();
            // The aggregate template stays 24 bytes in every mode; only the
            // bank cells vary.
            let stats = object.maps.get("STATS").unwrap();
            assert_eq!(stats.value_size(), 24, "{mode:?} aggregate template");
            let expected = match mode {
                CounterMode::Counts => 0x0200_0018_0010_0200u64,
                CounterMode::Timestamps => 0x0200_0028_0010_0200u64,
                CounterMode::Latency => 0x0200_0128_0010_0200u64,
            };
            assert_eq!(geometry.configuration, expected, "{mode:?} config word");
        }
    }

    #[test]
    fn production_geometry_selects_mode_and_gates_token() {
        const FULL_OUTPUTS: &str =
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2";
        // Omitted builds carry empty statics, so byte identity is ambiguous
        // and selection refuses; legacy still resolves. This arm asserts
        // instead of early-returning, so =0/WIDE/SMALL builds execute it.
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") != "1" {
            assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"), "");
            for mode in [
                CounterMode::Counts,
                CounterMode::Timestamps,
                CounterMode::Latency,
            ] {
                assert!(
                    counter_object_for_mode(mode).is_empty(),
                    "{mode:?} must be omitted when disabled"
                );
            }
            assert_eq!(
                production_geometry_for(counter_object_for_mode(CounterMode::Counts), ""),
                Err(BankRefusal::Shape(BankShapeCause::ObjectAmbiguous))
            );
            assert_eq!(
                production_geometry_for(b"", FULL_OUTPUTS),
                Err(BankRefusal::Shape(BankShapeCause::ObjectAmbiguous))
            );
            assert_eq!(
                production_geometry_for(b"", "counts-bank-proof"),
                Ok(BankGeometry::legacy())
            );
            return;
        }
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            assert_eq!(
                production_geometry_for(counter_object_for_mode(mode), FULL_OUTPUTS),
                Ok(BankGeometry::checked(mode, 16, 512).unwrap()),
                "{mode:?} positive"
            );
        }
        assert_eq!(
            production_geometry_for(
                counter_object_for_mode(CounterMode::Timestamps),
                "counts-bank-growth-v2",
            ),
            Err(BankRefusal::Shape(BankShapeCause::TokenNotEmitted)),
            "a token missing from the emitted outputs refuses"
        );
        assert_eq!(
            production_geometry_for(crate::EBPF_OBJECT, FULL_OUTPUTS),
            Err(BankRefusal::Shape(BankShapeCause::ObjectUnknown)),
            "an unknown object refuses"
        );
        assert_eq!(
            production_geometry_for(crate::EBPF_OBJECT, "counts-bank-proof"),
            Ok(BankGeometry::legacy()),
            "legacy resolves without consulting embedded bytes"
        );
    }

    #[test]
    fn embedded_bank_objects_refuse_wrong_reader_expectations() {
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") != "1" {
            assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"), "");
            return;
        }
        let counts = aya_obj::Object::parse(counter_object_for_mode(CounterMode::Counts)).unwrap();
        let timestamps =
            aya_obj::Object::parse(counter_object_for_mode(CounterMode::Timestamps)).unwrap();
        // Cross-mode geometry: the inner template width names the mismatch.
        assert_eq!(
            validate_object_maps(
                BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap(),
                |name| timestamps.maps.get(name),
            ),
            Err(BankRefusal::Shape(BankShapeCause::InnerTemplateShape)),
            "counts geometry over timestamps bytes"
        );
        assert_eq!(
            validate_object_maps(
                BankGeometry::checked(CounterMode::Latency, 16, 512).unwrap(),
                |name| counts.maps.get(name),
            ),
            Err(BankRefusal::Shape(BankShapeCause::InnerTemplateShape)),
            "latency geometry over counts bytes"
        );
        // A timestamps-wide aggregate cannot relabel the bank template.
        let mut tampered = timestamps.maps.clone();
        let aya_obj::Map::Legacy(stats) = tampered.get_mut("STATS").unwrap() else {
            unreachable!();
        };
        stats.def.value_size = 40;
        assert_eq!(
            validate_object_maps(
                BankGeometry::checked(CounterMode::Timestamps, 16, 512).unwrap(),
                |name| tampered.get(name),
            ),
            Err(BankRefusal::Shape(BankShapeCause::StatsShape)),
            "timestamps geometry over a relabeled aggregate"
        );
    }

    #[test]
    fn scaled_counts_geometry_and_record_layouts_are_checked() {
        use std::mem::{offset_of, size_of};
        assert_eq!(size_of::<CountsBankRoute>(), 32);
        assert_eq!(size_of::<CountsBankCommit>(), 16);
        assert_eq!(
            (
                offset_of!(CountsBankRoute, transaction),
                offset_of!(CountsBankRoute, first),
                offset_of!(CountsBankRoute, end),
                offset_of!(CountsBankRoute, bank),
                offset_of!(CountsBankRoute, cell),
                offset_of!(CountsBankRoute, inner_id),
                offset_of!(CountsBankRoute, reserved_zero)
            ),
            (0, 8, 12, 16, 20, 24, 28)
        );
        assert_eq!(
            (
                offset_of!(CountsBankCommit, first),
                offset_of!(CountsBankCommit, end),
                offset_of!(CountsBankCommit, configuration)
            ),
            (0, 4, 8)
        );
        let geometry = BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap();
        for (slot, wanted) in [
            (0, (0, 0)),
            (511, (0, 511)),
            (512, (1, 0)),
            (8191, (15, 511)),
        ] {
            assert_eq!(geometry.locate(slot), Ok(wanted));
        }
        assert!(geometry.locate(8192).is_err());
        assert_eq!(geometry.bank_payload_bytes(2), Ok(24_576));
        assert!(geometry.bank_payload_bytes(0).is_err());
        assert!(geometry.bank_payload_bytes(usize::MAX).is_err());
        for (banks, cells) in [
            (0, 512),
            (16, 0),
            (2, 1),
            (17, 512),
            (16, 513),
            (u32::MAX, u32::MAX),
        ] {
            assert!(BankGeometry::checked(CounterMode::Counts, banks, cells).is_err());
        }
        let commit = CountsBankCommit {
            first: 511,
            end: 513,
            configuration: 0x0200_0018_0010_0200,
        };
        let routes = vec![
            (
                511,
                CountsBankRoute {
                    transaction: 1,
                    first: 511,
                    end: 513,
                    bank: 0,
                    cell: 511,
                    inner_id: 101,
                    reserved_zero: 0,
                },
            ),
            (
                512,
                CountsBankRoute {
                    transaction: 1,
                    first: 511,
                    end: 513,
                    bank: 1,
                    cell: 0,
                    inner_id: 102,
                    reserved_zero: 0,
                },
            ),
        ];
        let ids = vec![(0, 101), (1, 102)];
        assert!(
            StagedExtent::checked(
                NonZeroU64::new(1).unwrap(),
                commit,
                routes.clone(),
                ids.clone()
            )
            .is_ok()
        );
        let mut wrong_bank_id = routes.clone();
        wrong_bank_id[0].1.inner_id = 102; // Real dependency, but for the OTHER bank.
        assert!(
            StagedExtent::checked(
                NonZeroU64::new(1).unwrap(),
                commit,
                wrong_bank_id,
                ids.clone()
            )
            .is_err()
        );
        for damage in 0..5 {
            let mut changed = routes.clone();
            match damage {
                0 => changed[0].1.reserved_zero = 1,
                1 => changed[0].1.cell = 512,
                2 => changed[0].1.bank = 16,
                3 => changed[0].1.transaction = 0,
                _ => {
                    changed.remove(0);
                }
            }
            assert!(
                StagedExtent::checked(NonZeroU64::new(1).unwrap(), commit, changed, ids.clone())
                    .is_err()
            );
        }
        let legacy = CountsBankCommit {
            configuration: BANK_CONFIG,
            ..commit
        };
        assert!(StagedExtent::checked(NonZeroU64::new(1).unwrap(), legacy, routes, ids).is_err());

        // Actual parsing/preparation rejects a future profile before lifecycle
        // attachment. Build small Aya map definitions, never a host BTF blob.
        let mut format1 = BTreeMap::new();
        for (name, _) in FORMAT1_MAPS {
            let expected = reader_metadata(name).unwrap();
            format1.insert(
                name,
                aya_obj::Map::new_from_params(
                    expected.map_type as u32,
                    expected.key_size,
                    expected.value_size,
                    expected.max_entries,
                    expected.flags,
                ),
            );
        }
        let aya_obj::Map::Legacy(outer) = format1.get_mut("COUNTER_BANKS").unwrap() else {
            unreachable!();
        };
        outer.inner_def = Some(aya_obj::maps::bpf_map_def {
            map_type: 6,
            key_size: 4,
            value_size: 24,
            max_entries: 1,
            ..Default::default()
        });
        assert_eq!(
            validate_format1_object_maps(|name| format1.get(name)),
            Ok(())
        );
        for damage in 0..5 {
            let mut changed = format1.clone();
            let name = match damage {
                0 | 1 => "COUNTER_BANKS",
                2 => "COUNTER_BANK_META",
                3 => "COUNTER_BANK_COMMIT",
                _ => "STATS",
            };
            let aya_obj::Map::Legacy(map) = changed.get_mut(name).unwrap() else {
                unreachable!();
            };
            match damage {
                0 => map.def.max_entries = 16,
                1 => map.inner_def.as_mut().unwrap().max_entries = 512,
                2 => map.def.value_size = 32,
                3 => map.def.max_entries = 8192,
                _ => map.def.value_size = 40,
            }
            let expected = match damage {
                0 => BankShapeCause::BanksOuterShape,
                1 => BankShapeCause::InnerTemplateShape,
                2 => BankShapeCause::MetaShape,
                3 => BankShapeCause::CommitShape,
                _ => BankShapeCause::StatsShape,
            };
            assert_eq!(
                validate_format1_object_maps(|name| changed.get(name)),
                Err(BankRefusal::Shape(expected)),
                "damage {damage}"
            );
        }
        assert_eq!(
            validate_format1_object_maps(|name| {
                if name == "COUNTER_BANK_META" {
                    None
                } else {
                    format1.get(name)
                }
            }),
            Err(BankRefusal::Shape(BankShapeCause::MetaShape))
        );
    }

    #[test]
    fn partial_bank_extent_stays_inactive_until_complete_ack() {
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        let mut history = plan(1);
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { .. }
        ));
        let old = io.routes[&0];
        history.extend_exact(plan(2)).unwrap();
        io.next_stage();
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { .. }
        ));
        assert_eq!(io.maps, BTreeMap::from([(0, 101)]));
        assert!(
            !io.trace.contains(&"allocate"),
            "a partial bank is shared, never replaced"
        );
        assert_eq!(io.routes[&0], old);
        assert_eq!(
            (
                io.routes[&1].bank,
                io.routes[&1].cell,
                io.routes[&1].inner_id
            ),
            (0, 1, 101)
        );
        let checks: Vec<_> = io
            .trace
            .iter()
            .enumerate()
            .filter(|(_, step)| **step == "verify")
            .map(|(at, _)| at)
            .collect();
        let commit = io.trace.iter().position(|step| *step == "commit").unwrap();
        assert_eq!(checks.len(), 2);
        assert!(checks[0] < commit && commit < checks[1]);
        assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0, 1]);
        for at in [1, 2] {
            for damage in [
                GrowthDamage::RouteId,
                GrowthDamage::OuterId,
                GrowthDamage::Provider,
                GrowthDamage::EntrySide,
                GrowthDamage::ReturnSide,
                GrowthDamage::Unreadable,
            ] {
                let mut directory = BankDirectory::counts_growth_v2();
                let mut io = GrowthIo::new(&pool);
                let mut history = plan(1);
                assert!(matches!(
                    directory.stage_with(
                        &mut io,
                        &mut history,
                        growth_reservation(),
                        &pool.reserver()
                    ),
                    BankPublication::Published { .. }
                ));
                let old = io.routes[&0];
                history.extend_exact(plan(2)).unwrap();
                io.next_stage();
                io.damage = Some((at, damage));
                assert!(
                    matches!(
                        directory.stage_with(
                            &mut io,
                            &mut history,
                            growth_reservation(),
                            &pool.reserver()
                        ),
                        BankPublication::Quarantined { .. }
                    ),
                    "check {at}: {damage:?}"
                );
                assert_eq!(io.routes[&0], old);
                assert_eq!(io.maps[&0], 101);
                assert!(!io.trace.contains(&"remove-route") && !io.trace.contains(&"remove-bank"));
                assert_eq!(
                    io.trace.contains(&"commit"),
                    at == 2,
                    "bad precommit read must prevent activation"
                );
                assert!(!io.held.is_empty());
                assert_eq!(
                    directory.validate_read_plan(&history),
                    Err(BankRefusal::Quarantined)
                );
            }
        }
        for unreadable in [false, true] {
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            let mut history = plan(1);
            assert!(matches!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Published { .. }
            ));
            history.extend_exact(plan(2)).unwrap();
            io.next_stage();
            io.commit_unreadable = unreadable;
            io.commit_wrong = !unreadable;
            assert!(matches!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Quarantined { .. }
            ));
            assert_eq!(io.routes.len(), 2);
            assert_eq!(io.maps[&0], 101);
            assert!(!io.trace.contains(&"remove-route") && !io.trace.contains(&"remove-bank"));
            assert!(!io.held.is_empty());
        }
        // ENOENT alone cannot authorize cleanup after an attempted commit:
        // the complete candidate must still have the same ownership facts.
        for damage in [
            None,
            Some(GrowthDamage::Provider),
            Some(GrowthDamage::EntrySide),
            Some(GrowthDamage::ReturnSide),
            Some(GrowthDamage::Unreadable),
        ] {
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            let mut history = plan(1);
            assert!(matches!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Published { .. }
            ));
            let old = io.routes[&0];
            history.extend_exact(plan(2)).unwrap();
            io.next_stage();
            io.commit_absent = true;
            io.damage = damage.map(|kind| (2, kind));
            let publication = directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver(),
            );
            assert_eq!(io.checks, 2, "post-insert check with {damage:?}");
            assert_eq!(io.routes[&0], old);
            assert_eq!(io.maps[&0], 101);
            assert!(!io.commits.contains_key(&2));
            assert!(
                !io.trace.contains(&"remove-bank"),
                "shared old bank is retained"
            );
            assert!(!io.held.is_empty());
            if damage.is_none() {
                assert!(matches!(publication, BankPublication::RolledBack { .. }));
                assert_eq!(io.routes.keys().copied().collect::<Vec<_>>(), [0]);
                assert!(io.trace.contains(&"remove-route"));
                assert!(!directory.quarantined);
            } else {
                assert!(
                    matches!(publication, BankPublication::Quarantined { .. }),
                    "{damage:?}"
                );
                assert_eq!(io.routes.len(), 2);
                assert!(!io.trace.contains(&"remove-route"));
                assert!(
                    !io.trace.contains(&"retire-entry") && !io.trace.contains(&"retire-return")
                );
                // Restoring observable facts cannot revive an owner whose
                // post-insert acknowledgement was already contradictory.
                io.damage = None;
                io.providers.insert(1);
                io.entries.insert(1);
                io.returns.insert(1);
                io.next_stage();
                assert_eq!(
                    directory.stage_with(
                        &mut io,
                        &mut history,
                        growth_reservation(),
                        &pool.reserver()
                    ),
                    BankPublication::Refused(BankRefusal::Quarantined)
                );
                assert!(io.trace.is_empty());
                assert_eq!(
                    directory.validate_read_plan(&history),
                    Err(BankRefusal::Quarantined)
                );
            }
        }
    }

    #[test]
    fn consumed_rollback_holes_preserve_historical_positions() {
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        let mut history = plan(1);
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { .. }
        ));
        let old = io.routes[&0];
        history.extend_exact(plan(2)).unwrap();
        io.next_stage();
        io.commit_absent = true;
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::RolledBack { .. }
        ));
        assert_eq!(directory.allocated_high_water(), 2);
        assert_eq!(io.routes.keys().copied().collect::<Vec<_>>(), [0]);
        assert!(
            !io.trace.contains(&"remove-bank"),
            "rollback must preserve the shared old bank"
        );
        io.next_stage();
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Refused(BankRefusal::Allocated)
        ));
        assert!(io.trace.is_empty());
        assert!(!history.is_active(1));
        assert_eq!(history.counter_consumed_end(), 2);
        history.extend_exact(plan(2)).unwrap();
        assert_eq!(
            history
                .slots
                .iter()
                .map(|slot| slot.index)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert!(!history.is_active(1) && history.is_active(2));
        assert_eq!(physical(&history.slots[1]), physical(&history.slots[2]));
        io.next_stage();
        io.commit_absent = false;
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { .. }
        ));
        assert_eq!(directory.allocated_high_water(), 3);
        assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0, 2]);
        assert_eq!(io.routes.keys().copied().collect::<Vec<_>>(), [0, 2]);
        assert_eq!(io.routes[&0], old);
        assert_eq!((io.routes[&2].bank, io.routes[&2].cell), (0, 2));
        // The actual transaction consumes this same plan; retries keep the hole.
        assert_eq!(history.counter_consumed_end(), 3);
    }

    #[test]
    fn same_plan_preflight_refusals_leave_history_and_native_state_unchanged() {
        for case in 0..8 {
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            let mut history = plan(1);
            let mut envelope = growth_reservation();
            let reason = match case {
                0 => {
                    history = AttachPlan::from_slots(vec![slot(0, 1)]);
                    BankRefusal::Shape(BankShapeCause::PlanNotCounters)
                }
                1 => {
                    history.slots[0].index = 1;
                    BankRefusal::Topology
                }
                2 => {
                    history = plan(2);
                    history.slots[1].object = history.slots[0].object;
                    BankRefusal::Topology
                }
                3 => {
                    history.deactivate(0);
                    BankRefusal::Topology
                }
                4 => {
                    envelope.retained_bytes = 48;
                    BankRefusal::Budget
                }
                5 => {
                    io.cpus = 0;
                    BankRefusal::Topology
                }
                6 => {
                    io.target_refusal = Some(BankRefusal::Ownership);
                    BankRefusal::Ownership
                }
                _ => {
                    // Native preflight also owns CPU/stop/backend continuity.
                    io.target_refusal = Some(BankRefusal::Topology);
                    BankRefusal::Topology
                }
            };
            let before = history.slots.clone();
            let active: Vec<_> = (0..history.slots.len())
                .map(|index| history.is_active(index as u32))
                .collect();
            let charged = pool.snapshot().charged_bytes;
            assert_eq!(
                directory.stage_with(&mut io, &mut history, envelope, &pool.reserver()),
                BankPublication::Refused(reason),
                "preflight case {case}"
            );
            assert_eq!(history.counter_consumed_end(), 0, "case {case}");
            assert_eq!(history.slots, before, "case {case}");
            assert_eq!(
                (0..history.slots.len())
                    .map(|index| history.is_active(index as u32))
                    .collect::<Vec<_>>(),
                active,
                "case {case}"
            );
            assert_eq!(directory.allocated_high_water(), 0);
            assert_eq!(directory.next_transaction, NonZeroU64::new(1));
            assert!(directory.budget.is_none() && !directory.quarantined);
            assert!(
                io.trace
                    .iter()
                    .all(|step| matches!(*step, "validate" | "observe"))
            );
            assert!(io.maps.is_empty() && io.outer.is_empty() && io.routes.is_empty());
            assert!(io.commits.is_empty() && io.attempted.is_empty());
            assert!(io.providers.is_empty() && io.entries.is_empty() && io.returns.is_empty());
            assert!(io.held.is_empty());
            assert_eq!(pool.snapshot().charged_bytes, charged);
        }
    }

    #[test]
    fn same_plan_initial_commit_anomalies_quarantine_without_consumption() {
        for observation in [
            CommitObservation::Exact,
            CommitObservation::Contradictory,
            CommitObservation::Unreadable,
        ] {
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            let mut history = plan(1);
            assert!(matches!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Published { transaction: 1, .. }
            ));
            let old = io.routes[&0];
            history.extend_exact(plan(2)).unwrap();
            let before = history.slots.clone();
            let charged = pool.snapshot().charged_bytes;
            io.next_stage();
            match observation {
                CommitObservation::Exact | CommitObservation::Contradictory => {
                    io.commits.insert(
                        2,
                        CountsBankCommit {
                            first: 1,
                            end: 2,
                            configuration: if observation == CommitObservation::Exact {
                                0x0200_0018_0010_0200
                            } else {
                                0x0200_0018_0010_0201
                            },
                        },
                    );
                }
                CommitObservation::Unreadable => io.initial_unreadable = true,
                CommitObservation::Absent => unreachable!(),
            }
            let commits = io.commits.clone();
            assert_eq!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Refused(BankRefusal::Quarantined),
                "initial {observation:?}"
            );
            assert!(directory.quarantined);
            assert_eq!(directory.allocated_high_water(), 1);
            assert_eq!(directory.next_transaction, NonZeroU64::new(2));
            assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
            assert_eq!(history.counter_consumed_end(), 1);
            assert_eq!(history.slots, before);
            assert!(history.is_active(0) && history.is_active(1));
            assert_eq!(io.trace, ["validate", "observe"]);
            assert_eq!(io.maps, BTreeMap::from([(0, 101)]));
            assert_eq!(io.outer, BTreeMap::from([(0, 101)]));
            assert_eq!(io.routes, BTreeMap::from([(0, old)]));
            assert_eq!(io.commits, commits);
            assert_eq!(io.attempted, BTreeSet::from([1]));
            assert_eq!(io.providers, BTreeSet::from([0]));
            assert_eq!(io.entries, BTreeSet::from([0]));
            assert_eq!(io.returns, BTreeSet::from([0]));
            assert_eq!(io.held.len(), 1);
            assert_eq!(pool.snapshot().charged_bytes, charged);
            io.next_stage();
            assert_eq!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Refused(BankRefusal::Quarantined)
            );
            assert!(io.trace.is_empty());
            assert_eq!(
                directory.validate_read_plan(&history),
                Err(BankRefusal::Quarantined)
            );
        }
    }

    #[test]
    fn same_plan_consumption_precedes_first_native_allocation() {
        for cut in [false, true] {
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            let mut history = plan(1);
            let charged = pool.snapshot().charged_bytes;
            io.failure = Some(if cut { "allocate-cut" } else { "allocate" });
            if cut {
                // Stop at the replaceable native boundary before it can mutate
                // a map. Inspect the SAME plan after unwinding, not a shadow
                // plan or a test-side consumption call.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    directory.stage_with(
                        &mut io,
                        &mut history,
                        growth_reservation(),
                        &pool.reserver(),
                    )
                }));
                assert!(result.is_err());
                assert_eq!(io.trace, ["validate", "observe", "retain", "allocate"]);
                assert!(matches!(
                    directory.positions[0].state,
                    PositionState::Pending
                ));
                assert!(history.is_active(0));
            } else {
                assert_eq!(
                    directory.stage_with(
                        &mut io,
                        &mut history,
                        growth_reservation(),
                        &pool.reserver()
                    ),
                    BankPublication::RolledBack {
                        transaction: 1,
                        extent: BankExtent { first: 0, end: 1 },
                        reason: BankRefusal::Native,
                    }
                );
                assert_eq!(
                    io.trace,
                    ["validate", "observe", "retain", "allocate", "observe"]
                );
                assert!(matches!(
                    directory.positions[0].state,
                    PositionState::NeverPublishedRetired
                ));
                assert!(!history.is_active(0));
            }
            assert_eq!(history.counter_consumed_end(), 1, "allocation cut {cut}");
            assert_eq!(history.slots.len(), 1);
            assert_eq!(directory.allocated_high_water(), 1);
            assert_eq!(directory.next_transaction, NonZeroU64::new(2));
            assert!(directory.published_indices().next().is_none());
            assert!(io.maps.is_empty() && io.outer.is_empty() && io.routes.is_empty());
            assert!(io.commits.is_empty() && io.attempted.is_empty());
            assert_eq!(io.held.len(), 1);
            // Literal envelope: 1,048,576 retained + 65,536 metadata.
            assert_eq!(pool.snapshot().charged_bytes, charged + 1_114_112);
        }
    }

    fn same_plan_clean_rollback_keeps_holes(compact: bool) {
        for failure in ["entry", "commit"] {
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            let mut history = plan(1);
            assert!(matches!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Published { transaction: 1, .. }
            ));
            let old = io.routes[&0];
            history.extend_exact(plan(3)).unwrap();
            let before = history.slots.clone();
            let charged = pool.snapshot().charged_bytes;
            io.next_stage();
            io.failure = (failure == "entry").then_some("entry");
            io.commit_absent = failure == "commit";
            assert_eq!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::RolledBack {
                    transaction: 2,
                    extent: BankExtent { first: 1, end: 3 },
                    reason: if failure == "entry" {
                        BankRefusal::Links
                    } else {
                        BankRefusal::Commit
                    },
                },
                "failure {failure}, compact {compact}"
            );
            assert_eq!(history.counter_consumed_end(), 3);
            assert_eq!(history.slots, before);
            assert!(history.is_active(0) && !history.is_active(1) && !history.is_active(2));
            assert_eq!(directory.allocated_high_water(), 3);
            assert_eq!(directory.next_transaction, NonZeroU64::new(3));
            assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
            assert!(
                directory.positions[1..]
                    .iter()
                    .all(|position| matches!(position.state, PositionState::NeverPublishedRetired))
            );
            assert_eq!(io.routes, BTreeMap::from([(0, old)]));
            assert_eq!(io.maps, BTreeMap::from([(0, 101)]));
            assert_eq!(io.outer, BTreeMap::from([(0, 101)]));
            assert_eq!(io.providers, BTreeSet::from([0]));
            assert_eq!(io.entries, BTreeSet::from([0]));
            assert_eq!(io.returns, BTreeSet::from([0]));
            assert!(!io.trace.contains(&"remove-bank"));
            assert_eq!(io.held.len(), 2);
            assert_eq!(pool.snapshot().charged_bytes, charged + 1_114_112);
            if compact {
                assert_eq!(
                    history.excise_unlinked_tail_cells(1, &BTreeSet::from([1, 2, 99])),
                    [0, 1, 2]
                );
            } else {
                history.withdraw_unlinked_additions(1);
            }
            assert_eq!(history.slots, before);
            assert_eq!(history.counter_consumed_end(), 3);
            assert!(history.validate_slot_index().is_ok());

            let delta = history.extend_exact(plan(3)).unwrap();
            assert_eq!(
                delta.new.iter().map(|slot| slot.index).collect::<Vec<_>>(),
                [3, 4]
            );
            assert!(delta.replace.is_empty() && delta.retire.is_empty());
            assert_eq!(physical(&history.slots[1]), physical(&history.slots[3]));
            assert_eq!(physical(&history.slots[2]), physical(&history.slots[4]));
            assert!(!history.is_active(1) && !history.is_active(2));
            io.failure = None;
            io.commit_absent = false;
            io.next_stage();
            assert_eq!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Published {
                    transaction: 3,
                    extent: BankExtent { first: 3, end: 5 }
                }
            );
            assert_eq!(history.counter_consumed_end(), 5);
            assert_eq!(directory.allocated_high_water(), 5);
            assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0, 3, 4]);
            assert_eq!(io.routes.keys().copied().collect::<Vec<_>>(), [0, 3, 4]);
            assert_eq!(io.routes[&0], old);
            assert_eq!(
                (
                    io.routes[&3].bank,
                    io.routes[&3].cell,
                    io.routes[&3].transaction
                ),
                (0, 3, 3)
            );
            assert_eq!(
                (
                    io.routes[&4].bank,
                    io.routes[&4].cell,
                    io.routes[&4].transaction
                ),
                (0, 4, 3)
            );
            assert!(!io.trace.contains(&"allocate") && !io.trace.contains(&"inner"));
            assert_eq!(directory.validate_read_plan(&history), Ok(()));
        }
    }

    #[test]
    fn same_plan_rollback_withdrawal_keeps_holes_and_retries_fresh_ordinals() {
        same_plan_clean_rollback_keeps_holes(false);
    }

    #[test]
    fn same_plan_rollback_compaction_keeps_holes_and_retries_fresh_ordinals() {
        same_plan_clean_rollback_keeps_holes(true);
    }

    #[test]
    fn same_plan_postattempt_uncertainty_retains_floor_and_paid_identities() {
        for case in 0..4 {
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            let mut history = plan(1);
            assert!(matches!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Published { transaction: 1, .. }
            ));
            let old = io.routes[&0];
            history.extend_exact(plan(2)).unwrap();
            let charged = pool.snapshot().charged_bytes;
            io.next_stage();
            match case {
                0 => io.commit_wrong = true,
                1 => io.commit_unreadable = true,
                2 => io.damage = Some((2, GrowthDamage::Provider)),
                _ => {
                    io.commit_absent = true;
                    io.failure = Some("retire");
                }
            }
            assert_eq!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Quarantined {
                    transaction: 2,
                    extent: BankExtent { first: 1, end: 2 }
                },
                "uncertainty {case}"
            );
            assert_eq!(history.counter_consumed_end(), 2);
            assert!(history.is_active(0) && history.is_active(1));
            assert_eq!(directory.allocated_high_water(), 2);
            assert_eq!(directory.next_transaction, NonZeroU64::new(3));
            assert!(matches!(
                directory.positions[1].state,
                PositionState::Pending
            ));
            assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
            assert_eq!(io.maps, BTreeMap::from([(0, 101)]));
            assert_eq!(io.outer, BTreeMap::from([(0, 101)]));
            assert_eq!(io.routes[&0], old);
            assert_eq!(io.entries, BTreeSet::from([0, 1]));
            assert_eq!(io.returns, BTreeSet::from([0, 1]));
            assert_eq!(io.held.len(), 2);
            assert_eq!(pool.snapshot().charged_bytes, charged + 1_114_112);
            assert!(!io.trace.contains(&"remove-bank"));
            if case == 3 {
                assert_eq!(io.routes.keys().copied().collect::<Vec<_>>(), [0]);
                assert!(io.trace.contains(&"remove-route") && io.trace.contains(&"retire-entry"));
            } else {
                assert_eq!(io.routes.keys().copied().collect::<Vec<_>>(), [0, 1]);
                assert!(!io.trace.contains(&"remove-route") && !io.trace.contains(&"retire-entry"));
            }
            io.next_stage();
            assert_eq!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Refused(BankRefusal::Quarantined)
            );
            assert!(io.trace.is_empty());
            assert_eq!(history.counter_consumed_end(), 2);
            assert_eq!(
                directory.validate_read_plan(&history),
                Err(BankRefusal::Quarantined)
            );
        }
    }

    #[test]
    fn same_plan_success_consumes_once_and_keeps_inactive_published_history() {
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        let mut history = plan(1);
        assert_eq!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published {
                transaction: 1,
                extent: BankExtent { first: 0, end: 1 }
            }
        );
        assert_eq!(history.counter_consumed_end(), 1);
        let old = io.routes[&0];
        history.extend_exact(plan(2)).unwrap();
        history.deactivate(0);
        io.next_stage();
        assert_eq!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published {
                transaction: 2,
                extent: BankExtent { first: 1, end: 2 }
            }
        );
        assert_eq!(history.counter_consumed_end(), 2);
        assert!(!history.is_active(0) && history.is_active(1));
        assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0, 1]);
        assert_eq!(directory.validate_read_plan(&history), Ok(()));
        assert_eq!(io.routes[&0], old);
        assert_eq!(
            io.trace,
            [
                "validate", "observe", "retain", "route", "return", "entry", "verify", "commit",
                "verify", "observe"
            ]
        );
        let charged = pool.snapshot().charged_bytes;
        io.next_stage();
        assert_eq!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Refused(BankRefusal::Allocated)
        );
        assert!(io.trace.is_empty());
        assert_eq!(history.counter_consumed_end(), 2);
        assert_eq!(directory.allocated_high_water(), 2);
        assert_eq!(directory.next_transaction, NonZeroU64::new(3));
        assert_eq!(io.held.len(), 2);
        assert_eq!(pool.snapshot().charged_bytes, charged);
    }

    #[test]
    fn same_plan_floor_mismatch_refuses_rebuilt_input_before_io() {
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        let mut history = plan(1);
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { transaction: 1, .. }
        ));
        let old = io.routes[&0];
        let charged = pool.snapshot().charged_bytes;
        let mut rebuilt = plan(2);
        io.next_stage();
        assert_eq!(
            directory.stage_with(
                &mut io,
                &mut rebuilt,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Refused(BankRefusal::Topology)
        );
        assert!(io.trace.is_empty());
        assert_eq!(rebuilt.counter_consumed_end(), 0);
        assert_eq!(history.counter_consumed_end(), 1);
        assert_eq!(directory.allocated_high_water(), 1);
        assert_eq!(directory.next_transaction, NonZeroU64::new(2));
        assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
        assert_eq!(io.routes, BTreeMap::from([(0, old)]));
        assert_eq!(io.held.len(), 1);
        assert_eq!(pool.snapshot().charged_bytes, charged);
    }

    #[test]
    fn scaled_charge_refusal_precedes_every_native_operation() {
        let mut failures = Vec::new();
        for case in 0..8 {
            let mut bad = growth_reservation();
            match case {
                0 => bad.retained_bytes = 48, // One cell at two CPUs, not a full512-cell bank.
                1 => bad.transient_bytes = 1,
                2 => bad.metadata_bytes = 1,
                3 => bad.file_descriptors = 1,
                4 => bad.retained_bytes = usize::MAX,
                5 => bad.metadata_bytes = usize::MAX,
                6 => bad.metadata_bytes = 0,
                _ => bad.file_descriptors = 0,
            }
            failures.push((2, bad));
        }
        failures.extend([
            (0, growth_reservation()),
            (usize::MAX, growth_reservation()),
        ]);
        for (cpus, bad) in failures {
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            io.cpus = cpus;
            let charged = pool.snapshot().charged_bytes;
            assert!(matches!(
                directory.stage_with(&mut io, &mut plan(1), bad, &pool.reserver()),
                BankPublication::Refused(BankRefusal::Budget | BankRefusal::Topology)
            ));
            assert!(io.trace.is_empty() && io.maps.is_empty() && io.routes.is_empty());
            assert_eq!(pool.snapshot().charged_bytes, charged);
            assert_eq!(directory.allocated_high_water(), 0);
        }
        // At1024 possible CPUs a whole bank needs12,582,912 payload bytes.
        // The one-cell amount is only24,576: metadata and FD headroom are
        // deliberately ample, so forgetting the other511 cells is causal.
        // The fixed kernel maps alone (~555 MiB at P=1024) exceed the 256 MiB
        // cap, so even the funded envelope refuses the memory cap here.
        let geometry = BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap();
        assert_eq!(geometry.bank_payload_bytes(1024), Ok(12_582_912));
        for enough in [false, true] {
            let pool = SemanticResourcePool::reference_limit(128 * 1024 * 1024);
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            io.cpus = 1024;
            let envelope = BankReservation {
                retained_bytes: if enough {
                    32 * 1024 * 1024
                } else {
                    1024 * 1024
                },
                transient_bytes: 8 * 1024 * 1024,
                metadata_bytes: 1024 * 1024,
                file_descriptors: 65_536,
            };
            let result = directory.stage_with(&mut io, &mut plan(1), envelope, &pool.reserver());
            if enough {
                assert_eq!(
                    result,
                    BankPublication::Refused(BankRefusal::BudgetExhausted {
                        resource: "counter-memory-limit",
                        needed: 568_068_096,
                        available: 268_435_456,
                    }),
                    "funded P=1024 refuses the kernel map cap: {result:?}"
                );
                assert!(io.trace.is_empty() && io.maps.is_empty());
            } else {
                assert_eq!(result, BankPublication::Refused(BankRefusal::Budget));
                assert!(io.trace.is_empty() && io.maps.is_empty());
            }
        }
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        let mut history = plan(1);
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { .. }
        ));
        history.extend_exact(plan(2)).unwrap();
        let old = io.routes[&0];
        let charged = pool.snapshot().charged_bytes;
        io.next_stage();
        let refused = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH);
        assert_eq!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &refused.reserver()
            ),
            BankPublication::Refused(BankRefusal::Budget)
        );
        assert!(io.trace.is_empty());
        assert_eq!(io.routes[&0], old);
        assert_eq!(pool.snapshot().charged_bytes, charged);
        assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
    }

    #[test]
    fn full_width_transaction_commit_rejects_high32_alias() {
        let high = 0x1_0000_0007;
        let commit = CountsBankCommit {
            first: 0,
            end: 1,
            configuration: 0x0200_0018_0010_0200,
        };
        let route = CountsBankRoute {
            transaction: 7,
            first: 0,
            end: 1,
            bank: 0,
            cell: 0,
            inner_id: 101,
            reserved_zero: 0,
        };
        assert!(
            StagedExtent::checked(
                NonZeroU64::new(high).unwrap(),
                commit,
                vec![(0, route)],
                vec![(0, 101)]
            )
            .is_err()
        );
        for missing_high in [false, true] {
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let mut directory = BankDirectory::counts_growth_v2();
            directory.next_transaction = NonZeroU64::new(high);
            let mut io = GrowthIo::new(&pool);
            io.commits.insert(7, commit);
            io.commit_absent = missing_high;
            let publication = directory.stage_with(
                &mut io,
                &mut plan(1),
                growth_reservation(),
                &pool.reserver(),
            );
            assert_eq!(io.commits[&7], commit);
            if missing_high {
                assert!(matches!(publication, BankPublication::RolledBack { .. }));
                assert!(io.routes.is_empty() && io.maps.is_empty());
                assert!(!io.commits.contains_key(&high));
                assert!(directory.published_indices().next().is_none());
            } else {
                assert!(
                    matches!(publication, BankPublication::Published { transaction, .. } if transaction == high)
                );
                assert_eq!(io.routes[&0].transaction, high);
                assert_eq!(io.commits[&high], commit);
                assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
            }
        }
    }

    #[test]
    fn fixed_counter_roots_resolve_abis_then_attach_returns_before_entries() {
        use crate::attach::{
            CapturePolicy, StaticRoots, attach_targets_observed_with_roots, pid_continuity,
        };
        use p11scope_manifest::elf::ElfAbi;
        use std::cell::RefCell;

        let slots = plan(2).slots;
        let calls = RefCell::new(Vec::new());
        let outcome = attach_targets_observed_with_roots(
            &slots,
            CapturePolicy::Counter(CounterMode::Counts),
            false,
            StaticRoots::CounterBanks,
            Some(CounterMode::Counts),
            |slot| {
                calls.borrow_mut().push(("abi", slot.index));
                Ok(ElfAbi::Lp64)
            },
            |program, slot, _| {
                calls.borrow_mut().push((program, slot.index));
                pid_continuity::NativeAttempt {
                    started_ns: Some(1),
                    result: Ok(()),
                }
            },
            |_| Some(2),
        )
        .unwrap();
        assert!(outcome.failures.is_empty());
        assert_eq!(outcome.completed.len(), 2);
        assert_eq!(
            calls.into_inner(),
            vec![
                ("abi", 0),
                ("abi", 1),
                ("p11_counter_bank_return", 0),
                ("p11_counter_bank_return", 1),
                ("p11_counter_bank_entry", 0),
                ("p11_counter_bank_entry", 1),
            ]
        );
        let mut attached = false;
        let refused = attach_targets_observed_with_roots(
            &slots,
            CapturePolicy::AggregateOnly,
            false,
            StaticRoots::CounterBanks,
            Some(CounterMode::Counts),
            |_| Ok(ElfAbi::Ilp32),
            |_, _, _| {
                attached = true;
                pid_continuity::NativeAttempt {
                    started_ns: None,
                    result: Ok(()),
                }
            },
            |_| None,
        );
        assert!(refused.is_err(), "this bounded host proof is LP64 only");
        assert!(!attached, "all ABI validation precedes the first link");
        let mut legacy_attached = false;
        let legacy_refused = attach_targets_observed_with_roots(
            &slots,
            CapturePolicy::AggregateOnly,
            false,
            StaticRoots::CounterBanks,
            Some(CounterMode::Counts),
            |_| Ok(ElfAbi::Lp64),
            |_, _, _| {
                legacy_attached = true;
                pid_continuity::NativeAttempt {
                    started_ns: None,
                    result: Ok(()),
                }
            },
            |_| None,
        );
        assert!(
            legacy_refused.is_err(),
            "legacy aggregate policy must not take bank roots"
        );
        assert!(!legacy_attached, "policy refusal precedes the first link");
        let mut mismatched_attached = false;
        let mismatched = attach_targets_observed_with_roots(
            &slots,
            CapturePolicy::Counter(CounterMode::Timestamps),
            false,
            StaticRoots::CounterBanks,
            Some(CounterMode::Counts),
            |_| Ok(ElfAbi::Lp64),
            |_, _, _| {
                mismatched_attached = true;
                pid_continuity::NativeAttempt {
                    started_ns: None,
                    result: Ok(()),
                }
            },
            |_| None,
        );
        assert!(
            mismatched.is_err(),
            "a timestamps policy must not take counts bank roots"
        );
        assert!(!mismatched_attached, "mode refusal precedes the first link");
    }

    #[derive(Default)]
    struct Native {
        trace: Vec<&'static str>,
        inners: BTreeMap<u32, u32>,
        metadata: BTreeMap<u32, BankMetadata>,
        commits: BTreeMap<u64, BankCommit>,
        entries: BTreeSet<u32>,
        returns: BTreeSet<u32>,
        held: Vec<ResourceLease>,
        acknowledgements: Vec<CommitAck>,
        attempted: BTreeSet<u64>,
        fail: Option<&'static str>,
        foreign_inner: Option<u32>,
        failed_delete: bool,
        failed_retire: bool,
        provider_guard: Option<(PinnedObjects, [Option<RetainedInventoryTarget>; BANKS])>,
    }

    impl BankIo for Native {
        fn possible_cpus(&self) -> usize {
            2
        }
        fn validate_targets(
            &mut self,
            slots: &[Slot],
            published: &[u32],
            _fresh: BankExtent,
            _old_capacity: usize,
        ) -> Result<(), BankRefusal> {
            self.trace.push("validate");
            let published = legacy_indices_mask(published.iter().copied())?;
            if let Some((pins, retained)) = &self.provider_guard {
                validate_provider_slots(slots, pins, published, |index| {
                    retained[index as usize].as_ref()
                })?;
            }
            Ok(())
        }

        fn retain_charge(&mut self, charge: ResourceLease) {
            self.held.push(charge);
        }

        fn allocate_bank(&mut self, slot: u32, all_slots: &[Slot]) -> Result<u32, BankRefusal> {
            assert!(
                !self.held.is_empty(),
                "precharge precedes native allocation"
            );
            self.trace.push("allocate");
            if self.fail == Some("allocate") {
                return Err(BankRefusal::Native);
            }
            if self.foreign_inner == Some(slot) {
                self.inners.insert(slot, 99);
            }
            if let Some((pins, retained)) = &mut self.provider_guard {
                let target = all_slots.get(slot as usize).ok_or(BankRefusal::Topology)?;
                retained[slot as usize] = Some(
                    pins.retain_inventory_target(target.object)
                        .map_err(|_| BankRefusal::Ownership)?,
                );
            }
            Ok(slot + 1)
        }

        fn insert_inner(&mut self, slot: u32, expected_id: u32) -> Result<(), BankRefusal> {
            self.trace.push("inner");
            if self.inners.contains_key(&slot) {
                return Err(BankRefusal::Quarantined);
            }
            self.inners.insert(slot, expected_id);
            Ok(())
        }

        fn insert_route(&mut self, slot: u32, route: CountsBankRoute) -> Result<(), BankRefusal> {
            self.trace.push("metadata");
            if self.fail == Some("metadata") || self.metadata.contains_key(&slot) {
                return Err(BankRefusal::Native);
            }
            let metadata = legacy_route(slot, route)?;
            self.metadata.insert(slot, metadata);
            Ok(())
        }

        fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
            assert!(slots.iter().all(|slot| {
                let metadata = self.metadata[&slot.index];
                !self.commits.contains_key(&metadata.transaction)
            }));
            self.trace.push("return");
            self.returns.extend(slots.iter().map(|slot| slot.index));
            self.trace.push("entry");
            if self.fail == Some("entry") {
                return Err(BankRefusal::Links);
            }
            self.entries.extend(slots.iter().map(|slot| slot.index));
            Ok(())
        }

        fn verify_candidate(
            &mut self,
            expected: &StagedExtent,
            all_slots: &[Slot],
            _published: &[u32],
        ) -> CandidateCheck {
            self.trace.push("verify");
            assert_eq!(all_slots.len(), expected.commit.end as usize);
            if let Some((pins, retained)) = &self.provider_guard {
                let Ok(all) = legacy_indices_mask(all_slots.iter().map(|slot| slot.index)) else {
                    return CandidateCheck::Contradictory;
                };
                if validate_provider_slots(all_slots, pins, all, |index| {
                    retained[index as usize].as_ref()
                })
                .is_err()
                {
                    return CandidateCheck::Contradictory;
                }
            }
            for &(slot, route) in &expected.routes {
                let Ok(wire) = legacy_route(slot, route) else {
                    return CandidateCheck::Contradictory;
                };
                if self.metadata.get(&slot) != Some(&wire)
                    || self.inners.get(&route.bank) != Some(&route.inner_id)
                    || !expected.bank_ids.contains(&(route.bank, route.inner_id))
                    || !self.entries.contains(&slot)
                    || !self.returns.contains(&slot)
                {
                    return CandidateCheck::Contradictory;
                }
            }
            CandidateCheck::Exact
        }

        fn insert_commit(
            &mut self,
            transaction: u64,
            commit: CountsBankCommit,
        ) -> Result<(), BankRefusal> {
            let commit = legacy_commit(commit)?;
            self.trace.push("commit");
            self.attempted.insert(transaction);
            assert!(!self.commits.contains_key(&transaction));
            if self.fail != Some("commit-absent") {
                self.commits.insert(transaction, commit);
            }
            if self.fail == Some("commit-absent") || self.fail == Some("commit-ack-lost") {
                Err(BankRefusal::Commit)
            } else {
                Ok(())
            }
        }

        fn observe_commit(
            &mut self,
            transaction: u64,
            expected: CountsBankCommit,
        ) -> CommitObservation {
            self.trace.push("ack");
            let acknowledgement =
                if self.attempted.contains(&transaction) && !self.acknowledgements.is_empty() {
                    self.acknowledgements.remove(0)
                } else {
                    match self.commits.get(&transaction) {
                        Some(commit) => CommitAck::Present(*commit),
                        None => CommitAck::Absent,
                    }
                };
            match acknowledgement {
                CommitAck::Absent => CommitObservation::Absent,
                CommitAck::Present(actual) if legacy_commit(expected) == Ok(actual) => {
                    CommitObservation::Exact
                }
                CommitAck::Present(_) => CommitObservation::Contradictory,
                CommitAck::Unreadable => CommitObservation::Unreadable,
            }
        }

        fn remove_route_owned(
            &mut self,
            slot: u32,
            expected: CountsBankRoute,
        ) -> Result<(), BankRefusal> {
            let expected = legacy_route(slot, expected)?;
            self.trace.push("remove-metadata");
            if self.failed_delete || self.metadata.get(&slot) != Some(&expected) {
                return Err(BankRefusal::Ownership);
            }
            self.metadata.remove(&slot);
            Ok(())
        }

        fn remove_new_bank_owned(
            &mut self,
            slot: u32,
            expected_id: u32,
        ) -> Result<(), BankRefusal> {
            self.trace.push("remove-inner");
            if self.failed_delete || self.inners.get(&slot) != Some(&expected_id) {
                return Err(BankRefusal::Ownership);
            }
            self.inners.remove(&slot);
            Ok(())
        }

        fn retire_links(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
            self.trace.push("retire-links");
            if self.failed_retire {
                Err(BankRefusal::Links)
            } else {
                for slot in slots {
                    self.entries.remove(&slot.index);
                    self.returns.remove(&slot.index);
                }
                Ok(())
            }
        }
    }

    #[test]
    fn staging_precharges_before_native_mutation_and_links_return_first() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut directory = BankDirectory::default();
        let mut native = Native::default();
        assert!(matches!(
            directory.stage_with(&mut native, &mut plan(2), reservation(), &pool.reserver()),
            BankPublication::Published {
                extent: BankExtent { first: 0, end: 2 },
                ..
            }
        ));
        let return_at = native
            .trace
            .iter()
            .position(|step| *step == "return")
            .unwrap();
        let entry_at = native
            .trace
            .iter()
            .position(|step| *step == "entry")
            .unwrap();
        let commit_at = native
            .trace
            .iter()
            .position(|step| *step == "commit")
            .unwrap();
        assert!(return_at < entry_at && entry_at < commit_at);
        assert!(pool.snapshot().charged_bytes > SEMANTIC_TRANSITION_SCRATCH);

        // The actual Session gate must remain closed outside the transaction,
        // and a refused overlapping admission must not clear the first guard.
        let banks = CounterBanks {
            geometry: BankGeometry::legacy(),
            directory: Arc::new(Mutex::new(BankDirectory::default())),
            keepalive: CounterKeepalive::precharge(&pool.reserver(), 4096).unwrap(),
            cpus: 2,
            backend: super::super::AttachBackend::Singles,
            link_staging: Arc::new(AtomicU64::new(0)),
            terminal: None,
        };
        let targets = plan(2).slots;
        assert!(!banks.permits_link_stage(&targets));
        let stage = banks.begin_link_stage(2).unwrap();
        assert!(banks.permits_link_stage(&targets));
        assert!(!banks.permits_link_stage(&targets[..1]));
        assert!(banks.begin_link_stage(1).is_err());
        assert!(banks.permits_link_stage(&targets));
        drop(stage);
        assert!(!banks.permits_link_stage(&targets));

        let refused = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH);
        let mut native = Native::default();
        let mut directory = BankDirectory::default();
        assert_eq!(
            directory.stage_with(
                &mut native,
                &mut plan(1),
                reservation(),
                &refused.reserver()
            ),
            BankPublication::Refused(BankRefusal::Budget)
        );
        assert!(native.trace.is_empty());
        assert_eq!(directory.legacy_published_mask().unwrap(), 0);
        drop(native);
    }

    #[test]
    fn exact_commit_ack_publishes_once_and_preserves_old_routes() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut directory = BankDirectory::default();
        let mut native = Native::default();
        let mut history = plan(1);
        let BankPublication::Published {
            transaction: old,
            extent: BankExtent { first: 0, end: 1 },
        } = directory.stage_with(&mut native, &mut history, reservation(), &pool.reserver())
        else {
            panic!("first real transaction did not publish");
        };
        let original = native.metadata[&0];
        history.extend_exact(plan(2)).unwrap();
        native.fail = Some("commit-ack-lost");
        let BankPublication::Published {
            transaction: new,
            extent: BankExtent { first: 1, end: 2 },
        } = directory.stage_with(&mut native, &mut history, reservation(), &pool.reserver())
        else {
            panic!("matching readback must resolve lost syscall acknowledgement");
        };
        assert!(new > old);
        assert_eq!(native.metadata[&0], original);
        assert_eq!(original.transaction, old);
        assert_eq!(native.metadata[&1].transaction, new);
        assert_eq!(native.commits[&old].mask, 1);
        assert_eq!(native.commits[&new].mask, 2);
        assert_eq!(directory.legacy_published_mask().unwrap(), 3);
        assert!(directory.validate_read_plan(&history).is_ok());

        let before = native.trace.len();
        history.slots[0].object = PinnedObjectId(99);
        assert_eq!(
            directory.stage_with(&mut native, &mut history, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Topology)
        );
        assert_eq!(
            native.trace.len(),
            before,
            "mismatch precedes native mutation"
        );
        assert_eq!(directory.legacy_published_mask().unwrap(), 3);
    }

    #[test]
    fn absent_commit_rolls_back_only_candidate_owned_keys() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        for failure in ["metadata", "entry", "commit-absent"] {
            let mut directory = BankDirectory::default();
            let mut native = Native {
                fail: Some(failure),
                ..Native::default()
            };
            let mut history = plan(2);
            assert!(
                matches!(
                    directory.stage_with(
                        &mut native,
                        &mut history,
                        reservation(),
                        &pool.reserver()
                    ),
                    BankPublication::RolledBack { .. }
                ),
                "{failure}"
            );
            assert!(native.inners.is_empty(), "{failure}");
            assert!(native.metadata.is_empty(), "{failure}");
            assert!(native.commits.is_empty(), "{failure}");
            assert_eq!(directory.legacy_published_mask().unwrap(), 0);
            assert!(
                !native.held.is_empty(),
                "cleanup custody retains the charge"
            );
            let before = native.trace.len();
            assert!(matches!(
                directory.stage_with(&mut native, &mut history, reservation(), &pool.reserver()),
                BankPublication::Refused(BankRefusal::Allocated)
            ));
            assert_eq!(
                native.trace.len(),
                before,
                "allocated positions are never revived"
            );
        }
        let mut directory = BankDirectory::default();
        let mut native = Native {
            foreign_inner: Some(0),
            ..Native::default()
        };
        assert!(matches!(
            directory.stage_with(&mut native, &mut plan(1), reservation(), &pool.reserver()),
            BankPublication::Quarantined { .. }
        ));
        assert_eq!(native.inners.get(&0), Some(&99));
        assert!(!native.trace.contains(&"remove-inner"));
        assert!(!native.trace.contains(&"commit"));
        assert_eq!(
            directory.validate_read_plan(&plan(1)),
            Err(BankRefusal::Quarantined)
        );
    }

    #[test]
    fn ambiguous_ack_retains_custody_and_refuses_reads() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        for acknowledgement in [
            CommitAck::Unreadable,
            CommitAck::Present(BankCommit {
                mask: 2,
                configuration: BANK_CONFIG,
            }),
            CommitAck::Present(BankCommit {
                mask: 1,
                configuration: BANK_CONFIG ^ 1,
            }),
        ] {
            let mut directory = BankDirectory::default();
            let mut native = Native {
                acknowledgements: vec![acknowledgement],
                ..Native::default()
            };
            let mut history = plan(1);
            assert!(matches!(
                directory.stage_with(&mut native, &mut history, reservation(), &pool.reserver()),
                BankPublication::Quarantined { .. }
            ));
            assert_eq!(native.inners.len(), 1);
            assert_eq!(native.metadata.len(), 1);
            assert!(!native.held.is_empty());
            assert!(!native.trace.contains(&"remove-inner"));
            assert_eq!(
                directory.validate_read_plan(&history),
                Err(BankRefusal::Quarantined)
            );
            history.extend_exact(plan(2)).unwrap();
            let before = native.trace.len();
            assert_eq!(
                directory.stage_with(&mut native, &mut history, reservation(), &pool.reserver()),
                BankPublication::Refused(BankRefusal::Quarantined)
            );
            assert_eq!(native.trace.len(), before);
        }
        let mut directory = BankDirectory::default();
        let mut native = Native {
            fail: Some("commit-absent"),
            failed_delete: true,
            ..Native::default()
        };
        assert!(matches!(
            directory.stage_with(&mut native, &mut plan(1), reservation(), &pool.reserver()),
            BankPublication::Quarantined { .. }
        ));
        assert!(!native.inners.is_empty());
        assert!(!native.held.is_empty());
        assert_eq!(
            directory.validate_read_plan(&plan(1)),
            Err(BankRefusal::Quarantined)
        );
        let mut directory = BankDirectory::default();
        let mut native = Native {
            fail: Some("commit-absent"),
            failed_retire: true,
            ..Native::default()
        };
        assert!(matches!(
            directory.stage_with(&mut native, &mut plan(1), reservation(), &pool.reserver()),
            BankPublication::Quarantined { .. }
        ));
        assert!(
            !native.held.is_empty(),
            "uncertain real link close retains all charges"
        );
        assert_eq!(
            directory.validate_read_plan(&plan(1)),
            Err(BankRefusal::Quarantined)
        );
    }

    #[test]
    fn native_limits_and_transaction_exhaustion_refuse_before_mutation() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut native = Native::default();
        let mut directory = BankDirectory::default();
        assert_eq!(
            directory.stage_with(&mut native, &mut plan(3), reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Shape(BankShapeCause::PlanBudgetMismatch)),
        );
        let mut aliases = plan(2);
        aliases.slots[1].object = aliases.slots[0].object;
        assert_eq!(
            directory.stage_with(&mut native, &mut aliases, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Topology),
        );
        assert!(native.trace.is_empty());
        let mut history = plan(1);
        directory.next_transaction = std::num::NonZeroU64::new(u64::MAX);
        assert!(matches!(
            directory.stage_with(&mut native, &mut history, reservation(), &pool.reserver()),
            BankPublication::Published {
                transaction: u64::MAX,
                ..
            }
        ));
        history.extend_exact(plan(2)).unwrap();
        let before = native.trace.len();
        assert_eq!(
            directory.stage_with(&mut native, &mut history, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Exhausted),
        );
        assert_eq!(native.trace.len(), before);
        history.deactivate(1);
        history.withdraw_unlinked_additions(1);
        assert_eq!(history.counter_consumed_end(), 1);
        assert_eq!(history.slots.len(), 1);
        assert!(directory.validate_read_plan(&history).is_ok());
        assert_eq!(directory.legacy_published_mask().unwrap(), 1);
    }

    #[test]
    fn retained_provider_prefix_binds_independent_stores_before_staging_or_reading() {
        use crate::discovery::identity::test_fixture::real_scan_pin;
        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old-provider.so");
        let foreign_path = dir.path().join("foreign-provider.so");
        std::fs::write(&old_path, b"identical owned provider bytes").unwrap();
        std::fs::write(&foreign_path, b"identical owned provider bytes").unwrap();
        let old = real_scan_pin(&old_path, None, 1, "same-content-digest");
        let same = real_scan_pin(&old_path, None, 2, "same-content-digest");
        let foreign = real_scan_pin(&foreign_path, None, 3, "same-content-digest");
        let id = old.pinned().next().unwrap().id;
        assert_eq!(same.pinned().next().unwrap().id, id);
        assert_eq!(foreign.pinned().next().unwrap().id, id);
        let mut selected_slot = slot(0, 1);
        selected_slot.object = id;
        let policy = crate::plan::AdmissionPolicy::counters(
            crate::capacity::CounterBudget::new(8192).unwrap(),
        );
        let mut selected = AttachPlan::from_slots_with_policy(vec![selected_slot], policy).unwrap();
        let retained = [Some(old.retain_inventory_target(id).unwrap()), None];
        for pins in [&old, &same] {
            assert_eq!(
                validate_provider_slots(&selected.slots, pins, 1, |index| {
                    retained[index as usize].as_ref()
                }),
                Ok(()),
                "a fresh pin store of the same opened provider is valid"
            );
        }
        assert_eq!(
            validate_provider_slots(&selected.slots, &foreign, 1, |index| {
                retained[index as usize].as_ref()
            }),
            Err(BankRefusal::Ownership),
            "same local ID, offset and content do not identify the held file"
        );
        assert_eq!(
            validate_provider_slots(&selected.slots, &same, 1, |_| None),
            Err(BankRefusal::Ownership),
            "read labeling requires the actual retained prefix proof"
        );

        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut directory = BankDirectory::default();
        let mut native = Native {
            provider_guard: Some((old, retained)),
            ..Native::default()
        };
        assert!(matches!(
            directory.stage_with(&mut native, &mut selected, reservation(), &pool.reserver()),
            BankPublication::Published {
                transaction: 1,
                extent: BankExtent { first: 0, end: 1 }
            }
        ));
        // A separately built store now assigns zero to a foreign provider and
        // one to the original provider. Numeric prefix checks alone accept it.
        let mut switched = foreign;
        assert!(switched.absorb(same).is_empty());
        assert_eq!(switched.pinned().count(), 2);
        let mut appended_slot = slot(1, 2);
        appended_slot.object = switched
            .pinned()
            .map(|pin| pin.id)
            .find(|&id| id != selected.slots[0].object)
            .unwrap();
        let appended = AttachPlan::from_slots_with_policy(
            vec![selected.slots[0].clone(), appended_slot],
            policy,
        )
        .unwrap();
        selected.extend_exact(appended).unwrap();
        let bindings = native.provider_guard.as_mut().unwrap();
        bindings.0 = switched;
        let charged = pool.snapshot().charged_bytes;
        let before = native.trace.len();
        assert_eq!(
            directory.stage_with(&mut native, &mut selected, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Ownership)
        );
        assert_eq!(directory.legacy_published_mask().unwrap(), 1);
        assert_eq!(directory.allocated_high_water(), 1);
        assert_eq!(directory.next_transaction.unwrap().get(), 2);
        assert_eq!(native.metadata.len(), 1);
        assert_eq!(native.commits.len(), 1);
        assert_eq!(native.held.len(), 1);
        assert_eq!(pool.snapshot().charged_bytes, charged);
        assert!(!native.trace[before..].iter().any(|step| {
            matches!(
                *step,
                "allocate" | "inner" | "metadata" | "return" | "entry" | "commit"
            )
        }));
        let mut restored = real_scan_pin(&old_path, None, 4, "same-content-digest");
        assert!(
            restored
                .absorb(real_scan_pin(&foreign_path, None, 5, "same-content-digest"))
                .is_empty()
        );
        native.provider_guard.as_mut().unwrap().0 = restored;
        assert!(matches!(
            directory.stage_with(&mut native, &mut selected, reservation(), &pool.reserver()),
            BankPublication::Published {
                transaction: 2,
                extent: BankExtent { first: 1, end: 2 }
            }
        ));
        assert_eq!(native.metadata[&0].transaction, 1);
        assert_eq!(native.commits[&1].mask, 1);
    }

    #[test]
    fn physical_endpoint_duplicates_refuse_even_with_distinct_local_ids() {
        use crate::discovery::identity::test_fixture::real_scan_pin;
        use p11scope_manifest::maps::{Device, ObjectKey};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.so");
        std::fs::write(&path, b"one owned kernel file through two mapping keys").unwrap();
        let mut pins = real_scan_pin(&path, None, 1, "provider-digest");
        let old = pins.pinned().next().unwrap().id;
        let retained = pins.retain_inventory_target(old).unwrap();
        let alias = real_scan_pin(
            &path,
            Some(ObjectKey {
                device: Device {
                    major: 0,
                    minor: 4021,
                },
                inode: 987654,
            }),
            2,
            "provider-digest",
        );
        assert!(pins.absorb(alias).is_empty());
        let ids: Vec<_> = pins.pinned().map(|pin| pin.id).collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
        assert!(retained.same_object_as(&pins, ids[1]));
        let mut duplicate_slots = vec![slot(0, 1), slot(1, 2)];
        duplicate_slots[0].object = ids[0];
        duplicate_slots[1].object = ids[1];
        let duplicate = AttachPlan::from_slots_with_policy(
            duplicate_slots,
            crate::plan::AdmissionPolicy::counters(
                crate::capacity::CounterBudget::new(8192).unwrap(),
            ),
        )
        .unwrap();
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut native = Native {
            provider_guard: Some((pins, [Some(retained), None])),
            ..Native::default()
        };
        let mut directory = BankDirectory::default();
        let mut first = AttachPlan::from_slots_with_policy(
            duplicate.slots[..1].to_vec(),
            duplicate.admission_policy(),
        )
        .unwrap();
        assert!(matches!(
            directory.stage_with(&mut native, &mut first, reservation(), &pool.reserver()),
            BankPublication::Published {
                extent: BankExtent { first: 0, end: 1 },
                ..
            }
        ));
        first.extend_exact(duplicate).unwrap();
        let before = native.trace.len();
        assert_eq!(
            directory.stage_with(&mut native, &mut first, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Ownership)
        );
        assert_eq!(directory.legacy_published_mask().unwrap(), 1);
        assert_eq!(directory.allocated_high_water(), 1);
        assert_eq!(native.commits.len(), 1);
        assert!(!native.trace[before..].contains(&"allocate"));
        let (pins, retained) = native.provider_guard.as_ref().unwrap();
        first.slots[1].file_offset += 8;
        assert_eq!(
            validate_provider_slots(&first.slots, pins, 1, |index| {
                retained[index as usize].as_ref()
            }),
            Ok(()),
            "different offsets in the same provider remain different endpoints"
        );
    }

    fn reader_metadata(name: &str) -> Result<super::super::ExactMapMetadata, BankRefusal> {
        let (kind, key, value, entries, flags) = match name {
            "COUNTER_BANKS" => (MapType::HashOfMaps, 4, 4, 2, 128),
            "COUNTER_BANK_META" => (MapType::Hash, 4, 24, 2, 128),
            "COUNTER_BANK_COMMIT" => (MapType::Hash, 8, 16, 2, 128),
            "COUNTER_BANK_FAULT" => (MapType::PerCpuArray, 4, 8, 1, 0),
            "COUNTER_HEALTH" => (MapType::PerCpuArray, 4, 8, 2, 0),
            "STATS" => (MapType::PerCpuArray, 4, 24, 512, 0),
            "RV_COUNTS" => (MapType::PerCpuHash, 16, 8, 4096, 0),
            "START" => (MapType::Hash, 16, 288, 16384, 0),
            _ => {
                return Err(BankRefusal::Shape(
                    BankShapeCause::TestReaderMetadataUnknown,
                ));
            }
        };
        Ok(super::super::map_metadata(kind, key, value, entries, flags))
    }

    fn reader_banks(pool: &SemanticResourcePool) -> CounterBanks {
        CounterBanks {
            geometry: BankGeometry::legacy(),
            directory: Arc::new(Mutex::new(BankDirectory::default())),
            keepalive: CounterKeepalive::precharge(&pool.reserver(), 4096).unwrap(),
            cpus: 2,
            backend: super::super::AttachBackend::Singles,
            link_staging: Arc::new(AtomicU64::new(0)),
            terminal: None,
        }
    }

    pub(in crate::attach) fn growth_provider_fixture()
    -> (tempfile::TempDir, PinnedObjects, Slot, Slot, String) {
        use crate::discovery::identity::test_fixture::real_scan_pin;
        use sha2::Digest;
        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("first-provider.so");
        let second_path = dir.path().join("second-provider.so");
        let bytes = b"same owned provider bytes, distinct opened kernel files";
        std::fs::write(&first_path, bytes).unwrap();
        std::fs::write(&second_path, bytes).unwrap();
        let digest = p11scope_manifest::identity::hex(&sha2::Sha256::digest(bytes));
        let mut pins = real_scan_pin(&first_path, None, 1, &digest);
        let first_id = pins.pinned().next().unwrap().id;
        assert!(
            pins.absorb(real_scan_pin(&second_path, None, 2, &digest))
                .is_empty()
        );
        let second_id = pins
            .pinned()
            .map(|pin| pin.id)
            .find(|&id| id != first_id)
            .unwrap();
        let mut first = slot(0, 1);
        first.object = first_id;
        first.object_path = first_path.to_str().unwrap().into();
        let mut second = slot(1, 2);
        second.object = second_id;
        second.object_path = second_path.to_str().unwrap().into();
        (dir, pins, first, second, digest)
    }

    struct GrowthOwnedHistory {
        dir: tempfile::TempDir,
        history: AttachPlan,
        banks: CounterBanks,
        pool: SemanticResourcePool,
        digest: String,
    }

    fn growth_owned_history(last_slot: bool) -> GrowthOwnedHistory {
        growth_owned_history_for(CounterMode::Counts, last_slot)
    }

    fn growth_owned_history_for(mode: CounterMode, last_slot: bool) -> GrowthOwnedHistory {
        let (dir, pins, first, second, digest) = growth_provider_fixture();
        let pool = SemanticResourcePool::reference_limit(256 * 1024 * 1024);
        let geometry = BankGeometry::checked(mode, 16, 512).unwrap();
        let keepalive =
            CounterKeepalive::precharge_with_geometry(&pool.reserver(), 16 * 1024 * 1024, geometry)
                .unwrap();
        let policy = crate::plan::AdmissionPolicy::counters(
            crate::capacity::CounterBudget::new(8192).unwrap(),
        );
        let mut history = AttachPlan::from_slots_with_policy(vec![first.clone()], policy).unwrap();
        let mut directory = BankDirectory::growth_v2_for(mode);
        let mut io = GrowthIo::new(&pool);
        io.target_store = Some(&pins);
        io.provider_owner = Some(&keepalive.custody);
        let envelope = BankReservation {
            retained_bytes: 32 * 1024 * 1024,
            transient_bytes: 64 * 1024 * 1024,
            metadata_bytes: 8 * 1024 * 1024,
            file_descriptors: 131_072,
        };
        assert!(matches!(
            directory.stage_with(&mut io, &mut history, envelope, &pool.reserver()),
            BankPublication::Published { transaction: 1, .. }
        ));
        let mut candidate = vec![first.clone()];
        for index in 1..if last_slot { 8191 } else { 2 } {
            let mut addition = second.clone();
            addition.index = index;
            addition.file_offset = 0x80 + 16 * u64::from(index - 1);
            candidate.push(addition);
        }
        history
            .extend_exact(AttachPlan::from_slots_with_policy(candidate, policy).unwrap())
            .unwrap();
        io.next_stage();
        if last_slot {
            // Burn a real Directory extent before the first new map can be
            // created. This is a host model, not 8192 native attachments.
            io.failure = Some("allocate");
        } else {
            io.commit_absent = true;
        }
        assert!(matches!(
            directory.stage_with(&mut io, &mut history, envelope, &pool.reserver()),
            BankPublication::RolledBack { transaction: 2, .. }
        ));
        io.next_stage();
        io.failure = None;
        io.commit_absent = false;
        history
            .extend_exact(AttachPlan::from_slots_with_policy(vec![first, second], policy).unwrap())
            .unwrap();
        assert!(matches!(
            directory.stage_with(&mut io, &mut history, envelope, &pool.reserver()),
            BankPublication::Published { transaction: 3, .. }
        ));
        history.deactivate(0);
        let last = if last_slot { 8191 } else { 2 };
        assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0, last]);
        assert_eq!(history.counter_consumed_end(), last + 1);
        drop(io);
        GrowthOwnedHistory {
            dir,
            history,
            banks: CounterBanks {
                geometry,
                directory: Arc::new(Mutex::new(directory)),
                keepalive,
                cpus: 2,
                backend: super::super::AttachBackend::Singles,
                link_staging: Arc::new(AtomicU64::new(0)),
                terminal: None,
            },
            pool,
            digest,
        }
    }

    /// Upper bound on the `BankReservation` one `stage_counter_banks` call
    /// charges, for harness envelopes. It runs the same `stage_requirements`
    /// (plus the Multi storage check inputs) rather than a second formula, so
    /// accounting changes move both sides together. Every input must dominate
    /// the matching production value at staging time:
    /// - `new_banks`: every bank the fresh extent spans (production counts only
    ///   the not-yet-allocated subset);
    /// - `old_capacity`: at least `positions.capacity()` (the directory replaces
    ///   its positions vector every stage with exactly the staged length);
    /// - `provider_copies`: at least the fresh slots'
    ///   `retained_target_copy_allocation_charge × 4` sum `NativeIo` charges;
    /// - `multi_links`: at least the session link length and capacity (Multi
    ///   attaches at most two leaves per endpoint and reserves exactly that).
    ///
    /// Slot copies use 16, the `NativeIo` charge, which dominates the directory
    /// precheck's 4. `all_slots` must cover `first..end`. Callers add headroom
    /// on top of the returned requirement.
    #[allow(clippy::too_many_arguments)] // Explicit mirror of stage_requirements' checked inputs plus the Multi extent.
    pub(crate) fn estimate_counter_stage_reservation(
        mode: CounterMode,
        banks: u32,
        cells: u32,
        all_slots: &[Slot],
        first: u32,
        end: u32,
        old_capacity: usize,
        cpus: usize,
        new_banks: usize,
        provider_copies: usize,
        multi_links: Option<(usize, usize)>,
    ) -> Result<BankReservation, BankRefusal> {
        let geometry = BankGeometry::checked(mode, banks, cells)?;
        let fresh = BankExtent::checked(first, end, geometry.limit())?;
        let base = stage_requirements(
            geometry,
            all_slots,
            fresh,
            old_capacity,
            cpus,
            new_banks,
            provider_copies,
            16,
        )?;
        let (retained, transient, metadata) = match multi_links {
            None => (base.0, base.1, base.2),
            Some((old_link_len, old_link_capacity)) => {
                let extra = counter_multi_requirements(
                    &all_slots[first as usize..end as usize],
                    old_link_len,
                    old_link_capacity,
                )?;
                (
                    base.0.checked_add(extra.0).ok_or(BankRefusal::Budget)?,
                    base.1.checked_add(extra.1).ok_or(BankRefusal::Budget)?,
                    base.2.checked_add(extra.2).ok_or(BankRefusal::Budget)?,
                )
            }
        };
        Ok(BankReservation {
            retained_bytes: retained,
            transient_bytes: transient,
            metadata_bytes: metadata,
            file_descriptors: base.3,
        })
    }

    /// Actual Directory publication/rollback and real retained files supply
    /// the charged selection. Only map/link I/O above it is replaced.
    pub(crate) fn growth_snapshot_fixture(
        last_slot: bool,
    ) -> (
        tempfile::TempDir,
        AttachPlan,
        super::CounterPublishedSnapshot,
        SemanticResourcePool,
    ) {
        growth_snapshot_fixture_for(CounterMode::Counts, last_slot)
    }

    /// The same charged selection for a timing preparation. The publication
    /// shape is mode-independent; only the geometry word differs.
    pub(crate) fn growth_snapshot_fixture_for(
        mode: CounterMode,
        last_slot: bool,
    ) -> (
        tempfile::TempDir,
        AttachPlan,
        super::CounterPublishedSnapshot,
        SemanticResourcePool,
    ) {
        let owned = growth_owned_history_for(mode, last_slot);
        let snapshot = owned
            .banks
            .published_snapshot(
                &owned.history,
                &PinnedObjects::empty(),
                &owned.pool.reserver(),
            )
            .unwrap();
        (owned.dir, owned.history, snapshot, owned.pool)
    }

    #[test]
    fn format2_fd_headroom_preflight_preserves_existing_publication() {
        for (label, required, snapshot, refusal) in [
            (
                "finite exact fit",
                24,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Finite(124),
                    observed_open: 100,
                }),
                None,
            ),
            (
                "finite one short",
                24,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Finite(123),
                    observed_open: 100,
                }),
                Some(BankRefusal::BudgetExhausted {
                    resource: "file descriptors",
                    needed: 124,
                    available: 123,
                }),
            ),
            (
                "unreadable",
                24,
                Err(BankRefusal::Native),
                Some(BankRefusal::Native),
            ),
            (
                "finite overflow",
                24,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Finite(u64::MAX),
                    observed_open: u64::MAX - 23,
                }),
                Some(BankRefusal::Budget),
            ),
            (
                "unlimited healthy",
                24,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Unlimited,
                    observed_open: 100,
                }),
                None,
            ),
            (
                "unlimited overflow",
                24,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Unlimited,
                    observed_open: u64::MAX - 23,
                }),
                Some(BankRefusal::Budget),
            ),
            (
                "zero request",
                0,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Unlimited,
                    observed_open: 100,
                }),
                Some(BankRefusal::Budget),
            ),
        ] {
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let mut directory = BankDirectory::counts_growth_v2();
            let mut history = plan(1);
            let mut io = GrowthIo::new(&pool);
            assert!(matches!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Published { transaction: 1, .. }
            ));
            let old = io.routes[&0];
            history.extend_exact(plan(2)).unwrap();
            let slots = history.slots.clone();
            let charged = pool.snapshot().charged_bytes;
            io.next_stage();
            // An explicit 24-FD request isolates OS arithmetic from the caller's
            // 128-FD allowance. The actual fresh-extent calculation is covered
            // separately below; only OS headroom differs across these twins.
            io.fd_preflight = Some((required, snapshot));
            let result = directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver(),
            );
            assert_eq!(
                io.trace.iter().filter(|&&step| step == "fd-query").count(),
                usize::from(required != 0),
                "{label}"
            );
            if let Some(reason) = refusal {
                assert_eq!(result, BankPublication::Refused(reason), "{label}");
                assert_eq!(history.counter_consumed_end(), 1);
                assert_eq!(history.slots, slots);
                assert!(history.is_active(0) && history.is_active(1));
                assert_eq!(directory.allocated_high_water(), 1);
                assert_eq!(directory.next_transaction, NonZeroU64::new(2));
                assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
                assert!(!directory.quarantined);
                assert!(
                    io.trace
                        .iter()
                        .all(|step| matches!(*step, "validate" | "fd-query"))
                );
                assert_eq!(io.maps, BTreeMap::from([(0, 101)]));
                assert_eq!(io.outer, BTreeMap::from([(0, 101)]));
                assert_eq!(io.routes, BTreeMap::from([(0, old)]));
                assert_eq!(io.providers, BTreeSet::from([0]));
                assert_eq!(io.entries, BTreeSet::from([0]));
                assert_eq!(io.returns, BTreeSet::from([0]));
                assert_eq!(io.commits.len(), 1);
                assert_eq!(io.attempted, BTreeSet::from([1]));
                assert_eq!(io.held.len(), 1);
                assert_eq!(pool.snapshot().charged_bytes, charged);
            } else {
                assert_eq!(
                    result,
                    BankPublication::Published {
                        transaction: 2,
                        extent: BankExtent { first: 1, end: 2 }
                    },
                    "{label}"
                );
                assert_eq!(history.counter_consumed_end(), 2);
                assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0, 1]);
                assert_eq!(io.routes[&0], old);
                assert_eq!(io.held.len(), 2);
                assert_eq!(pool.snapshot().charged_bytes, charged + 1_114_112);
                let query = io
                    .trace
                    .iter()
                    .position(|&step| step == "fd-query")
                    .unwrap();
                let observe = io.trace.iter().position(|&step| step == "observe").unwrap();
                assert!(query < observe);
            }
        }
    }

    #[test]
    fn one_process_singles_8192_fd_admission_fits_existing_soft_limit() {
        let (_fixture, pins, first, _, _) = growth_provider_fixture();
        for cpus in [2, 12] {
            for caller_fds in [1_048_576, 65_536] {
                let pool = SemanticResourcePool::reference_limit(256 * 1024 * 1024);
                let mut directory = BankDirectory::counts_growth_v2();
                let mut history = AttachPlan::from_slots_with_policy(
                    (0..8192)
                        .map(|index| {
                            let mut selected = first.clone();
                            selected.index = index;
                            selected.file_offset = 0x1000 + 16 * u64::from(index);
                            selected
                        })
                        .collect(),
                    crate::plan::AdmissionPolicy::counters(
                        crate::capacity::CounterBudget::new(8192).unwrap(),
                    ),
                )
                .unwrap();
                let mut io = GrowthIo::new(&pool);
                io.cpus = cpus;
                io.target_store = Some(&pins);
                io.fd_stage_snapshot = Some(Ok(FdSnapshot {
                    soft_limit: FdLimit::Finite(65_536),
                    observed_open: 100,
                }));
                // A deliberate first-allocation refusal isolates admission;
                // this control creates no native links or 8192-row model maps.
                io.failure = Some("allocate");
                let charged = pool.snapshot().charged_bytes;
                let outcome = directory.stage_with(
                    &mut io,
                    &mut history,
                    BankReservation {
                        retained_bytes: 64 * 1024 * 1024,
                        transient_bytes: 64 * 1024 * 1024,
                        metadata_bytes: 16 * 1024 * 1024,
                        file_descriptors: caller_fds,
                    },
                    &pool.reserver(),
                );
                assert_eq!(
                    outcome,
                    BankPublication::RolledBack {
                        transaction: 1,
                        extent: BankExtent {
                            first: 0,
                            end: 8192
                        },
                        reason: BankRefusal::Native,
                    },
                    "OneProcess/Singles must admit the 8192-fresh/16-map FD demand under the existing 65536 soft limit; cpus={cpus}, caller_fds={caller_fds}, trace={:?}",
                    io.trace
                );
                assert_eq!(
                    io.trace,
                    [
                        "validate", "fd-query", "observe", "retain", "allocate", "observe"
                    ]
                );
                assert_eq!(
                    stage_requirements(
                        BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap(),
                        &history.slots,
                        BankExtent {
                            first: 0,
                            end: 8192
                        },
                        0,
                        cpus,
                        16,
                        0,
                        16,
                    )
                    .unwrap()
                    .3,
                    16_401,
                    "8192 fresh pairs +16 maps +one transient perf FD"
                );
                assert_eq!(history.counter_consumed_end(), 8192);
                assert!((0..8192).all(|index| !history.is_active(index)));
                assert_eq!(directory.allocated_high_water(), 8192);
                assert_eq!(directory.next_transaction, NonZeroU64::new(2));
                assert_eq!(directory.published_indices().count(), 0);
                assert!(!directory.quarantined);
                assert!(io.maps.is_empty() && io.outer.is_empty() && io.routes.is_empty());
                assert!(io.commits.is_empty() && io.entries.is_empty() && io.returns.is_empty());
                assert_eq!(io.held.len(), 1, "the attempted extent remains paid");
                assert_eq!(pool.snapshot().charged_bytes, charged + 80 * 1024 * 1024);
            }
        }
    }

    #[test]
    fn one_process_singles_fd_charge_uses_fresh_extent_and_shared_provider_fds() {
        use std::os::fd::AsRawFd;
        let (_fixture, pins, first, _, _) = growth_provider_fixture();
        let held = pins.retain_inventory_target(first.object).unwrap();
        let shared = held.share();
        let original_fd = pins.file_for(first.object).unwrap().as_raw_fd();
        assert_eq!(held.borrowed_file_and_digest().0.as_raw_fd(), original_fd);
        assert_eq!(shared.borrowed_file_and_digest().0.as_raw_fd(), original_fd);
        let provider_bytes = held.retained_copy_allocation_charge().unwrap() * 4;
        assert!(provider_bytes > 0);
        let slots: Vec<_> = (0..513)
            .map(|index| {
                let mut selected = first.clone();
                selected.index = index;
                selected.file_offset = 0x1000 + 16 * u64::from(index);
                selected
            })
            .collect();
        let geometry = BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap();
        let fresh = BankExtent {
            first: 512,
            end: 513,
        };
        let mut retained = Vec::new();
        for cpus in [2, 12] {
            let bare = stage_requirements(geometry, &slots, fresh, 512, cpus, 1, 0, 16).unwrap();
            let owned =
                stage_requirements(geometry, &slots, fresh, 512, cpus, 1, provider_bytes, 16)
                    .unwrap();
            assert_eq!(
                bare.3, 4,
                "one fresh pair, one new bank, one transient perf FD"
            );
            assert_eq!(owned.3, 4, "retained File owners share the original FD");
            assert_eq!(owned.0, bare.0 + provider_bytes);
            retained.push(bare.0);
        }
        assert_eq!(
            retained[1] - retained[0],
            122_880,
            "the full512-cell bank still charges 24 bytes across all additional possible CPUs"
        );
        assert_eq!(
            stage_requirements(geometry, &slots, fresh, 512, usize::MAX, 1, 0, 16),
            Err(BankRefusal::Budget),
            "CPU map-byte arithmetic must still refuse checked overflow"
        );
    }

    #[test]
    fn one_process_singles_fd_preflight_preserves_publication_at_headroom_boundary() {
        use std::os::fd::AsRawFd;
        for (label, caller_fds, snapshot, refusal) in [
            (
                "OS exact fit",
                128,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Finite(103),
                    observed_open: 100,
                }),
                None,
            ),
            (
                "caller exact fit",
                3,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Finite(103),
                    observed_open: 100,
                }),
                None,
            ),
            (
                "caller one short",
                2,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Finite(103),
                    observed_open: 100,
                }),
                Some(BankRefusal::Budget),
            ),
            (
                "OS one short",
                128,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Finite(102),
                    observed_open: 100,
                }),
                Some(BankRefusal::BudgetExhausted {
                    resource: "file descriptors",
                    needed: 103,
                    available: 102,
                }),
            ),
            (
                "unreadable",
                128,
                Err(BankRefusal::Native),
                Some(BankRefusal::Native),
            ),
            (
                "finite checked overflow",
                128,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Finite(u64::MAX),
                    observed_open: u64::MAX - 2,
                }),
                Some(BankRefusal::Budget),
            ),
            (
                "unlimited exact arithmetic fit",
                128,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Unlimited,
                    observed_open: u64::MAX - 3,
                }),
                None,
            ),
            (
                "unlimited checked overflow",
                128,
                Ok(FdSnapshot {
                    soft_limit: FdLimit::Unlimited,
                    observed_open: u64::MAX - 2,
                }),
                Some(BankRefusal::Budget),
            ),
        ] {
            let (_fixture, pins, first, second, _) = growth_provider_fixture();
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let keepalive = CounterKeepalive::precharge_with_geometry(
                &pool.reserver(),
                16 * 1024 * 1024,
                BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap(),
            )
            .unwrap();
            let policy = crate::plan::AdmissionPolicy::counters(
                crate::capacity::CounterBudget::new(8192).unwrap(),
            );
            let mut history =
                AttachPlan::from_slots_with_policy(vec![first.clone()], policy).unwrap();
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            io.target_store = Some(&pins);
            io.provider_owner = Some(&keepalive.custody);
            assert!(matches!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Published { transaction: 1, .. }
            ));
            let old = io.routes[&0];
            let old_fd = keepalive.custody.lock().unwrap().providers[0]
                .as_ref()
                .unwrap()
                .borrowed_file_and_digest()
                .0
                .as_raw_fd();
            history
                .extend_exact(
                    AttachPlan::from_slots_with_policy(vec![first, second], policy).unwrap(),
                )
                .unwrap();
            let before = history.slots.clone();
            let charged = pool.snapshot().charged_bytes;
            let mut envelope = growth_reservation();
            envelope.file_descriptors = caller_fds;
            io.next_stage();
            // Existing open descriptors already include the old pair, map and
            // pinned providers. Only this fresh pair + transient FD needs room.
            io.fd_stage_snapshot = Some(snapshot);
            let result = directory.stage_with(&mut io, &mut history, envelope, &pool.reserver());
            assert_eq!(
                io.trace.iter().filter(|&&step| step == "fd-query").count(),
                usize::from(caller_fds >= 3),
                "{label}"
            );
            assert_eq!(io.routes[&0], old, "{label}");
            assert_eq!(io.maps, BTreeMap::from([(0, 101)]));
            assert_eq!(io.outer, BTreeMap::from([(0, 101)]));
            assert!(!directory.quarantined);
            let custody = keepalive.custody.lock().unwrap();
            assert_eq!(
                custody.providers[0]
                    .as_ref()
                    .unwrap()
                    .borrowed_file_and_digest()
                    .0
                    .as_raw_fd(),
                old_fd
            );
            if let Some(reason) = refusal {
                assert_eq!(result, BankPublication::Refused(reason), "{label}");
                assert_eq!(history.counter_consumed_end(), 1);
                assert_eq!(history.slots, before);
                assert!(history.is_active(0) && history.is_active(1));
                assert_eq!(directory.allocated_high_water(), 1);
                assert_eq!(directory.next_transaction, NonZeroU64::new(2));
                assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
                assert!(
                    io.trace
                        .iter()
                        .all(|step| matches!(*step, "validate" | "fd-query"))
                );
                assert_eq!(io.routes, BTreeMap::from([(0, old)]));
                assert_eq!(io.providers, BTreeSet::from([0]));
                assert_eq!(io.entries, BTreeSet::from([0]));
                assert_eq!(io.returns, BTreeSet::from([0]));
                assert_eq!(
                    io.commits,
                    BTreeMap::from([(
                        1,
                        CountsBankCommit {
                            first: 0,
                            end: 1,
                            configuration: COUNTS_GROWTH_V2_CONFIG
                        }
                    )])
                );
                assert_eq!(io.attempted, BTreeSet::from([1]));
                assert_eq!(custody.charges.len(), 1);
                assert!(custody.providers[1].is_none());
                assert_eq!(pool.snapshot().charged_bytes, charged);
            } else {
                assert_eq!(
                    result,
                    BankPublication::Published {
                        transaction: 2,
                        extent: BankExtent { first: 1, end: 2 }
                    },
                    "{label}"
                );
                assert_eq!(history.counter_consumed_end(), 2);
                assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0, 1]);
                assert_eq!(custody.charges.len(), 2);
                assert!(custody.providers[1].is_some());
                assert_eq!(pool.snapshot().charged_bytes, charged + 1_114_112);
                let query = io
                    .trace
                    .iter()
                    .position(|&step| step == "fd-query")
                    .unwrap();
                let observe = io.trace.iter().position(|&step| step == "observe").unwrap();
                let retain = io.trace.iter().position(|&step| step == "retain").unwrap();
                assert!(query < observe && observe < retain);
            }
        }
    }

    #[test]
    fn fd_budget_refusal_names_resource_with_needed_and_available() {
        // Small-host shape: a 512-endpoint first stage charges 512 * 2 links
        // + 1 bank + 1 transient = 1026 FDs, which already exceeds a soft
        // RLIMIT_NOFILE of 1024 before counting observed-open FDs. The
        // refusal must name the resource and both numbers, in print and value.
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut history = plan(1);
        let mut io = GrowthIo::new(&pool);
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { transaction: 1, .. }
        ));
        history.extend_exact(plan(2)).unwrap();
        io.next_stage();
        io.fd_preflight = Some((
            1026,
            Ok(FdSnapshot {
                soft_limit: FdLimit::Finite(1024),
                observed_open: 40,
            }),
        ));
        let result = directory.stage_with(
            &mut io,
            &mut history,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(
            result,
            BankPublication::Refused(BankRefusal::BudgetExhausted {
                resource: "file descriptors",
                needed: 1066,
                available: 1024,
            })
        );
        let printed = format!("{result:?}");
        assert!(
            printed.contains("file descriptors")
                && printed.contains("1066")
                && printed.contains("1024"),
            "{printed}"
        );
    }

    #[test]
    fn counter_map_memory_table_reports_fixed_per_bank_and_ceiling() {
        use super::{
            COUNTER_MAP_MEMORY_LIMIT, check_counter_map_memory, counter_affordable_banks,
            counter_affordable_endpoints, counter_bank_map_bytes, counter_fixed_map_bytes,
        };
        let modes = [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ];
        let cpus_list = [1usize, 4, 12, 64, 128, 172, 256];
        println!("mode P fixed per_bank banks endpoints total");
        for mode in modes {
            for cpus in cpus_list {
                let fixed = counter_fixed_map_bytes(cpus).unwrap();
                let per_bank = counter_bank_map_bytes(mode, cpus).unwrap();
                let banks = counter_affordable_banks(mode, cpus).unwrap();
                let endpoints = counter_affordable_endpoints(mode, cpus).unwrap();
                assert_eq!(endpoints, banks * 512, "{mode:?} P={cpus}");
                assert!(banks <= 16, "{mode:?} P={cpus}: {banks} banks");
                let total = fixed
                    .checked_add(banks.checked_mul(per_bank).unwrap())
                    .unwrap();
                assert!(
                    total <= COUNTER_MAP_MEMORY_LIMIT,
                    "{mode:?} P={cpus}: {total} > {COUNTER_MAP_MEMORY_LIMIT}"
                );
                if banks < 16 {
                    let next = fixed
                        .checked_add((banks + 1).checked_mul(per_bank).unwrap())
                        .unwrap();
                    assert!(
                        next > COUNTER_MAP_MEMORY_LIMIT,
                        "{mode:?} P={cpus}: next {next} still fits"
                    );
                    let refusal = check_counter_map_memory(mode, cpus, banks + 1);
                    assert!(
                        matches!(
                            refusal,
                            Err(BankRefusal::BudgetExhausted {
                                resource: "counter-memory-limit",
                                ..
                            })
                        ),
                        "{mode:?} P={cpus}: {refusal:?}"
                    );
                }
                assert!(
                    check_counter_map_memory(mode, cpus, banks).is_ok(),
                    "{mode:?} P={cpus}: affordable {banks} banks must fit"
                );
                println!(
                    "{} {cpus} {fixed} {per_bank} {banks} {endpoints} {total}",
                    mode.name()
                );
            }
        }
    }

    #[test]
    fn counter_fixed_map_bytes_match_configured_payload() {
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") != "1" {
            return;
        }
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let embedded = super::counter_object_for_mode(mode);
            let object = aya_obj::Object::parse(embedded).unwrap();
            for cpus in [1usize, 12, 256] {
                let mut fixed = 0usize;
                for name in ["RV_COUNTS", "START", "STATS"] {
                    let map = object.maps.get(name).unwrap();
                    fixed = fixed
                        .checked_add(super::configured_payload(map, cpus).unwrap())
                        .unwrap();
                }
                assert_eq!(
                    super::counter_fixed_map_bytes(cpus).unwrap(),
                    fixed,
                    "{mode:?} P={cpus}: fixed must equal the configured payload"
                );
            }
            let stats = object.maps.get("STATS").unwrap();
            assert_eq!(stats.value_size(), 24, "{mode:?} aggregate template");
        }
    }

    #[test]
    fn counter_map_memory_preflight_names_mode_cpus_and_ceiling() {
        use super::{
            counter_affordable_endpoints, counter_bank_map_bytes, counter_fixed_map_bytes,
        };
        for (mode, cpus) in [
            (CounterMode::Counts, 256usize),
            (CounterMode::Timestamps, 256),
            (CounterMode::Latency, 256),
            (CounterMode::Latency, 12),
        ] {
            let fixed = counter_fixed_map_bytes(cpus).unwrap();
            let per_bank = counter_bank_map_bytes(mode, cpus).unwrap();
            let ceiling = counter_affordable_endpoints(mode, cpus).unwrap();
            assert!(
                super::check_counter_endpoints_fit(mode, cpus, ceiling).is_ok(),
                "{mode:?} P={cpus}: ceiling {ceiling} must fit"
            );
            if ceiling < 8192 {
                let refusal = super::check_counter_endpoints_fit(mode, cpus, ceiling + 1)
                    .expect_err("N+1 must refuse");
                for word in [
                    "counter-memory-limit",
                    mode.name(),
                    &cpus.to_string(),
                    &fixed.to_string(),
                    &per_bank.to_string(),
                    &ceiling.to_string(),
                ] {
                    assert!(
                        refusal.contains(word),
                        "{mode:?} P={cpus}: message names {word}: {refusal}"
                    );
                }
            }
        }
    }

    #[test]
    fn counter_memory_growth_to_ceiling_then_n_plus_one_refuses() {
        use super::{BankExtent, BankGeometry, counter_affordable_endpoints};
        let mode = CounterMode::Latency;
        let cpus = 256usize;
        let ceiling = counter_affordable_endpoints(mode, cpus).unwrap();
        assert!(
            ceiling > 512 && ceiling < 8192 && ceiling.is_multiple_of(512),
            "latency P=256 must have a partial ceiling, got {ceiling}"
        );
        let pool = SemanticResourcePool::reference_limit(1024 * 1024 * 1024);
        let mut directory = BankDirectory::growth_v2_for(mode);
        let mut history = plan(512);
        let mut io = GrowthIo::new(&pool);
        io.cpus = cpus;
        let envelope_for =
            |all: usize, first: u32, end: u32, old_capacity: usize, new_banks: usize| {
                let all_plan = plan(all as u32);
                estimate_counter_stage_reservation(
                    mode,
                    16,
                    512,
                    &all_plan.slots,
                    first,
                    end,
                    old_capacity,
                    cpus,
                    new_banks,
                    0,
                    None,
                )
                .unwrap()
            };
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                envelope_for(512, 0, 512, 0, 1),
                &pool.reserver()
            ),
            BankPublication::Published { extent, .. }
                if extent == BankExtent { first: 0, end: 512 }
        ));
        history.extend_exact(plan(ceiling as u32)).unwrap();
        io.next_stage();
        let banks_after_first = 1usize;
        let banks_after_second = ceiling / 512;
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                envelope_for(
                    ceiling,
                    512,
                    ceiling as u32,
                    512,
                    banks_after_second - banks_after_first
                ),
                &pool.reserver()
            ),
            BankPublication::Published { extent, .. }
                if extent == BankExtent { first: 512, end: ceiling as u32 }
        ));
        let published_before: Vec<u32> = directory.published_indices().collect();
        assert_eq!(published_before.len(), ceiling);
        history.extend_exact(plan(ceiling as u32 + 1)).unwrap();
        io.next_stage();
        let result = directory.stage_with(
            &mut io,
            &mut history,
            envelope_for(ceiling + 1, ceiling as u32, ceiling as u32 + 1, ceiling, 1),
            &pool.reserver(),
        );
        assert!(
            matches!(
                result,
                BankPublication::Refused(BankRefusal::BudgetExhausted {
                    resource: "counter-memory-limit",
                    ..
                })
            ),
            "N+1 must refuse the memory cap: {result:?}"
        );
        let published_after: Vec<u32> = directory.published_indices().collect();
        assert_eq!(
            published_after, published_before,
            "the published prefix stays intact"
        );
        assert_eq!(io.routes.len(), ceiling, "routes keep the prefix");
        assert_eq!(
            directory.allocated_high_water(),
            ceiling,
            "no hole consumes the refused extent"
        );
        let geometry = BankGeometry::checked(mode, 16, 512).unwrap();
        let _ = geometry;
    }

    #[test]
    fn counter_growth_cannot_consume_terminal_reserve() {
        use super::{
            counter_read_storage_bytes, counter_read_transient_bytes, counter_snapshot_bytes_for,
            counter_terminal_reserve_bytes,
        };
        let mode = CounterMode::Counts;
        let cpus = 2usize;
        let pool = SemanticResourcePool::reference_limit(45 * 1024 * 1024);
        let terminal = counter_terminal_reserve_bytes(mode, cpus).unwrap();
        assert!(
            terminal > 30 * 1024 * 1024,
            "the terminal hold must dominate: {terminal}"
        );
        let _hold = pool.reserver().reserve(terminal).unwrap();
        let mut directory = BankDirectory::growth_v2_for(mode);
        let mut history = plan(512);
        let mut io = GrowthIo::new(&pool);
        io.cpus = cpus;
        let first_plan = plan(512);
        let first_envelope = estimate_counter_stage_reservation(
            mode,
            16,
            512,
            &first_plan.slots,
            0,
            512,
            0,
            cpus,
            1,
            0,
            None,
        )
        .unwrap();
        assert!(matches!(
            directory.stage_with(&mut io, &mut history, first_envelope, &pool.reserver()),
            BankPublication::Published { extent, .. }
                if extent == BankExtent { first: 0, end: 512 }
        ));
        let second_plan = plan(1024);
        let second_need = estimate_counter_stage_reservation(
            mode,
            16,
            512,
            &second_plan.slots,
            512,
            1024,
            512,
            cpus,
            1,
            0,
            None,
        )
        .unwrap();
        let available = pool.snapshot().limit_bytes - pool.snapshot().charged_bytes;
        let second_charge =
            second_need.retained_bytes + second_need.metadata_bytes + second_need.transient_bytes;
        assert!(
            second_charge > available,
            "the second stage must need the reserve: {second_charge} > {available}"
        );
        history.extend_exact(plan(1024)).unwrap();
        io.next_stage();
        let result = directory.stage_with(&mut io, &mut history, second_need, &pool.reserver());
        assert_eq!(
            result,
            BankPublication::Refused(BankRefusal::Budget),
            "growth needing the reserve refuses Budget: {result:?}"
        );
        let published: Vec<u32> = directory.published_indices().collect();
        assert_eq!(published.len(), 512, "the published prefix stays intact");
        assert_eq!(io.routes.len(), 512, "routes keep the prefix");
        assert_eq!(directory.allocated_high_water(), 512);
        let small_transient = counter_read_transient_bytes(mode, cpus, 12, 8192, 512).unwrap();
        let small_storage = counter_read_storage_bytes(512, 12).unwrap();
        let small_snapshot = counter_snapshot_bytes_for(512, 512).unwrap();
        let fresh = small_transient + small_storage + small_snapshot;
        let available_after = pool.snapshot().limit_bytes - pool.snapshot().charged_bytes;
        assert!(
            fresh <= available_after,
            "the terminal fresh must fit: {fresh} <= {available_after}"
        );
        pool.reserver().reserve(fresh).unwrap();
    }

    #[test]
    fn counter_budgets_pin_each_field_against_scripted_session() {
        let owned = growth_owned_history(false);
        assert_eq!(
            owned
                .banks
                .directory
                .lock()
                .unwrap()
                .published_indices()
                .collect::<Vec<_>>(),
            [0, 2]
        );
        let budgets = owned.banks.budgets(5).unwrap();
        assert_eq!(budgets.endpoints.published, 2);
        assert_eq!(budgets.endpoints.holes, 1);
        assert_eq!(budgets.endpoints.ceiling, 8192);
        assert_eq!(budgets.rv_keys.used, 5);
        assert_eq!(budgets.rv_keys.limit, 65536);
        assert_eq!(budgets.start.limit, 16384);
        assert_eq!(budgets.fd.projected, 6);
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        if limit.rlim_cur == libc::RLIM_INFINITY {
            assert_eq!(budgets.fd.soft, None);
        } else {
            assert_eq!(budgets.fd.soft, Some(limit.rlim_cur));
        }
        let fixed = super::counter_fixed_map_bytes(2).unwrap();
        let per_bank = super::counter_bank_map_bytes(CounterMode::Counts, 2).unwrap();
        assert_eq!(budgets.memory.charged, fixed + per_bank);
        assert_eq!(budgets.memory.limit, super::COUNTER_MAP_MEMORY_LIMIT);
    }

    #[test]
    fn counter_bank_multi_storage_remains_paid_after_clean_rollback() {
        use super::super::RegisteredLink;
        for short in [None, Some(0), Some(1), Some(2)] {
            let (_fixture, pins, first, second, _) = growth_provider_fixture();
            let pool = SemanticResourcePool::reference_limit(256 * 1024 * 1024);
            let initial = pool.snapshot().charged_bytes;
            let geometry = BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap();
            let keepalive = CounterKeepalive::precharge_with_geometry(
                &pool.reserver(),
                16 * 1024 * 1024,
                geometry,
            )
            .unwrap();
            let mut links: Vec<RegisteredLink> =
                ["p11_counter_bank_return", "p11_counter_bank_entry"]
                    .into_iter()
                    .map(|program| RegisteredLink::MultiUProbe {
                        program,
                        slots: vec![0],
                        fds: vec![tempfile::tempfile().unwrap().into()],
                        registration: None,
                    })
                    .collect::<Box<[_]>>()
                    .into_vec();
            let original_fds: Vec<_> = links
                .iter()
                .flat_map(|link| match link {
                    RegisteredLink::MultiUProbe { fds, .. } => {
                        fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>()
                    }
                    _ => unreachable!(),
                })
                .collect();
            let old_capacity = links.capacity();
            let policy = crate::plan::AdmissionPolicy::counters(
                crate::capacity::CounterBudget::new(8192).unwrap(),
            );
            let mut history =
                AttachPlan::from_slots_with_policy(vec![first.clone()], policy).unwrap();
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            io.target_store = Some(&pins);
            io.provider_owner = Some(&keepalive.custody);
            assert!(matches!(
                directory.stage_with(
                    &mut io,
                    &mut history,
                    growth_reservation(),
                    &pool.reserver()
                ),
                BankPublication::Published { transaction: 1, .. }
            ));
            let old = io.routes[&0];
            history
                .extend_exact(
                    AttachPlan::from_slots_with_policy(vec![first, second], policy).unwrap(),
                )
                .unwrap();
            let fresh = BankExtent { first: 1, end: 2 };
            let fresh_slots = &history.slots[1..];
            let provider_bytes = pins
                .retained_target_copy_allocation_charge(fresh_slots[0].object)
                .unwrap()
                .checked_mul(4)
                .unwrap();
            let base = stage_requirements(
                geometry,
                &history.slots,
                fresh,
                directory.positions.capacity(),
                2,
                0,
                provider_bytes,
                16,
            )
            .unwrap();
            let extra: (usize, usize, usize) =
                counter_multi_requirements(fresh_slots, links.len(), links.capacity()).unwrap();
            assert!(extra.0 > 0 && extra.1 > 0 && extra.2 > 0);
            if short.is_none() {
                let large_slots: Vec<_> = (0..8192)
                    .map(|index| {
                        let mut slot = fresh_slots[0].clone();
                        slot.index = index;
                        slot.file_offset = 0x1000 + 16 * u64::from(index);
                        slot
                    })
                    .collect();
                let large: (usize, usize, usize) =
                    counter_multi_requirements(&large_slots, 0, 0).unwrap();
                assert!(
                    large.0.checked_add(large.2).unwrap()
                        >= 16_384
                            * (size_of::<RegisteredLink>()
                                + size_of::<u32>()
                                + size_of::<std::os::fd::OwnedFd>()
                                + 2 * OWNED_ALLOCATION_PADDING),
                    "8192 worst-bisect pairs must pay all retained leaf headers/member/FD backing"
                );
                assert!(
                    large.1 >= 8192 * (2 * size_of::<(u64, u64)>() + 2 * size_of::<usize>()),
                    "return/entry sites and overlapping bisect indices need real transient backing"
                );
                let mut wide = fresh_slots.to_vec();
                wide[0].names[0].reserve(4096);
                let extra_name = wide[0].names[0].capacity() - fresh_slots[0].names[0].capacity();
                let wide_charge: (usize, usize, usize) =
                    counter_multi_requirements(&wide, links.len(), links.capacity()).unwrap();
                assert!(
                    wide_charge.1 >= extra.1 + extra_name,
                    "a cloned group member must charge its deep name backing"
                );
            }
            assert!(
                extra.0 + extra.2
                    >= 4 * size_of::<RegisteredLink>()
                        + 2 * (size_of::<u32>() + size_of::<std::os::fd::OwnedFd>())
                        + 4 * OWNED_ALLOCATION_PADDING,
                "new registry backing and both possible leaf member/FD vectors need retained payment"
            );
            assert!(
                extra.1 >= old_capacity * size_of::<RegisteredLink>(),
                "old/new backing overlap must remain paid"
            );
            let overflow: Result<(usize, usize, usize), BankRefusal> =
                counter_multi_requirements(fresh_slots, usize::MAX, usize::MAX);
            assert_eq!(overflow, Err(BankRefusal::Budget));
            let mut envelope = BankReservation {
                retained_bytes: base.0.checked_add(extra.0).unwrap(),
                transient_bytes: base.1.checked_add(extra.1).unwrap(),
                metadata_bytes: base.2.checked_add(extra.2).unwrap(),
                file_descriptors: base.3,
            };
            match short {
                Some(0) => envelope.retained_bytes -= 1,
                Some(1) => envelope.transient_bytes -= 1,
                Some(2) => envelope.metadata_bytes -= 1,
                None => {}
                _ => unreachable!(),
            }
            let charged = pool.snapshot().charged_bytes;
            io.next_stage();
            io.failure = Some("entry");
            io.counter_multi_storage = Some((&mut links, envelope));
            let result = directory.stage_with(&mut io, &mut history, envelope, &pool.reserver());
            if short.is_some() {
                assert_eq!(result, BankPublication::Refused(BankRefusal::Budget));
                assert!(io.trace.iter().all(|step| *step == "validate"));
                assert_eq!(history.counter_consumed_end(), 1);
                assert!(history.is_active(1));
                assert_eq!(directory.allocated_high_water(), 1);
                assert_eq!(directory.next_transaction, NonZeroU64::new(2));
                assert_eq!(keepalive.custody.lock().unwrap().charges.len(), 1);
                assert_eq!(pool.snapshot().charged_bytes, charged);
            } else {
                assert_eq!(
                    result,
                    BankPublication::RolledBack {
                        transaction: 2,
                        extent: fresh,
                        reason: BankRefusal::Links
                    }
                );
                assert_eq!(history.counter_consumed_end(), 2);
                assert!(!history.is_active(1));
                assert_eq!(directory.next_transaction, NonZeroU64::new(3));
                assert_eq!(keepalive.custody.lock().unwrap().charges.len(), 2);
                assert_eq!(
                    pool.snapshot().charged_bytes,
                    charged + envelope.charges().unwrap().0,
                    "clean rollback refunds scratch, never the retained extent lease paying registry backing"
                );
            }
            assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
            assert_eq!(io.routes, BTreeMap::from([(0, old)]));
            assert_eq!(io.entries, BTreeSet::from([0]));
            assert_eq!(io.returns, BTreeSet::from([0]));
            drop(io);
            assert_eq!(links.len(), 2);
            if short.is_some() {
                assert_eq!(links.capacity(), old_capacity);
            } else {
                assert!(links.capacity() >= 4 && links.capacity() > old_capacity);
            }
            assert!(
                original_fds
                    .iter()
                    .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
            );
            drop(links);
            assert!(
                pool.snapshot().charged_bytes > initial,
                "releasing registry storage alone cannot refund retained history"
            );
            drop(keepalive);
            assert_eq!(pool.snapshot().charged_bytes, initial);
        }
    }

    #[test]
    fn counter_bank_explicit_backend_is_fixed_before_loading() {
        use super::super::{AttachBackend, BackendSelection, RegisteredLink};
        // API pins: a requested backend creates a NEW Session; no existing
        // Session or setter participates. The old constructor remains Singles.
        let _: fn(&Scope, &[u8], BankReservation, &SemanticResourceReserver) -> Result<Session> =
            Session::prepare_counter_banks;
        let _: fn(
            &Scope,
            &[u8],
            BankReservation,
            &SemanticResourceReserver,
            AttachBackend,
        ) -> Result<Session> = Session::prepare_counter_banks_with_backend;
        let _load_for_backend =
            |preparation: &CounterPreparation<'_>, ebpf: &mut Ebpf, backend: AttachBackend| {
                preparation.validate_and_load(ebpf, backend)
            };
        let singles = super::super::select_session_backend(
            BackendSelection::Singles,
            true,
            || panic!("Singles must not probe Multi"),
            || panic!("Singles must not probe the Multi PID filter"),
        )
        .unwrap();
        assert_eq!(singles.backend, AttachBackend::Singles);
        let refused = super::super::select_session_backend(
            BackendSelection::Multi,
            true,
            || panic!("PID scope uses its PID gate"),
            || Err("actual PID-filter gate refused".into()),
        );
        assert!(
            refused.is_err(),
            "forced Multi cannot silently select Singles"
        );
        let activated = std::cell::Cell::new(false);
        let refusal_before_activation =
            super::super::activate_after_preparation_with(refused.map(|_| ()), || {
                activated.set(true);
                Ok(())
            });
        assert!(refusal_before_activation.is_err() && !activated.get());
        let selected = super::super::select_session_backend(
            BackendSelection::Multi,
            true,
            || panic!("PID scope uses its PID gate"),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(selected.backend, AttachBackend::Multi);
        assert!(selected.fallback.is_none());
        for backend in [AttachBackend::Singles, AttachBackend::Multi] {
            let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
            let geometry = BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap();
            let banks = CounterBanks {
                directory: Arc::new(Mutex::new(BankDirectory::counts_growth_v2())),
                keepalive: CounterKeepalive::precharge_with_geometry(
                    &pool.reserver(),
                    16 * 1024 * 1024,
                    geometry,
                )
                .unwrap(),
                cpus: 2,
                geometry,
                link_staging: Arc::new(AtomicU64::new(0)),
                terminal: None,
                backend,
            };
            let foreign = if backend == AttachBackend::Singles {
                AttachBackend::Multi
            } else {
                AttachBackend::Singles
            };
            assert_eq!(banks.backend, backend);
            let validate_backend =
                |value: AttachBackend| -> Result<(), BankRefusal> { banks.validate_backend(value) };
            let validate_unlinked =
                |value: AttachBackend, links: &[RegisteredLink]| -> Result<(), BankRefusal> {
                    banks.validate_unlinked_backend(value, links)
                };
            assert_eq!(validate_backend(backend), Ok(()));
            assert_eq!(validate_backend(foreign), Err(BankRefusal::Topology));
            assert_eq!(validate_unlinked(backend, &[]), Ok(()));
            assert_eq!(validate_unlinked(foreign, &[]), Err(BankRefusal::Topology));
            let links = vec![RegisteredLink::MultiUProbe {
                program: "p11_counter_bank_entry",
                slots: vec![0],
                fds: vec![tempfile::tempfile().unwrap().into()],
                registration: None,
            }];
            assert_eq!(
                validate_unlinked(backend, &links),
                Err(BankRefusal::Allocated),
                "constructor admission cannot reuse an active registry"
            );
            let activated = std::cell::Cell::new(false);
            let active_owner =
                validate_unlinked(backend, &links).map_err(|reason| anyhow::anyhow!("{reason:?}"));
            let refused = super::super::activate_after_preparation_with(active_owner, || {
                activated.set(true);
                Ok(())
            });
            assert!(refused.is_err() && !activated.get());
            assert_eq!(
                validate_backend(backend),
                Ok(()),
                "ordinary later appends keep their healthy old links"
            );
            assert!(super::super::loads_with_multi_flag(
                AttachBackend::Multi,
                "p11_counter_bank_entry"
            ));
            assert!(super::super::loads_with_multi_flag(
                AttachBackend::Multi,
                "p11_counter_bank_return"
            ));
            assert!(!super::super::loads_with_multi_flag(
                AttachBackend::Singles,
                "p11_counter_bank_entry"
            ));
            assert!(!super::super::loads_with_multi_flag(
                AttachBackend::Singles,
                "p11_counter_bank_return"
            ));
        }
    }

    #[test]
    fn format2_charge_holders_cover_8192_nonempty_extents() {
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let charged = pool.snapshot().charged_bytes;
        let geometry = BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap();
        assert!(
            CounterKeepalive::precharge_with_geometry(&pool.reserver(), 32 * 1024, geometry)
                .is_err(),
            "even 8192 lease holders alone exceed this request; reject before allocation"
        );
        assert_eq!(pool.snapshot().charged_bytes, charged);
        let held =
            CounterKeepalive::precharge_with_geometry(&pool.reserver(), 16 * 1024 * 1024, geometry)
                .unwrap();
        let baseline = pool.snapshot().charged_bytes;
        {
            let mut custody = held.custody.lock().unwrap();
            assert!(custody.charges.capacity() >= 8192);
            assert!(custody.providers.capacity() >= 8192);
            let storage = custody.charges.as_ptr();
            for transaction in 1..=8192 {
                custody.retain_charge(pool.reserver().reserve(1).unwrap());
                assert_eq!(
                    custody.charges.as_ptr(),
                    storage,
                    "handoff {transaction} allocated after the floor"
                );
                assert_eq!(custody.charges.len(), transaction);
                assert_eq!(pool.snapshot().charged_bytes, baseline + transaction);
            }
        }
        assert_eq!(
            pool.snapshot().charged_bytes,
            charged + 16 * 1024 * 1024 + 8192
        );
        drop(held);
        assert_eq!(pool.snapshot().charged_bytes, charged);
    }

    #[test]
    fn format2_partial_bank_retains_each_provider() {
        let (_dir, pins, first, second, digest) = growth_provider_fixture();
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let owner = CounterKeepalive::precharge_with_geometry(
            &pool.reserver(),
            16 * 1024 * 1024,
            BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap(),
        )
        .unwrap();
        let policy = crate::plan::AdmissionPolicy::counters(
            crate::capacity::CounterBudget::new(8192).unwrap(),
        );
        let mut history = AttachPlan::from_slots_with_policy(vec![first.clone()], policy).unwrap();
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        io.target_store = Some(&pins);
        io.provider_owner = Some(&owner.custody);
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { transaction: 1, .. }
        ));
        history
            .extend_exact(
                AttachPlan::from_slots_with_policy(vec![first.clone(), second.clone()], policy)
                    .unwrap(),
            )
            .unwrap();
        io.next_stage();
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { transaction: 2, .. }
        ));
        assert!(
            !io.trace.contains(&"allocate"),
            "new provider shares the already allocated bank"
        );
        assert_eq!(
            (
                io.routes[&1].bank,
                io.routes[&1].cell,
                io.routes[&1].inner_id
            ),
            (0, 1, 101)
        );
        let provider = io
            .trace
            .iter()
            .position(|&step| step == "retain-provider")
            .unwrap();
        let first_link = io.trace.iter().position(|&step| step == "return").unwrap();
        assert!(provider < first_link);
        let mut custody = owner.custody.lock().unwrap();
        assert_eq!(custody.charges.len(), 2);
        for target in [&first, &second] {
            let retained = custody.providers[target.index as usize].as_ref().unwrap();
            assert_eq!(retained.abi(), p11scope_manifest::elf::ElfAbi::Lp64);
            assert_eq!(retained.check_unchanged(), Ok(true));
            assert!(retained.same_object_as(&pins, target.object));
            let (file, sha256) = retained.borrowed_file_and_digest();
            assert!(std::ptr::eq(file, pins.file_for(target.object).unwrap()));
            assert_eq!(sha256, digest);
        }
        let mut foreign = first;
        foreign.object = second.object;
        assert_eq!(
            custody.retain_targets(&[foreign], &pins),
            Err(BankRefusal::Ownership)
        );
        assert!(
            custody.providers[0]
                .as_ref()
                .unwrap()
                .same_object_as(&pins, history.slots[0].object)
        );
    }

    #[test]
    fn format2_view_preserves_holes_and_retained_identity() {
        use crate::discovery::identity::test_fixture::real_scan_pin;
        let owned = growth_owned_history(false);
        let empty = PinnedObjects::empty();
        let snapshot = owned
            .banks
            .published_snapshot(&owned.history, &empty, &owned.pool.reserver())
            .unwrap();
        assert_eq!(snapshot.original_indices(), [0, 2]);
        assert_eq!(snapshot.validate_plan(&owned.history), Ok(()));
        assert!(
            !owned.history.is_active(0)
                && !owned.history.is_active(1)
                && owned.history.is_active(2)
        );
        assert!(
            owned.banks.keepalive.custody.lock().unwrap().providers[1].is_some(),
            "the omitted hole deliberately has retained identity; only Directory authority omits it"
        );
        for index in [0, 2] {
            let proof = owned.banks.keepalive.custody.lock().unwrap().providers[index].take();
            assert!(proof.is_some());
            assert_eq!(
                snapshot.validate_plan(&owned.history),
                Err(BankRefusal::Ownership)
            );
            assert!(
                matches!(
                    owned
                        .banks
                        .published_snapshot(&owned.history, &empty, &owned.pool.reserver()),
                    Err(BankRefusal::Ownership)
                ),
                "missing published proof {index} must not prune the row"
            );
            owned.banks.keepalive.custody.lock().unwrap().providers[index] = proof;
        }
        let hole = owned.banks.keepalive.custody.lock().unwrap().providers[1].take();
        assert!(hole.is_some());
        assert_eq!(
            owned
                .banks
                .published_snapshot(&owned.history, &empty, &owned.pool.reserver())
                .unwrap()
                .original_indices(),
            [0, 2]
        );
        let first_path = owned.dir.path().join("first-provider.so");
        let same = real_scan_pin(&first_path, None, 20, &owned.digest);
        assert_eq!(
            owned
                .banks
                .published_snapshot(&owned.history, &same, &owned.pool.reserver())
                .unwrap()
                .original_indices(),
            [0, 2]
        );
        let foreign_path = owned.dir.path().join("foreign-provider.so");
        std::fs::copy(&first_path, &foreign_path).unwrap();
        let foreign = real_scan_pin(&foreign_path, None, 21, &owned.digest);
        assert!(
            matches!(
                owned
                    .banks
                    .published_snapshot(&owned.history, &foreign, &owned.pool.reserver()),
                Err(BankRefusal::Ownership)
            ),
            "present foreign ID 0 must never use missing-pin fallback"
        );
        let mut relabelled = owned.history.clone();
        relabelled.slots[0].object = PinnedObjectId(u32::MAX);
        assert_eq!(
            snapshot.validate_plan(&relabelled),
            Err(BankRefusal::Topology)
        );
        let refused = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH);
        assert!(matches!(
            owned
                .banks
                .published_snapshot(&owned.history, &empty, &refused.reserver()),
            Err(BankRefusal::Budget)
        ));
        assert_eq!(
            refused.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH
        );
        std::fs::write(first_path, b"changed retained provider").unwrap();
        assert_eq!(
            snapshot.validate_plan(&owned.history),
            Err(BankRefusal::Ownership)
        );
        assert!(
            matches!(
                owned
                    .banks
                    .published_snapshot(&owned.history, &empty, &owned.pool.reserver()),
                Err(BankRefusal::Ownership)
            ),
            "retained FD mutation cannot become historical success"
        );
    }

    #[test]
    #[ignore = "requires the explicitly selected format2 artifact; parses only, no native load"]
    fn format2_preparation_rejects_mixed_profiles_before_lifecycle() {
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"), "1");
        assert_eq!(
            env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
        );
        let path = std::path::Path::new(env!("OUT_DIR"))
            .join("counter-bank-growth-v2")
            .join("p11scope-ebpf-counts-bank-growth-v2");
        let bytes = std::fs::read(path).expect("compile the actual selected format2 artifact");
        let parsed = aya_obj::Object::parse(&bytes).unwrap();
        for (name, expected) in [
            ("COUNTER_BANKS", (13, 4, 4, 16, 128)),
            ("COUNTER_BANK_META", (1, 4, 32, 8192, 128)),
            ("COUNTER_BANK_COMMIT", (1, 8, 16, 8192, 128)),
            ("RV_COUNTS", (5, 16, 8, 65536, 0)),
            ("SLOT_FILE", (2, 4, 4, 8192, 128)),
            ("STATS", (6, 4, 24, 512, 0)),
            ("START", (1, 16, 288, 16384, 0)),
        ] {
            let map = parsed.maps.get(name).expect("actual required format2 map");
            assert_eq!(
                (
                    map.map_type(),
                    map.key_size(),
                    map.value_size(),
                    map.max_entries(),
                    map.map_flags()
                ),
                expected,
                "actual emitted {name}"
            );
        }
        let inner = parsed.maps["COUNTER_BANKS"].inner().unwrap();
        assert_eq!(
            (
                inner.map_type(),
                inner.key_size(),
                inner.value_size(),
                inner.max_entries(),
                inner.map_flags()
            ),
            (6, 4, 24, 512, 0)
        );
        drop(parsed);
        // These are explicit request ceilings, not allocations of a GiB or
        // evidence that any native map/program has loaded successfully.
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024 * 1024);
        let envelope = BankReservation {
            retained_bytes: 1024 * 1024 * 1024,
            transient_bytes: 512 * 1024 * 1024,
            metadata_bytes: 64 * 1024 * 1024,
            file_descriptors: 1_048_576,
        };
        let preparation = CounterPreparation::new(&bytes, envelope, &pool.reserver());
        assert!(
            preparation.is_ok(),
            "actual valid format2 preparation: {:?}",
            preparation.err()
        );
        // Ordinary bytes and malformed bytes must fail at the same real
        // constructor before the actual constructor's lifecycle boundary.
        for wrong in [crate::EBPF_OBJECT, &b"not an ELF object"[..]] {
            let charged = pool.snapshot().charged_bytes;
            let activated = std::cell::Cell::new(false);
            let preparation = CounterPreparation::new(wrong, envelope, &pool.reserver());
            let result =
                super::super::activate_after_preparation_with(preparation.map(|_| ()), || {
                    activated.set(true);
                    Ok(())
                });
            assert!(result.is_err());
            assert!(
                !activated.get(),
                "wrong actual shape must never reach lifecycle attachment"
            );
            assert_eq!(pool.snapshot().charged_bytes, charged);
        }
    }

    #[test]
    #[ignore = "requires the explicitly selected format2 artifact; parses only, no native load"]
    fn format2_preparation_charges_custody_and_payload_together() {
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"), "1");
        assert_eq!(
            env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
        );
        let bytes = std::fs::read(
            std::path::Path::new(env!("OUT_DIR"))
                .join("counter-bank-growth-v2/p11scope-ebpf-counts-bank-growth-v2"),
        )
        .unwrap();
        let parsed = aya_obj::Object::parse(&bytes).unwrap();
        let cpus = aya::util::nr_cpus().unwrap();
        let payload = parsed
            .maps
            .values()
            .try_fold(0usize, |total, map| {
                total.checked_add(configured_payload(map, cpus)?)
            })
            .unwrap();
        let old_floor = payload
            + size_of::<CounterBanks>()
            + size_of::<CounterKeepalive>()
            + size_of::<Session>()
            + 16 * OWNED_ALLOCATION_PADDING;
        // This actual object needs 8192 provider holders AND 8192 consumed
        // extent leases, alongside every configured map. The old floor already
        // includes CounterKeepalive inline; count only its backing/Arc here.
        let combined_floor = old_floor
            + 8192 * (size_of::<Option<RetainedInventoryTarget>>() + size_of::<ResourceLease>())
            + 2 * size_of::<usize>()
            + 3 * OWNED_ALLOCATION_PADDING;
        let transient = bytes.len().checked_mul(32).unwrap();
        drop(parsed);
        for (one_short, healthy) in [(0, true), (1, false)] {
            let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024 * 1024);
            let baseline = pool.snapshot().charged_bytes;
            let envelope = BankReservation {
                retained_bytes: combined_floor - 1 - one_short,
                transient_bytes: transient,
                metadata_bytes: 1,
                file_descriptors: 1_048_576,
            };
            assert!(
                envelope.retained_bytes >= old_floor,
                "both twins satisfy the old payload-only minimum"
            );
            let preparation = CounterPreparation::new(&bytes, envelope, &pool.reserver());
            if healthy {
                assert!(
                    preparation.is_ok(),
                    "exact combined fit: {:?}",
                    preparation.as_ref().err()
                );
                assert_eq!(
                    pool.snapshot().charged_bytes,
                    baseline + combined_floor + transient
                );
            } else {
                assert!(
                    preparation.is_err(),
                    "one byte short cannot independently spend one charge on maps and custody"
                );
                assert_eq!(pool.snapshot().charged_bytes, baseline);
            }
            drop(preparation);
            assert_eq!(pool.snapshot().charged_bytes, baseline);
        }
    }

    #[test]
    fn bank_mode_artifacts_select_exactly_three_growth_v2_modes() {
        for (token, object, value_bytes, configuration) in [
            (
                "counts-bank-growth-v2",
                "p11scope-ebpf-counts-bank-growth-v2",
                24u32,
                0x0200_0018_0010_0200u64,
            ),
            (
                "timestamps-bank-growth-v2",
                "p11scope-ebpf-timestamps-bank-growth-v2",
                40u32,
                0x0200_0028_0010_0200u64,
            ),
            (
                "latency-bank-growth-v2",
                "p11scope-ebpf-latency-bank-growth-v2",
                296u32,
                0x0200_0128_0010_0200u64,
            ),
        ] {
            let artifact = bank_mode_artifact(token).unwrap();
            assert_eq!(artifact.token, token);
            assert_eq!(artifact.object, object);
            assert_eq!(artifact.value_bytes, value_bytes);
            assert_eq!(artifact.configuration, configuration);
        }
        for bad in [
            "",
            "counts-bank-proof",
            "counts-bank-growth-v3",
            "Counts-Bank-Growth-v2",
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2",
        ] {
            assert!(
                matches!(
                    bank_mode_artifact(bad),
                    Err(BankRefusal::Shape(BankShapeCause::TestArtifactUnknown))
                ),
                "{bad:?}"
            );
        }
    }

    fn format2_object_maps(inner_value: u32) -> BTreeMap<&'static str, aya_obj::Map> {
        let mut maps = BTreeMap::new();
        for (name, expected) in FORMAT2_MAPS {
            maps.insert(
                name,
                aya_obj::Map::new_from_params(
                    expected.map_type as u32,
                    expected.key_size,
                    expected.value_size,
                    expected.max_entries,
                    expected.flags,
                ),
            );
        }
        let aya_obj::Map::Legacy(outer) = maps.get_mut("COUNTER_BANKS").unwrap() else {
            unreachable!();
        };
        outer.inner_def = Some(aya_obj::maps::bpf_map_def {
            map_type: 6,
            key_size: 4,
            value_size: inner_value,
            max_entries: 512,
            ..Default::default()
        });
        maps
    }

    #[test]
    fn bank_geometry_selects_exactly_three_modes_and_legacy() {
        // Token twins: exactly the three growth tokens plus legacy.
        for (token, mode, configuration) in [
            (
                "counts-bank-growth-v2",
                CounterMode::Counts,
                COUNTS_GROWTH_V2_CONFIG,
            ),
            (
                "timestamps-bank-growth-v2",
                CounterMode::Timestamps,
                TIMESTAMPS_GROWTH_V2_CONFIG,
            ),
            (
                "latency-bank-growth-v2",
                CounterMode::Latency,
                LATENCY_GROWTH_V2_CONFIG,
            ),
        ] {
            let geometry = BankGeometry::selected(token).unwrap();
            assert_eq!(geometry.mode(), mode);
            assert_eq!(geometry.configuration, configuration);
            assert_eq!((geometry.banks, geometry.cells), (16, 512));
            assert_eq!(geometry.limit(), 8192);
            // The configuration word carries the per-cell value size.
            assert_eq!((configuration >> 32) & 0xffff, mode.stats_bytes());
            assert_eq!(BankGeometry::checked(mode, 16, 512).unwrap(), geometry);
        }
        let legacy = BankGeometry::selected("counts-bank-proof").unwrap();
        assert!(legacy.is_legacy());
        assert_eq!(legacy.mode(), CounterMode::Counts);
        assert_eq!(legacy.configuration, BANK_CONFIG);
        for bad in [
            "",
            "counts-bank-growth-v3",
            "Counts-Bank-Growth-v2",
            "timestamps-bank-growth-v3",
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2",
            "latency-bank-growth-v2,timestamps-bank-growth-v2",
        ] {
            assert!(
                matches!(
                    BankGeometry::selected(bad),
                    Err(BankRefusal::Shape(BankShapeCause::UnknownProfile))
                ),
                "{bad:?}"
            );
        }
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            for (banks, cells) in [(0, 512), (16, 0), (2, 1), (17, 512), (16, 513)] {
                assert!(
                    BankGeometry::checked(mode, banks, cells).is_err(),
                    "{mode:?} {banks}x{cells}"
                );
            }
        }
        // Value-size twins: the inner bank template must match the mode, and
        // the legacy aggregate template stays 24 bytes in every bank object.
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let geometry = BankGeometry::checked(mode, 16, 512).unwrap();
            let value = mode.stats_bytes() as u32;
            let maps = format2_object_maps(value);
            assert_eq!(
                validate_object_maps(geometry, |name| maps.get(name)),
                Ok(())
            );
            for wrong in [24u32, 40, 296] {
                if wrong == value {
                    continue;
                }
                let maps = format2_object_maps(wrong);
                assert_eq!(
                    validate_object_maps(geometry, |name| maps.get(name)),
                    Err(BankRefusal::Shape(BankShapeCause::InnerTemplateShape)),
                    "{mode:?} must refuse a {wrong}-byte inner template"
                );
            }
            let mut maps = format2_object_maps(value);
            let aya_obj::Map::Legacy(outer) = maps.get_mut("COUNTER_BANKS").unwrap() else {
                unreachable!();
            };
            outer.inner_def = None;
            assert_eq!(
                validate_object_maps(geometry, |name| maps.get(name)),
                Err(BankRefusal::Shape(BankShapeCause::InnerTemplateMissing)),
                "{mode:?} must refuse a missing inner template"
            );
        }
        let mut maps = format2_object_maps(40);
        let aya_obj::Map::Legacy(stats) = maps.get_mut("STATS").unwrap() else {
            unreachable!();
        };
        stats.def.value_size = 40;
        assert_eq!(
            validate_object_maps(
                BankGeometry::checked(CounterMode::Timestamps, 16, 512).unwrap(),
                |name| maps.get(name)
            ),
            Err(BankRefusal::Shape(BankShapeCause::StatsShape)),
            "a timestamps-shaped aggregate map cannot relabel the bank template"
        );
    }

    #[test]
    fn bank_payload_charges_mode_bytes_times_possible_cpus() {
        for (mode, bytes) in [
            (CounterMode::Counts, 24usize),
            (CounterMode::Timestamps, 40usize),
            (CounterMode::Latency, 296usize),
        ] {
            let geometry = BankGeometry::checked(mode, 16, 512).unwrap();
            for cpus in [1usize, 2, 12, 256] {
                assert_eq!(
                    geometry.bank_payload_bytes(cpus),
                    Ok(512 * bytes * cpus),
                    "{mode:?} at P={cpus}"
                );
            }
            assert_eq!(
                geometry.bank_payload_bytes(0),
                Err(BankRefusal::Topology),
                "{mode:?}"
            );
            assert_eq!(
                geometry.bank_payload_bytes(usize::MAX),
                Err(BankRefusal::Budget),
                "{mode:?}"
            );
        }
        // Per-bank latency bytes at P=256 stay exactly representable; the
        // sixteen-bank growth below is what the 256 MiB envelope refuses.
        let latency = BankGeometry::checked(CounterMode::Latency, 16, 512).unwrap();
        assert_eq!(latency.bank_payload_bytes(256), Ok(512 * 296 * 256));
        assert_eq!(
            latency.bank_payload_bytes(usize::MAX / (512 * 296) + 1),
            Err(BankRefusal::Budget)
        );
        // Sixteen latency banks at P=256 (~620 MiB of payload) refuse against
        // a 256 MiB envelope before any allocation; counts and timestamps fit
        // the same envelope, and funded latency refuses the 256 MiB kernel map
        // cap (fixed 143,394,816 plus 16 banks, needed 764,151,808).
        for (mode, retained, funded) in [
            (CounterMode::Counts, 256 * 1024 * 1024, true),
            (CounterMode::Timestamps, 256 * 1024 * 1024, true),
            (CounterMode::Latency, 256 * 1024 * 1024, false),
        ] {
            let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024 * 1024);
            let baseline = pool.snapshot().charged_bytes;
            let mut directory = BankDirectory::growth_v2_for(mode);
            let mut history = plan(8192);
            let mut io = GrowthIo::new(&pool);
            io.cpus = 256;
            let envelope = BankReservation {
                retained_bytes: retained,
                transient_bytes: 256 * 1024 * 1024,
                metadata_bytes: 16 * 1024 * 1024,
                file_descriptors: 131_072,
            };
            let publication =
                directory.stage_with(&mut io, &mut history, envelope, &pool.reserver());
            if funded {
                assert!(
                    matches!(
                        publication,
                        BankPublication::Published { extent, .. }
                            if extent.first == 0 && extent.end == 8192
                    ),
                    "{mode:?} with {retained} retained bytes: {publication:?}"
                );
                assert_eq!(directory.published_indices().count(), 8192, "{mode:?}");
            } else {
                assert_eq!(publication, BankPublication::Refused(BankRefusal::Budget));
                assert!(
                    io.trace.is_empty(),
                    "budget refusal precedes native work: {:?}",
                    io.trace
                );
                assert_eq!(pool.snapshot().charged_bytes, baseline);
                assert!(directory.published_indices().next().is_none());
                assert_eq!(directory.allocated_high_water(), 0);
            }
        }
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024 * 1024);
        let baseline = pool.snapshot().charged_bytes;
        let mut directory = BankDirectory::growth_v2_for(CounterMode::Latency);
        let mut history = plan(8192);
        let mut io = GrowthIo::new(&pool);
        io.cpus = 256;
        let publication = directory.stage_with(
            &mut io,
            &mut history,
            BankReservation {
                retained_bytes: 1024 * 1024 * 1024,
                transient_bytes: 256 * 1024 * 1024,
                metadata_bytes: 16 * 1024 * 1024,
                file_descriptors: 131_072,
            },
            &pool.reserver(),
        );
        assert_eq!(
            publication,
            BankPublication::Refused(BankRefusal::BudgetExhausted {
                resource: "counter-memory-limit",
                needed: 764_151_808,
                available: 268_435_456,
            }),
            "funded latency 16 banks refuse the kernel map cap: {publication:?}"
        );
        assert!(
            io.trace.is_empty(),
            "memory-cap refusal precedes native work: {:?}",
            io.trace
        );
        assert_eq!(pool.snapshot().charged_bytes, baseline);
        assert!(directory.published_indices().next().is_none());
        assert_eq!(directory.allocated_high_water(), 0);
    }

    #[test]
    fn counter_build_gate_refuses_disabled() {
        for disabled in ["0", "", "2", "yes"] {
            let refusal = super::check_counter_build(disabled, "").unwrap_err();
            assert!(
                refusal.contains("counter-mode-unavailable-in-build"),
                "{disabled:?}: {refusal}"
            );
        }
        assert!(
            super::check_counter_build(
                "1",
                "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2",
            )
            .is_ok()
        );
    }

    #[test]
    fn counter_preparation_refuses_when_objects_disabled() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") == "1" {
            assert_eq!(
                env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
                "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
            );
            return;
        }
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"), "");
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let envelope = BankReservation {
            retained_bytes: 1024 * 1024,
            transient_bytes: 1024 * 1024,
            metadata_bytes: 64 * 1024,
            file_descriptors: 1024,
        };
        // The build gate refuses before the kernel probe: even a kernel that
        // would allow counters gets the build token, and a kernel refusal
        // never masks it (deterministic checks run first).
        for verdict in [
            BpfLoopVerdict::Available,
            BpfLoopVerdict::Unavailable("needs Linux 5.17+".into()),
        ] {
            let Err(refusal) = CounterPreparation::new_with_backend_and_probe(
                b"not an object",
                envelope,
                &pool.reserver(),
                AttachBackend::Singles,
                || verdict.clone(),
            ) else {
                panic!("disabled build must refuse preparation");
            };
            let message = format!("{refusal:#}");
            assert!(
                message.contains("counter-mode-unavailable-in-build"),
                "{message}"
            );
        }
    }

    #[cfg(feature = "wide-detailed-2112")]
    #[test]
    fn counter_preparation_refuses_on_wide_build() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"), "0");
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"), "");
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let envelope = BankReservation {
            retained_bytes: 1024 * 1024,
            transient_bytes: 1024 * 1024,
            metadata_bytes: 64 * 1024,
            file_descriptors: 1024,
        };
        for verdict in [
            BpfLoopVerdict::Available,
            BpfLoopVerdict::Unavailable("needs Linux 5.17+".into()),
        ] {
            let Err(refusal) = CounterPreparation::new_with_backend_and_probe(
                b"not an object",
                envelope,
                &pool.reserver(),
                AttachBackend::Singles,
                || verdict.clone(),
            ) else {
                panic!("wide builds must refuse preparation");
            };
            let message = format!("{refusal:#}");
            assert!(
                message.contains("counter-mode-unavailable-in-build"),
                "{message}"
            );
        }
    }

    #[cfg(feature = "stub-object-attributes")]
    #[test]
    fn counter_preparation_stays_healthy_on_p0_build() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"), "1");
        assert_eq!(
            env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
        );
        assert!(!crate::EBPF_COUNTER_COUNTS_OBJECT.is_empty());
        // The build gate passes; garbage bytes fail at object parsing or the
        // embedded pin, never with a build or kernel token.
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let envelope = BankReservation {
            retained_bytes: 1024 * 1024,
            transient_bytes: 1024 * 1024,
            metadata_bytes: 64 * 1024,
            file_descriptors: 1024,
        };
        let Err(error) = CounterPreparation::new_with_backend_and_probe(
            b"not an object",
            envelope,
            &pool.reserver(),
            AttachBackend::Singles,
            || BpfLoopVerdict::Available,
        ) else {
            panic!("garbage bytes must fail");
        };
        let text = format!("{error:#}");
        assert!(
            !text.contains("counter-mode-unavailable-in-build"),
            "p0 must stay healthy: {text}"
        );
        assert!(
            !text.contains("counter-mode-unavailable-on-kernel"),
            "p0 must stay healthy: {text}"
        );
    }

    #[cfg(feature = "unsafe-unvalidated-metadata")]
    #[test]
    fn counter_preparation_stays_healthy_on_unsafe_build() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"), "1");
        assert_eq!(
            env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
        );
        assert!(!crate::EBPF_COUNTER_COUNTS_OBJECT.is_empty());
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let envelope = BankReservation {
            retained_bytes: 1024 * 1024,
            transient_bytes: 1024 * 1024,
            metadata_bytes: 64 * 1024,
            file_descriptors: 1024,
        };
        let Err(error) = CounterPreparation::new_with_backend_and_probe(
            b"not an object",
            envelope,
            &pool.reserver(),
            AttachBackend::Singles,
            || BpfLoopVerdict::Available,
        ) else {
            panic!("garbage bytes must fail");
        };
        let text = format!("{error:#}");
        assert!(
            !text.contains("counter-mode-unavailable-in-build"),
            "unsafe must stay healthy: {text}"
        );
        assert!(
            !text.contains("counter-mode-unavailable-on-kernel"),
            "unsafe must stay healthy: {text}"
        );
    }

    /// Loads every bank mode object: sixteen per-mode inner maps are staged
    /// into the outer map, then the two bank roots and the two lifecycle
    /// roots load against them. No attachment, commit publication or
    /// workload runs here.
    #[test]
    #[ignore = "requires the default build with embedded counter objects, BPF privilege and LP64 map/program load"]
    fn counter_bank_mode_objects_load_lp64() {
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"), "1");
        assert_eq!(
            env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
        );
        let directory = tempfile::tempdir().expect("counter load directory");
        for (mode, token, counter_mode) in [
            ("counts", "counts-bank-growth-v2", CounterMode::Counts),
            (
                "timestamps",
                "timestamps-bank-growth-v2",
                CounterMode::Timestamps,
            ),
            ("latency", "latency-bank-growth-v2", CounterMode::Latency),
        ] {
            let artifact = bank_mode_artifact(token).unwrap();
            let path = directory.path().join(artifact.object);
            std::fs::write(&path, super::counter_object_for_mode(counter_mode))
                .expect("write embedded bank object");
            let check = std::process::Command::new("python3")
                .args([
                    "-I",
                    "scripts/check-counter-object.py",
                    "--mode",
                    mode,
                    "--profile",
                    token,
                ])
                .arg(&path)
                .output()
                .expect("run bank checker");
            assert!(
                check.status.success(),
                "{mode}: {}",
                String::from_utf8_lossy(&check.stderr)
            );
            let bytes = std::fs::read(&path).unwrap();
            let parsed = aya_obj::Object::parse(&bytes).unwrap();
            for (name, expected) in [
                ("COUNTER_BANKS", (13, 4, 4, 16, 128)),
                ("COUNTER_BANK_META", (1, 4, 32, 8192, 128)),
                ("COUNTER_BANK_COMMIT", (1, 8, 16, 8192, 128)),
                ("RV_COUNTS", (5, 16, 8, 65536, 0)),
                ("SLOT_FILE", (2, 4, 4, 8192, 128)),
                ("STATS", (6, 4, 24, 512, 0)),
                ("START", (1, 16, 288, 16384, 0)),
            ] {
                let map = parsed.maps.get(name).expect("actual required bank map");
                assert_eq!(
                    (
                        map.map_type(),
                        map.key_size(),
                        map.value_size(),
                        map.max_entries(),
                        map.map_flags()
                    ),
                    expected,
                    "{mode} actual emitted {name}"
                );
            }
            let inner = parsed.maps["COUNTER_BANKS"].inner().unwrap();
            assert_eq!(
                (
                    inner.map_type(),
                    inner.key_size(),
                    inner.value_size(),
                    inner.max_entries(),
                    inner.map_flags()
                ),
                (6, 4, artifact.value_bytes, 512, 0),
                "{mode} actual inner template"
            );
            drop(parsed);
            let mut object = aya::EbpfLoader::new()
                .allow_unsupported_maps()
                .load_file(&path)
                .expect("load bank BTF and maps");
            let storage: std::collections::BTreeMap<_, _> = object
                .maps()
                .filter_map(|(name, map)| match map {
                    aya::maps::Map::Unsupported(data) => Some((name, data)),
                    _ => None,
                })
                .collect();
            let expected = std::collections::BTreeMap::from([
                ("PROC_EPOCH", 152u32),
                ("ROOT_AFFILIATION", 8),
                ("TASK_COOKIE", 8),
                ("THREAD_OWNER", 560),
            ]);
            assert_eq!(
                storage.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>(),
                "{mode}"
            );
            for (name, value_size) in expected {
                let info = storage[name].info().expect("read native task-storage info");
                assert_eq!(
                    (
                        info.map_type().unwrap(),
                        info.key_size(),
                        info.value_size(),
                        info.max_entries(),
                        info.map_flags(),
                    ),
                    (aya::maps::MapType::TaskStorage, 4, value_size, 0, 1),
                    "{mode} {name}"
                );
            }
            drop(storage);
            let native_banks: Vec<_> = (0..16)
                .map(|bank| {
                    aya::maps::MapData::create(
                        aya_obj::Map::new_from_params(6, 4, artifact.value_bytes, 512, 0),
                        &format!("{mode}_bank{bank}"),
                        None,
                    )
                    .expect("allocate actual 512-cell bank")
                })
                .collect();
            let ids: std::collections::BTreeSet<_> = native_banks
                .iter()
                .map(|bank| {
                    let info = bank.info().expect("actual inner-map metadata");
                    assert_eq!(
                        (
                            info.map_type().unwrap(),
                            info.key_size(),
                            info.value_size(),
                            info.max_entries(),
                            info.map_flags()
                        ),
                        (
                            aya::maps::MapType::PerCpuArray,
                            4,
                            artifact.value_bytes,
                            512,
                            0
                        ),
                        "{mode}",
                    );
                    assert_ne!(info.id(), 0, "{mode}");
                    info.id()
                })
                .collect();
            assert_eq!(
                ids.len(),
                16,
                "{mode} all sixteen banks retain distinct native IDs"
            );
            {
                let mut banks: aya::maps::HashOfMaps<_, u32> = object
                    .map_mut("COUNTER_BANKS")
                    .expect("real outer map")
                    .try_into()
                    .expect("real HashOfMaps ABI");
                for (index, bank) in native_banks.iter().enumerate() {
                    banks
                        .insert(index as u32, bank, 1)
                        .expect("stage bank with BPF_NOEXIST");
                    assert_eq!(
                        banks.get(&(index as u32), 0).unwrap().info().unwrap().id(),
                        bank.info().unwrap().id(),
                        "{mode}",
                    );
                }
            }
            for name in PROGRAMS {
                let program: &mut aya::programs::UProbe = object
                    .program_mut(name)
                    .expect("bank root")
                    .try_into()
                    .expect("uprobe program kind");
                program
                    .load()
                    .expect("actual outer-to-inner verifier bridge");
            }
            for name in ["sched_process_exec", "sched_process_exit"] {
                let program: &mut aya::programs::RawTracePoint = object
                    .program_mut(name)
                    .expect("actual lifecycle root")
                    .try_into()
                    .expect("raw tracepoint program kind");
                program
                    .load()
                    .expect("actual full-bound owner cleanup verifier");
            }
        }
    }

    #[test]
    fn format2_link_stage_requires_exact_extent() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut banks = reader_banks(&pool);
        banks.geometry = BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap();
        *banks.directory.lock().unwrap() = BankDirectory::counts_growth_v2();
        let slots = vec![slot(511, 1), slot(512, 2)];
        // The existing atomic is an exact (first,end) guard, not a slot mask.
        // This literal crosses a bank boundary and cannot be mistaken for2.
        let stage = banks
            .begin_link_stage(0x0000_01ff_0000_0201)
            .expect("format2 extent511..513 must admit its complete target pair");
        assert!(banks.permits_link_stage(&slots));
        assert!(!banks.permits_link_stage(&slots[..1]));
        assert!(!banks.permits_link_stage(&[slot(511, 1), slot(513, 2)]));
        assert!(banks.begin_link_stage(0x0000_0200_0000_0201).is_err());
        assert!(
            banks.permits_link_stage(&slots),
            "overlap refusal preserves the existing guard"
        );
        drop(stage);
        assert!(!banks.permits_link_stage(&slots));
        for invalid in [
            0,
            0x0000_0200_0000_0200,
            0x0000_0201_0000_0200,
            0x0000_2000_0000_2001,
        ] {
            assert!(
                banks.begin_link_stage(invalid).is_err(),
                "invalid extent {invalid:#x}"
            );
        }
        let last = banks.begin_link_stage(0x0000_1fff_0000_2000).unwrap();
        assert!(banks.permits_link_stage(&[slot(8191, 3)]));
        assert!(!banks.permits_link_stage(&[slot(8192, 3)]));
        drop(last);
    }

    #[test]
    fn counter_reader_binding_distinguishes_legacy_from_present_refusal() {
        assert!(
            reader_profile_with(
                None,
                |_| panic!("legacy absence must not inspect counter maps"),
                || panic!("legacy absence must not query counter CPU topology"),
            )
            .unwrap()
            .is_none()
        );
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let banks = reader_banks(&pool);
        assert!(matches!(
            reader_profile_with(Some(&banks), |_| Err(BankRefusal::Native), || Ok(2)),
            Err(BankRefusal::Native)
        ));
        assert!(matches!(
            reader_profile_with(Some(&banks), reader_metadata, || Err(BankRefusal::Native)),
            Err(BankRefusal::Native)
        ));
        banks.directory.lock().unwrap().quarantined = true;
        assert!(matches!(
            reader_profile_with(
                Some(&banks),
                |_| panic!("quarantine must not become a healthy profile"),
                || Ok(2)
            ),
            Err(BankRefusal::Quarantined)
        ));
        *banks.directory.lock().unwrap() = BankDirectory::counts_growth_v2();
        assert!(matches!(
            reader_profile_with(
                Some(&banks),
                |_| panic!("incomplete format2 must refuse before map I/O"),
                || panic!("incomplete format2 must refuse before CPU I/O")
            ),
            Err(BankRefusal::Shape(BankShapeCause::BindingGeometryChanged))
        ));
    }

    #[test]
    fn counter_reader_binding_reports_validated_prepared_counts_bounds() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let banks = reader_banks(&pool);
        let profile = reader_profile_with(Some(&banks), reader_metadata, || Ok(2))
            .unwrap()
            .unwrap();
        assert_eq!(profile.mode(), p11scope_ebpf_common::CounterMode::Counts);
        assert_eq!(profile.logical_slots(), 512);
        assert_eq!(profile.rv_keys(), 4096);
        assert_eq!(profile.start_rows(), 16384);
        assert_eq!(profile.possible_cpus(), 2);
        assert!(matches!(
            reader_profile_with(Some(&banks), reader_metadata, || Ok(3)),
            Err(BankRefusal::Topology)
        ));
        assert!(
            matches!(
                reader_profile_with(
                    Some(&banks),
                    |name| {
                        let mut actual = reader_metadata(name)?;
                        if name == "STATS" {
                            actual.value_size = 40;
                        }
                        Ok(actual)
                    },
                    || Ok(2)
                ),
                Err(BankRefusal::Shape(BankShapeCause::StatsShape))
            ),
            "a timestamps-shaped map cannot relabel this Counts preparation"
        );
    }

    #[test]
    fn counter_preparation_refuses_when_bpf_loop_is_absent() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let baseline = pool.snapshot().charged_bytes;
        // Garbage bytes: the kernel refusal precedes parsing entirely.
        let refused = CounterPreparation::new_with_backend_and_probe(
            b"not an ELF object",
            reservation(),
            &pool.reserver(),
            AttachBackend::Singles,
            || BpfLoopVerdict::Unavailable("test kernel lacks helper 181".into()),
        );
        let Err(error) = refused else {
            panic!("kernel refusal must fail");
        };
        let text = format!("{error:#}");
        assert!(
            text.starts_with("counter-mode-unavailable-on-kernel:"),
            "{text}"
        );
        assert!(text.contains("helper 181"), "{text}");
        assert_eq!(pool.snapshot().charged_bytes, baseline);
        // An unproven probe defers: some later gate refuses, never the
        // kernel token, and nothing stays charged.
        for verdict in [
            BpfLoopVerdict::Available,
            BpfLoopVerdict::Unknown("test control load failed".into()),
        ] {
            let charged = pool.snapshot().charged_bytes;
            let result = CounterPreparation::new_with_backend_and_probe(
                b"not an ELF object",
                reservation(),
                &pool.reserver(),
                AttachBackend::Singles,
                || verdict,
            );
            let Err(error) = result else {
                panic!("deferred preparation of garbage bytes must fail");
            };
            let text = format!("{error:#}");
            assert!(
                !text.contains("counter-mode-unavailable-on-kernel"),
                "must defer past the kernel gate: {text}"
            );
            assert_eq!(pool.snapshot().charged_bytes, charged);
        }
    }

    #[test]
    fn counter_verifier_budget_refusal_maps_e2big_only() {
        // A kernel verifier-budget rejection (E2BIG from BPF_PROG_LOAD)
        // becomes the finite named refusal without the raw verifier log.
        let blob = "verifier-line\n".repeat(9000);
        let loaded: anyhow::Error = std::io::Error::from_raw_os_error(libc::E2BIG).into();
        let loaded = loaded.context(format!("loading function_list_return\n{blob}"));
        let mapped = map_counter_verifier_budget_refusal(loaded);
        assert_eq!(
            mapped.to_string(),
            "counter-mode-unavailable-on-kernel: the kernel verifier rejected a counter program as too complex (E2BIG)"
        );
        assert!(
            !format!("{mapped:#}").contains("verifier-line"),
            "the raw verifier log must not survive the mapping"
        );
        // Every other failure passes through with its chain unchanged: the
        // old-kernel token (no E2BIG), the Multi pid-filter errno (EINVAL)
        // and an unrelated error.
        for untouched in [
            anyhow::anyhow!(
                "counter-mode-unavailable-on-kernel: the kernel loads BPF programs but rejects the bpf_loop (helper 181) probe"
            ),
            std::io::Error::from_raw_os_error(libc::EINVAL).into(),
            anyhow::anyhow!("some other failure"),
        ] {
            let before = format!("{untouched:#}");
            let after = map_counter_verifier_budget_refusal(untouched);
            assert_eq!(format!("{after:#}"), before);
        }
    }

    /// The C producer's bucket index must equal the shared `bucket_of` over
    /// the full equality boundary set, in both timing modes.
    #[test]
    fn counter_bank_bucket_matches_bucket_of() {
        use p11scope_ebpf_common::bucket_of;
        use std::collections::BTreeSet;
        use std::process::Command;
        let mut inputs = BTreeSet::from([0u64, u64::MAX]);
        for shift in 0..64u32 {
            let power = 1u64 << shift;
            inputs.insert(power - 1);
            inputs.insert(power);
            inputs.insert(power + 1);
        }
        let inputs: Vec<u64> = inputs.into_iter().collect();
        assert_eq!(
            inputs.len(),
            190,
            "boundary set dedups only the small-k overlaps"
        );
        let temporary = tempfile::tempdir().expect("counter bucket probe directory");
        for mode in ["TIMESTAMPS", "LATENCY"] {
            let binary = temporary.path().join(format!("bank-bucket-{mode}"));
            let mode_flag = format!("-DP11SCOPE_BANK_MODE_{mode}");
            let output = Command::new("clang-18")
                .arg(&mode_flag)
                .args([
                    "-O2",
                    "-g",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-DP11SCOPE_COUNTER_BANK_PROOF",
                    "-I",
                    "crates/ebpf/native",
                    "tests/fixtures/task-owner/bank_bucket_probe.c",
                    "-o",
                ])
                .arg(&binary)
                .output()
                .expect("compile actual bank_bucket producer");
            assert!(
                output.status.success(),
                "native {mode} bucket compile: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let hex: Vec<String> = inputs.iter().map(|value| format!("{value:x}")).collect();
            let output = Command::new(&binary)
                .args(&hex)
                .output()
                .expect("run actual bank_bucket producer");
            assert!(
                output.status.success(),
                "native {mode} bucket run: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).expect("bucket lines are text");
            let buckets: Vec<u32> = stdout
                .lines()
                .map(|line| line.parse().expect("bucket index per line"))
                .collect();
            assert_eq!(buckets.len(), inputs.len());
            for (input, actual) in inputs.iter().zip(buckets) {
                assert_eq!(
                    actual,
                    bucket_of(*input),
                    "C bank_bucket({input:#x}) in {mode} mode"
                );
            }
        }
    }

    /// Bank roots never touch the legacy per-slot aggregate map: the timing
    /// producer must not even name it. (The counts twin is pinned the same
    /// way by the object checker; timing profiles land with the checker.)
    #[test]
    fn counter_bank_timing_roots_never_touch_stats() {
        let source = std::fs::read_to_string("crates/ebpf/native/counter_bank_timing.c")
            .expect("timing bank producer source");
        assert!(
            !source.contains("STATS"),
            "timing producer must not name the legacy aggregate map"
        );
    }

    /// 5.15 refusal cell: without helper 181, counter preparation refuses
    /// with the kernel token before parsing or charging anything. Runs on
    /// pre-5.17 kernels with BPF privilege; the 6.1/6.6/host positive side
    /// is the existing growth cells, which must keep passing unmodified.
    #[test]
    #[ignore = "requires the default build with embedded counter objects, BPF privilege and a pre-5.17 kernel"]
    fn counter_preparation_refuses_without_bpf_loop_on_old_kernels() {
        use super::super::BpfLoopVerdict;
        assert_eq!(env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"), "1");
        assert_eq!(
            env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
            "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
        );
        // Wrong kernel for this cell fails loud here, never as a vacuous pass.
        assert!(
            matches!(
                super::super::kernel_bpf_loop_probe(),
                BpfLoopVerdict::Unavailable(_)
            ),
            "this refusal cell runs only where the kernel lacks helper 181"
        );
        let path = std::path::Path::new(env!("OUT_DIR"))
            .join("counter-bank-growth-v2")
            .join("p11scope-ebpf-counts-bank-growth-v2");
        let bytes = std::fs::read(path).expect("compile the actual selected format2 artifact");
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024 * 1024);
        let baseline = pool.snapshot().charged_bytes;
        let envelope = BankReservation {
            retained_bytes: 1024 * 1024 * 1024,
            transient_bytes: 512 * 1024 * 1024,
            metadata_bytes: 64 * 1024 * 1024,
            file_descriptors: 1_048_576,
        };
        let refused = CounterPreparation::new(&bytes, envelope, &pool.reserver());
        let Err(error) = refused else {
            panic!("old-kernel preparation must refuse");
        };
        let text = format!("{error:#}");
        assert!(
            text.starts_with("counter-mode-unavailable-on-kernel:"),
            "{text}"
        );
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }
}
