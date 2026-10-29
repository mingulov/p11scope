//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private counter publication, retained native custody and charged collection.

use super::{BpfLoopVerdict, CapturePolicy, Scope, Session};
use crate::discovery::identity::{PinnedObjectId, PinnedObjects, RetainedInventoryTarget};
use crate::plan::{AttachKey, AttachPlan, Slot};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourcePool, SemanticResourceReserver,
};
use anyhow::{Context, Result, ensure};
use aya::Ebpf;
use aya::maps::{HashMap, HashOfMaps, Map, MapData, MapError, MapType};
use aya::programs::UProbe;
use p11scope_ebpf_common::{
    CallStart, CounterMode, MAX_SLOTS, RING_BYTES, RV_ENTRIES, START_ENTRIES, SlotStats,
};
use std::collections::BTreeSet;
use std::mem::size_of;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

/// Engine-built counter capture request: the mode to prepare, the
/// preparation envelope, and the capture pool reserver funding the terminal
/// hold, keepalive and load overlap. The Engine mints one per counter
/// capture from its own pool; preparation runs inside the Session start
/// chain so the FD raise covers it.
pub(crate) struct CounterSpec {
    mode: CounterMode,
    reservation: BankReservation,
    reserve: SemanticResourceReserver,
}

impl CounterSpec {
    pub(crate) fn new(
        mode: CounterMode,
        reservation: BankReservation,
        reserve: SemanticResourceReserver,
    ) -> Self {
        Self {
            mode,
            reservation,
            reserve,
        }
    }

    /// Production envelope: the proven growth-cell base (retained,
    /// transient, metadata) with FDs for the host CPU count plus the
    /// 512-endpoint stage. Preparation validates the floors; the capture
    /// pool funds the charges.
    pub(crate) fn for_production(
        mode: CounterMode,
        cpus: usize,
        reserve: SemanticResourceReserver,
    ) -> Result<Self, BankRefusal> {
        if cpus == 0 {
            return Err(BankRefusal::Topology);
        }
        let file_descriptors = cpus
            .checked_mul(4)
            .and_then(|n| n.checked_add(512))
            .ok_or(BankRefusal::Budget)?;
        Ok(Self::new(
            mode,
            BankReservation {
                retained_bytes: 128 * 1024 * 1024,
                transient_bytes: 64 * 1024 * 1024,
                metadata_bytes: 32 * 1024 * 1024,
                file_descriptors,
            },
            reserve,
        ))
    }

    pub(crate) fn mode(self) -> CounterMode {
        self.mode
    }

    /// Production preparation: the embedded object for the spec mode with
    /// the real kernel probe and the real CPU count.
    pub(super) fn prepare(
        &self,
        backend: super::AttachBackend,
    ) -> Result<CounterPreparation<'static>> {
        self.prepare_with_probe_and_cpus(backend, super::kernel_bpf_loop_probe, None)
    }

    /// Preparation with an injected probe verdict and CPU count, so tests
    /// pin the envelope deterministically on any kernel.
    pub(super) fn prepare_with_probe_and_cpus(
        &self,
        backend: super::AttachBackend,
        probe: impl FnOnce() -> BpfLoopVerdict,
        cpus_override: Option<usize>,
    ) -> Result<CounterPreparation<'static>> {
        CounterPreparation::new_with_backend_probe_and_cpus(
            counter_object_for_mode(self.mode),
            self.reservation,
            &self.reserve,
            backend,
            probe,
            cpus_override,
        )
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

/// Shared return-value key pool for counter reads: every growth geometry
/// publishes at most this many RV keys. Read limits pin here.
pub(crate) const COUNTER_RV_KEY_POOL: usize = 65536;

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
/// It intentionally equals the staging charge (key-excluded `512*B*P`, the
/// ruled parent §1 formula), not `configured_payload` for the inner
/// PERCPU_ARRAY: the 4-byte inner key there adds 2 KiB per bank (the type-6
/// arm adds the key; the `FORMAT2_MAPS` inner template is key 4, value B,
/// 512 entries). No ceiling moves: every current B (24/40/296) is a
/// multiple of 8, so alignment is identity and only the key differs.
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

/// Terminal close bookkeeping: link retire, map close, keepalive drop and
/// the cleanup receipt. Fixed 4 MiB upper bound; the terminal hold keeps it
/// unspendable too. Derivation at the 8,192-endpoint ceiling, both backends
/// (Singles carries entry+return uprobes per endpoint; Multi reserves at
/// most two leaves per endpoint, `src/attach/counter_banks.rs:1089`): at
/// most 16,384 owned links transfer once, either through the foreground
/// terminal detach (`src/attach.rs:7620`, `src/attach.rs:1757`) or
/// `Session::drop` (`src/attach.rs:8681`), via `take_owned_links`
/// (`src/attach.rs:8513`, one `OwnedLink` per link) into one push-grown
/// worker batch (old+new backing <= 2x final: 16,384 x 72 x 2 + 32 =
/// 2,359,328), each boxed once by `retain_counter`
/// (`src/attach/cleanup_worker.rs:44`: 16,384 x (48 + 32) = 1,310,720),
/// plus one transient single-link Vec (80), retirement leases of at most
/// one `Arc` per slot (`src/attach.rs:1608`, `src/attach.rs:2359`: 8,192 x
/// 8 + 64 = 65,600) and a 4,096 receipt/batch allowance. Map close and
/// keepalive drop only free their precharged backing, and the production
/// closer is infallible `drop` (`src/attach/cleanup_worker.rs:640`), so the
/// receipt carries only fixed worker-level strings. Total 3,739,824 (72-
/// byte batch tuples, 48-byte links, 32-byte padding), rounded up to 4 MiB;
/// the dominance test recomputes it from `size_of`. Transfer-failure
/// strings (diagnostic only) are outside this figure.
pub(crate) const COUNTER_TERMINAL_CLEANUP_BYTES: usize = 4 * 1024 * 1024;

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

/// Deterministic build gate, checked before the kernel probe (and before
/// the CLI policy resolves any object bytes): builds that omit counter
/// objects (`=0`, SMALL, WIDE) refuse every mode with
/// `counter-mode-unavailable-in-build`. build.rs already folds WIDE into the
/// emitted `ENABLED` flag, so this gate reads only the emitted pair. P0 and
/// unsafe-compiled builds embed identical bytes and pass.
pub(crate) fn check_counter_build(enabled: &str, outputs: &str) -> Result<(), String> {
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

/// Finite site names for bare `Topology` staging refusals. The refusal VALUE
/// stays a bare `BankRefusal` (every existing match keeps working); the name
/// travels alongside through the `_detailed` staging twins into the Session's
/// last-check slot, so an Engine counter start can say WHICH check failed
/// instead of reporting a bare `Topology`. Non-Topology refusals already
/// name themselves (`Shape` causes, `BudgetExhausted` resources) and carry
/// no check name.
const COUNTER_CHECK_PLAN_BUDGET: &str = "counter plan budget differs from the staged budget";
const COUNTER_CHECK_PLAN_CONSUMED: &str =
    "counter plan consumed prefix differs from the staged length";
const COUNTER_CHECK_PLAN_SHORTER: &str = "counter plan is shorter than the staged prefix";
const COUNTER_CHECK_PLAN_INDEX: &str = "counter plan slot indices are not dense";
const COUNTER_CHECK_PLAN_INACTIVE: &str = "counter plan has inactive fresh slots";
const COUNTER_CHECK_PLAN_KEY: &str = "counter plan slot differs from the staged key";
const COUNTER_CHECK_DUPLICATE: &str = "counter plan has duplicate physical endpoints";
const COUNTER_CHECK_ADOPT: &str = "counter plan cannot adopt the staged prefix";
const COUNTER_CHECK_SIZING_CPUS: &str = "counter stage sizing saw zero CPUs";
const COUNTER_CHECK_SESSION_STOPPED: &str = "counter session is stopping or detached";
const COUNTER_CHECK_BACKEND: &str = "counter banks backend differs from the session backend";
const COUNTER_CHECK_SCOPE: &str = "counter session scope is not one process or all processes";
const COUNTER_CHECK_UNCHANGED: &str = "counter pinned provider changed";
const COUNTER_CHECK_CPUS: &str = "counter CPU count changed since preparation";
const COUNTER_CHECK_CONSUME_POLICY: &str = "counter extent plan is not a counter plan";
const COUNTER_CHECK_CONSUME_EXTENT: &str = "counter extent does not cover the fresh tail";
const COUNTER_CHECK_CONSUME_FRONTIER: &str = "counter extent frontier moved";
const COUNTER_CHECK_CONSUME_TOPOLOGY: &str = "counter extent has inactive or misindexed slots";

/// Names a history-consumption refusal. Unreachable after `validate_plan`
/// passes (it proves the same policy, extent, frontier and activity facts),
/// so this only labels defense-in-depth.
fn consume_check_name(error: crate::plan::CounterHistoryError) -> &'static str {
    match error {
        crate::plan::CounterHistoryError::Policy => COUNTER_CHECK_CONSUME_POLICY,
        crate::plan::CounterHistoryError::Extent => COUNTER_CHECK_CONSUME_EXTENT,
        crate::plan::CounterHistoryError::Frontier => COUNTER_CHECK_CONSUME_FRONTIER,
        crate::plan::CounterHistoryError::Topology => COUNTER_CHECK_CONSUME_TOPOLOGY,
    }
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
    // Singles retains two BPF-link FDs per endpoint, with one transient
    // perf FD during sequential attachment. Multi can bisect to the same
    // two-leaf-per-endpoint maximum and needs no perf FD, so this same
    // bound conservatively admits either backend. Links are offset-based,
    // so the count is scope-independent: cgroup/system sessions (pid-wide
    // links, membership enforced by the in-BPF scope gate) share this
    // bound. Provider owners share Arc<File>; observed_open already counts
    // old maps, links and providers. Map bytes above still cover every
    // possible CPU.
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

/// Upper bound on the `BankReservation` one `stage_counter_banks` call
/// charges, for Engine staging envelopes and harness envelopes. It runs the
/// same `stage_requirements` (plus the Multi storage check inputs) rather
/// than a second formula, so accounting changes move both sides together.
/// Every input must dominate the matching production value at staging time:
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
    /// Check name for the last `validate_targets` call when it refused a
    /// bare `Topology`, `None` otherwise. Fake IOs keep the default.
    fn last_check(&self) -> Option<&'static str> {
        None
    }
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
        self.validate_plan_detailed(plan)
            .map_err(|(refusal, _)| refusal)
    }

    /// `validate_plan` with the failing `Topology` check named. The arms run
    /// in the original short-circuit order, so refusals are identical and
    /// only gain a name.
    fn validate_plan_detailed(
        &self,
        plan: &AttachPlan,
    ) -> Result<(), (BankRefusal, Option<&'static str>)> {
        let crate::plan::AdmissionPolicy::Counters(budget) = plan.admission_policy() else {
            return Err((BankRefusal::Shape(BankShapeCause::PlanNotCounters), None));
        };
        if budget.validate_count(plan.slots.len()).is_err()
            || plan.slots.len() > self.geometry.limit() as usize
        {
            return Err((BankRefusal::Shape(BankShapeCause::PlanBudgetMismatch), None));
        }
        if self.budget.is_some_and(|old| old != budget) {
            return Err((BankRefusal::Topology, Some(COUNTER_CHECK_PLAN_BUDGET)));
        }
        if plan.counter_consumed_end() as usize != self.positions.len() {
            return Err((BankRefusal::Topology, Some(COUNTER_CHECK_PLAN_CONSUMED)));
        }
        if plan.slots.len() < self.positions.len() {
            return Err((BankRefusal::Topology, Some(COUNTER_CHECK_PLAN_SHORTER)));
        }
        for (index, slot) in plan.slots.iter().enumerate() {
            if slot.index as usize != index {
                return Err((BankRefusal::Topology, Some(COUNTER_CHECK_PLAN_INDEX)));
            }
            if index >= self.positions.len() && !plan.is_active(slot.index) {
                return Err((BankRefusal::Topology, Some(COUNTER_CHECK_PLAN_INACTIVE)));
            }
            if self
                .positions
                .get(index)
                .is_some_and(|old| old.key != physical(slot))
            {
                return Err((BankRefusal::Topology, Some(COUNTER_CHECK_PLAN_KEY)));
            }
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
        let mut check = None;
        self.stage_with_checked(io, plan, reservation, reserve, &mut check)
    }

    /// `stage_with` with the failing `Topology` check named. Refusal values
    /// are identical; only the name travels alongside.
    fn stage_with_detailed(
        &mut self,
        io: &mut impl BankIo,
        plan: &mut AttachPlan,
        reservation: BankReservation,
        reserve: &SemanticResourceReserver,
    ) -> (BankPublication, Option<&'static str>) {
        let mut check = None;
        let publication = self.stage_with_checked(io, plan, reservation, reserve, &mut check);
        (publication, check)
    }

    fn stage_with_checked(
        &mut self,
        io: &mut impl BankIo,
        plan: &mut AttachPlan,
        reservation: BankReservation,
        reserve: &SemanticResourceReserver,
        check: &mut Option<&'static str>,
    ) -> BankPublication {
        if self.quarantined {
            return BankPublication::Refused(BankRefusal::Quarantined);
        }
        if let Err((reason, failed)) = self.validate_plan_detailed(plan) {
            *check = failed;
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
            *check = Some(COUNTER_CHECK_DUPLICATE);
            return BankPublication::Refused(BankRefusal::Topology);
        }
        let mut published = Vec::with_capacity(self.positions.len());
        published.extend(self.published_indices());
        if let Err(reason) =
            io.validate_targets(&plan.slots, &published, extent, self.positions.capacity())
        {
            if reason == BankRefusal::Topology {
                *check = io.last_check();
            }
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
        if let Err(error) = plan.consume_counter_extent(first, end) {
            *check = Some(consume_check_name(error));
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

/// Crate-visible (6.15) so the selected-detail adapter can name the banks
/// handle its reserve/close entry points take. The handle's methods keep
/// their own narrow visibility; only the gate's reserve/close surface is
/// `pub(crate)`. No logic change: widening the handle type alone.
pub(crate) struct CounterBanks {
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
        Self::new_with_backend_probe_and_cpus(object, envelope, reserve, backend, probe, None)
    }

    fn new_with_backend_probe_and_cpus(
        object: &'a [u8],
        envelope: BankReservation,
        reserve: &SemanticResourceReserver,
        backend: super::AttachBackend,
        probe: impl FnOnce() -> BpfLoopVerdict,
        cpus_override: Option<usize>,
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
        // The memory preflight and the terminal reserve run before any pool
        // reservation, so a fixed-exceeds request fails before keepalive or
        // scratch can charge.
        // Production reads the host count; tests inject counts no host
        // reaches (fixed-exceeds preflight) through the seam.
        let cpus = match cpus_override {
            Some(cpus) => cpus,
            None => aya::util::nr_cpus().map_err(|(path, error)| {
                anyhow::Error::new(error)
                    .context(format!("reading possible counter CPUs at {path}"))
            })?,
        };
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

/// The native target gate behind `validate_targets`: session liveness,
/// backend, scope, pin stability and CPU continuity, in short-circuit
/// order. A free function so unit tests can pin every predicate without a
/// Session; the refusal is always a bare `Topology`, named here.
/// Counter staging admits the session scopes whose links it can bound:
/// one process (PID) and all processes (cgroup/system, enforced by the
/// in-BPF scope gate; link counts are offset-based and scope-independent).
/// The diagnostic-only calling-process scope is never a session scope.
fn counter_scope_admitted(scope: aya::programs::uprobe::UProbeScope) -> bool {
    use aya::programs::uprobe::UProbeScope::{AllProcesses, OneProcess};
    matches!(scope, OneProcess(_) | AllProcesses)
}

fn native_target_gate(
    stopped: bool,
    backend_ok: bool,
    scope_admitted: bool,
    unchanged_ok: bool,
    cpus_now: Option<usize>,
    cpus_expected: usize,
) -> Result<(), &'static str> {
    if stopped {
        return Err(COUNTER_CHECK_SESSION_STOPPED);
    }
    if !backend_ok {
        return Err(COUNTER_CHECK_BACKEND);
    }
    if !scope_admitted {
        return Err(COUNTER_CHECK_SCOPE);
    }
    if !unchanged_ok {
        return Err(COUNTER_CHECK_UNCHANGED);
    }
    if cpus_now != Some(cpus_expected) {
        return Err(COUNTER_CHECK_CPUS);
    }
    Ok(())
}

struct NativeIo<'a> {
    session: &'a mut Session,
    objects: &'a PinnedObjects,
    custody: &'a mut NativeCustody,
    cpus: usize,
    geometry: BankGeometry,
    reservation: BankReservation,
    last_check: Option<&'static str>,
}

impl NativeIo<'_> {
    /// `validate_targets` with the failing `Topology` gate predicate named.
    /// Non-Topology refusals carry no name.
    fn validate_targets_detailed(
        &mut self,
        slots: &[Slot],
        published: &[u32],
        fresh: BankExtent,
        old_capacity: usize,
    ) -> Result<(), (BankRefusal, Option<&'static str>)> {
        let stopped = self.session.mutation_stopped();
        let backend_ok = self
            .session
            .counter_banks
            .as_ref()
            .is_some_and(|banks| banks.validate_backend(self.session.backend).is_ok());
        let scope_admitted = counter_scope_admitted(self.session.uprobe_scope);
        let unchanged_ok = self.objects.check_unchanged() == Ok(true);
        let cpus_now = aya::util::nr_cpus().ok();
        if let Err(check) = native_target_gate(
            stopped,
            backend_ok,
            scope_admitted,
            unchanged_ok,
            cpus_now,
            self.cpus,
        ) {
            return Err((BankRefusal::Topology, Some(check)));
        }
        validate_maps(&self.session.ebpf, self.geometry).map_err(|refusal| (refusal, None))?;
        if self.custody.charges.len() == self.custody.charges.capacity() {
            return Err((BankRefusal::Budget, None));
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
            .ok_or((BankRefusal::Budget, None))?;
        let (retained, transient, metadata, fds) = stage_requirements(
            self.geometry,
            slots,
            fresh,
            old_capacity,
            self.cpus,
            new_banks,
            provider_copies,
            16,
        )
        .map_err(|refusal| (refusal, None))?;
        check_counter_stage_reservation(self.reservation, (retained, transient, metadata, fds))
            .map_err(|refusal| (refusal, None))?;
        if self.session.backend == super::AttachBackend::Multi {
            check_counter_multi_reservation(
                self.reservation,
                (retained, transient, metadata, fds),
                &slots[fresh.first as usize..fresh.end as usize],
                self.session.links.len(),
                self.session.links.capacity(),
            )
            .map_err(|refusal| (refusal, None))?;
        }
        check_fd_headroom_with(fds, read_fd_snapshot).map_err(|refusal| (refusal, None))?;
        validate_provider_union(slots, published, fresh, self.objects, self.custody, false)
            .map_err(|refusal| (refusal, None))
    }
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
        let result = self.validate_targets_detailed(slots, published, fresh, old_capacity);
        self.last_check = result.as_ref().err().and_then(|(_, check)| *check);
        result.map_err(|(refusal, _)| refusal)
    }

    fn last_check(&self) -> Option<&'static str> {
        self.last_check
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
        // Separate lane, separate watches: the counter session never ends
        // pre-arm watches, so its ended set is always empty.
        let (failed, mut completed) = self
            .session
            .attach_targets(slots, self.objects, &BTreeSet::new())
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
            || !counter_scope_admitted(self.session.uprobe_scope)
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

/// Named refusal for a counter program the kernel verifier rejects
/// as too complex: shared by the start-path mapping and the doctor
/// load preflight so both name one token.
const COUNTER_VERIFIER_BUDGET_REFUSAL: &str = "counter-mode-unavailable-on-kernel: the kernel verifier rejected a counter program as too complex (E2BIG)";

/// Finite refusal for a counter-object preflight load failure: only a
/// genuine program-load E2BIG becomes the old-kernel token; any other
/// failure names its errno class (or a static fallback when no errno is
/// present) so callers treat it as unproven instead of refused. The loader
/// error itself is never rendered: its Display can carry the verifier log.
fn counter_load_refusal(error: &anyhow::Error) -> String {
    // The token needs a genuine BPF_PROG_LOAD E2BIG, as
    // `map_counter_verifier_budget_refusal` checks: a map-create E2BIG or a
    // bare io E2BIG is unproven and keeps its own error.
    let budget = error.chain().any(|cause| {
        cause
            .downcast_ref::<aya::programs::ProgramError>()
            .is_some_and(|program| {
                matches!(
                    program,
                    aya::programs::ProgramError::LoadError { io_error, .. }
                    if super::is_verifier_budget_errno(io_error.raw_os_error())
                )
            })
    });
    if budget {
        return COUNTER_VERIFIER_BUDGET_REFUSAL.to_string();
    }
    let io_error = error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .last();
    match io_error {
        Some(io) => format!("counter object load failed ({io})"),
        None => "counter object load failed before the verifier ran".to_string(),
    }
}

/// Doctor load preflight for one counter object: runs the production
/// preparation for the mode (spec envelope, kernel gates, object load,
/// program loads) and releases it without attaching anything, so the
/// doctor counter line reports the kernel verifier's real verdict.
/// Named counter refusals from the gates are real verdicts; only the
/// verifier's own E2BIG from the load proves a load refusal, and any
/// other failure is unproven. Map creation alone would prove nothing:
/// aya loads programs explicitly after the object loads.
pub(crate) fn counter_object_preflight(mode: CounterMode) -> Result<(), String> {
    // A doctor-owned pool funds preparation exactly like the capture
    // pool; the pool charges without allocating.
    let pool = SemanticResourcePool::with_limit(1024 * 1024 * 1024);
    let cpus = aya::util::nr_cpus()
        .map_err(|(_, error)| format!("counter object load failed ({error})"))?;
    let spec = CounterSpec::for_production(mode, cpus, pool.reserver())
        .map_err(|refusal| format!("counter object load failed ({refusal:?})"))?;
    // System-like backend selection (the primary counter path), the
    // same functional probe production uses.
    let backend = super::select_session_backend(
        super::BackendSelection::Auto,
        false,
        super::multi_functional_probe,
        super::kernel_multi_pid_filter,
    )
    .map_err(|error| counter_load_refusal(&error))?
    .backend;
    let prepared = spec.prepare(backend).map_err(|error| {
        let text = format!("{error:#}");
        if text.starts_with("counter-mode-") || text.starts_with("counter-memory-limit") {
            text.lines().next().unwrap_or(&text).to_string()
        } else {
            counter_load_refusal(&error)
        }
    })?;
    let scope = Scope::Pid(std::process::id());
    super::Session::prepare_inner_unlinked_with_object(
        &scope,
        CapturePolicy::Counter(mode),
        None,
        None,
        None,
        backend,
        None,
        Some(prepared),
        None,
    )
    .map(|_| ())
    .map_err(|error| counter_load_refusal(&error))
}

/// Whether the error chain already carries a named `counter-mode-*`
/// refusal (the old-kernel token, the build token, or a mapped
/// verifier-budget refusal). Any chain link counts: intermediate
/// context may wrap the token without renaming it.
fn is_counter_mode_refusal(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().starts_with("counter-mode-"))
}

/// Production counter-start error mapping for `start_on_backend`: a
/// verifier-budget E2BIG becomes the named old-kernel token, and any
/// `counter-mode-*` refusal returns without the generic environment
/// hint (the token already names the cause; a CAP_BPF/kernel-floor
/// hint would mislead a root user on a supported kernel). Every
/// other error keeps the generic hint through the shared wrapper.
pub(super) fn map_counter_start_error(error: anyhow::Error) -> anyhow::Error {
    let mapped = map_counter_verifier_budget_refusal(error);
    if is_counter_mode_refusal(&mapped) {
        mapped
    } else {
        super::unsupported_environment_context(mapped)
    }
}

/// Maps a kernel verifier-budget rejection during counter preparation to
/// the named counter-mode refusal. Only a genuine BPF_PROG_LOAD E2BIG (the
/// program is too complex for this kernel's verifier) is rewritten, with a
/// finite reason that never embeds the raw verifier log; every other error
/// passes through unchanged. Detection downcasts to a genuine program-load
/// refusal, as `is_verifier_budget_refusal` does: any other E2BIG in the
/// chain (a map-create E2BIG, a bare io error) keeps its own error.
fn map_counter_verifier_budget_refusal(error: anyhow::Error) -> anyhow::Error {
    let budget = error.chain().any(|cause| {
        cause
            .downcast_ref::<aya::programs::ProgramError>()
            .is_some_and(|program| {
                matches!(
                    program,
                    aya::programs::ProgramError::LoadError { io_error, .. }
                    if super::is_verifier_budget_errno(io_error.raw_os_error())
                )
            })
    });
    if budget {
        anyhow::anyhow!("{COUNTER_VERIFIER_BUDGET_REFUSAL}")
    } else {
        error
    }
}

/// Resource name for the counter endpoint ceiling `BudgetExhausted`
/// refusal: growth past the ceiling refuses with the requested and
/// ceiling counts. The Engine growth refusal text renders this resource
/// in plain words.
pub(crate) const COUNTER_ENDPOINT_CEILING_RESOURCE: &str = "counter endpoints";

/// Over-ceiling refusal for counter growth: when the candidate plan holds
/// more slots than the endpoint budget or the bank geometry allows, the
/// budget refuses with the requested and ceiling counts. Returns `None`
/// when the plan fits, so callers build extents only for in-budget plans.
/// The predicate matches validate_plan_detailed's budget arm (over iff
/// longer than the smaller of the budget and geometry limits); only the
/// refusal value carries the counts.
fn counter_growth_ceiling_refusal(
    slots: usize,
    budget: crate::capacity::CounterBudget,
    geometry: BankGeometry,
) -> Option<BankRefusal> {
    let Ok(needed) = u64::try_from(slots) else {
        return Some(BankRefusal::Budget);
    };
    let ceiling = budget.endpoint_limit().min(u64::from(geometry.limit()));
    if needed > ceiling {
        Some(BankRefusal::BudgetExhausted {
            resource: COUNTER_ENDPOINT_CEILING_RESOURCE,
            needed,
            available: ceiling,
        })
    } else {
        None
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
                    None,
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
            None,
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

    /// Check name for the last staging call when it refused a bare
    /// `Topology`, `None` otherwise. Lets an Engine counter start say which
    /// check failed; refusal values are unchanged.
    pub(crate) fn last_counter_stage_check(&self) -> Option<&'static str> {
        self.last_counter_stage_check
    }

    pub(crate) fn stage_counter_banks(
        &mut self,
        plan: &mut AttachPlan,
        objects: &PinnedObjects,
        reservation: BankReservation,
        reserve: &SemanticResourceReserver,
    ) -> BankPublication {
        self.last_counter_stage_check = None;
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
            last_check: None,
        };
        let (publication, check) =
            directory.stage_with_detailed(&mut native, plan, reservation, reserve);
        self.last_counter_stage_check = check;
        publication
    }

    /// Engine-driven growth staging: size this extent's envelope from live
    /// directory, custody and link state (both new-bank counts, provider
    /// copies, Multi link facts) and publish through the standard
    /// transaction. Appends only; refusals leave the published prefix
    /// intact.
    pub(crate) fn stage_counter_growth(
        &mut self,
        plan: &mut AttachPlan,
        objects: &PinnedObjects,
        reserve: &SemanticResourceReserver,
    ) -> BankPublication {
        self.last_counter_stage_check = None;
        let Some(banks) = self.counter_banks.as_ref() else {
            return BankPublication::Refused(BankRefusal::Shape(
                BankShapeCause::StagedWithoutBanks,
            ));
        };
        let geometry = banks.geometry;
        let cpus = banks.cpus;
        // Lock order matches stage_with (directory, then custody); both are
        // released before the delegation below re-acquires them.
        let directory = match banks.directory.lock() {
            Ok(directory) => directory,
            Err(_) => return BankPublication::Refused(BankRefusal::Quarantined),
        };
        if directory.geometry != geometry {
            return BankPublication::Refused(BankRefusal::Shape(
                BankShapeCause::StagedGeometryChanged,
            ));
        };
        // Rebuilt candidate plans start unconsumed; restore the staged
        // prefix from the directory high-water before consuming the tail.
        if plan.counter_consumed_end() == 0 {
            let high_water = directory.allocated_high_water();
            if high_water != 0 && plan.adopt_counter_consumed(high_water as u32).is_err() {
                drop(directory);
                self.last_counter_stage_check = Some(COUNTER_CHECK_ADOPT);
                return BankPublication::Refused(BankRefusal::Topology);
            }
        }
        let first = directory.allocated_high_water();
        let end = plan.slots.len();
        if first == end {
            return BankPublication::Refused(BankRefusal::Allocated);
        }
        // The plan budget precedes the extent shape: growth past the
        // endpoint ceiling refuses with the budget (carrying the
        // requested and ceiling counts) instead of a shape error, so the
        // refusal names the honest cause. ExtentBounds stays for
        // genuinely misshapen extents within the ceiling.
        let crate::plan::AdmissionPolicy::Counters(budget) = plan.admission_policy() else {
            drop(directory);
            return BankPublication::Refused(BankRefusal::Shape(BankShapeCause::PlanNotCounters));
        };
        if let Some(refusal) = counter_growth_ceiling_refusal(plan.slots.len(), budget, geometry) {
            drop(directory);
            return BankPublication::Refused(refusal);
        }
        let extent = match BankExtent::checked(first as u32, end as u32, geometry.limit()) {
            Ok(extent) => extent,
            Err(reason) => return BankPublication::Refused(reason),
        };
        let old_capacity = directory.positions.capacity();
        let directory_new_banks = (0..geometry.banks as usize)
            .filter(|&bank| {
                directory.bank_ids.get(bank).copied().flatten().is_none()
                    && bank >= (extent.first / geometry.cells) as usize
                    && bank <= ((extent.end - 1) / geometry.cells) as usize
            })
            .count();
        let custody = match banks.keepalive.custody.lock() {
            Ok(custody) => custody,
            Err(_) => return BankPublication::Refused(BankRefusal::Quarantined),
        };
        let custody_new_banks = (extent.first / geometry.cells..=(extent.end - 1) / geometry.cells)
            .filter(|&bank| custody.banks[bank as usize].is_none())
            .count();
        let new_banks = directory_new_banks.max(custody_new_banks);
        let provider_copies = plan.slots[extent.first as usize..extent.end as usize]
            .iter()
            .try_fold(0usize, |bytes, slot| {
                if self.has_slot_link(slot.index)
                    || custody
                        .providers
                        .get(slot.index as usize)
                        .is_none_or(Option::is_some)
                {
                    return None;
                }
                bytes.checked_add(
                    objects
                        .retained_target_copy_allocation_charge(slot.object)?
                        .checked_mul(4)?,
                )
            });
        let Some(provider_copies) = provider_copies else {
            return BankPublication::Refused(BankRefusal::Budget);
        };
        let multi_links = (self.backend == super::AttachBackend::Multi)
            .then(|| (self.links.len(), self.links.capacity()));
        drop(custody);
        drop(directory);
        let reservation = match estimate_counter_stage_reservation(
            geometry.mode(),
            geometry.banks,
            geometry.cells,
            &plan.slots,
            extent.first,
            extent.end,
            old_capacity,
            cpus,
            new_banks,
            provider_copies,
            multi_links,
        ) {
            Ok(reservation) => reservation,
            Err(reason) => {
                // Only the zero-CPU arm yields Topology; Shape and Budget
                // refusals already name themselves.
                if reason == BankRefusal::Topology {
                    self.last_counter_stage_check = Some(COUNTER_CHECK_SIZING_CPUS);
                }
                return BankPublication::Refused(reason);
            }
        };
        self.stage_counter_banks(plan, objects, reservation, reserve)
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
        // Parent §3 FD row: Singles projects 2*published + banks + 1, Multi
        // projects 2*published + banks.
        let extra = match self.backend {
            super::AttachBackend::Singles => 1,
            super::AttachBackend::Multi => 0,
        };
        let projected = published
            .checked_mul(2)
            .and_then(|n| n.checked_add(allocated_banks))
            .and_then(|n| n.checked_add(extra))
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

// ---- selected-detail toggle (A2.8, R5) ----

/// Why a selected-detail window refused to open against a broad counter
/// Session (parent contracts §2 toggle refusal row). Every refusal
/// precedes any child native work: a refused open attaches no links and
/// charges nothing, and broad keeps counting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetailToggleRefusal {
    /// The broad Session carries no counter banks.
    BroadNotCounter,
    /// The broad Session is stopping or detached.
    BroadStopping,
    /// The child spec is not a Detailed child: no endpoints or more
    /// than [`MAX_SLOTS`].
    ChildShape,
    /// The selection is not a published broad row (out of range,
    /// pending, retired, or no longer naming its published key).
    NotPublished,
    /// The child names another kernel file than the broad retained
    /// provider, does not cover the selected endpoint, or names ids
    /// unresolvable in the given store.
    Foreign,
    /// The retained provider changed under the pin (broad or child side).
    Changed,
    /// Broad is quarantined (flag or poisoned locks).
    Quarantined,
    /// The child start charge was refused (bytes or FD headroom).
    Budget,
}

/// How a closed window's broad identity drifted from its open mark. Close
/// always delivers the lineage; the drift names the first mismatch in
/// generation/indices/bank-ids/transaction order, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DetailToggleDrift {
    Generation {
        before: NonZeroU64,
        after: NonZeroU64,
    },
    Indices {
        before: Vec<u32>,
        after: Vec<u32>,
    },
    BankIds {
        bank: u32,
        before: Option<u32>,
        after: Option<u32>,
    },
    Transaction {
        before: Option<NonZeroU64>,
        after: Option<NonZeroU64>,
    },
}

/// The broad Session facts one window opens against: its collection
/// generation and whether it already stopped. The [`Session`] wrapper
/// reads both from the live Session; scripted callers pass them in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BroadToggleFacts {
    pub(crate) generation: NonZeroU64,
    pub(crate) stopped: bool,
}

/// Sized start charge for one Detailed child (R6 selected-detail child
/// row): the child's own maps in bytes plus its link/pin/map FDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DetailChildEnvelope {
    pub(crate) bytes: usize,
    pub(crate) file_descriptors: usize,
}

/// Fixed control block inside the child start envelope: SELECTED_DETAIL /
/// SELECTED_BCTL / SELECTED_STATE cells, SLOT_FILE, META/COMMIT/FAULT/HEALTH
/// heads, control maps and the generation/lease overhead. An admission
/// envelope like [`BankReservation`]'s metadata bytes, not a kernel census.
const DETAIL_CHILD_CONTROL_BYTES: usize = 64 * 1024;
/// Worst-case link FDs per child endpoint: entry+return. Singles attaches
/// exactly this; Multi attaches fewer (shared multi links), so the
/// envelope covers both backends.
const DETAIL_CHILD_LINK_FDS_PER_ENDPOINT: usize = 2;
/// Map/pin/pidfd FD slack inside the child envelope: the Detailed map set,
/// provider pins, pidfds and headroom. An admission envelope.
const DETAIL_CHILD_FD_SLACK: usize = 64;
/// Provider-copy overlap multiplier, mirroring growth staging's per-slot
/// retained-copy charge (old+new overlap in native validation).
const DETAIL_CHILD_COPY_OVERLAP: usize = 4;

/// Size one Detailed child's start charge: the full child maps (the child
/// loads the full Detailed shape regardless of its endpoint count) plus
/// per-endpoint provider copies and worst-case link FDs.
pub(crate) fn detail_child_envelope(
    child_slots: &[Slot],
    objects: &PinnedObjects,
    cpus: usize,
) -> Result<DetailChildEnvelope, DetailToggleRefusal> {
    let endpoints = child_slots.len();
    if endpoints == 0 || endpoints > MAX_SLOTS as usize {
        return Err(DetailToggleRefusal::ChildShape);
    }
    if cpus == 0 {
        return Err(DetailToggleRefusal::Budget);
    }
    let stats = (MAX_SLOTS as usize)
        .checked_mul(size_of::<SlotStats>())
        .and_then(|row| row.checked_mul(cpus))
        .ok_or(DetailToggleRefusal::Budget)?;
    let start = (START_ENTRIES as usize)
        .checked_mul(16 + size_of::<CallStart>())
        .ok_or(DetailToggleRefusal::Budget)?;
    let rv = (RV_ENTRIES as usize)
        .checked_mul(
            16usize
                .checked_add(
                    8usize
                        .checked_mul(cpus)
                        .ok_or(DetailToggleRefusal::Budget)?,
                )
                .ok_or(DetailToggleRefusal::Budget)?,
        )
        .ok_or(DetailToggleRefusal::Budget)?;
    let mut bytes = stats
        .checked_add(start)
        .and_then(|sum| sum.checked_add(rv))
        .and_then(|sum| sum.checked_add(RING_BYTES as usize))
        .and_then(|sum| sum.checked_add(DETAIL_CHILD_CONTROL_BYTES))
        .ok_or(DetailToggleRefusal::Budget)?;
    for slot in child_slots {
        let copy = objects
            .retained_target_copy_allocation_charge(slot.object)
            .ok_or(DetailToggleRefusal::Budget)?;
        bytes = bytes
            .checked_add(
                copy.checked_mul(DETAIL_CHILD_COPY_OVERLAP)
                    .ok_or(DetailToggleRefusal::Budget)?,
            )
            .ok_or(DetailToggleRefusal::Budget)?;
    }
    let file_descriptors = endpoints
        .checked_mul(DETAIL_CHILD_LINK_FDS_PER_ENDPOINT)
        .and_then(|links| links.checked_add(DETAIL_CHILD_FD_SLACK))
        .ok_or(DetailToggleRefusal::Budget)?;
    Ok(DetailChildEnvelope {
        bytes,
        file_descriptors,
    })
}

/// One broad read bracketing a detail window: the window's ordinal plus
/// the broad identity bound to that read (generation, published original
/// indices, allocated bank inner ids, directory waterline).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BroadReadMark {
    pub(crate) seq: u64,
    pub(crate) generation: NonZeroU64,
    pub(crate) indices: Vec<u32>,
    pub(crate) bank_ids: Vec<(u32, u32)>,
    pub(crate) transaction: Option<NonZeroU64>,
}

/// Lineage joining one detail window's rows to its broad rows (parent
/// contracts §2): broad identity, the detail generation and the two
/// bracketing broad reads. Carries no sums: broad totals render only
/// from broad reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CounterDetailLineage {
    pub(crate) broad_generation: NonZeroU64,
    pub(crate) broad_original_index: u32,
    pub(crate) broad_physical: AttachKey,
    pub(crate) detail_generation: u64,
    pub(crate) broad_read_seq_before: u64,
    pub(crate) broad_read_seq_after: u64,
    pub(crate) broad_mark_before: BroadReadMark,
    pub(crate) broad_mark_after: BroadReadMark,
}

/// First broad-identity mismatch between the open mark and a later mark,
/// in generation/indices/bank-ids/transaction order. An appended index
/// tail, appended banks, an advanced waterline and exhaustion past the
/// open mark all verify clean: the prefix is what must hold.
fn verify_broad_mark(before: &BroadReadMark, after: &BroadReadMark) -> Option<DetailToggleDrift> {
    if before.generation != after.generation {
        return Some(DetailToggleDrift::Generation {
            before: before.generation,
            after: after.generation,
        });
    }
    if after.indices.len() < before.indices.len()
        || after.indices[..before.indices.len()] != before.indices[..]
    {
        return Some(DetailToggleDrift::Indices {
            before: before.indices.clone(),
            after: after.indices.clone(),
        });
    }
    for (bank, id) in &before.bank_ids {
        let current = after
            .bank_ids
            .iter()
            .find_map(|(other, other_id)| (*other == *bank).then_some(*other_id));
        if current != Some(*id) {
            return Some(DetailToggleDrift::BankIds {
                bank: *bank,
                before: Some(*id),
                after: current,
            });
        }
    }
    let orders = match (before.transaction, after.transaction) {
        (Some(first), Some(second)) => second >= first,
        (Some(_), None) => true,
        (None, None) => true,
        (None, Some(_)) => false,
    };
    if !orders {
        return Some(DetailToggleDrift::Transaction {
            before: before.transaction,
            after: after.transaction,
        });
    }
    None
}

impl FdSnapshot {
    #[cfg(test)]
    fn scripted(soft: u64, observed: u64) -> Self {
        Self {
            soft_limit: FdLimit::Finite(soft),
            observed_open: observed,
        }
    }

    #[cfg(test)]
    fn scripted_unlimited(observed: u64) -> Self {
        Self {
            soft_limit: FdLimit::Unlimited,
            observed_open: observed,
        }
    }
}

/// Admit the child start FDs against one snapshot: exact headroom passes,
/// a short soft limit and unreadable state refuse with Budget.
fn admit_detail_child_fds(
    file_descriptors: usize,
    read: impl FnOnce() -> Result<FdSnapshot, BankRefusal>,
) -> Result<(), DetailToggleRefusal> {
    check_fd_headroom_with(file_descriptors, read).map_err(|_| DetailToggleRefusal::Budget)
}

/// One outstanding detail-window admission (M3 product rule): the
/// custody attaches one when it places a reservation, and it travels
/// with the reservation/window through take, bind and park until the
/// terminal close/abandon — so a taken window still occupies
/// admission. Move-only (no `Clone`): exactly one holder per
/// admission. Dropping releases admission (fail-safe against a
/// permanent `WindowActive`) but emits no ledger event: the driver
/// still owes exactly one explicit terminal (close, abandon, or a
/// recorded close-refused entry) for the window ledger.
pub(crate) struct AdmissionGuard {
    live: Arc<AtomicUsize>,
}

impl AdmissionGuard {
    /// Mint one admission against the custody's shared counter.
    pub(crate) fn mint(shared: &Arc<AtomicUsize>) -> Self {
        shared.fetch_add(1, Ordering::SeqCst);
        Self {
            live: Arc::clone(shared),
        }
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for AdmissionGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdmissionGuard(<held>)")
    }
}

/// A reserved (not yet bound) selected-detail window (6.15 split): the
/// before-mark, the selection and the start-charge lease, plus the
/// retained identity needed to re-validate at bind time WITHOUT banks
/// access (the bind seam holds no broad handle): the child slot keys,
/// one retained live target per distinct child object (shared live
/// file handles, so unchanged checks stay live), and a share of the
/// broad retained target the selection was proved against. Binding
/// assigns the sealed detail generation; abandoning releases the
/// charge with no lineage (a never-bound reservation joins nothing).
/// The admission guard (attached at custody placement) travels into
/// the bound window.
pub(crate) struct DetailWindowReservation {
    before: BroadReadMark,
    selected: u32,
    physical: AttachKey,
    child_keys: Vec<AttachKey>,
    child_targets: Vec<(PinnedObjectId, RetainedInventoryTarget)>,
    broad: RetainedInventoryTarget,
    admission: Option<AdmissionGuard>,
    _charge: ResourceLease,
}

impl std::fmt::Debug for DetailWindowReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetailWindowReservation")
            .field("before", &self.before)
            .field("selected", &self.selected)
            .field("physical", &self.physical)
            .field("retained", &"<held>")
            .field("admitted", &self.admission.is_some())
            .field("_charge", &"<held>")
            .finish()
    }
}

/// What abandoning a never-bound reservation returns: the selection it
/// held, for the window ledger. The charge releases on drop; there is
/// no lineage (no detail generation was ever bound, no detail ran).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReservationAbandonment {
    pub(crate) before: BroadReadMark,
    pub(crate) selected: u32,
    pub(crate) physical: AttachKey,
}

impl DetailWindowReservation {
    pub(crate) fn selected(&self) -> u32 {
        self.selected
    }

    pub(crate) fn physical(&self) -> AttachKey {
        self.physical
    }

    pub(crate) fn mark_before(&self) -> &BroadReadMark {
        &self.before
    }

    /// Attach the custody's admission guard at placement (the gate
    /// mints none: admission starts when the reservation is placed,
    /// never while it is still a local value).
    pub(crate) fn admit(&mut self, guard: AdmissionGuard) {
        assert!(
            self.admission.is_none(),
            "a reservation admits exactly once, at placement"
        );
        self.admission = Some(guard);
    }

    /// Bind the sealed detail generation (R2-D2-B order: generation
    /// first, then validate). Pure assignment: moves the marks, the
    /// selection, the retained identity, the admission guard and the
    /// charge into the window. Every check runs after, in
    /// [`CounterDetailWindow::validate_live_match`] plus the
    /// adapter's own binding checks, so a refused bind still parks a
    /// closeable `Unactivated` window instead of dropping the lease.
    pub(crate) fn bind_generation(mut self, generation: u64) -> CounterDetailWindow {
        CounterDetailWindow {
            before: self.before,
            selected: self.selected,
            physical: self.physical,
            detail_generation: generation,
            child_keys: self.child_keys,
            child_targets: self.child_targets,
            broad: self.broad,
            admission: self.admission.take(),
            _charge: self._charge,
        }
    }

    /// Abandon a never-bound reservation (cancel / preparation
    /// failure / refused reselect): return the held selection for the
    /// ledger and release the charge and the admission. No lineage:
    /// nothing ran.
    pub(crate) fn abandon(self) -> ReservationAbandonment {
        ReservationAbandonment {
            before: self.before,
            selected: self.selected,
            physical: self.physical,
        }
    }
}

/// Whether a retained child target is the broad retained object:
/// equal non-empty digest, equal pin, and the same kernel file behind
/// both fds. The pin-store comparison's target-vs-target form (the
/// store form additionally short-circuits on equal mappings, which
/// implies the same kernel file; an fstat failure here refuses
/// fail-closed instead).
fn retained_same_object(child: &RetainedInventoryTarget, broad: &RetainedInventoryTarget) -> bool {
    let (_, child_digest) = child.borrowed_file_and_digest();
    let (_, broad_digest) = broad.borrowed_file_and_digest();
    !broad_digest.is_empty()
        && child_digest == broad_digest
        && child.content_key() == broad.content_key()
        && retained_same_kernel_file(child, broad)
}

/// Whether two retained targets name the same kernel file (an fstat
/// pair on the two fds), whatever their pins or digests say. An
/// in-place rewrite keeps the kernel file; anything else does not.
/// Unreadable state refuses fail-closed.
fn retained_same_kernel_file(
    left: &RetainedInventoryTarget,
    right: &RetainedInventoryTarget,
) -> bool {
    let (left_file, _) = left.borrowed_file_and_digest();
    let (right_file, _) = right.borrowed_file_and_digest();
    match (left_file.metadata(), right_file.metadata()) {
        (Ok(left), Ok(right)) => left.dev() == right.dev() && left.ino() == right.ino(),
        _ => false,
    }
}

/// An open selected-detail window against one broad counter Session: the
/// before-mark, the selection, the bound detail generation, the
/// retained bind-time identity and the start-charge lease, held until
/// close. The admission guard travels with the window until close.
pub(crate) struct CounterDetailWindow {
    before: BroadReadMark,
    selected: u32,
    physical: AttachKey,
    detail_generation: u64,
    child_keys: Vec<AttachKey>,
    child_targets: Vec<(PinnedObjectId, RetainedInventoryTarget)>,
    broad: RetainedInventoryTarget,
    admission: Option<AdmissionGuard>,
    _charge: ResourceLease,
}

impl std::fmt::Debug for CounterDetailWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CounterDetailWindow")
            .field("before", &self.before)
            .field("selected", &self.selected)
            .field("physical", &self.physical)
            .field("detail_generation", &self.detail_generation)
            .field("retained", &"<held>")
            .field("admitted", &self.admission.is_some())
            .field("_charge", &"<held>")
            .finish()
    }
}

impl CounterDetailWindow {
    pub(crate) fn selected(&self) -> u32 {
        self.selected
    }

    pub(crate) fn physical(&self) -> AttachKey {
        self.physical
    }

    pub(crate) fn detail_generation(&self) -> u64 {
        self.detail_generation
    }

    pub(crate) fn mark_before(&self) -> &BroadReadMark {
        &self.before
    }

    /// Attach the custody's admission guard when parking a window that
    /// arrived without one (bound windows normally inherit it from
    /// their reservation; this covers only defensively built ones).
    pub(crate) fn admit_unadmitted(&mut self, guard: AdmissionGuard) {
        if self.admission.is_none() {
            self.admission = Some(guard);
        }
    }

    /// Re-validate the reservation against live files at bind time
    /// (R2-D2-B, owned-data half): the broad retained target is
    /// unchanged, every retained child target is unchanged and still
    /// names the same retained object, some child slot still covers
    /// the reserved physical key, and FD headroom still admits the
    /// child. What this cannot see (no banks access at the bind seam
    /// — no live directory, no stopped flag) the close discloses as
    /// drift, or the lifecycle's cancel check owns; see the adapter.
    pub(crate) fn validate_live_match(&self) -> Result<(), DetailToggleRefusal> {
        // Broad side first: the retained share live-checks its shared
        // file handle, exactly as the reserve-time held target did.
        if self.broad.check_unchanged() != Ok(true) {
            return Err(DetailToggleRefusal::Changed);
        }
        // Per retained child slot: unchanged, then same retained
        // object (a changed same-file digest reports Changed;
        // another file is Foreign) — the reserve checks, re-run
        // against the retained per-object targets.
        let mut covered = false;
        for key in &self.child_keys {
            let (_, target) = self
                .child_targets
                .iter()
                .find(|(id, _)| *id == key.object)
                .expect("retained targets cover every distinct child id");
            if target.check_unchanged() != Ok(true) {
                return Err(DetailToggleRefusal::Changed);
            }
            if !retained_same_object(target, &self.broad) {
                if retained_same_kernel_file(target, &self.broad) {
                    return Err(DetailToggleRefusal::Changed);
                }
                return Err(DetailToggleRefusal::Foreign);
            }
            covered |= key.file_offset == self.physical.file_offset;
        }
        if !covered {
            return Err(DetailToggleRefusal::Foreign);
        }
        // FD headroom re-check (admission only; the byte charge is
        // already held from reserve).
        let links = self
            .child_keys
            .len()
            .checked_mul(DETAIL_CHILD_LINK_FDS_PER_ENDPOINT)
            .ok_or(DetailToggleRefusal::Budget)?;
        let fds = links
            .checked_add(DETAIL_CHILD_FD_SLACK)
            .ok_or(DetailToggleRefusal::Budget)?;
        admit_detail_child_fds(fds, read_fd_snapshot)?;
        Ok(())
    }

    /// Close the window against live broad banks: record the after-mark
    /// and report the first identity drift, if any. The lineage always
    /// delivers (rows still join through it); poisoned locks refuse with
    /// Quarantined rather than fabricating the after-mark.
    /// `read_seq_after` is the driver's final successful-observe seq
    /// (R2-D2-C seq injection): the mark carries it, the gate mints
    /// nothing.
    pub(crate) fn close(
        self,
        banks: &CounterBanks,
        generation: NonZeroU64,
        read_seq_after: u64,
    ) -> Result<(CounterDetailLineage, Option<DetailToggleDrift>), DetailToggleRefusal> {
        let directory = banks
            .directory
            .lock()
            .map_err(|_| DetailToggleRefusal::Quarantined)?;
        let custody = banks
            .keepalive
            .custody
            .lock()
            .map_err(|_| DetailToggleRefusal::Quarantined)?;
        let after = BroadReadMark {
            seq: read_seq_after,
            generation,
            indices: directory.published_indices().collect(),
            bank_ids: custody
                .banks
                .iter()
                .enumerate()
                .filter_map(|(bank, handle)| handle.as_ref().map(|held| (bank as u32, held.id)))
                .collect(),
            transaction: directory.next_transaction,
        };
        drop(directory);
        drop(custody);
        let drift = verify_broad_mark(&self.before, &after);
        Ok((
            CounterDetailLineage {
                broad_generation: self.before.generation,
                broad_original_index: self.selected,
                broad_physical: self.physical,
                detail_generation: self.detail_generation,
                broad_read_seq_before: self.before.seq,
                broad_read_seq_after: after.seq,
                broad_mark_before: self.before,
                broad_mark_after: after,
            },
            drift,
        ))
    }

    /// Close against a live broad Session (reads its banks and
    /// generation) with the driver's final successful-observe seq.
    pub(crate) fn close_on(
        self,
        session: &Session,
        read_seq_after: u64,
    ) -> Result<(CounterDetailLineage, Option<DetailToggleDrift>), DetailToggleRefusal> {
        let Some(banks) = session.counter_banks.as_ref() else {
            return Err(DetailToggleRefusal::BroadNotCounter);
        };
        self.close(
            banks,
            session.counter_collection_generation(),
            read_seq_after,
        )
    }
}

impl CounterBanks {
    /// Poison the directory mutex so the next reserve or close refuses
    /// `Quarantined`: the unit seam for accepted-then-refused close
    /// twins in the selected-detail adapter (which cannot name the
    /// private lock). Mirrors the gate's own poison helper.
    #[cfg(test)]
    pub(crate) fn poison_directory_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.directory.lock().unwrap();
            panic!("intentional close-test poison");
        }));
        assert!(
            self.directory.is_poisoned(),
            "the mutex stays poisoned for the refused close"
        );
    }

    /// Reserve a selected-detail window (6.15 split, phase 1): validate
    /// the published selection and the child slots, charge the child's
    /// maps/FDs/links at start plus the retained bind-time identity,
    /// and snapshot broad identity for the close gate. No generation:
    /// binding assigns it at the CAS seam. `broad` carries the broad
    /// Session's own facts (the [`Session`] wrapper reads them);
    /// `objects` is the store the child slot ids resolve in; the
    /// before-mark carries the driver's `read_seq_before` (R2-D2-C seq
    /// injection): the gate mints no seqs.
    #[allow(clippy::too_many_arguments)] // One atomic reserve boundary over all facts, like the adapter orchestration.
    pub(crate) fn reserve_detail_window(
        &self,
        broad: BroadToggleFacts,
        plan: &AttachPlan,
        objects: &PinnedObjects,
        selected: u32,
        child_slots: &[Slot],
        read_seq_before: u64,
        reserve: &SemanticResourceReserver,
    ) -> Result<DetailWindowReservation, DetailToggleRefusal> {
        let directory = self
            .directory
            .lock()
            .map_err(|_| DetailToggleRefusal::Quarantined)?;
        if directory.quarantined {
            return Err(DetailToggleRefusal::Quarantined);
        }
        if broad.stopped {
            return Err(DetailToggleRefusal::BroadStopping);
        }
        if child_slots.is_empty() || child_slots.len() > MAX_SLOTS as usize {
            return Err(DetailToggleRefusal::ChildShape);
        }
        let Some(slot) = plan.slots.get(selected as usize) else {
            return Err(DetailToggleRefusal::NotPublished);
        };
        let physical = physical(slot);
        let Some(position) = directory.positions.get(selected as usize) else {
            return Err(DetailToggleRefusal::NotPublished);
        };
        if !matches!(position.state, PositionState::Published(_)) || position.key != physical {
            return Err(DetailToggleRefusal::NotPublished);
        }
        let custody = self
            .keepalive
            .custody
            .lock()
            .map_err(|_| DetailToggleRefusal::Quarantined)?;
        let Some(held) = custody
            .providers
            .get(selected as usize)
            .and_then(Option::as_ref)
        else {
            return Err(DetailToggleRefusal::NotPublished);
        };
        // The child must cover the selected endpoint: its offset on the
        // broad retained kernel file.
        let covered = child_slots.iter().any(|candidate| {
            candidate.file_offset == physical.file_offset
                && held.same_kernel_file_as(objects, candidate.object)
        });
        if !covered {
            return Err(DetailToggleRefusal::Foreign);
        }
        if held.check_unchanged() != Ok(true) {
            return Err(DetailToggleRefusal::Changed);
        }
        // Identity per child slot: unchanged, then same-object (a changed
        // same-file digest reports Changed; another file is Foreign).
        for candidate in child_slots {
            if objects.object_unchanged(candidate.object) != Ok(true) {
                return Err(DetailToggleRefusal::Changed);
            }
            if !held.same_object_as(objects, candidate.object) {
                if held.same_kernel_file_as(objects, candidate.object) {
                    return Err(DetailToggleRefusal::Changed);
                }
                return Err(DetailToggleRefusal::Foreign);
            }
        }
        let cpus = aya::util::nr_cpus().map_err(|_| DetailToggleRefusal::Budget)?;
        let envelope = detail_child_envelope(child_slots, objects, cpus)?;
        // Retention for the bind-time re-validation: the child slot
        // keys, one retained live target per distinct child object
        // (never the whole pin store: retention stays bounded to the
        // selected subset however large the convert store is), one
        // broad share, plus slop. Sized here (from the live inputs),
        // charged with the envelope in one lease; the targets retain
        // after the charge lands.
        let mut distinct = std::collections::BTreeSet::new();
        for candidate in child_slots {
            distinct.insert(candidate.object);
        }
        let mut retention = child_slots
            .len()
            .checked_mul(size_of::<AttachKey>())
            .ok_or(DetailToggleRefusal::Budget)?;
        retention = retention
            .checked_add(
                distinct
                    .len()
                    .checked_mul(size_of::<(PinnedObjectId, RetainedInventoryTarget)>())
                    .ok_or(DetailToggleRefusal::Budget)?,
            )
            .ok_or(DetailToggleRefusal::Budget)?;
        for id in &distinct {
            let copy = objects
                .retained_target_copy_allocation_charge(*id)
                .ok_or(DetailToggleRefusal::Budget)?;
            retention = retention
                .checked_add(copy)
                .ok_or(DetailToggleRefusal::Budget)?;
        }
        retention = retention
            .checked_add(
                held.retained_copy_allocation_charge()
                    .ok_or(DetailToggleRefusal::Budget)?,
            )
            .ok_or(DetailToggleRefusal::Budget)?;
        retention = retention
            .checked_add(3 * OWNED_ALLOCATION_PADDING)
            .ok_or(DetailToggleRefusal::Budget)?;
        let charge = reserve
            .reserve(
                envelope
                    .bytes
                    .checked_add(retention)
                    .ok_or(DetailToggleRefusal::Budget)?,
            )
            .map_err(|_| DetailToggleRefusal::Budget)?;
        admit_detail_child_fds(envelope.file_descriptors, read_fd_snapshot)?;
        let before = BroadReadMark {
            seq: read_seq_before,
            generation: broad.generation,
            indices: directory.published_indices().collect(),
            bank_ids: custody
                .banks
                .iter()
                .enumerate()
                .filter_map(|(bank, handle)| handle.as_ref().map(|held| (bank as u32, held.id)))
                .collect(),
            transaction: directory.next_transaction,
        };
        let mut child_keys = Vec::with_capacity(child_slots.len());
        child_keys.extend(child_slots.iter().map(|candidate| AttachKey {
            object: candidate.object,
            file_offset: candidate.file_offset,
        }));
        // Retain after the charge lands (the lease drops on refusal):
        // one live target per distinct child object. A target that
        // changed between the checks above and this retention refuses
        // Changed — fail-closed, never a stale retention.
        let mut child_targets = Vec::with_capacity(distinct.len());
        for id in distinct {
            let target = objects
                .retain_inventory_target(id)
                .map_err(|_| DetailToggleRefusal::Changed)?;
            child_targets.push((id, target));
        }
        Ok(DetailWindowReservation {
            before,
            selected,
            physical,
            child_keys,
            child_targets,
            broad: held.share(),
            admission: None,
            _charge: charge,
        })
    }
}

impl Session {
    /// Reserve a selected-detail window against this broad counter
    /// Session (reads its banks and facts). `child_objects` is the
    /// store the child slot ids resolve in — the convert subset's own
    /// id space, never the broad store. STAGED (6.15): called by the
    /// detail adapter's session-level reserve; unit coverage runs
    /// banks-level.
    pub(crate) fn reserve_gate_window(
        &self,
        broad_plan: &AttachPlan,
        child_objects: &PinnedObjects,
        selected: u32,
        child_slots: &[Slot],
        read_seq_before: u64,
        reserve: &SemanticResourceReserver,
    ) -> Result<DetailWindowReservation, DetailToggleRefusal> {
        let Some(banks) = self.counter_banks.as_ref() else {
            return Err(DetailToggleRefusal::BroadNotCounter);
        };
        banks.reserve_detail_window(
            BroadToggleFacts {
                generation: self.counter_collection_generation(),
                stopped: self.mutation_stopped(),
            },
            broad_plan,
            child_objects,
            selected,
            child_slots,
            read_seq_before,
            reserve,
        )
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
        last_check: Option<&'static str>,
    }

    /// Check name for a scripted fake-IO `Topology` refusal. Real IOs name
    /// real checks; the fake names its script so tests can pin the channel.
    const COUNTER_CHECK_SCRIPTED_TARGETS: &str = "scripted target refusal";

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

        fn last_check(&self) -> Option<&'static str> {
            self.last_check
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
            self.last_check = None;
            assert!(published.iter().all(|slot| self.routes.contains_key(slot)));
            if let Some(reason) = self.target_refusal {
                if reason == BankRefusal::Topology {
                    self.last_check = Some(COUNTER_CHECK_SCRIPTED_TARGETS);
                }
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
    fn counter_growth_stages_fresh_adopted_plan_after_prefix() {
        // The Engine growth seam: the candidate plan is rebuilt fresh
        // (unconsumed) and adopts the staged prefix from the directory
        // high-water before staging its tail — the same adopt
        // `Session::stage_counter_growth` performs. The fresh tail must
        // publish exactly its extent.
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
        let mut history = AttachPlan::from_slots_with_policy(vec![first.clone()], policy).unwrap();
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
            BankPublication::Published { extent, .. }
                if extent == BankExtent { first: 0, end: 1 }
        ));
        let mut candidate =
            AttachPlan::from_slots_with_policy(vec![first, second], policy).unwrap();
        assert_eq!(candidate.counter_consumed_end(), 0);
        candidate.adopt_counter_consumed(1).unwrap();
        io.next_stage();
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut candidate,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Published { extent, .. }
                if extent == BankExtent { first: 1, end: 2 }
        ));
        assert_eq!(candidate.counter_consumed_end(), 2);
        assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0, 1]);
    }

    #[test]
    fn counter_growth_fresh_plan_without_adopt_refuses_without_publish() {
        // Failure twin: without the adopt, the fresh candidate's consumed
        // floor disagrees with the directory and staging refuses before
        // any native work, leaving the published prefix intact.
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
        let mut history = AttachPlan::from_slots_with_policy(vec![first.clone()], policy).unwrap();
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
            BankPublication::Published { .. }
        ));
        let mut candidate =
            AttachPlan::from_slots_with_policy(vec![first, second], policy).unwrap();
        io.next_stage();
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut candidate,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(publication, BankPublication::Refused(BankRefusal::Topology));
        assert_eq!(
            check,
            Some("counter plan consumed prefix differs from the staged length")
        );
        assert_eq!(candidate.counter_consumed_end(), 0);
        assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0]);
        assert_eq!(io.routes.len(), 1, "no fresh route was inserted");
    }

    #[test]
    fn counter_growth_ceiling_refusal_carries_requested_and_ceiling_counts() {
        // The growth seam checks the plan budget before building bank
        // extents, so the 8,193rd endpoint refuses with the budget (and
        // its counts) instead of a shape error. In-budget plans pass
        // through to the extent shape check.
        let growth = BankGeometry::checked(CounterMode::Counts, 16, 512).unwrap();
        let budget = crate::capacity::CounterBudget::new(8192).unwrap();
        assert_eq!(
            counter_growth_ceiling_refusal(8193, budget, growth),
            Some(BankRefusal::BudgetExhausted {
                resource: COUNTER_ENDPOINT_CEILING_RESOURCE,
                needed: 8193,
                available: 8192,
            })
        );
        assert_eq!(counter_growth_ceiling_refusal(8192, budget, growth), None);
        assert_eq!(counter_growth_ceiling_refusal(512, budget, growth), None);
        // The tighter of the budget and the geometry wins: a small budget
        // on the growth geometry refuses at the budget.
        let small = crate::capacity::CounterBudget::new(512).unwrap();
        assert_eq!(
            counter_growth_ceiling_refusal(513, small, growth),
            Some(BankRefusal::BudgetExhausted {
                resource: COUNTER_ENDPOINT_CEILING_RESOURCE,
                needed: 513,
                available: 512,
            })
        );
        assert_eq!(counter_growth_ceiling_refusal(512, small, growth), None);
    }

    #[test]
    fn counter_stage_check_names_inactive_fresh_slots() {
        // The a2-7a root shape: loader arming retired every endpoint, so the
        // Engine stages an all-inactive plan and the refusal must name it.
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        let mut history = plan(2);
        history.deactivate(0);
        history.deactivate(1);
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut history,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(publication, BankPublication::Refused(BankRefusal::Topology));
        assert_eq!(check, Some("counter plan has inactive fresh slots"));
        // The bare twin is unchanged: same value, no name in the value.
        io.next_stage();
        assert_eq!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Refused(BankRefusal::Topology)
        );
        assert!(matches!(
            directory.stage_with(
                &mut io,
                &mut history,
                growth_reservation(),
                &pool.reserver()
            ),
            BankPublication::Refused(BankRefusal::Topology)
        ));
    }

    #[test]
    fn counter_stage_check_names_non_dense_indices() {
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        let mut history = plan(1);
        history.slots[0].index = 1;
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut history,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(publication, BankPublication::Refused(BankRefusal::Topology));
        assert_eq!(check, Some("counter plan slot indices are not dense"));
    }

    #[test]
    fn counter_stage_check_names_duplicate_endpoints() {
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        let mut history = plan(2);
        history.slots[1].object = history.slots[0].object;
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut history,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(publication, BankPublication::Refused(BankRefusal::Topology));
        assert_eq!(check, Some("counter plan has duplicate physical endpoints"));
    }

    #[test]
    fn counter_stage_check_names_consumed_mismatch() {
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
        io.next_stage();
        let mut fresh = plan(2);
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut fresh,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(publication, BankPublication::Refused(BankRefusal::Topology));
        assert_eq!(
            check,
            Some("counter plan consumed prefix differs from the staged length")
        );
    }

    #[test]
    fn counter_stage_check_names_budget_mismatch() {
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
        io.next_stage();
        let mut other = AttachPlan::from_slots_with_policy(
            vec![slot(0, 1)],
            crate::plan::AdmissionPolicy::counters(
                crate::capacity::CounterBudget::new(1024).unwrap(),
            ),
        )
        .unwrap();
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut other,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(publication, BankPublication::Refused(BankRefusal::Topology));
        assert_eq!(
            check,
            Some("counter plan budget differs from the staged budget")
        );
    }

    #[test]
    fn counter_stage_check_names_key_mismatch() {
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
        io.next_stage();
        let mut other = AttachPlan::from_slots_with_policy(
            vec![slot(0, 2)],
            crate::plan::AdmissionPolicy::counters(
                crate::capacity::CounterBudget::new(8192).unwrap(),
            ),
        )
        .unwrap();
        other.consume_counter_extent(0, 1).unwrap();
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut other,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(publication, BankPublication::Refused(BankRefusal::Topology));
        assert_eq!(check, Some("counter plan slot differs from the staged key"));
    }

    #[test]
    fn counter_stage_check_names_scripted_target_refusal() {
        // The fake names its script so tests can pin the IO half of the
        // check channel end to end.
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        io.target_refusal = Some(BankRefusal::Topology);
        let mut history = plan(1);
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut history,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(publication, BankPublication::Refused(BankRefusal::Topology));
        assert_eq!(check, Some("scripted target refusal"));
    }

    #[test]
    fn counter_stage_check_stays_empty_without_topology() {
        // Non-Topology refusals name themselves and carry no check name.
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut directory = BankDirectory::counts_growth_v2();
        let mut io = GrowthIo::new(&pool);
        io.target_refusal = Some(BankRefusal::Ownership);
        let mut history = plan(1);
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut history,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(
            publication,
            BankPublication::Refused(BankRefusal::Ownership)
        );
        assert_eq!(check, None);
        io.next_stage();
        io.target_refusal = None;
        let mut detailed = AttachPlan::from_slots(vec![slot(0, 1)]);
        let (publication, check) = directory.stage_with_detailed(
            &mut io,
            &mut detailed,
            growth_reservation(),
            &pool.reserver(),
        );
        assert_eq!(
            publication,
            BankPublication::Refused(BankRefusal::Shape(BankShapeCause::PlanNotCounters))
        );
        assert_eq!(check, None);
    }

    #[test]
    fn counter_scope_admission_covers_process_and_machine_scopes() {
        // Cgroup/system sessions stage through the same seam: their links
        // are offset-based (scope-independent counts) with membership
        // enforced by the in-BPF scope gate. The diagnostic-only
        // calling-process scope is never a session scope.
        use aya::programs::uprobe::UProbeScope;
        use std::num::NonZeroU32;
        assert!(super::counter_scope_admitted(UProbeScope::OneProcess(
            NonZeroU32::new(7).unwrap()
        )));
        assert!(
            super::counter_scope_admitted(UProbeScope::AllProcesses),
            "cgroup/system sessions stage through the same seam"
        );
        assert!(!super::counter_scope_admitted(UProbeScope::CallingProcess));
    }

    #[test]
    fn native_target_gate_names_each_predicate_in_order() {
        // Each predicate names its own failure, the first failure wins,
        // and a clear gate passes.
        assert_eq!(
            native_target_gate(true, true, true, true, Some(2), 2),
            Err("counter session is stopping or detached")
        );
        assert_eq!(
            native_target_gate(false, false, true, true, Some(2), 2),
            Err("counter banks backend differs from the session backend")
        );
        assert_eq!(
            native_target_gate(false, true, false, true, Some(2), 2),
            Err("counter session scope is not one process or all processes")
        );
        assert_eq!(
            native_target_gate(false, true, true, false, Some(2), 2),
            Err("counter pinned provider changed")
        );
        assert_eq!(
            native_target_gate(false, true, true, true, Some(3), 2),
            Err("counter CPU count changed since preparation")
        );
        assert_eq!(
            native_target_gate(true, false, false, false, None, 2),
            Err("counter session is stopping or detached")
        );
        assert_eq!(
            native_target_gate(false, true, true, true, Some(2), 2),
            Ok(())
        );
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
            let baseline = pool.snapshot().charged_bytes;
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
                assert!(io.routes.is_empty(), "no route survives the refusal");
                assert_eq!(directory.allocated_high_water(), 0);
                assert_eq!(pool.snapshot().charged_bytes, baseline);
            } else {
                assert_eq!(result, BankPublication::Refused(BankRefusal::Budget));
                assert!(io.trace.is_empty() && io.maps.is_empty());
                assert!(io.routes.is_empty(), "no route survives the refusal");
                assert_eq!(directory.allocated_high_water(), 0);
                assert_eq!(pool.snapshot().charged_bytes, baseline);
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
        growth_owned_history_with_backend(mode, last_slot, super::super::AttachBackend::Singles)
    }

    fn growth_owned_history_with_backend(
        mode: CounterMode,
        last_slot: bool,
        backend: super::super::AttachBackend,
    ) -> GrowthOwnedHistory {
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
                backend,
                link_staging: Arc::new(AtomicU64::new(0)),
                terminal: None,
            },
            pool,
            digest,
        }
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
        // One literal per-bank count: a `+ cpus` scaling mutant reads
        // self-consistently everywhere else in this table, so the literal
        // is what kills it directly.
        assert_eq!(
            counter_bank_map_bytes(CounterMode::Counts, 12).unwrap(),
            147_456,
            "512 cells * 24 value bytes * 12 CPUs"
        );
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
    fn counter_preflight_names_ceiling_before_preparation() {
        // The S4 preflight names the requested count and charges nothing:
        // refusal happens before preparation with the pool untouched.
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let baseline = pool.snapshot().charged_bytes;
        for (mode, cpus, requested) in [
            (CounterMode::Counts, 12usize, 8193usize),
            (CounterMode::Latency, 490usize, 1usize),
        ] {
            let ceiling = super::counter_affordable_endpoints(mode, cpus).unwrap();
            assert!(
                requested > ceiling,
                "{mode:?} P={cpus}: requested {requested} must exceed ceiling {ceiling}"
            );
            let refusal = super::check_counter_endpoints_fit(mode, cpus, requested)
                .expect_err("over-ceiling request must refuse");
            assert!(
                refusal.starts_with("counter-memory-limit:"),
                "{mode:?} P={cpus}: {refusal}"
            );
            assert!(
                refusal.contains(&format!("(requested {requested})")),
                "{mode:?} P={cpus}: refusal names the requested count: {refusal}"
            );
        }
        assert_eq!(pool.snapshot().charged_bytes, baseline);
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
        // The old 45 MiB plus the 3 MiB terminal cleanup raise (1 to 4 MiB):
        // available-after-hold stays byte-identical, so every margin below
        // evaluates exactly as before.
        let pool = SemanticResourcePool::reference_limit(48 * 1024 * 1024);
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
    fn counter_terminal_cleanup_constant_dominates_derived_bound() {
        use super::super::{OwnedLink, ProducerProgram};
        // Both backends retire at most two owned links per endpoint: Singles
        // carries an entry and a return uprobe per endpoint (the budgets FD
        // row charges 2*published), and Multi staging reserves at most two
        // leaves per endpoint (`counter_multi_requirements`).
        let links: usize = 2 * 8192;
        // Worker batch: the terminal transfer push-grows one Vec of owned
        // links; old+new backing coexist during a doubling, so twice the
        // final backing plus one allocation padding dominates the peak.
        let batch = links
            .checked_mul(size_of::<(OwnedLink, ProducerProgram)>())
            .and_then(|final_backing| final_backing.checked_mul(2))
            .and_then(|peak| peak.checked_add(OWNED_ALLOCATION_PADDING))
            .unwrap();
        // One `retain_counter` box per transferred link, padded each.
        let boxes = links
            .checked_mul(
                size_of::<OwnedLink>()
                    .checked_add(OWNED_ALLOCATION_PADDING)
                    .unwrap(),
            )
            .unwrap();
        // One transient single-link transfer Vec at a time.
        let transient = size_of::<OwnedLink>()
            .checked_add(OWNED_ALLOCATION_PADDING)
            .unwrap();
        // Retirement leases: at most one Arc per slot.
        let leases = 8192usize
            .checked_mul(size_of::<std::sync::Arc<std::fs::File>>())
            .and_then(|n| n.checked_add(2 * OWNED_ALLOCATION_PADDING))
            .unwrap();
        // Receipt, worker batch and channel command: fixed small structs and
        // fixed worker-level strings. The production closer is infallible
        // (`drop` only), so no per-close failure string can accrue; map close
        // and keepalive drop free their precharged backing without allocating.
        let receipts = 4096usize;
        let bound = batch
            .checked_add(boxes)
            .and_then(|n| n.checked_add(transient))
            .and_then(|n| n.checked_add(leases))
            .and_then(|n| n.checked_add(receipts))
            .unwrap();
        assert!(
            super::COUNTER_TERMINAL_CLEANUP_BYTES >= bound,
            "cleanup constant {} must dominate derived {bound} (batch {batch}, boxes {boxes}, transient {transient}, leases {leases}, receipts {receipts})",
            super::COUNTER_TERMINAL_CLEANUP_BYTES
        );
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
    fn counter_budgets_multi_omits_singles_extra_fd() {
        let owned = growth_owned_history_with_backend(
            CounterMode::Counts,
            false,
            super::super::AttachBackend::Multi,
        );
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
        // Parent §3 FD row: Singles projects 2*published + banks + 1 (the
        // twin above pins 6); Multi projects 2*published + banks, no extra.
        assert_eq!(budgets.fd.projected, 5);
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
        // The Counts object selects the Counts geometry, so preparation holds
        // the same terminal figure production reserves for it.
        let terminal = super::counter_terminal_reserve_bytes(CounterMode::Counts, cpus).unwrap();
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
                    baseline + combined_floor + transient + terminal
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
    fn counter_preparation_charges_terminal_reserve_from_pool() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        // Omitted-object builds refuse at the build gate before any reserve;
        // that refusal has its own cell. This cell pins the terminal wiring
        // through the constructor the Session calls.
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") != "1" {
            return;
        }
        let object = super::counter_object_for_mode(CounterMode::Counts);
        assert!(!object.is_empty());
        let cpus = aya::util::nr_cpus().unwrap();
        let mode = CounterMode::Counts;
        let terminal_bytes = super::counter_terminal_reserve_bytes(mode, cpus).unwrap();
        let envelope = BankReservation {
            retained_bytes: 1024 * 1024 * 1024,
            transient_bytes: 512 * 1024 * 1024,
            metadata_bytes: 64 * 1024 * 1024,
            file_descriptors: 1_048_576,
        };
        // Success grows charged bytes by retained + transient + terminal.
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024 * 1024);
        let baseline = pool.snapshot().charged_bytes;
        let preparation = CounterPreparation::new_with_backend_and_probe(
            object,
            envelope,
            &pool.reserver(),
            AttachBackend::Singles,
            || BpfLoopVerdict::Available,
        )
        .expect("healthy preparation charges the terminal reserve");
        assert!(
            preparation.banks.terminal.is_some(),
            "preparation must hold the terminal lease"
        );
        let (retained, transient) = envelope.charges().unwrap();
        assert_eq!(
            pool.snapshot().charged_bytes,
            baseline + retained + transient + terminal_bytes,
            "preparation charges the terminal reserve from the pool"
        );
        drop(preparation);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
        // A pool one byte short of the terminal figure refuses with the
        // terminal token and leaves the pool at baseline.
        let short = SemanticResourcePool::reference_limit(terminal_bytes - 1);
        let short_baseline = short.snapshot().charged_bytes;
        let Err(refusal) = CounterPreparation::new_with_backend_and_probe(
            object,
            envelope,
            &short.reserver(),
            AttachBackend::Singles,
            || BpfLoopVerdict::Available,
        ) else {
            panic!("a pool below the terminal reserve must refuse");
        };
        let message = format!("{refusal:#}");
        assert!(
            message.contains("counter terminal reserve refused"),
            "{message}"
        );
        assert_eq!(short.snapshot().charged_bytes, short_baseline);
    }

    #[test]
    fn counter_preparation_memory_preflight_precedes_pool_reserves() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        // Same build gate as the terminal cell above: omitted-object builds
        // refuse before the preflight.
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") != "1" {
            return;
        }
        let object = super::counter_object_for_mode(CounterMode::Counts);
        assert!(!object.is_empty());
        // P=1024 through the CPU-count seam: the fixed maps alone (~555 MiB)
        // exceed the 256 MiB cap, so the affordable ceiling is zero. No host
        // reaches this count; the seam is the only way to stage it.
        assert_eq!(
            super::counter_affordable_endpoints(CounterMode::Counts, 1024).unwrap(),
            0
        );
        let envelope = BankReservation {
            retained_bytes: 1024 * 1024 * 1024,
            transient_bytes: 512 * 1024 * 1024,
            metadata_bytes: 64 * 1024 * 1024,
            file_descriptors: 1_048_576,
        };
        // A funded pool still refuses with the token and stays at baseline.
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024 * 1024);
        let baseline = pool.snapshot().charged_bytes;
        let Err(refusal) = CounterPreparation::new_with_backend_probe_and_cpus(
            object,
            envelope,
            &pool.reserver(),
            AttachBackend::Singles,
            || BpfLoopVerdict::Available,
            Some(1024),
        ) else {
            panic!("fixed-exceeds preparation must refuse");
        };
        let message = format!("{refusal:#}");
        assert!(message.contains("counter-memory-limit"), "{message}");
        assert_eq!(pool.snapshot().charged_bytes, baseline);
        // A pool too small for keepalive still reports the cap first: the
        // preflight runs before any pool reservation.
        let small = SemanticResourcePool::reference_limit(1024 * 1024);
        let small_baseline = small.snapshot().charged_bytes;
        let Err(refusal) = CounterPreparation::new_with_backend_probe_and_cpus(
            object,
            envelope,
            &small.reserver(),
            AttachBackend::Singles,
            || BpfLoopVerdict::Available,
            Some(1024),
        ) else {
            panic!("fixed-exceeds preparation must refuse before keepalive");
        };
        let message = format!("{refusal:#}");
        assert!(message.contains("counter-memory-limit"), "{message}");
        assert_eq!(small.snapshot().charged_bytes, small_baseline);
    }

    #[test]
    fn counter_verifier_budget_refusal_maps_e2big_only() {
        // A kernel verifier-budget rejection (E2BIG from BPF_PROG_LOAD,
        // shaped as the genuine loader error) becomes the finite named
        // refusal without the raw verifier log.
        let loaded = anyhow::Error::new(aya::programs::ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
            verifier_log: aya_obj::VerifierLog::new("verifier-line\n".repeat(9000)),
        })
        .context("loading function_list_return");
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
        // old-kernel token (no E2BIG), the Multi pid-filter errno (EINVAL),
        // a bare io E2BIG without a program load, and an unrelated error.
        for untouched in [
            anyhow::anyhow!(
                "counter-mode-unavailable-on-kernel: the kernel loads BPF programs but rejects the bpf_loop (helper 181) probe"
            ),
            std::io::Error::from_raw_os_error(libc::EINVAL).into(),
            std::io::Error::from_raw_os_error(libc::E2BIG).into(),
            anyhow::anyhow!("some other failure"),
        ] {
            let before = format!("{untouched:#}");
            let after = map_counter_verifier_budget_refusal(untouched);
            assert_eq!(format!("{after:#}"), before);
        }
    }

    #[test]
    fn counter_verifier_budget_refusal_keeps_log_exhaustion_untouched() {
        // ENOSPC (verifier log exhaustion) classifies as a budget refusal
        // only at the attach/doctor seam; the counter mapping rewrites
        // E2BIG alone, so an ENOSPC chain passes through with its errno
        // intact instead of taking the kernel-specific token.
        let untouched: anyhow::Error = std::io::Error::from_raw_os_error(libc::ENOSPC).into();
        let untouched = untouched.context("loading function_list_return");
        let before = format!("{untouched:#}");
        assert!(before.contains("os error 28"), "{before}");
        let after = map_counter_verifier_budget_refusal(untouched);
        assert_eq!(format!("{after:#}"), before);
        assert!(
            !format!("{after:#}").contains("counter-mode-unavailable-on-kernel"),
            "ENOSPC must not take the kernel-specific token: {after:#}"
        );
    }

    #[test]
    fn counter_verifier_budget_refusal_keeps_map_create_e2big() {
        // A map-create E2BIG is not a program-load refusal: only a genuine
        // BPF_PROG_LOAD E2BIG takes the old-kernel token. The map error
        // keeps its own text and errno.
        let map_create =
            anyhow::Error::new(aya::EbpfError::MapError(aya::maps::MapError::CreateError {
                name: "COUNTS".to_string(),
                io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
            }))
            .context("creating counter map");
        let before = format!("{map_create:#}");
        assert!(before.contains("os error 7"), "{before}");
        let after = map_counter_verifier_budget_refusal(map_create);
        assert_eq!(format!("{after:#}"), before);
        assert!(
            !format!("{after:#}").contains("counter-mode-unavailable-on-kernel"),
            "a map-create E2BIG must keep its own error: {after:#}"
        );
    }

    #[test]
    fn counter_start_error_maps_e2big_load_chain_to_the_named_refusal() {
        // The 6.1 production shape: aya's load error (E2BIG source, long
        // verifier log) under a loader context, as start_on_backend sees
        // it. The token replaces the whole chain; neither generic hint
        // may survive.
        let loaded = anyhow::Error::new(aya::programs::ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
            verifier_log: aya_obj::VerifierLog::new("verifier-line\n".repeat(9000)),
        })
        .context("loading function_list_return");
        let mapped = super::map_counter_start_error(loaded);
        let text = format!("{mapped:#}");
        assert!(
            text.starts_with("counter-mode-unavailable-on-kernel:"),
            "{text}"
        );
        assert!(!text.contains("p11scope bug"), "{text}");
        assert!(!text.contains("CAP_BPF"), "{text}");
        assert!(!text.contains("verifier-line"), "{text}");
    }

    #[test]
    fn counter_start_error_passes_named_refusals_through_unwrapped() {
        // The old-kernel token and the build token pass through with no
        // generic hint; a wrapped token keeps the token and gains no
        // hint; anything else keeps the generic hint.
        for token in [
            "counter-mode-unavailable-on-kernel: the kernel loads BPF programs but rejects the bpf_loop (helper 181) probe (test); counter bank objects need Linux 5.17+",
            "counter-mode-unavailable-in-build: this build omits counter objects",
        ] {
            let mapped = super::map_counter_start_error(anyhow::anyhow!("{token}"));
            assert_eq!(format!("{mapped:#}"), token);
        }
        let wrapped = anyhow::anyhow!(
            "counter-mode-unavailable-on-kernel: the kernel loads BPF programs but rejects the bpf_loop (helper 181) probe (test)"
        )
        .context("preparing counter banks");
        let text = format!("{:#}", super::map_counter_start_error(wrapped));
        assert!(
            text.contains("counter-mode-unavailable-on-kernel:"),
            "{text}"
        );
        assert!(!text.contains("CAP_BPF"), "{text}");
        assert!(!text.contains("p11scope bug"), "{text}");
        let other = super::map_counter_start_error(anyhow::anyhow!("some other failure"));
        let text = format!("{other:#}");
        assert!(text.contains("some other failure"), "{text}");
        assert!(text.contains("CAP_BPF"), "{text}");
    }

    #[test]
    fn counter_budget_token_applies_only_to_real_e2big() {
        // ENOSPC (an exhausted verifier log buffer, never the
        // instruction budget) keeps its errno and never becomes the
        // old-kernel token, at the mapping and at the start seam alike:
        // both read the shared E2BIG-only budget errno predicate.
        let loaded: anyhow::Error = std::io::Error::from_raw_os_error(libc::ENOSPC).into();
        let mapped =
            super::map_counter_verifier_budget_refusal(loaded.context("loading p11_return"));
        let text = format!("{mapped:#}");
        assert!(
            !text.contains("counter-mode-unavailable-on-kernel"),
            "{text}"
        );
        assert!(
            mapped.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.raw_os_error() == Some(libc::ENOSPC))),
            "{text}"
        );
        let loaded: anyhow::Error = std::io::Error::from_raw_os_error(libc::ENOSPC).into();
        let started = super::map_counter_start_error(loaded.context("loading p11_return"));
        let text = format!("{started:#}");
        assert!(
            !text.contains("counter-mode-unavailable-on-kernel"),
            "{text}"
        );
        assert!(text.contains("CAP_BPF"), "{text}");
    }

    #[test]
    fn counter_load_refusal_names_e2big_and_bounds_other_failures() {
        // The preflight names the same token for a real E2BIG, even
        // wrapped under loader context; any other failure is a
        // one-line errno-class text (unproven, never refused), and a
        // failure with no errno at all gets the static fallback.
        let e2big = anyhow::Error::new(aya::programs::ProgramError::LoadError {
            io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
            verifier_log: aya_obj::VerifierLog::new("verifier-line\n".repeat(9000)),
        })
        .context("loading function_list_return");
        assert_eq!(
            super::counter_load_refusal(&e2big),
            super::COUNTER_VERIFIER_BUDGET_REFUSAL
        );
        let denied: anyhow::Error = std::io::Error::from_raw_os_error(libc::EPERM).into();
        let text = super::counter_load_refusal(&denied.context("loading p11_return"));
        assert!(text.starts_with("counter object load failed ("), "{text}");
        assert!(!text.contains('\n'), "{text}");
        assert!(!text.contains("counter-mode-"), "{text}");
        let bare = anyhow::anyhow!("no errno here");
        assert_eq!(
            super::counter_load_refusal(&bare),
            "counter object load failed before the verifier ran"
        );
    }

    #[test]
    fn counter_load_refusal_keeps_map_create_e2big() {
        // A map-create E2BIG is not a program-load refusal: the preflight
        // must not take the verifier-budget token for it. Fails while the
        // preflight matches any io E2BIG in the chain.
        let map_create =
            anyhow::Error::new(aya::EbpfError::MapError(aya::maps::MapError::CreateError {
                name: "COUNTS".to_string(),
                io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
            }))
            .context("creating counter map");
        let text = super::counter_load_refusal(&map_create);
        assert!(text.starts_with("counter object load failed ("), "{text}");
        assert!(!text.contains("counter-mode-"), "{text}");
    }

    #[test]
    fn counter_load_refusal_keeps_bare_io_e2big() {
        // A bare io E2BIG with no program load behind it is unproven, never
        // a verifier verdict. Fails while the preflight matches any io E2BIG.
        let bare: anyhow::Error = std::io::Error::from_raw_os_error(libc::E2BIG).into();
        let text = super::counter_load_refusal(&bare.context("loading BPF object"));
        assert!(text.starts_with("counter object load failed ("), "{text}");
        assert!(!text.contains("counter-mode-"), "{text}");
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

    #[test]
    fn counter_spec_prepares_requested_mode() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") != "1" {
            // Disabled builds refuse at the build gate (twin below); the
            // healthy path needs embedded objects.
            return;
        }
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let pool = SemanticResourcePool::reference_limit(1024 * 1024 * 1024);
            let baseline = pool.snapshot().charged_bytes;
            assert!(!super::counter_object_for_mode(mode).is_empty());
            let spec =
                super::CounterSpec::for_production(mode, 8, pool.reserver()).expect("spec sizes");
            let prepared = spec
                .prepare_with_probe_and_cpus(
                    AttachBackend::Singles,
                    || BpfLoopVerdict::Available,
                    Some(8),
                )
                .expect("spec prepares");
            assert_eq!(prepared.banks.geometry_mode(), mode);
            assert!(
                pool.snapshot().charged_bytes > baseline,
                "{mode:?}: preparation holds terminal, keepalive and scratch"
            );
        }
    }

    #[test]
    fn counter_spec_production_prepare_matches_probe_and_build() {
        use super::super::AttachBackend;
        let pool = SemanticResourcePool::reference_limit(1024 * 1024 * 1024);
        let cpus = aya::util::nr_cpus().expect("possible CPUs");
        let spec = super::CounterSpec::for_production(CounterMode::Counts, cpus, pool.reserver())
            .expect("spec sizes");
        match spec.prepare(AttachBackend::Singles) {
            Ok(prepared) => {
                assert_eq!(
                    env!("P11SCOPE_COUNTER_OBJECTS_ENABLED"),
                    "1",
                    "success needs embedded objects"
                );
                assert_eq!(prepared.banks.geometry_mode(), CounterMode::Counts);
            }
            Err(error) => {
                let text = format!("{error:#}");
                assert!(
                    text.contains("counter-mode-unavailable-in-build")
                        || text.starts_with("counter-mode-unavailable-on-kernel:"),
                    "production prepare refuses only at the build or kernel gate: {text}"
                );
            }
        }
    }

    #[test]
    fn counter_spec_refuses_when_objects_disabled() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") == "1" {
            assert_eq!(
                env!("P11SCOPE_COUNTER_OBJECTS_OUTPUTS"),
                "counts-bank-growth-v2,timestamps-bank-growth-v2,latency-bank-growth-v2"
            );
            return;
        }
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let baseline = pool.snapshot().charged_bytes;
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let spec =
                super::CounterSpec::for_production(mode, 8, pool.reserver()).expect("spec sizes");
            let Err(error) = spec.prepare_with_probe_and_cpus(
                AttachBackend::Singles,
                || BpfLoopVerdict::Available,
                Some(8),
            ) else {
                panic!("{mode:?}: disabled builds must refuse preparation");
            };
            assert!(
                format!("{error:#}").contains("counter-mode-unavailable-in-build"),
                "{mode:?}: {error:#}"
            );
        }
        assert_eq!(
            pool.snapshot().charged_bytes,
            baseline,
            "build refusal charges nothing and attaches zero links (no session)"
        );
    }

    #[test]
    fn counter_spec_prepare_validates_envelope() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let zero = BankReservation {
            retained_bytes: 0,
            transient_bytes: 0,
            metadata_bytes: 0,
            file_descriptors: 0,
        };
        let spec = super::CounterSpec::new(CounterMode::Counts, zero, pool.reserver());
        let Err(error) = spec.prepare_with_probe_and_cpus(
            AttachBackend::Singles,
            || BpfLoopVerdict::Available,
            Some(8),
        ) else {
            panic!("a zero envelope must refuse");
        };
        let text = format!("{error:#}");
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") == "1" {
            assert!(text.contains("invalid counter reservation"), "{text}");
        } else {
            assert!(text.contains("counter-mode-unavailable-in-build"), "{text}");
        }
    }

    #[test]
    fn counter_budgets_view_reports_all_legs() {
        use super::super::{AttachBackend, BpfLoopVerdict};
        if env!("P11SCOPE_COUNTER_OBJECTS_ENABLED") != "1" {
            return;
        }
        let pool = SemanticResourcePool::reference_limit(1024 * 1024 * 1024);
        let spec = super::CounterSpec::for_production(CounterMode::Counts, 8, pool.reserver())
            .expect("spec sizes");
        let prepared = spec
            .prepare_with_probe_and_cpus(
                AttachBackend::Singles,
                || BpfLoopVerdict::Available,
                Some(8),
            )
            .expect("spec prepares");
        let view = prepared.banks.budgets(0).expect("budgets");
        assert_eq!(view.endpoints.published, 0);
        assert_eq!(view.endpoints.holes, 0);
        assert_eq!(view.endpoints.ceiling, 8192);
        assert_eq!(view.rv_keys.used, 0);
        assert_eq!(view.rv_keys.limit, 65536);
        assert_eq!(view.start.limit, 16384);
        assert_eq!(view.fd.projected, 1);
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes one initialized rlimit value; no change.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        assert_eq!(
            view.fd.soft,
            (limit.rlim_cur != libc::RLIM_INFINITY).then_some(limit.rlim_cur)
        );
        assert_eq!(
            view.memory.charged,
            super::counter_fixed_map_bytes(8).unwrap()
        );
        assert!(
            view.memory.charged <= view.memory.limit,
            "charged must stay within the kernel-map cap"
        );
        // A staged 512-endpoint plan projects the 1,026-FD first stage.
        let mut history = plan(512);
        let mut io = GrowthIo::new(&pool);
        io.cpus = 8;
        let envelope = super::estimate_counter_stage_reservation(
            CounterMode::Counts,
            16,
            512,
            &history.slots,
            0,
            512,
            0,
            8,
            1,
            0,
            None,
        )
        .unwrap();
        let mut directory = prepared.banks.directory.lock().expect("directory lock");
        assert!(matches!(
            directory.stage_with(&mut io, &mut history, envelope, &pool.reserver()),
            super::BankPublication::Published { extent, .. }
                if extent.first == 0 && extent.end == 512
        ));
        drop(directory);
        let staged = prepared.banks.budgets(0).expect("staged budgets");
        assert_eq!(staged.endpoints.published, 512);
        assert_eq!(staged.fd.projected, 1026);
        assert!(staged.memory.charged <= staged.memory.limit);
    }

    #[test]
    fn counter_rv_key_pool_matches_geometry() {
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let geometry = super::BankGeometry::checked(mode, 16, 512).unwrap();
            assert_eq!(geometry.rv_keys(), super::COUNTER_RV_KEY_POOL);
        }
    }

    #[test]
    fn counter_stage_envelope_funds_first_512_fds() {
        let history = plan(512);
        let envelope = super::estimate_counter_stage_reservation(
            CounterMode::Counts,
            16,
            512,
            &history.slots,
            0,
            512,
            0,
            12,
            1,
            0,
            Some((0, 0)),
        )
        .unwrap();
        // 512 endpoints times two link FDs, plus one bank and one transient:
        // the soft-1024 failure twin's `needed >= 1026` floor.
        assert_eq!(envelope.file_descriptors, 1026);
    }

    // ---- selected-detail toggle (A2.8, R5) ----

    /// Same-provider slots with distinct offsets: the growth shape the
    /// privileged toggle cells stage (bank 0 full, bank 1 entered).
    /// Shared with the 6.15 detail adapter's tests (which stage their
    /// own broad banks through the same genuine publication path).
    pub(crate) fn toggle_object_plan(object: PinnedObjectId, count: u32) -> AttachPlan {
        AttachPlan::from_slots_with_policy(
            (0..count)
                .map(|index| {
                    let mut target = slot(index, 0);
                    target.object = object;
                    target.file_offset = 0x80 + u64::from(index) * 0x10;
                    target.names = vec![format!("C_Toggle{index:04x}")];
                    target
                })
                .collect(),
            crate::plan::AdmissionPolicy::counters(
                crate::capacity::CounterBudget::new(8192).unwrap(),
            ),
        )
        .unwrap()
    }

    /// Shared with the 6.15 detail adapter's tests.
    pub(crate) fn toggle_provider(
        dir: &tempfile::TempDir,
        name: &str,
        bytes: &[u8],
    ) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Admission for 513+ same-provider slots: per-slot provider-copy
    /// charges times staging overlap exceed the small growth reservation.
    fn toggle_reservation() -> BankReservation {
        BankReservation {
            retained_bytes: 32 * 1024 * 1024,
            transient_bytes: 16 * 1024 * 1024,
            metadata_bytes: 1024 * 1024,
            file_descriptors: 4096,
        }
    }

    /// Scripted broad banks with `history` staged through the injected
    /// map-I/O seam: published positions plus retained providers, the
    /// same state the gate reads live. Shared with the 6.15 detail
    /// adapter's tests (returns the banks only; the growth twin keeps
    /// its own injected seam for trace asserts).
    pub(crate) fn stage_toggle_banks(
        pool: &SemanticResourcePool,
        objects: &PinnedObjects,
        history: &mut AttachPlan,
    ) -> CounterBanks {
        let geometry =
            BankGeometry::checked(p11scope_ebpf_common::CounterMode::Counts, 16, 512).unwrap();
        let keepalive_bytes = CounterKeepalive::allocation_bytes(geometry).unwrap();
        let banks = CounterBanks {
            geometry,
            directory: Arc::new(Mutex::new(BankDirectory::counts_growth_v2())),
            keepalive: CounterKeepalive::precharge_with_geometry(
                &pool.reserver(),
                keepalive_bytes,
                geometry,
            )
            .unwrap(),
            cpus: 2,
            backend: crate::attach::AttachBackend::Singles,
            link_staging: Arc::new(AtomicU64::new(0)),
            terminal: None,
        };
        let mut io = GrowthIo::new(pool);
        io.target_store = Some(objects);
        io.provider_owner = Some(&banks.keepalive.custody);
        let publication = banks.directory.lock().unwrap().stage_with(
            &mut io,
            history,
            toggle_reservation(),
            &pool.reserver(),
        );
        assert!(
            matches!(publication, BankPublication::Published { .. }),
            "toggle prefix stages: {publication:?}"
        );
        banks
    }

    fn poison_toggle_mutex<T>(mutex: &Mutex<T>) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = mutex.lock().unwrap();
            panic!("intentional toggle-test poison");
        }));
        assert!(mutex.is_poisoned(), "the mutex stays poisoned");
    }

    #[test]
    fn detail_child_envelope_sizes_maps_fds_and_links() {
        use p11scope_ebpf_common::{
            CallStart, MAX_SLOTS, RING_BYTES, RV_ENTRIES, START_ENTRIES, SlotStats,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle child provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let slots = toggle_object_plan(object, 1).slots;
        let copy = objects
            .retained_target_copy_allocation_charge(object)
            .unwrap();
        assert!(copy > 0, "a real provider copy charges nonzero bytes");
        let envelope = super::detail_child_envelope(&slots, &objects, 2).unwrap();
        let stats = MAX_SLOTS as usize * size_of::<SlotStats>() * 2;
        let start = START_ENTRIES as usize * (16 + size_of::<CallStart>());
        let rv = RV_ENTRIES as usize * (16 + 8 * 2);
        // Full child maps plus the documented control block and one
        // provider copy with staging overlap; nothing is per-endpoint
        // except the copies, because the child loads the full shape.
        assert_eq!(
            envelope.bytes,
            stats + start + rv + RING_BYTES as usize + 64 * 1024 + copy * 4
        );
        // Entry+return per endpoint plus map/pin/pidfd slack: the
        // worst case covers Singles exactly and Multi loosely.
        assert_eq!(envelope.file_descriptors, 2 + 64);
        let wide = toggle_object_plan(object, 512).slots;
        let wide_envelope = super::detail_child_envelope(&wide, &objects, 2).unwrap();
        assert_eq!(
            wide_envelope.bytes - envelope.bytes,
            copy * 4 * 511,
            "only provider copies scale with child endpoints"
        );
        assert_eq!(wide_envelope.file_descriptors, 2 * 512 + 64);
        // Floors: no child without endpoints, no Detailed child past the
        // slot bound, no per-CPU sizing without CPUs, no unknown object.
        assert_eq!(
            super::detail_child_envelope(&[], &objects, 2).unwrap_err(),
            super::DetailToggleRefusal::ChildShape
        );
        let over = toggle_object_plan(object, MAX_SLOTS + 1).slots;
        assert_eq!(
            super::detail_child_envelope(&over, &objects, 2).unwrap_err(),
            super::DetailToggleRefusal::ChildShape
        );
        assert_eq!(
            super::detail_child_envelope(&slots, &objects, 0).unwrap_err(),
            super::DetailToggleRefusal::Budget
        );
        let mut foreign_slot = slots[0].clone();
        foreign_slot.object = PinnedObjectId(object.0 + 1000);
        assert_eq!(
            super::detail_child_envelope(&[foreign_slot], &objects, 2).unwrap_err(),
            super::DetailToggleRefusal::Budget
        );
        assert_eq!(
            super::detail_child_envelope(&slots, &objects, usize::MAX).unwrap_err(),
            super::DetailToggleRefusal::Budget
        );
    }

    #[test]
    fn counter_detail_reserve_charges_child_and_snapshots_broad() {
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle broad provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let custody = banks.keepalive.custody.lock().unwrap();
        assert!(
            custody.providers[512].is_some(),
            "bank-1 slot retains its provider"
        );
        drop(custody);
        let generation = NonZeroU64::new(7).unwrap();
        let child_slots = history.slots[512..513].to_vec();
        let expected =
            super::detail_child_envelope(&child_slots, &objects, aya::util::nr_cpus().unwrap())
                .unwrap();
        // Reserve additionally retains the bind-time identity: the
        // child slot keys, one retained live target for the distinct
        // child object (never the whole pin store), and the broad
        // share.
        let retained = child_slots.len() * std::mem::size_of::<crate::plan::AttachKey>()
            + std::mem::size_of::<(
                crate::discovery::identity::PinnedObjectId,
                crate::discovery::identity::RetainedInventoryTarget,
            )>()
            + objects
                .retained_target_copy_allocation_charge(object)
                .expect("provider copy charge sizes")
            + banks.keepalive.custody.lock().unwrap().providers[512]
                .as_ref()
                .unwrap()
                .retained_copy_allocation_charge()
                .expect("broad share charge sizes")
            + 3 * crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING;
        let before = pool.snapshot().charged_bytes;
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation,
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        // The R6 child row plus the retained bind-time identity:
        // charged at reserve through the capture reserver, to the byte.
        assert_eq!(
            pool.snapshot().charged_bytes - before,
            expected.bytes + retained,
            "reserve charges exactly envelope plus retention"
        );
        assert_eq!(reservation.selected(), 512);
        assert_eq!(
            reservation.physical(),
            crate::plan::AttachKey {
                object,
                file_offset: 0x80 + 512 * 0x10,
            }
        );
        let mark = reservation.mark_before();
        assert_eq!((mark.seq, mark.generation), (41, generation));
        assert_eq!(
            mark.indices,
            (0..513).collect::<Vec<_>>(),
            "the before-mark carries every published original index"
        );
        assert_eq!(mark.transaction, NonZeroU64::new(2));
        // Binding assigns the sealed generation and keeps the marks.
        let window = reservation.bind_generation(9);
        assert_eq!(window.selected(), 512);
        assert_eq!(window.detail_generation(), 9);
        assert_eq!(window.mark_before().seq, 41);
    }

    #[test]
    fn counter_detail_window_refuses_stopping_broad() {
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle stopping provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let child_slots = history.slots[512..513].to_vec();
        let charged = pool.snapshot().charged_bytes;
        assert_eq!(
            banks
                .reserve_detail_window(
                    super::BroadToggleFacts {
                        generation: NonZeroU64::new(7).unwrap(),
                        stopped: true
                    },
                    &history,
                    &objects,
                    512,
                    child_slots.as_slice(),
                    41,
                    &pool.reserver(),
                )
                .unwrap_err(),
            super::DetailToggleRefusal::BroadStopping
        );
        assert_eq!(
            pool.snapshot().charged_bytes,
            charged,
            "a refused reserve charges nothing"
        );
    }

    #[test]
    fn counter_detail_window_refuses_unpublished_selection() {
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle unpublished provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        // Genuine directory states, set directly: the transitions that
        // produce them belong to staging (covered there); the gate must
        // match every non-published state.
        {
            let mut directory = banks.directory.lock().unwrap();
            directory.positions[7].state = super::PositionState::Pending;
            directory.positions[8].state = super::PositionState::NeverPublishedRetired;
        }
        for selected in [7, 8, 513, 8191] {
            let child_slots = history.slots[..1].to_vec();
            assert_eq!(
                banks
                    .reserve_detail_window(
                        super::BroadToggleFacts {
                            generation: NonZeroU64::new(7).unwrap(),
                            stopped: false
                        },
                        &history,
                        &objects,
                        selected,
                        child_slots.as_slice(),
                        41,
                        &pool.reserver(),
                    )
                    .unwrap_err(),
                super::DetailToggleRefusal::NotPublished,
                "selection {selected} is not a published broad row"
            );
        }
        // A plan row that no longer names its published key is not the
        // published selection either, even at a published index.
        let mut relabeled = history.clone();
        relabeled.slots[9].file_offset += 0x10;
        let child_slots = relabeled.slots[9..10].to_vec();
        assert_eq!(
            banks
                .reserve_detail_window(
                    super::BroadToggleFacts {
                        generation: NonZeroU64::new(7).unwrap(),
                        stopped: false,
                    },
                    &relabeled,
                    &objects,
                    9,
                    child_slots.as_slice(),
                    41,
                    &pool.reserver(),
                )
                .unwrap_err(),
            super::DetailToggleRefusal::NotPublished
        );
    }

    #[test]
    fn counter_detail_window_refuses_foreign_and_changed_provider() {
        let dir = tempfile::tempdir().unwrap();
        let old_path = toggle_provider(&dir, "old-provider.so", b"identical owned provider bytes");
        let foreign_path = toggle_provider(
            &dir,
            "foreign-provider.so",
            b"identical owned provider bytes",
        );
        let old = crate::discovery::identity::test_fixture::real_scan_pin(
            &old_path,
            None,
            1,
            "same-digest",
        );
        let foreign = crate::discovery::identity::test_fixture::real_scan_pin(
            &foreign_path,
            None,
            2,
            "same-digest",
        );
        let object = old.pinned().next().unwrap().id;
        assert_eq!(foreign.pinned().next().unwrap().id, object);
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &old, &mut history);
        let open = |objects: &PinnedObjects,
                    child_slots: &[Slot],
                    selected: u32|
         -> Result<super::DetailWindowReservation, super::DetailToggleRefusal> {
            banks.reserve_detail_window(
                super::BroadToggleFacts {
                    generation: NonZeroU64::new(7).unwrap(),
                    stopped: false,
                },
                &history,
                objects,
                selected,
                child_slots,
                41,
                &pool.reserver(),
            )
        };
        // Same local id, offset and content do not identify the held
        // file: the child covers the selected offset but names another
        // kernel file.
        let mut foreign_slots = toggle_object_plan(object, 1).slots;
        foreign_slots[0].file_offset = 0x80 + 512 * 0x10;
        assert_eq!(
            open(&foreign, foreign_slots.as_slice(), 512).unwrap_err(),
            super::DetailToggleRefusal::Foreign
        );
        // A child that does not cover the selected endpoint is foreign
        // to the selection, even on the same file.
        let elsewhere = history.slots[511..512].to_vec();
        assert_eq!(
            open(&old, elsewhere.as_slice(), 512).unwrap_err(),
            super::DetailToggleRefusal::Foreign
        );
        // An in-place rewrite keeps the kernel file but changes the
        // bytes: same file, changed provider.
        std::fs::write(&old_path, b"identical owned provider bytes, rewritten").unwrap();
        let child_slots = history.slots[512..513].to_vec();
        assert_eq!(
            open(&old, child_slots.as_slice(), 512).unwrap_err(),
            super::DetailToggleRefusal::Changed
        );
    }

    #[test]
    fn counter_detail_window_refuses_quarantined_broad() {
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle quarantined provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        for poison_directory in [false, true] {
            for poison_custody in [false, true] {
                if !poison_directory && !poison_custody {
                    continue;
                }
                let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
                let mut history = toggle_object_plan(object, 513);
                let banks = stage_toggle_banks(&pool, &objects, &mut history);
                if poison_directory {
                    poison_toggle_mutex(&banks.directory);
                }
                if poison_custody {
                    poison_toggle_mutex(&banks.keepalive.custody);
                }
                let child_slots = history.slots[512..513].to_vec();
                assert_eq!(
                    banks
                        .reserve_detail_window(
                            super::BroadToggleFacts {
                                generation: NonZeroU64::new(7).unwrap(),
                                stopped: false
                            },
                            &history,
                            &objects,
                            512,
                            child_slots.as_slice(),
                            41,
                            &pool.reserver(),
                        )
                        .unwrap_err(),
                    super::DetailToggleRefusal::Quarantined,
                    "poisoned directory={poison_directory} custody={poison_custody} refuses"
                );
            }
        }
        // The flag twin: a quarantined directory refuses with live locks.
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        banks.directory.lock().unwrap().quarantined = true;
        let child_slots = history.slots[512..513].to_vec();
        assert_eq!(
            banks
                .reserve_detail_window(
                    super::BroadToggleFacts {
                        generation: NonZeroU64::new(7).unwrap(),
                        stopped: false
                    },
                    &history,
                    &objects,
                    512,
                    child_slots.as_slice(),
                    41,
                    &pool.reserver(),
                )
                .unwrap_err(),
            super::DetailToggleRefusal::Quarantined
        );
    }

    #[test]
    fn counter_detail_window_refuses_unfunded_child_charge() {
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle budget provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        // Staging funds from its own pool; the window charges against a
        // pool too small for the child envelope.
        let staging = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&staging, &objects, &mut history);
        let poor = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH);
        let child_slots = history.slots[512..513].to_vec();
        assert_eq!(
            banks
                .reserve_detail_window(
                    super::BroadToggleFacts {
                        generation: NonZeroU64::new(7).unwrap(),
                        stopped: false
                    },
                    &history,
                    &objects,
                    512,
                    child_slots.as_slice(),
                    41,
                    &poor.reserver(),
                )
                .unwrap_err(),
            super::DetailToggleRefusal::Budget
        );
        assert_eq!(
            poor.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH,
            "a refused reserve leaves the poor pool at its construction charge"
        );
        // The FD headroom check behind the gate, over scripted
        // snapshots: exact headroom passes, a short soft limit names
        // file descriptors, unlimited always passes.
        let envelope = super::detail_child_envelope(&child_slots, &objects, 2).unwrap();
        let fds = envelope.file_descriptors;
        assert!(
            super::admit_detail_child_fds(fds, || Ok(super::FdSnapshot::scripted(fds as u64, 0)))
                .is_ok()
        );
        assert_eq!(
            super::admit_detail_child_fds(fds, || Ok(super::FdSnapshot::scripted(
                fds as u64 - 1,
                0
            )))
            .unwrap_err(),
            super::DetailToggleRefusal::Budget
        );
        assert!(
            super::admit_detail_child_fds(fds, || Ok(super::FdSnapshot::scripted_unlimited(
                1_000_000_000
            )))
            .is_ok()
        );
        // An observed count that cannot admit any headroom refuses even
        // under an unlimited soft cap.
        assert_eq!(
            super::admit_detail_child_fds(fds, || Ok(super::FdSnapshot::scripted_unlimited(
                u64::MAX
            )))
            .unwrap_err(),
            super::DetailToggleRefusal::Budget
        );
        assert_eq!(
            super::admit_detail_child_fds(fds, || Err(super::BankRefusal::Native)).unwrap_err(),
            super::DetailToggleRefusal::Budget
        );
    }

    #[test]
    fn counter_detail_window_refuses_malformed_child() {
        use p11scope_ebpf_common::MAX_SLOTS;
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle child-shape provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let over = toggle_object_plan(object, MAX_SLOTS + 1).slots;
        for child_slots in [&[][..], &over[..]] {
            assert_eq!(
                banks
                    .reserve_detail_window(
                        super::BroadToggleFacts {
                            generation: NonZeroU64::new(7).unwrap(),
                            stopped: false
                        },
                        &history,
                        &objects,
                        512,
                        child_slots,
                        41,
                        &pool.reserver(),
                    )
                    .unwrap_err(),
                super::DetailToggleRefusal::ChildShape,
                "a child with {} endpoints is not a Detailed child",
                child_slots.len()
            );
        }
    }

    #[test]
    fn counter_detail_window_close_verifies_prefix_and_reports_drift() {
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle close provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let generation = NonZeroU64::new(7).unwrap();
        let child_slots = history.slots[512..513].to_vec();
        // A clean close joins through the lineage: same generation and
        // prefix, the injected bracketing seqs, no drift.
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation,
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let window = reservation.bind_generation(9);
        let charged = pool.snapshot().charged_bytes;
        let (lineage, drift) = window.close(&banks, generation, 87).unwrap();
        assert_eq!(drift, None);
        assert_eq!(
            (
                lineage.broad_generation,
                lineage.broad_original_index,
                lineage.detail_generation,
            ),
            (generation, 512, 9)
        );
        assert_eq!(
            lineage.broad_physical,
            crate::plan::AttachKey {
                object,
                file_offset: 0x80 + 512 * 0x10,
            }
        );
        assert_eq!(
            (lineage.broad_read_seq_before, lineage.broad_read_seq_after),
            (41, 87),
            "the marks carry the injected driver seqs, minted nowhere else"
        );
        assert_eq!(
            lineage.broad_mark_before.indices,
            lineage.broad_mark_after.indices
        );
        assert_eq!(
            lineage.broad_mark_after.transaction,
            lineage.broad_mark_before.transaction
        );
        // The start charge releases with the window: closing frees
        // exactly what opening held.
        assert!(
            pool.snapshot().charged_bytes < charged,
            "the window lease releases at close"
        );
        // A replacement broad (new generation) never joins silently.
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation,
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let window = reservation.bind_generation(9);
        let after = NonZeroU64::new(8).unwrap();
        let (_, drift) = window.close(&banks, after, 87).unwrap();
        assert_eq!(
            drift,
            Some(super::DetailToggleDrift::Generation {
                before: generation,
                after,
            })
        );
        // A retired published row breaks the prefix.
        let route9 = match banks.directory.lock().unwrap().positions[9].state {
            super::PositionState::Published(route) => route,
            _ => panic!("slot 9 stages published"),
        };
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation,
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let window = reservation.bind_generation(9);
        banks.directory.lock().unwrap().positions[9].state =
            super::PositionState::NeverPublishedRetired;
        let (lineage, drift) = window.close(&banks, generation, 87).unwrap();
        assert_eq!(lineage.broad_mark_before.indices.len(), 513);
        assert_eq!(lineage.broad_mark_after.indices.len(), 512);
        assert!(
            matches!(drift, Some(super::DetailToggleDrift::Indices { .. })),
            "retiring a published row drifts the prefix: {drift:?}"
        );
        banks.directory.lock().unwrap().positions[9].state =
            super::PositionState::Published(route9);
        // A rewound transaction waterline cannot order the brackets.
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation,
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let window = reservation.bind_generation(9);
        let waterline = lineage.broad_mark_before.transaction;
        banks.directory.lock().unwrap().next_transaction = NonZeroU64::new(1);
        let (_, drift) = window.close(&banks, generation, 87).unwrap();
        assert_eq!(
            drift,
            Some(super::DetailToggleDrift::Transaction {
                before: waterline,
                after: NonZeroU64::new(1),
            })
        );
    }

    #[test]
    fn counter_detail_mark_verify_names_first_drift_in_order() {
        let generation = NonZeroU64::new(7).unwrap();
        let before = super::BroadReadMark {
            seq: 0,
            generation,
            indices: vec![0, 1, 2],
            bank_ids: vec![(0, 101)],
            transaction: NonZeroU64::new(2),
        };
        // Clean and growth-prefix scenes verify without drift.
        assert_eq!(
            super::verify_broad_mark(&before, &before),
            None,
            "identical marks verify clean"
        );
        let grown = super::BroadReadMark {
            seq: 1,
            indices: vec![0, 1, 2, 3],
            bank_ids: vec![(0, 101)],
            transaction: NonZeroU64::new(3),
            ..before.clone()
        };
        assert_eq!(
            super::verify_broad_mark(&before, &grown),
            None,
            "an appended tail keeps the prefix"
        );
        // Each drift kind reports exactly, in check order.
        let generation_after = NonZeroU64::new(8).unwrap();
        for (after, expected) in [
            (
                super::BroadReadMark {
                    generation: generation_after,
                    ..before.clone()
                },
                super::DetailToggleDrift::Generation {
                    before: generation,
                    after: generation_after,
                },
            ),
            (
                super::BroadReadMark {
                    seq: 1,
                    indices: vec![0, 1],
                    ..before.clone()
                },
                super::DetailToggleDrift::Indices {
                    before: vec![0, 1, 2],
                    after: vec![0, 1],
                },
            ),
            (
                super::BroadReadMark {
                    seq: 1,
                    indices: vec![0, 1, 9],
                    ..before.clone()
                },
                super::DetailToggleDrift::Indices {
                    before: vec![0, 1, 2],
                    after: vec![0, 1, 9],
                },
            ),
            (
                super::BroadReadMark {
                    seq: 1,
                    bank_ids: vec![(0, 102)],
                    ..before.clone()
                },
                super::DetailToggleDrift::BankIds {
                    bank: 0,
                    before: Some(101),
                    after: Some(102),
                },
            ),
            (
                super::BroadReadMark {
                    seq: 1,
                    bank_ids: vec![],
                    ..before.clone()
                },
                super::DetailToggleDrift::BankIds {
                    bank: 0,
                    before: Some(101),
                    after: None,
                },
            ),
            (
                super::BroadReadMark {
                    seq: 1,
                    transaction: NonZeroU64::new(1),
                    ..before.clone()
                },
                super::DetailToggleDrift::Transaction {
                    before: NonZeroU64::new(2),
                    after: NonZeroU64::new(1),
                },
            ),
        ] {
            assert_eq!(super::verify_broad_mark(&before, &after), Some(expected));
        }
        // Exhaustion past the open mark still orders after it: no drift.
        // Fresh banks appended past the open mark keep the prefix too.
        for after in [
            super::BroadReadMark {
                seq: 1,
                transaction: None,
                ..before.clone()
            },
            super::BroadReadMark {
                seq: 1,
                indices: vec![0, 1, 2, 3],
                bank_ids: vec![(0, 101), (1, 201)],
                transaction: NonZeroU64::new(3),
                ..before.clone()
            },
        ] {
            assert_eq!(super::verify_broad_mark(&before, &after), None);
        }
        // An exhausted open mark stays exhausted; a waterline that comes
        // back from exhaustion is impossible and drifts.
        let exhausted = super::BroadReadMark {
            transaction: None,
            ..before.clone()
        };
        assert_eq!(
            super::verify_broad_mark(&exhausted, &exhausted),
            None,
            "exhausted-to-exhausted verifies clean"
        );
        assert_eq!(
            super::verify_broad_mark(&exhausted, &before),
            Some(super::DetailToggleDrift::Transaction {
                before: None,
                after: NonZeroU64::new(2),
            })
        );
        // First drift wins, in generation/indices/bank-ids/transaction order.
        let everything = super::BroadReadMark {
            seq: 1,
            generation: generation_after,
            indices: vec![0],
            bank_ids: vec![(0, 102)],
            transaction: NonZeroU64::new(1),
        };
        assert_eq!(
            super::verify_broad_mark(&before, &everything),
            Some(super::DetailToggleDrift::Generation {
                before: generation,
                after: generation_after,
            })
        );
    }

    #[test]
    fn counter_detail_growth_during_window_inserts_only_fresh_extent() {
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle growth provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        // Two stages retain a full envelope each; size for both plus
        // the window charge.
        let pool = SemanticResourcePool::reference_limit(256 * 1024 * 1024);
        let geometry =
            BankGeometry::checked(p11scope_ebpf_common::CounterMode::Counts, 16, 512).unwrap();
        let keepalive_bytes = CounterKeepalive::allocation_bytes(geometry).unwrap();
        let banks = CounterBanks {
            geometry,
            directory: Arc::new(Mutex::new(BankDirectory::counts_growth_v2())),
            keepalive: CounterKeepalive::precharge_with_geometry(
                &pool.reserver(),
                keepalive_bytes,
                geometry,
            )
            .unwrap(),
            cpus: 2,
            backend: crate::attach::AttachBackend::Singles,
            link_staging: Arc::new(AtomicU64::new(0)),
            terminal: None,
        };
        let mut history = toggle_object_plan(object, 513);
        let mut io = GrowthIo::new(&pool);
        io.target_store = Some(&objects);
        io.provider_owner = Some(&banks.keepalive.custody);
        assert!(matches!(
            banks.directory.lock().unwrap().stage_with(
                &mut io,
                &mut history,
                toggle_reservation(),
                &pool.reserver(),
            ),
            BankPublication::Published {
                extent: BankExtent { first: 0, end: 513 },
                ..
            }
        ));
        assert_eq!(io.maps, BTreeMap::from([(0, 101), (1, 102)]));
        // Detail opens on a bank-1 endpoint while broad holds 513 rows.
        let generation = NonZeroU64::new(7).unwrap();
        let child_slots = history.slots[512..513].to_vec();
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation,
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let window = reservation.bind_generation(9);
        let prefix_routes = io.routes.clone();
        let prefix_maps = io.maps.clone();
        assert_eq!(prefix_routes.len(), 513);
        // One broad append while detail is open: bank 1 fills and bank 2
        // is fresh. Only fresh-extent inserts may run; no published cell,
        // RV key or route is written, deleted or zeroed.
        io.next_stage();
        let grown = toggle_object_plan(object, 1536);
        history.extend_exact(grown).unwrap();
        assert!(matches!(
            banks.directory.lock().unwrap().stage_with(
                &mut io,
                &mut history,
                toggle_reservation(),
                &pool.reserver(),
            ),
            BankPublication::Published {
                extent: BankExtent {
                    first: 513,
                    end: 1536
                },
                ..
            }
        ));
        assert_eq!(
            io.trace.iter().filter(|step| **step == "allocate").count(),
            1,
            "only the fresh bank allocates: {:?}",
            io.trace
        );
        assert_eq!(io.maps.get(&0), Some(&101));
        assert_eq!(io.maps.get(&1), Some(&102));
        assert_eq!(io.maps.len(), 3, "banks 0-1 keep their ids");
        for (slot, route) in &prefix_routes {
            assert_eq!(
                io.routes.get(slot),
                Some(route),
                "published route {slot} is byte-identical across growth"
            );
        }
        assert_eq!(io.routes.len(), 1536);
        assert!(
            !io.trace.contains(&"remove-route") && !io.trace.contains(&"remove-bank"),
            "growth removes nothing: {:?}",
            io.trace
        );
        drop(prefix_maps);
        let directory = banks.directory.lock().unwrap();
        assert_eq!(
            directory.published_indices().collect::<Vec<_>>(),
            (0..1536).collect::<Vec<_>>(),
            "published indices keep their prefix across growth"
        );
        drop(directory);
        let (lineage, drift) = window.close(&banks, generation, 87).unwrap();
        assert_eq!(drift, None, "an appended tail closes clean");
        assert_eq!(
            (lineage.broad_read_seq_before, lineage.broad_read_seq_after),
            (41, 87),
            "growth keeps the injected bracketing seqs"
        );
    }

    #[test]
    fn counter_detail_toggle_drives_promotion_service_to_disposal() {
        use crate::attach::selected_detailed::SelectedConstructionPermit;
        use crate::discovery::caller_registry::{CallerId, ModuleId};
        use crate::inventory_promotion::lifecycle::{
            NativeActivationSource, NativeCasReceipt, PendingInstall, PreparationOutcome,
            SelectedActivationBinding, SelectedActivationProof, SelectedLifecycleService,
        };
        use std::sync::Arc;
        // Scripted broad banks with 513 published rows.
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle service provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let generation = NonZeroU64::new(7).unwrap();
        let child_slots = history.slots[512..513].to_vec();
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation,
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let window = reservation.bind_generation(9);
        // The real V5-18 promotion service, start to terminal status:
        // a failed preparation disposes through the genuine joined
        // path and reports PreparationFailed, never installing.
        let (mut promoter, request) =
            crate::inventory_promotion::lifecycle::taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        let coordinator =
            crate::discovery::engine::inventory_coordinator::InventoryCoordinator::new(
                crate::attach::Scope::Pid(std::process::id()),
                crate::discovery::hooks::HookRegistry::builtin(),
                Vec::new(),
                crate::discovery::caller_registry::OsProcessSource,
                crate::discovery::caller_registry::RegistryLimits::default_limits(),
            )
            .expect("a test coordinator builds");
        struct StubSource;
        impl NativeActivationSource for StubSource {
            fn activate(
                &mut self,
                _session: &crate::attach::Session,
                expected: &SelectedActivationBinding,
            ) -> Result<
                NativeCasReceipt,
                crate::inventory_promotion::lifecycle::NativeActivationRefusal,
            > {
                Ok(NativeCasReceipt::scripted(*expected))
            }
        }
        service
            .start(
                request,
                coordinator.reserve_promotion_install().expect("capacity"),
                Box::new(StubSource),
                || {
                    PreparationOutcome::Failed(
                        crate::attach::selected_detailed::SelectedPreparationFailure::scripted_settled(
                        ),
                    )
                },
            )
            .expect("start runs");
        let mut sink = std::io::sink();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let event = loop {
            if let Some(event) = service.poll(&mut sink) {
                break event;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the service emits its terminal event"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        let crate::inventory_promotion::lifecycle::LifecycleEvent::Status(update) = event else {
            panic!("a failed job must not install");
        };
        assert_eq!(
            promoter.set_status(update),
            Some(crate::inventory_promotion::PromotionState::Refused(
                crate::inventory_promotion::PromotionRefusal::PreparationFailed
            ))
        );
        assert!(service.is_idle());
        // The reclaim path through the same real service: a posed
        // install reclaims into genuine lane disposal and ends.
        let (_promoter, request) = crate::inventory_promotion::lifecycle::taken_request_for_test();
        let domain =
            crate::attach::capture::NativeDomainId::try_mint().expect("a test domain mints");
        let binding = SelectedActivationBinding::new(
            domain,
            7,
            p11scope_ebpf_common::ImageIdentity {
                task_cookie: 71,
                exec_id: 72,
            },
        );
        let pin = Arc::new(crate::process::PidPin::open(std::process::id()).expect("self pins"));
        let custody = crate::process::WeakProcessCustody::pinned_for_test(&pin);
        let view =
            crate::inventory_promotion::lifecycle::scripted_promotion_view_with_baseline_for_test(
                pin.pid(),
                pin.start_time(),
                1,
                custody,
                0xC00,
                0xE9E,
            );
        let mut promoter = crate::inventory_promotion::Promoter::new();
        assert!(promoter.enable(crate::inventory_promotion::CaptureId::new(11)));
        promoter
            .request(Arc::clone(&view), CallerId(3), ModuleId(5))
            .expect("exact pair queues");
        let baseline_request = promoter.take_request().expect("mailbox holds it");
        let baseline = view
            .baseline()
            .expect("paired")
            .for_request(&baseline_request, &pin, 1)
            .expect("genuine derivation");
        let slot = Slot {
            index: 0,
            descriptor_index: 0,
            object: crate::discovery::identity::PinnedObjectId(7),
            object_path: "toggle-reclaim-test".into(),
            file_offset: 0x1000,
            names: vec!["C_Sign".into()],
            aliased: false,
            semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: Vec::new(),
        };
        let subset_plan = crate::plan::AttachPlan::from_slots(vec![slot]);
        let lane = crate::inventory_semantics::AttestedSemanticLane::start(
            crate::inventory_semantics::AttestedSubset::scripted(
                subset_plan,
                crate::discovery::identity::PinnedObjects::empty(),
                BTreeMap::new(),
            ),
            &crate::attach::Scope::Pid(std::process::id()),
            crate::attach::BackendSelection::Auto,
        )
        .expect("one scripted slot forms a shell lane");
        let permit = SelectedConstructionPermit::scripted_for_test(
            crate::events::EventsDomain::test_standin(0x70),
            Arc::clone(&pin),
            crate::attach::Scope::Pid(pin.pid()),
            domain,
            p11scope_ebpf_common::ImageIdentity {
                task_cookie: 71,
                exec_id: 72,
            },
            7,
            baseline,
        );
        let lane = crate::inventory_semantics::selected::ProvisionalSelectedLane::scripted_for_test(
            lane, permit,
        );
        let proof =
            SelectedActivationProof::mint(&request, binding, NativeCasReceipt::scripted(binding))
                .expect("matching receipt mints");
        service.seed_installing_for_test(request);
        service
            .reclaim_install(
                PendingInstall::from_parts(
                    proof,
                    lane,
                    coordinator.reserve_promotion_install().expect("capacity"),
                ),
                None,
            )
            .expect("a posed install reclaims");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let event = loop {
            if let Some(event) = service.poll(&mut sink) {
                break event;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "disposal settles to its terminal event"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        assert!(
            matches!(
                event,
                crate::inventory_promotion::lifecycle::LifecycleEvent::Status(_)
            ),
            "reclaim ends in a terminal status"
        );
        assert!(service.is_idle());
        // Both promotion drives left broad untouched: the window that
        // stayed open across them closes clean with identical broad
        // identity under both injected bracketing seqs.
        let (lineage, drift) = window.close(&banks, generation, 87).unwrap();
        assert_eq!(drift, None);
        assert_eq!(
            (
                &lineage.broad_mark_after.generation,
                &lineage.broad_mark_after.indices,
                &lineage.broad_mark_after.bank_ids,
                &lineage.broad_mark_after.transaction,
            ),
            (
                &lineage.broad_mark_before.generation,
                &lineage.broad_mark_before.indices,
                &lineage.broad_mark_before.bank_ids,
                &lineage.broad_mark_before.transaction,
            )
        );
        assert_eq!(
            (lineage.broad_mark_before.seq, lineage.broad_mark_after.seq),
            (41, 87)
        );
    }

    #[test]
    fn counter_detail_reserve_holds_no_generation_until_bind() {
        // The split: reserve carries no detail generation; binding
        // assigns exactly the sealed generation it is given, and
        // keeps the reservation's marks and selection.
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle split provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let child_slots = history.slots[512..513].to_vec();
        for generation in [9, 10] {
            let reservation = banks
                .reserve_detail_window(
                    super::BroadToggleFacts {
                        generation: NonZeroU64::new(7).unwrap(),
                        stopped: false,
                    },
                    &history,
                    &objects,
                    512,
                    child_slots.as_slice(),
                    41,
                    &pool.reserver(),
                )
                .unwrap();
            assert_eq!(reservation.selected(), 512);
            let window = reservation.bind_generation(generation);
            assert_eq!(window.detail_generation(), generation);
            assert_eq!(window.selected(), 512);
            assert_eq!(window.mark_before().seq, 41);
            let (lineage, drift) = window
                .close(&banks, NonZeroU64::new(7).unwrap(), 87)
                .unwrap();
            assert_eq!(drift, None);
            assert_eq!(lineage.detail_generation, generation);
        }
        // A never-bound reservation abandons with its selection and
        // no lineage: nothing ran, nothing joins.
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation: NonZeroU64::new(7).unwrap(),
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let charged = pool.snapshot().charged_bytes;
        let abandoned = reservation.abandon();
        assert_eq!(abandoned.selected, 512);
        assert_eq!(abandoned.before.seq, 41);
        assert!(
            pool.snapshot().charged_bytes < charged,
            "abandon releases the reservation charge"
        );
    }

    #[test]
    fn counter_detail_bind_revalidates_live_identity() {
        // Bind-time re-validation without banks access: an in-place
        // rewrite between reserve and bind refuses Changed (live file
        // checks on the retained clones), while a forged reservation
        // whose child names another file refuses Foreign. Both keep
        // their windows closeable: the refusal never drops the lease.
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle bind provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let child_slots = history.slots[512..513].to_vec();
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation: NonZeroU64::new(7).unwrap(),
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let window = reservation.bind_generation(9);
        window
            .validate_live_match()
            .expect("an unchanged window validates");
        std::fs::write(&path, b"toggle bind provider bytes, rewritten").unwrap();
        assert_eq!(
            window.validate_live_match().unwrap_err(),
            super::DetailToggleRefusal::Changed,
            "a rewrite between reserve and bind refuses"
        );
        // The refused window still closes with true marks: validation
        // refuses the match, never the close.
        let (lineage, _) = window
            .close(&banks, NonZeroU64::new(7).unwrap(), 87)
            .unwrap();
        assert_eq!(
            (lineage.broad_read_seq_before, lineage.broad_read_seq_after),
            (41, 87)
        );
        // Forged foreign retention: the child clone names another
        // file than the broad share was proved against. Fresh
        // fixtures: the scene above rewrote its provider file.
        let fresh_dir = tempfile::tempdir().unwrap();
        let fresh_path = toggle_provider(&fresh_dir, "provider.so", b"toggle bind fresh bytes");
        let fresh_objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &fresh_path,
            None,
            1,
            "toggle-fresh",
        );
        let fresh_object = fresh_objects.pinned().next().unwrap().id;
        let fresh_pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut fresh_history = toggle_object_plan(fresh_object, 513);
        let fresh_banks = stage_toggle_banks(&fresh_pool, &fresh_objects, &mut fresh_history);
        let foreign_dir = tempfile::tempdir().unwrap();
        let foreign_path = toggle_provider(
            &foreign_dir,
            "foreign.so",
            b"toggle bind foreign provider bytes",
        );
        let foreign_objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &foreign_path,
            None,
            1,
            "toggle-foreign",
        );
        let fresh_slots = fresh_history.slots[9..10].to_vec();
        let reservation = fresh_banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation: NonZeroU64::new(7).unwrap(),
                    stopped: false,
                },
                &fresh_history,
                &fresh_objects,
                9,
                fresh_slots.as_slice(),
                41,
                &fresh_pool.reserver(),
            )
            .unwrap();
        let window = reservation.bind_generation(9);
        let foreign_key = crate::plan::AttachKey {
            object: foreign_objects.pinned().next().unwrap().id,
            file_offset: 0x80 + 9 * 0x10,
        };
        // Same-module forgery: identical marks and selection, but the
        // retained child target names another kernel file.
        let foreign_id = foreign_objects.pinned().next().unwrap().id;
        let forged = super::CounterDetailWindow {
            before: window.mark_before().clone(),
            selected: window.selected(),
            physical: window.physical(),
            detail_generation: window.detail_generation(),
            child_keys: vec![foreign_key],
            child_targets: vec![(
                foreign_id,
                foreign_objects.retain_inventory_target(foreign_id).unwrap(),
            )],
            broad: fresh_banks.keepalive.custody.lock().unwrap().providers[9]
                .as_ref()
                .unwrap()
                .share(),
            admission: None,
            _charge: fresh_pool.reserver().reserve(1).unwrap(),
        };
        drop(window);
        assert_eq!(
            forged.validate_live_match().unwrap_err(),
            super::DetailToggleRefusal::Foreign,
            "a child naming another file refuses Foreign at bind"
        );
        let (lineage, _) = forged
            .close(&fresh_banks, NonZeroU64::new(7).unwrap(), 87)
            .unwrap();
        assert_eq!(
            (lineage.broad_read_seq_before, lineage.broad_read_seq_after),
            (41, 87),
            "the refused window still closes with true marks"
        );
    }

    #[test]
    fn counter_detail_bind_after_selected_retirement_closes_with_indices_drift() {
        // Retirement between reserve and bind is invisible to the bind
        // (no live directory at that seam — a documented gap): the
        // bind succeeds on owned data, and the close discloses the
        // retirement as Indices drift with real seqs. Never silent,
        // never fabricated.
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle retire provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let child_slots = history.slots[512..513].to_vec();
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation: NonZeroU64::new(7).unwrap(),
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        banks.directory.lock().unwrap().positions[512].state =
            super::PositionState::NeverPublishedRetired;
        let window = reservation.bind_generation(9);
        window
            .validate_live_match()
            .expect("retirement is invisible to the owned-data bind");
        let (lineage, drift) = window
            .close(&banks, NonZeroU64::new(7).unwrap(), 87)
            .unwrap();
        assert_eq!(lineage.broad_mark_before.indices.len(), 513);
        assert_eq!(lineage.broad_mark_after.indices.len(), 512);
        assert!(
            matches!(drift, Some(super::DetailToggleDrift::Indices { .. })),
            "the retired selection discloses Indices drift: {drift:?}"
        );
        assert_eq!(
            (lineage.broad_read_seq_before, lineage.broad_read_seq_after),
            (41, 87)
        );
    }

    #[test]
    fn counter_detail_close_on_quarantined_banks_refuses_without_lineage() {
        // A quarantined close refuses with no lineage at all: the
        // driver records an explicit close_refused ledger entry
        // instead. The after-mark is never fabricated from dead locks.
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle close-quarantine bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let child_slots = history.slots[512..513].to_vec();
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation: NonZeroU64::new(7).unwrap(),
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let window = reservation.bind_generation(9);
        poison_toggle_mutex(&banks.directory);
        assert_eq!(
            window
                .close(&banks, NonZeroU64::new(7).unwrap(), 87)
                .unwrap_err(),
            super::DetailToggleRefusal::Quarantined
        );
    }

    #[test]
    fn counter_detail_retention_covers_only_the_selected_child() {
        // Retention must cover the selected subset only: a small child
        // selected from a store with many unrelated pins retains just
        // its own objects, never the whole store.
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"toggle retention provider bytes");
        let mut objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "toggle-digest",
        );
        for index in 0..32 {
            let other = toggle_provider(
                &dir,
                &format!("unrelated-{index}.so"),
                b"toggle unrelated provider bytes",
            );
            let pins = crate::discovery::identity::test_fixture::real_scan_pin(
                &other,
                None,
                1,
                "toggle-unrelated",
            );
            assert!(
                objects.absorb(pins).is_empty(),
                "distinct files merge without skips"
            );
        }
        let object = objects
            .pinned()
            .find(|pin| pin.path.ends_with("provider.so"))
            .unwrap()
            .id;
        assert_eq!(
            objects.pinned().count(),
            33,
            "the premise: one provider plus 32 unrelated pins"
        );
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let mut history = toggle_object_plan(object, 513);
        let banks = stage_toggle_banks(&pool, &objects, &mut history);
        let child_slots = history.slots[512..513].to_vec();
        let before = pool.snapshot().charged_bytes;
        let reservation = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation: NonZeroU64::new(7).unwrap(),
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        let wide_charge = pool.snapshot().charged_bytes - before;
        assert_eq!(
            reservation.child_targets.len(),
            1,
            "retention holds the selected object only, not the whole store"
        );
        assert_eq!(
            reservation.child_targets[0].0, object,
            "the retained target is the selected provider"
        );
        reservation.abandon();
        // Absorbing 32 MORE unrelated pins into the same store changes
        // neither the retained set nor the charge: retention is bounded
        // to the selected subset, never to the store.
        for index in 32..64 {
            let other = toggle_provider(
                &dir,
                &format!("extra-{index}.so"),
                b"toggle extra unrelated bytes",
            );
            let pins = crate::discovery::identity::test_fixture::real_scan_pin(
                &other,
                None,
                1,
                "toggle-extra",
            );
            assert!(
                objects.absorb(pins).is_empty(),
                "distinct files merge without skips"
            );
        }
        assert_eq!(objects.pinned().count(), 65, "the store doubled");
        let before = pool.snapshot().charged_bytes;
        let again = banks
            .reserve_detail_window(
                super::BroadToggleFacts {
                    generation: NonZeroU64::new(7).unwrap(),
                    stopped: false,
                },
                &history,
                &objects,
                512,
                child_slots.as_slice(),
                41,
                &pool.reserver(),
            )
            .unwrap();
        assert_eq!(
            pool.snapshot().charged_bytes - before,
            wide_charge,
            "doubling the unrelated pins charges not one byte more"
        );
        assert_eq!(
            again.child_targets.len(),
            1,
            "doubling the unrelated pins retains not one object more"
        );
        again.abandon();
    }
}
