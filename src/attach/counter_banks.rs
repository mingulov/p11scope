//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private Counts publication, retained native custody and charged collection.

use super::{CapturePolicy, Scope, Session};
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
const BANKS: usize = 2;
const GROWTH_BANKS: usize = 16;
pub(super) const PROGRAMS: [&str; 2] = ["p11_counter_bank_entry", "p11_counter_bank_return"];

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
            return Err(BankRefusal::Shape);
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
struct CountsBankGeometry {
    banks: u32,
    cells: u32,
    configuration: u64,
}

impl CountsBankGeometry {
    fn legacy() -> Self {
        Self {
            banks: 2,
            cells: 1,
            configuration: BANK_CONFIG,
        }
    }

    fn checked(banks: u32, cells: u32) -> Result<Self, BankRefusal> {
        if (banks, cells) != (16, 512) || banks.checked_mul(cells) != Some(8192) {
            return Err(BankRefusal::Shape);
        }
        Ok(Self {
            banks,
            cells,
            configuration: COUNTS_GROWTH_V2_CONFIG,
        })
    }

    fn is_legacy(self) -> bool {
        self == Self::legacy()
    }

    fn validate(self) -> Result<(), BankRefusal> {
        if self.is_legacy() || Self::checked(self.banks, self.cells) == Ok(self) {
            Ok(())
        } else {
            Err(BankRefusal::Shape)
        }
    }

    fn selected(profile: &str) -> Result<Self, BankRefusal> {
        match profile {
            "counts-bank-proof" => Ok(Self::legacy()),
            "counts-bank-growth-v2" => Self::checked(16, 512),
            _ => Err(BankRefusal::Shape),
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
            return Err(BankRefusal::Shape);
        }
        Ok((slot / self.cells, slot % self.cells))
    }

    fn bank_payload_bytes(self, cpus: usize) -> Result<usize, BankRefusal> {
        if cpus == 0 {
            return Err(BankRefusal::Topology);
        }
        (self.cells as usize)
            .checked_mul(size_of::<p11scope_ebpf_common::CountStats>())
            .and_then(|bytes| bytes.checked_mul(cpus))
            .ok_or(BankRefusal::Budget)
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
            CountsBankGeometry::checked(16, 512)?,
            transaction,
            commit,
            routes,
            bank_ids,
        )
    }

    fn checked_with(
        geometry: CountsBankGeometry,
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
            return Err(BankRefusal::Shape);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BankRefusal {
    Shape,
    Topology,
    Allocated,
    Exhausted,
    Budget,
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
        FdLimit::Finite(limit) if total > limit => Err(BankRefusal::Budget),
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
    geometry: CountsBankGeometry,
    all_slots: &[Slot],
    fresh: BankExtent,
    old_capacity: usize,
    cpus: usize,
    new_banks: usize,
    provider_copies: usize,
    slot_copies: usize,
) -> Result<(usize, usize, usize, usize), BankRefusal> {
    geometry.validate()?;
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
        .and_then(|n| {
            n.checked_add(cpus.checked_mul(4 * size_of::<p11scope_ebpf_common::CountStats>())?)
        })
        .ok_or(BankRefusal::Budget)?;
    // Singles + OneProcess uses Aya's pid-scoped perf-event path, with a
    // retained FD per endpoint side and a transient perf FD during BPF-link
    // creation. The conservative (4*C+4)*slots+new_banks request includes
    // historical custody and staging: at C=2, 8192 slots +16 maps is 98,320.
    // NativeIo checks this fixed backend/scope, the caller reservation and
    // current OS headroom. This is neither an atomic reservation nor measured
    // useful-8192 qualification; subsequent EMFILE uses paid rollback/custody.
    let fds = cpus
        .checked_mul(4)
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_mul(all_slots.len()))
        .and_then(|n| n.checked_add(new_banks))
        .ok_or(BankRefusal::Budget)?;
    Ok((retained, transient, metadata, fds))
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
    geometry: CountsBankGeometry,
    positions: Vec<BankPosition>,
    bank_ids: Vec<Option<u32>>,
    next_transaction: Option<NonZeroU64>,
    quarantined: bool,
    budget: Option<crate::capacity::CounterBudget>,
}

impl Default for BankDirectory {
    fn default() -> Self {
        Self {
            geometry: CountsBankGeometry::legacy(),
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
    fn counts_growth_v2() -> Self {
        Self {
            geometry: CountsBankGeometry::checked(16, 512).expect("closed Counts geometry"),
            ..Self::default()
        }
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
            return Err(BankRefusal::Shape);
        }
        legacy_indices_mask(self.published_indices())
    }

    fn validate_plan(&self, plan: &AttachPlan) -> Result<(), BankRefusal> {
        let crate::plan::AdmissionPolicy::Counters(budget) = plan.admission_policy() else {
            return Err(BankRefusal::Shape);
        };
        if budget.validate_count(plan.slots.len()).is_err()
            || plan.slots.len() > self.geometry.limit() as usize
        {
            return Err(BankRefusal::Shape);
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
        if reservation.retained_bytes < retained
            || reservation.transient_bytes < transient
            || reservation.metadata_bytes < metadata
            || reservation.file_descriptors < fds
        {
            return Err(BankRefusal::Budget);
        }
        Ok(())
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
            return Err(BankRefusal::Shape);
        }
        mask |= 1 << index;
    }
    Ok(mask)
}

fn legacy_commit(commit: CountsBankCommit) -> Result<BankCommit, BankRefusal> {
    if commit.configuration != BANK_CONFIG {
        return Err(BankRefusal::Shape);
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
        return Err(BankRefusal::Shape);
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
        Self::precharge_with_geometry(reserve, bytes, CountsBankGeometry::legacy())
    }

    fn precharge_with_geometry(
        reserve: &SemanticResourceReserver,
        bytes: usize,
        geometry: CountsBankGeometry,
    ) -> Result<Arc<Self>> {
        geometry
            .validate()
            .map_err(|_| anyhow::anyhow!("unsupported counter geometry"))?;
        let positions = geometry.limit() as usize;
        let required = positions
            .checked_mul(size_of::<Option<RetainedInventoryTarget>>() + size_of::<ResourceLease>())
            .and_then(|n| {
                n.checked_add(
                    size_of::<Self>() + 2 * size_of::<usize>() + 3 * OWNED_ALLOCATION_PADDING,
                )
            })
            .context("counter custody capacity overflow")?;
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
    geometry: CountsBankGeometry,
    // Immutable geometry avoids reentering the Directory lock during stage.
    link_staging: Arc<AtomicU64>,
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
        ensure!(
            env!("P11SCOPE_COUNTER_BANK_PROOF_ENABLED") == "1",
            "private Counts bank artifact was not selected at build time"
        );
        ensure!(
            !cfg!(any(
                feature = "unsafe-unvalidated-metadata",
                feature = "wide-detailed-2112",
                feature = "stub-object-attributes"
            )),
            "private Counts bank preparation requires its fixed artifact configuration"
        );
        let geometry = CountsBankGeometry::selected(env!("P11SCOPE_COUNTER_BANK_PROOF_OUTPUTS"))
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
        let parsed = aya_obj::Object::parse(object).context("parsing selected counter artifact")?;
        // Parse and validate actual maps/template before common loading can
        // attach lifecycle roots. An emitted token alone grants no shape.
        validate_object_maps(geometry, |name| parsed.maps.get(name))
            .map_err(|_| anyhow::anyhow!("unsupported private counter artifact profile"))?;
        ensure!(
            PROGRAMS
                .iter()
                .all(|name| parsed.programs.contains_key(*name)),
            "selected object lacks the exact private Counts bank roots"
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
        ensure!(
            envelope.retained_bytes
                >= payload
                    .checked_add(
                        size_of::<CounterBanks>()
                            + size_of::<CounterKeepalive>()
                            + size_of::<Session>()
                            + 16 * OWNED_ALLOCATION_PADDING
                    )
                    .context("counter retained bound overflow")?,
            "counter retained reservation is smaller than configured data capacity"
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
                link_staging: Arc::new(AtomicU64::new(0)),
            },
            _scratch: scratch,
        })
    }

    pub(super) fn validate_and_load(&self, ebpf: &mut Ebpf) -> Result<()> {
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
            root.load()
                .with_context(|| format!("loading private counter root {program}"))?;
        }
        Ok(())
    }
}

fn map_data(map: &Map) -> Result<&MapData, BankRefusal> {
    match map {
        Map::HashOfMaps(data)
        | Map::Array(data)
        | Map::HashMap(data)
        | Map::PerCpuArray(data)
        | Map::PerCpuHashMap(data) => Ok(data),
        _ => Err(BankRefusal::Shape),
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
    let data = map_data(ebpf.map(name).ok_or(BankRefusal::Shape)?)?;
    let actual = super::read_map_metadata(name, data).map_err(|_| BankRefusal::Shape)?;
    super::compare_map_metadata(
        name,
        actual,
        super::map_metadata(kind, key, value, entries, flags),
    )
    .map_err(|_| BankRefusal::Shape)
}

fn exact_map_metadata(
    map: &Map,
    kind: MapType,
    key: u32,
    value: u32,
    entries: u32,
    flags: u32,
) -> Result<(), BankRefusal> {
    let actual = super::read_map_metadata("retained counter bank", map_data(map)?)
        .map_err(|_| BankRefusal::Native)?;
    super::compare_map_metadata(
        "retained counter bank",
        actual,
        super::map_metadata(kind, key, value, entries, flags),
    )
    .map_err(|_| BankRefusal::Shape)
}

fn validate_maps(ebpf: &Ebpf, geometry: CountsBankGeometry) -> Result<(), BankRefusal> {
    validate_maps_for(geometry, |name| {
        let data = map_data(ebpf.map(name).ok_or(BankRefusal::Shape)?)?;
        super::read_map_metadata(name, data).map_err(|_| BankRefusal::Shape)
    })
}

#[cfg(test)]
fn validate_maps_with(
    metadata: impl FnMut(&str) -> Result<super::ExactMapMetadata, BankRefusal>,
) -> Result<(), BankRefusal> {
    validate_maps_for(CountsBankGeometry::legacy(), metadata)
}

fn profile_maps(
    geometry: CountsBankGeometry,
) -> &'static [(&'static str, super::ExactMapMetadata)] {
    if geometry.is_legacy() {
        &FORMAT1_MAPS
    } else {
        &FORMAT2_MAPS
    }
}

fn validate_maps_for(
    geometry: CountsBankGeometry,
    mut metadata: impl FnMut(&str) -> Result<super::ExactMapMetadata, BankRefusal>,
) -> Result<(), BankRefusal> {
    geometry.validate()?;
    for &(name, expected) in profile_maps(geometry) {
        super::compare_map_metadata(name, metadata(name)?, expected)
            .map_err(|_| BankRefusal::Shape)?;
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
    validate_object_maps(CountsBankGeometry::legacy(), map)
}

fn validate_object_maps<'a>(
    geometry: CountsBankGeometry,
    mut map: impl FnMut(&str) -> Option<&'a aya_obj::Map>,
) -> Result<(), BankRefusal> {
    geometry.validate()?;
    for &(name, expected) in profile_maps(geometry) {
        let actual = map(name).ok_or(BankRefusal::Shape)?;
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
            return Err(BankRefusal::Shape);
        }
    }
    let inner = map("COUNTER_BANKS")
        .and_then(aya_obj::Map::inner)
        .ok_or(BankRefusal::Shape)?;
    if (
        inner.map_type(),
        inner.key_size(),
        inner.value_size(),
        inner.max_entries(),
        inner.map_flags(),
    ) != (6, 4, 24, geometry.cells, 0)
        || inner.inner().is_some()
    {
        return Err(BankRefusal::Shape);
    }
    Ok(())
}

/// Map-of-maps lookup returns an ID. Borrow the retained outer FD directly;
/// unlike HashOfMaps::get this does not open another inner FD on each scrape.
fn outer_id(
    ebpf: &Ebpf,
    geometry: CountsBankGeometry,
    key: u32,
) -> Result<Option<u32>, BankRefusal> {
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
        return Err(BankRefusal::Shape);
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
    geometry: CountsBankGeometry,
    slot: u32,
    expected: CountsBankRoute,
) -> Result<Option<bool>, BankRefusal> {
    let map = ebpf.map("COUNTER_BANK_META").ok_or(BankRefusal::Shape)?;
    if geometry.is_legacy() {
        let map: HashMap<_, u32, BankMetadata> =
            HashMap::try_from(map).map_err(|_| BankRefusal::Shape)?;
        match map.get(&slot, 0) {
            Ok(actual) => Ok(Some(actual == legacy_route(slot, expected)?)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(_) => Err(BankRefusal::Native),
        }
    } else {
        let map: HashMap<_, u32, CountsBankRoute> =
            HashMap::try_from(map).map_err(|_| BankRefusal::Shape)?;
        match map.get(&slot, 0) {
            Ok(actual) => Ok(Some(actual == expected)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(_) => Err(BankRefusal::Native),
        }
    }
}

fn observe_native_commit(
    ebpf: &Ebpf,
    geometry: CountsBankGeometry,
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
    geometry: CountsBankGeometry,
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
            || self.session.backend != super::AttachBackend::Singles
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
        if self.reservation.retained_bytes < retained
            || self.reservation.transient_bytes < transient
            || self.reservation.metadata_bytes < metadata
            || self.reservation.file_descriptors < fds
        {
            return Err(BankRefusal::Budget);
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
            return Err(BankRefusal::Shape);
        }
        if self.custody.banks[index].is_some() {
            return Err(BankRefusal::Allocated);
        }
        let object = aya_obj::Map::new_from_params(6, 4, 24, self.geometry.cells, 0);
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
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
        let result = outer.insert(bank, map_data(&held.map)?, super::BPF_NOEXIST);
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
            .ok_or(BankRefusal::Shape)?;
        let result = if self.geometry.is_legacy() {
            let mut map: HashMap<_, u32, BankMetadata> =
                HashMap::try_from(map).map_err(|_| BankRefusal::Shape)?;
            map.insert(slot, legacy_route(slot, route)?, super::BPF_NOEXIST)
        } else {
            let mut map: HashMap<_, u32, CountsBankRoute> =
                HashMap::try_from(map).map_err(|_| BankRefusal::Shape)?;
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
            .ok_or(BankRefusal::Shape)?;
        let banks = self
            .session
            .counter_banks
            .as_ref()
            .ok_or(BankRefusal::Shape)?;
        let _stage = banks.begin_link_stage((u64::from(first) << 32) | u64::from(end))?;
        let (failed, completed) = self
            .session
            .attach_targets(slots, self.objects)
            .map_err(|_| BankRefusal::Links)?;
        let sides = self.session.current_static_sides();
        if !failed.is_empty()
            || completed.len() != slots.len()
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
            || self.session.backend != super::AttachBackend::Singles
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
            let Ok(data) = map_data(&held.map) else {
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
                    24,
                    self.geometry.cells,
                    0,
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
            .ok_or(BankRefusal::Shape)?;
        if self.geometry.is_legacy() {
            let mut map: HashMap<_, u64, BankCommit> =
                HashMap::try_from(map).map_err(|_| BankRefusal::Shape)?;
            map.insert(transaction, legacy_commit(commit)?, super::BPF_NOEXIST)
                .map_err(|_| BankRefusal::Commit)
        } else {
            let mut map: HashMap<_, u64, CountsBankCommit> =
                HashMap::try_from(map).map_err(|_| BankRefusal::Shape)?;
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
            .ok_or(BankRefusal::Shape)?;
        if self.geometry.is_legacy() {
            let mut map: HashMap<_, u32, BankMetadata> =
                HashMap::try_from(map).map_err(|_| BankRefusal::Shape)?;
            map.remove(&slot).map_err(|_| BankRefusal::Ownership)
        } else {
            let mut map: HashMap<_, u32, CountsBankRoute> =
                HashMap::try_from(map).map_err(|_| BankRefusal::Shape)?;
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
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
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

impl Session {
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
        let (mut session, prepared_instance) = Self::prepare_inner_unlinked_with_object(
            scope,
            CapturePolicy::AggregateOnly,
            None,
            None,
            None,
            super::AttachBackend::Singles,
            None,
            Some(preparation),
        )?;
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
            return BankPublication::Refused(BankRefusal::Shape);
        };
        let directory = Arc::clone(&banks.directory);
        let keepalive = Arc::clone(&banks.keepalive);
        let cpus = banks.cpus;
        let geometry = banks.geometry;
        let Ok(mut directory) = directory.lock() else {
            return BankPublication::Refused(BankRefusal::Quarantined);
        };
        if directory.geometry != geometry {
            return BankPublication::Refused(BankRefusal::Shape);
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

/// The current constructor prepares only the validated native Counts proof.
/// This is not inferred from a caller's requested mode or a map's name.
#[derive(Clone, Copy)]
struct CounterReaderProfile {
    cpus: usize,
    geometry: CountsBankGeometry,
}

impl CounterReaderProfile {
    fn mode(&self) -> CounterMode {
        CounterMode::Counts
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
        return Err(BankRefusal::Shape);
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
                let data = map_data(self.ebpf.map(name).ok_or(BankRefusal::Shape)?)?;
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
            return Err(BankRefusal::Shape);
        }
        directory.validate_read_plan(plan)?;
        if plan.slots.len() != directory.positions.len()
            || plan.counter_consumed_end() as usize != directory.positions.len()
        {
            return Err(BankRefusal::Topology);
        }
        let count = directory.published_indices().count();
        let bytes = count
            .checked_mul(
                size_of::<PublishedRow>() + size_of::<u32>() + size_of::<(u64, u64, u64)>(),
            )
            .and_then(|n| {
                n.checked_add(
                    directory
                        .positions
                        .len()
                        .checked_mul(size_of::<AttachKey>() + 1)?,
                )
            })
            .and_then(|n| {
                n.checked_add(size_of::<CounterBankView>() + 5 * OWNED_ALLOCATION_PADDING)
            })
            .ok_or(BankRefusal::Budget)?;
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
                if exact_map_metadata(&held.map, MapType::PerCpuArray, 4, 24, geometry.cells, 0)
                    .is_err()
                    || map_data(&held.map)?
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
        let banks = self.counter_banks.as_ref().ok_or(BankRefusal::Shape)?;
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
            _: &[Slot],
            published: &[u32],
            _fresh: BankExtent,
            _old_capacity: usize,
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
        let geometry = CountsBankGeometry::checked(16, 512).unwrap();
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
            assert!(CountsBankGeometry::checked(banks, cells).is_err());
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
            assert_eq!(
                validate_format1_object_maps(|name| changed.get(name)),
                Err(BankRefusal::Shape)
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
            Err(BankRefusal::Shape)
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
                    BankRefusal::Shape
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
        let geometry = CountsBankGeometry::checked(16, 512).unwrap();
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
                assert!(matches!(result, BankPublication::Published { .. }));
                assert_eq!(io.maps.len(), 1);
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
            CapturePolicy::AggregateOnly,
            false,
            StaticRoots::CounterBanks,
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
            geometry: CountsBankGeometry::legacy(),
            directory: Arc::new(Mutex::new(BankDirectory::default())),
            keepalive: CounterKeepalive::precharge(&pool.reserver(), 4096).unwrap(),
            cpus: 2,
            link_staging: Arc::new(AtomicU64::new(0)),
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
            BankPublication::Refused(BankRefusal::Shape),
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
            _ => return Err(BankRefusal::Shape),
        };
        Ok(super::super::map_metadata(kind, key, value, entries, flags))
    }

    fn reader_banks(pool: &SemanticResourcePool) -> CounterBanks {
        CounterBanks {
            geometry: CountsBankGeometry::legacy(),
            directory: Arc::new(Mutex::new(BankDirectory::default())),
            keepalive: CounterKeepalive::precharge(&pool.reserver(), 4096).unwrap(),
            cpus: 2,
            link_staging: Arc::new(AtomicU64::new(0)),
        }
    }

    fn growth_provider_fixture() -> (tempfile::TempDir, PinnedObjects, Slot, Slot, String) {
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
        let (dir, pins, first, second, digest) = growth_provider_fixture();
        let pool = SemanticResourcePool::reference_limit(256 * 1024 * 1024);
        let geometry = CountsBankGeometry::checked(16, 512).unwrap();
        let keepalive =
            CounterKeepalive::precharge_with_geometry(&pool.reserver(), 16 * 1024 * 1024, geometry)
                .unwrap();
        let policy = crate::plan::AdmissionPolicy::counters(
            crate::capacity::CounterBudget::new(8192).unwrap(),
        );
        let mut history = AttachPlan::from_slots_with_policy(vec![first.clone()], policy).unwrap();
        let mut directory = BankDirectory::counts_growth_v2();
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
                link_staging: Arc::new(AtomicU64::new(0)),
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
        let owned = growth_owned_history(last_slot);
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
                Some(BankRefusal::Budget),
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
            // At two possible CPUs, the existing conservative shared-bank
            // two-slot envelope is 24 FD slots. The caller allows 128: only
            // the independently observed OS headroom differs across twins.
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
    fn format2_charge_holders_cover_8192_nonempty_extents() {
        let pool = SemanticResourcePool::reference_limit(64 * 1024 * 1024);
        let charged = pool.snapshot().charged_bytes;
        let geometry = CountsBankGeometry::checked(16, 512).unwrap();
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
            CountsBankGeometry::checked(16, 512).unwrap(),
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
        assert_eq!(env!("P11SCOPE_COUNTER_BANK_PROOF_ENABLED"), "1");
        assert_eq!(
            env!("P11SCOPE_COUNTER_BANK_PROOF_OUTPUTS"),
            "counts-bank-growth-v2"
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
    fn format2_link_stage_requires_exact_extent() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut banks = reader_banks(&pool);
        banks.geometry = CountsBankGeometry::checked(16, 512).unwrap();
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
            Err(BankRefusal::Shape)
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
                Err(BankRefusal::Shape)
            ),
            "a timestamps-shaped map cannot relabel this Counts preparation"
        );
    }
}
