//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private Counts publication directory with a live format1 adapter.
//! Format2 geometry is staged and cannot yet prepare a real Session.

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

    fn validate_stage(self, slots: &[Slot], cpus: usize) -> Result<(), BankRefusal> {
        let bytes = stage_owned_bytes(slots, cpus).ok_or(BankRefusal::Budget)?;
        let fds = cpus
            .checked_mul(4)
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_mul(slots.len()))
            .ok_or(BankRefusal::Budget)?;
        if cpus == 0
            || self.retained_bytes < bytes
            || self.transient_bytes < bytes
            || self.file_descriptors < fds
        {
            return Err(BankRefusal::Budget);
        }
        Ok(())
    }
}

fn stage_owned_bytes(slots: &[Slot], cpus: usize) -> Option<usize> {
    // Bound the known Slot/per-CPU requests and their common-attach copies.
    // The fixed allowance covers this <=2-endpoint path's ordered metadata;
    // the caller separately reserves native/allocator metadata. This is a
    // requested-allocation envelope, not an exact total-memory measurement.
    let slots = slots.iter().try_fold(0usize, |total, slot| {
        total
            .checked_add(size_of::<Slot>() + 8 * OWNED_ALLOCATION_PADDING)?
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
            })?)?
            .checked_add(cpus.checked_mul(size_of::<p11scope_ebpf_common::CountStats>())?)
    })?;
    slots.checked_mul(16)?.checked_add(32 * 1024)
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

/// Format2 is staged here only. The emitted object and real Session adapter
/// continue to use the independently validated format1 layouts above.
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
    fn validate_targets(&mut self, slots: &[Slot], published: &[u32]) -> Result<(), BankRefusal>;
    fn retain_charge(&mut self, charge: ResourceLease);
    fn allocate_bank(&mut self, bank: u32) -> Result<u32, BankRefusal>;
    fn insert_inner(&mut self, bank: u32, expected_id: u32) -> Result<(), BankRefusal>;
    fn insert_route(&mut self, slot: u32, route: CountsBankRoute) -> Result<(), BankRefusal>;
    fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal>;
    fn verify_candidate(&mut self, expected: &StagedExtent) -> CandidateCheck;
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

impl BankDirectory {
    // Staged private constructor: real CounterPreparation never selects it yet.
    #[allow(dead_code)]
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

    fn legacy_published_mask(&self) -> Result<u64, BankRefusal> {
        if !self.geometry.is_legacy() {
            return Err(BankRefusal::Shape);
        }
        legacy_indices_mask(self.published_indices())
    }

    fn legacy_metadata(&self) -> Result<[Option<BankMetadata>; BANKS], BankRefusal> {
        if !self.geometry.is_legacy() {
            return Err(BankRefusal::Shape);
        }
        let mut metadata = [None; BANKS];
        for (slot, position) in self.positions.iter().enumerate() {
            if let PositionState::Published(route) = position.state {
                metadata[slot] = Some(legacy_route(slot as u32, route)?);
            }
        }
        Ok(metadata)
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
            || plan.slots.len() < self.positions.len()
            || plan.slots.iter().enumerate().any(|(index, slot)| {
                slot.index as usize != index
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
        if self.geometry.is_legacy() {
            return reservation.validate_stage(&plan.slots, cpus);
        }
        let payload = self.geometry.bank_payload_bytes(cpus)?;
        let first_bank = self.geometry.locate(extent.first)?.0;
        let last_bank = self.geometry.locate(extent.end - 1)?.0;
        let new_banks = (first_bank..=last_bank)
            .filter(|bank| {
                self.bank_ids
                    .get(*bank as usize)
                    .copied()
                    .flatten()
                    .is_none()
            })
            .count();
        let payload = payload.checked_mul(new_banks).ok_or(BankRefusal::Budget)?;
        let slots = &plan.slots[extent.first as usize..extent.end as usize];
        let copies = slots
            .iter()
            .try_fold(0usize, |total, slot| {
                total.checked_add(stage_slot_bytes(slot)?.checked_mul(4)?)
            })
            .ok_or(BankRefusal::Budget)?;
        // Count requested old/new table overlap, exact-sized route/dependency
        // buffers, native per-CPU read scratch and allocator padding. The
        // caller's additional metadata allowance is not a kernel-memory claim.
        let table = plan
            .slots
            .len()
            .checked_mul(size_of::<BankPosition>())
            .and_then(|bytes| {
                bytes.checked_add(
                    self.positions
                        .capacity()
                        .checked_mul(size_of::<BankPosition>())?,
                )
            })
            .ok_or(BankRefusal::Budget)?;
        let metadata = extent
            .len()
            .checked_mul(2 * size_of::<(u32, CountsBankRoute)>())
            .and_then(|bytes| {
                bytes.checked_add(plan.slots.len().checked_mul(size_of::<AttachKey>())?)
            })
            .and_then(|bytes| {
                bytes.checked_add(self.positions.len().checked_mul(size_of::<u32>())?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    (self.geometry.banks as usize)
                        .checked_mul(2 * size_of::<(u32, u32)>() + size_of::<Option<u32>>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(size_of::<StagedExtent>() + 16 * OWNED_ALLOCATION_PADDING)
            })
            .ok_or(BankRefusal::Budget)?;
        let retained = payload
            .checked_add(copies)
            .and_then(|bytes| bytes.checked_add(table))
            .ok_or(BankRefusal::Budget)?;
        let transient = copies
            .checked_add(table)
            .and_then(|bytes| bytes.checked_add(metadata.checked_mul(2)?))
            .and_then(|bytes| {
                bytes.checked_add(
                    cpus.checked_mul(4 * size_of::<p11scope_ebpf_common::CountStats>())?,
                )
            })
            .ok_or(BankRefusal::Budget)?;
        let fds = cpus
            .checked_mul(4)
            .and_then(|count| count.checked_add(4))
            .and_then(|count| {
                count.checked_mul(self.published_indices().count().checked_add(extent.len())?)
            })
            .and_then(|count| count.checked_add(new_banks))
            .ok_or(BankRefusal::Budget)?;
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
        plan: &AttachPlan,
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
        if let Err(reason) = io.validate_targets(&plan.slots, &published) {
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
        io.retain_charge(charge);
        self.positions = positions;
        self.budget = match plan.admission_policy() {
            crate::plan::AdmissionPolicy::Counters(budget) => Some(budget),
            _ => unreachable!("validated counter policy"),
        };
        self.next_transaction = transaction.get().checked_add(1).and_then(NonZeroU64::new);
        let commit = CountsBankCommit {
            first,
            end,
            configuration: self.geometry.configuration,
        };
        if io.observe_commit(transaction.get(), commit) != CommitObservation::Absent {
            return self.quarantine(transaction.get(), extent);
        }
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
                        let id = io.allocate_bank(bank)?;
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
            if io.verify_candidate(&expected) != CandidateCheck::Exact {
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
            if io.verify_candidate(expected) != CandidateCheck::Exact {
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

#[derive(Default)]
struct NativeCustody {
    banks: [Option<Arc<BankHandle>>; BANKS],
    // Full retained identity survives link removal, including final reads.
    providers: [Option<RetainedInventoryTarget>; BANKS],
    // Last: maps/providers drop before the requests that cover their lifetime.
    charges: [Option<ResourceLease>; BANKS],
}

/// Shared by the Session and each *actual* transferred link. A failed submit,
/// closer panic, quarantine or process-exit abandon retains the same owner.
pub(crate) struct CounterKeepalive {
    custody: Mutex<NativeCustody>,
    _base: ResourceLease,
}

impl CounterKeepalive {
    pub(crate) fn precharge(reserve: &SemanticResourceReserver, bytes: usize) -> Result<Arc<Self>> {
        ensure!(
            bytes >= size_of::<Self>() + 2 * size_of::<usize>() + OWNED_ALLOCATION_PADDING,
            "counter keepalive reservation is too small"
        );
        let charge = reserve
            .reserve(bytes)
            .map_err(|_| anyhow::anyhow!("private counter custody reservation refused"))?;
        Ok(Arc::new(Self {
            custody: Mutex::new(NativeCustody::default()),
            _base: charge,
        }))
    }
}

pub(super) struct CounterBanks {
    directory: Arc<Mutex<BankDirectory>>,
    pub(super) keepalive: Arc<CounterKeepalive>,
    cpus: usize,
    // Host transaction admission only; never native/capture/B1 authority.
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
            env!("P11SCOPE_COUNTER_BANK_PROOF_ENABLED") == "1"
                && matches!(
                    env!("P11SCOPE_COUNTER_BANK_PROOF_OUTPUTS"),
                    "counts-bank-proof"
                ),
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
        let (retained, transient) = envelope
            .charges()
            .map_err(|_| anyhow::anyhow!("invalid counter reservation"))?;
        let keepalive = CounterKeepalive::precharge(reserve, retained)?;
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
        // This constructor still prepares format1 only. Reject an incomplete
        // format2 object before common preparation can attach lifecycle roots.
        validate_format1_object_maps(|name| parsed.maps.get(name))
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
        // Both future one-cell banks coexist with all old maps/template/data.
        let payload = payload
            .checked_add(
                cpus.checked_mul(24 * BANKS)
                    .context("bank payload overflow")?,
            )
            .context("counter payload overflow")?;
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
                directory: Arc::new(Mutex::new(BankDirectory::default())),
                keepalive,
                cpus,
                link_staging: Arc::new(AtomicU64::new(0)),
            },
            _scratch: scratch,
        })
    }

    pub(super) fn validate_and_load(&self, ebpf: &mut Ebpf) -> Result<()> {
        validate_maps(ebpf)
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
                "COUNTER_BANK_META" => HashMap::<_, u32, BankMetadata>::try_from(
                    ebpf.map(name).context("counter metadata map")?,
                )?
                .keys()
                .next()
                .is_none(),
                _ => HashMap::<_, u64, BankCommit>::try_from(
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

fn validate_maps(ebpf: &Ebpf) -> Result<(), BankRefusal> {
    validate_maps_with(|name| {
        let data = map_data(ebpf.map(name).ok_or(BankRefusal::Shape)?)?;
        super::read_map_metadata(name, data).map_err(|_| BankRefusal::Shape)
    })
}

fn validate_maps_with(
    mut metadata: impl FnMut(&str) -> Result<super::ExactMapMetadata, BankRefusal>,
) -> Result<(), BankRefusal> {
    for (name, expected) in FORMAT1_MAPS {
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

fn validate_format1_object_maps<'a>(
    mut map: impl FnMut(&str) -> Option<&'a aya_obj::Map>,
) -> Result<(), BankRefusal> {
    for (name, expected) in FORMAT1_MAPS {
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
    ) != (6, 4, 24, 1, 0)
        || inner.inner().is_some()
    {
        return Err(BankRefusal::Shape);
    }
    Ok(())
}

/// Map-of-maps lookup returns an ID. Borrow the retained outer FD directly;
/// unlike HashOfMaps::get this does not open another inner FD on each scrape.
fn outer_id(ebpf: &Ebpf, key: u32) -> Result<Option<u32>, BankRefusal> {
    // Pin buffer sizes at this raw-syscall seam even if another crate-private
    // caller has replaced an Ebpf map since the original preparation.
    exact_map(ebpf, "COUNTER_BANKS", MapType::HashOfMaps, 4, 4, 2, 128)?;
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

struct NativeIo<'a> {
    session: &'a mut Session,
    objects: &'a PinnedObjects,
    custody: &'a mut NativeCustody,
    cpus: usize,
    reservation: BankReservation,
    plan: &'a AttachPlan,
}

impl BankIo for NativeIo<'_> {
    fn possible_cpus(&self) -> usize {
        self.cpus
    }

    fn validate_targets(&mut self, slots: &[Slot], published: &[u32]) -> Result<(), BankRefusal> {
        let published = legacy_indices_mask(published.iter().copied())?;
        if self.session.mutation_stopped()
            || self.session.backend != super::AttachBackend::Singles
            || self.objects.check_unchanged() != Ok(true)
            || aya::util::nr_cpus().ok() != Some(self.cpus)
        {
            return Err(BankRefusal::Topology);
        }
        validate_provider_slots(slots, self.objects, published, |index| {
            self.custody.providers[index as usize].as_ref()
        })?;
        let copies = slots
            .iter()
            .try_fold(0usize, |total, slot| {
                if self.objects.abi_for(slot.object) != Some(p11scope_manifest::elf::ElfAbi::Lp64)
                    || (published & (1 << slot.index) == 0
                        && self.session.has_slot_link(slot.index))
                {
                    return None;
                }
                total.checked_add(
                    self.objects
                        .retained_target_copy_allocation_charge(slot.object)?
                        .checked_mul(4)?,
                )
            })
            .ok_or(BankRefusal::Topology)?;
        let requested = copies
            .checked_add(stage_owned_bytes(&self.plan.slots, self.cpus).ok_or(BankRefusal::Budget)?)
            .ok_or(BankRefusal::Budget)?;
        if requested > self.reservation.retained_bytes
            || requested > self.reservation.transient_bytes
        {
            return Err(BankRefusal::Budget);
        }
        Ok(())
    }

    fn retain_charge(&mut self, charge: ResourceLease) {
        let slot = self
            .custody
            .charges
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("format1's consumed extent bounds retained attempts");
        *slot = Some(charge);
    }

    fn allocate_bank(&mut self, bank: u32) -> Result<u32, BankRefusal> {
        // Explicit format1 adapter only. Real format2 preparation/staging is
        // refused before any lifecycle or endpoint attachment.
        let index = bank as usize;
        if index >= BANKS {
            return Err(BankRefusal::Shape);
        }
        if self.custody.banks[index].is_some() {
            return Err(BankRefusal::Allocated);
        }
        let target = self.plan.slots.get(index).ok_or(BankRefusal::Topology)?;
        let retained = self
            .objects
            .retain_inventory_target(target.object)
            .map_err(|_| BankRefusal::Ownership)?;
        self.custody.providers[index] = Some(retained);
        let object = aya_obj::Map::new_from_params(6, 4, 24, 1, 0);
        let data =
            MapData::create(object, "p11_counter_bank", None).map_err(|_| BankRefusal::Native)?;
        let id = data.info().map_err(|_| BankRefusal::Native)?.id();
        if id == 0
            || self
                .custody
                .banks
                .iter()
                .flatten()
                .any(|bank| bank.id == id)
        {
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
        match outer_id(&self.session.ebpf, bank)? {
            Some(id) if id == expected_id => Ok(()),
            None if result.is_err() => Err(BankRefusal::Native),
            _ => Err(BankRefusal::Quarantined),
        }
    }

    fn insert_route(&mut self, slot: u32, route: CountsBankRoute) -> Result<(), BankRefusal> {
        let wire = legacy_route(slot, route)?;
        if self
            .custody
            .banks
            .get(route.bank as usize)
            .and_then(Option::as_ref)
            .is_none_or(|bank| bank.id != route.inner_id)
        {
            return Err(BankRefusal::Quarantined);
        }
        let mut map: HashMap<_, u32, BankMetadata> = HashMap::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANK_META")
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
        let result = map.insert(slot, wire, super::BPF_NOEXIST);
        match map.get(&slot, 0) {
            Ok(actual) if actual == wire && result.is_ok() => Ok(()),
            Err(MapError::KeyNotFound) if result.is_err() => Err(BankRefusal::Native),
            _ => Err(BankRefusal::Quarantined),
        }
    }

    fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
        let mask = legacy_indices_mask(slots.iter().map(|slot| slot.index))?;
        let banks = self
            .session
            .counter_banks
            .as_ref()
            .ok_or(BankRefusal::Shape)?;
        let _stage = banks.begin_link_stage(mask)?;
        let (failed, completed) = self
            .session
            .attach_targets(slots, self.objects)
            .map_err(|_| BankRefusal::Links)?;
        if !failed.is_empty()
            || completed.len() != slots.len()
            || self.objects.check_unchanged() != Ok(true)
            || slots.iter().any(|slot| {
                !self
                    .session
                    .current_static_sides()
                    .contains(&(slot.index, super::ProbeSide::Entry))
                    || !self
                        .session
                        .current_static_sides()
                        .contains(&(slot.index, super::ProbeSide::Return))
            })
        {
            return Err(BankRefusal::Links);
        }
        Ok(())
    }

    fn verify_candidate(&mut self, expected: &StagedExtent) -> CandidateCheck {
        if legacy_commit(expected.commit).is_err()
            || validate_maps(&self.session.ebpf).is_err()
            || self.session.mutation_stopped()
            || self.session.backend != super::AttachBackend::Singles
        {
            return CandidateCheck::Contradictory;
        }
        if aya::util::nr_cpus().ok() != Some(self.cpus) {
            return CandidateCheck::Unreadable;
        }
        let all = match legacy_indices_mask(self.plan.slots.iter().map(|slot| slot.index)) {
            Ok(mask) => mask,
            Err(_) => return CandidateCheck::Contradictory,
        };
        if self.objects.check_unchanged() != Ok(true)
            || validate_provider_slots(&self.plan.slots, self.objects, all, |index| {
                self.custody.providers[index as usize].as_ref()
            })
            .is_err()
        {
            return CandidateCheck::Contradictory;
        }
        let Some(map) = self.session.ebpf.map("COUNTER_BANK_META") else {
            return CandidateCheck::Unreadable;
        };
        let Ok(metadata): Result<HashMap<_, u32, BankMetadata>, _> = HashMap::try_from(map) else {
            return CandidateCheck::Contradictory;
        };
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
            if held.id != id || info.id() != id {
                return CandidateCheck::Contradictory;
            }
            match outer_id(&self.session.ebpf, bank) {
                Ok(Some(actual)) if actual == id => {}
                Ok(_) => return CandidateCheck::Contradictory,
                Err(_) => return CandidateCheck::Unreadable,
            }
        }
        for &(slot, route) in &expected.routes {
            let Ok(wire) = legacy_route(slot, route) else {
                return CandidateCheck::Contradictory;
            };
            if !expected.bank_ids.contains(&(route.bank, route.inner_id))
                || !sides.contains(&(slot, super::ProbeSide::Entry))
                || !sides.contains(&(slot, super::ProbeSide::Return))
            {
                return CandidateCheck::Contradictory;
            }
            match metadata.get(&slot, 0) {
                Ok(actual) if actual == wire => {}
                Ok(_) | Err(MapError::KeyNotFound) => return CandidateCheck::Contradictory,
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
        let wire = legacy_commit(commit)?;
        let mut map: HashMap<_, u64, BankCommit> = HashMap::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANK_COMMIT")
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
        map.insert(transaction, wire, super::BPF_NOEXIST)
            .map_err(|_| BankRefusal::Commit)
    }

    fn observe_commit(
        &mut self,
        transaction: u64,
        expected: CountsBankCommit,
    ) -> CommitObservation {
        let Ok(wire) = legacy_commit(expected) else {
            return CommitObservation::Contradictory;
        };
        let Some(map) = self.session.ebpf.map("COUNTER_BANK_COMMIT") else {
            return CommitObservation::Unreadable;
        };
        let Ok(map): Result<HashMap<_, u64, BankCommit>, _> = HashMap::try_from(map) else {
            return CommitObservation::Unreadable;
        };
        match map.get(&transaction, 0) {
            Ok(actual) if actual == wire => CommitObservation::Exact,
            Ok(_) => CommitObservation::Contradictory,
            Err(MapError::KeyNotFound) => CommitObservation::Absent,
            Err(_) => CommitObservation::Unreadable,
        }
    }

    fn remove_route_owned(
        &mut self,
        slot: u32,
        expected: CountsBankRoute,
    ) -> Result<(), BankRefusal> {
        let wire = legacy_route(slot, expected)?;
        if self
            .custody
            .banks
            .get(expected.bank as usize)
            .and_then(Option::as_ref)
            .is_none_or(|bank| bank.id != expected.inner_id)
        {
            return Err(BankRefusal::Ownership);
        }
        let mut map: HashMap<_, u32, BankMetadata> = HashMap::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANK_META")
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
        if map.get(&slot, 0).map_err(|_| BankRefusal::Ownership)? != wire {
            return Err(BankRefusal::Ownership);
        }
        map.remove(&slot).map_err(|_| BankRefusal::Ownership)
    }

    fn remove_new_bank_owned(&mut self, bank: u32, expected_id: u32) -> Result<(), BankRefusal> {
        if self
            .custody
            .banks
            .get(bank as usize)
            .and_then(Option::as_ref)
            .is_none_or(|held| held.id != expected_id)
            || outer_id(&self.session.ebpf, bank)? != Some(expected_id)
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
        outer.remove(&bank).map_err(|_| BankRefusal::Ownership)
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
        plan: &AttachPlan,
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
        let Ok(mut directory) = directory.lock() else {
            return BankPublication::Refused(BankRefusal::Quarantined);
        };
        if !directory.geometry.is_legacy() {
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
            reservation,
            plan,
        };
        directory.stage_with(&mut native, plan, reservation, reserve)
    }
}

impl CounterBanks {
    fn begin_link_stage(&self, mask: u64) -> Result<LinkStage, BankRefusal> {
        if mask == 0
            || mask & !3 != 0
            || self
                .link_staging
                .compare_exchange(0, mask, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return Err(BankRefusal::Quarantined);
        }
        Ok(LinkStage(Arc::clone(&self.link_staging)))
    }

    pub(super) fn permits_link_stage(&self, slots: &[Slot]) -> bool {
        !slots.is_empty()
            && slots.len() <= BANKS
            && slots.iter().all(|slot| (slot.index as usize) < BANKS)
            && self.link_staging.load(Ordering::Relaxed)
                == slots
                    .iter()
                    .fold(0u64, |mask, slot| mask | (1 << slot.index))
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
struct CounterReaderProfile {
    cpus: usize,
}

impl CounterReaderProfile {
    fn mode(&self) -> CounterMode {
        CounterMode::Counts
    }
    fn logical_slots(&self) -> usize {
        512
    }
    fn rv_keys(&self) -> usize {
        4096
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
    if !directory.geometry.is_legacy() {
        return Err(BankRefusal::Shape);
    }
    drop(directory);
    let cpus = possible_cpus()?;
    if cpus == 0 || cpus != banks.cpus {
        return Err(BankRefusal::Topology);
    }
    validate_maps_with(metadata)?;
    Ok(Some(CounterReaderProfile { cpus }))
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

/// Arc clones share the exact retained handles/charge. No get-by-ID FD is
/// opened by collection and no slot is inferred from display metadata.
pub(crate) struct CounterBankView {
    banks: [Option<Arc<BankHandle>>; BANKS],
    metadata: [Option<BankMetadata>; BANKS],
    expected: usize,
    status: BankReadStatus,
    _keepalive: Arc<CounterKeepalive>,
}

impl CounterBankView {
    pub(crate) fn bank(&self, slot: u32) -> Option<&Map> {
        self.banks
            .get(slot as usize)?
            .as_ref()
            .map(|bank| &bank.map)
    }

    pub(crate) fn routing(&self, ebpf: &Ebpf) -> Result<BankReadStatus, BankRefusal> {
        validate_maps(ebpf)?;
        if self.status != BankReadStatus::Healthy {
            return Ok(self.status);
        }
        let metadata: HashMap<_, u32, BankMetadata> =
            HashMap::try_from(ebpf.map("COUNTER_BANK_META").ok_or(BankRefusal::Shape)?)
                .map_err(|_| BankRefusal::Shape)?;
        let commits: HashMap<_, u64, BankCommit> =
            HashMap::try_from(ebpf.map("COUNTER_BANK_COMMIT").ok_or(BankRefusal::Shape)?)
                .map_err(|_| BankRefusal::Shape)?;
        for slot in 0..self.expected {
            let Some(bank) = &self.banks[slot] else {
                return Ok(BankReadStatus::Routing);
            };
            let Some(expected) = self.metadata[slot] else {
                return Ok(BankReadStatus::Routing);
            };
            match metadata.get(&(slot as u32), 0) {
                Ok(actual) if actual == expected => {}
                Ok(_) | Err(MapError::KeyNotFound) => return Ok(BankReadStatus::Routing),
                Err(_) => return Err(BankRefusal::Native),
            }
            match commits.get(&expected.transaction, 0) {
                Ok(commit)
                    if commit
                        == (BankCommit {
                            mask: expected.mask,
                            configuration: BANK_CONFIG,
                        }) => {}
                Ok(_) | Err(MapError::KeyNotFound) => return Ok(BankReadStatus::Routing),
                Err(_) => return Err(BankRefusal::Native),
            }
            if outer_id(ebpf, slot as u32)? != Some(bank.id) {
                return Ok(BankReadStatus::Routing);
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
    ) -> Result<CounterBankView, BankRefusal> {
        let banks = self.counter_banks.as_ref().ok_or(BankRefusal::Shape)?;
        let directory = banks
            .directory
            .lock()
            .map_err(|_| BankRefusal::Quarantined)?;
        if !directory.geometry.is_legacy() {
            return Err(BankRefusal::Shape);
        }
        let custody = banks
            .keepalive
            .custody
            .lock()
            .map_err(|_| BankRefusal::Quarantined)?;
        let status = match directory.validate_read_plan(plan) {
            Ok(()) => {
                validate_provider_slots(
                    &plan.slots,
                    objects,
                    directory.legacy_published_mask()?,
                    |index| custody.providers[index as usize].as_ref(),
                )?;
                BankReadStatus::Healthy
            }
            Err(BankRefusal::Quarantined) => BankReadStatus::Quarantined,
            Err(_) => BankReadStatus::Routing,
        };
        Ok(CounterBankView {
            banks: custody.banks.clone(),
            metadata: directory.legacy_metadata()?,
            expected: plan.slots.len(),
            status,
            _keepalive: Arc::clone(&banks.keepalive),
        })
    }
}

#[cfg(test)]
mod tests {
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
        checks: usize,
        damage: Option<(usize, GrowthDamage)>,
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

        fn validate_targets(&mut self, _: &[Slot], published: &[u32]) -> Result<(), BankRefusal> {
            self.require_precharge();
            self.trace.push("validate");
            assert!(published.iter().all(|slot| self.routes.contains_key(slot)));
            Ok(())
        }

        fn retain_charge(&mut self, charge: ResourceLease) {
            self.held.push(charge);
        }

        fn allocate_bank(&mut self, bank: u32) -> Result<u32, BankRefusal> {
            self.require_precharge();
            self.trace.push("allocate");
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
            self.trace.push("return");
            self.returns.extend(slots.iter().map(|slot| slot.index));
            self.trace.push("entry");
            self.entries.extend(slots.iter().map(|slot| slot.index));
            Ok(())
        }

        fn verify_candidate(&mut self, expected: &StagedExtent) -> CandidateCheck {
            self.trace.push("verify");
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
            self.trace.push("observe");
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
        assert!(matches!(
            directory.stage_with(&mut io, &plan(1), growth_reservation(), &pool.reserver()),
            BankPublication::Published { .. }
        ));
        let old = io.routes[&0];
        io.next_stage();
        assert!(matches!(
            directory.stage_with(&mut io, &plan(2), growth_reservation(), &pool.reserver()),
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
                assert!(matches!(
                    directory.stage_with(&mut io, &plan(1), growth_reservation(), &pool.reserver()),
                    BankPublication::Published { .. }
                ));
                let old = io.routes[&0];
                io.next_stage();
                io.damage = Some((at, damage));
                assert!(
                    matches!(
                        directory.stage_with(
                            &mut io,
                            &plan(2),
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
                    directory.validate_read_plan(&plan(2)),
                    Err(BankRefusal::Quarantined)
                );
            }
        }
        for unreadable in [false, true] {
            let mut directory = BankDirectory::counts_growth_v2();
            let mut io = GrowthIo::new(&pool);
            assert!(matches!(
                directory.stage_with(&mut io, &plan(1), growth_reservation(), &pool.reserver()),
                BankPublication::Published { .. }
            ));
            io.next_stage();
            io.commit_unreadable = unreadable;
            io.commit_wrong = !unreadable;
            assert!(matches!(
                directory.stage_with(&mut io, &plan(2), growth_reservation(), &pool.reserver()),
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
            assert!(matches!(
                directory.stage_with(&mut io, &plan(1), growth_reservation(), &pool.reserver()),
                BankPublication::Published { .. }
            ));
            let old = io.routes[&0];
            io.next_stage();
            io.commit_absent = true;
            io.damage = damage.map(|kind| (2, kind));
            let publication =
                directory.stage_with(&mut io, &plan(2), growth_reservation(), &pool.reserver());
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
                    directory.stage_with(&mut io, &plan(2), growth_reservation(), &pool.reserver()),
                    BankPublication::Refused(BankRefusal::Quarantined)
                );
                assert!(io.trace.is_empty());
                assert_eq!(
                    directory.validate_read_plan(&plan(2)),
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
            directory.stage_with(&mut io, &history, growth_reservation(), &pool.reserver()),
            BankPublication::Published { .. }
        ));
        let old = io.routes[&0];
        history.extend_exact(plan(2)).unwrap();
        io.next_stage();
        io.commit_absent = true;
        assert!(matches!(
            directory.stage_with(&mut io, &history, growth_reservation(), &pool.reserver()),
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
            directory.stage_with(&mut io, &history, growth_reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Allocated)
        ));
        assert!(io.trace.is_empty());
        history.deactivate(1);
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
            directory.stage_with(&mut io, &history, growth_reservation(), &pool.reserver()),
            BankPublication::Published { .. }
        ));
        assert_eq!(directory.allocated_high_water(), 3);
        assert_eq!(directory.published_indices().collect::<Vec<_>>(), [0, 2]);
        assert_eq!(io.routes.keys().copied().collect::<Vec<_>>(), [0, 2]);
        assert_eq!(io.routes[&0], old);
        assert_eq!((io.routes[&2].bank, io.routes[&2].cell), (0, 2));
        // Directory high-water only: no plan floor or tail helper is exercised.
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
                directory.stage_with(&mut io, &plan(1), bad, &pool.reserver()),
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
            let result = directory.stage_with(&mut io, &plan(1), envelope, &pool.reserver());
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
        assert!(matches!(
            directory.stage_with(&mut io, &plan(1), growth_reservation(), &pool.reserver()),
            BankPublication::Published { .. }
        ));
        let old = io.routes[&0];
        let charged = pool.snapshot().charged_bytes;
        io.next_stage();
        let refused = SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH);
        assert_eq!(
            directory.stage_with(&mut io, &plan(2), growth_reservation(), &refused.reserver()),
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
            let publication =
                directory.stage_with(&mut io, &plan(1), growth_reservation(), &pool.reserver());
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
        targets: Vec<Slot>,
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
        ) -> Result<(), BankRefusal> {
            self.trace.push("validate");
            let published = legacy_indices_mask(published.iter().copied())?;
            if let Some((pins, retained)) = &self.provider_guard {
                validate_provider_slots(slots, pins, published, |index| {
                    retained[index as usize].as_ref()
                })?;
            }
            self.targets = slots.to_vec();
            Ok(())
        }

        fn retain_charge(&mut self, charge: ResourceLease) {
            self.held.push(charge);
        }

        fn allocate_bank(&mut self, slot: u32) -> Result<u32, BankRefusal> {
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
                let target = self
                    .targets
                    .get(slot as usize)
                    .ok_or(BankRefusal::Topology)?;
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

        fn verify_candidate(&mut self, expected: &StagedExtent) -> CandidateCheck {
            self.trace.push("verify");
            if let Some((pins, retained)) = &self.provider_guard {
                let Ok(all) = legacy_indices_mask(self.targets.iter().map(|slot| slot.index))
                else {
                    return CandidateCheck::Contradictory;
                };
                if validate_provider_slots(&self.targets, pins, all, |index| {
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
            directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver()),
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
            directory: Arc::new(Mutex::new(BankDirectory::default())),
            keepalive: CounterKeepalive::precharge(&pool.reserver(), 4096).unwrap(),
            cpus: 2,
            link_staging: Arc::new(AtomicU64::new(0)),
        };
        let targets = plan(2).slots;
        assert!(!banks.permits_link_stage(&targets));
        let stage = banks.begin_link_stage(3).unwrap();
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
            directory.stage_with(&mut native, &plan(1), reservation(), &refused.reserver()),
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
        let BankPublication::Published {
            transaction: old,
            extent: BankExtent { first: 0, end: 1 },
        } = directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver())
        else {
            panic!("first real transaction did not publish");
        };
        let original = native.metadata[&0];
        native.fail = Some("commit-ack-lost");
        let BankPublication::Published {
            transaction: new,
            extent: BankExtent { first: 1, end: 2 },
        } = directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver())
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
        assert!(directory.validate_read_plan(&plan(2)).is_ok());

        let before = native.trace.len();
        let mut replacement = plan(2);
        replacement.slots[0].object = PinnedObjectId(99);
        assert_eq!(
            directory.stage_with(&mut native, &replacement, reservation(), &pool.reserver()),
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
            assert!(
                matches!(
                    directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver()),
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
                directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver()),
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
            directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
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
            assert!(matches!(
                directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
                BankPublication::Quarantined { .. }
            ));
            assert_eq!(native.inners.len(), 1);
            assert_eq!(native.metadata.len(), 1);
            assert!(!native.held.is_empty());
            assert!(!native.trace.contains(&"remove-inner"));
            assert_eq!(
                directory.validate_read_plan(&plan(1)),
                Err(BankRefusal::Quarantined)
            );
            let before = native.trace.len();
            assert_eq!(
                directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver()),
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
            directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
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
            directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
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
            directory.stage_with(&mut native, &plan(3), reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Shape),
        );
        let mut aliases = plan(2);
        aliases.slots[1].object = aliases.slots[0].object;
        assert_eq!(
            directory.stage_with(&mut native, &aliases, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Topology),
        );
        assert!(native.trace.is_empty());
        directory.next_transaction = std::num::NonZeroU64::new(u64::MAX);
        assert!(matches!(
            directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver()),
            BankPublication::Published {
                transaction: u64::MAX,
                ..
            }
        ));
        let before = native.trace.len();
        assert_eq!(
            directory.stage_with(&mut native, &plan(2), reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Exhausted),
        );
        assert_eq!(native.trace.len(), before);
        assert!(directory.validate_read_plan(&plan(1)).is_ok());
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
        let mut selected = plan(1);
        selected.slots[0].object = id;
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
            directory.stage_with(&mut native, &selected, reservation(), &pool.reserver()),
            BankPublication::Published {
                transaction: 1,
                extent: BankExtent { first: 0, end: 1 }
            }
        ));
        let mut appended = plan(2);
        appended.slots[0].object = id;
        // A separately built store now assigns zero to a foreign provider and
        // one to the original provider. Numeric prefix checks alone accept it.
        let mut switched = foreign;
        assert!(switched.absorb(same).is_empty());
        assert_eq!(switched.pinned().count(), 2);
        appended.slots[1].object = switched
            .pinned()
            .map(|pin| pin.id)
            .find(|&id| id != selected.slots[0].object)
            .unwrap();
        let bindings = native.provider_guard.as_mut().unwrap();
        bindings.0 = switched;
        let charged = pool.snapshot().charged_bytes;
        let before = native.trace.len();
        assert_eq!(
            directory.stage_with(&mut native, &appended, reservation(), &pool.reserver()),
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
            directory.stage_with(&mut native, &appended, reservation(), &pool.reserver()),
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
        let mut duplicate = plan(2);
        duplicate.slots[0].object = ids[0];
        duplicate.slots[1].object = ids[1];
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut native = Native {
            provider_guard: Some((pins, [Some(retained), None])),
            ..Native::default()
        };
        let mut directory = BankDirectory::default();
        let first = AttachPlan::from_slots_with_policy(
            duplicate.slots[..1].to_vec(),
            duplicate.admission_policy(),
        )
        .unwrap();
        assert!(matches!(
            directory.stage_with(&mut native, &first, reservation(), &pool.reserver()),
            BankPublication::Published {
                extent: BankExtent { first: 0, end: 1 },
                ..
            }
        ));
        let before = native.trace.len();
        assert_eq!(
            directory.stage_with(&mut native, &duplicate, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Ownership)
        );
        assert_eq!(directory.legacy_published_mask().unwrap(), 1);
        assert_eq!(directory.allocated_high_water(), 1);
        assert_eq!(native.commits.len(), 1);
        assert!(!native.trace[before..].contains(&"allocate"));
        let (pins, retained) = native.provider_guard.as_ref().unwrap();
        duplicate.slots[1].file_offset += 8;
        assert_eq!(
            validate_provider_slots(&duplicate.slots, pins, 1, |index| {
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
            directory: Arc::new(Mutex::new(BankDirectory::default())),
            keepalive: CounterKeepalive::precharge(&pool.reserver(), 4096).unwrap(),
            cpus: 2,
            link_staging: Arc::new(AtomicU64::new(0)),
        }
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
