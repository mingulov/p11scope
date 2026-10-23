//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private two-cell Counts transaction. This is not general counter growth.

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
use std::mem::size_of;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) const BANK_CONFIG: u64 = 0x1800_0102;
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
        mask: u64,
    },
    RolledBack {
        transaction: u64,
        mask: u64,
        reason: BankRefusal,
    },
    Quarantined {
        transaction: u64,
        mask: u64,
    },
    Refused(BankRefusal),
}

/// Native operations sit below the production transaction. No operation may
/// replace a key or discard ownership when it reports an uncertain result.
trait BankIo {
    fn possible_cpus(&self) -> usize;
    fn validate_targets(&mut self, slots: &[Slot], published: u64) -> Result<(), BankRefusal>;
    fn retain_charge(&mut self, charge: ResourceLease);
    fn allocate(&mut self, slot: u32) -> Result<(), BankRefusal>;
    fn insert_inner(&mut self, slot: u32) -> Result<(), BankRefusal>;
    fn insert_metadata(&mut self, slot: u32, metadata: BankMetadata) -> Result<(), BankRefusal>;
    fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal>;
    fn insert_commit(&mut self, transaction: u64, commit: BankCommit) -> Result<(), BankRefusal>;
    fn acknowledge(&mut self, transaction: u64) -> CommitAck;
    fn remove_metadata_owned(
        &mut self,
        slot: u32,
        expected: BankMetadata,
    ) -> Result<(), BankRefusal>;
    fn remove_inner_owned(&mut self, slot: u32) -> Result<(), BankRefusal>;
    fn retire_links(&mut self, slots: &[Slot]) -> Result<(), BankRefusal>;
}

struct BankDirectory {
    keys: [Option<AttachKey>; BANKS],
    allocated: u64,
    published: u64,
    next_transaction: Option<NonZeroU64>,
    quarantined: bool,
    metadata: [Option<BankMetadata>; BANKS],
    budget: Option<crate::capacity::CounterBudget>,
}

impl Default for BankDirectory {
    fn default() -> Self {
        Self {
            keys: [None; BANKS],
            allocated: 0,
            published: 0,
            next_transaction: NonZeroU64::new(1),
            quarantined: false,
            metadata: [None; BANKS],
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
    fn published_mask(&self) -> u64 {
        self.published
    }

    fn validate_plan(&self, plan: &AttachPlan) -> Result<(), BankRefusal> {
        let crate::plan::AdmissionPolicy::Counters(budget) = plan.admission_policy() else {
            return Err(BankRefusal::Shape);
        };
        if budget.validate_count(plan.slots.len()).is_err() {
            return Err(BankRefusal::Shape);
        }
        if self.budget.is_some_and(|old| old != budget) {
            return Err(BankRefusal::Topology);
        }
        if plan.slots.len() > BANKS {
            return Err(BankRefusal::Shape);
        }
        if plan.slots.iter().enumerate().any(|(index, slot)| {
            slot.index as usize != index
                || self.keys[index].is_some_and(|old| old != physical(slot))
                || plan.slots[..index]
                    .iter()
                    .any(|old| physical(old) == physical(slot))
        }) || self.keys.iter().skip(plan.slots.len()).any(Option::is_some)
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
        {
            return Err(BankRefusal::Topology);
        }
        // Rolled-back allocated positions remain retired. An old published
        // prefix can still be read; it never reuses those failed positions.
        if plan.slots.len() > BANKS
            || plan.slots.iter().enumerate().any(|(index, slot)| {
                slot.index as usize != index
                    || self.keys[index] != Some(physical(slot))
                    || self.published & (1 << index) == 0
            })
            || self.published != (1u64 << plan.slots.len()) - 1
        {
            return Err(BankRefusal::Topology);
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
        let mask = ((1u64 << plan.slots.len()) - 1) & !self.published;
        if mask == 0 || mask & self.allocated != 0 {
            return BankPublication::Refused(BankRefusal::Allocated);
        }
        let Some(transaction) = self.next_transaction else {
            return BankPublication::Refused(BankRefusal::Exhausted);
        };
        let (retained, transient) = match reservation.charges() {
            Ok(bytes) => bytes,
            Err(reason) => return BankPublication::Refused(reason),
        };
        // The complete plan bounds the new subset without allocating that
        // subset or duplicating provider/slot metadata first.
        if let Err(reason) = reservation.validate_stage(&plan.slots, io.possible_cpus()) {
            return BankPublication::Refused(reason);
        }
        // Precharge both old/new overlap and all staging before cloning a Slot
        // or making native allocation, publication, provider or link calls.
        let charge = match reserve.reserve(retained) {
            Ok(charge) => charge,
            Err(_) => return BankPublication::Refused(BankRefusal::Budget),
        };
        let _scratch = match reserve.reserve(transient) {
            Ok(charge) => charge,
            Err(_) => return BankPublication::Refused(BankRefusal::Budget),
        };
        if let Err(reason) = io.validate_targets(&plan.slots, self.published) {
            return BankPublication::Refused(reason);
        }
        let slots: Vec<_> = plan
            .slots
            .iter()
            .filter(|slot| mask & (1 << slot.index) != 0)
            .cloned()
            .collect();
        // This guard moves into the same native custody as the eventual links,
        // including rollback failures, quarantine and abandonment.
        io.retain_charge(charge);
        let transaction = transaction.get();
        self.next_transaction = transaction.checked_add(1).and_then(NonZeroU64::new);
        self.allocated |= mask;
        if let crate::plan::AdmissionPolicy::Counters(budget) = plan.admission_policy() {
            self.budget = Some(budget);
        }
        for slot in &slots {
            self.keys[slot.index as usize] = Some(physical(slot));
        }
        if io.acknowledge(transaction) != CommitAck::Absent {
            self.quarantined = true;
            return BankPublication::Quarantined { transaction, mask };
        }
        let expected = BankCommit {
            mask,
            configuration: BANK_CONFIG,
        };
        let metadata = |slot: u32| BankMetadata {
            transaction,
            mask,
            logical_slot: slot,
            cells: 1,
        };
        let mut inners = 0u64;
        let mut metas = 0u64;
        let mut links_attempted = false;
        let mut commit_attempted = false;
        let result = (|| {
            for slot in &slots {
                io.allocate(slot.index)?;
                io.insert_inner(slot.index)?;
                inners |= 1 << slot.index;
                io.insert_metadata(slot.index, metadata(slot.index))?;
                metas |= 1 << slot.index;
            }
            links_attempted = true;
            io.attach_inactive(&slots)?;
            commit_attempted = true;
            io.insert_commit(transaction, expected)
        })();
        match io.acknowledge(transaction) {
            CommitAck::Present(actual) if commit_attempted && actual == expected => {
                self.published |= mask;
                for slot in &slots {
                    self.metadata[slot.index as usize] = Some(metadata(slot.index));
                }
                BankPublication::Published { transaction, mask }
            }
            CommitAck::Absent if result == Err(BankRefusal::Quarantined) => {
                self.quarantined = true;
                BankPublication::Quarantined { transaction, mask }
            }
            CommitAck::Absent => {
                let mut clean = true;
                // Only positively inserted keys belong to this candidate. Each
                // removal independently verifies the exact metadata/map ID.
                for slot in slots.iter().rev() {
                    if metas & (1 << slot.index) != 0 {
                        clean &= io
                            .remove_metadata_owned(slot.index, metadata(slot.index))
                            .is_ok();
                    }
                    if inners & (1 << slot.index) != 0 {
                        clean &= io.remove_inner_owned(slot.index).is_ok();
                    }
                }
                if links_attempted {
                    clean &= io.retire_links(&slots).is_ok();
                }
                if clean {
                    BankPublication::RolledBack {
                        transaction,
                        mask,
                        reason: result.err().unwrap_or(BankRefusal::Commit),
                    }
                } else {
                    self.quarantined = true;
                    BankPublication::Quarantined { transaction, mask }
                }
            }
            CommitAck::Present(_) | CommitAck::Unreadable => {
                self.quarantined = true;
                BankPublication::Quarantined { transaction, mask }
            }
        }
    }
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
                && env!("P11SCOPE_COUNTER_BANK_PROOF_OUTPUTS") == "counts-bank-proof",
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
    exact_map(ebpf, "COUNTER_BANKS", MapType::HashOfMaps, 4, 4, 2, 128)?;
    exact_map(ebpf, "COUNTER_BANK_META", MapType::Hash, 4, 24, 2, 128)?;
    exact_map(ebpf, "COUNTER_BANK_COMMIT", MapType::Hash, 8, 16, 2, 128)?;
    exact_map(ebpf, "COUNTER_BANK_FAULT", MapType::PerCpuArray, 4, 8, 1, 0)?;
    exact_map(ebpf, "COUNTER_HEALTH", MapType::PerCpuArray, 4, 8, 2, 0)?;
    exact_map(ebpf, "STATS", MapType::PerCpuArray, 4, 24, 512, 0)?;
    exact_map(ebpf, "RV_COUNTS", MapType::PerCpuHash, 16, 8, 4096, 0)?;
    exact_map(
        ebpf,
        "START",
        MapType::Hash,
        16,
        size_of::<p11scope_ebpf_common::CallStart>() as u32,
        16384,
        0,
    )
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

    fn validate_targets(&mut self, slots: &[Slot], published: u64) -> Result<(), BankRefusal> {
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
                // attach_targets creates a held-object copy and retained targets;
                // include every simultaneous copy before the first one is made.
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
        // At most two permanently allocated positions/attempts. This is
        // custody, not a second allocation/admission authority or history.
        let slot = self
            .custody
            .charges
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("bounded counter attempts have preallocated charge slots");
        *slot = Some(charge);
    }

    fn allocate(&mut self, slot: u32) -> Result<(), BankRefusal> {
        let index = slot as usize;
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
        Ok(())
    }

    fn insert_inner(&mut self, slot: u32) -> Result<(), BankRefusal> {
        let bank = self.custody.banks[slot as usize]
            .as_ref()
            .ok_or(BankRefusal::Ownership)?;
        let mut outer: HashOfMaps<_, u32> = HashOfMaps::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANKS")
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
        let result = outer.insert(slot, map_data(&bank.map)?, super::BPF_NOEXIST);
        match outer_id(&self.session.ebpf, slot)? {
            Some(id) if id == bank.id => Ok(()),
            None if result.is_err() => Err(BankRefusal::Native),
            _ => Err(BankRefusal::Quarantined),
        }
    }

    fn insert_metadata(&mut self, slot: u32, metadata: BankMetadata) -> Result<(), BankRefusal> {
        let mut map: HashMap<_, u32, BankMetadata> = HashMap::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANK_META")
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
        let result = map.insert(slot, metadata, super::BPF_NOEXIST);
        match map.get(&slot, 0) {
            Ok(actual) if actual == metadata && result.is_ok() => Ok(()),
            Err(MapError::KeyNotFound) if result.is_err() => Err(BankRefusal::Native),
            _ => Err(BankRefusal::Quarantined),
        }
    }

    fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
        let mask = slots
            .iter()
            .fold(0u64, |mask, slot| mask | (1 << slot.index));
        let banks = self
            .session
            .counter_banks
            .as_ref()
            .ok_or(BankRefusal::Shape)?;
        let _stage = banks.begin_link_stage(mask)?;
        let result = self.session.attach_targets(slots, self.objects);
        let (failed, completed) = result.map_err(|_| BankRefusal::Links)?;
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

    fn insert_commit(&mut self, transaction: u64, commit: BankCommit) -> Result<(), BankRefusal> {
        let mut map: HashMap<_, u64, BankCommit> = HashMap::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANK_COMMIT")
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
        map.insert(transaction, commit, super::BPF_NOEXIST)
            .map_err(|_| BankRefusal::Commit)
    }

    fn acknowledge(&mut self, transaction: u64) -> CommitAck {
        let Some(map) = self.session.ebpf.map("COUNTER_BANK_COMMIT") else {
            return CommitAck::Unreadable;
        };
        let Ok(map) = HashMap::<_, u64, BankCommit>::try_from(map) else {
            return CommitAck::Unreadable;
        };
        match map.get(&transaction, 0) {
            Ok(commit) => CommitAck::Present(commit),
            Err(MapError::KeyNotFound) => CommitAck::Absent,
            Err(_) => CommitAck::Unreadable,
        }
    }

    fn remove_metadata_owned(
        &mut self,
        slot: u32,
        expected: BankMetadata,
    ) -> Result<(), BankRefusal> {
        let mut map: HashMap<_, u32, BankMetadata> = HashMap::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANK_META")
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
        if map.get(&slot, 0).map_err(|_| BankRefusal::Ownership)? != expected {
            return Err(BankRefusal::Ownership);
        }
        map.remove(&slot).map_err(|_| BankRefusal::Ownership)
    }

    fn remove_inner_owned(&mut self, slot: u32) -> Result<(), BankRefusal> {
        let bank = self.custody.banks[slot as usize]
            .as_ref()
            .ok_or(BankRefusal::Ownership)?;
        if outer_id(&self.session.ebpf, slot)? != Some(bank.id) {
            return Err(BankRefusal::Ownership);
        }
        let mut outer: HashOfMaps<_, u32> = HashOfMaps::try_from(
            self.session
                .ebpf
                .map_mut("COUNTER_BANKS")
                .ok_or(BankRefusal::Shape)?,
        )
        .map_err(|_| BankRefusal::Shape)?;
        outer.remove(&slot).map_err(|_| BankRefusal::Ownership)
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
        let custody = banks
            .keepalive
            .custody
            .lock()
            .map_err(|_| BankRefusal::Quarantined)?;
        let status = match directory.validate_read_plan(plan) {
            Ok(()) => {
                validate_provider_slots(&plan.slots, objects, directory.published, |index| {
                    custody.providers[index as usize].as_ref()
                })?;
                BankReadStatus::Healthy
            }
            Err(BankRefusal::Quarantined) => BankReadStatus::Quarantined,
            Err(_) => BankReadStatus::Routing,
        };
        Ok(CounterBankView {
            banks: custody.banks.clone(),
            metadata: directory.metadata,
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
        fn validate_targets(&mut self, slots: &[Slot], published: u64) -> Result<(), BankRefusal> {
            self.trace.push("validate");
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

        fn allocate(&mut self, slot: u32) -> Result<(), BankRefusal> {
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
            Ok(())
        }

        fn insert_inner(&mut self, slot: u32) -> Result<(), BankRefusal> {
            self.trace.push("inner");
            if self.inners.contains_key(&slot) {
                return Err(BankRefusal::Quarantined);
            }
            self.inners.insert(slot, slot + 1);
            Ok(())
        }

        fn insert_metadata(
            &mut self,
            slot: u32,
            metadata: BankMetadata,
        ) -> Result<(), BankRefusal> {
            self.trace.push("metadata");
            if self.fail == Some("metadata") || self.metadata.contains_key(&slot) {
                return Err(BankRefusal::Native);
            }
            self.metadata.insert(slot, metadata);
            Ok(())
        }

        fn attach_inactive(&mut self, slots: &[Slot]) -> Result<(), BankRefusal> {
            assert!(slots.iter().all(|slot| {
                let metadata = self.metadata[&slot.index];
                !self.commits.contains_key(&metadata.transaction)
            }));
            self.trace.extend(["return", "entry"]);
            if self.fail == Some("entry") {
                return Err(BankRefusal::Links);
            }
            Ok(())
        }

        fn insert_commit(
            &mut self,
            transaction: u64,
            commit: BankCommit,
        ) -> Result<(), BankRefusal> {
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

        fn acknowledge(&mut self, transaction: u64) -> CommitAck {
            self.trace.push("ack");
            if self.attempted.contains(&transaction) && !self.acknowledgements.is_empty() {
                return self.acknowledgements.remove(0);
            }
            match self.commits.get(&transaction) {
                Some(commit) => CommitAck::Present(*commit),
                None => CommitAck::Absent,
            }
        }

        fn remove_metadata_owned(
            &mut self,
            slot: u32,
            expected: BankMetadata,
        ) -> Result<(), BankRefusal> {
            self.trace.push("remove-metadata");
            if self.failed_delete || self.metadata.get(&slot) != Some(&expected) {
                return Err(BankRefusal::Ownership);
            }
            self.metadata.remove(&slot);
            Ok(())
        }

        fn remove_inner_owned(&mut self, slot: u32) -> Result<(), BankRefusal> {
            self.trace.push("remove-inner");
            if self.failed_delete || self.inners.get(&slot) != Some(&(slot + 1)) {
                return Err(BankRefusal::Ownership);
            }
            self.inners.remove(&slot);
            Ok(())
        }

        fn retire_links(&mut self, _: &[Slot]) -> Result<(), BankRefusal> {
            self.trace.push("retire-links");
            if self.failed_retire {
                Err(BankRefusal::Links)
            } else {
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
            BankPublication::Published { mask: 3, .. }
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
        assert_eq!(directory.published_mask(), 0);
        drop(native);
    }

    #[test]
    fn exact_commit_ack_publishes_once_and_preserves_old_routes() {
        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let mut directory = BankDirectory::default();
        let mut native = Native::default();
        let BankPublication::Published {
            transaction: old,
            mask: 1,
        } = directory.stage_with(&mut native, &plan(1), reservation(), &pool.reserver())
        else {
            panic!("first real transaction did not publish");
        };
        let original = native.metadata[&0];
        native.fail = Some("commit-ack-lost");
        let BankPublication::Published {
            transaction: new,
            mask: 2,
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
        assert_eq!(directory.published_mask(), 3);
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
        assert_eq!(directory.published_mask(), 3);
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
            assert_eq!(directory.published_mask(), 0);
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
        assert_eq!(directory.published_mask(), 1);
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
                mask: 1
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
        assert_eq!(directory.published_mask(), 1);
        assert_eq!(directory.allocated, 1);
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
                mask: 2
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
            BankPublication::Published { mask: 1, .. }
        ));
        let before = native.trace.len();
        assert_eq!(
            directory.stage_with(&mut native, &duplicate, reservation(), &pool.reserver()),
            BankPublication::Refused(BankRefusal::Ownership)
        );
        assert_eq!(directory.published_mask(), 1);
        assert_eq!(directory.allocated, 1);
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
