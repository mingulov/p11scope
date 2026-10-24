//! SPDX-License-Identifier: GPL-3.0-or-later
//! Session-owned live retirement and bounded collected-Finish ownership.

use super::cleanup_worker::{BatchStatus, BatchTicket};
use super::global_retirement::Retirements;
use super::pid_continuity::PairBook;
use super::{
    CleanupWorker, DetachOrder, OwnedLink, RegisteredLink, RetainedStaticTarget,
    current_static_sides_from, extract_selected_links, plan_group_rebuild, prune_linkless_retained,
};
use crate::plan::Slot;
use anyhow::{Result, bail};
use aya::programs::uprobe::UProbeScope;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct RetirementTicket {
    identity: Arc<TicketIdentity>,
}

struct TicketIdentity {
    allocation: Arc<()>,
    batch: Option<BatchTicket>,
    retired_slots: BTreeSet<u32>,
}

impl std::fmt::Debug for RetirementTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RetirementTicket(<Session-owned batch>)")
    }
}

impl PartialEq for RetirementTicket {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
    }
}
impl Eq for RetirementTicket {}

impl RetirementTicket {
    pub(crate) fn retired_slots(&self) -> &BTreeSet<u32> {
        &self.identity.retired_slots
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetirementPoll {
    Pending,
    Settled,
    Refused,
}

#[derive(Default)]
pub(super) struct NativeRetirement {
    allocation: Arc<()>,
    pending: Option<Pending>,
    preflight: Option<CollectedPreflight>,
    collected: Option<Box<CollectedCursor>>,
}

struct Pending {
    ticket: RetirementTicket,
    // The actual original opened file, offset and ABI remain held while any
    // old native ownership is pending or uncertain. Paths are never reopened.
    _points: BTreeMap<u32, RetainedStaticTarget>,
    refused: bool,
}

impl NativeRetirement {
    pub(super) fn blocking(&self) -> bool {
        self.pending.is_some() || self.preflight.is_some() || self.collected.is_some()
    }

    pub(super) fn collected_blocking(&self) -> bool {
        self.preflight.is_some() || self.collected.is_some()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_with(
        &mut self,
        scope: UProbeScope,
        stopped: bool,
        failed_cleanup: bool,
        ended: bool,
        requested: &[Slot],
        links: &mut Vec<RegisteredLink>,
        retained: &mut BTreeMap<u32, RetainedStaticTarget>,
        pairs: &mut PairBook,
        gaps: &mut Retirements,
        worker: &CleanupWorker,
        mut transfer: impl FnMut(RegisteredLink) -> Result<Vec<OwnedLink>>,
        clock: impl FnOnce() -> Option<u64>,
    ) -> Result<Option<RetirementTicket>> {
        if self.blocking() {
            bail!("an earlier global native retirement is pending or uncertain");
        }
        if !matches!(scope, UProbeScope::AllProcesses) || stopped || failed_cleanup || ended {
            return Ok(None);
        }
        let requested_indices: BTreeSet<_> = requested.iter().map(|slot| slot.index).collect();
        if requested_indices.is_empty()
            || requested_indices.len() != requested.len()
            || requested_indices.len() > p11scope_ebpf_common::MAX_SLOTS as usize
            || plan_group_rebuild(links, &requested_indices).is_some()
        {
            return Ok(None);
        }
        if links.iter().any(|link| {
            link.slots()
                .iter()
                .any(|slot| requested_indices.contains(slot))
                && !matches!(link.producer(), super::ProducerProgram::UProbe(program)
                if super::static_probe_side(program).is_some())
        }) {
            return Ok(None);
        }
        let choices: Vec<_> = links
            .iter()
            .map(|link| {
                matches!(
                    link,
                    RegisteredLink::UProbe { .. } | RegisteredLink::MultiUProbe { .. }
                ) && !link.slots().is_empty()
                    && link
                        .slots()
                        .iter()
                        .all(|slot| requested_indices.contains(slot))
            })
            .collect();
        let retired_slots: BTreeSet<_> = links
            .iter()
            .zip(&choices)
            .filter(|(_, chosen)| **chosen)
            .flat_map(|(link, _)| link.slots().iter().copied())
            .collect();
        if retired_slots.is_empty() {
            return Ok(None);
        }
        let sides = current_static_sides_from(links);
        let mut points = BTreeMap::new();
        for index in &retired_slots {
            let Some(target) = retained.get(index) else {
                return Ok(None);
            };
            // Requested indices select within this Session only. Replacement
            // descriptors already carry updated metadata; old physical
            // authority comes solely from the original held target and pair.
            if target.slot.index != *index
                || super::pid_continuity::current_pair(*index, links, &sides).is_none()
                || target.held.as_ref().is_none_or(|held| {
                    held.abi() != target.abi
                        || held.attach_path() != target.path
                        || held.check_unchanged() != Ok(true)
                })
            {
                return Ok(None);
            }
            points.insert(*index, target.clone());
        }
        // Before any ownership transfer, an unavailable prestarted worker is
        // an untouched fallback. The caller can synchronously detach its still
        // owned original links; no physical gap or quarantine is opened here.
        if worker.live_admission().is_err() {
            return Ok(None);
        }
        gaps.retire_selected(
            scope,
            false,
            links,
            &choices,
            &BTreeSet::new(),
            retained,
            clock,
        );
        let mut choices = choices.into_iter();
        let selected = extract_selected_links(links, pairs, |_| choices.next().unwrap());
        prune_linkless_retained(retained, links);
        let mut owned = Vec::new();
        let mut refused = false;
        for link in selected {
            let producer = link.producer();
            match transfer(link) {
                Ok(transferred) if !transferred.is_empty() => {
                    owned.extend(transferred.into_iter().map(|link| (link, producer)));
                }
                result => {
                    refused = true;
                    worker.note_transfer_failed(1);
                    worker.note_failure(match result {
                        Err(error) => format!("global native ownership transfer: {error:#}"),
                        Ok(_) => "global native ownership transfer produced no owned handle".into(),
                    });
                }
            }
        }
        let batch = if owned.is_empty() {
            None
        } else {
            let leases = Arc::new(
                points
                    .values()
                    .filter_map(RetainedStaticTarget::retirement_lease)
                    .collect(),
            );
            match worker.submit_live(owned, leases, DetachOrder) {
                Ok(batch) => Some(batch),
                Err(failure) => {
                    refused = true;
                    worker.retain_unsubmitted(failure);
                    None
                }
            }
        };
        let ticket = RetirementTicket {
            identity: Arc::new(TicketIdentity {
                allocation: Arc::clone(&self.allocation),
                batch,
                retired_slots,
            }),
        };
        self.pending = Some(Pending {
            ticket: ticket.clone(),
            _points: points,
            refused,
        });
        // Once ownership was extracted this can never return untouched None,
        // including a transfer/channel failure with no successful worker batch.
        Ok(Some(ticket))
    }

    pub(super) fn poll(
        &mut self,
        ticket: &RetirementTicket,
        worker: &CleanupWorker,
    ) -> RetirementPoll {
        let Some(pending) = &mut self.pending else {
            return RetirementPoll::Refused;
        };
        if !Arc::ptr_eq(&ticket.identity.allocation, &self.allocation)
            || ticket != &pending.ticket
            || pending.refused
        {
            return RetirementPoll::Refused;
        }
        let Some(batch) = &ticket.identity.batch else {
            return RetirementPoll::Refused;
        };
        if !batch.belongs_to(worker) {
            return RetirementPoll::Refused;
        }
        match batch.status() {
            BatchStatus::Pending if worker.running() => RetirementPoll::Pending,
            BatchStatus::Pending => {
                pending.refused = true;
                RetirementPoll::Refused
            }
            BatchStatus::Failed => {
                pending.refused = true;
                RetirementPoll::Refused
            }
            BatchStatus::Released => {
                self.pending = None;
                RetirementPoll::Settled
            }
        }
    }
}

use super::cleanup_worker::{
    CleanupWorkerIdentity, CollectedCleanupRetention, collected_allocation_charge,
};
use super::pid_continuity::{PairStamp, RegistrationId};
use super::{CollectedFinishQ, CollectedFinishQOwner, ProbeSide};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

// Process-local cache identity only: never Session/Q/pool/detach authority.
static COLLECTED_INPUT_ISSUED: AtomicU64 = AtomicU64::new(0);

pub(crate) struct RetainedRetirementInput {
    removed: Vec<Slot>,
    storage: ResourceLease,
    identity: NonZeroU64,
}

pub(crate) struct RetainedRetirementInputRefusal {
    removed: Vec<Slot>,
    storage: ResourceLease,
}

impl RetainedRetirementInput {
    pub(crate) fn from_reserved_removed(
        removed: Vec<Slot>,
        storage: ResourceLease,
    ) -> std::result::Result<Self, RetainedRetirementInputRefusal> {
        Self::from_reserved_removed_with_issuer(removed, storage, &COLLECTED_INPUT_ISSUED)
    }

    fn from_reserved_removed_with_issuer(
        removed: Vec<Slot>,
        storage: ResourceLease,
        issuer: &AtomicU64,
    ) -> std::result::Result<Self, RetainedRetirementInputRefusal> {
        match issuer.try_update(Ordering::Relaxed, Ordering::Relaxed, |issued| {
            issued.checked_add(1)
        }) {
            Ok(previous) => Ok(Self {
                removed,
                storage,
                identity: NonZeroU64::new(previous + 1).expect("checked nonzero input identity"),
            }),
            Err(_) => Err(RetainedRetirementInputRefusal { removed, storage }),
        }
    }

    pub(crate) fn into_removed(self) -> (Vec<Slot>, ResourceLease) {
        (self.removed, self.storage)
    }
}

impl RetainedRetirementInputRefusal {
    pub(crate) fn into_removed(self) -> (Vec<Slot>, ResourceLease) {
        (self.removed, self.storage)
    }
}

impl std::fmt::Debug for RetainedRetirementInputRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetainedRetirementInputRefusal(<original owners retained>)")
    }
}

/// External clones retain only two empty allocation identities. The original
/// Session cursor, not this ticket, owns every selector/lease/native receipt.
#[derive(Clone)]
pub(crate) struct CollectedRetirementTicket {
    owner: Arc<()>,
    cursor: Arc<()>,
}

pub(crate) struct RetirementProgress {
    pub(crate) used: usize,
    pub(crate) state: CollectedRetirementState,
    // Available from first valid take, including post-take Preparing. It is
    // cancellation identity, not evidence of preparation or native closure.
    pub(crate) ticket: Option<CollectedRetirementTicket>,
}

pub(crate) enum CollectedRetirementState {
    Yielded,
    Preparing,
    Prepared(CollectedRetirementTicket),
    Transferring,
    Pending,
    Closed(RetainedRetirementInput),
    RefusedUntouched(RetainedRetirementInput),
    RefusedRetained,
}

impl RetirementProgress {
    pub(super) fn yielded() -> Self {
        Self {
            used: 0,
            state: CollectedRetirementState::Yielded,
            ticket: None,
        }
    }
    fn preparing() -> Self {
        Self {
            used: 1,
            state: CollectedRetirementState::Preparing,
            ticket: None,
        }
    }
}

fn add_bytes(bytes: &mut usize, extra: usize) -> Result<()> {
    *bytes = bytes
        .checked_add(extra)
        .ok_or_else(|| anyhow::anyhow!("collected retirement backing overflow"))?;
    Ok(())
}

fn array_bytes<T>(capacity: usize) -> Result<usize> {
    capacity
        .checked_mul(std::mem::size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .and_then(|bytes| {
            bytes.checked_add(if capacity == 0 {
                0
            } else {
                OWNED_ALLOCATION_PADDING
            })
        })
        .ok_or_else(|| anyhow::anyhow!("collected retirement capacity overflow"))
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
struct SlotSizing {
    base: bool,
    name: usize,
}

impl SlotSizing {
    // One field group or one owned name. Never clone/sort an input descriptor.
    fn step(&mut self, slot: &Slot, bytes: &mut usize) -> Result<bool> {
        if !self.base {
            add_bytes(bytes, slot.object_path.capacity())?;
            add_bytes(bytes, OWNED_ALLOCATION_PADDING)?;
            add_bytes(bytes, array_bytes::<String>(slot.names.capacity())?)?;
            add_bytes(bytes, array_bytes_for(&slot.module_ids)?)?;
            self.base = true;
        } else if let Some(name) = slot.names.get(self.name) {
            add_bytes(bytes, name.capacity())?;
            add_bytes(bytes, OWNED_ALLOCATION_PADDING)?;
            self.name += 1;
        } else {
            return Ok(true);
        }
        Ok(false)
    }
}

fn array_bytes_for<T>(values: &Vec<T>) -> Result<usize> {
    array_bytes::<T>(values.capacity())
}

// Refusal-only cache/version checks beneath the actual Session/Q owner and
// exclusive mutation fence. Inline BTreeMap/PairBook addresses are not owner
// identity: moving the same Session must not replace its native ownership.
#[derive(Clone, Copy)]
struct RegistryFence {
    links: usize,
    link_count: usize,
    target_count: usize,
    pair_state: (u64, u64, usize, bool),
}

impl RegistryFence {
    fn new(
        links: &[RegisteredLink],
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        pairs: &PairBook,
    ) -> Self {
        Self {
            links: links.as_ptr() as usize,
            link_count: links.len(),
            target_count: retained.len(),
            pair_state: pairs.collected_fence(),
        }
    }
    fn matches(
        &self,
        links: &[RegisteredLink],
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        pairs: &PairBook,
    ) -> bool {
        self.links == links.as_ptr() as usize
            && self.link_count == links.len()
            && self.target_count == retained.len()
            && self.pair_state == pairs.collected_fence()
    }
}

struct CollectedPreflight {
    input: NonZeroU64,
    // Address is a refusal-only cache fence. Every call must additionally
    // validate the borrowed original Q, its real domains and ring bounds.
    q: usize,
    scope: UProbeScope,
    fence: RegistryFence,
    worker: CleanupWorkerIdentity,
    phase: PreflightPhase,
    sizing: SlotSizing,
    bytes: usize,
    backing: usize,
    high: usize,
    ranks: [usize; 10],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreflightPhase {
    InputBase,
    Input(usize),
    InputCovered,
    Registry(usize),
    Targets {
        after: Option<u32>,
        current: Option<u32>,
    },
    Stamps {
        after: Option<u32>,
        current: Option<u32>,
    },
    Admit,
}

type PreflightCheckpoint = (PreflightPhase, SlotSizing, usize, usize, usize, [usize; 10]);

impl CollectedPreflight {
    fn checkpoint(&self) -> PreflightCheckpoint {
        (
            self.phase,
            self.sizing,
            self.bytes,
            self.backing,
            self.high,
            self.ranks,
        )
    }

    fn step(
        &mut self,
        input: &RetainedRetirementInput,
        reserver: &SemanticResourceReserver,
        links: &[RegisteredLink],
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        pairs: &PairBook,
    ) -> Result<bool> {
        let checkpoint = self.checkpoint();
        let result = self.step_inner(input, reserver, links, retained, pairs);
        if result.is_err() {
            (
                self.phase,
                self.sizing,
                self.bytes,
                self.backing,
                self.high,
                self.ranks,
            ) = checkpoint;
        }
        result
    }

    fn step_inner(
        &mut self,
        input: &RetainedRetirementInput,
        reserver: &SemanticResourceReserver,
        links: &[RegisteredLink],
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        pairs: &PairBook,
    ) -> Result<bool> {
        match &mut self.phase {
            PreflightPhase::InputBase => {
                anyhow::ensure!(
                    !input.removed.is_empty() && input.removed.len() <= retained.len(),
                    "collected retirement needs a bounded nonempty original selection"
                );
                self.bytes = std::mem::size_of::<RetainedRetirementInput>();
                add_bytes(&mut self.bytes, array_bytes_for(&input.removed)?)?;
                self.phase = PreflightPhase::Input(0);
            }
            PreflightPhase::Input(index) => {
                if let Some(slot) = input.removed.get(*index) {
                    if !self.sizing.base {
                        anyhow::ensure!(
                            retained.contains_key(&slot.index),
                            "collected retirement index has no original retained owner"
                        );
                        self.high = self.high.max(
                            (slot.index as usize)
                                .checked_add(1)
                                .ok_or_else(|| anyhow::anyhow!("original slot bound overflow"))?,
                        );
                    }
                    if self.sizing.step(slot, &mut self.bytes)? {
                        self.sizing = SlotSizing::default();
                        *index += 1;
                    }
                } else {
                    self.phase = PreflightPhase::InputCovered;
                }
            }
            PreflightPhase::InputCovered => {
                anyhow::ensure!(
                    reserver.covers(&input.storage, self.bytes),
                    "collected retirement input is foreign or undercharged"
                );
                self.phase = PreflightPhase::Registry(0);
            }
            PreflightPhase::Registry(index) => {
                if let Some(link) = links.get(*index) {
                    let rank = DetachOrder.rank(&link.producer()) as usize;
                    self.ranks[rank] = self.ranks[rank]
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("collected retirement rank overflow"))?;
                    if let RegisteredLink::MultiUProbe { slots, fds, .. } = link {
                        add_bytes(&mut self.backing, array_bytes_for(slots)?)?;
                        add_bytes(&mut self.backing, array_bytes_for(fds)?)?;
                    }
                    *index += 1;
                } else {
                    self.phase = PreflightPhase::Targets {
                        after: None,
                        current: None,
                    };
                }
            }
            PreflightPhase::Targets { after, current } => {
                if let Some(index) = *current {
                    let target = retained
                        .get(&index)
                        .ok_or_else(|| anyhow::anyhow!("original target vanished"))?;
                    if self.sizing.step(&target.slot, &mut self.backing)? {
                        self.sizing = SlotSizing::default();
                        *after = Some(index);
                        *current = None;
                    }
                } else if let Some((index, target)) = next_target(retained, *after) {
                    add_bytes(&mut self.backing, target.path.capacity())?;
                    add_bytes(&mut self.backing, OWNED_ALLOCATION_PADDING)?;
                    if let Some(held) = &target.held {
                        add_bytes(
                            &mut self.backing,
                            held.retained_copy_allocation_charge()
                                .ok_or_else(|| anyhow::anyhow!("held target backing overflow"))?,
                        )?;
                    }
                    *current = Some(index);
                } else {
                    self.phase = PreflightPhase::Stamps {
                        after: None,
                        current: None,
                    };
                }
            }
            PreflightPhase::Stamps { after, current } => {
                if let Some(index) = *current {
                    let (_, stamp) = pairs
                        .next_collected_stamp(index.checked_sub(1))
                        .filter(|(actual, _)| *actual == index)
                        .ok_or_else(|| anyhow::anyhow!("original pair stamp vanished"))?;
                    if self.sizing.step(&stamp.slot, &mut self.backing)? {
                        self.sizing = SlotSizing::default();
                        *after = Some(index);
                        *current = None;
                    }
                } else if let Some((index, stamp)) = pairs.next_collected_stamp(*after) {
                    add_bytes(
                        &mut self.backing,
                        stamp
                            .target
                            .retained_copy_allocation_charge()
                            .ok_or_else(|| anyhow::anyhow!("pair target backing overflow"))?,
                    )?;
                    *current = Some(index);
                } else {
                    self.phase = PreflightPhase::Admit;
                }
            }
            PreflightPhase::Admit => return Ok(true),
        }
        Ok(false)
    }

    fn allocation_charge(&self, inputs: usize, links: usize) -> Result<(usize, usize, usize)> {
        let mut bytes = self.backing;
        let shell = std::mem::size_of::<CollectedCursor>() + OWNED_ALLOCATION_PADDING
            + 16 + OWNED_ALLOCATION_PADDING // constant cursor identity
            + 2 * (16 + std::mem::size_of::<Vec<Arc<std::fs::File>>>() + OWNED_ALLOCATION_PADDING)
            + super::cleanup_worker::collected_release_ticket_charge();
        add_bytes(&mut bytes, array_bytes::<SelectionRow>(self.high)?)?;
        add_bytes(&mut bytes, array_bytes::<LinkChoice>(links)?)?;
        add_bytes(&mut bytes, array_bytes::<RetainedStaticTarget>(inputs)?)?;
        add_bytes(&mut bytes, array_bytes::<PairStamp>(inputs)?)?;
        add_bytes(&mut bytes, array_bytes::<Arc<std::fs::File>>(inputs)?)?;
        let mut batches = 0usize;
        for count in self.ranks {
            add_bytes(&mut bytes, array_bytes::<RegisteredLink>(count)?)?;
            batches = batches
                .checked_add(
                    count
                        .checked_add(3)
                        .ok_or_else(|| anyhow::anyhow!("collected chunk count overflow"))?
                        / 4,
                )
                .ok_or_else(|| anyhow::anyhow!("collected chunk count overflow"))?;
        }
        add_bytes(&mut bytes, array_bytes::<BatchTicket>(batches)?)?;
        add_bytes(
            &mut bytes,
            array_bytes::<Vec<(OwnedLink, super::ProducerProgram)>>(batches)?,
        )?;
        add_bytes(
            &mut bytes,
            batches
                .checked_mul(array_bytes::<(OwnedLink, super::ProducerProgram)>(4)?)
                .ok_or_else(|| anyhow::anyhow!("collected chunk backing overflow"))?,
        )?;
        add_bytes(
            &mut bytes,
            collected_allocation_charge(links, batches)
                .ok_or_else(|| anyhow::anyhow!("collected worker backing overflow"))?,
        )?;
        Ok((bytes, shell, batches))
    }
}

fn next_target(
    retained: &BTreeMap<u32, RetainedStaticTarget>,
    after: Option<u32>,
) -> Option<(u32, &RetainedStaticTarget)> {
    use std::ops::Bound::{Excluded, Unbounded};
    match after {
        None => retained.first_key_value(),
        Some(after) => retained.range((Excluded(after), Unbounded)).next(),
    }
    .map(|(index, target)| (*index, target))
}

#[derive(Default)]
struct SelectionRow {
    requested: Option<usize>,
    entry: Option<RegistrationId>,
    return_: Option<RegistrationId>,
}

struct LinkChoice {
    selected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CollectedPhase {
    Allocate(u8),
    Rows,
    Chunks,
    Selection(usize),
    LinkStart(usize),
    LinkMember {
        link: usize,
        member: usize,
        chosen: usize,
    },
    Validate(usize),
    Prepared,
    Invalidate(usize),
    Targets(usize),
    Extract(usize),
    Transfer {
        rank: usize,
        chunk: usize,
    },
    Submit {
        rank: usize,
        chunk: usize,
    },
    Pending(usize),
    Dispose(u8),
    Release,
    ReleasePending,
    Refused,
}

type CollectedPayload = (OwnedLink, super::ProducerProgram);
type CollectedChunk = Vec<CollectedPayload>;

struct CollectedCursor {
    input: Option<RetainedRetirementInput>,
    input_bytes: usize,
    ticket: CollectedRetirementTicket,
    // Address is a refusal-only cache fence. Every call must additionally
    // validate the borrowed original Q, its real domains and ring bounds.
    q: usize,
    scope: UProbeScope,
    fence: RegistryFence,
    worker: CleanupWorkerIdentity,
    phase: CollectedPhase,
    high: usize,
    ranks: [usize; 10],
    max_batches: usize,
    rows: Vec<SelectionRow>,
    choices: Vec<LinkChoice>,
    buckets: [Vec<RegisteredLink>; 10],
    chunks: Vec<CollectedChunk>,
    tickets: Vec<BatchTicket>,
    mutated: bool,
    cancelling: bool,
    files: super::cleanup_worker::FileLeases,
    // Last: all cursor/deep backing is released before its paid guard.
    retention: Option<Arc<CollectedCleanupRetention>>,
    release: Option<BatchTicket>,
    // This independent constant charge outlives the background backing
    // release. It is taken out before the Box is freed, then refunded.
    shell_storage: Option<ResourceLease>,
}

impl CollectedCursor {
    fn progress(&self, state: CollectedRetirementState) -> RetirementProgress {
        RetirementProgress {
            used: 1,
            state,
            ticket: Some(self.ticket.clone()),
        }
    }
    fn matches(&self, ticket: &CollectedRetirementTicket) -> bool {
        Arc::ptr_eq(&self.ticket.owner, &ticket.owner)
            && Arc::ptr_eq(&self.ticket.cursor, &ticket.cursor)
    }
    fn original(&self) -> &RetainedRetirementInput {
        self.input.as_ref().expect("original input retained")
    }

    fn prepare_one(
        &mut self,
        links: &[RegisteredLink],
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        worker: &CleanupWorker,
    ) -> Result<()> {
        match self.phase {
            CollectedPhase::Allocate(0) => {
                self.rows = Vec::with_capacity(self.high);
                self.phase = CollectedPhase::Allocate(1);
            }
            CollectedPhase::Allocate(1) => {
                self.choices = Vec::with_capacity(links.len());
                self.phase = CollectedPhase::Allocate(2);
            }
            CollectedPhase::Allocate(2) => {
                self.chunks = Vec::with_capacity(self.max_batches);
                self.phase = CollectedPhase::Allocate(3);
            }
            CollectedPhase::Allocate(3) => {
                self.tickets = Vec::with_capacity(self.max_batches);
                self.phase = CollectedPhase::Allocate(4);
            }
            CollectedPhase::Allocate(index @ 4..=13) => {
                let rank = index as usize - 4;
                self.buckets[rank] = Vec::with_capacity(self.ranks[rank]);
                self.phase = if index == 13 {
                    CollectedPhase::Rows
                } else {
                    CollectedPhase::Allocate(index + 1)
                };
            }
            CollectedPhase::Rows => {
                if self.rows.len() < self.high {
                    self.rows.push(SelectionRow::default());
                } else {
                    self.phase = CollectedPhase::Chunks;
                }
            }
            CollectedPhase::Chunks => {
                if self.chunks.len() < self.max_batches {
                    self.chunks.push(Vec::with_capacity(4));
                } else {
                    self.phase = CollectedPhase::Selection(0);
                }
            }
            CollectedPhase::Selection(index) => {
                if let Some(slot) = self.original().removed.get(index) {
                    let slot_index = slot.index as usize;
                    anyhow::ensure!(
                        self.rows[slot_index].requested.replace(index).is_none(),
                        "collected retirement repeats a selected original"
                    );
                    self.phase = CollectedPhase::Selection(index + 1);
                } else {
                    self.phase = CollectedPhase::LinkStart(0);
                }
            }
            CollectedPhase::LinkStart(index) => {
                if links.get(index).is_some() {
                    self.choices.push(LinkChoice { selected: false });
                    self.phase = CollectedPhase::LinkMember {
                        link: index,
                        member: 0,
                        chosen: 0,
                    };
                } else {
                    self.phase = CollectedPhase::Validate(0);
                }
            }
            CollectedPhase::LinkMember {
                link,
                member,
                chosen,
            } => {
                let original = &links[link];
                if let Some(index) = original.slots().get(member) {
                    let mut selected = chosen;
                    if let Some(row) = self
                        .rows
                        .get_mut(*index as usize)
                        .filter(|row| row.requested.is_some())
                    {
                        let (program, registration) = match original {
                            RegisteredLink::UProbe {
                                program,
                                registration,
                                ..
                            } => (*program, *registration),
                            RegisteredLink::MultiUProbe {
                                program,
                                registration,
                                fds,
                                ..
                            } if !fds.is_empty() => (*program, *registration),
                            _ => bail!(
                                "collected retirement selected an unsupported native original"
                            ),
                        };
                        let registration = registration
                            .ok_or_else(|| anyhow::anyhow!("original registration is missing"))?;
                        let side = super::static_probe_side(program).ok_or_else(|| {
                            anyhow::anyhow!("collected retirement selected a nonstatic producer")
                        })?;
                        let place = match side {
                            ProbeSide::Entry => &mut row.entry,
                            ProbeSide::Return => &mut row.return_,
                        };
                        anyhow::ensure!(
                            place.replace(registration).is_none(),
                            "collected retirement has duplicate original sides"
                        );
                        selected += 1;
                    }
                    self.phase = CollectedPhase::LinkMember {
                        link,
                        member: member + 1,
                        chosen: selected,
                    };
                } else {
                    anyhow::ensure!(
                        chosen == 0 || chosen == original.slots().len(),
                        "collected retirement refuses a partial original Multi group"
                    );
                    self.choices[link].selected = chosen != 0;
                    self.phase = CollectedPhase::LinkStart(link + 1);
                }
            }
            CollectedPhase::Validate(index) => {
                if let Some(slot) = self.original().removed.get(index) {
                    let row = &self.rows[slot.index as usize];
                    anyhow::ensure!(
                        row.entry.is_some() && row.return_.is_some() && row.entry != row.return_,
                        "collected retirement has no exact original pair"
                    );
                    let target = retained
                        .get(&slot.index)
                        .ok_or_else(|| anyhow::anyhow!("original target is missing"))?;
                    anyhow::ensure!(
                        target.slot.index == slot.index && held_target_valid_without_copy(target),
                        "collected retirement original held target changed"
                    );
                    self.retention
                        .as_ref()
                        .expect("precharged retained owner")
                        .retain_file(target.retirement_lease().expect("validated held file"));
                    self.phase = CollectedPhase::Validate(index + 1);
                } else {
                    worker.collected_admission().map_err(anyhow::Error::msg)?;
                    self.phase = CollectedPhase::Prepared;
                }
            }
            CollectedPhase::Prepared => {}
            _ => bail!("collected preparation phase already ended"),
        }
        Ok(())
    }

    fn dispose_one(&mut self) -> bool {
        let CollectedPhase::Dispose(step) = self.phase else {
            return false;
        };
        match step {
            0 => {
                if self.tickets.pop().is_none() {
                    self.tickets = Vec::new();
                    self.phase = CollectedPhase::Dispose(1);
                }
            }
            1 => {
                if self.chunks.pop().is_none() {
                    self.chunks = Vec::new();
                    self.phase = CollectedPhase::Dispose(2);
                }
            }
            2 => {
                if self.rows.pop().is_none() {
                    self.rows = Vec::new();
                    self.phase = CollectedPhase::Dispose(3);
                }
            }
            3 => {
                if self.choices.pop().is_none() {
                    self.choices = Vec::new();
                    self.phase = CollectedPhase::Dispose(4);
                }
            }
            4..=13 => {
                let rank = (step - 4) as usize;
                debug_assert!(self.buckets[rank].is_empty());
                self.buckets[rank] = Vec::new();
                self.phase = CollectedPhase::Dispose(step + 1);
            }
            14 => return true,
            _ => unreachable!(),
        }
        false
    }
}

fn held_target_valid_without_copy(target: &RetainedStaticTarget) -> bool {
    use std::os::fd::AsRawFd as _;
    let Some(held) = &target.held else {
        return false;
    };
    let raw = target.path.as_os_str().as_encoded_bytes();
    let Some(number) = raw
        .strip_prefix(b"/proc/self/fd/")
        .filter(|number| !number.is_empty() && number.len() <= 10)
    else {
        return false;
    };
    let fd = number.iter().try_fold(0i32, |value, byte| {
        byte.is_ascii_digit().then_some(())?;
        value.checked_mul(10)?.checked_add(i32::from(*byte - b'0'))
    });
    fd == Some(held.borrowed_file_and_digest().0.as_raw_fd())
        && target.abi == held.abi()
        && held.check_unchanged() == Ok(true)
}

fn same_collected_scope(left: UProbeScope, right: UProbeScope) -> bool {
    match (left, right) {
        (UProbeScope::AllProcesses, UProbeScope::AllProcesses) => true,
        (UProbeScope::OneProcess(left), UProbeScope::OneProcess(right)) => left == right,
        _ => false,
    }
}

fn validate_collected_q(
    owner: &CollectedFinishQOwner<'_>,
    q: &CollectedFinishQ,
    read_events: impl FnOnce() -> Result<crate::events::EventsConsumptionCut>,
    read_discovery: impl FnOnce() -> Result<aya::maps::ring_buf::RingBufPositions>,
) -> Result<()> {
    super::validate_collected_finish_q_owner(owner, &q.producers, q.grant.as_ref())?;
    anyhow::ensure!(
        owner.gate.quiescent() && q.matches_owner(owner.producers, owner.discovery),
        "collected retirement requires the original stopped Session Q"
    );
    let events = read_events()?;
    let discovery = read_discovery()?;
    anyhow::ensure!(
        q.covers_events_bounds(&events)
            && events.producer_bound() == q.events_stop()
            && discovery.capacity == q.discovery_positions.capacity
            && discovery.producer == q.discovery_stop()
            && discovery.consumer >= q.discovery_positions.consumer
            && discovery.consumer <= discovery.producer
            && discovery.consumer.is_multiple_of(8)
            && owner.gate.quiescent(),
        "collected retirement producer bounds moved after Q"
    );
    Ok(())
}

impl NativeRetirement {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_collected_with(
        &mut self,
        owner: CollectedFinishQOwner<'_>,
        q: &CollectedFinishQ,
        scope: UProbeScope,
        input: &mut Option<RetainedRetirementInput>,
        reserver: &SemanticResourceReserver,
        links: &[RegisteredLink],
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        pairs: &PairBook,
        worker: &CleanupWorker,
        read_events: impl FnOnce() -> Result<crate::events::EventsConsumptionCut>,
        read_discovery: impl FnOnce() -> Result<aya::maps::ring_buf::RingBufPositions>,
        work: usize,
    ) -> Result<RetirementProgress> {
        if work == 0 {
            return Ok(RetirementProgress::yielded());
        }
        anyhow::ensure!(
            matches!(
                scope,
                UProbeScope::AllProcesses | UProbeScope::OneProcess(_)
            ),
            "collected retirement requires an explicit retained process scope"
        );
        anyhow::ensure!(
            self.pending.is_none(),
            "ordinary native retirement already owns this Session"
        );
        if let Some(cursor) = &self.collected {
            anyhow::ensure!(
                !cursor.mutated
                    && (cursor.cancelling
                        || matches!(
                            cursor.phase,
                            CollectedPhase::Allocate(_)
                                | CollectedPhase::Rows
                                | CollectedPhase::Chunks
                                | CollectedPhase::Selection(_)
                                | CollectedPhase::LinkStart(_)
                                | CollectedPhase::LinkMember { .. }
                                | CollectedPhase::Validate(_)
                                | CollectedPhase::Prepared
                        )),
                "collected preparation has already ended"
            );
            anyhow::ensure!(
                input.is_none()
                    && cursor.q == q as *const _ as usize
                    && same_collected_scope(cursor.scope, scope)
                    && cursor.worker.belongs_to(worker)
                    && cursor.fence.matches(links, retained, pairs),
                "collected preparation owner/registry changed"
            );
        } else if let Some(preflight) = &self.preflight {
            anyhow::ensure!(
                input
                    .as_ref()
                    .is_some_and(|input| input.identity == preflight.input)
                    && preflight.q == q as *const _ as usize
                    && same_collected_scope(preflight.scope, scope)
                    && preflight.worker.belongs_to(worker)
                    && preflight.fence.matches(links, retained, pairs),
                "collected preflight input/owner/registry changed"
            );
        }
        let (payment, required) = if let Some(cursor) = &self.collected {
            (&cursor.original().storage, cursor.input_bytes)
        } else {
            (
                &input
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("collected caller input is missing"))?
                    .storage,
                0,
            )
        };
        anyhow::ensure!(
            reserver.covers(payment, required),
            "collected preparation refuses a foreign or undercharged retained payment"
        );
        validate_collected_q(&owner, q, read_events, read_discovery)?;
        if let Some(cursor) = &mut self.collected {
            if cursor.cancelling {
                return self.drive_collected_release(worker, false);
            }
            if let Err(_reason) = cursor.prepare_one(links, retained, worker) {
                cursor.cancelling = true;
                cursor.phase = CollectedPhase::Dispose(0);
            }
            return Ok(match cursor.phase {
                CollectedPhase::Prepared => {
                    cursor.progress(CollectedRetirementState::Prepared(cursor.ticket.clone()))
                }
                _ => cursor.progress(CollectedRetirementState::Preparing),
            });
        }
        let original = input
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("collected retirement lost caller input"))?;
        if self.preflight.is_none() {
            worker.collected_admission().map_err(anyhow::Error::msg)?;
            self.preflight = Some(CollectedPreflight {
                input: original.identity,
                q: q as *const _ as usize,
                scope,
                fence: RegistryFence::new(links, retained, pairs),
                worker: worker.identity(),
                phase: PreflightPhase::InputBase,
                sizing: SlotSizing::default(),
                bytes: 0,
                backing: 0,
                high: 0,
                ranks: [0; 10],
            });
            return Ok(RetirementProgress::preparing());
        }
        let preflight = self.preflight.as_mut().expect("current preflight");
        if !preflight.step(original, reserver, links, retained, pairs)? {
            return Ok(RetirementProgress::preparing());
        }
        // All original/deep capacities and the actual pool check precede
        // allocating a cursor, cloning any file, or taking caller ownership.
        anyhow::ensure!(
            reserver.covers(&original.storage, preflight.bytes),
            "input payment changed"
        );
        worker.collected_admission().map_err(anyhow::Error::msg)?;
        let (bytes, shell_bytes, batches) =
            preflight.allocation_charge(original.removed.len(), links.len())?;
        let storage = reserver
            .reserve(bytes)
            .map_err(|_| anyhow::anyhow!("collected retirement cursor budget refused"))?;
        let shell_storage = reserver
            .reserve(shell_bytes)
            .map_err(|_| anyhow::anyhow!("collected retirement shell budget refused"))?;
        // No fallible query/reservation remains before taking the SAME input.
        let preflight = self.preflight.take().expect("admitted original preflight");
        let ticket = CollectedRetirementTicket {
            owner: Arc::clone(&self.allocation),
            cursor: Arc::new(()),
        };
        let retention = CollectedCleanupRetention::new(storage, original.removed.len());
        let cursor = Box::new(CollectedCursor {
            input: input.take(),
            input_bytes: preflight.bytes,
            ticket,
            q: preflight.q,
            scope,
            fence: preflight.fence,
            worker: preflight.worker,
            phase: CollectedPhase::Allocate(0),
            high: preflight.high,
            ranks: preflight.ranks,
            max_batches: batches,
            rows: Vec::new(),
            choices: Vec::new(),
            buckets: std::array::from_fn(|_| Vec::new()),
            chunks: Vec::new(),
            tickets: Vec::new(),
            mutated: false,
            cancelling: false,
            files: Arc::new(Vec::new()),
            retention: Some(retention),
            release: None,
            shell_storage: Some(shell_storage),
        });
        let progress = cursor.progress(CollectedRetirementState::Preparing);
        self.collected = Some(cursor);
        Ok(progress)
    }

    pub(super) fn cancel_collected_with(
        &mut self,
        input: Option<&RetainedRetirementInput>,
        ticket: Option<&CollectedRetirementTicket>,
        worker: &CleanupWorker,
        work: usize,
    ) -> Result<RetirementProgress> {
        if work == 0 {
            return Ok(RetirementProgress::yielded());
        }
        if let Some(preflight) = &self.preflight {
            anyhow::ensure!(
                ticket.is_none()
                    && input.is_some_and(|input| input.identity == preflight.input)
                    && preflight.worker.belongs_to(worker),
                "collected preparation cancellation is foreign"
            );
            self.preflight = None;
            return Ok(RetirementProgress {
                used: 1,
                state: CollectedRetirementState::Yielded,
                ticket: None,
            });
        }
        let cursor = self
            .collected
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no collected cursor to cancel"))?;
        anyhow::ensure!(
            input.is_none()
                && ticket.is_some_and(|ticket| cursor.matches(ticket))
                && cursor.worker.belongs_to(worker),
            "collected cursor cancellation is foreign"
        );
        if cursor.mutated {
            // Task5 must add a separately authenticated bounded abort/drain
            // handoff before terminal success. Destruction/exit is no receipt.
            cursor.phase = CollectedPhase::Refused;
            return Ok(cursor.progress(CollectedRetirementState::RefusedRetained));
        }
        if !cursor.cancelling {
            cursor.cancelling = true;
            cursor.phase = CollectedPhase::Dispose(0);
        }
        self.drive_collected_release(worker, false)
    }

    fn drive_collected_release(
        &mut self,
        worker: &CleanupWorker,
        closed: bool,
    ) -> Result<RetirementProgress> {
        let cursor = self.collected.as_mut().expect("current original cursor");
        anyhow::ensure!(
            closed || !cursor.mutated,
            "mutated retirement cannot return an untouched input"
        );
        anyhow::ensure!(
            cursor.worker.belongs_to(worker),
            "retained release worker is foreign"
        );
        match cursor.phase {
            CollectedPhase::Dispose(_) => {
                if cursor.dispose_one() {
                    cursor.phase = CollectedPhase::Release;
                }
            }
            CollectedPhase::Release => {
                // All variable plain backing and every completed native ticket
                // are gone. MOVE the actual guard: no foreground alias remains.
                let guard = cursor
                    .retention
                    .take()
                    .expect("original retained owner guard");
                match worker.submit_collected_release(guard) {
                    Ok(ticket) => {
                        cursor.release = Some(ticket);
                        cursor.phase = CollectedPhase::ReleasePending;
                    }
                    Err(failure) => {
                        worker.retain_unsubmitted(failure);
                        cursor.phase = CollectedPhase::Refused;
                    }
                }
            }
            CollectedPhase::ReleasePending => {
                let release = cursor
                    .release
                    .as_ref()
                    .expect("original retained release ticket");
                anyhow::ensure!(
                    release.belongs_to(worker),
                    "retained release receipt is foreign"
                );
                match release.status() {
                    BatchStatus::Released => return Ok(self.finish_collected(closed)),
                    BatchStatus::Pending if worker.running() => {}
                    BatchStatus::Pending | BatchStatus::Failed => {
                        cursor.phase = CollectedPhase::Refused
                    }
                }
            }
            CollectedPhase::Refused => {}
            _ => bail!("retained owner release is not ready"),
        }
        Ok(
            cursor.progress(if matches!(cursor.phase, CollectedPhase::Refused) {
                CollectedRetirementState::RefusedRetained
            } else if closed {
                CollectedRetirementState::Pending
            } else {
                CollectedRetirementState::Preparing
            }),
        )
    }

    fn finish_collected(&mut self, closed: bool) -> RetirementProgress {
        let mut cursor = self.collected.take().expect("current collected cursor");
        let input = cursor.input.take().expect("same original removal input");
        let ticket = cursor.ticket.clone();
        let shell_storage = cursor.shell_storage.take();
        drop(cursor);
        drop(shell_storage);
        RetirementProgress {
            used: 1,
            state: if closed {
                CollectedRetirementState::Closed(input)
            } else {
                CollectedRetirementState::RefusedUntouched(input)
            },
            ticket: Some(ticket),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn begin_collected_with(
        &mut self,
        owner: CollectedFinishQOwner<'_>,
        q: &CollectedFinishQ,
        scope: UProbeScope,
        ticket: &CollectedRetirementTicket,
        links: &mut Vec<RegisteredLink>,
        retained: &mut BTreeMap<u32, RetainedStaticTarget>,
        pairs: &mut PairBook,
        _gaps: &mut Retirements,
        worker: &CleanupWorker,
        mut transfer: impl FnMut(RegisteredLink) -> Result<Vec<OwnedLink>>,
        read_events: impl FnOnce() -> Result<crate::events::EventsConsumptionCut>,
        read_discovery: impl FnOnce() -> Result<aya::maps::ring_buf::RingBufPositions>,
        work: usize,
    ) -> Result<RetirementProgress> {
        if work == 0 {
            return Ok(RetirementProgress::yielded());
        }
        let cursor = self
            .collected
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no prepared collected retirement"))?;
        anyhow::ensure!(
            cursor.matches(ticket)
                && cursor.q == q as *const _ as usize
                && same_collected_scope(cursor.scope, scope)
                && cursor.worker.belongs_to(worker)
                && cursor.fence.matches(links, retained, pairs),
            "collected transfer owner/registry changed"
        );
        validate_collected_q(&owner, q, read_events, read_discovery)?;
        if cursor.cancelling {
            return self.drive_collected_release(worker, false);
        }
        match cursor.phase {
            CollectedPhase::Prepared => {
                cursor.phase = CollectedPhase::Invalidate(0);
            }
            CollectedPhase::Invalidate(index) => {
                if let Some(slot) = cursor.original().removed.get(index).map(|slot| slot.index) {
                    if let Some(stamp) = pairs.take_collected_stamp(slot) {
                        cursor
                            .retention
                            .as_ref()
                            .expect("retained original guard")
                            .retain_stamp(stamp);
                    }
                    cursor.mutated = true;
                    cursor.fence.pair_state = pairs.collected_fence();
                    cursor.phase = CollectedPhase::Invalidate(index + 1);
                } else {
                    cursor.phase = CollectedPhase::Targets(0);
                }
            }
            CollectedPhase::Targets(index) => {
                if let Some(slot) = cursor.original().removed.get(index).map(|slot| slot.index) {
                    if let Some(target) = retained.remove(&slot) {
                        cursor
                            .retention
                            .as_ref()
                            .expect("retained original guard")
                            .retain_target(target);
                        cursor.fence.target_count = retained.len();
                        cursor.phase = CollectedPhase::Targets(index + 1);
                    } else {
                        cursor.phase = CollectedPhase::Refused;
                    }
                } else {
                    cursor.phase = CollectedPhase::Extract(cursor.choices.len());
                }
            }
            CollectedPhase::Extract(end) => {
                if end == 0 {
                    cursor.phase = CollectedPhase::Transfer { rank: 0, chunk: 0 };
                } else {
                    let index = end - 1;
                    if cursor.choices[index].selected {
                        let original = links.swap_remove(index);
                        let rank = DetachOrder.rank(&original.producer()) as usize;
                        cursor.buckets[rank].push(original);
                        cursor.fence.link_count = links.len();
                    }
                    cursor.phase = CollectedPhase::Extract(index);
                }
            }
            CollectedPhase::Transfer { rank, chunk } => {
                if rank == 10 {
                    cursor.phase = CollectedPhase::Pending(0);
                } else if cursor.buckets[rank].is_empty() {
                    cursor.phase = if cursor.chunks.get(chunk).is_none_or(Vec::is_empty) {
                        CollectedPhase::Transfer {
                            rank: rank + 1,
                            chunk,
                        }
                    } else {
                        CollectedPhase::Submit {
                            rank: rank + 1,
                            chunk,
                        }
                    };
                } else if worker.collected_admission().is_err() {
                    cursor.phase = CollectedPhase::Refused;
                } else {
                    let original = cursor.buckets[rank].pop().expect("original rank member");
                    let producer = original.producer();
                    match transfer(original) {
                        Ok(mut owned) if owned.len() == 1 => {
                            cursor.chunks[chunk]
                                .push((owned.pop().expect("one static owning payload"), producer));
                            if cursor.chunks[chunk].len() == 4 {
                                cursor.phase = CollectedPhase::Submit { rank, chunk };
                            }
                        }
                        Err(error) => {
                            worker.note_transfer_failed(1);
                            cursor.phase = CollectedPhase::Refused;
                            return Err(
                                error.context("transferring original collected static ownership")
                            );
                        }
                        Ok(owned) => {
                            worker.note_transfer_failed(owned.len().max(1));
                            // A violated one-payload static leaf contract is
                            // uncertain, never a foreground close opportunity.
                            std::mem::forget((
                                owned,
                                Arc::clone(
                                    cursor.retention.as_ref().expect("native ownership guard"),
                                ),
                            ));
                            cursor.phase = CollectedPhase::Refused;
                        }
                    }
                }
            }
            CollectedPhase::Submit { rank, chunk } => {
                let payloads = std::mem::take(&mut cursor.chunks[chunk]);
                match worker.submit_collected(
                    payloads,
                    Arc::clone(&cursor.files),
                    Arc::clone(cursor.retention.as_ref().expect("native ownership guard")),
                ) {
                    Ok(batch) => {
                        cursor.tickets.push(batch);
                        cursor.phase = CollectedPhase::Transfer {
                            rank,
                            chunk: chunk + 1,
                        };
                    }
                    Err(failure) => {
                        worker.retain_unsubmitted(failure);
                        cursor.phase = CollectedPhase::Refused;
                    }
                }
            }
            CollectedPhase::Pending(_) => {
                return Ok(cursor.progress(CollectedRetirementState::Pending));
            }
            CollectedPhase::Refused => {
                return Ok(cursor.progress(CollectedRetirementState::RefusedRetained));
            }
            _ => bail!("collected retirement is not prepared for transfer"),
        }
        Ok(cursor.progress(match cursor.phase {
            CollectedPhase::Pending(_) => CollectedRetirementState::Pending,
            CollectedPhase::Refused => CollectedRetirementState::RefusedRetained,
            _ => CollectedRetirementState::Transferring,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn poll_collected_with(
        &mut self,
        owner: CollectedFinishQOwner<'_>,
        q: &CollectedFinishQ,
        ticket: &CollectedRetirementTicket,
        worker: &CleanupWorker,
        read_events: impl FnOnce() -> Result<crate::events::EventsConsumptionCut>,
        read_discovery: impl FnOnce() -> Result<aya::maps::ring_buf::RingBufPositions>,
        work: usize,
    ) -> Result<RetirementProgress> {
        if work == 0 {
            return Ok(RetirementProgress::yielded());
        }
        let cursor = self
            .collected
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no collected batch to poll"))?;
        anyhow::ensure!(
            cursor.matches(ticket)
                && cursor.q == q as *const _ as usize
                && cursor.worker.belongs_to(worker),
            "collected poll ticket/Q/worker is foreign"
        );
        validate_collected_q(&owner, q, read_events, read_discovery)?;
        match cursor.phase {
            CollectedPhase::Pending(index) => {
                if let Some(batch) = cursor.tickets.get(index) {
                    anyhow::ensure!(
                        batch.belongs_to(worker),
                        "collected receipt belongs to another worker"
                    );
                    match batch.status() {
                        BatchStatus::Pending if worker.running() => {}
                        BatchStatus::Released => cursor.phase = CollectedPhase::Pending(index + 1),
                        BatchStatus::Pending | BatchStatus::Failed => {
                            cursor.phase = CollectedPhase::Refused
                        }
                    }
                } else {
                    cursor.phase = CollectedPhase::Dispose(0);
                }
            }
            CollectedPhase::Dispose(_)
            | CollectedPhase::Release
            | CollectedPhase::ReleasePending => {
                let closed = !cursor.cancelling;
                return self.drive_collected_release(worker, closed);
            }
            CollectedPhase::Refused => {
                return Ok(cursor.progress(CollectedRetirementState::RefusedRetained));
            }
            _ => bail!("collected original batch has not been submitted"),
        }
        Ok(cursor.progress(match cursor.phase {
            CollectedPhase::Refused => CollectedRetirementState::RefusedRetained,
            _ => CollectedRetirementState::Pending,
        }))
    }

    pub(super) fn program_to_validate(&self, links: &[RegisteredLink]) -> Option<&'static str> {
        let index = match (&self.preflight, &self.collected) {
            (Some(preflight), _) => match preflight.phase {
                PreflightPhase::Registry(index) => index,
                _ => return None,
            },
            (_, Some(cursor)) => match cursor.phase {
                CollectedPhase::LinkStart(index) => index,
                _ => return None,
            },
            _ => return None,
        };
        match links.get(index) {
            Some(RegisteredLink::UProbe { program, .. }) => Some(*program),
            _ => None,
        }
    }
}

impl NativeRetirement {
    /// Session destruction cannot leave extracted Aya IDs for Ebpf's
    /// foreground destructor. Transfer the original unsent registrations to
    /// the SAME worker, then explicitly abandon all uncertain cursor custody.
    pub(super) fn abandon_collected_with(
        &mut self,
        remaining: &[RegisteredLink],
        worker: Option<&CleanupWorker>,
        mut transfer: impl FnMut(RegisteredLink) -> Result<Vec<OwnedLink>>,
    ) {
        let Some(cursor) = &mut self.collected else {
            return;
        };
        let Some(worker) = worker else {
            return;
        };
        if !cursor.worker.belongs_to(worker) {
            return;
        }
        let Some(retention) = cursor.retention.as_ref() else {
            worker.note_failure("collected cursor abandoned during retained-owner release".into());
            return;
        };
        if !remaining.is_empty() {
            // A return may have been extracted before its entry. The separate
            // remaining-registry submit cannot prove one merged rank order:
            // retain these ACTUAL unsent handles rather than queue return first.
            for bucket in &mut cursor.buckets {
                while let Some(original) = bucket.pop() {
                    let producer = original.producer();
                    match transfer(original) {
                        Ok(owned) => worker.retain_collected_abandoned(
                            owned.into_iter().map(|owned| (owned, producer)).collect(),
                            Arc::clone(&cursor.files),
                            Arc::clone(retention),
                        ),
                        Err(_) => worker.note_transfer_failed(1),
                    }
                }
            }
            for chunk in &mut cursor.chunks {
                if !chunk.is_empty() {
                    worker.retain_collected_abandoned(
                        std::mem::take(chunk),
                        Arc::clone(&cursor.files),
                        Arc::clone(retention),
                    );
                }
            }
            worker.note_failure("collected destructor retained an unproved joint handoff".into());
            return;
        }
        // Only destruction uses this loop. Normal work/cancellation never
        // calls it or treats it as a bounded/healthy disposition. Reuse the
        // prepaid four-payload buffers in the same global detach rank order.
        let mut next = cursor
            .chunks
            .iter()
            .position(|chunk| chunk.capacity() != 0)
            .unwrap_or(cursor.chunks.len());
        for rank in 0..10 {
            while let Some(original) = cursor.buckets[rank].pop() {
                let producer = original.producer();
                match transfer(original) {
                    Ok(mut owned) if owned.len() == 1 && next < cursor.chunks.len() => {
                        cursor.chunks[next]
                            .push((owned.pop().expect("one original payload"), producer));
                        if cursor.chunks[next].len() == 4 {
                            let payloads = std::mem::take(&mut cursor.chunks[next]);
                            if let Err(failure) = worker.submit_collected(
                                payloads,
                                Arc::clone(&cursor.files),
                                Arc::clone(retention),
                            ) {
                                worker.retain_unsubmitted(failure);
                            }
                            next += 1;
                        }
                    }
                    Ok(owned) => {
                        worker.note_transfer_failed(1);
                        std::mem::forget((owned, Arc::clone(retention)));
                    }
                    Err(_) => worker.note_transfer_failed(1),
                }
            }
            if cursor
                .chunks
                .get(next)
                .and_then(|chunk| chunk.first())
                .is_some_and(|(_, producer)| DetachOrder.rank(producer) as usize == rank)
            {
                let payloads = std::mem::take(&mut cursor.chunks[next]);
                if let Err(failure) = worker.submit_collected(
                    payloads,
                    Arc::clone(&cursor.files),
                    Arc::clone(retention),
                ) {
                    worker.retain_unsubmitted(failure);
                }
                next += 1;
            }
        }
    }
}

impl Drop for NativeRetirement {
    fn drop(&mut self) {
        if let Some(cursor) = self.collected.take() {
            // Explicit abandonment is not a close or refund. Unsent original
            // registrations, payloads, providers and their real charge stay
            // together until process exit; no foreground native destructor.
            std::mem::forget(cursor);
        }
    }
}

#[cfg(test)]
#[path = "native_retirement_fixture.rs"]
pub(crate) mod fixture;

#[cfg(test)]
#[path = "native_retirement_tests.rs"]
mod tests;
