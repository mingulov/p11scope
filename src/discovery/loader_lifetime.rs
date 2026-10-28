//! SPDX-License-Identifier: GPL-3.0-or-later
//! Staged L1 loader-lifetime token/generation model (G16).
//!
//! Pure userspace model of the loader transition's private identities,
//! finite charges and sealed retirement state machine: 40-bit
//! [`LoaderToken`] values with checked per-slot generations, exact export
//! descriptors with never-reused site ordinals, domain-sealed retirement
//! fences and reference-balanced cutoff/acknowledgement. The state machine
//! is `Prepared -> Active -> Closing -> ProducersQuiet -> Draining ->
//! Reclaimable`, with permanent quarantine on exhaustion or custody faults.
//!
//! This model enables no production reuse: production allocation stays on
//! [`super::loader::LoaderRegistry`]'s 256-context refusal path until L2/L3
//! land atomically. L2 binds the real BPF producer guards, maps and wire
//! transport to the cookie contract pinned here; L3 wires Engine queue/scan
//! accounting and link cleanup into the fence acknowledgement. Queued-work
//! references are split by the five owning queues so L3's wiring checklist
//! is explicit; export bindings carry the real (view, object, offset, hook,
//! ABI) tuple, and L2 seals its BPF/wire transport.

use std::sync::atomic::{AtomicU64, Ordering};

use p11scope_manifest::elf::{ElfAbi, SymbolFact};

use super::identity::PinnedObjectId;
use crate::process::ProcessViewId;

/// Loader storage slots. Must equal the production registry bound: reuse
/// recycles storage, never identity.
pub(crate) const MAX_LIFETIME_SLOTS: usize = 256;
/// Per-incarnation site ordinals are nonzero and fit 24 bits.
pub(crate) const MAX_SITE_ORDINAL: u32 = 0x00ff_ffff;
/// Tokens are nonzero 40-bit `(generation << 8) | slot` values.
const TOKEN_BITS: u32 = 40;
const TOKEN_MAX: u64 = (1 << TOKEN_BITS) - 1;

/// Sealed Session/discovery-domain identity. Tokens and fences carry their
/// domain on every call; equal numeric tokens from another domain never
/// match. Each Session mints exactly one domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LifetimeDomain(u64);

static NEXT_DOMAIN: AtomicU64 = AtomicU64::new(1);

impl LifetimeDomain {
    pub(crate) fn mint() -> Self {
        Self(NEXT_DOMAIN.fetch_add(1, Ordering::SeqCst))
    }
}

/// Opaque loader incarnation identity: `(generation << 8) | slot`.
/// Generation 0 is never issued; burned generations never wrap or roll back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LoaderToken(u64);

impl LoaderToken {
    pub(crate) fn new(generation: u32, slot: u8) -> Option<Self> {
        if generation == 0 {
            return None;
        }
        Some(Self((u64::from(generation) << 8) | u64::from(slot)))
    }

    pub(crate) fn from_bits(bits: u64) -> Option<Self> {
        if bits == 0 || bits > TOKEN_MAX || (bits >> 8) == 0 {
            return None;
        }
        Some(Self(bits))
    }

    pub(crate) fn generation(self) -> u32 {
        (self.0 >> 8) as u32
    }

    pub(crate) fn slot(self) -> u8 {
        (self.0 & 0xff) as u8
    }

    pub(crate) fn bits(self) -> u64 {
        self.0
    }
}

/// Live phases of one incarnation. Storage states (free/reclaimable) are
/// reported through [`SlotView`], never as a token phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotPhase {
    Prepared,
    Active,
    Closing,
    ProducersQuiet,
    Draining,
    Quarantined,
}

/// Observable storage state of one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotView {
    Free {
        generation: u32,
    },
    Reclaimable {
        generation: u32,
    },
    Live {
        token: LoaderToken,
        phase: SlotPhase,
    },
}

/// The five owning queues whose references must all reach disposition
/// before a fence acknowledges. L3 charges each real queue here; H5's queue
/// owners transfer those references exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueKind {
    Collected,
    Pending,
    Deferred,
    TerminalBatch,
    SelectionHandoff,
}

impl QueueKind {
    const ALL: [QueueKind; 5] = [
        QueueKind::Collected,
        QueueKind::Pending,
        QueueKind::Deferred,
        QueueKind::TerminalBatch,
        QueueKind::SelectionHandoff,
    ];

    fn index(self) -> usize {
        match self {
            QueueKind::Collected => 0,
            QueueKind::Pending => 1,
            QueueKind::Deferred => 2,
            QueueKind::TerminalBatch => 3,
            QueueKind::SelectionHandoff => 4,
        }
    }
}

/// Identity tuple for one export site: owning view, pinned object, export
/// file offset, hook symbol and ABI. Matching is exact-tuple equality: a
/// retry reuses its descriptor, any field change mints a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExportBinding {
    pub(crate) view: ProcessViewId,
    pub(crate) object: PinnedObjectId,
    pub(crate) file_offset: u64,
    pub(crate) hook: SymbolFact,
    pub(crate) abi: ElfAbi,
}

/// Driver-supplied drain observation: the shared consumer position and
/// whether a BUSY record from another writer still sits before the fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsumerDrain {
    pub(crate) consumer: u64,
    pub(crate) busy_before_q: bool,
}

/// Local-prefix drain outcome. A foreign BUSY head is bounded Pending, not
/// the global drain's ungated-writer conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrefixOutcome {
    Pending(PendingReason),
    PrefixComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingReason {
    Draining,
    ForeignBusy,
}

/// Owned retirement cursor. Authority stays slot-side: every step
/// re-validates domain, token currency and phase, so a copied cursor can
/// never forge progress for a successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoaderRetirement {
    domain: LifetimeDomain,
    token: LoaderToken,
}

/// Session-minted retirement fence. Constructible only through
/// [`LifetimeRegistry::mint_fence`] after close, closed-zero and Q sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoaderRetirementFence {
    domain: LifetimeDomain,
    token: LoaderToken,
    fence_q: u64,
}

/// Sealed reclamation receipt minted only by a successful acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReclaimedSlot {
    slot: u8,
    retired_generation: u32,
}

impl ReclaimedSlot {
    pub(crate) fn slot(self) -> u8 {
        self.slot
    }

    pub(crate) fn retired_generation(self) -> u32 {
        self.retired_generation
    }
}

/// Immutable historical fact preserved at acknowledgement. Production
/// history retention follows the existing capture-history budgets (L3); the
/// model keeps the facts themselves immutable either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HistoricalFact {
    token: LoaderToken,
    publication_arms: u64,
    useful_calls: u64,
}

impl HistoricalFact {
    pub(crate) fn token(self) -> LoaderToken {
        self.token
    }

    pub(crate) fn publication_arms(self) -> u64 {
        self.publication_arms
    }

    pub(crate) fn useful_calls(self) -> u64 {
        self.useful_calls
    }
}

/// Typed model refusal. Messages carry counts, never private token bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifetimeError {
    ForeignDomain,
    StaleToken,
    CapacityExhausted,
    GenerationExhausted,
    GenerationRollback,
    SiteExhausted,
    DescriptorExhausted,
    AdmissionClosed,
    UnexpectedPhase {
        expected: &'static str,
        actual: SlotPhase,
    },
    ProducersActive {
        short: u64,
        long: u64,
    },
    QAlreadyFixed,
    DrainIncomplete {
        consumer: u64,
        fence_q: u64,
    },
    ForeignBusyBeforeQ,
    RecordsPending {
        queue: QueueKind,
        count: u64,
    },
    ScansPending(u64),
    DescriptorsPending(usize),
    CleanupIncomplete,
    CleanupFailed,
    Quarantined,
    PermanentQuarantine,
    BookkeepingOverflow,
    UnbalancedRelease,
    MissingShortGuard,
    StateDeleteFailed,
    LinksStillOpen,
    UnknownDescriptor,
    ExportAlreadyClosed,
    PendingMismatch,
    InvalidCeiling,
    InjectedPrepareFault {
        slot: u8,
        generation: u32,
    },
}

impl std::fmt::Display for LifetimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignDomain => write!(formatter, "foreign domain cannot use this registry"),
            Self::StaleToken => write!(formatter, "token is not the current occupant"),
            Self::CapacityExhausted => write!(formatter, "256 loader contexts are charged"),
            Self::GenerationExhausted => write!(formatter, "no slot has a burnable generation"),
            Self::GenerationRollback => write!(formatter, "generations never roll back"),
            Self::SiteExhausted => write!(formatter, "site ordinals are exhausted"),
            Self::DescriptorExhausted => write!(formatter, "descriptor budget is exhausted"),
            Self::AdmissionClosed => write!(formatter, "retiring context admits no new work"),
            Self::UnexpectedPhase { expected, actual } => {
                write!(formatter, "expected {expected}, found {actual:?}")
            }
            Self::ProducersActive { short, long } => write!(
                formatter,
                "producers are not quiet: {short} short and {long} long references"
            ),
            Self::QAlreadyFixed => write!(formatter, "the fence position is already fixed"),
            Self::DrainIncomplete { consumer, fence_q } => write!(
                formatter,
                "consumer {consumer} has not reached fence {fence_q}"
            ),
            Self::ForeignBusyBeforeQ => {
                write!(formatter, "a foreign BUSY record blocks the prefix")
            }
            Self::RecordsPending { queue, count } => {
                write!(formatter, "{count} {queue:?} records await disposition")
            }
            Self::ScansPending(count) => write!(formatter, "{count} scans await settlement"),
            Self::DescriptorsPending(count) => {
                write!(formatter, "{count} descriptors await settlement")
            }
            Self::CleanupIncomplete => write!(formatter, "link cleanup is not recorded"),
            Self::CleanupFailed => write!(formatter, "link cleanup failed; custody is retained"),
            Self::Quarantined => write!(formatter, "the context is quarantined"),
            Self::PermanentQuarantine => {
                write!(formatter, "quarantined contexts never retire")
            }
            Self::BookkeepingOverflow => write!(formatter, "reference count would wrap"),
            Self::UnbalancedRelease => write!(formatter, "release exceeds held references"),
            Self::MissingShortGuard => write!(formatter, "insertion needs a held short guard"),
            Self::StateDeleteFailed => {
                write!(formatter, "state deletion failed; the lease is pinned")
            }
            Self::LinksStillOpen => write!(formatter, "links close before settlement"),
            Self::UnknownDescriptor => write!(formatter, "no such export descriptor"),
            Self::ExportAlreadyClosed => write!(formatter, "export links are already closed"),
            Self::PendingMismatch => write!(formatter, "no matching pending charge"),
            Self::InvalidCeiling => write!(formatter, "descriptor ceiling is not finite"),
            Self::InjectedPrepareFault { slot, generation } => write!(
                formatter,
                "injected prepare fault burned slot {slot} generation {generation}"
            ),
        }
    }
}

impl std::error::Error for LifetimeError {}

#[derive(Debug)]
struct LiveDescriptor {
    cookie: u64,
    binding: ExportBinding,
    links_closed: bool,
}

#[derive(Debug)]
struct LiveSlot {
    token: LoaderToken,
    phase: SlotPhase,
    short_refs: u64,
    long_refs: u64,
    queued: [u64; 5],
    pending_scans: u64,
    site_high_water: u32,
    descriptors: Vec<LiveDescriptor>,
    fence_q: Option<u64>,
    prefix_complete: bool,
    cleanup: Option<bool>,
    publication_arms: u64,
    useful_calls: u64,
}

impl LiveSlot {
    fn new(token: LoaderToken) -> Self {
        Self {
            token,
            phase: SlotPhase::Prepared,
            short_refs: 0,
            long_refs: 0,
            queued: [0; 5],
            pending_scans: 0,
            site_high_water: 0,
            descriptors: Vec::new(),
            fence_q: None,
            prefix_complete: false,
            cleanup: None,
            publication_arms: 0,
            useful_calls: 0,
        }
    }
}

#[derive(Debug)]
enum Slot {
    Free { generation: u32 },
    Reclaimable { generation: u32 },
    Live(Box<LiveSlot>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingCharge {
    slot: u8,
    generation: u32,
}

/// Staged generation registry. Every method checks the domain first, then
/// token currency against the slot's current occupant, then the phase rule,
/// so stale references can never resolve to a successor.
#[derive(Debug)]
pub(crate) struct LifetimeRegistry {
    domain: LifetimeDomain,
    slots: [Slot; MAX_LIFETIME_SLOTS],
    descriptor_ceiling: u64,
    pending_charges: Vec<PendingCharge>,
    history: Vec<HistoricalFact>,
}

impl LifetimeRegistry {
    pub(crate) fn new(
        domain: LifetimeDomain,
        descriptor_ceiling: u64,
    ) -> Result<Self, LifetimeError> {
        if descriptor_ceiling == 0 {
            return Err(LifetimeError::InvalidCeiling);
        }
        Ok(Self {
            domain,
            slots: std::array::from_fn(|_| Slot::Free { generation: 0 }),
            descriptor_ceiling,
            pending_charges: Vec::new(),
            history: Vec::new(),
        })
    }

    pub(crate) fn domain(&self) -> LifetimeDomain {
        self.domain
    }

    /// At most `floor(D/2)` dynamic export descriptors, per the Session
    /// descriptor ceiling snapshot L3 supplies.
    pub(crate) fn max_descriptors(&self) -> usize {
        usize::try_from(self.descriptor_ceiling / 2).unwrap_or(usize::MAX)
    }

    /// Every live context in every phase, including retiring custody and
    /// permanent quarantine. Free and reclaimable storage is uncharged.
    pub(crate) fn charged_contexts(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Slot::Live(_)))
            .count()
    }

    pub(crate) fn charged_descriptors(&self) -> usize {
        let live: usize = self
            .slots
            .iter()
            .filter_map(|slot| match slot {
                Slot::Live(context) => Some(context.descriptors.len()),
                _ => None,
            })
            .sum();
        live + self.pending_charges.len()
    }

    pub(crate) fn history(&self) -> &[HistoricalFact] {
        &self.history
    }

    pub(crate) fn pending_charges(&self) -> usize {
        self.pending_charges.len()
    }

    pub(crate) fn slot_state(&self, slot: u8) -> SlotView {
        match &self.slots[usize::from(slot)] {
            Slot::Free { generation } => SlotView::Free {
                generation: *generation,
            },
            Slot::Reclaimable { generation } => SlotView::Reclaimable {
                generation: *generation,
            },
            Slot::Live(context) => SlotView::Live {
                token: context.token,
                phase: context.phase,
            },
        }
    }

    /// The current occupant's phase, or `None` for any stale token. Stale
    /// references never name the successor.
    pub(crate) fn phase_of(&self, token: LoaderToken) -> Option<SlotPhase> {
        match &self.slots[usize::from(token.slot())] {
            Slot::Live(context) if context.token == token => Some(context.phase),
            _ => None,
        }
    }

    /// Whether the fixed prefix has been observed drained. Poll progress
    /// only; the acknowledgement re-proves the consumer position itself.
    pub(crate) fn prefix_complete(&self, token: LoaderToken) -> Option<bool> {
        match &self.slots[usize::from(token.slot())] {
            Slot::Live(context) if context.token == token => Some(context.prefix_complete),
            _ => None,
        }
    }

    fn check_domain(&self, domain: LifetimeDomain) -> Result<(), LifetimeError> {
        if domain == self.domain {
            Ok(())
        } else {
            Err(LifetimeError::ForeignDomain)
        }
    }

    fn live(&self, token: LoaderToken) -> Result<&LiveSlot, LifetimeError> {
        match &self.slots[usize::from(token.slot())] {
            Slot::Live(context) if context.token == token => Ok(context),
            _ => Err(LifetimeError::StaleToken),
        }
    }

    fn live_mut(&mut self, token: LoaderToken) -> Result<&mut LiveSlot, LifetimeError> {
        match &mut self.slots[usize::from(token.slot())] {
            Slot::Live(context) if context.token == token => Ok(context),
            _ => Err(LifetimeError::StaleToken),
        }
    }

    fn burnable_slot(&self) -> Option<(u8, u32)> {
        for (index, slot) in self.slots.iter().enumerate() {
            let generation = match slot {
                Slot::Free { generation } | Slot::Reclaimable { generation } => *generation,
                Slot::Live(_) => continue,
            };
            if generation < u32::MAX {
                return Some((index as u8, generation));
            }
        }
        None
    }

    /// Reserve storage and burn one generation. Failed publication/attach
    /// burns through [`Self::prepare_new_faulted`]; nothing rolls back.
    pub(crate) fn prepare_new(
        &mut self,
        domain: LifetimeDomain,
    ) -> Result<LoaderToken, LifetimeError> {
        self.check_domain(domain)?;
        if self.charged_contexts() == MAX_LIFETIME_SLOTS {
            return Err(LifetimeError::CapacityExhausted);
        }
        let Some((slot, burned)) = self.burnable_slot() else {
            return Err(LifetimeError::GenerationExhausted);
        };
        let generation = burned + 1;
        let token = LoaderToken::new(generation, slot).expect("burned generation is nonzero");
        self.slots[usize::from(slot)] = Slot::Live(Box::new(LiveSlot::new(token)));
        Ok(token)
    }

    /// Model a failed publication/attach: the generation burns, the slot
    /// stays free, and at most one pending descriptor charge is retained
    /// until [`Self::cleanup_pending`]. A full descriptor budget refuses the
    /// charge but the burn still sticks.
    pub(crate) fn prepare_new_faulted(
        &mut self,
        domain: LifetimeDomain,
    ) -> Result<LoaderToken, LifetimeError> {
        self.check_domain(domain)?;
        if self.charged_contexts() == MAX_LIFETIME_SLOTS {
            return Err(LifetimeError::CapacityExhausted);
        }
        let Some((slot, burned)) = self.burnable_slot() else {
            return Err(LifetimeError::GenerationExhausted);
        };
        let generation = burned + 1;
        self.slots[usize::from(slot)] = Slot::Free { generation };
        if self.charged_descriptors() < self.max_descriptors() {
            self.pending_charges
                .push(PendingCharge { slot, generation });
        } else {
            return Err(LifetimeError::DescriptorExhausted);
        }
        Err(LifetimeError::InjectedPrepareFault { slot, generation })
    }

    pub(crate) fn cleanup_pending(
        &mut self,
        domain: LifetimeDomain,
        slot: u8,
        generation: u32,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let position = self
            .pending_charges
            .iter()
            .position(|charge| charge.slot == slot && charge.generation == generation)
            .ok_or(LifetimeError::PendingMismatch)?;
        self.pending_charges.remove(position);
        Ok(())
    }

    pub(crate) fn activate(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        if context.phase != SlotPhase::Prepared {
            return Err(LifetimeError::UnexpectedPhase {
                expected: "Prepared",
                actual: context.phase,
            });
        }
        context.phase = SlotPhase::Active;
        Ok(())
    }

    /// Cancel a prepared-but-never-attached context. The charge frees; the
    /// burned generation never rolls back.
    pub(crate) fn cancel_prepared(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let slot = token.slot();
        let context = self.live_mut(token)?;
        if context.phase != SlotPhase::Prepared {
            return Err(LifetimeError::UnexpectedPhase {
                expected: "Prepared",
                actual: context.phase,
            });
        }
        let generation = context.token.generation();
        self.slots[usize::from(slot)] = Slot::Free { generation };
        Ok(())
    }

    /// Short callback admission. Open only before retirement closes the
    /// gate; L2 implements the checked CAS behind this rule.
    pub(crate) fn acquire_short(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        match context.phase {
            SlotPhase::Prepared | SlotPhase::Active => {}
            SlotPhase::Quarantined => return Err(LifetimeError::Quarantined),
            _ => return Err(LifetimeError::AdmissionClosed),
        }
        context.short_refs = context.short_refs.checked_add(1).ok_or_else(|| {
            context.phase = SlotPhase::Quarantined;
            LifetimeError::BookkeepingOverflow
        })?;
        Ok(())
    }

    pub(crate) fn release_short(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        context.short_refs = context
            .short_refs
            .checked_sub(1)
            .ok_or(LifetimeError::UnbalancedRelease)?;
        Ok(())
    }

    /// Discovery-state insertion takes one long lease while the entry body
    /// still holds its short guard. New producer leases stop once the
    /// context is proven quiet.
    pub(crate) fn insert_state(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        match context.phase {
            SlotPhase::Prepared | SlotPhase::Active | SlotPhase::Closing => {}
            SlotPhase::Quarantined => return Err(LifetimeError::Quarantined),
            _ => return Err(LifetimeError::AdmissionClosed),
        }
        if context.short_refs == 0 {
            return Err(LifetimeError::MissingShortGuard);
        }
        context.long_refs = context.long_refs.checked_add(1).ok_or_else(|| {
            context.phase = SlotPhase::Quarantined;
            LifetimeError::BookkeepingOverflow
        })?;
        Ok(())
    }

    /// Native guarded removal. Success refunds the long lease; failure
    /// poisons and pins the context without refunding it.
    pub(crate) fn remove_state(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
        deleted: bool,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        if context.long_refs == 0 {
            return Err(LifetimeError::UnbalancedRelease);
        }
        if !deleted {
            context.phase = SlotPhase::Quarantined;
            return Err(LifetimeError::StateDeleteFailed);
        }
        context.long_refs -= 1;
        Ok(())
    }

    /// Charge one queued reference on collection. Consumer-side: allowed in
    /// every live phase so retiring contexts keep exact custody.
    pub(crate) fn collect_record(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
        queue: QueueKind,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        match context.queued[queue.index()].checked_add(1) {
            Some(next) => context.queued[queue.index()] = next,
            None => {
                context.phase = SlotPhase::Quarantined;
                return Err(LifetimeError::BookkeepingOverflow);
            }
        }
        Ok(())
    }

    pub(crate) fn dispose_record(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
        queue: QueueKind,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        let cell = &mut context.queued[queue.index()];
        *cell = cell
            .checked_sub(1)
            .ok_or(LifetimeError::UnbalancedRelease)?;
        Ok(())
    }

    pub(crate) fn register_scan(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        context.pending_scans = context.pending_scans.checked_add(1).ok_or_else(|| {
            context.phase = SlotPhase::Quarantined;
            LifetimeError::BookkeepingOverflow
        })?;
        Ok(())
    }

    pub(crate) fn settle_scan(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        context.pending_scans = context
            .pending_scans
            .checked_sub(1)
            .ok_or(LifetimeError::UnbalancedRelease)?;
        Ok(())
    }

    /// One publication-surface arm (FunctionList, InterfaceList or
    /// Interface selection). Recorded while the context can still publish.
    pub(crate) fn record_publication(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        match context.phase {
            SlotPhase::Prepared | SlotPhase::Active => {}
            SlotPhase::Quarantined => return Err(LifetimeError::Quarantined),
            _ => {
                return Err(LifetimeError::UnexpectedPhase {
                    expected: "Prepared or Active",
                    actual: context.phase,
                });
            }
        }
        context.publication_arms = context.publication_arms.saturating_add(1);
        Ok(())
    }

    /// One useful controlled call. Calls execute only while attached.
    pub(crate) fn record_call(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        if context.phase != SlotPhase::Active {
            return Err(LifetimeError::UnexpectedPhase {
                expected: "Active",
                actual: context.phase,
            });
        }
        context.useful_calls = context.useful_calls.saturating_add(1);
        Ok(())
    }

    /// Bind one export site. The same context/binding retry reuses the
    /// exact descriptor; a distinct binding mints the next checked ordinal
    /// and charges one descriptor. New binds stop when admission closes.
    pub(crate) fn bind_export(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
        binding: ExportBinding,
    ) -> Result<u64, LifetimeError> {
        self.check_domain(domain)?;
        let retry = {
            let context = self.live(token)?;
            match context.phase {
                SlotPhase::Prepared | SlotPhase::Active => {}
                SlotPhase::Quarantined => return Err(LifetimeError::Quarantined),
                _ => return Err(LifetimeError::AdmissionClosed),
            }
            context
                .descriptors
                .iter()
                .find(|known| known.binding == binding)
                .map(|known| known.cookie)
        };
        if let Some(cookie) = retry {
            return Ok(cookie);
        }
        if self.charged_descriptors() >= self.max_descriptors() {
            return Err(LifetimeError::DescriptorExhausted);
        }
        let context = self.live_mut(token)?;
        let ordinal = context
            .site_high_water
            .checked_add(1)
            .filter(|next| *next <= MAX_SITE_ORDINAL)
            .ok_or(LifetimeError::SiteExhausted)?;
        let cookie = export_cookie(token, ordinal).expect("checked ordinal fits the cookie");
        context.site_high_water = ordinal;
        context.descriptors.push(LiveDescriptor {
            cookie,
            binding,
            links_closed: false,
        });
        Ok(cookie)
    }

    /// Close an export's links. The charge stays until deferred dispatch
    /// settles through [`Self::settle_export`].
    pub(crate) fn release_export(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
        cookie: u64,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        let descriptor = context
            .descriptors
            .iter_mut()
            .find(|known| known.cookie == cookie)
            .ok_or(LifetimeError::UnknownDescriptor)?;
        if descriptor.links_closed {
            return Err(LifetimeError::ExportAlreadyClosed);
        }
        descriptor.links_closed = true;
        Ok(())
    }

    /// Settle one export after its deferred dispatch completes. Links close
    /// first; settlement frees the charge.
    pub(crate) fn settle_export(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
        cookie: u64,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        let position = context
            .descriptors
            .iter()
            .position(|known| known.cookie == cookie)
            .ok_or(LifetimeError::UnknownDescriptor)?;
        if !context.descriptors[position].links_closed {
            return Err(LifetimeError::LinksStillOpen);
        }
        context.descriptors.remove(position);
        Ok(())
    }

    /// Close new entry admission for the exact token and return the owned
    /// retirement cursor. Return consumers stay attached; accepted work
    /// settles through the normal path.
    pub(crate) fn begin_retirement(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
    ) -> Result<LoaderRetirement, LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        match context.phase {
            SlotPhase::Active => {}
            SlotPhase::Quarantined => return Err(LifetimeError::PermanentQuarantine),
            _ => {
                return Err(LifetimeError::UnexpectedPhase {
                    expected: "Active",
                    actual: context.phase,
                });
            }
        }
        context.phase = SlotPhase::Closing;
        Ok(LoaderRetirement { domain, token })
    }

    /// Observe closed-and-zero: every accepted body and discovery-state
    /// lease has finished. Anything still held is honest Pending-equivalent
    /// evidence, never authority to proceed.
    pub(crate) fn observe_closed_zero(
        &mut self,
        retirement: &LoaderRetirement,
    ) -> Result<(), LifetimeError> {
        self.check_domain(retirement.domain)?;
        let context = self.live_mut(retirement.token)?;
        if context.phase != SlotPhase::Closing {
            return Err(LifetimeError::UnexpectedPhase {
                expected: "Closing",
                actual: context.phase,
            });
        }
        if context.short_refs != 0 || context.long_refs != 0 {
            return Err(LifetimeError::ProducersActive {
                short: context.short_refs,
                long: context.long_refs,
            });
        }
        context.phase = SlotPhase::ProducersQuiet;
        Ok(())
    }

    /// Sample the retained ring's exact producer position after the local
    /// proof. The fence is fixed once; a later snapshot never replaces it.
    pub(crate) fn sample_q(
        &mut self,
        retirement: &LoaderRetirement,
        fence_q: u64,
    ) -> Result<(), LifetimeError> {
        self.check_domain(retirement.domain)?;
        let context = self.live_mut(retirement.token)?;
        if context.fence_q.is_some() {
            return Err(LifetimeError::QAlreadyFixed);
        }
        if context.phase != SlotPhase::ProducersQuiet {
            return Err(LifetimeError::UnexpectedPhase {
                expected: "ProducersQuiet",
                actual: context.phase,
            });
        }
        context.fence_q = Some(fence_q);
        context.phase = SlotPhase::Draining;
        Ok(())
    }

    /// Drain the fixed prefix with the single consumer. Records beyond Q
    /// are ordinary continuing traffic; an already-advanced shared consumer
    /// completes the prefix and waits only for queued disposition.
    pub(crate) fn drain_prefix(
        &mut self,
        retirement: &LoaderRetirement,
        drain: ConsumerDrain,
    ) -> Result<PrefixOutcome, LifetimeError> {
        self.check_domain(retirement.domain)?;
        let context = self.live_mut(retirement.token)?;
        if context.phase != SlotPhase::Draining {
            return Err(LifetimeError::UnexpectedPhase {
                expected: "Draining",
                actual: context.phase,
            });
        }
        let fence_q = context.fence_q.expect("draining implies a fixed fence");
        if drain.consumer < fence_q {
            if drain.busy_before_q {
                return Ok(PrefixOutcome::Pending(PendingReason::ForeignBusy));
            }
            return Ok(PrefixOutcome::Pending(PendingReason::Draining));
        }
        context.prefix_complete = true;
        Ok(PrefixOutcome::PrefixComplete)
    }

    /// Mint the typed fence after close, closed-zero and Q sampling. Queue
    /// and scan disposition are the acknowledgement's business, not the
    /// mint's.
    pub(crate) fn mint_fence(
        &mut self,
        retirement: &LoaderRetirement,
    ) -> Result<LoaderRetirementFence, LifetimeError> {
        self.check_domain(retirement.domain)?;
        let context = self.live(retirement.token)?;
        if context.phase != SlotPhase::Draining {
            return Err(LifetimeError::UnexpectedPhase {
                expected: "Draining",
                actual: context.phase,
            });
        }
        Ok(LoaderRetirementFence {
            domain: retirement.domain,
            token: retirement.token,
            fence_q: context.fence_q.expect("draining implies a fixed fence"),
        })
    }

    /// Record return-link/config cleanup. Failure retains custody; a later
    /// success may still complete the retirement.
    pub(crate) fn record_link_cleanup(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
        success: bool,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        if context.phase != SlotPhase::Draining {
            return Err(LifetimeError::UnexpectedPhase {
                expected: "Draining",
                actual: context.phase,
            });
        }
        context.cleanup = Some(success);
        Ok(())
    }

    /// Acknowledge a same-domain fence after the fixed prefix drained, every
    /// queued reference and scan reached disposition, every descriptor
    /// settled and link cleanup succeeded. Success preserves the immutable
    /// historical fact and frees storage; anything else refuses with the
    /// exact outstanding custody. The fence is a borrowable receipt: retry
    /// is safe, and a second acknowledgement after reclamation finds a
    /// stale token, never the successor.
    pub(crate) fn ack_fence(
        &mut self,
        fence: &LoaderRetirementFence,
        drain: ConsumerDrain,
    ) -> Result<ReclaimedSlot, LifetimeError> {
        self.check_domain(fence.domain)?;
        let slot = fence.token.slot();
        let context = self.live(fence.token)?;
        if context.token != fence.token || context.fence_q != Some(fence.fence_q) {
            return Err(LifetimeError::StaleToken);
        }
        if context.phase != SlotPhase::Draining {
            return Err(LifetimeError::UnexpectedPhase {
                expected: "Draining",
                actual: context.phase,
            });
        }
        match context.cleanup {
            Some(true) => {}
            Some(false) => return Err(LifetimeError::CleanupFailed),
            None => return Err(LifetimeError::CleanupIncomplete),
        }
        if drain.consumer < fence.fence_q {
            if drain.busy_before_q {
                return Err(LifetimeError::ForeignBusyBeforeQ);
            }
            return Err(LifetimeError::DrainIncomplete {
                consumer: drain.consumer,
                fence_q: fence.fence_q,
            });
        }
        for queue in QueueKind::ALL {
            let count = context.queued[queue.index()];
            if count != 0 {
                return Err(LifetimeError::RecordsPending { queue, count });
            }
        }
        if context.pending_scans != 0 {
            return Err(LifetimeError::ScansPending(context.pending_scans));
        }
        if !context.descriptors.is_empty() {
            return Err(LifetimeError::DescriptorsPending(context.descriptors.len()));
        }
        let fact = HistoricalFact {
            token: context.token,
            publication_arms: context.publication_arms,
            useful_calls: context.useful_calls,
        };
        let generation = context.token.generation();
        self.history.push(fact);
        self.slots[usize::from(slot)] = Slot::Reclaimable { generation };
        Ok(ReclaimedSlot {
            slot,
            retired_generation: generation,
        })
    }

    /// L1 model-test seams. Each obeys the same domain/currency/phase rules
    /// it helps test; production drivers never call them. They stand in for
    /// states reachable only after billions of incarnations (exhaustion) or
    /// under native fault injection (counter overflow).
    pub(crate) fn inject_slot_generation(
        &mut self,
        domain: LifetimeDomain,
        slot: u8,
        generation: u32,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        match &mut self.slots[usize::from(slot)] {
            Slot::Free {
                generation: current,
            }
            | Slot::Reclaimable {
                generation: current,
            } => {
                if generation < *current {
                    return Err(LifetimeError::GenerationRollback);
                }
                *current = generation;
                Ok(())
            }
            Slot::Live(_) => Err(LifetimeError::StaleToken),
        }
    }

    pub(crate) fn inject_site_high_water(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
        high_water: u32,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        if high_water < context.site_high_water {
            return Err(LifetimeError::GenerationRollback);
        }
        context.site_high_water = high_water;
        Ok(())
    }

    pub(crate) fn inject_refs(
        &mut self,
        domain: LifetimeDomain,
        token: LoaderToken,
        short: u64,
        long: u64,
        queued: u64,
    ) -> Result<(), LifetimeError> {
        self.check_domain(domain)?;
        let context = self.live_mut(token)?;
        context.short_refs = short;
        context.long_refs = long;
        context.queued = [queued; 5];
        Ok(())
    }
}

/// Loader attach cookie: exactly the token. L2's BPF resolves it through
/// the token-keyed gate; old-format cookies never issue after the atomic
/// cutover and fail closed at lookup.
pub(crate) fn loader_attach_cookie(token: LoaderToken) -> u64 {
    token.bits()
}

pub(crate) fn decode_loader_cookie(cookie: u64) -> Option<LoaderToken> {
    LoaderToken::from_bits(cookie)
}

/// Dynamic export cookie: `(token << 24) | site_ordinal`. The 40-bit token
/// plus 24-bit ordinal fill exactly 64 bits.
pub(crate) fn export_cookie(token: LoaderToken, ordinal: u32) -> Option<u64> {
    if ordinal == 0 || ordinal > MAX_SITE_ORDINAL {
        return None;
    }
    Some((token.bits() << 24) | u64::from(ordinal))
}

pub(crate) fn decode_export_cookie(cookie: u64) -> Option<(LoaderToken, u32)> {
    let ordinal = (cookie & 0x00ff_ffff) as u32;
    if ordinal == 0 {
        return None;
    }
    Some((LoaderToken::from_bits(cookie >> 24)?, ordinal))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_registry() -> (LifetimeDomain, LifetimeRegistry) {
        let domain = LifetimeDomain::mint();
        let registry = LifetimeRegistry::new(domain, 4096).unwrap();
        (domain, registry)
    }

    fn binding(object: u64) -> ExportBinding {
        ExportBinding {
            view: ProcessViewId(7),
            object: PinnedObjectId(object as u32),
            file_offset: 0x2100,
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            abi: ElfAbi::Lp64,
        }
    }

    /// Drive one incarnation through useful work and full retirement. Each
    /// lifetime arms all three publication surfaces and completes exactly
    /// two useful calls, mirroring the G16 workload denominator.
    fn drive_lifetime(
        registry: &mut LifetimeRegistry,
        domain: LifetimeDomain,
        token: LoaderToken,
        fence_q: u64,
    ) -> ReclaimedSlot {
        registry.activate(domain, token).unwrap();
        for _ in 0..3 {
            registry.record_publication(domain, token).unwrap();
        }
        registry.record_call(domain, token).unwrap();
        registry.record_call(domain, token).unwrap();
        let cookie = registry.bind_export(domain, token, binding(9)).unwrap();
        registry.release_export(domain, token, cookie).unwrap();
        registry.settle_export(domain, token, cookie).unwrap();
        registry.acquire_short(domain, token).unwrap();
        registry.insert_state(domain, token).unwrap();
        registry.remove_state(domain, token, true).unwrap();
        registry.release_short(domain, token).unwrap();
        registry
            .collect_record(domain, token, QueueKind::Deferred)
            .unwrap();
        registry
            .dispose_record(domain, token, QueueKind::Deferred)
            .unwrap();
        registry.register_scan(domain, token).unwrap();
        registry.settle_scan(domain, token).unwrap();
        let retirement = registry.begin_retirement(domain, token).unwrap();
        assert_eq!(
            registry.acquire_short(domain, token),
            Err(LifetimeError::AdmissionClosed)
        );
        registry.observe_closed_zero(&retirement).unwrap();
        registry.sample_q(&retirement, fence_q).unwrap();
        assert_eq!(
            registry.sample_q(&retirement, fence_q + 1),
            Err(LifetimeError::QAlreadyFixed)
        );
        let drain = ConsumerDrain {
            consumer: fence_q,
            busy_before_q: false,
        };
        assert_eq!(
            registry.drain_prefix(&retirement, drain),
            Ok(PrefixOutcome::PrefixComplete)
        );
        let fence = registry.mint_fence(&retirement).unwrap();
        registry.record_link_cleanup(domain, token, true).unwrap();
        registry.ack_fence(&fence, drain).unwrap()
    }

    #[test]
    fn loader_token_bit_layout_is_exact_and_bounded() {
        assert_eq!(LoaderToken::new(1, 0).unwrap().bits(), 0x100);
        let token = LoaderToken::new(0x1234_5678, 0xab).unwrap();
        assert_eq!(token.bits(), 0x1234_5678ab);
        assert_eq!(token.generation(), 0x1234_5678);
        assert_eq!(token.slot(), 0xab);
        assert_eq!(LoaderToken::from_bits(token.bits()), Some(token));
        assert_eq!(LoaderToken::new(0, 7), None);
        assert_eq!(LoaderToken::from_bits(0), None);
        assert_eq!(LoaderToken::from_bits(5), None);
        assert_eq!(LoaderToken::from_bits(TOKEN_MAX + 1), None);
        let widest = LoaderToken::from_bits(TOKEN_MAX).unwrap();
        assert_eq!((widest.generation(), widest.slot()), (u32::MAX, u8::MAX));
        assert_eq!(loader_attach_cookie(token), token.bits());
        assert_eq!(decode_loader_cookie(token.bits()), Some(token));
        assert_eq!(decode_loader_cookie(0), None);
    }

    #[test]
    fn export_cookie_contract_fills_64_bits_exactly() {
        let token = LoaderToken::new(9, 3).unwrap();
        let cookie = export_cookie(token, 1).unwrap();
        assert_eq!(decode_export_cookie(cookie), Some((token, 1)));
        assert_eq!(export_cookie(token, 0), None);
        assert_eq!(export_cookie(token, MAX_SITE_ORDINAL + 1), None);
        assert_eq!(decode_export_cookie(0), None);
        assert_eq!(decode_export_cookie(token.bits() << 24), None);
        let widest = LoaderToken::from_bits(TOKEN_MAX).unwrap();
        assert_eq!(export_cookie(widest, MAX_SITE_ORDINAL), Some(u64::MAX));
        assert_eq!(
            decode_export_cookie(u64::MAX),
            Some((widest, MAX_SITE_ORDINAL))
        );
        assert_eq!(MAX_SITE_ORDINAL, 0x00ff_ffff);
    }

    #[test]
    fn model_slot_bound_matches_production_loader_and_budget_is_floored() {
        assert_eq!(
            MAX_LIFETIME_SLOTS,
            super::super::loader::MAX_LOADER_CONTEXTS
        );
        assert_eq!(
            LifetimeRegistry::new(LifetimeDomain::mint(), 0).unwrap_err(),
            LifetimeError::InvalidCeiling
        );
        let domain = LifetimeDomain::mint();
        assert_eq!(
            LifetimeRegistry::new(domain, 1).unwrap().max_descriptors(),
            0
        );
        assert_eq!(
            LifetimeRegistry::new(domain, 7).unwrap().max_descriptors(),
            3
        );
    }

    #[test]
    fn loader_lifetime_generation_reuses_storage_not_identity() {
        let (domain, mut registry) = fresh_registry();
        for generation in 1..=300u32 {
            let token = registry.prepare_new(domain).unwrap();
            assert_eq!(token, LoaderToken::new(generation, 0).unwrap());
            let receipt = drive_lifetime(&mut registry, domain, token, u64::from(generation) * 100);
            assert_eq!(receipt.slot(), 0);
            assert_eq!(receipt.retired_generation(), generation);
            assert_eq!(registry.charged_contexts(), 0);
        }
        assert_eq!(registry.history().len(), 300);
        for (index, fact) in registry.history().iter().enumerate() {
            assert_eq!(fact.token(), LoaderToken::new(index as u32 + 1, 0).unwrap());
            assert_eq!(fact.publication_arms(), 3);
            assert_eq!(fact.useful_calls(), 2);
        }
        // A 301st incarnation reuses slot 0 with a fresh identity while
        // every stale reference to retired generations refuses.
        let successor = registry.prepare_new(domain).unwrap();
        assert_eq!(successor.generation(), 301);
        registry.activate(domain, successor).unwrap();
        registry.record_call(domain, successor).unwrap();
        for generation in [1u32, 150, 300] {
            let stale = LoaderToken::new(generation, 0).unwrap();
            assert_eq!(registry.phase_of(stale), None);
            assert_eq!(
                registry.collect_record(domain, stale, QueueKind::Collected),
                Err(LifetimeError::StaleToken)
            );
            assert_eq!(
                registry.settle_scan(domain, stale),
                Err(LifetimeError::StaleToken)
            );
            assert_eq!(
                registry.bind_export(domain, stale, binding(9)),
                Err(LifetimeError::StaleToken)
            );
            assert_eq!(
                registry.record_call(domain, stale),
                Err(LifetimeError::StaleToken)
            );
        }
        assert_eq!(registry.phase_of(successor), Some(SlotPhase::Active));
    }

    #[test]
    fn loader_lifetime_retiring_slots_remain_charged() {
        let (domain, mut registry) = fresh_registry();
        let mut tokens = Vec::new();
        for _ in 0..MAX_LIFETIME_SLOTS {
            let token = registry.prepare_new(domain).unwrap();
            registry.activate(domain, token).unwrap();
            tokens.push(token);
        }
        assert_eq!(registry.charged_contexts(), 256);
        for token in tokens.iter().take(10) {
            registry.begin_retirement(domain, *token).unwrap();
        }
        assert_eq!(registry.charged_contexts(), 256);
        assert_eq!(
            registry.prepare_new(domain),
            Err(LifetimeError::CapacityExhausted)
        );
        // Retire one fully: its charge frees and the next incarnation
        // reuses the storage with a fresh generation.
        let token = tokens[0];
        let retirement = LoaderRetirement { domain, token };
        registry.observe_closed_zero(&retirement).unwrap();
        registry.sample_q(&retirement, 4096).unwrap();
        let drain = ConsumerDrain {
            consumer: 8192,
            busy_before_q: false,
        };
        assert_eq!(
            registry.drain_prefix(&retirement, drain),
            Ok(PrefixOutcome::PrefixComplete)
        );
        let fence = registry.mint_fence(&retirement).unwrap();
        registry.record_link_cleanup(domain, token, true).unwrap();
        let receipt = registry.ack_fence(&fence, drain).unwrap();
        assert_eq!(registry.charged_contexts(), 255);
        let successor = registry.prepare_new(domain).unwrap();
        assert_eq!(successor.slot(), receipt.slot());
        assert_eq!(successor.generation(), receipt.retired_generation() + 1);
        assert_eq!(registry.charged_contexts(), 256);
        assert_eq!(registry.history().len(), 1);
    }

    #[test]
    fn loader_lifetime_failed_prepare_burns_generation() {
        let (domain, mut registry) = fresh_registry();
        assert_eq!(
            registry.prepare_new_faulted(domain),
            Err(LifetimeError::InjectedPrepareFault {
                slot: 0,
                generation: 1
            })
        );
        assert_eq!(registry.slot_state(0), SlotView::Free { generation: 1 });
        assert_eq!(registry.charged_contexts(), 0);
        assert_eq!(registry.pending_charges(), 1);
        // The burned generation never incarnates: the next prepare skips it.
        let token = registry.prepare_new(domain).unwrap();
        assert_eq!(token, LoaderToken::new(2, 0).unwrap());
        // Exact-match cleanup frees the pending charge; a stale cleanup
        // never frees another attempt's custody.
        assert_eq!(
            registry.cleanup_pending(domain, 0, 9),
            Err(LifetimeError::PendingMismatch)
        );
        registry.cleanup_pending(domain, 0, 1).unwrap();
        assert_eq!(registry.pending_charges(), 0);
        assert_eq!(
            registry.cleanup_pending(domain, 0, 1),
            Err(LifetimeError::PendingMismatch)
        );
        registry.activate(domain, token).unwrap();
        registry.record_call(domain, token).unwrap();
        assert_eq!(registry.phase_of(token), Some(SlotPhase::Active));
    }

    #[test]
    fn loader_lifetime_faulted_prepare_under_full_budget_burns_without_charge() {
        let domain = LifetimeDomain::mint();
        let mut registry = LifetimeRegistry::new(domain, 6).unwrap();
        assert_eq!(registry.max_descriptors(), 3);
        for generation in 1..=3u32 {
            assert_eq!(
                registry.prepare_new_faulted(domain),
                Err(LifetimeError::InjectedPrepareFault {
                    slot: 0,
                    generation
                })
            );
        }
        assert_eq!(registry.pending_charges(), 3);
        assert_eq!(
            registry.prepare_new_faulted(domain),
            Err(LifetimeError::DescriptorExhausted)
        );
        assert_eq!(registry.slot_state(0), SlotView::Free { generation: 4 });
        assert_eq!(registry.pending_charges(), 3);
        registry.cleanup_pending(domain, 0, 2).unwrap();
        assert_eq!(registry.pending_charges(), 2);
    }

    #[test]
    fn loader_lifetime_site_and_generation_exhaustion_refuse() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        registry.activate(domain, token).unwrap();
        registry
            .inject_site_high_water(domain, token, MAX_SITE_ORDINAL - 1)
            .unwrap();
        let last = registry.bind_export(domain, token, binding(11)).unwrap();
        assert_eq!(decode_export_cookie(last), Some((token, MAX_SITE_ORDINAL)));
        assert_eq!(
            registry.bind_export(domain, token, binding(12)),
            Err(LifetimeError::SiteExhausted)
        );
        // A same-site retry reuses the exact descriptor without minting.
        assert_eq!(registry.bind_export(domain, token, binding(11)), Ok(last));
        assert_eq!(
            registry.inject_site_high_water(domain, token, 7),
            Err(LifetimeError::GenerationRollback)
        );

        let (domain, mut registry) = fresh_registry();
        for slot in 0..5u8 {
            registry
                .inject_slot_generation(domain, slot, u32::MAX - 1)
                .unwrap();
        }
        assert_eq!(
            registry.inject_slot_generation(domain, 0, 3),
            Err(LifetimeError::GenerationRollback)
        );
        // Slot 0 burns its final generation; the incarnation still works.
        let oldest = registry.prepare_new(domain).unwrap();
        assert_eq!(oldest, LoaderToken::new(u32::MAX, 0).unwrap());
        drive_lifetime(&mut registry, domain, oldest, 100);
        assert_eq!(registry.history().len(), 1);
        // The exhausted slot stays unavailable without wrap; others serve.
        let next = registry.prepare_new(domain).unwrap();
        assert_eq!(next, LoaderToken::new(u32::MAX, 1).unwrap());
        for slot in 2..=255u8 {
            registry
                .inject_slot_generation(domain, slot, u32::MAX)
                .unwrap();
        }
        assert_eq!(
            registry.prepare_new(domain),
            Err(LifetimeError::GenerationExhausted)
        );
        assert_eq!(
            registry.slot_state(0),
            SlotView::Reclaimable {
                generation: u32::MAX
            }
        );
        assert_eq!(
            registry.slot_state(255),
            SlotView::Free {
                generation: u32::MAX
            }
        );
    }

    #[test]
    fn loader_lifetime_foreign_domain_fence_refuses() {
        let (domain_a, mut registry_a) = fresh_registry();
        let (domain_b, mut registry_b) = fresh_registry();
        let token_a = registry_a.prepare_new(domain_a).unwrap();
        let token_b = registry_b.prepare_new(domain_b).unwrap();
        assert_eq!(token_a.bits(), token_b.bits());
        assert_eq!(registry_a.domain(), domain_a);
        assert_eq!(registry_b.domain(), domain_b);
        // Equal numeric tokens never cross domains, on any operation.
        assert_eq!(
            registry_a.prepare_new(domain_b),
            Err(LifetimeError::ForeignDomain)
        );
        assert_eq!(
            registry_b.activate(domain_a, token_b),
            Err(LifetimeError::ForeignDomain)
        );
        assert_eq!(
            registry_b.acquire_short(domain_a, token_b),
            Err(LifetimeError::ForeignDomain)
        );
        assert_eq!(
            registry_b.collect_record(domain_a, token_b, QueueKind::Pending),
            Err(LifetimeError::ForeignDomain)
        );
        assert_eq!(
            registry_b.begin_retirement(domain_a, token_b),
            Err(LifetimeError::ForeignDomain)
        );
        registry_a.activate(domain_a, token_a).unwrap();
        registry_b.activate(domain_b, token_b).unwrap();
        let retirement_a = registry_a.begin_retirement(domain_a, token_a).unwrap();
        registry_a.observe_closed_zero(&retirement_a).unwrap();
        registry_a.sample_q(&retirement_a, 512).unwrap();
        let fence_a = registry_a.mint_fence(&retirement_a).unwrap();
        let drain = ConsumerDrain {
            consumer: 512,
            busy_before_q: false,
        };
        assert_eq!(
            registry_b.ack_fence(&fence_a, drain),
            Err(LifetimeError::ForeignDomain)
        );
        // Each domain's own token still works; the foreign fence changed nothing.
        registry_b.record_call(domain_b, token_b).unwrap();
        registry_a
            .record_link_cleanup(domain_a, token_a, true)
            .unwrap();
        let receipt = registry_a.ack_fence(&fence_a, drain).unwrap();
        assert_eq!(receipt.retired_generation(), 1);
        assert_eq!(registry_b.phase_of(token_b), Some(SlotPhase::Active));
    }

    #[test]
    fn loader_lifetime_prefix_and_ack_wait_for_exact_custody() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        registry.activate(domain, token).unwrap();
        registry.acquire_short(domain, token).unwrap();
        let retirement = registry.begin_retirement(domain, token).unwrap();
        assert_eq!(
            registry.observe_closed_zero(&retirement),
            Err(LifetimeError::ProducersActive { short: 1, long: 0 })
        );
        registry.release_short(domain, token).unwrap();
        registry.observe_closed_zero(&retirement).unwrap();
        registry.sample_q(&retirement, 1000).unwrap();
        assert_eq!(
            registry.drain_prefix(
                &retirement,
                ConsumerDrain {
                    consumer: 100,
                    busy_before_q: false
                }
            ),
            Ok(PrefixOutcome::Pending(PendingReason::Draining))
        );
        assert_eq!(
            registry.drain_prefix(
                &retirement,
                ConsumerDrain {
                    consumer: 100,
                    busy_before_q: true
                }
            ),
            Ok(PrefixOutcome::Pending(PendingReason::ForeignBusy))
        );
        let fence = registry.mint_fence(&retirement).unwrap();
        let stalled = ConsumerDrain {
            consumer: 100,
            busy_before_q: false,
        };
        registry.record_link_cleanup(domain, token, true).unwrap();
        assert_eq!(
            registry.ack_fence(&fence, stalled),
            Err(LifetimeError::DrainIncomplete {
                consumer: 100,
                fence_q: 1000
            })
        );
        assert_eq!(
            registry.ack_fence(
                &fence,
                ConsumerDrain {
                    consumer: 100,
                    busy_before_q: true
                }
            ),
            Err(LifetimeError::ForeignBusyBeforeQ)
        );
        assert_eq!(registry.prefix_complete(token), Some(false));
        registry
            .collect_record(domain, token, QueueKind::TerminalBatch)
            .unwrap();
        registry.register_scan(domain, token).unwrap();
        let drained = ConsumerDrain {
            consumer: 1000,
            busy_before_q: false,
        };
        assert_eq!(
            registry.ack_fence(&fence, drained),
            Err(LifetimeError::RecordsPending {
                queue: QueueKind::TerminalBatch,
                count: 1
            })
        );
        registry
            .dispose_record(domain, token, QueueKind::TerminalBatch)
            .unwrap();
        assert_eq!(
            registry.ack_fence(&fence, drained),
            Err(LifetimeError::ScansPending(1))
        );
        registry.settle_scan(domain, token).unwrap();
        assert_eq!(
            registry.drain_prefix(&retirement, drained),
            Ok(PrefixOutcome::PrefixComplete)
        );
        assert_eq!(registry.prefix_complete(token), Some(true));
        registry.ack_fence(&fence, drained).unwrap();
        assert_eq!(registry.history().len(), 1);
    }

    #[test]
    fn loader_lifetime_cleanup_failure_retains_custody_until_success() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        registry.activate(domain, token).unwrap();
        let cookie = registry.bind_export(domain, token, binding(31)).unwrap();
        let retirement = registry.begin_retirement(domain, token).unwrap();
        registry.observe_closed_zero(&retirement).unwrap();
        registry.sample_q(&retirement, 64).unwrap();
        let fence = registry.mint_fence(&retirement).unwrap();
        let drain = ConsumerDrain {
            consumer: 64,
            busy_before_q: false,
        };
        assert_eq!(
            registry.ack_fence(&fence, drain),
            Err(LifetimeError::CleanupIncomplete)
        );
        registry.record_link_cleanup(domain, token, false).unwrap();
        assert_eq!(
            registry.ack_fence(&fence, drain),
            Err(LifetimeError::CleanupFailed)
        );
        assert_eq!(registry.charged_contexts(), 1);
        registry.record_link_cleanup(domain, token, true).unwrap();
        assert_eq!(
            registry.ack_fence(&fence, drain),
            Err(LifetimeError::DescriptorsPending(1))
        );
        registry.release_export(domain, token, cookie).unwrap();
        registry.settle_export(domain, token, cookie).unwrap();
        registry.ack_fence(&fence, drain).unwrap();
        assert_eq!(registry.charged_contexts(), 0);
    }

    #[test]
    fn loader_lifetime_failed_delete_and_overflow_quarantine_without_refund() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        registry.activate(domain, token).unwrap();
        assert_eq!(
            registry.insert_state(domain, token),
            Err(LifetimeError::MissingShortGuard)
        );
        registry.acquire_short(domain, token).unwrap();
        registry.insert_state(domain, token).unwrap();
        assert_eq!(
            registry.remove_state(domain, token, false),
            Err(LifetimeError::StateDeleteFailed)
        );
        assert_eq!(registry.phase_of(token), Some(SlotPhase::Quarantined));
        assert_eq!(
            registry.begin_retirement(domain, token),
            Err(LifetimeError::PermanentQuarantine)
        );
        assert_eq!(registry.charged_contexts(), 1);

        let other = registry.prepare_new(domain).unwrap();
        registry.activate(domain, other).unwrap();
        registry.inject_refs(domain, other, u64::MAX, 0, 0).unwrap();
        assert_eq!(
            registry.acquire_short(domain, other),
            Err(LifetimeError::BookkeepingOverflow)
        );
        assert_eq!(registry.phase_of(other), Some(SlotPhase::Quarantined));
        assert_eq!(registry.release_short(domain, other), Ok(()));
        assert_eq!(registry.release_short(domain, other), Ok(()));
    }

    #[test]
    fn loader_lifetime_releases_balance_exactly_and_cancel_frees_prepared() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        assert_eq!(
            registry.release_short(domain, token),
            Err(LifetimeError::UnbalancedRelease)
        );
        assert_eq!(
            registry.dispose_record(domain, token, QueueKind::Collected),
            Err(LifetimeError::UnbalancedRelease)
        );
        assert_eq!(
            registry.settle_scan(domain, token),
            Err(LifetimeError::UnbalancedRelease)
        );
        assert_eq!(
            registry.remove_state(domain, token, true),
            Err(LifetimeError::UnbalancedRelease)
        );
        registry.cancel_prepared(domain, token).unwrap();
        assert_eq!(
            registry.slot_state(token.slot()),
            SlotView::Free { generation: 1 }
        );
        assert_eq!(registry.charged_contexts(), 0);
        let successor = registry.prepare_new(domain).unwrap();
        assert_eq!(successor.generation(), 2);
        registry.activate(domain, successor).unwrap();
        assert_eq!(
            registry.cancel_prepared(domain, successor),
            Err(LifetimeError::UnexpectedPhase {
                expected: "Prepared",
                actual: SlotPhase::Active
            })
        );
    }

    #[test]
    fn loader_lifetime_cancel_prepared_preserves_short_guard_until_release() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        registry.acquire_short(domain, token).unwrap();

        assert_eq!(
            registry.cancel_prepared(domain, token),
            Err(LifetimeError::ProducersActive { short: 1, long: 0 })
        );
        assert_eq!(registry.phase_of(token), Some(SlotPhase::Prepared));
        assert_eq!(registry.charged_contexts(), 1);
        registry.release_short(domain, token).unwrap();
        registry.cancel_prepared(domain, token).unwrap();
        assert_eq!(registry.charged_contexts(), 0);
        let successor = registry.prepare_new(domain).unwrap();
        assert_eq!(successor.slot(), token.slot());
        assert_eq!(successor.generation(), 2);
    }

    #[test]
    fn loader_lifetime_cancel_prepared_preserves_long_lease_until_delete() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        registry.acquire_short(domain, token).unwrap();
        registry.insert_state(domain, token).unwrap();
        registry.release_short(domain, token).unwrap();

        assert_eq!(
            registry.cancel_prepared(domain, token),
            Err(LifetimeError::ProducersActive { short: 0, long: 1 })
        );
        assert_eq!(registry.phase_of(token), Some(SlotPhase::Prepared));
        assert_eq!(registry.charged_contexts(), 1);
        registry.remove_state(domain, token, true).unwrap();
        registry.cancel_prepared(domain, token).unwrap();
        assert_eq!(registry.charged_contexts(), 0);
        let successor = registry.prepare_new(domain).unwrap();
        assert_eq!(successor.slot(), token.slot());
        assert_eq!(successor.generation(), 2);
    }

    #[test]
    fn loader_lifetime_cancel_prepared_preserves_queued_debt_until_disposition() {
        for queue in QueueKind::ALL {
            let (domain, mut registry) = fresh_registry();
            let token = registry.prepare_new(domain).unwrap();
            registry.collect_record(domain, token, queue).unwrap();

            assert_eq!(
                registry.cancel_prepared(domain, token),
                Err(LifetimeError::RecordsPending { queue, count: 1 })
            );
            assert_eq!(registry.phase_of(token), Some(SlotPhase::Prepared));
            assert_eq!(registry.charged_contexts(), 1);
            registry.dispose_record(domain, token, queue).unwrap();
            registry.cancel_prepared(domain, token).unwrap();
            assert_eq!(registry.charged_contexts(), 0);
            let successor = registry.prepare_new(domain).unwrap();
            assert_eq!(successor.slot(), token.slot());
            assert_eq!(successor.generation(), 2);
        }
    }

    #[test]
    fn loader_lifetime_cancel_prepared_preserves_scan_debt_until_settlement() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        registry.register_scan(domain, token).unwrap();

        assert_eq!(
            registry.cancel_prepared(domain, token),
            Err(LifetimeError::ScansPending(1))
        );
        assert_eq!(registry.phase_of(token), Some(SlotPhase::Prepared));
        assert_eq!(registry.charged_contexts(), 1);
        registry.settle_scan(domain, token).unwrap();
        registry.cancel_prepared(domain, token).unwrap();
        assert_eq!(registry.charged_contexts(), 0);
        let successor = registry.prepare_new(domain).unwrap();
        assert_eq!(successor.slot(), token.slot());
        assert_eq!(successor.generation(), 2);
    }

    #[test]
    fn loader_lifetime_cancel_prepared_releases_staged_binding_without_debt() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        // Binding metadata may be staged before attachment; it does not
        // itself admit a callback, discovery state, record or scan.
        registry.bind_export(domain, token, binding(21)).unwrap();
        assert_eq!(registry.charged_descriptors(), 1);

        registry.cancel_prepared(domain, token).unwrap();
        assert_eq!(registry.charged_contexts(), 0);
        assert_eq!(registry.charged_descriptors(), 0);
        let successor = registry.prepare_new(domain).unwrap();
        assert_eq!(successor.slot(), token.slot());
        assert_eq!(successor.generation(), 2);
    }

    #[test]
    fn loader_lifetime_export_links_close_before_settlement() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        registry.activate(domain, token).unwrap();
        let cookie = registry.bind_export(domain, token, binding(21)).unwrap();
        assert_eq!(
            registry.settle_export(domain, token, cookie),
            Err(LifetimeError::LinksStillOpen)
        );
        assert_eq!(
            registry.release_export(domain, token, cookie + 1),
            Err(LifetimeError::UnknownDescriptor)
        );
        registry.release_export(domain, token, cookie).unwrap();
        assert_eq!(
            registry.release_export(domain, token, cookie),
            Err(LifetimeError::ExportAlreadyClosed)
        );
        assert_eq!(registry.charged_descriptors(), 1);
        registry.settle_export(domain, token, cookie).unwrap();
        assert_eq!(registry.charged_descriptors(), 0);
        assert_eq!(
            registry.settle_export(domain, token, cookie),
            Err(LifetimeError::UnknownDescriptor)
        );
    }

    #[test]
    fn loader_lifetime_binding_incarnation_scopes_real_tuples_per_token() {
        let (domain, mut registry) = fresh_registry();
        let token = registry.prepare_new(domain).unwrap();
        registry.activate(domain, token).unwrap();
        let base = ExportBinding {
            view: ProcessViewId(7),
            object: PinnedObjectId(9),
            file_offset: 0x2100,
            hook: SymbolFact {
                virtual_address: 0x2100,
                file_offset: 0x2100,
            },
            abi: ElfAbi::Lp64,
        };
        let first = registry.bind_export(domain, token, base).unwrap();
        assert_eq!(first, export_cookie(token, 1).unwrap());
        assert_eq!(registry.bind_export(domain, token, base), Ok(first));
        // Every field of the real tuple is significant: varying exactly
        // one mints a new descriptor with the next ordinal.
        let variants = [
            ExportBinding {
                view: ProcessViewId(8),
                ..base
            },
            ExportBinding {
                object: PinnedObjectId(10),
                ..base
            },
            ExportBinding {
                file_offset: 0x2200,
                ..base
            },
            ExportBinding {
                hook: SymbolFact {
                    virtual_address: 0x2200,
                    file_offset: 0x2200,
                },
                ..base
            },
            ExportBinding {
                abi: ElfAbi::Ilp32,
                ..base
            },
        ];
        let mut cookies = vec![first];
        for (index, variant) in variants.iter().enumerate() {
            let cookie = registry.bind_export(domain, token, *variant).unwrap();
            assert_eq!(cookie, export_cookie(token, index as u32 + 2).unwrap());
            cookies.push(cookie);
        }
        for cookie in cookies {
            registry.release_export(domain, token, cookie).unwrap();
            registry.settle_export(domain, token, cookie).unwrap();
        }
        // Bindings are scoped to the incarnation: the same tuple under the
        // successor mints ordinals from 1 again under the new token, while
        // the retired token refuses.
        let retirement = registry.begin_retirement(domain, token).unwrap();
        registry.observe_closed_zero(&retirement).unwrap();
        registry.sample_q(&retirement, 100).unwrap();
        let fence = registry.mint_fence(&retirement).unwrap();
        registry.record_link_cleanup(domain, token, true).unwrap();
        let drain = ConsumerDrain {
            consumer: 100,
            busy_before_q: false,
        };
        let receipt = registry.ack_fence(&fence, drain).unwrap();
        assert_eq!(receipt.retired_generation(), 1);
        let successor = registry.prepare_new(domain).unwrap();
        assert_eq!(successor, LoaderToken::new(2, 0).unwrap());
        registry.activate(domain, successor).unwrap();
        let rebound = registry.bind_export(domain, successor, base).unwrap();
        assert_eq!(rebound, export_cookie(successor, 1).unwrap());
        assert_ne!(rebound, first);
        assert_eq!(
            registry.bind_export(domain, token, base),
            Err(LifetimeError::StaleToken)
        );
    }
}
