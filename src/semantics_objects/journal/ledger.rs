//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Capture resource reservations backed by the registry's existing pool.

use super::MAX_UNSETTLED_STAGED;
use super::reservations::{
    FreePopOutcome, LeafBudget, MintWalkCursor, Refusal, ReleaseRoleCursor, ReservationId,
    ReservationTable, Role, RoleKey, SingleReleaseCursor,
};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SEMANTIC_RESOURCE_LIMIT, SemanticResourceReserver,
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_LEDGER_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct LedgerGeneration(u64);

/// `Role::Model` namespace for deferred-origin charges (6.07b): the
/// origin ticket doubles as the pending-call charge key under
/// namespace 0, so deferred records charge here instead.
const DEFERRED_NAMESPACE: u64 = 1;

/// Resource provenance only. The private constructor retains the ledger's
/// nonrecycled generation as well as its private operation ID.
#[derive(Clone, Copy)]
pub(in crate::semantics_objects) struct ExistingReservation {
    generation: LedgerGeneration,
    id: ReservationId,
    raw_key: Option<RoleKey>,
}

impl std::fmt::Debug for ExistingReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExistingReservation(<private>)")
    }
}

impl ExistingReservation {
    /// Exact originally minted reservation identity, before any alias merge.
    /// This comparison creates no reservation or role membership.
    pub(super) fn same_reservation(&self, other: &Self) -> bool {
        self.generation == other.generation && self.id == other.id
    }
}

/// Returned only by a successful actual H9 membership insertion. A replay
/// may use it to prepay the association copy before the staged copy drops.
#[derive(Clone, Copy)]
pub(crate) struct StagedResourceOrigin {
    generation: LedgerGeneration,
    id: ReservationId,
    key: RoleKey,
}

/// One capture's move-only resource owner. The fixed table is paid before its
/// first allocation; each role also retains its own actual pool lease. Legacy
/// scalar-role methods allocate distinct operations. Only the same-wire bridge
/// may join roles under a previously minted private reservation ID.
pub(crate) struct StagingLedger {
    // Drop memberships/buffer before refunding the buffer's charge.
    table: Option<ReservationTable<Option<ResourceLease>>>,
    reserver: Option<SemanticResourceReserver>,
    table_storage: Option<ResourceLease>,
    next_keyassoc: u64,
    next_raw: u64,
    generation: Option<LedgerGeneration>,
    byte_limit: u64,
    // Resumable H8 void sweep: `Some` while a budgeted void still owns
    // slot/link work. No insert, merge or transfer may run until the
    // sweep completes (the machine defers collection meanwhile).
    h8_void: Option<ReleaseRoleCursor>,
}

/// Opaque cursor for one budgeted staged release: the disposal holds
/// it across credits until its head's chain unlink finishes.
pub(crate) struct LedgerReleaseCursor {
    inner: Option<SingleReleaseCursor<Option<ResourceLease>>>,
}

/// Resumable budgeted fallback-association mint: the preflight walk
/// debits head/inspect/next reads through the shared gate one leaf
/// per unit; the commit validates the walked ticket, rechecks the
/// byte limit, reserves the pool charge, pops a free slot and
/// inserts through the shared write path. The caller retains the
/// cursor (and its payload lease) until insert or refusal commits.
/// Refusals match the synchronous mint exactly; tickets never
/// recycle and refusals never consume one.
pub(crate) struct LedgerMintCursor {
    bytes: u64,
    bytes_usize: usize,
    ticket: u64,
    walk: MintWalkCursor,
    phase: LedgerMintPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LedgerMintPhase {
    Walk,
    Commit,
}

/// One budgeted mint step's outcome: `Yield` (call again with fresh
/// credit; nothing committed) or `Done` with the minted ticket or
/// the refusal.
pub(crate) enum MintStepOutcome {
    Yield,
    Done(Result<u64, LedgerRefusal>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LedgerRefusal {
    Full,
    ReplayRefused,
}

impl From<Refusal> for LedgerRefusal {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Full => Self::Full,
            Refusal::Replay | Refusal::Foreign => Self::ReplayRefused,
        }
    }
}

impl std::fmt::Debug for StagingLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagingLedger")
            .field("operations", &self.census())
            .field("bytes", &self.charged_bytes())
            .finish_non_exhaustive()
    }
}

impl StagingLedger {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::unallocated(None)
    }

    pub(crate) fn with_resources(reserver: SemanticResourceReserver) -> Self {
        Self::unallocated(Some(reserver))
    }

    fn unallocated(reserver: Option<SemanticResourceReserver>) -> Self {
        Self {
            table: None,
            reserver,
            table_storage: None,
            next_keyassoc: 0,
            next_raw: 0,
            generation: NEXT_LEDGER_GENERATION
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                    last.checked_add(1)
                })
                .ok()
                .map(|last| LedgerGeneration(last + 1)),
            byte_limit: SEMANTIC_RESOURCE_LIMIT as u64,
            h8_void: None,
        }
    }

    /// Whether staged charges hold real pool leases: a resource-backed
    /// ledger keeps every live staged charge through replay.
    pub(crate) fn has_reserver(&self) -> bool {
        self.reserver.is_some()
    }

    #[cfg(test)]
    pub(crate) fn roles_for_test(&self) -> [usize; 5] {
        [
            Role::Raw,
            Role::H8Open,
            Role::Model,
            Role::H9Staged,
            Role::Association,
        ]
        .map(|role| {
            self.table
                .as_ref()
                .map_or(0, |table| table.population(role))
        })
    }

    /// Test-only sum of retained H8 member bytes, measured before the
    /// void so the refund check cannot infer it from the post-void
    /// balance.
    #[cfg(test)]
    pub(crate) fn h8_bytes_for_test(&self) -> u64 {
        self.table
            .as_ref()
            .map_or(0, |table| table.role_bytes_for_test(Role::H8Open) as u64)
    }

    /// Test-only list of retained staged keys as (namespace, value):
    /// the high-occupancy twin finds the held head among them.
    #[cfg(test)]
    pub(crate) fn staged_keys_for_test(&self) -> Vec<(u64, u64)> {
        self.table.as_ref().map_or(Vec::new(), |table| {
            table
                .staged_keys_for_test()
                .iter()
                .map(|key| (key.namespace, key.value))
                .collect()
        })
    }

    /// Test-only bucket for a model token: brute-force colliding
    /// survivors around a staged head's bucket.
    #[cfg(test)]
    pub(crate) fn model_bucket_for_test(value: u64) -> usize {
        ReservationTable::<Option<ResourceLease>>::model_bucket_for_test(value)
    }

    /// Test-only bucket for a staged (namespace, value) key.
    #[cfg(test)]
    pub(crate) fn staged_bucket_for_test(namespace: u64, value: u64) -> usize {
        ReservationTable::<Option<ResourceLease>>::staged_bucket_for_test(namespace, value)
    }

    /// Test-only bucket for a fallback association ticket.
    #[cfg(test)]
    pub(crate) fn assoc_bucket_for_test(ticket: u64) -> usize {
        ReservationTable::<Option<ResourceLease>>::assoc_bucket_for_test(ticket)
    }

    /// Test-only read of the lookup cost counter.
    #[cfg(test)]
    pub(crate) fn test_slot_visits_for_test(&self) -> usize {
        self.table
            .as_ref()
            .map_or(0, |table| table.test_slot_visits_for_test())
    }

    /// Test-only reset of the lookup cost counter.
    #[cfg(test)]
    pub(crate) fn reset_test_slot_visits_for_test(&self) {
        if let Some(table) = self.table.as_ref() {
            table.reset_test_slot_visits_for_test();
        }
    }

    /// Test-only read of the unified budgeted-leaf counter.
    #[cfg(test)]
    pub(crate) fn test_leaf_reads_for_test(&self) -> usize {
        self.table
            .as_ref()
            .map_or(0, |table| table.test_leaf_reads_for_test())
    }

    /// Test-only reset of the unified budgeted-leaf counter.
    #[cfg(test)]
    pub(crate) fn reset_test_leaf_reads_for_test(&self) {
        if let Some(table) = self.table.as_ref() {
            table.reset_test_leaf_reads_for_test();
        }
    }

    /// Test-only read of the sync-walk counter.
    #[cfg(test)]
    pub(crate) fn test_preflight_reads_for_test(&self) -> usize {
        self.table
            .as_ref()
            .map_or(0, |table| table.test_preflight_reads_for_test())
    }

    /// Test-only reset of the sync-walk counter.
    #[cfg(test)]
    pub(crate) fn reset_test_preflight_reads_for_test(&self) {
        if let Some(table) = self.table.as_ref() {
            table.reset_test_preflight_reads_for_test();
        }
    }

    /// Audit custody uses this ledger's existing pool, never a supplied budget.
    pub(super) fn resource_reserver(&self) -> Option<&SemanticResourceReserver> {
        self.reserver.as_ref()
    }

    pub(crate) fn prepare_capacity(&mut self) -> Result<(), LedgerRefusal> {
        if self.table.is_some() {
            return Ok(());
        }
        let bytes =
            ReservationTable::<Option<ResourceLease>>::allocation_bytes(MAX_UNSETTLED_STAGED)
                .and_then(|bytes| bytes.checked_add(OWNED_ALLOCATION_PADDING))
                .ok_or(LedgerRefusal::Full)?;
        let storage = match &self.reserver {
            Some(reserver) => Some(reserver.reserve(bytes).map_err(|_| LedgerRefusal::Full)?),
            None => {
                #[cfg(not(test))]
                return Err(LedgerRefusal::Full);
                #[cfg(test)]
                None
            }
        };
        let table =
            ReservationTable::try_new(MAX_UNSETTLED_STAGED).map_err(|_| LedgerRefusal::Full)?;
        self.table = Some(table);
        self.table_storage = storage;
        Ok(())
    }

    pub(crate) fn census(&self) -> usize {
        self.table.as_ref().map_or(0, ReservationTable::census)
    }

    /// Reservations this ledger can still mint before its fixed table is
    /// full. Scheduling only: every charge still preflights its own slot.
    pub(crate) fn reservation_room(&self) -> usize {
        MAX_UNSETTLED_STAGED.saturating_sub(self.census())
    }

    /// Test-only free-list length: listed vacancies plus live census
    /// always cover the table. A refused mint must leave this
    /// unchanged (no slot lost on the refusal path).
    #[cfg(test)]
    pub(crate) fn free_list_len_for_test(&self) -> usize {
        self.table
            .as_ref()
            .map_or(0, |table| table.free_list_len_for_test())
    }

    fn key(value: u64) -> RoleKey {
        RoleKey {
            namespace: 0,
            value,
        }
    }

    fn charge_role(
        &mut self,
        role: Role,
        key: RoleKey,
        existing: Option<ReservationId>,
        bytes: u64,
    ) -> Result<ReservationId, LedgerRefusal> {
        self.charge_role_with_credit(role, key, existing, bytes, 0)
    }

    fn charge_role_with_credit(
        &mut self,
        role: Role,
        key: RoleKey,
        existing: Option<ReservationId>,
        bytes: u64,
        credit: u64,
    ) -> Result<ReservationId, LedgerRefusal> {
        let total = self
            .charged_bytes()
            .saturating_sub(credit)
            .checked_add(bytes)
            .ok_or(LedgerRefusal::Full)?;
        if total > self.byte_limit {
            return Err(LedgerRefusal::Full);
        }
        if existing.is_some() && self.table.is_none() {
            return Err(LedgerRefusal::ReplayRefused);
        }
        self.prepare_capacity()?;
        let bytes = usize::try_from(bytes).map_err(|_| LedgerRefusal::Full)?;
        let table = self.table.as_mut().unwrap();
        table.preflight(role, key, existing, bytes)?;
        // The prospective copy's budget is obtained before its owner inserts
        // storage. Refusal preserves every existing role and physical lease.
        let charge = match &self.reserver {
            Some(reserver) => Some(
                reserver
                    .reserve(
                        bytes
                            .checked_add(OWNED_ALLOCATION_PADDING)
                            .ok_or(LedgerRefusal::Full)?,
                    )
                    .map_err(|_| LedgerRefusal::Full)?,
            ),
            None => None, // Only cfg(test) construction permits an unbound table.
        };
        // Synchronous charge path: the preflight above passed with
        // no yield or table mutation between, so the prechecked
        // insert's expects hold (no second preflight walks).
        table
            .insert_prechecked(role, key, existing, bytes, charge)
            .map_err(Into::into)
    }

    pub(super) fn reserve_raw(
        &mut self,
        producers: &crate::attach::SessionDrainProducers,
    ) -> Result<ExistingReservation, LedgerRefusal> {
        let generation = self.generation.ok_or(LedgerRefusal::Full)?;
        let next = self.next_raw.checked_add(1).ok_or(LedgerRefusal::Full)?;
        let raw_key = RoleKey {
            namespace: producers.native_domain().journal_tag(),
            value: next,
        };
        let id = self.charge_role(Role::Raw, raw_key, None, 0)?;
        self.next_raw = next;
        Ok(ExistingReservation {
            generation,
            id,
            raw_key: Some(raw_key),
        })
    }

    pub(super) fn matches_reservation(&self, reservation: &ExistingReservation) -> bool {
        self.generation == Some(reservation.generation)
    }

    /// Present resource state only: neither a positive grant nor proof of
    /// why ingestion declined the original. All five roles and merged IDs
    /// must have released this actual generation's minted operation.
    pub(super) fn original_is_released(&self, reservation: &ExistingReservation) -> bool {
        self.matches_reservation(reservation)
            && self
                .table
                .as_ref()
                .is_some_and(|table| table.reservation_is_released(reservation.id))
    }

    pub(super) fn generation(&self) -> Option<LedgerGeneration> {
        self.generation
    }

    pub(super) fn release_raw(&mut self, reservation: &ExistingReservation) {
        if self.matches_reservation(reservation)
            && let Some(key) = reservation.raw_key
        {
            self.release_role(Role::Raw, key);
        }
    }

    fn checked_existing(
        &self,
        reservation: &ExistingReservation,
    ) -> Result<ReservationId, LedgerRefusal> {
        self.matches_reservation(reservation)
            .then_some(reservation.id)
            .ok_or(LedgerRefusal::ReplayRefused)
    }

    pub(super) fn charge_h8open_from_raw(
        &mut self,
        ordinal: u64,
        bytes: u64,
        reservation: &ExistingReservation,
    ) -> Result<(), LedgerRefusal> {
        let id = self.checked_existing(reservation)?;
        self.charge_role(Role::H8Open, Self::key(ordinal), Some(id), bytes)
            .map(|_| ())
    }

    pub(super) fn h8_reservation(&self, ordinal: u64) -> Option<ExistingReservation> {
        Some(ExistingReservation {
            generation: self.generation?,
            id: self
                .table
                .as_ref()?
                .reservation(Role::H8Open, Self::key(ordinal))?,
            raw_key: None,
        })
    }

    pub(super) fn matches_unconverted_original(
        &self,
        begin: u64,
        original: &ExistingReservation,
        staged: Option<(u64, u64)>,
    ) -> bool {
        self.matches_reservation(original)
            && self.table.as_ref().is_some_and(|table| {
                table.unconverted_original(
                    Self::key(begin),
                    original.id,
                    staged.map(|(namespace, value)| RoleKey { namespace, value }),
                )
            })
    }

    #[cfg(test)]
    pub(super) fn h8_open_bytes_for_test(&self, begin: u64) -> Option<usize> {
        self.table
            .as_ref()?
            .member_bytes(Role::H8Open, Self::key(begin))
    }

    pub(super) fn matches_completed_staging(
        &self,
        begin_ordinal: u64,
        domain: u64,
        admission: u64,
        staged: &StagedResourceOrigin,
    ) -> bool {
        self.generation == Some(staged.generation)
            && staged.key
                == (RoleKey {
                    namespace: domain,
                    value: admission,
                })
            && self.table.as_ref().is_some_and(|table| {
                table.unconverted_staging(Self::key(begin_ordinal), staged.key, staged.id)
            })
    }

    pub(in crate::semantics_objects) fn charge_model_from_open(
        &mut self,
        token: u64,
        bytes: u64,
        reservation: &ExistingReservation,
    ) -> Result<(), LedgerRefusal> {
        let id = self.checked_existing(reservation)?;
        self.charge_role(Role::Model, Self::key(token), Some(id), bytes)
            .map(|_| ())
    }

    fn release_role(&mut self, role: Role, key: RoleKey) {
        if let Some(table) = self.table.as_mut() {
            drop(table.release(role, key));
        }
    }

    pub(crate) fn charge(&mut self, ticket: u64, bytes: u64) -> Result<(), LedgerRefusal> {
        self.charge_role(Role::H9Staged, Self::key(ticket), None, bytes)
            .map(|_| ())
    }

    pub(crate) fn charge_collected(
        &mut self,
        native: crate::attach::capture::NativeDomainId,
        ticket: u64,
        bytes: u64,
        origin: Option<&super::joint_driver::JointResourceOrigin>,
    ) -> Result<StagedResourceOrigin, LedgerRefusal> {
        let generation = self.generation.ok_or(LedgerRefusal::Full)?;
        let existing = match origin {
            Some(origin) => {
                if !origin.matches_native(native) {
                    return Err(LedgerRefusal::ReplayRefused);
                }
                Some(self.checked_existing(origin.reservation())?)
            }
            None => None,
        };
        let key = RoleKey {
            namespace: native.journal_tag(),
            value: ticket,
        };
        self.charge_role(Role::H9Staged, key, existing, bytes)
            .map(|id| StagedResourceOrigin {
                generation,
                id,
                key,
            })
    }

    pub(crate) fn release_collected(
        &mut self,
        native: crate::attach::capture::NativeDomainId,
        ticket: u64,
    ) {
        self.release_role(
            Role::H9Staged,
            RoleKey {
                namespace: native.journal_tag(),
                value: ticket,
            },
        );
    }

    pub(crate) fn release(&mut self, ticket: u64, _bytes: u64) {
        self.release_role(Role::H9Staged, Self::key(ticket));
    }

    /// Initial cursor for a collected staged release (native tag plus
    /// ticket). Empty ledgers hold no work and complete at once.
    pub(crate) fn release_cursor_collected(
        &self,
        native: crate::attach::capture::NativeDomainId,
        ticket: u64,
    ) -> LedgerReleaseCursor {
        let inner = self.table.as_ref().map(|table| {
            table.single_release_cursor(
                Role::H9Staged,
                RoleKey {
                    namespace: native.journal_tag(),
                    value: ticket,
                },
            )
        });
        LedgerReleaseCursor { inner }
    }

    /// Initial cursor for a plain staged release (namespace zero).
    /// Empty ledgers hold no work and complete at once.
    pub(crate) fn release_cursor(&self, ticket: u64) -> LedgerReleaseCursor {
        let inner = self
            .table
            .as_ref()
            .map(|table| table.single_release_cursor(Role::H9Staged, Self::key(ticket)));
        LedgerReleaseCursor { inner }
    }

    /// Initial cursor for one budgeted association release (fallback
    /// ledger chain reads during disposal invalidation). Empty
    /// ledgers hold no work and complete at once. Driven by the same
    /// [`Self::release_step`] gate as staged releases.
    pub(crate) fn release_assoc_cursor(&self, ticket: u64) -> LedgerReleaseCursor {
        let inner = self
            .table
            .as_ref()
            .map(|table| table.single_release_cursor(Role::Association, Self::key(ticket)));
        LedgerReleaseCursor { inner }
    }

    /// Drive one budgeted release (staged or association) through
    /// the shared pre-debit `gate`. Returns whether the release
    /// completed and, on completion, the removed bytes and charge when
    /// a membership was found. The caller RETAINS the returned charge
    /// until its payload drops (drop-then-refund): dropping it at
    /// unlink completion would refund the pool while the staged
    /// payload still lives. A missing key completes with `None`.
    pub(crate) fn release_step(
        &mut self,
        cursor: &mut LedgerReleaseCursor,
        gate: &mut LeafBudget,
    ) -> (bool, Option<(usize, Option<ResourceLease>)>) {
        let Some(inner) = cursor.inner.as_mut() else {
            return (true, None);
        };
        let Some(table) = self.table.as_mut() else {
            cursor.inner = None;
            return (true, None);
        };
        let (done, result) = table.release_single_step(inner, gate);
        if done {
            cursor.inner = None;
            (true, result)
        } else {
            debug_assert!(result.is_none());
            (false, None)
        }
    }

    /// Start one budgeted association mint for `bytes`: pure admission
    /// checks (byte limit, table fullness, ticket exhaustion, following
    /// the synchronous mint's order) and the preflight walk cursor for
    /// the next ticket. A missing table refuses Full (its prepare
    /// refused earlier — like the synchronous mint, which prepares
    /// inside charge and refuses when that fails).
    pub(crate) fn start_keyassoc_mint(
        &self,
        bytes: u64,
    ) -> Result<LedgerMintCursor, LedgerRefusal> {
        let total = self
            .charged_bytes()
            .checked_add(bytes)
            .ok_or(LedgerRefusal::Full)?;
        if total > self.byte_limit {
            return Err(LedgerRefusal::Full);
        }
        let bytes_usize = usize::try_from(bytes).map_err(|_| LedgerRefusal::Full)?;
        let Some(table) = self.table.as_ref() else {
            return Err(LedgerRefusal::Full);
        };
        if table.census() >= MAX_UNSETTLED_STAGED {
            return Err(LedgerRefusal::Full);
        }
        let ticket = self
            .next_keyassoc
            .checked_add(1)
            .ok_or(LedgerRefusal::Full)?;
        let walk = table.mint_walk_cursor(Role::Association, Self::key(ticket));
        Ok(LedgerMintCursor {
            bytes,
            bytes_usize,
            ticket,
            walk,
            phase: LedgerMintPhase::Walk,
        })
    }

    /// Restart a mint's walk with a fresh ticket after an interleaved
    /// mint took the walked one (fresh tickets cannot collide without
    /// interleave, so a hit restarts instead of refusing: the mint
    /// linearizes after the interleaved one, like a later synchronous
    /// mint). Re-runs the admission checks; their refusal ends the
    /// mint without consuming a ticket.
    fn restart_keyassoc_mint(&self, cursor: &mut LedgerMintCursor) -> Result<(), LedgerRefusal> {
        let fresh = self.start_keyassoc_mint(cursor.bytes)?;
        cursor.ticket = fresh.ticket;
        cursor.walk = fresh.walk;
        cursor.phase = LedgerMintPhase::Walk;
        Ok(())
    }

    /// Drive one budgeted mint step through the shared pre-debit
    /// `gate`: the walk first (one leaf per head/inspect/next read),
    /// then the commit (ticket validation, byte-limit recheck, pool
    /// reserve, free pop, insert). Yields without advancing past a
    /// refused leaf; the caller retains the cursor (and its payload
    /// lease) until `Done`. A refused free-pop charge yields with the
    /// walk-miss retained (no re-walk).
    pub(crate) fn mint_step(
        &mut self,
        cursor: &mut LedgerMintCursor,
        gate: &mut LeafBudget,
    ) -> MintStepOutcome {
        loop {
            match cursor.phase {
                LedgerMintPhase::Walk => {
                    let Some(table) = self.table.as_ref() else {
                        return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                    };
                    match table.mint_walk_step(&mut cursor.walk, gate) {
                        None => return MintStepOutcome::Yield,
                        Some(true) => {
                            cursor.phase = LedgerMintPhase::Commit;
                        }
                        Some(false) => {
                            if self.restart_keyassoc_mint(cursor).is_err() {
                                return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                            }
                        }
                    }
                }
                LedgerMintPhase::Commit => {
                    if self.next_keyassoc.checked_add(1) != Some(cursor.ticket) {
                        if self.restart_keyassoc_mint(cursor).is_err() {
                            return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                        }
                        continue;
                    }
                    if self
                        .charged_bytes()
                        .checked_add(cursor.bytes)
                        .is_none_or(|total| total > self.byte_limit)
                    {
                        return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                    }
                    let Some(table) = self.table.as_mut() else {
                        return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                    };
                    if table.census() >= MAX_UNSETTLED_STAGED {
                        return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                    }
                    let slot = match table.budgeted_free_pop(gate) {
                        FreePopOutcome::Yield => return MintStepOutcome::Yield,
                        FreePopOutcome::Full => {
                            return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                        }
                        FreePopOutcome::Slot(at) => at,
                    };
                    let lease_bytes = cursor
                        .bytes_usize
                        .checked_add(OWNED_ALLOCATION_PADDING)
                        .ok_or(LedgerRefusal::Full);
                    let Ok(lease_bytes) = lease_bytes else {
                        table.free_restore(slot);
                        return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                    };
                    let charge = match &self.reserver {
                        Some(reserver) => match reserver.reserve(lease_bytes) {
                            Ok(lease) => Some(lease),
                            Err(_) => {
                                table.free_restore(slot);
                                return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                            }
                        },
                        None => None,
                    };
                    // The slot stays popped across the reserve above:
                    // nothing else runs between, so the pop cannot go
                    // stale, and every refusal path above restores the
                    // exact vacancy. (A `Full` pop returned before
                    // reserving.)
                    let Some(table) = self.table.as_mut() else {
                        drop(charge);
                        return MintStepOutcome::Done(Err(LedgerRefusal::Full));
                    };
                    table.init_fresh_operation(slot);
                    table.attach_role_member(
                        Role::Association,
                        Self::key(cursor.ticket),
                        cursor.bytes_usize,
                        charge,
                        slot,
                    );
                    self.next_keyassoc = cursor.ticket;
                    return MintStepOutcome::Done(Ok(cursor.ticket));
                }
            }
        }
    }

    pub(crate) fn charge_h8open(&mut self, ordinal: u64, bytes: u64) -> Result<(), LedgerRefusal> {
        self.charge_role(Role::H8Open, Self::key(ordinal), None, bytes)
            .map(|_| ())
    }

    pub(crate) fn release_h8open(&mut self, ordinal: u64) {
        self.release_role(Role::H8Open, Self::key(ordinal));
    }

    pub(crate) fn release_all_h8open(&mut self) {
        if let Some(table) = self.table.as_mut() {
            table.release_role(Role::H8Open);
        }
    }

    /// Start the resumable H8 void sweep. Empty ledgers (no table or no
    /// H8 population) hold no sweep: `poll_h8_void` then completes at
    /// once with no work.
    pub(crate) fn start_h8_void(&mut self) {
        let needs = self
            .table
            .as_ref()
            .is_some_and(|table| table.population(Role::H8Open) > 0);
        self.h8_void = needs.then(ReleaseRoleCursor::new);
    }

    /// Drive the H8 void sweep through the shared pre-debit gate
    /// for at most `units` leaf units (slot visits plus chain-link
    /// reads). Returns whether the sweep completed and the units
    /// spent (never above `units`).
    pub(crate) fn poll_h8_void(&mut self, units: usize) -> (bool, usize) {
        use super::reservations::LeafBudget;
        let Some(cursor) = self.h8_void.as_mut() else {
            return (true, 0);
        };
        let Some(table) = self.table.as_mut() else {
            self.h8_void = None;
            return (true, 0);
        };
        let mut gate = LeafBudget::new(units);
        let done = table.release_role_step(Role::H8Open, cursor, &mut gate);
        let spent = gate.spent();
        debug_assert!(spent <= units);
        if done {
            self.h8_void = None;
        }
        (done, spent)
    }

    /// Whether a budgeted H8 void sweep still owns work.
    pub(crate) fn h8_void_pending(&self) -> bool {
        self.h8_void.is_some()
    }

    pub(crate) fn charge_model(&mut self, token: u64, bytes: u64) -> Result<(), LedgerRefusal> {
        self.charge_role(Role::Model, Self::key(token), None, bytes)
            .map(|_| ())
    }

    pub(crate) fn release_model(&mut self, token: u64) {
        self.release_role(Role::Model, Self::key(token));
    }

    /// Charge one deferred origin before its model insertion (6.07b
    /// §§2.2/3.8): keyed by origin ticket under a deferred namespace,
    /// so the charge never collides with the origin pending call's
    /// own Model charge and needs no ledger operation when the record
    /// moves pending→detached or across Join (same ticket).
    pub(crate) fn charge_deferred(&mut self, token: u64, bytes: u64) -> Result<(), LedgerRefusal> {
        self.charge_role(Role::Model, Self::deferred_key(token), None, bytes)
            .map(|_| ())
    }

    /// Release one deferred origin's charge at consume/loss. Tickets
    /// never recycle, so releasing an already-released ticket is a
    /// no-op, never a wrong refund.
    pub(crate) fn release_deferred(&mut self, token: u64) {
        self.release_role(Role::Model, Self::deferred_key(token));
    }

    fn deferred_key(value: u64) -> RoleKey {
        RoleKey {
            namespace: DEFERRED_NAMESPACE,
            value,
        }
    }

    pub(crate) fn mint_keyassoc(&mut self, bytes: u64) -> Result<u64, LedgerRefusal> {
        self.mint_keyassoc_from_stage(bytes, None)
    }

    /// `Some`-source callers must release the staged member right after the mint.
    pub(crate) fn mint_keyassoc_from_stage(
        &mut self,
        bytes: u64,
        source: Option<&StagedResourceOrigin>,
    ) -> Result<u64, LedgerRefusal> {
        let (existing, credit) = match source {
            Some(source) => {
                if self.generation != Some(source.generation)
                    || self
                        .table
                        .as_ref()
                        .and_then(|table| table.reservation(Role::H9Staged, source.key))
                        != Some(source.id)
                {
                    return Err(LedgerRefusal::ReplayRefused);
                }
                // The replayed association consumes the staged
                // custody it joins: credit the staged bytes the
                // replay releases right after this mint, so
                // at-capacity fallback replay accounts (N15). This
                // matches release-then-mint ordering exactly while
                // the staged reservation stays live for custody.
                let credit = self
                    .table
                    .as_ref()
                    .and_then(|table| table.member_bytes(Role::H9Staged, source.key))
                    .unwrap_or(0) as u64;
                (Some(source.id), credit)
            }
            None => (None, 0),
        };
        let ticket = self
            .next_keyassoc
            .checked_add(1)
            .ok_or(LedgerRefusal::Full)?;
        self.charge_role_with_credit(
            Role::Association,
            Self::key(ticket),
            existing,
            bytes,
            credit,
        )?;
        self.next_keyassoc = ticket;
        Ok(ticket)
    }

    pub(crate) fn release_keyassoc(&mut self, ticket: u64) {
        self.release_role(Role::Association, Self::key(ticket));
    }

    pub(crate) fn staged(&self) -> usize {
        self.table
            .as_ref()
            .map_or(0, |table| table.population(Role::H9Staged))
    }

    pub(crate) fn charged_bytes(&self) -> u64 {
        self.table.as_ref().map_or(0, |table| table.bytes() as u64)
    }

    #[cfg(test)]
    pub(crate) fn set_byte_limit(&mut self, limit: u64) {
        self.byte_limit = limit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantics_edge::resources::SemanticResourcePool;

    #[test]
    fn shared_ledger_released_original_keeps_generation_and_live_siblings_distinct() {
        let pool = SemanticResourcePool::default();
        let events = crate::events::EventsDomain::test_standin(0xf19a);
        let producers = crate::attach::SessionDrainProducers::test_pair(
            crate::attach::capture::NativeDomainId::mint(),
            events,
        );
        let mut ledger = StagingLedger::with_resources(pool.reserver());
        let original = ledger.reserve_raw(&producers).unwrap();
        assert!(!ledger.original_is_released(&original));
        ledger.charge_h8open_from_raw(1, 1, &original).unwrap();
        ledger.charge_model_from_open(1, 1, &original).unwrap();
        ledger.release_raw(&original);
        ledger.release_h8open(1);
        assert!(
            !ledger.original_is_released(&original),
            "the actual Model alias still owns custody"
        );
        ledger.charge_model(2, 1).unwrap();
        ledger.release_model(1);
        assert!(ledger.original_is_released(&original));
        assert_eq!(
            ledger.census(),
            1,
            "unrelated healthy Model custody must remain live"
        );
        let reused_slot = ledger.reserve_raw(&producers).unwrap();
        assert!(reused_slot.id != original.id);
        assert!(!ledger.original_is_released(&reused_slot));
        assert!(ledger.original_is_released(&original));
        let mut foreign = StagingLedger::with_resources(pool.reserver());
        let foreign_original = foreign.reserve_raw(&producers).unwrap();
        foreign.release_raw(&foreign_original);
        assert!(foreign.original_is_released(&foreign_original));
        assert!(!ledger.original_is_released(&foreign_original));
        assert!(!foreign.original_is_released(&original));
        ledger.release_raw(&reused_slot);
        assert!(ledger.original_is_released(&reused_slot));
        ledger.release_model(2);
        assert_eq!(ledger.census(), 0);
    }

    #[test]
    fn shared_ledger_pool_refuses_before_index_or_member_allocation() {
        let pool = SemanticResourcePool::default();
        let baseline = pool.snapshot().charged_bytes;
        pool.reference_set_limit(baseline);
        let mut ledger = StagingLedger::with_resources(pool.reserver());
        let (result, allocations, bytes) =
            crate::test_alloc::count_allocs_during(|| ledger.charge_h8open(1, 20));
        assert_eq!(result, Err(LedgerRefusal::Full));
        assert_eq!((allocations, bytes), (0, 0));
        assert_eq!(ledger.census(), 0);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn shared_ledger_actual_pool_retains_index_and_each_physical_role() {
        let pool = SemanticResourcePool::default();
        let baseline = pool.snapshot().charged_bytes;
        let mut ledger = StagingLedger::with_resources(pool.reserver());
        let (_, allocations, bytes) =
            crate::test_alloc::count_allocs_during(|| ledger.prepare_capacity().unwrap());
        assert_eq!(allocations, 1);
        let index = pool.snapshot().charged_bytes;
        assert_eq!(index, baseline + bytes + OWNED_ALLOCATION_PADDING);
        let (id, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            ledger
                .charge_role(Role::H8Open, StagingLedger::key(1), None, 20)
                .unwrap()
        });
        assert_eq!((allocations, bytes), (0, 0));
        ledger
            .charge_role(Role::Model, StagingLedger::key(1), Some(id), 30)
            .unwrap();
        assert_eq!(ledger.census(), 1);
        assert_eq!(
            pool.snapshot().charged_bytes,
            index + 50 + 2 * OWNED_ALLOCATION_PADDING
        );
        ledger.release_h8open(1);
        assert_eq!(ledger.census(), 1);
        assert_eq!(
            pool.snapshot().charged_bytes,
            index + 30 + OWNED_ALLOCATION_PADDING
        );
        ledger.release_model(1);
        assert_eq!(pool.snapshot().charged_bytes, index);
        drop(ledger);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn shared_ledger_actual_pool_holds_4096_operations_with_all_roles() {
        let pool = SemanticResourcePool::default();
        let baseline = pool.snapshot().charged_bytes;
        let mut ledger = StagingLedger::with_resources(pool.reserver());
        ledger.prepare_capacity().unwrap();
        let index = pool.snapshot().charged_bytes;
        let (_, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            for key in 1..=4_096 {
                let id = ledger
                    .charge_role(Role::Raw, StagingLedger::key(key), None, 1)
                    .unwrap();
                for (role, bytes) in [
                    (Role::H8Open, 2),
                    (Role::Model, 3),
                    (Role::H9Staged, 4),
                    (Role::Association, 5),
                ] {
                    ledger
                        .charge_role(role, StagingLedger::key(key), Some(id), bytes)
                        .unwrap();
                }
            }
        });
        assert_eq!((allocations, bytes), (0, 0));
        assert_eq!((ledger.census(), ledger.charged_bytes()), (4_096, 61_440));
        let charged = pool.snapshot().charged_bytes;
        assert_eq!(
            charged,
            index + 61_440 + 5 * 4_096 * OWNED_ALLOCATION_PADDING
        );
        let (result, allocations, bytes) =
            crate::test_alloc::count_allocs_during(|| ledger.charge_h8open(4_097, 2));
        assert_eq!(result, Err(LedgerRefusal::Full));
        assert_eq!((allocations, bytes), (0, 0));
        assert_eq!(pool.snapshot().charged_bytes, charged);
        ledger.release_all_h8open();
        assert_eq!(ledger.census(), 4_096);
        assert_eq!(
            pool.snapshot().charged_bytes,
            charged - 4_096 * (2 + OWNED_ALLOCATION_PADDING)
        );
        drop(ledger);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn shared_ledger_resumable_void_keeps_shared_model_and_merged_alias() {
        // One shared H8+Model operation, one merged H8+Model with two
        // aliases and one merged H8-only with two aliases (via a Raw
        // release): the resumable void driven one unit at a time
        // removes every H8 while preserving the Model siblings and
        // merged aliases with exact IDs, bytes and pool refund.
        let pool = SemanticResourcePool::default();
        let baseline = pool.snapshot().charged_bytes;
        let mut ledger = StagingLedger::with_resources(pool.reserver());
        ledger.prepare_capacity().unwrap();
        let index = pool.snapshot().charged_bytes;
        let shared = ledger
            .charge_role(Role::H8Open, StagingLedger::key(1), None, 10)
            .unwrap();
        ledger
            .charge_role(Role::Model, StagingLedger::key(1), Some(shared), 20)
            .unwrap();
        let merged_h8 = ledger
            .charge_role(Role::H8Open, StagingLedger::key(2), None, 10)
            .unwrap();
        let merged_model = ledger
            .charge_role(Role::Model, StagingLedger::key(3), None, 20)
            .unwrap();
        let merged_head = ledger
            .table
            .as_mut()
            .unwrap()
            .merge(merged_h8, merged_model)
            .unwrap();
        assert_eq!(merged_head, merged_h8);
        let vacating_h8 = ledger
            .charge_role(Role::H8Open, StagingLedger::key(4), None, 10)
            .unwrap();
        let vacating_raw = ledger
            .charge_role(Role::Raw, StagingLedger::key(5), None, 1)
            .unwrap();
        ledger
            .table
            .as_mut()
            .unwrap()
            .merge(vacating_h8, vacating_raw)
            .unwrap();
        ledger.release_role(Role::Raw, StagingLedger::key(5));
        for key in 100..110u64 {
            ledger
                .charge_role(Role::H8Open, StagingLedger::key(key), None, 10)
                .unwrap();
        }
        assert_eq!(ledger.roles_for_test()[1], 13);
        assert_eq!((ledger.census(), ledger.charged_bytes()), (13, 170));
        assert_eq!(
            pool.snapshot().charged_bytes,
            index + 170 + 15 * OWNED_ALLOCATION_PADDING
        );
        ledger.start_h8_void();
        assert!(ledger.h8_void_pending());
        let mut steps = 0;
        let mut saw_partial = false;
        loop {
            let (done, spent) = ledger.poll_h8_void(1);
            assert!(spent <= 1, "one-unit credit spent {spent}");
            steps += 1;
            if done {
                break;
            }
            saw_partial = true;
            assert!(steps < 20_000, "the void sweep must complete");
        }
        assert!(saw_partial, "one-unit credits must need several steps");
        assert!(!ledger.h8_void_pending());
        assert_eq!(ledger.roles_for_test()[1], 0);
        assert_eq!((ledger.census(), ledger.charged_bytes()), (2, 40));
        assert_eq!(
            pool.snapshot().charged_bytes,
            index + 40 + 2 * OWNED_ALLOCATION_PADDING,
            "one exact refund per removed H8 lease"
        );
        let table = ledger.table.as_ref().unwrap();
        assert_eq!(
            table.reservation(Role::Model, StagingLedger::key(1)),
            Some(shared)
        );
        assert_eq!(
            table.member_bytes(Role::Model, StagingLedger::key(1)),
            Some(20)
        );
        assert_eq!(table.reservation(Role::H8Open, StagingLedger::key(1)), None);
        assert_eq!(
            table.reservation(Role::Model, StagingLedger::key(3)),
            Some(merged_head)
        );
        assert_eq!(
            table.member_bytes(Role::Model, StagingLedger::key(3)),
            Some(20)
        );
        assert!(!table.reservation_is_released(merged_h8));
        assert!(!table.reservation_is_released(merged_model));
        assert!(table.reservation_is_released(vacating_h8));
        assert!(table.reservation_is_released(vacating_raw));
        assert_eq!(table.reservation(Role::H8Open, StagingLedger::key(4)), None);
        drop(ledger);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    /// A refused budgeted mint must not consume a vacancy: 4,096
    /// exact-fit pool refusals leave census zero and all vacancies
    /// usable, and the recovered pool mints the original ticket
    /// sequence without a sync-replay panic.
    #[test]
    fn refused_mint_restores_free_slot_across_storm() {
        let pool = SemanticResourcePool::default();
        let mut fallback = StagingLedger::with_resources(pool.reserver());
        fallback.prepare_capacity().unwrap();
        assert_eq!(fallback.census(), 0);
        assert_eq!(
            fallback.free_list_len_for_test(),
            MAX_UNSETTLED_STAGED,
            "a fresh table lists every vacancy"
        );
        pool.reference_set_limit(pool.snapshot().charged_bytes);
        let bytes = 16u64;
        for _ in 0..MAX_UNSETTLED_STAGED {
            let mut cursor = fallback
                .start_keyassoc_mint(bytes)
                .expect("admission passes; the pool refuses at commit");
            loop {
                let mut gate = LeafBudget::new(64);
                match fallback.mint_step(&mut cursor, &mut gate) {
                    MintStepOutcome::Yield => continue,
                    MintStepOutcome::Done(Err(_)) => break,
                    MintStepOutcome::Done(Ok(_)) => {
                        panic!("an exact-fit pool must refuse the mint")
                    }
                }
            }
            assert_eq!(fallback.census(), 0, "a refusal mints nothing");
        }
        assert_eq!(fallback.census(), 0);
        assert_eq!(
            fallback.free_list_len_for_test(),
            MAX_UNSETTLED_STAGED,
            "repeated refusals must not exhaust the free list"
        );
        pool.reference_set_limit(usize::MAX);
        for ticket in 1..=MAX_UNSETTLED_STAGED as u64 {
            let minted = fallback.mint_keyassoc(bytes).unwrap();
            assert_eq!(minted, ticket, "the original ticket sequence survives");
        }
        assert_eq!(fallback.census(), MAX_UNSETTLED_STAGED);
        assert_eq!(fallback.free_list_len_for_test(), 0);
    }
}
