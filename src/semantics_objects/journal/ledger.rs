//! SPDX-License-Identifier: GPL-3.0-or-later
//! Capture resource reservations backed by the registry's existing pool.

use super::MAX_UNSETTLED_STAGED;
use super::reservations::{Refusal, ReservationId, ReservationTable, Role, RoleKey};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SEMANTIC_RESOURCE_LIMIT, SemanticResourceReserver,
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_LEDGER_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct LedgerGeneration(u64);

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
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                    last.checked_add(1)
                })
                .ok()
                .map(|last| LedgerGeneration(last + 1)),
            byte_limit: SEMANTIC_RESOURCE_LIMIT as u64,
        }
    }

    /// Whether staged charges hold real pool leases: a resource-backed
    /// ledger keeps every live staged charge through replay.
    pub(crate) fn has_reserver(&self) -> bool {
        self.reserver.is_some()
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
        table
            .insert(role, key, existing, bytes, charge)
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

    pub(crate) fn charge_model(&mut self, token: u64, bytes: u64) -> Result<(), LedgerRefusal> {
        self.charge_role(Role::Model, Self::key(token), None, bytes)
            .map(|_| ())
    }

    pub(crate) fn release_model(&mut self, token: u64) {
        self.release_role(Role::Model, Self::key(token));
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
    fn shared_ledger_actual_pool_holds_1024_operations_with_all_roles() {
        let pool = SemanticResourcePool::default();
        let baseline = pool.snapshot().charged_bytes;
        let mut ledger = StagingLedger::with_resources(pool.reserver());
        ledger.prepare_capacity().unwrap();
        let index = pool.snapshot().charged_bytes;
        let (_, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            for key in 1..=1_024 {
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
        assert_eq!((ledger.census(), ledger.charged_bytes()), (1_024, 15_360));
        let charged = pool.snapshot().charged_bytes;
        assert_eq!(
            charged,
            index + 15_360 + 5 * 1_024 * OWNED_ALLOCATION_PADDING
        );
        let (result, allocations, bytes) =
            crate::test_alloc::count_allocs_during(|| ledger.charge_h8open(1_025, 2));
        assert_eq!(result, Err(LedgerRefusal::Full));
        assert_eq!((allocations, bytes), (0, 0));
        assert_eq!(pool.snapshot().charged_bytes, charged);
        ledger.release_all_h8open();
        assert_eq!(ledger.census(), 1_024);
        assert_eq!(
            pool.snapshot().charged_bytes,
            charged - 1_024 * (2 + OWNED_ALLOCATION_PADDING)
        );
        drop(ledger);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }
}
