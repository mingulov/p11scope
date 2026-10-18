//! SPDX-License-Identifier: GPL-3.0-or-later
//! Fixed resource bookkeeping. IDs and roles grant no semantic authority.
//!
//! The caller prepays this table's one allocation before construction. Each
//! physical membership moves its own charge into the table before insertion;
//! removing one role never releases a surviving sibling's storage charge.

use std::mem::size_of;

const ROLES: usize = 5;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Raw,
    H8Open,
    Model,
    H9Staged,
    Association,
}

impl Role {
    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RoleKey {
    pub(super) namespace: u64,
    pub(super) value: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ReservationId(u64);

impl std::fmt::Debug for ReservationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReservationId(<private>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    Full,
    Replay,
    Foreign,
}

struct Membership<C> {
    key: RoleKey,
    bytes: usize,
    charge: C,
}

struct Operation<C> {
    // At most one provisional reservation per role can later merge here.
    // Keeping these aliases makes an already owned provenance token stable.
    aliases: [Option<ReservationId>; ROLES],
    roles: [Option<Membership<C>>; ROLES],
}

pub(super) struct ReservationTable<C> {
    slots: Vec<Option<Operation<C>>>,
    next: u64,
    live: usize,
    bytes: usize,
    populations: [usize; ROLES],
}

impl<C> ReservationTable<C> {
    pub(super) fn allocation_bytes(capacity: usize) -> Option<usize> {
        capacity.checked_mul(size_of::<Option<Operation<C>>>())
    }

    pub(super) fn try_new(capacity: usize) -> Result<Self, std::collections::TryReserveError> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity)?;
        slots.resize_with(capacity, || None);
        Ok(Self {
            slots,
            next: 0,
            live: 0,
            bytes: 0,
            populations: [0; ROLES],
        })
    }

    pub(super) fn census(&self) -> usize {
        self.live
    }
    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(super) fn population(&self, role: Role) -> usize {
        self.populations[role.index()]
    }

    fn key_slot(&self, role: Role, key: RoleKey) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref().is_some_and(|operation| {
                operation.roles[role.index()]
                    .as_ref()
                    .is_some_and(|member| member.key == key)
            })
        })
    }

    fn id_slot(&self, id: ReservationId) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|operation| operation.aliases.contains(&Some(id)))
        })
    }

    pub(super) fn preflight(
        &self,
        role: Role,
        key: RoleKey,
        existing: Option<ReservationId>,
        bytes: usize,
    ) -> Result<(), Refusal> {
        if self.key_slot(role, key).is_some() {
            return Err(Refusal::Replay);
        }
        if self.bytes.checked_add(bytes).is_none() {
            return Err(Refusal::Full);
        }
        match existing {
            Some(id) => {
                let at = self.id_slot(id).ok_or(Refusal::Foreign)?;
                if self.slots[at].as_ref().unwrap().roles[role.index()].is_some() {
                    return Err(Refusal::Replay);
                }
            }
            None => {
                if self.live >= self.slots.len() || self.next.checked_add(1).is_none() {
                    return Err(Refusal::Full);
                }
            }
        }
        Ok(())
    }

    pub(super) fn insert(
        &mut self,
        role: Role,
        key: RoleKey,
        existing: Option<ReservationId>,
        bytes: usize,
        charge: C,
    ) -> Result<ReservationId, Refusal> {
        self.preflight(role, key, existing, bytes)?;
        let at = match existing {
            Some(id) => self.id_slot(id).expect("preflight retained the operation"),
            None => {
                let id = ReservationId(self.next + 1);
                let at = self
                    .slots
                    .iter()
                    .position(Option::is_none)
                    .expect("preflight retained a slot");
                let mut aliases = [None; ROLES];
                aliases[0] = Some(id);
                self.slots[at] = Some(Operation {
                    aliases,
                    roles: std::array::from_fn(|_| None),
                });
                self.next = id.0;
                self.live += 1;
                at
            }
        };
        let operation = self.slots[at].as_mut().unwrap();
        operation.roles[role.index()] = Some(Membership { key, bytes, charge });
        self.populations[role.index()] += 1;
        self.bytes += bytes;
        Ok(operation.aliases[0].unwrap())
    }

    pub(super) fn release(&mut self, role: Role, key: RoleKey) -> Option<(usize, C)> {
        let at = self.key_slot(role, key)?;
        let operation = self.slots[at].as_mut().unwrap();
        let member = operation.roles[role.index()].take().unwrap();
        self.bytes -= member.bytes;
        self.populations[role.index()] -= 1;
        if operation.roles.iter().all(Option::is_none) {
            self.slots[at] = None;
            self.live -= 1;
        }
        Some((member.bytes, member.charge))
    }

    /// Resource bookkeeping only. The enclosing journal must already own
    /// actual same-wire provenance before it may call this method.
    pub(super) fn merge(
        &mut self,
        left: ReservationId,
        right: ReservationId,
    ) -> Result<ReservationId, Refusal> {
        let left = self.id_slot(left).ok_or(Refusal::Foreign)?;
        let right = self.id_slot(right).ok_or(Refusal::Foreign)?;
        if left == right {
            return Ok(self.slots[left].as_ref().unwrap().aliases[0].unwrap());
        }
        let a = self.slots[left].as_ref().unwrap();
        let b = self.slots[right].as_ref().unwrap();
        if a.roles
            .iter()
            .zip(&b.roles)
            .any(|(a, b)| a.is_some() && b.is_some())
        {
            return Err(Refusal::Replay);
        }
        let aliases = a.aliases.iter().flatten().count() + b.aliases.iter().flatten().count();
        if aliases > ROLES {
            return Err(Refusal::Full);
        }
        // Every failure was checked before either original membership moves.
        let right = self.slots[right].take().unwrap();
        let left = self.slots[left].as_mut().unwrap();
        for alias in right.aliases.into_iter().flatten() {
            let slot = left.aliases.iter_mut().find(|slot| slot.is_none()).unwrap();
            *slot = Some(alias);
        }
        for (destination, source) in left.roles.iter_mut().zip(right.roles) {
            if source.is_some() {
                *destination = source;
            }
        }
        self.live -= 1;
        Ok(left.aliases[0].unwrap())
    }

    /// Atomically transfer a role. The old physical charge is returned rather
    /// than dropped: the caller releases it only after its old storage drops.
    pub(super) fn transfer(
        &mut self,
        from: Role,
        from_key: RoleKey,
        to: Role,
        to_key: RoleKey,
        bytes: usize,
        charge: C,
    ) -> Result<(ReservationId, usize, C), Refusal> {
        let at = self.key_slot(from, from_key).ok_or(Refusal::Foreign)?;
        let operation = self.slots[at].as_ref().unwrap();
        if from == to
            || self.key_slot(to, to_key).is_some()
            || operation.roles[to.index()].is_some()
        {
            return Err(Refusal::Replay);
        }
        let old_bytes = operation.roles[from.index()].as_ref().unwrap().bytes;
        let total = self
            .bytes
            .checked_sub(old_bytes)
            .and_then(|total| total.checked_add(bytes))
            .ok_or(Refusal::Full)?;
        let operation = self.slots[at].as_mut().unwrap();
        let old = operation.roles[from.index()].take().unwrap();
        operation.roles[to.index()] = Some(Membership {
            key: to_key,
            bytes,
            charge,
        });
        self.populations[from.index()] -= 1;
        self.populations[to.index()] += 1;
        self.bytes = total;
        Ok((operation.aliases[0].unwrap(), old.bytes, old.charge))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: u64) -> RoleKey {
        RoleKey {
            namespace: 7,
            value,
        }
    }

    #[test]
    fn resource_reservations_1024_same_operations_keep_five_physical_roles() {
        let mut table = ReservationTable::try_new(1_024).unwrap();
        let (_, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            for value in 1..=1_024 {
                let id = table.insert(Role::Raw, key(value), None, 1, ()).unwrap();
                for (role, bytes) in [
                    (Role::H8Open, 2),
                    (Role::Model, 3),
                    (Role::H9Staged, 4),
                    (Role::Association, 5),
                ] {
                    assert_eq!(table.insert(role, key(value), Some(id), bytes, ()), Ok(id));
                }
            }
        });
        assert_eq!((allocations, bytes), (0, 0));
        assert_eq!((table.census(), table.bytes()), (1_024, 15_360));
        let (_, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            assert_eq!(
                table.preflight(Role::Raw, key(1_025), None, 1),
                Err(Refusal::Full)
            );
        });
        assert_eq!((allocations, bytes), (0, 0));
        for value in 1..=1_024 {
            table.release(Role::H8Open, key(value)).unwrap();
        }
        assert_eq!((table.census(), table.bytes()), (1_024, 13_312));
        for role in [Role::Raw, Role::Model, Role::H9Staged, Role::Association] {
            for value in 1..=1_024 {
                table.release(role, key(value)).unwrap();
            }
        }
        assert_eq!((table.census(), table.bytes()), (0, 0));
    }

    #[test]
    fn resource_reservations_join_at_logical_limit_and_refuse_role_replay() {
        let mut table = ReservationTable::try_new(1).unwrap();
        let id = table.insert(Role::H8Open, key(1), None, 20, ()).unwrap();
        assert_eq!(table.preflight(Role::Model, key(99), Some(id), 30), Ok(()));
        table
            .insert(Role::Model, key(99), Some(id), 30, ())
            .unwrap();
        assert_eq!(
            table.insert(Role::Model, key(100), Some(id), 30, ()),
            Err(Refusal::Replay)
        );
        assert_eq!((table.census(), table.bytes()), (1, 50));
        table.release(Role::H8Open, key(1)).unwrap();
        assert_eq!((table.census(), table.bytes()), (1, 30));
        table.release(Role::Model, key(99)).unwrap();
        assert_eq!(
            table.insert(Role::Model, key(99), Some(id), 30, ()),
            Err(Refusal::Foreign)
        );
        let new = table.insert(Role::H8Open, key(1), None, 20, ()).unwrap();
        assert_ne!(new, id, "slot reuse cannot reuse reservation identities");
    }

    #[test]
    fn resource_reservations_proven_merge_preserves_aliases_and_physical_charges() {
        let mut table = ReservationTable::try_new(2).unwrap();
        let a = table.insert(Role::H8Open, key(1), None, 20, ()).unwrap();
        let b = table.insert(Role::H9Staged, key(2), None, 30, ()).unwrap();
        let merged = table.merge(a, b).unwrap();
        assert_eq!((table.census(), table.bytes()), (1, 50));
        assert_eq!(
            table.insert(Role::Model, key(3), Some(b), 40, ()),
            Ok(merged)
        );
        let c = table.insert(Role::H8Open, key(4), None, 10, ()).unwrap();
        assert_eq!(table.merge(merged, c), Err(Refusal::Replay));
        assert_eq!((table.census(), table.bytes()), (2, 100));
        table.release(Role::H8Open, key(1)).unwrap();
        assert_eq!((table.census(), table.bytes()), (2, 80));
        table.release(Role::H9Staged, key(2)).unwrap();
        table.release(Role::Model, key(3)).unwrap();
        assert_eq!((table.census(), table.bytes()), (1, 10));
    }

    #[test]
    fn resource_reservations_transfer_is_count_neutral_and_failure_preserves_source() {
        let mut table = ReservationTable::try_new(1).unwrap();
        let id = table.insert(Role::H9Staged, key(1), None, 40, ()).unwrap();
        let (same, old_bytes, ()) = table
            .transfer(Role::H9Staged, key(1), Role::Association, key(2), 50, ())
            .unwrap();
        assert_eq!((same, old_bytes), (id, 40));
        assert_eq!((table.census(), table.bytes()), (1, 50));
        assert_eq!(table.population(Role::H9Staged), 0);
        assert_eq!(table.population(Role::Association), 1);
        assert_eq!(
            table.transfer(Role::H9Staged, key(1), Role::Model, key(3), 60, ()),
            Err(Refusal::Foreign)
        );
        assert_eq!((table.census(), table.bytes()), (1, 50));
    }

    #[test]
    fn resource_reservations_table_has_one_exact_prepaid_allocation() {
        let expected = ReservationTable::<()>::allocation_bytes(1_024).unwrap();
        let (table, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            ReservationTable::<()>::try_new(1_024).unwrap()
        });
        assert_eq!((allocations, bytes), (1, expected));
        assert_eq!(table.slots.capacity(), 1_024);
    }

    #[test]
    fn resource_reservations_transfer_retains_old_physical_charge_until_drop() {
        struct Charge<'a> {
            live: &'a std::cell::Cell<usize>,
            bytes: usize,
        }
        impl Drop for Charge<'_> {
            fn drop(&mut self) {
                self.live.set(self.live.get() - self.bytes);
            }
        }
        let live = std::cell::Cell::new(0);
        let charge = |bytes| {
            live.set(live.get() + bytes);
            Charge { live: &live, bytes }
        };
        let mut table = ReservationTable::try_new(1).unwrap();
        let id = table
            .insert(Role::H9Staged, key(1), None, 40, charge(40))
            .unwrap();
        let (_, _, deferred) = table
            .transfer(
                Role::H9Staged,
                key(1),
                Role::Association,
                key(2),
                50,
                charge(50),
            )
            .unwrap();
        assert_eq!((table.census(), table.bytes(), live.get()), (1, 50, 90));
        assert!(matches!(
            table.insert(Role::Association, key(3), Some(id), 60, charge(60)),
            Err(Refusal::Replay)
        ));
        assert_eq!(
            live.get(),
            90,
            "a failed sibling role returns only its prospective charge"
        );
        drop(deferred);
        assert_eq!(
            live.get(),
            50,
            "the old physical copy decides when its charge ends"
        );
        drop(table);
        assert_eq!(live.get(), 0);
    }

    #[test]
    fn resource_reservations_exhaustion_and_byte_overflow_preserve_original_roles() {
        let mut table = ReservationTable::try_new(2).unwrap();
        let id = table
            .insert(Role::Raw, key(1), None, usize::MAX, ())
            .unwrap();
        assert_eq!(
            table.insert(Role::H8Open, key(1), Some(id), 1, ()),
            Err(Refusal::Full)
        );
        assert_eq!((table.census(), table.bytes()), (1, usize::MAX));
        table.next = u64::MAX;
        assert_eq!(
            table.insert(Role::Raw, key(2), None, 0, ()),
            Err(Refusal::Full)
        );
        assert_eq!(table.insert(Role::Model, key(1), Some(id), 0, ()), Ok(id));
        assert_eq!(table.population(Role::Raw), 1);
        assert_eq!(table.population(Role::Model), 1);
    }
}
