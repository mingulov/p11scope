//! SPDX-License-Identifier: GPL-3.0-or-later
//! Fixed resource bookkeeping. IDs and roles grant no semantic authority.
//!
//! The caller prepays this table's one allocation before construction. Each
//! physical membership moves its own charge into the table before insertion;
//! removing one role never releases a surviving sibling's storage charge.

use std::mem::size_of;

const ROLES: usize = 5;

/// Intrusive-index capacity: the production staging table is indexed;
/// larger tables keep the linear scans. No table today exceeds this.
const MAX_INDEXED: usize = 1_024;
/// Chain buckets per index (the key and id indexes share the shape).
/// At most five memberships per slot over 1,024 slots hash here.
const INDEX_BUCKETS: usize = 1_024;
/// Empty chain head/link: outside the node-code range.
const INDEX_NONE: u16 = u16::MAX;
/// Link planes inside each slot: key chains and id chains.
const KEY_LINKS: usize = 0;
const ID_LINKS: usize = 1;

/// Chain-node code: `slot * ROLES + lane`. Slots below `MAX_INDEXED`
/// keep every code below 5,120.
fn node_code(slot: usize, lane: usize) -> u16 {
    debug_assert!(slot < MAX_INDEXED && lane < ROLES);
    (slot * ROLES + lane) as u16
}

fn node_slot(code: u16) -> usize {
    usize::from(code) / ROLES
}

fn node_lane(code: u16) -> usize {
    usize::from(code) % ROLES
}

/// Deterministic Fx-style hash for the intrusive index. The seed is
/// fixed, so chain shapes are stable across runs and the lookup bound
/// is a stable property, not luck.
fn index_hash(parts: &[u64]) -> u64 {
    const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
    let mut hash = SEED;
    for part in parts {
        hash = hash.wrapping_add(*part);
        hash = hash.rotate_left(5).wrapping_mul(SEED);
    }
    hash
}

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

    const ALL: [Role; ROLES] = [
        Role::Raw,
        Role::H8Open,
        Role::Model,
        Role::H9Staged,
        Role::Association,
    ];

    fn at(lane: usize) -> Role {
        Self::ALL[lane]
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

/// One table slot: the operation plus its intrusive-index links. The
/// links live in the prepaid slot allocation (not in the table
/// struct), so the index adds no stack pressure however the table is
/// held: construction chains already nest ~2 MB deep in debug builds.
struct TableSlot<C> {
    operation: Option<Operation<C>>,
    /// Chain links per (link plane, lane): meaningful while the slot
    /// is occupied (key plane per role lane, id plane per alias lane).
    next: [[u16; ROLES]; 2],
    /// Free-list link: meaningful only while the slot is vacant.
    free_next: u16,
}

impl<C> TableSlot<C> {
    fn vacant() -> Self {
        Self {
            operation: None,
            next: [[INDEX_NONE; ROLES]; 2],
            free_next: INDEX_NONE,
        }
    }
}

pub(super) struct ReservationTable<C> {
    slots: Vec<TableSlot<C>>,
    next: u64,
    live: usize,
    bytes: usize,
    populations: [usize; ROLES],
    /// Intrusive lookup index: hash-chain heads over the slot array.
    /// Heads stay inline (4 KiB); the links live inside the slots, so
    /// the table keeps its exact single prepaid allocation and adds
    /// negligible stack pressure. Chain nodes are (slot, lane) codes;
    /// every membership and alias is linked exactly while present.
    /// Tables past `MAX_INDEXED` ignore the index and keep the linear
    /// scans.
    key_heads: [u16; INDEX_BUCKETS],
    id_heads: [u16; INDEX_BUCKETS],
    /// Intrusive free list head: per-slot links live in the slots. A
    /// slot is listed exactly while vacant.
    free_head: u16,
    /// Test-only lookup cost counter: slot visits across
    /// `key_slot`, `id_slot` and free-slot searches.
    #[cfg(test)]
    test_slot_visits: std::cell::Cell<usize>,
}

impl<C> ReservationTable<C> {
    pub(super) fn allocation_bytes(capacity: usize) -> Option<usize> {
        capacity.checked_mul(size_of::<TableSlot<C>>())
    }

    pub(super) fn try_new(capacity: usize) -> Result<Self, std::collections::TryReserveError> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity)?;
        slots.resize_with(capacity, TableSlot::vacant);
        // The free chain pops slot 0 first, matching the linear
        // first-vacant order on a fresh table.
        let mut free_head = INDEX_NONE;
        if capacity <= MAX_INDEXED {
            let mut prev = INDEX_NONE;
            for (at, slot) in slots.iter_mut().enumerate().rev() {
                slot.free_next = prev;
                prev = at as u16;
            }
            free_head = prev;
        }
        Ok(Self {
            slots,
            next: 0,
            live: 0,
            bytes: 0,
            populations: [0; ROLES],
            key_heads: [INDEX_NONE; INDEX_BUCKETS],
            id_heads: [INDEX_NONE; INDEX_BUCKETS],
            free_head,
            #[cfg(test)]
            test_slot_visits: std::cell::Cell::new(0),
        })
    }

    /// Whether the intrusive index covers this table.
    fn indexed(&self) -> bool {
        self.slots.len() <= MAX_INDEXED
    }

    fn key_bucket(role: Role, key: RoleKey) -> usize {
        index_hash(&[role.index() as u64, key.namespace, key.value]) as usize % INDEX_BUCKETS
    }

    fn id_bucket(id: ReservationId) -> usize {
        index_hash(&[id.0]) as usize % INDEX_BUCKETS
    }

    /// Push a node onto its bucket chain. State is taken explicitly
    /// so maintenance sites can sequence their own borrows.
    fn chain_link(
        heads: &mut [u16; INDEX_BUCKETS],
        slots: &mut [TableSlot<C>],
        plane: usize,
        bucket: usize,
        node: u16,
    ) {
        slots[node_slot(node)].next[plane][node_lane(node)] = heads[bucket];
        heads[bucket] = node;
    }

    /// Drop a node from its bucket chain. The node must be linked:
    /// every present membership and alias is linked exactly once.
    fn chain_unlink(
        heads: &mut [u16; INDEX_BUCKETS],
        slots: &mut [TableSlot<C>],
        plane: usize,
        bucket: usize,
        node: u16,
    ) {
        if heads[bucket] == node {
            heads[bucket] = slots[node_slot(node)].next[plane][node_lane(node)];
            return;
        }
        let mut prev = heads[bucket];
        loop {
            assert_ne!(prev, INDEX_NONE, "indexed node linked");
            let next = slots[node_slot(prev)].next[plane][node_lane(prev)];
            if next == node {
                slots[node_slot(prev)].next[plane][node_lane(prev)] =
                    slots[node_slot(node)].next[plane][node_lane(node)];
                return;
            }
            prev = next;
        }
    }

    /// Pop the first vacant slot from the intrusive free list.
    fn free_pop(head: &mut u16, slots: &mut [TableSlot<C>]) -> Option<usize> {
        let at = *head;
        if at == INDEX_NONE {
            return None;
        }
        *head = slots[at as usize].free_next;
        slots[at as usize].free_next = INDEX_NONE;
        Some(at as usize)
    }

    /// Return a vacated slot to the intrusive free list.
    fn free_push(head: &mut u16, slots: &mut [TableSlot<C>], at: usize) {
        slots[at].free_next = *head;
        *head = at as u16;
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

    /// Test-only read of the lookup cost counter.
    #[cfg(test)]
    pub(super) fn test_slot_visits_for_test(&self) -> usize {
        self.test_slot_visits.get()
    }

    /// Test-only reset of the lookup cost counter.
    #[cfg(test)]
    pub(super) fn reset_test_slot_visits_for_test(&self) {
        self.test_slot_visits.set(0);
    }

    pub(super) fn reservation(&self, role: Role, key: RoleKey) -> Option<ReservationId> {
        let at = self.key_slot(role, key)?;
        self.slots[at].operation.as_ref()?.aliases[0]
    }

    pub(super) fn member_bytes(&self, role: Role, key: RoleKey) -> Option<usize> {
        let at = self.key_slot(role, key)?;
        self.slots[at].operation.as_ref()?.roles[role.index()]
            .as_ref()
            .map(|member| member.bytes)
    }

    /// Read one original operation after its H8 lookup. A completed fallback
    /// may release neither an outstanding raw copy nor a converted model call.
    pub(super) fn unconverted_staging(
        &self,
        open: RoleKey,
        staged: RoleKey,
        reservation: ReservationId,
    ) -> bool {
        let Some(at) = self.key_slot(Role::H8Open, open) else {
            return false;
        };
        let operation = self.slots[at]
            .operation
            .as_ref()
            .expect("retained H8 membership");
        operation.aliases.contains(&Some(reservation))
            && operation.roles[Role::H9Staged.index()]
                .as_ref()
                .is_some_and(|member| member.key == staged)
            && operation.roles[Role::Raw.index()].is_none()
            && operation.roles[Role::Model.index()].is_none()
    }

    /// Read the original H8 operation without acquiring/releasing any role.
    /// `staged` is present only for a genuine already-staged H3 original.
    pub(super) fn unconverted_original(
        &self,
        open: RoleKey,
        reservation: ReservationId,
        staged: Option<RoleKey>,
    ) -> bool {
        let Some(at) = self.key_slot(Role::H8Open, open) else {
            return false;
        };
        let operation = self.slots[at]
            .operation
            .as_ref()
            .expect("retained H8 membership");
        operation.aliases.contains(&Some(reservation))
            && operation.roles[Role::H9Staged.index()]
                .as_ref()
                .map(|member| member.key)
                == staged
            && operation.roles[Role::Raw.index()].is_none()
            && operation.roles[Role::Model.index()].is_none()
    }

    pub(super) fn release_role(&mut self, role: Role) {
        let indexed = self.indexed();
        for at in 0..self.slots.len() {
            let taken = self.slots[at]
                .operation
                .as_mut()
                .and_then(|operation| operation.roles[role.index()].take());
            if let Some(member) = taken {
                if indexed {
                    Self::chain_unlink(
                        &mut self.key_heads,
                        &mut self.slots,
                        KEY_LINKS,
                        Self::key_bucket(role, member.key),
                        node_code(at, role.index()),
                    );
                }
                self.populations[role.index()] -= 1;
                self.bytes -= member.bytes;
                drop(member);
            }
            let vacant = self.slots[at]
                .operation
                .as_ref()
                .is_some_and(|operation| operation.roles.iter().all(Option::is_none));
            if vacant {
                let aliases = self.slots[at].operation.as_ref().unwrap().aliases;
                self.slots[at].operation = None;
                self.live -= 1;
                if indexed {
                    for (lane, alias) in aliases.iter().enumerate() {
                        if let Some(id) = alias {
                            Self::chain_unlink(
                                &mut self.id_heads,
                                &mut self.slots,
                                ID_LINKS,
                                Self::id_bucket(*id),
                                node_code(at, lane),
                            );
                        }
                    }
                    Self::free_push(&mut self.free_head, &mut self.slots, at);
                }
            }
        }
    }

    fn key_slot(&self, role: Role, key: RoleKey) -> Option<usize> {
        if self.indexed() {
            let mut code = self.key_heads[Self::key_bucket(role, key)];
            while code != INDEX_NONE {
                #[cfg(test)]
                self.test_slot_visits.set(self.test_slot_visits.get() + 1);
                let slot = node_slot(code);
                let lane = node_lane(code);
                // Buckets mix lanes on collision: the node owns its own
                // lane's membership, so the lane must match exactly.
                if lane == role.index()
                    && self.slots[slot]
                        .operation
                        .as_ref()
                        .is_some_and(|operation| {
                            operation.roles[lane]
                                .as_ref()
                                .is_some_and(|member| member.key == key)
                        })
                {
                    return Some(slot);
                }
                code = self.slots[slot].next[KEY_LINKS][lane];
            }
            return None;
        }
        self.slots.iter().position(|slot| {
            #[cfg(test)]
            self.test_slot_visits.set(self.test_slot_visits.get() + 1);
            slot.operation.as_ref().is_some_and(|operation| {
                operation.roles[role.index()]
                    .as_ref()
                    .is_some_and(|member| member.key == key)
            })
        })
    }

    fn id_slot(&self, id: ReservationId) -> Option<usize> {
        if self.indexed() {
            let mut code = self.id_heads[Self::id_bucket(id)];
            while code != INDEX_NONE {
                #[cfg(test)]
                self.test_slot_visits.set(self.test_slot_visits.get() + 1);
                let slot = node_slot(code);
                let lane = node_lane(code);
                if self.slots[slot]
                    .operation
                    .as_ref()
                    .is_some_and(|operation| operation.aliases[lane] == Some(id))
                {
                    return Some(slot);
                }
                code = self.slots[slot].next[ID_LINKS][lane];
            }
            return None;
        }
        self.slots.iter().position(|slot| {
            #[cfg(test)]
            self.test_slot_visits.set(self.test_slot_visits.get() + 1);
            slot.operation
                .as_ref()
                .is_some_and(|operation| operation.aliases.contains(&Some(id)))
        })
    }

    /// Test-only linear oracles: the old scan algorithms, kept pure
    /// (no cost counting) so the differential test can compare old
    /// against new on every lookup.
    #[cfg(test)]
    fn key_slot_linear_for_test(&self, role: Role, key: RoleKey) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.operation.as_ref().is_some_and(|operation| {
                operation.roles[role.index()]
                    .as_ref()
                    .is_some_and(|member| member.key == key)
            })
        })
    }

    #[cfg(test)]
    fn id_slot_linear_for_test(&self, id: ReservationId) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.operation
                .as_ref()
                .is_some_and(|operation| operation.aliases.contains(&Some(id)))
        })
    }

    /// Test-only indexed-lookup probes for the differential test.
    #[cfg(test)]
    pub(super) fn key_slot_for_test(&self, role: Role, key: RoleKey) -> Option<usize> {
        self.key_slot(role, key)
    }

    #[cfg(test)]
    pub(super) fn id_slot_for_test(&self, id: ReservationId) -> Option<usize> {
        self.id_slot(id)
    }

    /// Test-only free-list census: listed slots plus live operations
    /// always cover the table. The walk is fuel-capped, so a corrupt
    /// list fails loudly instead of hanging the test.
    #[cfg(test)]
    pub(super) fn free_list_len_for_test(&self) -> usize {
        if !self.indexed() {
            return self
                .slots
                .iter()
                .filter(|slot| slot.operation.is_none())
                .count();
        }
        let mut len = 0;
        let mut at = self.free_head;
        while at != INDEX_NONE && len <= self.slots.len() {
            len += 1;
            at = self.slots[at as usize].free_next;
        }
        len
    }

    /// IDs are never recycled. A previously minted ID is released only
    /// after its entire operation (including every merged alias/role) left
    /// the table; a reused physical slot does not revive that identity.
    pub(super) fn reservation_is_released(&self, id: ReservationId) -> bool {
        id.0 != 0 && id.0 <= self.next && self.id_slot(id).is_none()
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
                if self.slots[at].operation.as_ref().unwrap().roles[role.index()].is_some() {
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
                let at = if self.indexed() {
                    Self::free_pop(&mut self.free_head, &mut self.slots)
                        .expect("preflight retained a slot")
                } else {
                    self.slots
                        .iter()
                        .position(|slot| {
                            #[cfg(test)]
                            self.test_slot_visits.set(self.test_slot_visits.get() + 1);
                            slot.operation.is_none()
                        })
                        .expect("preflight retained a slot")
                };
                let mut aliases = [None; ROLES];
                aliases[0] = Some(id);
                self.slots[at].operation = Some(Operation {
                    aliases,
                    roles: std::array::from_fn(|_| None),
                });
                self.next = id.0;
                self.live += 1;
                if self.indexed() {
                    Self::chain_link(
                        &mut self.id_heads,
                        &mut self.slots,
                        ID_LINKS,
                        Self::id_bucket(id),
                        node_code(at, 0),
                    );
                }
                at
            }
        };
        let operation = self.slots[at].operation.as_mut().unwrap();
        operation.roles[role.index()] = Some(Membership { key, bytes, charge });
        self.populations[role.index()] += 1;
        self.bytes += bytes;
        let head = operation.aliases[0].unwrap();
        if self.indexed() {
            Self::chain_link(
                &mut self.key_heads,
                &mut self.slots,
                KEY_LINKS,
                Self::key_bucket(role, key),
                node_code(at, role.index()),
            );
        }
        Ok(head)
    }

    pub(super) fn release(&mut self, role: Role, key: RoleKey) -> Option<(usize, C)> {
        let at = self.key_slot(role, key)?;
        if self.indexed() {
            Self::chain_unlink(
                &mut self.key_heads,
                &mut self.slots,
                KEY_LINKS,
                Self::key_bucket(role, key),
                node_code(at, role.index()),
            );
        }
        let operation = self.slots[at].operation.as_mut().unwrap();
        let member = operation.roles[role.index()].take().unwrap();
        self.bytes -= member.bytes;
        self.populations[role.index()] -= 1;
        if operation.roles.iter().all(Option::is_none) {
            let aliases = operation.aliases;
            self.slots[at].operation = None;
            self.live -= 1;
            if self.indexed() {
                for (lane, alias) in aliases.iter().enumerate() {
                    if let Some(id) = alias {
                        Self::chain_unlink(
                            &mut self.id_heads,
                            &mut self.slots,
                            ID_LINKS,
                            Self::id_bucket(*id),
                            node_code(at, lane),
                        );
                    }
                }
                Self::free_push(&mut self.free_head, &mut self.slots, at);
            }
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
            return Ok(self.slots[left].operation.as_ref().unwrap().aliases[0].unwrap());
        }
        let a = self.slots[left].operation.as_ref().unwrap();
        let b = self.slots[right].operation.as_ref().unwrap();
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
        let mut moved_roles = [(
            0usize,
            RoleKey {
                namespace: 0,
                value: 0,
            },
        ); ROLES];
        let mut moved_roles_len = 0;
        let mut moved_ids = [ReservationId(0); ROLES];
        let mut moved_ids_len = 0;
        if self.indexed() {
            // Gather first: the links live in the slots, so unlinking
            // borrows the same storage the membership is read from.
            let doomed = self.slots[right].operation.as_ref().unwrap();
            for (lane, member) in doomed.roles.iter().enumerate() {
                if let Some(member) = member {
                    moved_roles[moved_roles_len] = (lane, member.key);
                    moved_roles_len += 1;
                }
            }
            for alias in doomed.aliases.iter().flatten() {
                moved_ids[moved_ids_len] = *alias;
                moved_ids_len += 1;
            }
            for (lane, key) in &moved_roles[..moved_roles_len] {
                Self::chain_unlink(
                    &mut self.key_heads,
                    &mut self.slots,
                    KEY_LINKS,
                    Self::key_bucket(Role::at(*lane), *key),
                    node_code(right, *lane),
                );
            }
            // Alias lanes are positional; recover them from the stored order.
            let right_aliases = self.slots[right].operation.as_ref().unwrap().aliases;
            let mut unlink_pos = 0;
            for (lane, alias) in right_aliases.iter().enumerate() {
                if let Some(id) = alias {
                    Self::chain_unlink(
                        &mut self.id_heads,
                        &mut self.slots,
                        ID_LINKS,
                        Self::id_bucket(*id),
                        node_code(right, lane),
                    );
                    debug_assert_eq!(moved_ids[unlink_pos], *id);
                    unlink_pos += 1;
                }
            }
        }
        let right_operation = self.slots[right].operation.take().unwrap();
        let left_operation = self.slots[left].operation.as_mut().unwrap();
        let mut moved_pos = [0usize; ROLES];
        let mut moved_pos_len = 0;
        for alias in right_operation.aliases.into_iter().flatten() {
            let pos = left_operation
                .aliases
                .iter()
                .position(|slot| slot.is_none())
                .unwrap();
            left_operation.aliases[pos] = Some(alias);
            moved_pos[moved_pos_len] = pos;
            moved_pos_len += 1;
        }
        for (destination, source) in left_operation.roles.iter_mut().zip(right_operation.roles) {
            if source.is_some() {
                *destination = source;
            }
        }
        let head = left_operation.aliases[0].unwrap();
        self.live -= 1;
        if self.indexed() {
            for (lane, key) in &moved_roles[..moved_roles_len] {
                Self::chain_link(
                    &mut self.key_heads,
                    &mut self.slots,
                    KEY_LINKS,
                    Self::key_bucket(Role::at(*lane), *key),
                    node_code(left, *lane),
                );
            }
            for (pos, id) in moved_pos[..moved_pos_len]
                .iter()
                .zip(&moved_ids[..moved_ids_len])
            {
                Self::chain_link(
                    &mut self.id_heads,
                    &mut self.slots,
                    ID_LINKS,
                    Self::id_bucket(*id),
                    node_code(left, *pos),
                );
            }
            Self::free_push(&mut self.free_head, &mut self.slots, right);
        }
        Ok(head)
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
        let operation = self.slots[at].operation.as_ref().unwrap();
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
        let operation = self.slots[at].operation.as_mut().unwrap();
        let old = operation.roles[from.index()].take().unwrap();
        operation.roles[to.index()] = Some(Membership {
            key: to_key,
            bytes,
            charge,
        });
        self.populations[from.index()] -= 1;
        self.populations[to.index()] += 1;
        self.bytes = total;
        let head = operation.aliases[0].unwrap();
        if self.indexed() {
            Self::chain_unlink(
                &mut self.key_heads,
                &mut self.slots,
                KEY_LINKS,
                Self::key_bucket(from, from_key),
                node_code(at, from.index()),
            );
            Self::chain_link(
                &mut self.key_heads,
                &mut self.slots,
                KEY_LINKS,
                Self::key_bucket(to, to_key),
                node_code(at, to.index()),
            );
        }
        Ok((head, old.bytes, old.charge))
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
    fn resource_reservations_release_requires_all_roles_and_merged_aliases() {
        let mut table = ReservationTable::try_new(2).unwrap();
        assert!(!table.reservation_is_released(ReservationId(0)));
        assert!(!table.reservation_is_released(ReservationId(1)));
        let a = table.insert(Role::Raw, key(1), None, 1, ()).unwrap();
        let b = table.insert(Role::H9Staged, key(2), None, 1, ()).unwrap();
        table.merge(a, b).unwrap();
        for role in [Role::H8Open, Role::Model, Role::Association] {
            table.insert(role, key(1), Some(b), 1, ()).unwrap();
        }
        assert!(!table.reservation_is_released(a));
        assert!(!table.reservation_is_released(b));
        for role in [Role::Raw, Role::H8Open, Role::Model, Role::H9Staged] {
            table
                .release(role, key(if role == Role::H9Staged { 2 } else { 1 }))
                .unwrap();
            assert!(!table.reservation_is_released(a));
            assert!(!table.reservation_is_released(b));
        }
        table.release(Role::Association, key(1)).unwrap();
        assert!(table.reservation_is_released(a));
        assert!(table.reservation_is_released(b));
        let next = table.insert(Role::Raw, key(1), None, 1, ()).unwrap();
        assert!(next != a && next != b);
        assert!(!table.reservation_is_released(next));
        assert!(table.reservation_is_released(a));
        assert!(table.reservation_is_released(b));
        assert!(!table.reservation_is_released(ReservationId(table.next + 1)));
        assert!(!table.reservation_is_released(ReservationId(0)));
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

    #[test]
    fn joint_keepup_reservation_lookups_are_bounded_at_full_occupancy() {
        let mut table = ReservationTable::try_new(1_024).unwrap();
        for value in 1..=1_024 {
            let id = table.insert(Role::Raw, key(value), None, 1, ()).unwrap();
            for (role, bytes) in [
                (Role::H8Open, 2),
                (Role::Model, 3),
                (Role::H9Staged, 4),
                (Role::Association, 5),
            ] {
                table.insert(role, key(value), Some(id), bytes, ()).unwrap();
            }
        }
        table.reset_test_slot_visits_for_test();
        let mut lookups = 0;
        for value in (1..=1_024u64).step_by(7) {
            for role in [
                Role::Raw,
                Role::H8Open,
                Role::Model,
                Role::H9Staged,
                Role::Association,
            ] {
                assert!(table.reservation(role, key(value)).is_some());
                assert!(table.member_bytes(role, key(value)).is_some());
                lookups += 2;
            }
        }
        let visits = table.test_slot_visits_for_test();
        assert!(
            visits < lookups * 64,
            "indexed lookups must not scan the table: {visits} visits for {lookups} lookups"
        );
    }

    #[test]
    fn resource_reservations_index_matches_linear_model() {
        use crate::semantics_objects::journal::tests::KeepupRng;

        fn check(
            table: &ReservationTable<()>,
            capacity: usize,
            pairs: &[(Role, RoleKey)],
            ids: &[ReservationId],
        ) {
            for (role, key) in pairs {
                assert_eq!(
                    table.key_slot_for_test(*role, *key),
                    table.key_slot_linear_for_test(*role, *key),
                    "key lookup matches the linear scan"
                );
            }
            for id in ids {
                assert_eq!(
                    table.id_slot_for_test(*id),
                    table.id_slot_linear_for_test(*id),
                    "id lookup matches the linear scan"
                );
            }
            assert_eq!(
                table.free_list_len_for_test() + table.census(),
                capacity,
                "the free list accounts every slot"
            );
        }

        fn fuzz(capacity: usize, seed: u64, ops: usize) {
            let mut table = ReservationTable::try_new(capacity).unwrap();
            let mut rng = KeepupRng::new(seed);
            let roles = [
                Role::Raw,
                Role::H8Open,
                Role::Model,
                Role::H9Staged,
                Role::Association,
            ];
            let mut pairs: Vec<(Role, RoleKey)> = Vec::new();
            let mut ids: Vec<ReservationId> = Vec::new();
            let track = |pairs: &mut Vec<(Role, RoleKey)>, pair: (Role, RoleKey)| {
                if !pairs.contains(&pair) {
                    pairs.push(pair);
                }
            };
            for _ in 0..ops {
                match rng.below(100) {
                    0..60 => {
                        let pair = (roles[rng.below(5) as usize], key(1 + rng.below(24)));
                        track(&mut pairs, pair);
                        let existing = if !ids.is_empty() && rng.below(2) == 0 {
                            Some(ids[rng.below(ids.len() as u64) as usize])
                        } else {
                            None
                        };
                        if let Ok(id) =
                            table.insert(pair.0, pair.1, existing, rng.below(9) as usize, ())
                        {
                            ids.push(id);
                        }
                    }
                    60..75 => {
                        let pair = (roles[rng.below(5) as usize], key(1 + rng.below(24)));
                        track(&mut pairs, pair);
                        let _ = table.release(pair.0, pair.1);
                    }
                    75..83 => {
                        if ids.len() >= 2 {
                            let a = ids[rng.below(ids.len() as u64) as usize];
                            let b = ids[rng.below(ids.len() as u64) as usize];
                            let _ = table.merge(a, b);
                        }
                    }
                    83..90 => {
                        let from = (roles[rng.below(5) as usize], key(1 + rng.below(24)));
                        let to = (roles[rng.below(5) as usize], key(1 + rng.below(24)));
                        track(&mut pairs, from);
                        track(&mut pairs, to);
                        let _ =
                            table.transfer(from.0, from.1, to.0, to.1, rng.below(9) as usize, ());
                    }
                    90..93 => {
                        table.release_role(roles[rng.below(5) as usize]);
                    }
                    _ => {
                        let _ = (table.census(), table.bytes());
                    }
                }
                check(&table, capacity, &pairs, &ids);
            }
        }
        fuzz(8, 0x1bd9_1f16_39b1_2c4d, 600);
        fuzz(1_024, 0x9e37_79b9_7f4a_7c15, 200);
    }

    #[test]
    fn resource_reservations_unindexed_capacity_keeps_linear_scans() {
        // Past MAX_INDEXED the table keeps the old scans: behavior is
        // identical, only the cost differs. Exercises the fallback.
        let mut table = ReservationTable::try_new(1_025).unwrap();
        assert!(!table.indexed());
        let a = table.insert(Role::Raw, key(1), None, 1, ()).unwrap();
        let b = table.insert(Role::Model, key(2), None, 1, ()).unwrap();
        table.merge(a, b).unwrap();
        table.insert(Role::H8Open, key(3), Some(a), 2, ()).unwrap();
        assert_eq!(table.key_slot_for_test(Role::Raw, key(1)), Some(0));
        assert_eq!(table.key_slot_for_test(Role::Model, key(2)), Some(0));
        assert_eq!(table.key_slot_for_test(Role::H8Open, key(3)), Some(0));
        assert_eq!(table.id_slot_for_test(b), Some(0));
        table.release(Role::Raw, key(1)).unwrap();
        table.release(Role::Model, key(2)).unwrap();
        table.release(Role::H8Open, key(3)).unwrap();
        assert_eq!((table.census(), table.bytes()), (0, 0));
        table.release_role(Role::Raw);
    }
}
