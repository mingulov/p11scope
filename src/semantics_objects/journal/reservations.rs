//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Fixed resource bookkeeping. IDs and roles grant no semantic authority.
//!
//! The caller prepays this table's one allocation before construction. Each
//! physical membership moves its own charge into the table before insertion;
//! removing one role never releases a surviving sibling's storage charge.

use std::mem::size_of;

const ROLES: usize = 5;

/// Intrusive-index capacity (conservative cutoff 13,106 indexed,
/// 13,107 linear, controller-approved): tables at or below this stay
/// indexed, including the production 4,096-slot staging table. The
/// encoding itself could cover 13,107 (max code 65,534 below the
/// 65,535 sentinel); the cutoff stays one slot conservative. Only
/// capacities past it keep the linear scans; no table today is one.
/// This bound sizes no memory: the slot layout, bucket count and
/// prepaid allocation are unchanged.
const MAX_INDEXED: usize = (u16::MAX as usize - 1) / ROLES;
/// Chain buckets per index (the key and id indexes share the shape).
/// At most five memberships per slot hash here; at staging capacity
/// the average key chain stays near twenty entries.
const INDEX_BUCKETS: usize = 1_024;
/// Empty chain head/link: outside the node-code range.
const INDEX_NONE: u16 = u16::MAX;
/// Link planes inside each slot: key chains and id chains.
const KEY_LINKS: usize = 0;
const ID_LINKS: usize = 1;

/// Chain-node code: `slot * ROLES + lane`. Slots below `MAX_INDEXED`
/// keep every code below `INDEX_NONE` (13,106 slots × 5 lanes).
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

/// Deterministic Fx-style hash for the intrusive index. The seed and
/// finalizer are fixed, so chain shapes are stable across runs and the
/// lookup bound is a stable property, not luck. The finalizer avalanches
/// the low bits: bucket selection uses `hash % INDEX_BUCKETS`, and
/// production keys are sequential tickets, ordinals and reservation IDs,
/// which the bare Fx rounds cluster into 32 buckets; the finalizer
/// spreads 4,096 sequential entries over ~1,000 buckets instead.
fn index_hash(parts: &[u64]) -> u64 {
    const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
    let mut hash = SEED;
    for part in parts {
        hash = hash.wrapping_add(*part);
        hash = hash.rotate_left(5).wrapping_mul(SEED);
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^= hash >> 33;
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

/// Resumable cursor for the budgeted role sweep (`release_role_step`).
/// Slots advance in order; chain unlinks resume from their predecessor
/// or retained splice position when a credit's leaf budget runs out.
/// The table stays
/// lookup-consistent across yields (a removed membership reads absent,
/// a dangling alias node is skipped), but the caller must not insert,
/// merge or transfer until the sweep completes.
pub(super) struct ReleaseRoleCursor {
    next_slot: usize,
    pending_key: Option<PendingUnlink>,
    pending_alias_slot: Option<usize>,
    pending_alias_lane: usize,
    pending_alias_unlink: Option<PendingUnlink>,
    pending_alias_ids: [Option<ReservationId>; ROLES],
}

struct PendingUnlink {
    plane: usize,
    bucket: usize,
    node: u16,
    prev: u16,
    /// True when the splice position is found but its
    /// target-successor load still owns one leaf unit: the next step
    /// reads the successor and completes the splice.
    splice_ready: bool,
}

impl ReleaseRoleCursor {
    pub(super) fn new() -> Self {
        Self {
            next_slot: 0,
            pending_key: None,
            pending_alias_slot: None,
            pending_alias_lane: 0,
            pending_alias_unlink: None,
            pending_alias_ids: [None; ROLES],
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
    /// Tables past `MAX_INDEXED` (codes past the `u16` link range)
    /// ignore the index and keep the linear scans.
    key_heads: [u16; INDEX_BUCKETS],
    id_heads: [u16; INDEX_BUCKETS],
    /// Intrusive free list head: per-slot links live in the slots. A
    /// slot is listed exactly while vacant.
    free_head: u16,
    /// Test-only lookup cost counter: slot visits across
    /// `key_slot`, `id_slot` and free-slot searches.
    #[cfg(test)]
    test_slot_visits: std::cell::Cell<usize>,
    /// Test-only sweep cost counter: independently counted slot
    /// visits plus chain-link reads (head, predecessor and
    /// target-successor loads) across `release_role_step`. The
    /// reported `spent` must match this count on every step.
    #[cfg(test)]
    test_sweep_visits: std::cell::Cell<usize>,
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
            #[cfg(test)]
            test_sweep_visits: std::cell::Cell::new(0),
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

    /// Resumable chain unlink for the budgeted void sweep: at most
    /// `budget` link reads this call (`INDEX_NONE` in `prev` starts at
    /// the head, `splice_ready` completes a retained splice). Returns
    /// whether the splice completed, the units spent and the
    /// independently counted link reads performed (both count the
    /// head read, predecessor reads and the target-successor load,
    /// never above `budget`). When the budget ends at the discovered
    /// splice position, the unlink yields with `splice_ready` set and
    /// the chain unchanged, so the next step's successor load is
    /// exact.
    fn chain_unlink_resumable(
        heads: &mut [u16; INDEX_BUCKETS],
        slots: &mut [TableSlot<C>],
        pending: &mut PendingUnlink,
        budget: usize,
    ) -> (bool, usize, usize) {
        if budget == 0 {
            return (false, 0, 0);
        }
        let mut spent = 0;
        let mut actual = 0;
        if pending.splice_ready {
            spent += 1;
            actual += 1;
            let successor =
                slots[node_slot(pending.node)].next[pending.plane][node_lane(pending.node)];
            if pending.prev == INDEX_NONE {
                heads[pending.bucket] = successor;
            } else {
                slots[node_slot(pending.prev)].next[pending.plane][node_lane(pending.prev)] =
                    successor;
            }
            pending.splice_ready = false;
            return (true, spent, actual);
        }
        if pending.prev == INDEX_NONE {
            spent += 1;
            actual += 1;
            let head = heads[pending.bucket];
            if head == pending.node {
                if spent >= budget {
                    pending.splice_ready = true;
                    return (false, spent, actual);
                }
                spent += 1;
                actual += 1;
                heads[pending.bucket] =
                    slots[node_slot(pending.node)].next[pending.plane][node_lane(pending.node)];
                return (true, spent, actual);
            }
            pending.prev = head;
            assert_ne!(pending.prev, INDEX_NONE, "indexed node linked");
            if spent >= budget {
                return (false, spent, actual);
            }
        }
        while spent < budget {
            spent += 1;
            actual += 1;
            let next = slots[node_slot(pending.prev)].next[pending.plane][node_lane(pending.prev)];
            if next == pending.node {
                if spent >= budget {
                    pending.splice_ready = true;
                    return (false, spent, actual);
                }
                spent += 1;
                actual += 1;
                slots[node_slot(pending.prev)].next[pending.plane][node_lane(pending.prev)] =
                    slots[node_slot(pending.node)].next[pending.plane][node_lane(pending.node)];
                return (true, spent, actual);
            }
            pending.prev = next;
            assert_ne!(pending.prev, INDEX_NONE, "indexed node linked");
        }
        (false, spent, actual)
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

    /// Test-only sum of one role's retained member bytes.
    #[cfg(test)]
    pub(super) fn role_bytes_for_test(&self, role: Role) -> usize {
        self.slots
            .iter()
            .filter_map(|slot| {
                slot.operation.as_ref()?.roles[role.index()]
                    .as_ref()
                    .map(|member| member.bytes)
            })
            .sum()
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

    /// Test-only read of the sweep cost counter.
    #[cfg(test)]
    pub(super) fn test_sweep_visits_for_test(&self) -> usize {
        self.test_sweep_visits.get()
    }

    /// Test-only reset of the sweep cost counter.
    #[cfg(test)]
    pub(super) fn reset_test_sweep_visits_for_test(&self) {
        self.test_sweep_visits.set(0);
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
        // Synchronous callers drain the same budgeted sweep without
        // yielding: each internal step still honors the leaf budget.
        let mut cursor = ReleaseRoleCursor::new();
        while !self.release_role_step(role, &mut cursor, 64).0 {}
    }

    /// One budgeted sweep step over `role`: at most `budget` leaf units
    /// (slot visits plus chain-link reads: bucket-head, predecessor
    /// and target-successor loads). Returns whether the sweep
    /// completed and the units spent (never above `budget`). The caller
    /// holds `cursor` across steps and must not insert, merge or
    /// transfer until completion.
    pub(super) fn release_role_step(
        &mut self,
        role: Role,
        cursor: &mut ReleaseRoleCursor,
        budget: usize,
    ) -> (bool, usize) {
        let mut spent = 0;
        let indexed = self.indexed();
        loop {
            if spent >= budget {
                debug_assert!(spent <= budget);
                return (false, spent);
            }
            if let Some(mut pending) = cursor.pending_alias_unlink.take() {
                let (done, used, actual) = Self::chain_unlink_resumable(
                    &mut self.id_heads,
                    &mut self.slots,
                    &mut pending,
                    budget - spent,
                );
                spent += used;
                #[cfg(test)]
                self.test_sweep_visits
                    .set(self.test_sweep_visits.get() + actual);
                #[cfg(not(test))]
                let _ = actual;
                if !done {
                    cursor.pending_alias_unlink = Some(pending);
                    debug_assert!(spent <= budget);
                    return (false, spent);
                }
                cursor.pending_alias_lane += 1;
                continue;
            }
            if let Some(at) = cursor.pending_alias_slot {
                // The slot was cleared at vacate time; its aliases live in
                // the cursor snapshot until the free push. Unlink the next
                // present lane, or finish the slot when none remain.
                let mut advanced = false;
                while cursor.pending_alias_lane < ROLES {
                    let lane = cursor.pending_alias_lane;
                    if let Some(id) = cursor.pending_alias_ids[lane] {
                        cursor.pending_alias_unlink = Some(PendingUnlink {
                            plane: ID_LINKS,
                            bucket: Self::id_bucket(id),
                            node: node_code(at, lane),
                            prev: INDEX_NONE,
                            splice_ready: false,
                        });
                        advanced = true;
                        break;
                    }
                    cursor.pending_alias_lane += 1;
                }
                if !advanced {
                    if indexed {
                        Self::free_push(&mut self.free_head, &mut self.slots, at);
                    }
                    cursor.pending_alias_slot = None;
                    cursor.pending_alias_ids = [None; ROLES];
                    cursor.next_slot = at + 1;
                }
                continue;
            }
            if let Some(mut pending) = cursor.pending_key.take() {
                let (done, used, actual) = Self::chain_unlink_resumable(
                    &mut self.key_heads,
                    &mut self.slots,
                    &mut pending,
                    budget - spent,
                );
                spent += used;
                #[cfg(test)]
                self.test_sweep_visits
                    .set(self.test_sweep_visits.get() + actual);
                #[cfg(not(test))]
                let _ = actual;
                if !done {
                    cursor.pending_key = Some(pending);
                    debug_assert!(spent <= budget);
                    return (false, spent);
                }
                let at = cursor.next_slot;
                if self.slot_is_vacant(at) {
                    self.clear_vacated_slot(at, cursor);
                } else {
                    cursor.next_slot = at + 1;
                }
                continue;
            }
            if cursor.next_slot >= self.slots.len() {
                debug_assert!(spent <= budget);
                return (true, spent);
            }
            let at = cursor.next_slot;
            spent += 1;
            #[cfg(test)]
            self.test_sweep_visits.set(self.test_sweep_visits.get() + 1);
            let key = self.slots[at]
                .operation
                .as_ref()
                .and_then(|operation| operation.roles[role.index()].as_ref())
                .map(|member| member.key);
            if let Some(key) = key {
                let member = self.slots[at]
                    .operation
                    .as_mut()
                    .and_then(|operation| operation.roles[role.index()].take())
                    .expect("swept membership retained");
                self.populations[role.index()] -= 1;
                self.bytes -= member.bytes;
                drop(member);
                if indexed {
                    cursor.pending_key = Some(PendingUnlink {
                        plane: KEY_LINKS,
                        bucket: Self::key_bucket(role, key),
                        node: node_code(at, role.index()),
                        prev: INDEX_NONE,
                        splice_ready: false,
                    });
                    continue;
                }
            }
            if self.slot_is_vacant(at) {
                self.clear_vacated_slot(at, cursor);
            } else {
                cursor.next_slot = at + 1;
            }
        }
    }

    fn slot_is_vacant(&self, at: usize) -> bool {
        self.slots[at]
            .operation
            .as_ref()
            .is_some_and(|operation| operation.roles.iter().all(Option::is_none))
    }

    /// Clear a vacated slot and queue its alias unlinks in the cursor.
    /// The slot's chain links stay (dangling but linked) until each alias
    /// splice completes; lookups skip the cleared operation meanwhile.
    /// Unindexed tables never linked aliases, so they finish immediately.
    fn clear_vacated_slot(&mut self, at: usize, cursor: &mut ReleaseRoleCursor) {
        let aliases = self.slots[at].operation.as_ref().unwrap().aliases;
        self.slots[at].operation = None;
        self.live -= 1;
        if !self.indexed() {
            cursor.next_slot = at + 1;
            return;
        }
        cursor.pending_alias_slot = Some(at);
        cursor.pending_alias_lane = 0;
        cursor.pending_alias_ids = aliases;
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
    fn resource_reservations_staging_capacity_keeps_one_exact_prepaid_allocation() {
        // The production staging table keeps one prepaid allocation whose
        // bytes match the current layout (single-allocation plus
        // accounting consistency). This does not pin the layout size
        // itself: byte parity across revisions is checked by comparing
        // the measured `allocation_bytes` (1,081,344 for 4,096 `()`
        // slots here) rather than by this oracle.
        use crate::semantics_objects::journal::MAX_UNSETTLED_STAGED;

        let expected = ReservationTable::<()>::allocation_bytes(MAX_UNSETTLED_STAGED).unwrap();
        let (table, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            ReservationTable::<()>::try_new(MAX_UNSETTLED_STAGED).unwrap()
        });
        assert_eq!((allocations, bytes), (1, expected));
        assert_eq!(table.slots.capacity(), MAX_UNSETTLED_STAGED);
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
    fn joint_keepup_reservation_staging_capacity_lookups_and_allocation_stay_bounded() {
        // Production staging capacity: the ledger's 4,096-slot table
        // must stay indexed like the 1,024 table, not fall back to
        // linear scans (measured: 44% of the service core in key_slot
        // at 5k calls/s x 4 endpoints, 15-27% ring loss).
        use crate::semantics_objects::journal::MAX_UNSETTLED_STAGED;

        let capacity = MAX_UNSETTLED_STAGED;
        let mut table = ReservationTable::try_new(capacity).unwrap();
        table.reset_test_slot_visits_for_test();
        let mut ids = Vec::new();
        for value in 1..=(capacity as u64) {
            let id = table.insert(Role::Raw, key(value), None, 1, ()).unwrap();
            for (role, bytes) in [
                (Role::H8Open, 2),
                (Role::Model, 3),
                (Role::H9Staged, 4),
                (Role::Association, 5),
            ] {
                table.insert(role, key(value), Some(id), bytes, ()).unwrap();
            }
            ids.push(id);
        }
        let fill_visits = table.test_slot_visits_for_test();
        assert!(
            fill_visits < capacity * 5 * 64,
            "staging-capacity allocation must not scan the table: {fill_visits} visits"
        );
        table.reset_test_slot_visits_for_test();
        let mut lookups = 0;
        for value in (1..=(capacity as u64)).step_by(7) {
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
        for id in ids.iter().step_by(7) {
            assert!(table.id_slot_for_test(*id).is_some());
            lookups += 1;
        }
        let visits = table.test_slot_visits_for_test();
        assert!(
            visits < lookups * 64,
            "staging-capacity lookups must not scan the table: {visits} visits for {lookups} lookups"
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
        fuzz(
            crate::semantics_objects::journal::MAX_UNSETTLED_STAGED,
            0x2b99_5f3c_8d41_e6a7,
            60,
        );
    }

    #[test]
    fn resource_reservations_unindexed_capacity_keeps_linear_scans() {
        // Past MAX_INDEXED (codes past the u16 link range) the table
        // keeps the old scans: behavior is identical, only the cost
        // differs. Exercises the fallback.
        let mut table = ReservationTable::try_new(MAX_INDEXED + 1).unwrap();
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

    #[test]
    fn resource_reservations_high_slot_release_preserves_colliding_chain_across_reuse() {
        // Three same-bucket Association keys with the middle member in
        // high slot 4,095: releasing it (plus its Raw sibling) must
        // sever exactly its links, so the two survivors stay reachable
        // with their exact IDs and bytes after slot 4,095 is reused for
        // an Association key in another bucket. Pins the severed-chain
        // gap a high-slot unlink skip would leave.
        use crate::semantics_objects::journal::MAX_UNSETTLED_STAGED;

        let mut table = ReservationTable::try_new(MAX_UNSETTLED_STAGED).unwrap();
        for value in 1..=4_094u64 {
            let id = table.insert(Role::Raw, key(value), None, 1, ()).unwrap();
            assert_eq!(id.0, value);
        }
        let bucket_of = |value| ReservationTable::<()>::key_bucket(Role::Association, key(value));
        let bucket = bucket_of(200_001);
        let mut colliding = vec![200_001u64];
        for value in 200_002..300_000u64 {
            if bucket_of(value) == bucket {
                colliding.push(value);
                if colliding.len() == 3 {
                    break;
                }
            }
        }
        assert_eq!(colliding.len(), 3, "three same-bucket Association keys");
        let (a_assoc, b_assoc, c_assoc) = (colliding[0], colliding[1], colliding[2]);
        let (a_raw, b_raw, c_raw) = (100_001u64, 100_002u64, 100_003u64);
        let a_id = table.insert(Role::Raw, key(a_raw), None, 10, ()).unwrap();
        assert_eq!(a_id.0, 4_095);
        assert_eq!(
            table.insert(Role::Association, key(a_assoc), Some(a_id), 20, ()),
            Ok(a_id)
        );
        assert_eq!(
            table.key_slot_for_test(Role::Association, key(a_assoc)),
            Some(4_094)
        );
        let b_id = table.insert(Role::Raw, key(b_raw), None, 10, ()).unwrap();
        assert_eq!(b_id.0, 4_096);
        assert_eq!(
            table.insert(Role::Association, key(b_assoc), Some(b_id), 20, ()),
            Ok(b_id)
        );
        assert_eq!(
            table.key_slot_for_test(Role::Association, key(b_assoc)),
            Some(4_095)
        );
        table.release(Role::Raw, key(1)).unwrap();
        assert_eq!(table.reservation(Role::Raw, key(1)), None);
        let c_id = table.insert(Role::Raw, key(c_raw), None, 10, ()).unwrap();
        assert_eq!(c_id.0, 4_097);
        assert_eq!(
            table.insert(Role::Association, key(c_assoc), Some(c_id), 20, ()),
            Ok(c_id)
        );
        assert_eq!(
            table.key_slot_for_test(Role::Association, key(c_assoc)),
            Some(0)
        );
        table
            .release(Role::Association, key(b_assoc))
            .expect("the high-slot member releases");
        table.release(Role::Raw, key(b_raw)).unwrap();
        assert_eq!(table.reservation(Role::Association, key(b_assoc)), None);
        assert_eq!(table.member_bytes(Role::Association, key(b_assoc)), None);
        assert_eq!(table.reservation(Role::Raw, key(b_raw)), None);
        assert_eq!(
            table.reservation(Role::Association, key(a_assoc)),
            Some(a_id)
        );
        assert_eq!(
            table.member_bytes(Role::Association, key(a_assoc)),
            Some(20)
        );
        assert_eq!(table.member_bytes(Role::Raw, key(a_raw)), Some(10));
        assert_eq!(
            table.reservation(Role::Association, key(c_assoc)),
            Some(c_id)
        );
        assert_eq!(
            table.member_bytes(Role::Association, key(c_assoc)),
            Some(20)
        );
        assert_eq!(table.member_bytes(Role::Raw, key(c_raw)), Some(10));
        let mut d_assoc = 300_001u64;
        while bucket_of(d_assoc) == bucket {
            d_assoc += 1;
        }
        let d_raw = 100_004u64;
        let d_id = table.insert(Role::Raw, key(d_raw), None, 11, ()).unwrap();
        assert_eq!(d_id.0, 4_098);
        assert_eq!(
            table.key_slot_for_test(Role::Raw, key(d_raw)),
            Some(4_095),
            "the replacement reuses the freed high slot"
        );
        assert_eq!(
            table.insert(Role::Association, key(d_assoc), Some(d_id), 21, ()),
            Ok(d_id)
        );
        assert_eq!(
            table.reservation(Role::Association, key(a_assoc)),
            Some(a_id)
        );
        assert_eq!(
            table.member_bytes(Role::Association, key(a_assoc)),
            Some(20)
        );
        assert_eq!(table.member_bytes(Role::Raw, key(a_raw)), Some(10));
        assert_eq!(table.id_slot_for_test(a_id), Some(4_094));
        assert_eq!(
            table.reservation(Role::Association, key(c_assoc)),
            Some(c_id)
        );
        assert_eq!(
            table.member_bytes(Role::Association, key(c_assoc)),
            Some(20)
        );
        assert_eq!(table.member_bytes(Role::Raw, key(c_raw)), Some(10));
        assert_eq!(table.id_slot_for_test(c_id), Some(0));
        assert_eq!(table.reservation(Role::Association, key(b_assoc)), None);
        assert_eq!(table.reservation(Role::Raw, key(b_raw)), None);
        assert!(table.reservation_is_released(b_id));
        assert_eq!(
            table.reservation(Role::Association, key(d_assoc)),
            Some(d_id)
        );
        assert_eq!(
            table.member_bytes(Role::Association, key(d_assoc)),
            Some(21)
        );
        assert_eq!(table.member_bytes(Role::Raw, key(d_raw)), Some(11));
        assert_eq!(table.id_slot_for_test(d_id), Some(4_095));
    }

    #[test]
    fn resource_reservations_literal_13106_exercises_last_slot_and_highest_lane() {
        // Literal cutover pin (13,106 indexed, 13,107 linear): fill
        // 13,106, merge four single-role donors into last slot 13,105 so
        // it holds five aliases (id lane 4) and the Association role
        // (key lane 4, node code 65,529), release every alias, refuse a
        // new ID after minting u64::MAX, and verify the literal 13,107
        // fallback.
        assert_eq!(MAX_INDEXED, 13_106);
        let mut table = ReservationTable::try_new(13_106).unwrap();
        assert!(table.indexed());
        for value in 1..=13_101u64 {
            table.insert(Role::Raw, key(value), None, 1, ()).unwrap();
        }
        let h8 = table
            .insert(Role::H8Open, key(500_001), None, 2, ())
            .unwrap();
        let model = table
            .insert(Role::Model, key(500_002), None, 3, ())
            .unwrap();
        let staged = table
            .insert(Role::H9Staged, key(500_003), None, 4, ())
            .unwrap();
        let assoc = table
            .insert(Role::Association, key(500_004), None, 5, ())
            .unwrap();
        let target = table.insert(Role::Raw, key(500_005), None, 1, ()).unwrap();
        assert_eq!(
            table.key_slot_for_test(Role::Raw, key(500_005)),
            Some(13_105)
        );
        let head = table.merge(target, h8).unwrap();
        assert_eq!(head, target);
        assert_eq!(table.merge(head, model).unwrap(), target);
        assert_eq!(table.merge(target, staged).unwrap(), target);
        assert_eq!(table.merge(target, assoc).unwrap(), target);
        assert_eq!((table.census(), table.bytes()), (13_102, 13_101 + 15));
        for (role, value) in [
            (Role::Raw, 500_005),
            (Role::H8Open, 500_001),
            (Role::Model, 500_002),
            (Role::H9Staged, 500_003),
            (Role::Association, 500_004),
        ] {
            assert_eq!(
                table.key_slot_for_test(role, key(value)),
                Some(13_105),
                "last slot holds every lane"
            );
        }
        for id in [target, h8, model, staged, assoc] {
            assert_eq!(
                table.id_slot_for_test(id),
                Some(13_105),
                "last slot holds every alias through lane 4"
            );
        }
        assert_eq!(
            table.reservation(Role::Association, key(500_004)),
            Some(target)
        );
        for (role, value) in [
            (Role::Raw, 500_005),
            (Role::H8Open, 500_001),
            (Role::Model, 500_002),
            (Role::H9Staged, 500_003),
            (Role::Association, 500_004),
        ] {
            table.release(role, key(value)).unwrap();
        }
        assert_eq!((table.census(), table.bytes()), (13_101, 13_101));
        for id in [target, h8, model, staged, assoc] {
            assert!(table.reservation_is_released(id));
        }
        table.next = u64::MAX;
        assert_eq!(
            table.insert(Role::Raw, key(600_001), None, 1, ()),
            Err(Refusal::Full)
        );
        let mut fallback = ReservationTable::try_new(13_107).unwrap();
        assert!(!fallback.indexed());
        let a = fallback.insert(Role::Raw, key(1), None, 1, ()).unwrap();
        let b = fallback.insert(Role::Model, key(2), None, 1, ()).unwrap();
        fallback.merge(a, b).unwrap();
        fallback
            .insert(Role::H8Open, key(3), Some(a), 2, ())
            .unwrap();
        assert_eq!(fallback.key_slot_for_test(Role::Raw, key(1)), Some(0));
        assert_eq!(fallback.id_slot_for_test(b), Some(0));
        fallback.release(Role::Raw, key(1)).unwrap();
        fallback.release(Role::Model, key(2)).unwrap();
        fallback.release(Role::H8Open, key(3)).unwrap();
        assert_eq!((fallback.census(), fallback.bytes()), (0, 0));
        // Bulk release at the last linear slot (13,106): the sweep
        // must not encode a node code for the unindexed table.
        let mut last = ReservationTable::try_new(13_107).unwrap();
        assert!(!last.indexed());
        let first = last.insert(Role::Raw, key(1), None, 1, ()).unwrap();
        for value in 2..=13_106u64 {
            last.insert(Role::Raw, key(value), None, 1, ()).unwrap();
        }
        let doomed = last
            .insert(Role::H8Open, key(500_001), None, 2, ())
            .unwrap();
        assert_eq!(
            last.key_slot_for_test(Role::H8Open, key(500_001)),
            Some(13_106)
        );
        last.release_role(Role::H8Open);
        assert_eq!(last.population(Role::H8Open), 0);
        assert_eq!(
            last.reservation(Role::H8Open, key(500_001)),
            None,
            "the last-slot H8 membership is gone"
        );
        assert!(last.reservation_is_released(doomed));
        assert_eq!((last.census(), last.bytes()), (13_106, 13_106));
        assert_eq!(
            last.reservation(Role::Raw, key(1)),
            Some(first),
            "preserved members stay reachable"
        );
        assert_eq!(last.member_bytes(Role::Raw, key(13_106)), Some(1));
    }

    #[test]
    fn resource_reservations_void_credit_counts_every_slot_and_link_read() {
        // 512 standalone H8 members in the 4,096 staging table force
        // multi-credit cleanup at 64 units. Each step's independently
        // counted slot visits plus link reads (bucket-head,
        // predecessor and target-successor loads across the key and
        // id chains) must not exceed its credit, and the reported
        // spent must match that count. The same void driven one unit
        // at a time must also stay within one read per step.
        const BULK: u64 = 512;
        const BASE: u64 = 500_000;
        for budget in [64usize, 1usize] {
            let mut table = ReservationTable::try_new(4_096).unwrap();
            for ordinal in 0..BULK {
                table
                    .insert(
                        Role::H8Open,
                        RoleKey {
                            namespace: 0,
                            value: BASE + ordinal,
                        },
                        None,
                        10,
                        (),
                    )
                    .unwrap();
            }
            assert_eq!(table.population(Role::H8Open), BULK as usize);
            let mut cursor = ReleaseRoleCursor::new();
            let mut steps = 0;
            let mut saw_partial = false;
            loop {
                table.reset_test_sweep_visits_for_test();
                let (done, spent) = table.release_role_step(Role::H8Open, &mut cursor, budget);
                let actual = table.test_sweep_visits_for_test();
                assert!(
                    spent <= budget,
                    "credit {budget} reported {spent} above its budget"
                );
                assert!(
                    actual <= budget,
                    "credit {budget} performed {actual} leaf reads \
                     (reported {spent})"
                );
                assert_eq!(
                    spent, actual,
                    "credit {budget} must debit every leaf read it performs"
                );
                steps += 1;
                if done {
                    break;
                }
                saw_partial = true;
                assert!(steps < 20_000, "the void sweep must complete");
            }
            assert!(
                saw_partial,
                "credit {budget} must need several steps for 512 H8"
            );
            assert_eq!(table.population(Role::H8Open), 0);
            assert_eq!((table.census(), table.bytes()), (0, 0));
        }
    }

    #[test]
    fn resource_reservations_key_nonhead_unlink_counts_single_head_read() {
        // Two colliding key members: unlinking the non-head with
        // budget 1 must debit exactly the one head load it performs.
        const BASE: u64 = 500_000;
        let mut seen = std::collections::HashMap::new();
        let mut pair = None;
        for ordinal in 0..20_000u64 {
            let candidate = RoleKey {
                namespace: 0,
                value: BASE + ordinal,
            };
            let bucket = ReservationTable::<()>::key_bucket(Role::H8Open, candidate);
            if let Some(prev) = seen.get(&bucket) {
                pair = Some((*prev, BASE + ordinal));
                break;
            }
            seen.insert(bucket, BASE + ordinal);
        }
        let (first, second) = pair.expect("colliding keys exist");
        let mut table = ReservationTable::try_new(16).unwrap();
        let key_first = RoleKey {
            namespace: 0,
            value: first,
        };
        let key_second = RoleKey {
            namespace: 0,
            value: second,
        };
        table
            .insert(Role::H8Open, key_first, None, 10, ())
            .unwrap();
        table
            .insert(Role::H8Open, key_second, None, 10, ())
            .unwrap();
        let at_first = table
            .key_slot_for_test(Role::H8Open, key_first)
            .unwrap();
        let at_second = table
            .key_slot_for_test(Role::H8Open, key_second)
            .unwrap();
        let bucket = ReservationTable::<()>::key_bucket(Role::H8Open, key_first);
        assert_eq!(
            bucket,
            ReservationTable::<()>::key_bucket(Role::H8Open, key_second),
            "the pair collides"
        );
        assert_eq!(
            table.key_heads[bucket],
            node_code(at_second, 1),
            "the second insert is the head"
        );
        let mut pending = PendingUnlink {
            plane: KEY_LINKS,
            bucket,
            node: node_code(at_first, 1),
            prev: INDEX_NONE,
            splice_ready: false,
        };
        let (done, spent, actual) = ReservationTable::<()>::chain_unlink_resumable(
            &mut table.key_heads,
            &mut table.slots,
            &mut pending,
            1,
        );
        assert!(!done, "budget 1 cannot finish a non-head splice");
        assert_eq!(spent, 1, "one debit for the head load");
        assert_eq!(actual, 1, "exactly one head load occurs");
    }

    #[test]
    fn resource_reservations_id_nonhead_unlink_counts_single_head_read() {
        // Two colliding alias identities: unlinking the non-head alias
        // with budget 1 must debit exactly the one head load it performs.
        let mut table = ReservationTable::try_new(256).unwrap();
        let mut seen = std::collections::HashMap::new();
        let mut pair = None;
        for value in 1..=200u64 {
            let id = table.insert(Role::Raw, key(value), None, 1, ()).unwrap();
            let bucket = ReservationTable::<()>::id_bucket(id);
            if let Some(prev) = seen.get(&bucket) {
                pair = Some((*prev, id));
                break;
            }
            seen.insert(bucket, id);
        }
        let (first, second) = pair.expect("sequential identities collide");
        let at_first = table.id_slot_for_test(first).unwrap();
        let at_second = table.id_slot_for_test(second).unwrap();
        let bucket = ReservationTable::<()>::id_bucket(first);
        assert_eq!(
            bucket,
            ReservationTable::<()>::id_bucket(second),
            "the pair collides"
        );
        assert_eq!(
            table.id_heads[bucket],
            node_code(at_second, 0),
            "the second insert is the head"
        );
        let mut pending = PendingUnlink {
            plane: ID_LINKS,
            bucket,
            node: node_code(at_first, 0),
            prev: INDEX_NONE,
            splice_ready: false,
        };
        let (done, spent, actual) = ReservationTable::<()>::chain_unlink_resumable(
            &mut table.id_heads,
            &mut table.slots,
            &mut pending,
            1,
        );
        assert!(!done, "budget 1 cannot finish a non-head splice");
        assert_eq!(spent, 1, "one debit for the head load");
        assert_eq!(actual, 1, "exactly one head load occurs");
    }
}
