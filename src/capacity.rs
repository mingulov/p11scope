//! SPDX-License-Identifier: GPL-3.0-or-later
//! Package G (SYSPLAN): capacity and long-lived capture architecture.
//!
//! Reviewed resource contract plus its bounded implementation. This module is
//! not a constant bump: production admission stays at [`production_slots`]
//! until a reviewed contract qualifies a broader envelope. Every limit below
//! references the constant or control that actually enforces it, and every
//! refusal names the exhausted resource.

use p11scope_ebpf_common::{
    EXPERIMENTAL_SLOT_CANDIDATE, IMAGE_IDENTITY_TICKET_LIMIT, MAX_DESCRIPTORS, MAX_SLOTS,
    RING_BYTES, ROOT_AFFILIATION_LIMIT, RV_ENTRIES, START_ENTRIES, THREAD_OWNER_LIMIT,
};
use std::collections::{BTreeSet, HashSet};
use std::mem::size_of;
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};

/// One compact inventory value is one atomic `u64` constrained to 0/1.
pub const INVENTORY_ENDPOINT_BYTES: u64 = size_of::<u64>() as u64;

/// Validated capacity for the compact provider-usage inventory.
///
/// The endpoint count is the capture-lifetime ID bound. Its payload is exactly
/// one eight-byte value per endpoint; kernel map overhead is measured
/// separately and is deliberately not folded into this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryBudget {
    endpoint_limit: u64,
    payload_bytes: u64,
}

impl InventoryBudget {
    pub fn new(endpoint_limit: u64, payload_bytes: u64) -> Result<Self, String> {
        if endpoint_limit == 0 {
            return Err("inventory endpoint budget must be non-zero".into());
        }
        if endpoint_limit > u64::from(u32::MAX) {
            return Err(format!(
                "inventory endpoint budget {endpoint_limit} exceeds the u32 endpoint ID space"
            ));
        }
        let required = endpoint_limit
            .checked_mul(INVENTORY_ENDPOINT_BYTES)
            .ok_or_else(|| "inventory payload budget overflowed".to_string())?;
        if payload_bytes != required {
            return Err(format!(
                "inventory payload budget is {payload_bytes} bytes but {endpoint_limit} endpoints require exactly {required} bytes"
            ));
        }
        Ok(Self {
            endpoint_limit,
            payload_bytes,
        })
    }

    pub const fn endpoint_limit(self) -> u64 {
        self.endpoint_limit
    }

    pub const fn payload_bytes(self) -> u64 {
        self.payload_bytes
    }

    pub(crate) fn validate_count(self, endpoints: usize) -> Result<(), String> {
        let endpoints = u64::try_from(endpoints)
            .map_err(|_| "inventory endpoint count does not fit u64".to_string())?;
        let payload = endpoints
            .checked_mul(INVENTORY_ENDPOINT_BYTES)
            .ok_or_else(|| "inventory payload requirement overflowed".to_string())?;
        if endpoints > self.endpoint_limit || payload > self.payload_bytes {
            return Err(format!(
                "inventory plan requires {endpoints} endpoints ({payload} payload bytes) but only {} endpoints ({} payload bytes) are available",
                self.endpoint_limit, self.payload_bytes
            ));
        }
        Ok(())
    }
}

/// Explicit additional endpoint metadata and sparse caller-pair payload.
/// This private budget has no implicit pair capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallerBudget {
    endpoint_budget: InventoryBudget,
    pair_limit: u64,
    additional_payload_bytes: u64,
}

impl CallerBudget {
    // The private constructor becomes a production call site when caller
    // activation is selected; the current public CLI remains global-only.
    #[allow(dead_code)]
    pub(crate) fn new(
        endpoint_budget: InventoryBudget,
        pair_limit: u64,
        additional_payload_bytes: u64,
    ) -> Result<Self, String> {
        if pair_limit == 0 || pair_limit > u64::from(u32::MAX) {
            return Err(format!(
                "caller pair limit {pair_limit} must fit the non-zero u32 map capacity"
            ));
        }
        let required = endpoint_budget
            .endpoint_limit()
            .checked_mul(8)
            .and_then(|endpoints| {
                pair_limit
                    .checked_mul(56)
                    .and_then(|pairs| endpoints.checked_add(pairs))
            })
            .ok_or_else(|| "caller additional payload budget overflowed".to_string())?;
        if additional_payload_bytes != required {
            return Err(format!(
                "caller additional payload is {additional_payload_bytes} bytes, expected {required} bytes"
            ));
        }
        Ok(Self {
            endpoint_budget,
            pair_limit,
            additional_payload_bytes,
        })
    }

    pub(crate) const fn endpoint_budget(self) -> InventoryBudget {
        self.endpoint_budget
    }

    pub(crate) const fn pair_limit(self) -> u64 {
        self.pair_limit
    }

    #[allow(dead_code)]
    pub(crate) const fn additional_payload_bytes(self) -> u64 {
        self.additional_payload_bytes
    }
}

/// One row of the capacity inventory: the enforced limit and the source that
/// reports live occupancy or loss for it.
pub struct ResourceEntry {
    pub name: &'static str,
    pub limit: u64,
    pub occupancy_source: &'static str,
}

const INVENTORY: &[ResourceEntry] = &[
    ResourceEntry {
        name: "stats_slots",
        limit: MAX_SLOTS as u64,
        occupancy_source: "STATS map cardinality; attach plan slot allocation",
    },
    ResourceEntry {
        name: "start_inflight",
        limit: START_ENTRIES as u64,
        occupancy_source: "START map occupancy; EVIDENCE_START_INSERT_FAILURES",
    },
    ResourceEntry {
        name: "rv_keys",
        limit: RV_ENTRIES as u64,
        occupancy_source: "RV_COUNTS map occupancy; EVIDENCE_RV_UPDATE_FAILURES",
    },
    ResourceEntry {
        name: "descriptors",
        limit: MAX_DESCRIPTORS as u64,
        occupancy_source: "SEMANTICS map index bound; attach cookie descriptor word",
    },
    ResourceEntry {
        name: "task_owners",
        limit: THREAD_OWNER_LIMIT,
        occupancy_source: "OWNER_CTL outstanding; OWNER admission failures",
    },
    ResourceEntry {
        name: "image_identity_tickets",
        limit: IMAGE_IDENTITY_TICKET_LIMIT,
        occupancy_source: "COOKIE_CTL next_ticket; never reset or reused",
    },
    ResourceEntry {
        name: "root_affiliations",
        limit: ROOT_AFFILIATION_LIMIT,
        occupancy_source: "root affiliation control; admission/create failures",
    },
    ResourceEntry {
        name: "candidates",
        limit: crate::discovery::scan::MAX_TABLE_CANDIDATES as u64,
        occupancy_source: "scan candidate table budget; explicit refusal evidence",
    },
    ResourceEntry {
        name: "interfaces",
        limit: crate::discovery::scan::MAX_INTERFACE_RECORDS as u64,
        occupancy_source: "scan interface record budget; explicit refusal evidence",
    },
    ResourceEntry {
        name: "history_records",
        limit: crate::process::MAX_TRACKED as u64,
        occupancy_source: "history Registry limit (runtime RLIMIT_NOFILE-derived, capped)",
    },
    ResourceEntry {
        name: "semantic_keys",
        limit: crate::semantics::MAX_STATE_KEYS as u64,
        occupancy_source: "semantic state key budget; explicit lifetime drops",
    },
    ResourceEntry {
        name: "semantic_pending",
        limit: crate::semantics::MAX_PENDING as u64,
        occupancy_source: "pending plus detached operation bound",
    },
    ResourceEntry {
        name: "ring_bytes",
        limit: RING_BYTES as u64,
        occupancy_source: "EVENTS ring capacity; EVIDENCE_RING_LOSS",
    },
    ResourceEntry {
        name: "rings",
        limit: 2,
        occupancy_source: "EVENTS plus DISCOVERY ring pair; per-ring loss counters",
    },
    ResourceEntry {
        name: "links",
        limit: 2 * MAX_SLOTS as u64,
        occupancy_source: "entry plus return uprobe links per slot; attach/detach accounting",
    },
];

/// Every resource Package G budgets, with its enforced limit.
pub fn inventory() -> &'static [ResourceEntry] {
    INVENTORY
}

/// Production attach-slot admission limit. This is the only qualified value.
pub fn production_slots() -> u32 {
    MAX_SLOTS
}

/// Experimental slot-count candidate for the E11 storage comparison. This is
/// never a sufficiency claim and never gates admission.
pub fn experimental_candidate_slots() -> u32 {
    EXPERIMENTAL_SLOT_CANDIDATE
}

/// Broader admission stays unqualified until the reviewed contract lands.
pub fn broader_admission_qualified() -> bool {
    false
}

/// Native task-owner slot bound shared with `task_owner.c`. The lookup
/// checks, start-count bound and exec/exit cleanup loop all pin this literal;
/// they move together or not at all.
pub fn native_slot_bound() -> u32 {
    MAX_SLOTS
}

/// One dense-versus-sparse storage comparison row.
pub struct StorageRow {
    pub cpus: u32,
    pub residency: &'static str,
    pub dense_bytes: u64,
    pub sparse_bytes: u64,
    pub sparse_bound_bytes: u64,
    pub sparse_bounded_non_evicting: bool,
}

/// Right-sized dense versus bounded non-evicting sparse storage model (E11).
///
/// Dense STATS is a per-CPU array: its footprint scales with slots times CPUs
/// regardless of residency. Sparse storage pays per resident entry under a
/// fixed bound and never evicts: over-budget inserts fail with explicit
/// evidence instead of silently dropping a resident entry. Byte counts are a
/// static sizing model from the ABI struct sizes, not live kernel measurements.
pub struct StorageModel;

impl StorageModel {
    /// Sparse residency reference points: idle, E10-style sparse activity
    /// (peak active endpoints below 68), and full budget occupancy.
    const RESIDENCIES: &[(&'static str, u64)] = &[("idle", 0), ("sparse", 68), ("full", u64::MAX)];

    fn compare_for(slots: u64) -> Vec<StorageRow> {
        let mut rows = Vec::new();
        for cpus in [2u32, 12, 64] {
            for (residency, entries) in Self::RESIDENCIES {
                let entries = if *entries == u64::MAX {
                    slots
                } else {
                    *entries
                };
                let dense_bytes =
                    slots * size_of::<p11scope_ebpf_common::SlotStats>() as u64 * u64::from(cpus);
                let entry_bytes = size_of::<p11scope_ebpf_common::SlotStats>() as u64
                    + Self::SPARSE_ENTRY_OVERHEAD;
                rows.push(StorageRow {
                    cpus,
                    residency,
                    dense_bytes,
                    sparse_bytes: entries * entry_bytes,
                    sparse_bound_bytes: slots * entry_bytes,
                    sparse_bounded_non_evicting: true,
                });
            }
        }
        rows
    }

    /// Per-entry sparse overhead model: map key plus hash bookkeeping.
    const SPARSE_ENTRY_OVERHEAD: u64 = 64;

    /// Storage comparison at the production slot budget.
    pub fn compare() -> Vec<StorageRow> {
        Self::compare_for(u64::from(MAX_SLOTS))
    }

    /// Storage comparison at the experimental candidate budget.
    pub fn compare_experimental() -> Vec<StorageRow> {
        Self::compare_for(u64::from(EXPERIMENTAL_SLOT_CANDIDATE))
    }

    /// RV keeps its own key budget, independent of the slot budget.
    pub fn rv_key_budget() -> u64 {
        u64::from(RV_ENTRIES)
    }
}

/// Concurrent first-touch initialization/relookup ledger (E11).
///
/// Exactly one racing caller initializes an absent key; every other caller
/// re-resolves the initialized value. Allocation failure is counted
/// explicitly and never silent. Storage is non-evicting, so a resolved key
/// can never fail relookup for lack of room.
pub struct FirstTouchLedger {
    cap: usize,
    inner: Mutex<HashSet<u64>>,
    initializations: AtomicU64,
    relookups: AtomicU64,
    insert_failures: AtomicU64,
    relookup_failures: AtomicU64,
}

/// Point-in-time first-touch accounting.
pub struct FirstTouchSnapshot {
    pub initializations: u64,
    pub relookups: u64,
    pub insert_failures: u64,
    pub relookup_failures: u64,
}

/// Explicit first-touch allocation refusal.
#[derive(Debug)]
pub struct FirstTouchExhausted {
    pub key: u64,
    pub cap: usize,
}

impl std::fmt::Display for FirstTouchExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (key, cap) = (self.key, self.cap);
        write!(
            f,
            "first-touch budget exhausted: key {key} refused at cap {cap}"
        )
    }
}

impl std::error::Error for FirstTouchExhausted {}

impl FirstTouchLedger {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(HashSet::new()),
            initializations: AtomicU64::new(0),
            relookups: AtomicU64::new(0),
            insert_failures: AtomicU64::new(0),
            relookup_failures: AtomicU64::new(0),
        }
    }

    /// Initialize an absent key or re-resolve a present one. `Ok(true)` is a
    /// first-touch initialization, `Ok(false)` a relookup.
    pub fn first_touch_or_relookup(&self, key: u64) -> Result<bool, FirstTouchExhausted> {
        let mut guard = self.inner.lock().expect("first-touch ledger lock");
        if guard.contains(&key) {
            self.relookups.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        if guard.len() >= self.cap {
            self.insert_failures.fetch_add(1, Ordering::Relaxed);
            return Err(FirstTouchExhausted { key, cap: self.cap });
        }
        guard.insert(key);
        self.initializations.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    pub fn snapshot(&self) -> FirstTouchSnapshot {
        FirstTouchSnapshot {
            initializations: self.initializations.load(Ordering::Relaxed),
            relookups: self.relookups.load(Ordering::Relaxed),
            insert_failures: self.insert_failures.load(Ordering::Relaxed),
            relookup_failures: self.relookup_failures.load(Ordering::Relaxed),
        }
    }
}

/// Slot/token identity policy decision (E10/E12/E20).
///
/// Delayed returns, pending async work and late events can reference a
/// retired slot after its owner is gone. Recycling that slot or a runtime
/// view id into new evidence would misattribute old completions to a new
/// owner, so reclamation epochs are rejected: history is append-only and
/// retired ids stay tombstoned for the capture lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclamationPolicy {
    AppendOnly,
}

pub fn reclamation_policy() -> ReclamationPolicy {
    ReclamationPolicy::AppendOnly
}

/// Append-only historical slot identity allocator.
///
/// Ids increase monotonically and are never reused: [`allocate`](Self::allocate)
/// hands out the next ticket, [`retire`](Self::retire) tombstones it, and
/// [`resolve`](Self::resolve) maps old evidence to the tombstone rather than
/// to whatever a recycled id would now mean.
pub struct SlotIdentityAllocator {
    max_id: u32,
    next: u32,
    retired: BTreeSet<u32>,
}

/// What old evidence sees when it names a slot id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotIdentity {
    Active,
    Retired,
    Unknown,
}

impl SlotIdentity {
    pub fn is_retired(self) -> bool {
        matches!(self, Self::Retired)
    }
}

/// Lifetime identity exhaustion. Always names the resource.
#[derive(Debug, PartialEq, Eq)]
pub enum SlotIdentityError {
    Exhausted { wanted: u32, budget: u32 },
}

impl std::fmt::Display for SlotIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exhausted { wanted, budget } => write!(
                f,
                "slots/lifetime budget exhausted: ticket {wanted} exceeds max id {budget}"
            ),
        }
    }
}

impl std::error::Error for SlotIdentityError {}

impl SlotIdentityAllocator {
    pub fn new(lifetime_max_id: u32) -> Self {
        Self {
            max_id: lifetime_max_id,
            next: 0,
            retired: BTreeSet::new(),
        }
    }

    pub fn allocate(&mut self) -> Result<u32, SlotIdentityError> {
        if self.next > self.max_id {
            return Err(SlotIdentityError::Exhausted {
                wanted: self.next,
                budget: self.max_id,
            });
        }
        let id = self.next;
        self.next += 1;
        Ok(id)
    }

    pub fn retire(&mut self, id: u32) {
        if id < self.next {
            self.retired.insert(id);
        }
    }

    pub fn resolve(&self, id: u32) -> SlotIdentity {
        if id >= self.next {
            SlotIdentity::Unknown
        } else if self.retired.contains(&id) {
            SlotIdentity::Retired
        } else {
            SlotIdentity::Active
        }
    }
}

/// Separated attach, program-load and teardown cost (E05/E11).
///
/// `links` counts one entry-plus-return link pair per admitted endpoint.
/// Sharing map values across endpoints never removes link cost: every
/// endpoint still attaches and detaches its own probes.
pub struct AttachCost {
    pub links: u64,
    pub program_loads: u64,
    pub teardown_steps: u64,
    pub map_value_sharing_removes_link_cost: bool,
}

impl AttachCost {
    pub fn for_endpoints(endpoints: u64) -> Self {
        Self {
            links: endpoints,
            program_loads: u64::from(endpoints > 0) * 2,
            teardown_steps: endpoints * 2,
            map_value_sharing_removes_link_cost: false,
        }
    }
}

/// Published admission envelope. Broader admission stays unqualified.
pub fn admission_envelope() -> String {
    format!(
        "stats_slots={MAX_SLOTS} start_inflight={START_ENTRIES} rv_keys={RV_ENTRIES} \
         descriptors={MAX_DESCRIPTORS} broader_admission=unqualified",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_budget_requires_an_exact_checked_eight_byte_payload() {
        let budget = InventoryBudget::new(64, 512).unwrap();
        assert_eq!(budget.endpoint_limit(), 64);
        assert_eq!(budget.payload_bytes(), 512);
        assert!(InventoryBudget::new(0, 0).is_err());
        assert!(InventoryBudget::new(64, 511).is_err());
        assert!(InventoryBudget::new(64, 513).is_err());
        assert!(InventoryBudget::new(u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn inventory_has_unique_names_and_positive_limits() {
        let mut names = BTreeSet::new();
        for entry in inventory() {
            assert!(
                names.insert(entry.name),
                "duplicate resource {}",
                entry.name
            );
            assert!(entry.limit > 0);
            assert!(!entry.occupancy_source.is_empty());
        }
        assert!(names.len() >= 14);
    }

    #[test]
    fn experimental_comparison_scales_with_candidate_without_qualifying_it() {
        assert!(!broader_admission_qualified());
        let candidate = StorageModel::compare_experimental();
        let production = StorageModel::compare();
        assert_eq!(candidate.len(), production.len());
        for (candidate_row, production_row) in candidate.iter().zip(production.iter()) {
            assert_eq!(candidate_row.cpus, production_row.cpus);
            assert_eq!(candidate_row.residency, production_row.residency);
            assert!(candidate_row.sparse_bound_bytes > production_row.sparse_bound_bytes);
            assert!(candidate_row.sparse_bytes <= candidate_row.sparse_bound_bytes);
            assert!(candidate_row.sparse_bounded_non_evicting);
        }
        let full_64 = candidate
            .iter()
            .find(|row| row.cpus == 64 && row.residency == "full")
            .expect("candidate full-residency row at 64 CPUs");
        let expected_dense = u64::from(EXPERIMENTAL_SLOT_CANDIDATE)
            * size_of::<p11scope_ebpf_common::SlotStats>() as u64
            * 64;
        assert_eq!(full_64.dense_bytes, expected_dense);
    }

    #[test]
    fn allocator_retire_is_idempotent_and_unknown_stays_unknown() {
        let mut allocator = SlotIdentityAllocator::new(1);
        assert_eq!(allocator.resolve(9), SlotIdentity::Unknown);
        allocator.retire(9);
        assert_eq!(allocator.resolve(9), SlotIdentity::Unknown);
        assert_eq!(allocator.allocate(), Ok(0));
        allocator.retire(0);
        allocator.retire(0);
        assert_eq!(allocator.resolve(0), SlotIdentity::Retired);
        assert_eq!(allocator.allocate(), Ok(1));
        assert_eq!(allocator.resolve(1), SlotIdentity::Active);
        assert!(matches!(
            allocator.allocate(),
            Err(SlotIdentityError::Exhausted { .. })
        ));
    }

    #[test]
    fn ledger_is_send_and_sync_for_concurrent_first_touch() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FirstTouchLedger>();
    }
}
