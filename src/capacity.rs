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
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::mem::size_of;
use std::sync::{
    Mutex, RwLock, RwLockReadGuard,
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
    /// The ticket was consumed but storage creation failed, so no live
    /// identity ever existed for it. Distinct from [`SlotIdentity::Active`]:
    /// callers must not treat it as live, and [`TicketAllocator::retire`]
    /// leaves it untouched (nothing to tombstone).
    ConsumedWithoutIdentity,
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

/// Task 7 (finish plan): adaptive capacity, sustained identity, bounded history.
///
/// Candidate A core: the identity-ticket namespace is already u64 end to end
/// (native `cookie_for`, `ImageIdentity.task_cookie`, `COOKIE_CTL`), with
/// cookie 0 reserved and 16,384 enforced as an explicit policy comparison.
/// These types version that policy, mirror the allocator semantics
/// (monotonic, no reuse, quota/create/retry accounting) and add the separate
/// live-admission accounting candidate A owes. Candidates B (bounded overlap)
/// and C (stable identity plus replaceable evidence) are modeled with their
/// own transition proofs so the comparison runs all three on one workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketPolicy {
    limit: u64,
    version: u32,
}

impl TicketPolicy {
    /// Version 1 is the C1 policy: exactly the historical 16,384 lifetime
    /// bound. This is the default until a reviewed migration selects wider.
    pub const fn v1_c1() -> Self {
        Self {
            limit: IMAGE_IDENTITY_TICKET_LIMIT,
            version: 1,
        }
    }

    /// A reviewed wider (or equal) namespace. Version 0 is reserved; version 1
    /// is exactly the C1 bound; version 2+ carries an explicit reviewed limit.
    pub fn reviewed(limit: u64, version: u32) -> Result<Self, String> {
        if version == 0 {
            return Err("ticket policy version 0 is reserved".into());
        }
        if limit == 0 {
            return Err("ticket policy limit must be non-zero".into());
        }
        if version == 1 && limit != IMAGE_IDENTITY_TICKET_LIMIT {
            return Err(format!(
                "ticket policy v1 is exactly the C1 bound {IMAGE_IDENTITY_TICKET_LIMIT}, not {limit}"
            ));
        }
        Ok(Self { limit, version })
    }

    pub const fn limit(self) -> u64 {
        self.limit
    }

    pub const fn version(self) -> u32 {
        self.version
    }

    /// The exact `COOKIE_CTL` image this policy publishes at load: the limit
    /// with every counter at zero. Pure loader seam; the loader calls this
    /// instead of spelling the constant, so a policy migration is one call
    /// site plus the native/config review.
    pub fn control_image(self) -> p11scope_ebpf_common::ImageIdentityControl {
        p11scope_ebpf_common::ImageIdentityControl {
            limit: self.limit,
            ..Default::default()
        }
    }

    /// Policy-parameterized freshness check mirroring
    /// `attach::inventory::callers::validate_caller_control` for v1.
    pub fn validate_control(
        control: &p11scope_ebpf_common::ImageIdentityControl,
        policy: TicketPolicy,
    ) -> Result<(), String> {
        if control.limit != policy.limit
            || control.next_ticket != 0
            || control.unavailable != 0
            || control.create_failures != 0
            || control.retry_exhausted != 0
        {
            return Err(format!(
                "COOKIE_CTL is not a fresh caller identity control for ticket policy v{}",
                policy.version
            ));
        }
        Ok(())
    }
}

/// CAS attempts per allocation. Mirrors native `COOKIE_CAS_TRIES`.
pub const TICKET_CAS_TRIES: u32 = 8;

/// Scripted allocator fault, mirroring one native failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedFault {
    /// Another racing caller won the ticket CAS; burns one attempt.
    CasContention,
    /// The ticket CAS won but task-storage creation failed; the ticket is
    /// consumed exactly like native and no identity exists for it.
    CreateFailed,
}

/// Ordered fault script consumed by [`TicketAllocator::allocate_with_faults`].
pub struct FaultScript {
    script: Vec<InjectedFault>,
    cursor: usize,
}

impl FaultScript {
    pub fn new(script: Vec<InjectedFault>) -> Self {
        Self { script, cursor: 0 }
    }

    fn next_fault(&mut self) -> Option<InjectedFault> {
        let fault = self.script.get(self.cursor).copied();
        if fault.is_some() {
            self.cursor += 1;
        }
        fault
    }
}

/// Ticket allocation refusal. Always names the resource.
#[derive(Debug, PartialEq, Eq)]
pub enum TicketError {
    Quota { wanted_cookie: u64, limit: u64 },
    CreateFailed { consumed_cookie: u64 },
    RetryExhausted,
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quota {
                wanted_cookie,
                limit,
            } => write!(
                f,
                "identity tickets exhausted: cookie {wanted_cookie} exceeds limit {limit}"
            ),
            Self::CreateFailed { consumed_cookie } => write!(
                f,
                "identity tickets storage creation failed: ticket for cookie {consumed_cookie} consumed without an identity"
            ),
            Self::RetryExhausted => write!(
                f,
                "identity tickets CAS retry exhausted after {TICKET_CAS_TRIES} attempts"
            ),
        }
    }
}

impl std::error::Error for TicketError {}

/// Cumulative ticket accounting: attempts, admissions and every refusal mode.
pub struct TicketAccounting {
    pub attempted: u64,
    pub admitted: u64,
    pub quota_refusals: u64,
    pub create_failures: u64,
    pub retries_exhausted: u64,
    pub live_unretired: u64,
    pub next_ticket: u64,
}

/// Monotonic u64 ticket allocator mirroring native `cookie_for`.
///
/// Internal tickets run `0..limit`; the issued cookie is ticket + 1, so
/// cookie 0 stays reserved and cookies run `1..=limit`. Allocation never
/// reuses a cookie, retired or failed: a consumed ticket is gone. The wanted
/// cookie saturates instead of wrapping near u64::MAX, so exhaustion fails
/// closed before any arithmetic wrap.
pub struct TicketAllocator {
    policy: TicketPolicy,
    next_ticket: u64,
    retired: BTreeSet<u64>,
    consumed_without_identity: BTreeSet<u64>,
    attempted: u64,
    admitted: u64,
    quota_refusals: u64,
    create_failures: u64,
    retries_exhausted: u64,
}

impl TicketAllocator {
    pub fn new(policy: TicketPolicy) -> Self {
        Self {
            policy,
            next_ticket: 0,
            retired: BTreeSet::new(),
            consumed_without_identity: BTreeSet::new(),
            attempted: 0,
            admitted: 0,
            quota_refusals: 0,
            create_failures: 0,
            retries_exhausted: 0,
        }
    }

    /// Restore the allocator counter after restart or policy migration.
    /// Every replayed tombstone must name an issued cookie; anything else
    /// fails closed rather than inventing history.
    pub fn restore(
        policy: TicketPolicy,
        next_ticket: u64,
        retired: &[u64],
    ) -> Result<Self, String> {
        if next_ticket > policy.limit {
            return Err(format!(
                "restored ticket counter {next_ticket} exceeds policy limit {}",
                policy.limit
            ));
        }
        let mut tombstones = BTreeSet::new();
        for cookie in retired {
            if *cookie == 0 || *cookie > next_ticket {
                return Err(format!(
                    "restored tombstone {cookie} names no issued cookie below counter {next_ticket}"
                ));
            }
            tombstones.insert(*cookie);
        }
        Ok(Self {
            policy,
            next_ticket,
            retired: tombstones,
            // Restart replay recovers the counter and tombstones only; prior
            // create-failure identities are not distinguished from Active
            // after a restart (native keeps that count in COOKIE_CTL, which
            // the loader seam replays separately). Live accounting proof is
            // controller cell L-T7-7.
            consumed_without_identity: BTreeSet::new(),
            attempted: 0,
            admitted: 0,
            quota_refusals: 0,
            create_failures: 0,
            retries_exhausted: 0,
        })
    }

    pub fn policy(&self) -> TicketPolicy {
        self.policy
    }

    pub fn allocate(&mut self) -> Result<u64, TicketError> {
        self.attempted += 1;
        if self.next_ticket >= self.policy.limit {
            self.quota_refusals += 1;
            return Err(TicketError::Quota {
                wanted_cookie: self.next_ticket.saturating_add(1),
                limit: self.policy.limit,
            });
        }
        let cookie = self
            .next_ticket
            .checked_add(1)
            .expect("ticket below the limit always has a successor cookie");
        self.next_ticket += 1;
        self.admitted += 1;
        Ok(cookie)
    }

    /// Allocate under a scripted contention/failure workload. CAS contention
    /// burns attempts up to [`TICKET_CAS_TRIES`]; a create failure consumes
    /// one ticket exactly like native and reports it.
    pub fn allocate_with_faults(&mut self, faults: &mut FaultScript) -> Result<u64, TicketError> {
        let mut attempts = 0;
        loop {
            match faults.next_fault() {
                None => return self.allocate(),
                Some(InjectedFault::CasContention) => {
                    attempts += 1;
                    if attempts >= TICKET_CAS_TRIES {
                        self.attempted += 1;
                        self.retries_exhausted += 1;
                        return Err(TicketError::RetryExhausted);
                    }
                }
                Some(InjectedFault::CreateFailed) => {
                    self.attempted += 1;
                    if self.next_ticket >= self.policy.limit {
                        self.quota_refusals += 1;
                        return Err(TicketError::Quota {
                            wanted_cookie: self.next_ticket.saturating_add(1),
                            limit: self.policy.limit,
                        });
                    }
                    let cookie = self
                        .next_ticket
                        .checked_add(1)
                        .expect("ticket below the limit always has a successor cookie");
                    self.next_ticket += 1;
                    self.create_failures += 1;
                    self.consumed_without_identity.insert(cookie);
                    return Err(TicketError::CreateFailed {
                        consumed_cookie: cookie,
                    });
                }
            }
        }
    }

    pub fn retire(&mut self, cookie: u64) {
        if cookie != 0
            && cookie <= self.next_ticket
            && !self.consumed_without_identity.contains(&cookie)
        {
            self.retired.insert(cookie);
        }
    }

    pub fn resolve(&self, cookie: u64) -> SlotIdentity {
        if cookie == 0 || cookie > self.next_ticket {
            SlotIdentity::Unknown
        } else if self.consumed_without_identity.contains(&cookie) {
            SlotIdentity::ConsumedWithoutIdentity
        } else if self.retired.contains(&cookie) {
            SlotIdentity::Retired
        } else {
            SlotIdentity::Active
        }
    }

    pub fn accounting(&self) -> TicketAccounting {
        TicketAccounting {
            attempted: self.attempted,
            admitted: self.admitted,
            quota_refusals: self.quota_refusals,
            create_failures: self.create_failures,
            retries_exhausted: self.retries_exhausted,
            live_unretired: self
                .next_ticket
                .saturating_sub(self.retired.len() as u64)
                .saturating_sub(self.consumed_without_identity.len() as u64),
            next_ticket: self.next_ticket,
        }
    }
}

/// Live-admission refusal. Always names the resource.
#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionError {
    LiveBudgetExhausted { cookie: u64, cap: usize },
    DuplicateReservation { cookie: u64 },
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LiveBudgetExhausted { cookie, cap } => write!(
                f,
                "live admissions exhausted: cookie {cookie} refused at cap {cap}"
            ),
            Self::DuplicateReservation { cookie } => write!(
                f,
                "live admissions duplicate reservation for cookie {cookie}"
            ),
        }
    }
}

impl std::error::Error for AdmissionError {}

/// Cumulative live-admission accounting, separate from ticket accounting.
pub struct LiveAccounting {
    pub admitted_total: u64,
    pub refused_total: u64,
    pub rollbacks: u64,
    pub releases: u64,
    pub live: usize,
    pub peak_live: usize,
}

/// A reservation that a failed creation can still roll back. Opaque: only
/// [`LiveAdmission`] mints it, and `admit`/`rollback` consume it.
#[derive(Debug)]
pub struct AdmissionReservation {
    cookie: u64,
}

/// Proof that live storage for the cookie exists. Only this token releases
/// the admission: a lossy exit hint or a bare cookie cannot free the budget.
#[derive(Debug)]
pub struct StorageToken {
    cookie: u64,
}

/// Candidate A live-admission accounting, independent of the ticket
/// namespace. Reserve-then-admit lets a failed creation roll its reservation
/// back instead of leaking budget; release requires the storage token tied
/// to actual storage/task lifetime.
pub struct LiveAdmission {
    cap: usize,
    reserved: BTreeSet<u64>,
    live: BTreeSet<u64>,
    peak_live: usize,
    admitted_total: u64,
    refused_total: u64,
    rollbacks: u64,
    releases: u64,
}

impl LiveAdmission {
    pub fn new(cap: usize) -> Result<Self, String> {
        if cap == 0 {
            return Err("live admission cap must be non-zero".into());
        }
        Ok(Self {
            cap,
            reserved: BTreeSet::new(),
            live: BTreeSet::new(),
            peak_live: 0,
            admitted_total: 0,
            refused_total: 0,
            rollbacks: 0,
            releases: 0,
        })
    }

    pub fn reserve(&mut self, cookie: u64) -> Result<AdmissionReservation, AdmissionError> {
        if self.reserved.contains(&cookie) || self.live.contains(&cookie) {
            return Err(AdmissionError::DuplicateReservation { cookie });
        }
        if self.reserved.len() + self.live.len() >= self.cap {
            self.refused_total += 1;
            return Err(AdmissionError::LiveBudgetExhausted {
                cookie,
                cap: self.cap,
            });
        }
        self.reserved.insert(cookie);
        Ok(AdmissionReservation { cookie })
    }

    pub fn admit(&mut self, reservation: AdmissionReservation) -> StorageToken {
        assert!(
            self.reserved.remove(&reservation.cookie),
            "admission reservation must be outstanding"
        );
        self.live.insert(reservation.cookie);
        self.admitted_total += 1;
        self.peak_live = self.peak_live.max(self.live.len());
        StorageToken {
            cookie: reservation.cookie,
        }
    }

    pub fn rollback(&mut self, reservation: AdmissionReservation) {
        assert!(
            self.reserved.remove(&reservation.cookie),
            "rolled-back reservation must be outstanding"
        );
        self.rollbacks += 1;
    }

    pub fn release(&mut self, token: StorageToken) {
        assert!(
            self.live.remove(&token.cookie),
            "released token must name a live admission"
        );
        self.releases += 1;
    }

    pub fn live_count(&self) -> usize {
        self.live.len()
    }

    pub fn accounting(&self) -> LiveAccounting {
        LiveAccounting {
            admitted_total: self.admitted_total,
            refused_total: self.refused_total,
            rollbacks: self.rollbacks,
            releases: self.releases,
            live: self.live.len(),
            peak_live: self.peak_live,
        }
    }
}

/// Which side of an overlap a cookie belongs to. History stays
/// domain-qualified: equal numeric cookies on the two sides never merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSide {
    Old,
    New,
}

/// Candidate B transition refusal.
#[derive(Debug, PartialEq, Eq)]
pub enum OverlapError {
    OverlapInProgress,
    OldDomainStillProducing,
    TerminalEvidenceUnacked,
}

impl std::fmt::Display for OverlapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverlapInProgress => {
                f.write_str("identity domains: overlap already in progress; no unbounded chain")
            }
            Self::OldDomainStillProducing => {
                f.write_str("identity domains: old domain still producing; seal it before closing")
            }
            Self::TerminalEvidenceUnacked => {
                f.write_str("identity domains: old domain terminal evidence lacks a durable ack")
            }
        }
    }
}

impl std::error::Error for OverlapError {}

/// Custody receipt for a closed old domain.
#[derive(Debug, PartialEq, Eq)]
pub struct ClosedDomain {
    pub retired_cookies: u64,
    pub aliases_preserved: usize,
}

/// Candidate B: at most two overlapping identity domains. Opening the new
/// domain doubles transient link/map/reader cost (`link_factor` 2) until the
/// old domain is sealed, its terminal evidence acked, and it closes. Same
/// tasks alive across the rollover need explicit cross-domain aliases; the
/// alias map is part of the cost this candidate pays.
pub struct OverlapPair {
    old: TicketAllocator,
    new: Option<TicketAllocator>,
    aliases: BTreeMap<u64, u64>,
    old_sealed: bool,
    terminal_ack: Option<DurableAck>,
}

impl OverlapPair {
    pub fn single(policy: TicketPolicy) -> Self {
        Self {
            old: TicketAllocator::new(policy),
            new: None,
            aliases: BTreeMap::new(),
            old_sealed: false,
            terminal_ack: None,
        }
    }

    /// New arrivals use the new domain once it exists; otherwise the old one.
    pub fn allocate(&mut self) -> (DomainSide, Result<u64, TicketError>) {
        match self.new.as_mut() {
            Some(new) => (DomainSide::New, new.allocate()),
            None => (DomainSide::Old, self.old.allocate()),
        }
    }

    pub fn retire(&mut self, side: DomainSide, cookie: u64) {
        match (side, self.new.as_mut()) {
            (DomainSide::New, Some(new)) => new.retire(cookie),
            _ => self.old.retire(cookie),
        }
    }

    pub fn begin_overlap(&mut self, policy: TicketPolicy) -> Result<(), OverlapError> {
        if self.new.is_some() {
            return Err(OverlapError::OverlapInProgress);
        }
        self.new = Some(TicketAllocator::new(policy));
        Ok(())
    }

    /// Record that the same task holds `old_cookie` on the old domain and
    /// `new_cookie` on the new one. Explicit by construction: never derived
    /// from PID/starttime.
    pub fn alias_same_task(&mut self, old_cookie: u64, new_cookie: u64) {
        self.aliases.insert(old_cookie, new_cookie);
    }

    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }

    /// Transient cost factor: 2 while two domains are attached, else 1.
    pub fn link_factor(&self) -> u64 {
        u64::from(self.new.is_some()) + 1
    }

    pub fn seal_old_domain(&mut self) {
        self.old_sealed = true;
    }

    pub fn ack_old_terminal(&mut self, ack: DurableAck) {
        self.terminal_ack = Some(ack);
    }

    pub fn close_old_domain(&mut self) -> Result<ClosedDomain, OverlapError> {
        if !self.old_sealed {
            return Err(OverlapError::OldDomainStillProducing);
        }
        if self.terminal_ack.is_none() {
            return Err(OverlapError::TerminalEvidenceUnacked);
        }
        let Some(new) = self.new.take() else {
            return Err(OverlapError::OldDomainStillProducing);
        };
        let retired_cookies = self.old.accounting().admitted;
        self.old = new;
        self.old_sealed = false;
        self.terminal_ack = None;
        Ok(ClosedDomain {
            retired_cookies,
            aliases_preserved: self.aliases.len(),
        })
    }
}

/// Candidate C store-transition refusal.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    RotationInProgress,
    WriterCountMismatch {
        at_seal: u64,
        redirected: u64,
    },
    UnackedRelease {
        covered_through: u64,
        needed_through: u64,
    },
    NothingToRelease,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RotationInProgress => f.write_str(
                "evidence store: a retired store is still unreleased; no rotation chain",
            ),
            Self::WriterCountMismatch {
                at_seal,
                redirected,
            } => write!(
                f,
                "evidence store: {redirected} writers redirected but {at_seal} were live at seal"
            ),
            Self::UnackedRelease {
                covered_through,
                needed_through,
            } => write!(
                f,
                "evidence store: ack covers record {covered_through} but release needs {needed_through}"
            ),
            Self::NothingToRelease => f.write_str("evidence store: no retired store to release"),
        }
    }
}

impl std::error::Error for StoreError {}

/// A sealed retired evidence store awaiting writer proof and a covering ack.
#[derive(Debug)]
pub struct SealedStore {
    pub epoch: u64,
    pub base_id: u64,
    pub records: u64,
    pub writers_at_seal: u64,
}

/// Candidate C: stable identity with a separately replaceable evidence
/// store. Rotation seals the active store and opens a new epoch; the retired
/// store releases only after an exact writer-redirection proof plus a
/// durable ack covering every retired record. At most one retired store
/// pends at a time.
pub struct EvidenceRotation {
    active_epoch: u64,
    active_next_id: u64,
    active_records: u64,
    retired: Option<SealedStore>,
    redirected: Option<u64>,
}

impl EvidenceRotation {
    pub fn new() -> Self {
        Self {
            active_epoch: 0,
            active_next_id: 0,
            active_records: 0,
            retired: None,
            redirected: None,
        }
    }

    pub fn append(&mut self, records: u64) {
        self.active_next_id += records;
        self.active_records += records;
    }

    pub fn rotate(&mut self, writers_at_seal: u64) -> Result<(), StoreError> {
        if self.retired.is_some() {
            return Err(StoreError::RotationInProgress);
        }
        let base_id = self.active_next_id - self.active_records;
        self.retired = Some(SealedStore {
            epoch: self.active_epoch,
            base_id,
            records: self.active_records,
            writers_at_seal,
        });
        self.active_epoch += 1;
        self.active_records = 0;
        self.redirected = None;
        Ok(())
    }

    pub fn redirect_writers(&mut self, redirected: u64) -> Result<(), StoreError> {
        let Some(retired) = self.retired.as_ref() else {
            return Err(StoreError::NothingToRelease);
        };
        if redirected != retired.writers_at_seal {
            return Err(StoreError::WriterCountMismatch {
                at_seal: retired.writers_at_seal,
                redirected,
            });
        }
        self.redirected = Some(redirected);
        Ok(())
    }

    pub fn release_retired(&mut self, ack: &DurableAck) -> Result<SealedStore, StoreError> {
        let Some(retired) = self.retired.as_ref() else {
            return Err(StoreError::NothingToRelease);
        };
        if self.redirected != Some(retired.writers_at_seal) {
            return Err(StoreError::WriterCountMismatch {
                at_seal: retired.writers_at_seal,
                redirected: self.redirected.unwrap_or(0),
            });
        }
        let needed = retired.base_id + retired.records.saturating_sub(1);
        if ack.through_id < needed {
            return Err(StoreError::UnackedRelease {
                covered_through: ack.through_id,
                needed_through: needed,
            });
        }
        self.redirected = None;
        Ok(self.retired.take().expect("retired store checked above"))
    }
}

/// Initial outer-directory bound for the segment experiment: the outer map
/// capacity is a pre-creation choice, and raising this needs the live
/// directory-exhaustion cell, not an assumption.
pub const MAX_SEGMENTS: u32 = 16;

/// Inner-map kind. Compatible inners share kind plus key/value shape; the
/// kernel checks shape, not per-segment `max_entries`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerMapKind {
    PerCpuArray,
    Hash,
}

/// Compatible inner-map shape for one appended endpoint segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentSpec {
    pub kind: InnerMapKind,
    pub key_bytes: u32,
    pub value_bytes: u32,
    pub max_entries: u32,
}

impl SegmentSpec {
    pub fn compatible_with(self, other: SegmentSpec) -> bool {
        self.kind == other.kind
            && self.key_bytes == other.key_bytes
            && self.value_bytes == other.value_bytes
    }
}

/// Segment-directory refusal. Always names the resource.
#[derive(Debug, PartialEq, Eq)]
pub enum SegmentError {
    DirectoryFull { cap: u32 },
    IncompatibleSpec,
    EmptySegment,
    LengthOverflow,
    UnknownEndpoint { endpoint: u64 },
}

impl std::fmt::Display for SegmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectoryFull { cap } => {
                write!(
                    f,
                    "segment directory exhausted: no room beyond {cap} segments"
                )
            }
            Self::IncompatibleSpec => {
                f.write_str("segment directory: inner map shape differs from the directory spec")
            }
            Self::EmptySegment => {
                f.write_str("segment directory: appended segment must be non-empty")
            }
            Self::LengthOverflow => {
                f.write_str("segment directory: endpoint base plus length overflowed")
            }
            Self::UnknownEndpoint { endpoint } => {
                write!(f, "segment directory: endpoint {endpoint} is in no segment")
            }
        }
    }
}

impl std::error::Error for SegmentError {}

struct AppendedSegment {
    base: u64,
    len: u32,
    value_bytes: u64,
}

/// Static per-operation cost of the directory layout: outer plus inner
/// lookups, FDs, per-CPU payload bytes and link pairs, plus the static
/// allocation/publication counts (one inner creation and one outer-map
/// publication per appended segment). A sizing model like [`StorageModel`],
/// not a live kernel measurement: lookup latency, allocation timing and
/// publication syscall deltas stay live-only under controller cell L-T7-9.
pub struct SegmentCost {
    pub outer_lookups_per_op: u32,
    pub inner_lookups_per_op: u32,
    pub fds: u64,
    pub per_cpu_payload_bytes: u64,
    pub link_pairs: u64,
    pub inner_creations: u64,
    pub outer_publications: u64,
}

/// Appended endpoint segments in an outer directory. Segments only append:
/// existing observations never migrate, and no live segment is replaced.
/// Routing resolves a capture-local endpoint ID to its `(segment, index)`.
pub struct SegmentDirectory {
    cap: u32,
    spec: Option<SegmentSpec>,
    segments: Vec<AppendedSegment>,
    next_base: u64,
}

impl SegmentDirectory {
    pub fn new(cap: u32) -> Result<Self, String> {
        if cap == 0 || cap > MAX_SEGMENTS {
            return Err(format!(
                "segment directory cap {cap} must be within 1..={MAX_SEGMENTS}"
            ));
        }
        Ok(Self {
            cap,
            spec: None,
            segments: Vec::new(),
            next_base: 0,
        })
    }

    pub fn append(&mut self, spec: SegmentSpec, len: u32) -> Result<u32, SegmentError> {
        if self.segments.len() >= self.cap as usize {
            return Err(SegmentError::DirectoryFull { cap: self.cap });
        }
        if len == 0 {
            return Err(SegmentError::EmptySegment);
        }
        if let Some(first) = self.spec
            && !first.compatible_with(spec)
        {
            return Err(SegmentError::IncompatibleSpec);
        }
        let base = self.next_base;
        self.next_base = base
            .checked_add(u64::from(len))
            .ok_or(SegmentError::LengthOverflow)?;
        let id = self.segments.len() as u32;
        self.segments.push(AppendedSegment {
            base,
            len,
            value_bytes: u64::from(spec.value_bytes),
        });
        if self.spec.is_none() {
            self.spec = Some(spec);
        }
        Ok(id)
    }

    pub fn resolve(&self, endpoint: u64) -> Option<(u32, u32)> {
        for (id, segment) in self.segments.iter().enumerate() {
            let end = segment.base + u64::from(segment.len);
            if endpoint >= segment.base && endpoint < end {
                let index = u32::try_from(endpoint - segment.base)
                    .expect("segment-relative index fits its u32 length");
                return Some((id as u32, index));
            }
        }
        None
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn total_endpoints(&self) -> u64 {
        self.next_base
    }

    /// Cross-segment operation identity: the operation must name exactly the
    /// segments it touches, and every endpoint must resolve.
    pub fn check_cross_segment(&self, endpoints: &[u64]) -> Result<Vec<u32>, SegmentError> {
        let mut touched = BTreeSet::new();
        for endpoint in endpoints {
            let Some((segment, _)) = self.resolve(*endpoint) else {
                return Err(SegmentError::UnknownEndpoint {
                    endpoint: *endpoint,
                });
            };
            touched.insert(segment);
        }
        Ok(touched.into_iter().collect())
    }

    pub fn cost(&self, cpus: u32) -> SegmentCost {
        let payload: u64 = self
            .segments
            .iter()
            .map(|segment| u64::from(segment.len) * segment.value_bytes)
            .sum();
        SegmentCost {
            outer_lookups_per_op: 1,
            inner_lookups_per_op: 1,
            fds: 1 + self.segments.len() as u64,
            per_cpu_payload_bytes: payload.saturating_mul(u64::from(cpus)),
            link_pairs: self.next_base,
            inner_creations: self.segments.len() as u64,
            outer_publications: self.segments.len() as u64,
        }
    }
}

/// Live-counter replacement refusal: writers were active, so the cell is untouched.
#[derive(Debug, PartialEq, Eq)]
pub enum CounterError {
    WritersActive { in_flight: u64 },
}

impl CounterError {
    pub fn in_flight(&self) -> u64 {
        match self {
            Self::WritersActive { in_flight } => *in_flight,
        }
    }
}

impl std::fmt::Display for CounterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WritersActive { in_flight } => write!(
                f,
                "live counter replace refused: {in_flight} writers in flight"
            ),
        }
    }
}

impl std::error::Error for CounterError {}

/// Live-writer fence for one counter cell. Writers hold a read guard across
/// their increment; replacement takes the write lock, so a successful swap
/// observes every increment sequenced before it and no increment is lost.
pub struct WriterSet {
    lock: RwLock<()>,
    in_flight: AtomicU64,
}

/// RAII live-writer guard. Dropping it ends the writer's critical section.
pub struct WriterGuard<'a> {
    _guard: RwLockReadGuard<'a, ()>,
    in_flight: &'a AtomicU64,
}

impl Drop for WriterGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl WriterSet {
    pub fn new() -> Self {
        Self {
            lock: RwLock::new(()),
            in_flight: AtomicU64::new(0),
        }
    }

    pub fn hold(&self) -> WriterGuard<'_> {
        let guard = self.lock.read().expect("writer set lock");
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        WriterGuard {
            _guard: guard,
            in_flight: &self.in_flight,
        }
    }

    pub fn quiesced(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst) == 0
    }

    fn in_flight_count(&self) -> u64 {
        self.in_flight.load(Ordering::SeqCst)
    }
}

/// One live counter cell. Replacement without a proven writer transition is
/// refused; a refused replace touches nothing.
pub struct CounterCell {
    value: AtomicU64,
}

impl CounterCell {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::SeqCst);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }

    /// Swap the cell only when no writer is active. Returns the exact old
    /// value, so every increment lands either in a returned old value or in
    /// the cell: no replacement loses a concurrent increment.
    pub fn try_replace_quiesced(&self, new: u64, writers: &WriterSet) -> Result<u64, CounterError> {
        match writers.lock.try_write() {
            Ok(_held) => Ok(self.value.swap(new, Ordering::SeqCst)),
            Err(_) => Err(CounterError::WritersActive {
                in_flight: writers.in_flight_count(),
            }),
        }
    }
}

/// Exact allocation lifecycle. Reserved -> Initialized/readback -> Published
/// -> ProducersEnabled -> Retired/Quarantined -> SettlementAcked. Partial
/// attach or readback failure quarantines from Initialized or Published;
/// nothing leaves Quarantined except toward settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocState {
    Reserved,
    Initialized,
    Published,
    ProducersEnabled,
    Retired,
    Quarantined,
    SettlementAcked,
}

/// Illegal allocation transition. The allocation keeps its prior state and
/// payload: failure preserves prior data.
#[derive(Debug, PartialEq, Eq)]
pub struct AllocTransitionError {
    pub from: AllocState,
    pub to: AllocState,
}

impl std::fmt::Display for AllocTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "allocation transition {:?} -> {:?} is illegal",
            self.from, self.to
        )
    }
}

impl std::error::Error for AllocTransitionError {}

/// One allocation moving through [`AllocState`]. `payload_bytes` stands for
/// the prior data a failed transition must preserve.
pub struct Allocation {
    id: u64,
    state: AllocState,
    payload_bytes: u64,
}

impl Allocation {
    pub fn reserve(id: u64, payload_bytes: u64) -> Self {
        Self {
            id,
            state: AllocState::Reserved,
            payload_bytes,
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn state(&self) -> AllocState {
        self.state
    }

    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn transition(&mut self, to: AllocState) -> Result<(), AllocTransitionError> {
        let legal = matches!(
            (self.state, to),
            (AllocState::Reserved, AllocState::Initialized)
                | (AllocState::Initialized, AllocState::Published)
                | (AllocState::Initialized, AllocState::Quarantined)
                | (AllocState::Published, AllocState::ProducersEnabled)
                | (AllocState::Published, AllocState::Quarantined)
                | (AllocState::ProducersEnabled, AllocState::Retired)
                | (AllocState::ProducersEnabled, AllocState::Quarantined)
                | (AllocState::Retired, AllocState::SettlementAcked)
                | (AllocState::Quarantined, AllocState::SettlementAcked)
        );
        if !legal {
            return Err(AllocTransitionError {
                from: self.state,
                to,
            });
        }
        self.state = to;
        Ok(())
    }
}

/// RAM, history or disk budget refusal. Always names the resource.
#[derive(Debug, PartialEq, Eq)]
pub enum BudgetError {
    RamExhausted { wanted: u64, available: u64 },
    HistoryExhausted { wanted: u64, cap: u64 },
    DiskExhausted { wanted: u64, available: u64 },
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RamExhausted { wanted, available } => write!(
                f,
                "RAM budget exhausted: wanted {wanted} bytes with {available} available"
            ),
            Self::HistoryExhausted { wanted, cap } => write!(
                f,
                "history budget exhausted: wanted {wanted} records at cap {cap}"
            ),
            Self::DiskExhausted { wanted, available } => write!(
                f,
                "disk budget exhausted: wanted {wanted} bytes with {available} available"
            ),
        }
    }
}

impl std::error::Error for BudgetError {}

/// Live RAM byte budget with peak tracking.
pub struct RamBudget {
    limit: u64,
    current: u64,
    peak: u64,
}

impl RamBudget {
    pub fn new(limit: u64) -> Result<Self, String> {
        if limit == 0 {
            return Err("RAM budget must be non-zero".into());
        }
        Ok(Self {
            limit,
            current: 0,
            peak: 0,
        })
    }

    pub fn acquire(&mut self, bytes: u64) -> Result<(), BudgetError> {
        if bytes > self.limit - self.current {
            return Err(BudgetError::RamExhausted {
                wanted: bytes,
                available: self.limit - self.current,
            });
        }
        self.current += bytes;
        self.peak = self.peak.max(self.current);
        Ok(())
    }

    pub fn release(&mut self, bytes: u64) {
        self.current = self.current.saturating_sub(bytes);
    }

    pub fn current(&self) -> u64 {
        self.current
    }

    pub fn peak(&self) -> u64 {
        self.peak
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

/// Retained-history record budget, independent of live RAM.
pub struct HistoryBudget {
    cap: u64,
    current: u64,
    peak: u64,
}

impl HistoryBudget {
    pub fn new(cap: u64) -> Result<Self, String> {
        if cap == 0 {
            return Err("history budget must be non-zero".into());
        }
        Ok(Self {
            cap,
            current: 0,
            peak: 0,
        })
    }

    pub fn acquire_records(&mut self, records: u64) -> Result<(), BudgetError> {
        if records > self.cap - self.current {
            return Err(BudgetError::HistoryExhausted {
                wanted: records,
                cap: self.cap,
            });
        }
        self.current += records;
        self.peak = self.peak.max(self.current);
        Ok(())
    }

    pub fn release_records(&mut self, records: u64) {
        self.current = self.current.saturating_sub(records);
    }

    pub fn current(&self) -> u64 {
        self.current
    }

    pub fn peak(&self) -> u64 {
        self.peak
    }

    pub fn cap(&self) -> u64 {
        self.cap
    }
}

/// Durable-sink disk byte budget with full-sink refusal semantics.
pub struct DiskBudget {
    limit: u64,
    used: u64,
    peak: u64,
}

impl DiskBudget {
    pub fn new(limit: u64) -> Result<Self, String> {
        if limit == 0 {
            return Err("disk budget must be non-zero".into());
        }
        Ok(Self {
            limit,
            used: 0,
            peak: 0,
        })
    }

    pub fn acquire(&mut self, bytes: u64) -> Result<(), BudgetError> {
        if bytes > self.limit - self.used {
            return Err(BudgetError::DiskExhausted {
                wanted: bytes,
                available: self.limit - self.used,
            });
        }
        self.used += bytes;
        self.peak = self.peak.max(self.used);
        Ok(())
    }

    pub fn release(&mut self, bytes: u64) {
        self.used = self.used.saturating_sub(bytes);
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    pub fn available(&self) -> u64 {
        self.limit - self.used
    }

    pub fn peak(&self) -> u64 {
        self.peak
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

/// Stable export record identifier. IDs are assigned once, never reused, and
/// survive crash/replay: a re-staged batch carries the same IDs.
pub type RecordId = u64;

/// What one export record carries. Omission history travels with positives
/// and counters: publication stages the whole pending set, never a subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    PositiveEvidence,
    CounterSnapshot,
    OmissionHistory,
}

/// One staged export record with its stable ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportRecord {
    pub id: RecordId,
    pub kind: ExportKind,
    pub bytes: u64,
}

/// Content checksum over a record batch (FNV-1a over id/kind/bytes). The
/// session and the sink compare this independently: a mere flush mints no
/// ack without a matching readback.
pub fn export_checksum(records: &[ExportRecord]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for record in records {
        for word in [record.id, record.kind as u64, record.bytes] {
            for byte in word.to_le_bytes() {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0100_0000_01b3);
            }
        }
    }
    hash
}

/// Exact final snapshot presented before staging: record count plus content
/// checksum. Construct it with [`FinalSnapshot::compute`]; anything else is
/// compared, not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalSnapshot {
    pub records: u64,
    pub checksum: u64,
}

impl FinalSnapshot {
    pub fn compute(records: &[ExportRecord]) -> Self {
        Self {
            records: records.len() as u64,
            checksum: export_checksum(records),
        }
    }
}

/// Durable export acknowledgement: every record through `through_id` is
/// durable with a verified readback checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableAck {
    pub through_id: RecordId,
    pub checksum: u64,
}

/// A sink-side staged batch between write and commit. Dropping it without
/// commit models a crash: the session still holds the records under the
/// same stable IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagedExport {
    pub through_id: RecordId,
    pub checksum: u64,
    pub bytes: u64,
}

/// Durable-sink failure. Always names the failed step with byte counts.
#[derive(Debug, PartialEq, Eq)]
pub enum SinkError {
    WriteFailed {
        written_bytes: u64,
        total_bytes: u64,
    },
    ReadbackMismatch {
        expected: u64,
        actual: u64,
    },
    SinkFull {
        needed_bytes: u64,
        available_bytes: u64,
    },
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WriteFailed {
                written_bytes,
                total_bytes,
            } => write!(
                f,
                "durable sink write failed after {written_bytes} of {total_bytes} bytes"
            ),
            Self::ReadbackMismatch { expected, actual } => write!(
                f,
                "durable sink readback mismatch: expected checksum {expected}, got {actual}"
            ),
            Self::SinkFull {
                needed_bytes,
                available_bytes,
            } => write!(
                f,
                "durable sink full: needed {needed_bytes} bytes with {available_bytes} available"
            ),
        }
    }
}

impl std::error::Error for SinkError {}

/// Two-phase durable sink: `stage` writes the batch, `commit` verifies the
/// readback checksum and mints the ack. A flush alone never mints an ack.
pub trait DurableSink {
    fn stage(&mut self, records: &[ExportRecord]) -> Result<StagedExport, SinkError>;
    fn commit(
        &mut self,
        staged: StagedExport,
        readback_checksum: u64,
    ) -> Result<DurableAck, SinkError>;
}

/// Export-session protocol refusal.
#[derive(Debug, PartialEq, Eq)]
pub enum ExportError {
    ProducersStillOpen {
        open: u64,
    },
    FinalSnapshotMissing,
    FinalSnapshotMismatch {
        expected: FinalSnapshot,
        actual: FinalSnapshot,
    },
    NothingStaged,
    AckThroughMismatch {
        expected: RecordId,
        actual: RecordId,
    },
    AckChecksumMismatch {
        expected: u64,
        actual: u64,
    },
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProducersStillOpen { open } => write!(
                f,
                "durable export refused: {open} producers still open (cutoff never established)"
            ),
            Self::FinalSnapshotMissing => {
                f.write_str("durable export refused: final snapshot not included")
            }
            Self::FinalSnapshotMismatch { expected, actual } => write!(
                f,
                "durable export refused: final snapshot {expected:?} does not match pending {actual:?}"
            ),
            Self::NothingStaged => f.write_str("durable export: nothing staged to ack"),
            Self::AckThroughMismatch { expected, actual } => write!(
                f,
                "durable export refused: ack covers through record {actual} but {expected} is staged"
            ),
            Self::AckChecksumMismatch { expected, actual } => write!(
                f,
                "durable export refused: ack checksum {actual} does not match staged {expected}"
            ),
        }
    }
}

impl std::error::Error for ExportError {}

/// Replay classification: durable-log IDs at or below the ack are
/// duplicates; anything else unaccounted-for is reported, never absorbed.
pub struct ReplayReport {
    pub duplicates: u64,
    pub unaccounted: u64,
}

/// Bounded-retention durable export session. Reclaiming positive evidence
/// requires, in order: stable record IDs, producer cutoff, exact final
/// snapshot inclusion, and a covering ack from a two-phase durable sink.
/// Staging always takes the whole pending set, so omission history cannot
/// be stranded behind positives (A-F5).
pub struct ExportSession {
    next_id: RecordId,
    pending: BTreeMap<RecordId, ExportRecord>,
    producers_cut_off: bool,
    snapshot: Option<FinalSnapshot>,
    staged: Option<Vec<ExportRecord>>,
    acked_through: Option<RecordId>,
}

impl ExportSession {
    pub fn new() -> Self {
        Self {
            next_id: 0,
            pending: BTreeMap::new(),
            producers_cut_off: false,
            snapshot: None,
            staged: None,
            acked_through: None,
        }
    }

    pub fn append(&mut self, kind: ExportKind, bytes: u64) -> RecordId {
        let id = self.next_id;
        self.next_id += 1;
        self.pending.insert(id, ExportRecord { id, kind, bytes });
        id
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn pending_batch(&self) -> Vec<ExportRecord> {
        self.pending.values().copied().collect()
    }

    /// Fence producers before export. A nonzero open count refuses; the
    /// cutoff is what authorizes reclamation, never a flush or an exit hint.
    pub fn cutoff_producers(&mut self, open_producers: u64) -> Result<(), ExportError> {
        if open_producers > 0 {
            return Err(ExportError::ProducersStillOpen {
                open: open_producers,
            });
        }
        self.producers_cut_off = true;
        Ok(())
    }

    /// Include the exact final snapshot. It is re-verified at stage time,
    /// so appends between inclusion and staging cannot slip through.
    pub fn include_final_snapshot(&mut self, snapshot: &FinalSnapshot) -> Result<(), ExportError> {
        let actual = FinalSnapshot::compute(&self.pending_batch());
        if *snapshot != actual {
            return Err(ExportError::FinalSnapshotMismatch {
                expected: *snapshot,
                actual,
            });
        }
        self.snapshot = Some(*snapshot);
        Ok(())
    }

    /// Stage the whole pending set under its stable IDs. Re-staging after a
    /// crash returns the same IDs; only the ack retires them.
    pub fn stage_batch(&mut self) -> Result<Vec<ExportRecord>, ExportError> {
        if !self.producers_cut_off {
            return Err(ExportError::ProducersStillOpen { open: u64::MAX });
        }
        let Some(snapshot) = self.snapshot else {
            return Err(ExportError::FinalSnapshotMissing);
        };
        let batch = self.pending_batch();
        if batch.is_empty() {
            return Err(ExportError::NothingStaged);
        }
        let actual = FinalSnapshot::compute(&batch);
        if snapshot != actual {
            return Err(ExportError::FinalSnapshotMismatch {
                expected: snapshot,
                actual,
            });
        }
        self.staged = Some(batch.clone());
        Ok(batch)
    }

    /// Retire the staged batch under a covering ack. Partial acks and
    /// checksum mismatches are refused; the batch stays pending.
    pub fn commit_ack(&mut self, ack: &DurableAck) -> Result<u64, ExportError> {
        let Some(staged) = self.staged.as_ref() else {
            return Err(ExportError::NothingStaged);
        };
        let Some(last) = staged.last() else {
            return Err(ExportError::NothingStaged);
        };
        let expected_id = last.id;
        let expected_checksum = export_checksum(staged);
        let count = staged.len() as u64;
        let ids: Vec<RecordId> = staged.iter().map(|record| record.id).collect();
        if ack.through_id != expected_id {
            return Err(ExportError::AckThroughMismatch {
                expected: expected_id,
                actual: ack.through_id,
            });
        }
        if ack.checksum != expected_checksum {
            return Err(ExportError::AckChecksumMismatch {
                expected: expected_checksum,
                actual: ack.checksum,
            });
        }
        for id in ids {
            self.pending.remove(&id);
        }
        self.acked_through = Some(ack.through_id);
        self.staged = None;
        Ok(count)
    }

    pub fn acked_through(&self) -> Option<RecordId> {
        self.acked_through
    }

    /// Classify a replayed durable log against the ack frontier and pending.
    pub fn replay_report(&self, durable_log: &[(RecordId, u64)]) -> ReplayReport {
        let mut duplicates = 0;
        let mut unaccounted = 0;
        for (id, _) in durable_log {
            if self.acked_through.is_some_and(|through| *id <= through) {
                duplicates += 1;
            } else if !self.pending.contains_key(id) {
                unaccounted += 1;
            }
        }
        ReplayReport {
            duplicates,
            unaccounted,
        }
    }
}

impl Default for ExportSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for EvidenceRotation {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for CounterCell {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for WriterSet {
    fn default() -> Self {
        Self::new()
    }
}

/// One resource dimension measured three ways: current live use, peak use,
/// and retained (acknowledged but still held) use.
pub struct ResourceGauge {
    pub current: u64,
    pub peak: u64,
    pub retained: u64,
}

/// Peak/current/retained envelope report across the three bounded
/// dimensions. Live resources track occupancy; history growth tracks its own
/// budget; nothing is folded together.
pub struct EnvelopeReport {
    ram: ResourceGauge,
    history: ResourceGauge,
    disk: ResourceGauge,
}

impl EnvelopeReport {
    pub fn capture(
        ram: &RamBudget,
        history: &HistoryBudget,
        disk: &DiskBudget,
        retained_ram: u64,
        retained_history: u64,
        retained_disk: u64,
    ) -> Self {
        Self {
            ram: ResourceGauge {
                current: ram.current(),
                peak: ram.peak(),
                retained: retained_ram,
            },
            history: ResourceGauge {
                current: history.current(),
                peak: history.peak(),
                retained: retained_history,
            },
            disk: ResourceGauge {
                current: disk.used(),
                peak: disk.peak(),
                retained: retained_disk,
            },
        }
    }

    pub fn render(&self) -> String {
        format!(
            "ram current={} peak={} retained={}\nhistory current={} peak={} retained={}\ndisk current={} peak={} retained={}\n",
            self.ram.current,
            self.ram.peak,
            self.ram.retained,
            self.history.current,
            self.history.peak,
            self.history.retained,
            self.disk.current,
            self.disk.peak,
            self.disk.retained,
        )
    }
}

/// FDs beyond one-per-link reserved by the T7 boundary preflight for the
/// loaded maps, evidence files, fixture stdio and the sampling enumerator.
/// The preflight is a lower bound: refusal fires only when even one FD per
/// link plus this reserve cannot fit, so it never false-refuses a fittable
/// cell.
pub const T7_ENVELOPE_RESERVE_FDS: u64 = 64;

/// L-T7-5 boundary-cell envelope preflight outcome. Pure arithmetic over the
/// live `RLIMIT_NOFILE` soft limit and sampled FD occupancy; the privileged
/// cell samples both and refuses before attaching when they cannot fit.
#[derive(Debug)]
pub struct T7BoundaryPreflight {
    pub endpoints: u64,
    pub required_links: u64,
    pub required_fds: u64,
    pub rlimit_soft: u64,
    pub open_fds: u64,
}

/// Boundary-cell preflight gate: `Ok` proceeds to the sweep, `Err` is the
/// explicit out-of-envelope refusal verdict naming FDs. Never a coverage
/// pass and never an ambiguous failure.
pub fn t7_boundary_preflight(
    endpoints: u64,
    rlimit_soft: u64,
    open_fds: u64,
) -> Result<T7BoundaryPreflight, String> {
    let required_links = endpoints.saturating_add(2);
    let required_fds = required_links.saturating_add(T7_ENVELOPE_RESERVE_FDS);
    let available_fds = rlimit_soft.saturating_sub(open_fds);
    if required_fds > available_fds {
        return Err(format!(
            "T7 boundary cell out of envelope: {endpoints} endpoints need {required_links} links \
             ({required_fds} FDs lower bound with {T7_ENVELOPE_RESERVE_FDS} reserve) but only \
             {available_fds} FDs fit under RLIMIT_NOFILE soft={rlimit_soft} with {open_fds} open"
        ));
    }
    Ok(T7BoundaryPreflight {
        endpoints,
        required_links,
        required_fds,
        rlimit_soft,
        open_fds,
    })
}

/// Post-failure classifier for the boundary cell: FD-exhaustion signatures
/// (process or system wide) route to the explicit refusal verdict, while any
/// other failure — a coverage bug — still fails the cell.
pub fn t7_is_envelope_exhaustion(message: &str) -> bool {
    message.contains("Too many open files")
        || message.contains("too many open files")
        || message.contains("EMFILE")
        || message.contains("ENFILE")
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
