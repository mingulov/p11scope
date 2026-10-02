//! SPDX-License-Identifier: GPL-3.0-or-later
//! The owned Inventory capture facade (Task 6 C3): one caller-flavor
//! Inventory object behind `Prepared → Active → Retiring → Retired` (plus
//! `Failed`, which always keeps its retirement capability). Callers never
//! see `Ebpf`, maps, or links; they hand in attach-set deltas and get
//! receipts, bounded witness batches, cookie answers, and lifecycle records.
//!
//! Invariants (task6-native-feed-plan §3.2):
//!
//! - (a) `extend` validates every new entry the way private activation
//!   does: retained pin unchanged before and after, ABI equal to the pin,
//!   `id < N`, and its ENDPOINT_OBJECT binding published (and read back)
//!   before its link exists. The lifecycle roots attach once, on the first
//!   extend; entries attach incrementally and only for IDs this capture has
//!   not handled.
//! - (b) A failed entry keeps any link it acquired in custody and appears
//!   in the receipt; every other endpoint stays active. A failed ID is never
//!   retried (its ENDPOINT_OBJECT cell may already be committed).
//! - (c) `Failed` always holds the retirement capability.
//! - (d) Every read is bounded by a positive row/record count and a
//!   deadline; a zero window is refused.
//! - (e) PID scope uses `UProbeScope::OneProcess(pid)` for entries, the
//!   original pidfd custody, and a custody check after every attached
//!   entry: a link acquired after the original exited may name a reused
//!   PID, so the capture fails and retires instead of extending further.
//!   Custody is re-polled on every `custody()` and witness read. A
//!   thread-group leader that exited while other threads run (its
//!   `/proc/<pid>/stat` state reads `Z`) silences the OneProcess entries
//!   although the pidfd stays live (privileged probe
//!   `privileged_inventory_capture_pid_scope_leader_exit_probe_lp64`), so
//!   it, an observed exec, and any lifecycle loss (ring loss, a malformed
//!   record, a failed discovery quantum) make custody `PidUnproven`.
//! - (f) Singles only; Multi stays refused.
//! - (g) Health: a counter rise is a `health_regression` (once per rise);
//!   unreadable health or a poisoned OWNER_CTL is a non-sticky
//!   `health_unproven` that only withholds that pass's watches.
//!
//! Costs: one perf link and one FD per attached endpoint (plus two roots
//! and the DISCOVERY ring); `prepare` raises RLIMIT_NOFILE and refuses
//! with [`CaptureCapacityLimited`] (`fds`) unless N + 3 + a reserve fit.
//! Retained objects are shared clones of the attach set's open files (no
//! new FDs). A witness read costs two syscalls per visited row, keeps a
//! seen set bounded by the pair limit P, and rechecks at most
//! [`PIN_RECHECK_PER_READ`] held object pins; a cookie query is one
//! syscall plus two pidfd polls.
#![cfg_attr(not(test), allow(dead_code))]

use super::activation::{
    ActiveInventory, InventoryEndpoint, InventoryHealthSnapshot, InventoryLinkIo, InventoryLinked,
    InventoryState, InventoryTargets, RetiredInventory, RetiringInventory,
    attach_published_entry_with, require_live_pid_custody, service_inventory_discovery_with,
    validate_entry,
};
use super::callers::{CallerRowFault, CallerUseCursor};
use super::{AttachBackend, PreparedInventory, Scope};
use crate::capacity::{CallerBudget, InventoryBudget};
use crate::discovery::identity::{PinnedObjectId, RetainedInventoryTarget};
use crate::discovery::inventory_attach_set::{
    AttachEndpoint, AttachObjectId, EndpointId, InventoryAttachSet, TargetDelta,
};
use crate::process::PidPin;
use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use aya::maps::Map;
use p11scope_ebpf_common::inventory_callers::{CallerObjectKey, CallerObjectUse};
use p11scope_ebpf_common::{
    DISCOVERY_KIND_EXEC, DiscoveryRecord, ImageIdentity, ImageIdentityControl, ThreadOwnerControl,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::fd::AsFd as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The health read's own budget, separate from the row window: a row
/// quantum that spends its deadline never makes health unreadable.
const HEALTH_READ_BUDGET: Duration = Duration::from_millis(50);

/// Held object pins rechecked per witness read (round-robin).
pub(crate) const PIN_RECHECK_PER_READ: usize = 64;

/// Descriptors kept free beyond N + 3 (pidfds, the caller's own files).
pub(crate) const FD_RESERVE: u64 = 64;

/// The named resource of a descriptor refusal (`CapacityLimited("fds")`).
pub(crate) const FD_RESOURCE: &str = "fds";

/// A named capacity refusal: the capture cannot hold what it would need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaptureCapacityLimited {
    pub resource: &'static str,
    pub detail: String,
}

impl fmt::Display for CaptureCapacityLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "capacity limited ({}): {}", self.resource, self.detail)
    }
}

impl std::error::Error for CaptureCapacityLimited {}

/// The descriptor preflight: N entry links + 2 roots + the DISCOVERY ring
/// + `FD_RESERVE` must fit what the soft limit leaves free.
fn fd_preflight(
    endpoint_limit: u64,
    soft_limit: u64,
    in_use: u64,
) -> std::result::Result<(), CaptureCapacityLimited> {
    let needed = endpoint_limit.saturating_add(3).saturating_add(FD_RESERVE);
    let free = soft_limit.saturating_sub(in_use);
    if needed > free {
        return Err(CaptureCapacityLimited {
            resource: FD_RESOURCE,
            detail: format!(
                "N={endpoint_limit} entries need {needed} descriptors (N + 3 + {FD_RESERVE} reserve) but RLIMIT_NOFILE {soft_limit} leaves {free} free ({in_use} in use)"
            ),
        });
    }
    Ok(())
}

/// Open descriptors of this process (the `/proc/self/fd` listing, minus
/// the listing's own descriptor).
fn fds_in_use() -> Result<u64> {
    let count = std::fs::read_dir("/proc/self/fd")
        .context("listing /proc/self/fd")?
        .count();
    Ok((count as u64).saturating_sub(1))
}

/// Initial caller-pair limit P (plan §10 ruling D6): 65,536 pairs, about
/// 3.5 MiB of map payload. Re-tuned from C5 measurements (DR-07).
pub(crate) const DEFAULT_CALLER_PAIRS: u64 = 65_536;

/// The caller budget for `endpoints` with the default pair limit.
pub(crate) fn default_caller_budget(endpoints: InventoryBudget) -> Result<CallerBudget> {
    caller_budget(endpoints, DEFAULT_CALLER_PAIRS)
}

/// The caller budget for `endpoints` and `pairs`, with the exact payload.
pub(crate) fn caller_budget(endpoints: InventoryBudget, pairs: u64) -> Result<CallerBudget> {
    let payload = endpoints
        .endpoint_limit()
        .checked_mul(8)
        .zip(pairs.checked_mul(56))
        .and_then(|(endpoints, pairs)| endpoints.checked_add(pairs))
        .context("caller payload budget overflowed")?;
    CallerBudget::new(endpoints, pairs, payload).map_err(anyhow::Error::msg)
}

/// What one capture instruments.
pub(crate) enum CaptureScope {
    /// Every process (BPF scoping only).
    System,
    /// One process, by its retained original pidfd. A start-time pin or an
    /// exited process is refused before anything loads.
    Pid(PidPin),
}

/// One extend quantum: at most `max_entries` attach attempts before
/// `deadline`. What does not fit returns in the receipt's `deferred`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExtendWindow {
    max_entries: usize,
    deadline: Instant,
}

impl ExtendWindow {
    pub(crate) fn new(max_entries: usize, deadline: Instant) -> Result<Self> {
        if max_entries == 0 {
            bail!("Inventory extend window must permit a positive number of entries");
        }
        Ok(Self {
            max_entries,
            deadline,
        })
    }
}

/// One read quantum: at most `max_rows` CALLER_USE keys (or discovery
/// records) before `deadline`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadWindow {
    max_rows: usize,
    deadline: Instant,
}

impl ReadWindow {
    pub(crate) fn new(max_rows: usize, deadline: Instant) -> Result<Self> {
        if max_rows == 0 {
            bail!("Inventory read window must permit a positive number of rows");
        }
        Ok(Self { max_rows, deadline })
    }
}

/// One loaded object's identity domain. Cookies are tickets inside one
/// domain only; two domains' cookies are never comparable, so this type
/// has equality and nothing else (no order, no numeric access).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeDomainId(u64);

static NEXT_DOMAIN: AtomicU64 = AtomicU64::new(1);

impl NativeDomainId {
    /// The single minting point for every native identity domain in the
    /// process: the Inventory capture here and the Detailed (C6) object
    /// alike must mint through it, so no two loaded objects ever share
    /// a domain.
    pub(crate) fn mint() -> Self {
        Self(NEXT_DOMAIN.fetch_add(1, Ordering::Relaxed))
    }
}

/// A TASK_COOKIE ticket tagged with the domain that issued it. Equality
/// only: a cookie is comparable with another of the same domain and with
/// nothing else, never as a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DomainCookie {
    domain: NativeDomainId,
    cookie: u64,
}

impl DomainCookie {
    fn new(domain: NativeDomainId, cookie: u64) -> Self {
        Self { domain, cookie }
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
}

/// The process incarnation a PID-scoped capture was opened for: the pid
/// and the `/proc` start time its pin retained (`None` when unreadable —
/// no caller can then be proven to be this incarnation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScopeIncarnation {
    pub pid: u32,
    pub start_time: Option<u64>,
}

/// Where the retained targets for a delta's objects come from: the attach
/// set in production. The facade takes shared clones; it never borrows.
pub(crate) trait CaptureTargets {
    fn target(&self, object: AttachObjectId) -> Option<&RetainedInventoryTarget>;
}

impl CaptureTargets for InventoryAttachSet {
    fn target(&self, object: AttachObjectId) -> Option<&RetainedInventoryTarget> {
        InventoryAttachSet::target(self, object)
    }
}

/// Whether the capture's scope is still the process it was opened for.
/// Every non-held state is sticky; `at_ns` (CLOCK_MONOTONIC) is the
/// earliest instant the coverage can have stopped being proven: the exec
/// record's own instant, else the last poll or health read that still
/// proved custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScopeCustody {
    System,
    /// The original pidfd is live, its leader thread is alive, and no
    /// lifecycle record was lost or seen: every entry link fires for it.
    PidHeld,
    /// The process lives, but coverage from `at_ns` on is unproven: an
    /// exec of the target (a nonleader exec replaces the task the entries
    /// were bound to), its leader thread exited (OneProcess entries stop
    /// firing), or lifecycle evidence was lost.
    PidUnproven {
        at_ns: u64,
        reason: String,
    },
    /// The original exited, or custody could not be checked.
    PidLost {
        at_ns: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachedEndpoint {
    pub id: EndpointId,
    pub object: AttachObjectId,
    /// CLOCK_MONOTONIC instant after the entry's post-attach checks.
    pub at_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointFailure {
    pub id: EndpointId,
    pub object: AttachObjectId,
    pub reason: String,
    /// A link was acquired and stays in custody until retirement.
    pub link_retained: bool,
}

/// What one `extend` did. Every endpoint of the delta lands in exactly one
/// of `attached`, `failed`, `known`, or `deferred`.
#[derive(Debug, Default)]
pub(crate) struct ExtendReceipt {
    /// This extend activated the object (DISCOVERY reader and roots).
    pub activated_roots: bool,
    pub attached: Vec<AttachedEndpoint>,
    pub failed: Vec<EndpointFailure>,
    /// Already handled by this capture: nothing was done.
    pub known: Vec<EndpointId>,
    /// Not attempted (window spent, descriptors exhausted, custody lost,
    /// or the extend refused). Resubmit it in any order relative to newer
    /// deltas; a published-but-unattached entry retries its attach only.
    pub deferred: TargetDelta,
    /// An attach hit EMFILE: the window stopped there and the rest was
    /// deferred, nothing failed.
    pub fd_exhausted: bool,
    /// Why nothing was attempted, when the whole extend refused.
    pub refused: Option<String>,
    pub custody: Option<ScopeCustody>,
    /// Attach cost: total and worst single-entry wall time.
    pub attach_ns_total: u64,
    pub attach_ns_max: u64,
}

/// A positive physical-use witness that passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessRow {
    pub domain: NativeDomainId,
    /// Raw ticket and exec sequence: read through `cookie()` (domain
    /// tagged) and `exec_id()`, never as a bare number.
    image: ImageIdentity,
    pub object: AttachObjectId,
    pub endpoint: EndpointId,
    pub host_tgid: u32,
    /// First association instant (CLOCK_MONOTONIC), not first-ever call.
    pub recorded_at_ns: u64,
}

impl WitnessRow {
    /// The row's caller ticket, tagged with its domain.
    pub(crate) fn cookie(&self) -> DomainCookie {
        DomainCookie::new(self.domain, self.image.task_cookie)
    }

    /// The image's exec sequence under `cookie()`: comparable only
    /// between rows whose cookies are equal.
    pub(crate) fn exec_id(&self) -> u64 {
        self.image.exec_id
    }
}

/// A row that failed validation: integrity evidence, never dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessIntegrity {
    pub key: CallerObjectKey,
    pub value: Option<CallerObjectUse>,
    pub reason: String,
}

/// The health counters a witness batch carries (sums over CPUs).
#[derive(Debug, Clone, Default)]
pub(crate) struct CaptureHealth {
    pub caller_evidence: Option<[u64; 4]>,
    pub caller_control: Option<ImageIdentityControl>,
    pub usage_evidence: Option<[u64; 3]>,
    pub evidence: Option<[u64; 9]>,
    pub discovery_counters: Option<[u64; 5]>,
    pub owner: Option<ThreadOwnerControl>,
    pub failures: Vec<String>,
    pub malformed_discovery: u64,
    pub pin_check_failures: u64,
}

impl CaptureHealth {
    fn from_snapshot(snapshot: InventoryHealthSnapshot, state: &InventoryState) -> Self {
        Self {
            caller_evidence: snapshot.caller_evidence,
            caller_control: snapshot.caller_control,
            usage_evidence: snapshot.usage_evidence,
            evidence: snapshot.evidence,
            discovery_counters: snapshot.discovery_counters,
            owner: snapshot.owner,
            failures: snapshot.failures,
            malformed_discovery: state.malformed_discovery(),
            pin_check_failures: state.pin_check_failures(),
        }
    }

    /// The counters whose increase makes "no use" unprovable (plan §3.4),
    /// including every silent-drop path: a poisoned OWNER_CTL makes
    /// `scope_auth` refuse every entry, owner admission/reclamation
    /// failures drop entries, and an ABI layout refusal counts only in
    /// EVIDENCE.
    fn watch_counters(&self) -> Option<WatchCounters> {
        let control = self.caller_control?;
        let owner = self.owner?;
        Some(WatchCounters {
            caller_evidence: self.caller_evidence?,
            usage_evidence: self.usage_evidence?,
            identity: [
                control.unavailable,
                control.create_failures,
                control.retry_exhausted,
            ],
            evidence: self.evidence?,
            owner_poisoned: owner.poison != 0,
            owner_failures: [owner.admission_failures, owner.reclamation_failures],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct WatchCounters {
    caller_evidence: [u64; 4],
    usage_evidence: [u64; 3],
    identity: [u64; 3],
    evidence: [u64; 9],
    owner_poisoned: bool,
    owner_failures: [u64; 2],
}

/// One health assessment: a rise (reported once) and whether this pass's
/// health is proven at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HealthAssessment {
    regression: Option<String>,
    unproven: Option<String>,
}

/// Which producers a batch was read under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapturePhase {
    /// Loaded, no producer attached yet.
    Prepared,
    Active,
    /// Stopping: producers are being or have been detached.
    Retiring,
    Retired,
}

/// One bounded witness read plus a health snapshot.
#[derive(Debug)]
pub(crate) struct WitnessBatch {
    pub domain: NativeDomainId,
    pub phase: CapturePhase,
    pub rows: Vec<WitnessRow>,
    pub integrity: Vec<WitnessIntegrity>,
    /// Integrity rows reported over the capture so far.
    pub integrity_total: u64,
    pub visited: usize,
    /// This read reached the end of a CALLER_USE sweep: every row present
    /// when that sweep began has been reported.
    pub sweep_completed: bool,
    pub sweeps_completed: u64,
    pub row_bound_reached: bool,
    pub deadline_reached: bool,
    pub read_failures: Vec<String>,
    /// Distinct rows past the seen-set bound (counted, never reported).
    pub unrecorded_rows: u64,
    /// `sweep_completed`, but that sweep skipped rows (a lookup failure or
    /// the seen-set bound): it completed with gaps.
    pub sweep_gaps: bool,
    /// The userspace seen-set size: distinct CALLER_USE rows this capture
    /// has reported (bounded by `pair_limit`). Not the kernel map's
    /// occupancy, which a hash map does not expose without a full walk.
    pub seen_rows: usize,
    pub pair_limit: usize,
    pub health: CaptureHealth,
    /// A watch-relevant counter rose since the previous readable health
    /// read (at `health_baseline_ns`): every watched no-use edge demotes.
    /// Reported once per rise.
    pub health_regression: Option<String>,
    /// Health could not be proven this read (unreadable cells, or a
    /// poisoned OWNER_CTL): no edge may start or continue a watch from
    /// this batch. Not sticky and not a regression.
    pub health_unproven: Option<String>,
    /// The previous readable health read (CLOCK_MONOTONIC): the earliest
    /// instant a reported rise can have happened.
    pub health_baseline_ns: u64,
    /// This read's health instant (taken before the read): where a rise
    /// was detected, and — when health is proven, nothing rose, and
    /// custody holds — the latest proven-clean instant.
    pub health_read_ns: u64,
    /// Held objects whose retained pin no longer matches (modified in
    /// place) or could not be rechecked, first reported in this batch:
    /// their modules' coverage is unknown from now on.
    pub changed_objects: Vec<AttachObjectId>,
    /// Scope custody after this read.
    pub custody: ScopeCustody,
    /// PID scope: the last custody poll that proved the pidfd and leader
    /// live (`None` for the machine). A read is clean no later than this,
    /// whatever its `health_read_ns`.
    pub custody_proven_ns: Option<u64>,
    /// Read after stop began, after a failure, or with unproven health:
    /// never a settled terminal read (FD closure is not a
    /// callback-quiescence protocol, and unproven health proves nothing).
    pub unsettled: bool,
}

/// What one `query_cookie` learned about a pinned process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CookieQuery {
    /// The process's leader holds this ticket; the pidfd was live before
    /// and after the lookup.
    Cookie(DomainCookie),
    /// No ticket in this domain: it never entered an instrumented endpoint
    /// here, or a nonleader exec replaced the leader that held one.
    NoCookie,
    /// The pinned process exited before or during the query.
    Exited,
    Unavailable(String),
}

/// One bounded quantum of lifecycle records, in dequeue order.
pub(crate) struct DiscoveryBatch {
    pub records: Vec<DiscoveryRecord>,
    pub record_bound_reached: bool,
    pub deadline_reached: bool,
    /// A malformed or unreadable record stopped the quantum. Under PID
    /// scope it makes custody unproven (a lifecycle record was lost).
    pub failure: Option<String>,
}

impl fmt::Debug for DiscoveryBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryBatch")
            .field("records", &self.records.len())
            .field("record_bound_reached", &self.record_bound_reached)
            .field("deadline_reached", &self.deadline_reached)
            .field("failure", &self.failure)
            .finish()
    }
}

/// What retirement closed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CleanupSummary {
    pub attempted: usize,
    pub closed: usize,
    pub failures: Vec<String>,
    /// Links that stay owned (quarantined or failed to close).
    pub retained_links: usize,
}

/// Facade bookkeeping that travels through every state.
struct CaptureBook {
    domain: NativeDomainId,
    budget: InventoryBudget,
    pair_limit: usize,
    scope: Option<ScopeIncarnation>,
    /// Endpoint → object for every ENDPOINT_OBJECT binding this capture
    /// published and read back. Bounded by N. An entry here that is in
    /// neither `attached` nor `failed` is published-but-unattached (its
    /// attach hit EMFILE): a later extend retries the attach only.
    published: BTreeMap<u32, AttachObjectId>,
    attached: BTreeSet<u32>,
    /// Endpoints that failed: never retried. Bounded by N.
    failed: BTreeMap<u32, String>,
    custody_lost: Option<(u64, String)>,
    /// First reason PID-scope coverage became unproven (sticky).
    unproven: Option<(u64, String)>,
    /// The last instant a custody poll proved the pidfd and leader live.
    held_ns: u64,
    /// The last readable health read; ring loss and malformed records
    /// found after it are dated here.
    health_ns: u64,
    ring_loss: u64,
    malformed: u64,
    cursor: CallerUseCursor,
    integrity_total: u64,
    baseline: Option<WatchCounters>,
    /// Held objects whose pin changed or could not be rechecked (sticky),
    /// and the round-robin recheck cursor.
    changed_objects: BTreeSet<AttachObjectId>,
    recheck_after: Option<PinnedObjectId>,
    stopping: bool,
}

impl CaptureBook {
    fn new(
        budget: InventoryBudget,
        pair_limit: usize,
        scope: Option<ScopeIncarnation>,
        now_ns: u64,
    ) -> Self {
        Self {
            domain: NativeDomainId::mint(),
            budget,
            pair_limit,
            scope,
            published: BTreeMap::new(),
            attached: BTreeSet::new(),
            failed: BTreeMap::new(),
            custody_lost: None,
            unproven: None,
            held_ns: now_ns,
            health_ns: now_ns,
            ring_loss: 0,
            malformed: 0,
            cursor: CallerUseCursor::new(pair_limit),
            integrity_total: 0,
            // Preparation proved every counter fresh (zero).
            baseline: Some(WatchCounters::default()),
            changed_objects: BTreeSet::new(),
            recheck_after: None,
            stopping: false,
        }
    }

    fn scope_pid(&self) -> Option<u32> {
        self.scope.map(|scope| scope.pid)
    }

    /// Attached or failed: nothing more to do for this ID.
    fn knows(&self, id: u32) -> bool {
        self.attached.contains(&id) || self.failed.contains_key(&id)
    }

    fn custody(&self) -> ScopeCustody {
        if self.scope.is_none() {
            return ScopeCustody::System;
        }
        if let Some((at_ns, reason)) = &self.custody_lost {
            return ScopeCustody::PidLost {
                at_ns: *at_ns,
                reason: reason.clone(),
            };
        }
        match &self.unproven {
            Some((at_ns, reason)) => ScopeCustody::PidUnproven {
                at_ns: *at_ns,
                reason: reason.clone(),
            },
            None => ScopeCustody::PidHeld,
        }
    }

    /// PID scope only; the first reason (and its instant) stands.
    fn mark_unproven(&mut self, at_ns: u64, reason: String) {
        if self.scope.is_some() && self.unproven.is_none() {
            self.unproven = Some((at_ns, reason));
        }
    }

    fn mark_lost(&mut self, reason: String) {
        if self.scope.is_some() && self.custody_lost.is_none() {
            self.custody_lost = Some((self.held_ns, reason));
        }
    }

    /// One custody poll's verdict.
    fn absorb_poll(&mut self, poll: CustodyPoll, now_ns: u64) {
        match poll {
            CustodyPoll::Held => {
                if self.custody_lost.is_none() && self.unproven.is_none() {
                    self.held_ns = now_ns;
                }
            }
            CustodyPoll::Unproven(reason) => self.mark_unproven(self.held_ns, reason),
            CustodyPoll::Lost(reason) => self.mark_lost(format!("PID custody lost: {reason}")),
        }
    }

    fn observe_record(&mut self, record: &DiscoveryRecord) {
        if let Some(pid) = self.scope_pid()
            && record.kind == DISCOVERY_KIND_EXEC
            && (record.pid_tgid >> 32) as u32 == pid
        {
            self.mark_unproven(
                record.hook_ts_ns,
                "an exec of the PID target was observed (a nonleader exec replaces the task the entries were bound to)"
                    .into(),
            );
        }
    }

    /// Lifecycle loss under PID scope: an exec record may be among what
    /// was lost, so custody since the last clean health read is unproven.
    fn observe_lifecycle(&mut self, health: &CaptureHealth) {
        let ring_loss = health.discovery_counters.map(|counters| counters[0]);
        if let Some(ring_loss) = ring_loss
            && ring_loss > self.ring_loss
        {
            let reason = format!(
                "the lifecycle ring lost records (DISCOVERY ring loss {} -> {ring_loss}): an exec of the PID target may be among them",
                self.ring_loss
            );
            self.mark_unproven(self.health_ns, reason);
            self.ring_loss = ring_loss;
        }
        if health.malformed_discovery > self.malformed {
            let reason = format!(
                "{} malformed lifecycle record(s): an exec of the PID target may be among them",
                health.malformed_discovery - self.malformed
            );
            self.mark_unproven(self.health_ns, reason);
            self.malformed = health.malformed_discovery;
        }
    }

    fn fail(
        &mut self,
        receipt: &mut ExtendReceipt,
        endpoint: &AttachEndpoint,
        reason: String,
        link_retained: bool,
    ) {
        self.failed.insert(endpoint.id.0, reason.clone());
        receipt.failed.push(EndpointFailure {
            id: endpoint.id,
            object: endpoint.object,
            reason,
            link_retained,
        });
    }
}

/// One custody poll's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CustodyPoll {
    Held,
    Unproven(String),
    Lost(String),
}

/// The leader thread's `/proc/<pid>/stat` state and start time.
struct LeaderStat {
    state: char,
    /// `task->flags` (stat field 9).
    flags: u64,
    start_time: u64,
}

fn read_leader_stat(pid: u32) -> std::io::Result<LeaderStat> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "stat fields");
    let end = stat.rfind(')').ok_or_else(invalid)?;
    let mut fields = stat[end + 1..].split_whitespace();
    let state = fields
        .next()
        .and_then(|state| state.chars().next())
        .ok_or_else(invalid)?;
    // After the state: ppid pgrp session tty_nr tpgid, then flags.
    let flags = fields
        .nth(5)
        .and_then(|value| value.parse().ok())
        .ok_or_else(invalid)?;
    let start_time = fields
        .nth(12)
        .and_then(|value| value.parse().ok())
        .ok_or_else(invalid)?;
    Ok(LeaderStat {
        state,
        flags,
        start_time,
    })
}

/// The custody discipline: pidfd live, the leader thread's stat read, then
/// the pidfd live again (so the stat named the pinned generation).
fn poll_custody_with(
    expected_start: Option<u64>,
    exited: impl Fn() -> std::result::Result<bool, String>,
    leader: impl FnOnce() -> std::io::Result<LeaderStat>,
) -> CustodyPoll {
    match exited() {
        Ok(false) => {}
        Ok(true) => return CustodyPoll::Lost("the PID target exited".into()),
        Err(error) => return CustodyPoll::Lost(error),
    }
    let leader = leader();
    match exited() {
        Ok(false) => {}
        Ok(true) => return CustodyPoll::Lost("the PID target exited".into()),
        Err(error) => return CustodyPoll::Lost(error),
    }
    match leader {
        Err(error) => CustodyPoll::Unproven(format!(
            "the PID target's leader thread state is unreadable: {error}"
        )),
        Ok(stat) if stat.flags & PF_EXITING != 0 => CustodyPoll::Unproven(format!(
            "the PID target's thread-group leader is exiting (flags {:#x}): its OneProcess entries are going away",
            stat.flags
        )),
        Ok(stat) if matches!(stat.state, 'Z' | 'X' | 'x') => CustodyPoll::Unproven(format!(
            "the PID target's thread-group leader exited (state {}) while other threads run: its OneProcess entries no longer fire",
            stat.state
        )),
        Ok(stat) if expected_start.is_some_and(|start| start != stat.start_time) => {
            CustodyPoll::Unproven(format!(
                "the PID target's start time changed from {} to {}",
                expected_start.unwrap_or_default(),
                stat.start_time
            ))
        }
        Ok(_) => CustodyPoll::Held,
    }
}

/// One custody poll into the book. The instant is taken before the poll:
/// a held verdict proves custody up to the start of its reads, never past
/// them.
fn poll_into(
    book: &mut CaptureBook,
    clock: &mut dyn FnMut() -> u64,
    poll: impl FnOnce() -> CustodyPoll,
) {
    let now_ns = clock();
    let poll = poll();
    book.absorb_poll(poll, now_ns);
}

/// `PF_EXITING`: the task is already in `do_exit`.
const PF_EXITING: u64 = 0x4;

fn poll_custody(pin: Option<&PidPin>) -> CustodyPoll {
    let Some(pin) = pin else {
        return CustodyPoll::Lost("the PID pin is no longer held".into());
    };
    poll_custody_with(
        pin.start_time(),
        || pin.original_exited(),
        || read_leader_stat(pin.pid()),
    )
}

fn defer(receipt: &mut ExtendReceipt, rest: &[AttachEndpoint]) {
    for endpoint in rest {
        receipt.deferred.endpoints.push(*endpoint);
        if !receipt.deferred.objects.contains(&endpoint.object) {
            receipt.deferred.objects.push(endpoint.object);
        }
    }
}

fn monotonic_ns() -> u64 {
    // CLOCK_MONOTONIC cannot fail with valid arguments. Were it to, the
    // latest instant keeps a watch from claiming an interval it never had.
    crate::attach::monotonic_ns().unwrap_or(u64::MAX)
}

/// The incremental entry transaction over any link IO (the fake one in
/// unit tests). `custody` is the PID-scope check; `now` stamps attaches.
#[allow(clippy::too_many_arguments)]
fn extend_entries_with<I: InventoryLinkIo>(
    io: &mut I,
    targets: &mut InventoryTargets,
    links: &mut Vec<InventoryLinked<I::Link>>,
    book: &mut CaptureBook,
    delta: TargetDelta,
    source: &dyn CaptureTargets,
    window: ExtendWindow,
    custody: &mut dyn FnMut() -> std::result::Result<(), String>,
    now: &mut dyn FnMut() -> u64,
    receipt: &mut ExtendReceipt,
) {
    let mut attempted = 0usize;
    for (index, endpoint) in delta.endpoints.iter().enumerate() {
        if book.knows(endpoint.id.0) {
            receipt.known.push(endpoint.id);
            continue;
        }
        if attempted >= window.max_entries || Instant::now() >= window.deadline {
            let rest: Vec<AttachEndpoint> = delta.endpoints[index..]
                .iter()
                .filter(|endpoint| !book.knows(endpoint.id.0))
                .copied()
                .collect();
            defer(receipt, &rest);
            receipt.known.extend(
                delta.endpoints[index..]
                    .iter()
                    .filter(|endpoint| book.knows(endpoint.id.0))
                    .map(|endpoint| endpoint.id),
            );
            return;
        }
        attempted += 1;
        let local = PinnedObjectId(endpoint.object.index());
        let entry = InventoryEndpoint {
            id: endpoint.id.0,
            object: local,
            file_offset: endpoint.file_offset,
            abi: endpoint.abi,
        };
        // Published but unattached (an earlier attach hit EMFILE): the
        // binding and the entry record stand; only the attach is retried.
        let republish = !book.published.contains_key(&entry.id);
        if republish && !targets.holds_object(local) {
            match source.target(endpoint.object) {
                Some(target) => targets.retain_object(local, target.share()),
                None => {
                    book.fail(
                        receipt,
                        endpoint,
                        format!(
                            "the attach set holds no retained target for object {}",
                            endpoint.object.index()
                        ),
                        false,
                    );
                    continue;
                }
            }
        }
        if republish {
            let checked = targets
                .record_entry(entry)
                .and_then(|()| validate_entry(targets, &entry))
                .and_then(|()| {
                    targets.check_object(local).with_context(|| {
                        format!("before publishing Inventory endpoint {}", entry.id)
                    })
                });
            if let Err(error) = checked {
                book.fail(receipt, endpoint, format!("{error:#}"), false);
                continue;
            }
            if let Err(error) = io
                .publish_endpoint(entry.id, entry.object)
                .with_context(|| format!("publishing Inventory endpoint {}", entry.id))
            {
                // The cell's content is unknown: no binding is recorded, so
                // a row naming this endpoint is integrity evidence.
                book.fail(receipt, endpoint, format!("{error:#}"), false);
                continue;
            }
            book.published.insert(entry.id, endpoint.object);
        } else if book.published.get(&entry.id) != Some(&endpoint.object) {
            book.fail(
                receipt,
                endpoint,
                format!(
                    "Inventory endpoint {} was published for another object",
                    entry.id
                ),
                false,
            );
            continue;
        }
        let before = links.len();
        let started = Instant::now();
        let attached = attach_published_entry_with(io, targets, &entry, links);
        let spent = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        receipt.attach_ns_total = receipt.attach_ns_total.saturating_add(spent);
        receipt.attach_ns_max = receipt.attach_ns_max.max(spent);
        let retained = links.len() > before;
        match attached {
            Err(error) if !retained && crate::attach::is_fd_exhaustion(&error) => {
                // Descriptors ran out: nothing about this entry is wrong.
                // It stays published-unattached; it and the rest defer.
                receipt.fd_exhausted = true;
                let rest: Vec<AttachEndpoint> = delta.endpoints[index..]
                    .iter()
                    .filter(|endpoint| !book.knows(endpoint.id.0))
                    .copied()
                    .collect();
                defer(receipt, &rest);
                return;
            }
            Err(error) => {
                book.fail(receipt, endpoint, format!("{error:#}"), retained);
                continue;
            }
            Ok(()) => {}
        }
        if let Err(reason) = custody() {
            let reason = format!(
                "PID custody lost after attaching entry {}: {reason}",
                entry.id
            );
            book.mark_lost(reason.clone());
            book.fail(receipt, endpoint, reason, retained);
            let rest: Vec<AttachEndpoint> = delta.endpoints[index + 1..]
                .iter()
                .filter(|endpoint| !book.knows(endpoint.id.0))
                .copied()
                .collect();
            defer(receipt, &rest);
            return;
        }
        book.attached.insert(entry.id);
        receipt.attached.push(AttachedEndpoint {
            id: endpoint.id,
            object: endpoint.object,
            at_ns: now(),
        });
    }
}

enum CaptureState {
    Prepared(Box<PreparedInventory>),
    Active(Box<ActiveInventory>),
    Failed {
        error: String,
        retiring: Box<RetiringInventory>,
    },
    /// Only while a transition is in progress.
    Moving,
}

/// The owned capture. Dropping it while active is the documented
/// blocking, explicitly abandoned reclamation path; `begin_stop` is the
/// bounded one.
pub(crate) struct InventoryCapture {
    state: CaptureState,
    book: CaptureBook,
}

impl InventoryCapture {
    /// Loads and prepares one fresh caller-flavor object for `scope`. No
    /// producer exists until the first `extend`.
    pub(crate) fn prepare(
        scope: CaptureScope,
        endpoints: InventoryBudget,
        callers: CallerBudget,
        backend: AttachBackend,
    ) -> Result<Self> {
        if backend != AttachBackend::Singles {
            bail!("Inventory capture supports Singles only");
        }
        let (scope, pin) = match scope {
            CaptureScope::System => (Scope::System, None),
            CaptureScope::Pid(pin) => {
                require_live_pid_custody(&pin)?;
                (Scope::Pid(pin.pid()), Some(pin))
            }
        };
        let incarnation = pin.as_ref().map(|pin| ScopeIncarnation {
            pid: pin.pid(),
            start_time: pin.start_time(),
        });
        // Every entry link costs a descriptor (the `Session::start`
        // precedent): raise first, then prove N + 3 + reserve fit.
        let soft_limit = crate::process::raise_nofile().context("reading RLIMIT_NOFILE")?;
        fd_preflight(endpoints.endpoint_limit(), soft_limit as u64, fds_in_use()?)?;
        let pair_limit = usize::try_from(callers.pair_limit()).unwrap_or(usize::MAX);
        let prepared =
            PreparedInventory::prepare_callers_pinned(scope, pin, endpoints, callers, backend)?;
        Ok(Self {
            state: CaptureState::Prepared(Box::new(prepared)),
            book: CaptureBook::new(endpoints, pair_limit, incarnation, monotonic_ns()),
        })
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.book.domain
    }

    /// The PID incarnation this capture covers (`None` for the machine).
    pub(crate) fn incarnation(&self) -> Option<ScopeIncarnation> {
        self.book.scope
    }

    /// Polls the pidfd and the leader thread, then reports custody.
    pub(crate) fn custody(&mut self) -> ScopeCustody {
        self.poll_custody();
        self.book.custody()
    }

    fn pid_pin(&self) -> Option<&PidPin> {
        pid_pin_of(&self.state)
    }

    fn poll_custody(&mut self) {
        if self.book.scope.is_none() || self.book.custody_lost.is_some() {
            return;
        }
        let pin = pid_pin_of(&self.state);
        poll_into(&mut self.book, &mut monotonic_ns, || poll_custody(pin));
    }
}

fn pid_pin_of(state: &CaptureState) -> Option<&PidPin> {
    match state {
        CaptureState::Prepared(prepared) => prepared.pid_pin.as_ref(),
        CaptureState::Active(active) => active.state().pid_pin(),
        CaptureState::Failed { retiring, .. } => retiring.state().and_then(InventoryState::pid_pin),
        CaptureState::Moving => None,
    }
}

impl InventoryCapture {
    pub(crate) fn phase(&self) -> CapturePhase {
        match self.state {
            CaptureState::Prepared(_) => CapturePhase::Prepared,
            CaptureState::Active(_) => CapturePhase::Active,
            CaptureState::Failed { .. } | CaptureState::Moving => CapturePhase::Retiring,
        }
    }

    /// Why the capture failed, once it has.
    pub(crate) fn failure(&self) -> Option<&str> {
        match &self.state {
            CaptureState::Failed { error, .. } => Some(error),
            _ => None,
        }
    }

    /// Attaches the delta's new endpoints (activating the object first if
    /// this is the first extend). Bounded by `window`; the rest returns in
    /// the receipt's `deferred`.
    ///
    /// Contract: a delta may be submitted in any order relative to other
    /// deltas — a receipt's `deferred` backlog after a newer delta is
    /// fine — and resubmitting an endpoint already attached or failed is a
    /// no-op reported in `known`. An endpoint deferred by EMFILE stays
    /// published; its resubmission retries the attach only. The caller
    /// owns the backlog: an endpoint is never attempted unless submitted.
    pub(crate) fn extend(
        &mut self,
        delta: TargetDelta,
        source: &dyn CaptureTargets,
        window: ExtendWindow,
    ) -> ExtendReceipt {
        let mut receipt = ExtendReceipt::default();
        if let CaptureState::Prepared(_) = self.state {
            let CaptureState::Prepared(prepared) =
                std::mem::replace(&mut self.state, CaptureState::Moving)
            else {
                unreachable!()
            };
            match prepared.activate_roots(InventoryTargets::for_capture(self.book.budget)) {
                Ok(active) => {
                    self.state = CaptureState::Active(Box::new(active));
                    receipt.activated_roots = true;
                }
                Err(failure) => {
                    let error = format!("{:#}", failure.error);
                    // An activation that failed because the PID target
                    // exited is a custody loss, not a capture fault.
                    if let Some(pin) = failure.retiring.state().and_then(InventoryState::pid_pin)
                        && let Err(reason) = require_live_pid_custody(pin)
                    {
                        self.book
                            .mark_lost(format!("PID custody lost during activation: {reason:#}"));
                    }
                    self.book.stopping = true;
                    self.state = CaptureState::Failed {
                        error: error.clone(),
                        retiring: failure.retiring,
                    };
                    receipt.refused = Some(format!("Inventory capture activation failed: {error}"));
                }
            }
        }
        self.poll_custody();
        let book = &mut self.book;
        let active = match &mut self.state {
            CaptureState::Active(active) => active,
            CaptureState::Failed { error, .. } => {
                receipt
                    .refused
                    .get_or_insert_with(|| format!("Inventory capture failed: {error}"));
                defer(&mut receipt, &delta.endpoints);
                receipt.custody = Some(book.custody());
                return receipt;
            }
            CaptureState::Prepared(_) | CaptureState::Moving => {
                unreachable!("activation leaves the capture active or failed")
            }
        };
        let lost = active.with_entry_io(|io, targets, links, pin| {
            let mut custody = || match pin {
                Some(pin) => require_live_pid_custody(pin).map_err(|error| format!("{error:#}")),
                None => Ok(()),
            };
            if let Some((_, reason)) = &book.custody_lost {
                receipt.refused = Some(format!("PID custody was lost: {reason}"));
                defer(&mut receipt, &delta.endpoints);
                return true;
            }
            if let Err(reason) = custody() {
                let reason = format!("PID custody lost before extend: {reason}");
                book.mark_lost(reason.clone());
                receipt.refused = Some(reason);
                defer(&mut receipt, &delta.endpoints);
                return true;
            }
            extend_entries_with(
                io,
                targets,
                links,
                book,
                delta,
                source,
                window,
                &mut custody,
                &mut monotonic_ns,
                &mut receipt,
            );
            book.custody_lost.is_some()
        });
        if lost {
            self.fail_with(
                self.book
                    .custody_lost
                    .as_ref()
                    .map_or_else(|| "PID custody lost".into(), |(_, reason)| reason.clone()),
            );
        }
        receipt.custody = Some(self.book.custody());
        receipt
    }

    fn fail_with(&mut self, error: String) {
        // Producers are being detached from here on: reads are unsettled.
        self.book.stopping = true;
        if let CaptureState::Active(_) = self.state {
            let CaptureState::Active(active) =
                std::mem::replace(&mut self.state, CaptureState::Moving)
            else {
                unreachable!()
            };
            self.state = CaptureState::Failed {
                error,
                retiring: Box::new(active.begin_stop()),
            };
        }
    }

    /// One bounded CALLER_USE quantum plus a health snapshot, a bounded
    /// pin recheck, and a custody poll.
    pub(crate) fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
        self.poll_custody();
        let (phase, state) = match &mut self.state {
            CaptureState::Prepared(_) | CaptureState::Moving => (CapturePhase::Prepared, None),
            CaptureState::Active(active) => (CapturePhase::Active, Some(active.state_mut())),
            CaptureState::Failed { retiring, .. } => (CapturePhase::Retiring, retiring.state_mut()),
        };
        read_witnesses_from(state, &mut self.book, phase, window)
    }

    /// The pidfd-keyed TASK_COOKIE answer for `pin` in this domain.
    pub(crate) fn query_cookie(&self, pin: &PidPin) -> CookieQuery {
        let ebpf = match &self.state {
            CaptureState::Prepared(prepared) => Some(&prepared.ebpf),
            CaptureState::Active(active) => Some(active.state().ebpf()),
            CaptureState::Failed { retiring, .. } => retiring.state().map(InventoryState::ebpf),
            CaptureState::Moving => None,
        };
        query_cookie_in(ebpf, self.book.domain, pin)
    }

    /// Up to `max` lifecycle records (exec/exit) before `deadline`.
    pub(crate) fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        match &mut self.state {
            CaptureState::Active(active) => {
                let state = active.state_mut();
                service_with(&mut self.book, window, |max, deadline, dispatch| {
                    service_inventory_discovery_with(
                        max,
                        deadline,
                        || state.dequeue_discovery(),
                        dispatch,
                    )
                })
            }
            CaptureState::Failed { retiring, .. } => {
                service_with(&mut self.book, window, |max, deadline, dispatch| {
                    retiring.service_discovery(max, deadline, dispatch)
                })
            }
            CaptureState::Prepared(_) | CaptureState::Moving => DiscoveryBatch {
                records: Vec::new(),
                record_bound_reached: false,
                deadline_reached: false,
                failure: None,
            },
        }
    }

    /// Starts owned retirement. Reads stay available and are unsettled.
    pub(crate) fn begin_stop(self) -> RetiringCapture {
        let Self { state, mut book } = self;
        book.stopping = true;
        let (inner, failure) = match state {
            // Never activated: no producer ever existed.
            CaptureState::Prepared(_) | CaptureState::Moving => (RetiringInner::Unactivated, None),
            CaptureState::Active(active) => {
                (RetiringInner::Retiring(Box::new(active.begin_stop())), None)
            }
            CaptureState::Failed { error, retiring } => {
                (RetiringInner::Retiring(retiring), Some(error))
            }
        };
        RetiringCapture {
            inner,
            book,
            failure,
        }
    }
}

enum RetiringInner {
    Unactivated,
    Retiring(Box<RetiringInventory>),
}

/// A capture whose producers are being detached. Dropping it is the
/// blocking, explicitly abandoned reclamation path.
#[must_use]
pub(crate) struct RetiringCapture {
    inner: RetiringInner,
    book: CaptureBook,
    failure: Option<String>,
}

impl RetiringCapture {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.book.domain
    }

    /// The failure that preceded stop, when the capture had failed.
    pub(crate) fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    /// True once every link has had its close attempt.
    pub(crate) fn poll_completion(&mut self, deadline: Instant) -> Result<bool> {
        match &mut self.inner {
            RetiringInner::Unactivated => Ok(true),
            RetiringInner::Retiring(retiring) => retiring.poll_completion(deadline),
        }
    }

    pub(crate) fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        match &mut self.inner {
            RetiringInner::Unactivated => DiscoveryBatch {
                records: Vec::new(),
                record_bound_reached: false,
                deadline_reached: false,
                failure: None,
            },
            RetiringInner::Retiring(retiring) => {
                service_with(&mut self.book, window, |max, deadline, dispatch| {
                    retiring.service_discovery(max, deadline, dispatch)
                })
            }
        }
    }

    pub(crate) fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
        let state = match &mut self.inner {
            RetiringInner::Unactivated => None,
            RetiringInner::Retiring(retiring) => retiring.state_mut(),
        };
        read_witnesses_from(state, &mut self.book, CapturePhase::Retiring, window)
    }

    pub(crate) fn query_cookie(&self, pin: &PidPin) -> CookieQuery {
        let ebpf = match &self.inner {
            RetiringInner::Unactivated => None,
            RetiringInner::Retiring(retiring) => retiring.state().map(InventoryState::ebpf),
        };
        query_cookie_in(ebpf, self.book.domain, pin)
    }

    /// Transfers the completed retirement, or returns this capture intact.
    pub(crate) fn try_finish(self) -> std::result::Result<RetiredCapture, Box<Self>> {
        let Self {
            inner,
            book,
            failure,
        } = self;
        match inner {
            RetiringInner::Unactivated => Ok(RetiredCapture {
                inner: None,
                book,
                cleanup: CleanupSummary::default(),
                failure,
            }),
            RetiringInner::Retiring(retiring) => match retiring.try_finish() {
                Ok(retired) => {
                    let cleanup = CleanupSummary {
                        attempted: retired.cleanup.attempted,
                        closed: retired.cleanup.closed,
                        failures: retired
                            .cleanup
                            .failures
                            .iter()
                            .map(|failure| format!("{:?}: {:#}", failure.target, failure.error))
                            .collect(),
                        retained_links: 0,
                    };
                    let mut retired = RetiredCapture {
                        inner: Some(Box::new(retired)),
                        book,
                        cleanup,
                        failure,
                    };
                    retired.cleanup.retained_links = retired
                        .inner
                        .as_mut()
                        .map_or(0, |inner| inner.state_mut().live_links());
                    Ok(retired)
                }
                Err(retiring) => Err(Box::new(Self {
                    inner: RetiringInner::Retiring(retiring),
                    book,
                    failure,
                })),
            },
        }
    }
}

/// A retired capture: maps and pins stay readable until it drops.
pub(crate) struct RetiredCapture {
    inner: Option<Box<RetiredInventory>>,
    book: CaptureBook,
    cleanup: CleanupSummary,
    failure: Option<String>,
}

impl RetiredCapture {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.book.domain
    }

    pub(crate) fn cleanup(&self) -> &CleanupSummary {
        &self.cleanup
    }

    pub(crate) fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    pub(crate) fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
        let state = self.inner.as_mut().map(|inner| inner.state_mut());
        read_witnesses_from(state, &mut self.book, CapturePhase::Retired, window)
    }

    pub(crate) fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        match self.inner.as_mut() {
            None => DiscoveryBatch {
                records: Vec::new(),
                record_bound_reached: false,
                deadline_reached: false,
                failure: None,
            },
            Some(inner) => {
                let state = inner.state_mut();
                service_with(&mut self.book, window, |max, deadline, dispatch| {
                    service_inventory_discovery_with(
                        max,
                        deadline,
                        || state.dequeue_discovery(),
                        dispatch,
                    )
                })
            }
        }
    }

    pub(crate) fn query_cookie(&self, pin: &PidPin) -> CookieQuery {
        let ebpf = self.inner.as_ref().map(|inner| inner.state().ebpf());
        query_cookie_in(ebpf, self.book.domain, pin)
    }
}

type Dispatch<'a> = &'a mut dyn FnMut(DiscoveryRecord) -> Result<()>;

fn service_with(
    book: &mut CaptureBook,
    window: ReadWindow,
    service: impl FnOnce(
        usize,
        Instant,
        Dispatch<'_>,
    ) -> std::result::Result<
        super::activation::InventoryDiscoveryService,
        super::activation::InventoryDispatchFailure,
    >,
) -> DiscoveryBatch {
    let mut records = Vec::new();
    let mut dispatch = |record: DiscoveryRecord| {
        records.push(record);
        Ok(())
    };
    let result = service(window.max_rows, window.deadline, &mut dispatch);
    for record in &records {
        book.observe_record(record);
    }
    if let Err(failure) = &result {
        // A record that could not be decoded may have been an exec of the
        // PID target: custody since the last clean health read is unproven.
        book.mark_unproven(
            book.health_ns,
            format!("a lifecycle record was lost: {:#}", failure.error),
        );
    }
    match result {
        Ok(service) => DiscoveryBatch {
            records,
            record_bound_reached: service.record_bound_reached,
            deadline_reached: service.deadline_reached,
            failure: None,
        },
        Err(failure) => {
            // Dispatch never fails here, so no consumed record is held back.
            if let Some(record) = failure.record {
                book.observe_record(&record);
                records.push(*record);
            }
            DiscoveryBatch {
                records,
                record_bound_reached: false,
                deadline_reached: false,
                failure: Some(format!("{:#}", failure.error)),
            }
        }
    }
}

fn read_witnesses_from(
    state: Option<&mut InventoryState>,
    book: &mut CaptureBook,
    phase: CapturePhase,
    window: ReadWindow,
) -> WitnessBatch {
    let mut batch = WitnessBatch {
        domain: book.domain,
        phase,
        rows: Vec::new(),
        integrity: Vec::new(),
        integrity_total: book.integrity_total,
        visited: 0,
        sweep_completed: false,
        sweeps_completed: book.cursor.sweeps_completed(),
        row_bound_reached: false,
        deadline_reached: false,
        read_failures: Vec::new(),
        unrecorded_rows: 0,
        sweep_gaps: false,
        seen_rows: book.cursor.occupancy(),
        pair_limit: book.pair_limit,
        health: CaptureHealth::default(),
        health_regression: None,
        health_unproven: None,
        health_baseline_ns: book.health_ns,
        health_read_ns: 0,
        changed_objects: Vec::new(),
        custody: book.custody(),
        custody_proven_ns: book.scope.map(|_| book.held_ns),
        unsettled: book.stopping,
    };
    let Some(state) = state else {
        apply_health(
            &mut batch,
            HealthAssessment {
                regression: None,
                unproven: Some("the capture object is not held".into()),
            },
        );
        return batch;
    };
    // Health first, on its own fixed budget: a row quantum that spends
    // its deadline never turns into unproven health.
    let health_at = monotonic_ns();
    batch.health_read_ns = health_at;
    let snapshot = state.health(Instant::now() + HEALTH_READ_BUDGET);
    batch.health = CaptureHealth::from_snapshot(snapshot, state);
    let assessed = assess_health(book, &batch.health);
    book.observe_lifecycle(&batch.health);
    if assessed.unproven.is_none() {
        book.health_ns = health_at;
    }
    apply_health(&mut batch, assessed);
    batch.changed_objects = recheck_pins(state, book);
    let capacity = state.endpoint_capacity();
    let published = &book.published;
    let failed = &book.failed;
    let scope_pid = book.scope_pid();
    let mut io: &Ebpf = state.ebpf();
    let read = book.cursor.read_with(
        &mut io,
        window.max_rows,
        window.deadline,
        capacity,
        |endpoint| published.get(&endpoint).map(|object| object.index()),
        |_, value| witness_rejection(failed, scope_pid, value),
    );
    absorb_rows(book, &mut batch, read);
    batch.custody = book.custody();
    batch.custody_proven_ns = book.scope.map(|_| book.held_ns);
    batch
}

/// Records one health assessment on the batch. Unproven health never
/// settles a read: a terminal read that cannot prove health cannot close
/// any watch as clean (C5 ends watches at the last read with proven
/// health, never at this one).
fn apply_health(batch: &mut WitnessBatch, assessed: HealthAssessment) {
    batch.health_regression = assessed.regression;
    batch.health_unproven = assessed.unproven;
    batch.unsettled |= batch.health_unproven.is_some();
}

/// Rows a published binding alone does not make witnesses: a failed
/// endpoint's row is integrity evidence (its link may be suspect), and a
/// PID-scoped capture rejects any other tgid.
fn witness_rejection(
    failed: &BTreeMap<u32, String>,
    scope_pid: Option<u32>,
    value: &CallerObjectUse,
) -> Option<String> {
    if let Some(reason) = failed.get(&value.witness_endpoint) {
        return Some(format!(
            "CALLER_USE witness endpoint {} failed its attach ({reason})",
            value.witness_endpoint
        ));
    }
    scope_pid
        .filter(|pid| value.host_tgid != *pid)
        .map(|pid| format!("host tgid {} is outside PID scope {pid}", value.host_tgid))
}

/// Rechecks at most `PIN_RECHECK_PER_READ` held pins, round-robin, and
/// returns the objects newly found changed (or unreadable).
fn recheck_pins(state: &mut InventoryState, book: &mut CaptureBook) -> Vec<AttachObjectId> {
    let (checked, next) = state.recheck_pins(book.recheck_after, PIN_RECHECK_PER_READ);
    book.recheck_after = next;
    let mut changed = Vec::new();
    for (object, unchanged) in checked {
        if unchanged.unwrap_or(false) {
            continue;
        }
        let Some(object) = book
            .published
            .values()
            .find(|attach| attach.index() == object.0)
            .copied()
        else {
            continue;
        };
        if book.changed_objects.insert(object) {
            changed.push(object);
        }
    }
    changed
}

fn absorb_rows(
    book: &mut CaptureBook,
    batch: &mut WitnessBatch,
    read: super::callers::CallerRowsRead,
) {
    for (key, value) in read.rows {
        let object = book.published[&value.witness_endpoint];
        batch.rows.push(WitnessRow {
            domain: book.domain,
            image: key.image,
            object,
            endpoint: EndpointId(value.witness_endpoint),
            host_tgid: value.host_tgid,
            recorded_at_ns: value.recorded_at_ns,
        });
    }
    for (key, value, fault) in read.faults {
        let reason = match fault {
            CallerRowFault::InvalidKey => {
                "CALLER_USE key is invalid (no image or reserved bits)".into()
            }
            CallerRowFault::InvalidValue => {
                "CALLER_USE value is invalid for this capture's endpoint capacity".into()
            }
            CallerRowFault::Vanished => "CALLER_USE row vanished between key and lookup".into(),
            CallerRowFault::UnpublishedEndpoint => {
                "CALLER_USE witness endpoint was never published by this capture".into()
            }
            CallerRowFault::BindingMismatch { published } => format!(
                "CALLER_USE row names object {} but its witness endpoint is bound to object {published}",
                key.object_id
            ),
            CallerRowFault::Rejected(reason) => reason,
        };
        batch
            .integrity
            .push(WitnessIntegrity { key, value, reason });
    }
    book.integrity_total = book
        .integrity_total
        .saturating_add(batch.integrity.len() as u64);
    batch.integrity_total = book.integrity_total;
    batch.visited = read.visited;
    batch.sweep_completed = read.sweep_completed;
    batch.sweeps_completed = book.cursor.sweeps_completed();
    batch.row_bound_reached = read.row_bound_reached;
    batch.deadline_reached = read.deadline_reached;
    batch.read_failures = read.read_failures;
    batch.unrecorded_rows = read.unrecorded;
    batch.sweep_gaps = read.sweep_gaps;
    batch.seen_rows = book.cursor.occupancy();
}

/// A rise in any watch-relevant counter since the last readable health
/// read (reported once: the baseline then moves on), and whether this
/// read proves health at all. Unreadable health is unproven, never a
/// regression, and leaves the baseline where it was, so a rise hidden
/// behind it is reported by the next readable read. A poisoned OWNER_CTL
/// is a regression on its transition and unproven while it lasts.
fn assess_health(book: &mut CaptureBook, health: &CaptureHealth) -> HealthAssessment {
    let Some(current) = health
        .watch_counters()
        .filter(|_| health.failures.is_empty())
    else {
        let detail = if health.failures.is_empty() {
            "a health cell is missing".to_string()
        } else {
            health.failures.join("; ")
        };
        return HealthAssessment {
            regression: None,
            unproven: Some(format!("native capture health was unreadable: {detail}")),
        };
    };
    let previous = book.baseline.replace(current).unwrap_or_default();
    let mut rose = Vec::new();
    let mut compare = |name: &str, before: &[u64], after: &[u64]| {
        for (index, (before, after)) in before.iter().zip(after).enumerate() {
            if after > before {
                rose.push(format!("{name}[{index}] {before}->{after}"));
            }
        }
    };
    compare(
        "CALLER_EVIDENCE",
        &previous.caller_evidence,
        &current.caller_evidence,
    );
    compare(
        "USAGE_EVIDENCE",
        &previous.usage_evidence,
        &current.usage_evidence,
    );
    compare(
        "COOKIE_CTL(unavailable,create_failures,retry_exhausted)",
        &previous.identity,
        &current.identity,
    );
    compare("EVIDENCE", &previous.evidence, &current.evidence);
    compare(
        "OWNER_CTL(admission_failures,reclamation_failures)",
        &previous.owner_failures,
        &current.owner_failures,
    );
    if current.owner_poisoned && !previous.owner_poisoned {
        rose.push("OWNER_CTL.poison set: scope_auth refuses every entry".into());
    }
    HealthAssessment {
        regression: (!rose.is_empty())
            .then(|| format!("native capture health counters rose: {}", rose.join(", "))),
        unproven: current
            .owner_poisoned
            .then(|| "OWNER_CTL is poisoned: scope_auth refuses every entry".to_string()),
    }
}

fn query_cookie_in(ebpf: Option<&Ebpf>, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
    let Some(ebpf) = ebpf else {
        return CookieQuery::Unavailable("the capture object is not held".into());
    };
    let pidfd = match pin.pidfd() {
        Ok(pidfd) => pidfd,
        Err(error) => return CookieQuery::Unavailable(format!("{error}")),
    };
    let data = match ebpf.map("TASK_COOKIE") {
        Some(Map::Unsupported(data)) => data,
        _ => return CookieQuery::Unavailable("TASK_COOKIE map unavailable".into()),
    };
    let map_fd = data.fd().as_fd();
    query_cookie_with(
        domain,
        || pin.original_exited(),
        |value| {
            crate::attach::pidfd_task_storage_lookup_with(
                map_fd,
                pidfd,
                value,
                crate::attach::bpf_map_element_syscall,
            )
        },
    )
}

/// The query discipline: pidfd live before, one lookup, live after.
fn query_cookie_with(
    domain: NativeDomainId,
    exited: impl Fn() -> std::result::Result<bool, String>,
    lookup: impl FnOnce(&mut u64) -> std::io::Result<()>,
) -> CookieQuery {
    match exited() {
        Ok(false) => {}
        Ok(true) => return CookieQuery::Exited,
        Err(error) => return CookieQuery::Unavailable(error),
    }
    let mut cookie = 0u64;
    let looked_up = lookup(&mut cookie);
    match exited() {
        Ok(false) => {}
        Ok(true) => return CookieQuery::Exited,
        Err(error) => return CookieQuery::Unavailable(error),
    }
    match looked_up {
        Ok(()) if cookie != 0 => CookieQuery::Cookie(DomainCookie::new(domain, cookie)),
        Ok(()) => CookieQuery::Unavailable("TASK_COOKIE holds a zero cell".into()),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => CookieQuery::NoCookie,
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => CookieQuery::Exited,
        Err(error) => CookieQuery::Unavailable(format!("TASK_COOKIE lookup: {error}")),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod privileged_tests;
