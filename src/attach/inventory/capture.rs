//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
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
//!   Custody is re-polled on every `custody()` and witness read, in every
//!   phase (retiring and retired reads too). A
//!   thread-group leader that exited while other threads run (its
//!   `/proc/<pid>/stat` state reads `Z`) silences the OneProcess entries
//!   although the pidfd stays live (privileged probe
//!   `privileged_inventory_capture_pid_scope_leader_exit_probe_lp64`), so
//!   it, an observed exec, and any lifecycle loss (ring loss, a malformed
//!   record, a failed discovery quantum) make custody `PidUnproven`.
//!   System scope has no custody: the earliest lifecycle loss rides every
//!   later witness batch as a sticky `lifecycle_loss` instead.
//! - (f) Backends (C5.11): Singles attaches one perf link per entry. Multi
//!   attaches each extend's entries as uprobe-multi attach groups, one per
//!   (object, entry program): every member is published before the group's
//!   link exists, the pin is checked before and after the group, custody
//!   after it. A group is an immutable offset set: a later extend adds new
//!   groups and never touches an existing one, no endpoint is ever a member
//!   of two live groups, and nothing detaches a group (or any member of
//!   one) before stop, which closes every group whole. Should a member
//!   ever need retirement or replacement before stop, the explicit group
//!   rebuild rule applies (system-scale plan Task 2.3: retire the whole
//!   group, publish the gap, then rebuild or demote it whole); there is no
//!   such path today, because endpoints only grow, a failed endpoint is
//!   never retried, and a changed pin demotes coverage, not links. The
//!   kernel isolates refused sites (bisect), so they fail one by one; a
//!   post-attach failure fails every member, its links kept in custody.
//!   Scope filtering (C5.11 security review): System scope links use
//!   pid 0 (every process is in scope). PID scope links name the target
//!   (the kernel pid filter, which holds the target's task: a process
//!   that later reuses the PID never fires them) and keep the in-BPF
//!   PID_FILTER tgid guard as defence in depth. `prepare` admits a
//!   PID-scoped Multi capture only when the functional probe
//!   ([`crate::attach::kernel_multi_pid_filter`]) proved the kernel filter
//!   covers every thread; a pid-0 group under PID scope would rest on the
//!   tgid *number* alone, which a reused PID passes.
//! - (g) Health: a counter rise is a `health_regression` (once per rise);
//!   unreadable health or a poisoned OWNER_CTL is a non-sticky
//!   `health_unproven` that only withholds that pass's watches.
//!
//! Costs: Singles holds one perf link and one FD per attached endpoint;
//! Multi one FD per attach group (plus one per kernel-isolated refused
//! site's split), both plus two roots and the DISCOVERY ring. `prepare`
//! raises RLIMIT_NOFILE and refuses with [`CaptureCapacityLimited`]
//! (`fds`) unless the backend's link bound + 3 + a reserve fit.
//! Retained objects are shared clones of the attach set's open files (no
//! new FDs). A witness read costs two syscalls per visited row, keeps a
//! seen set bounded by the pair limit P, and rechecks at most
//! [`PIN_RECHECK_PER_READ`] held object pins; the count refresh then
//! re-reads witnessed rows within the same window (one batch step where
//! the kernel has it, else a per-key walk); a cookie query is one
//! syscall plus two pidfd polls.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) use super::activation::InfoTeardown;
use super::activation::{
    ActiveInventory, InventoryEndpoint, InventoryGroupRequest, InventoryHealthSnapshot,
    InventoryLinkIdentity, InventoryLinkIo, InventoryLinked, InventoryState, InventoryTargets,
    RetiredInventory, RetiringInventory, attach_published_entry_with, attach_published_return_with,
    require_live_pid_custody, service_inventory_discovery_with, validate_entry,
};
use super::callers::{CallerRowFault, CallerUseCursor, CallerUseIo};
use super::{AttachBackend, PreparedInventory, Scope};
#[cfg(test)]
pub(crate) use crate::attach::selected_detailed::baseline::scripted_observation;
pub(crate) use crate::attach::selected_detailed::baseline::{
    BindingObservation, CallerImageObservation,
};
use crate::capacity::{CallerBudget, InventoryBudget};
use crate::discovery::identity::{PinnedObjectId, RetainedInventoryTarget};
use crate::discovery::inventory_attach_set::{
    AttachEndpoint, AttachObjectId, EndpointId, InventoryAttachSet, TargetDelta,
};
use crate::process::PidPin;
use anyhow::{Context as _, Result, bail, ensure};
use aya::Ebpf;
use aya::maps::Map;
use p11scope_ebpf_common::inventory_callers::{CallerObjectKey, CallerObjectUse};
use p11scope_ebpf_common::{
    DISCOVERY_KIND_EXEC, DiscoveryRecord, ImageIdentity, ImageIdentityControl, ThreadOwnerControl,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::os::fd::AsFd as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The health read's own budget, separate from the row window: a row
/// quantum that spends its deadline never makes health unreadable.
const HEALTH_READ_BUDGET: Duration = Duration::from_millis(50);

/// Held object pins rechecked per witness read (round-robin).
pub(crate) const PIN_RECHECK_PER_READ: usize = 64;

/// Descriptors kept free beyond the link bound + 3 (pidfds, the caller's
/// own files).
pub(crate) const FD_RESERVE: u64 = 64;

/// Multi's link bound for the descriptor preflight. Each (object, entry
/// program) group of one extend attaches in links of
/// [`MULTI_LINK_MIN_SITES`]..=[`MULTI_LINK_MAX_SITES`] sites (sized by
/// `multi_link_sites`), so a capture holds at most about N/8 full links
/// plus one partial remainder per group per extend, plus a leaf per
/// kernel-isolated refused site (bisect); usually far fewer (96-site links
/// for providers few processes map). A capture that outgrows this bound
/// meets EMFILE, which defers the rest explicitly (`fd_exhausted`), as for
/// Singles.
pub(crate) const MULTI_LINK_BOUND: u64 = 1024;

/// Multi link sizing (review M1, controller ruling: adaptive). A group
/// attach is one uninterruptible `BPF_LINK_CREATE` whose cost is about
/// sites x processes mapping the object (each registration walks every
/// mm), and the extend deadline is checked only between links. Each link's
/// site count is chosen so one attach stays near [`MULTI_LINK_TARGET`]:
/// cheap objects keep whole function tables in one link (96 covers a
/// v2.40 or v3.0 table), and an object mapped by hundreds of processes
/// attaches in small links the deadline can stop between. An (object,
/// program) group larger than one link attaches as several immutable
/// groups.
pub(crate) const MULTI_LINK_TARGET: Duration = Duration::from_millis(200);
/// The fewest sites a link carries (a floor on link count and fds).
pub(crate) const MULTI_LINK_MIN_SITES: usize = 8;
/// The most sites a link carries.
pub(crate) const MULTI_LINK_MAX_SITES: usize = 96;
/// Cost model for a link's first estimate, per site: a base plus a share
/// per mapping process. Derived conservatively from host 7.0 (C5.11 M1):
/// 3,264 sites with one mapper each cost <= 0.16 ms/site (10.4 ms for a
/// 68-site link); 64-68 sites with 500 mappers cost 5.2-9.9 ms/site, i.e.
/// 10-20 us per site per mapper; the upper end is used.
pub(crate) const MULTI_LINK_SITE_BASE_NS: u64 = 150_000;
pub(crate) const MULTI_LINK_SITE_PER_MAPPER_NS: u64 = 20_000;

/// The first link of an object whose mapper count discovery cannot know
/// (a scope-limited view, review R4): 16 sites stay near the target even
/// at 500 mappers (<= 10 ms per site there), and the measured cost grows
/// the next links up to the max.
pub(crate) const MULTI_LINK_SCOPE_LIMITED_SITES: usize = 16;

/// What discovery knows of the processes mapping one object: the first
/// estimate of a uprobe-multi link's cost (review M1, R4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MapperEstimate {
    /// A whole-system pass saw this many processes mapping it (deep-scanned
    /// or attributed by maps identity).
    System(usize),
    /// Discovery saw a limited scope (`--pid`): the kernel's registration
    /// still walks every process mapping the object, which this view does
    /// not count, so the first link starts at
    /// [`MULTI_LINK_SCOPE_LIMITED_SITES`].
    ScopeLimited,
    /// No pass has reported (tests and pre-pass callers): as one mapper.
    Unknown,
}

/// The sites of the next link of one object: from the per-site cost the
/// previous link of that object measured when there is one, else from
/// what discovery knows of its mappers (the cost model over a system
/// count, unknown counting as one; a conservative fixed start for a
/// scope-limited view). Always within the min and max.
pub(crate) fn multi_link_sites(
    mappers: MapperEstimate,
    measured_ns_per_site: Option<u64>,
) -> usize {
    let per_site = match (measured_ns_per_site, mappers) {
        (Some(measured), _) => measured,
        (None, MapperEstimate::ScopeLimited) => return MULTI_LINK_SCOPE_LIMITED_SITES,
        (None, MapperEstimate::System(count)) => link_site_estimate(count),
        (None, MapperEstimate::Unknown) => link_site_estimate(1),
    };
    let target = u64::try_from(MULTI_LINK_TARGET.as_nanos()).unwrap_or(u64::MAX);
    let sites = usize::try_from(target / per_site.max(1)).unwrap_or(usize::MAX);
    sites.clamp(MULTI_LINK_MIN_SITES, MULTI_LINK_MAX_SITES)
}

/// The cost model's per-site estimate for `mappers` mapping processes.
fn link_site_estimate(mappers: usize) -> u64 {
    let mappers = u64::try_from(mappers).unwrap_or(u64::MAX);
    MULTI_LINK_SITE_BASE_NS.saturating_add(MULTI_LINK_SITE_PER_MAPPER_NS.saturating_mul(mappers))
}

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

/// The entry links a capture may hold: one per endpoint under Singles, at
/// most [`MULTI_LINK_BOUND`] (and never more than N) under Multi.
pub(crate) fn entry_link_bound(backend: AttachBackend, endpoint_limit: u64) -> u64 {
    match backend {
        AttachBackend::Singles => endpoint_limit,
        AttachBackend::Multi => endpoint_limit.min(MULTI_LINK_BOUND),
    }
}

/// The descriptor preflight: the backend's entry-link bound + 2 roots +
/// the DISCOVERY ring + the INFO ring + `FD_RESERVE` must fit what the
/// soft limit leaves free. Info returns stay excluded from the hard
/// preflight (keymeta Task 7, spec §17.4 N4): they attach
/// opportunistically and defer on EMFILE, never stopping the capture.
fn fd_preflight(
    backend: AttachBackend,
    endpoint_limit: u64,
    soft_limit: u64,
    in_use: u64,
) -> std::result::Result<(), CaptureCapacityLimited> {
    let links = entry_link_bound(backend, endpoint_limit);
    let needed = links.saturating_add(4).saturating_add(FD_RESERVE);
    let free = soft_limit.saturating_sub(in_use);
    if needed > free {
        let what = match backend {
            AttachBackend::Singles => format!(
                "N={endpoint_limit} entries need {needed} descriptors (N + 4 + {FD_RESERVE} reserve)"
            ),
            AttachBackend::Multi => format!(
                "N={endpoint_limit} entries in up to {links} attach-group links need {needed} descriptors ({links} + 4 + {FD_RESERVE} reserve)"
            ),
        };
        return Err(CaptureCapacityLimited {
            resource: FD_RESOURCE,
            detail: format!(
                "{what} but RLIMIT_NOFILE {soft_limit} leaves {free} free ({in_use} in use)"
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

/// Initial caller-pair limit P (plan §10 ruling D6): 65,536 pairs, 4 MiB
/// of map payload. Re-tuned from C5 measurements (DR-07).
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
        .zip(pairs.checked_mul(crate::capacity::CALLER_PAIR_BYTES))
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
    /// The existing retained cgroup scope; membership is filtered in BPF.
    #[cfg_attr(not(test), allow(dead_code))] // Cg4 wires the public command.
    Cgroup(CgroupCaptureScope),
}

/// Constructor-validated cgroup data. Retain the original Scope and root FD;
/// callers cannot substitute a System/PID scope or reopen an operator path.
#[derive(Clone)]
pub(crate) struct CgroupCaptureScope {
    scope: Scope,
}

impl CgroupCaptureScope {
    pub(crate) fn root(&self) -> &std::sync::Arc<std::fs::File> {
        let Scope::Cgroup { dir, .. } = &self.scope else {
            unreachable!("the cgroup constructor validates its scope")
        };
        dir
    }
}

impl CaptureScope {
    #[cfg_attr(not(test), allow(dead_code))] // Cg4 wires the public command.
    pub(crate) fn cgroup(scope: Scope) -> Result<Self> {
        if !matches!(scope, Scope::Cgroup { .. }) {
            bail!("Inventory cgroup capture requires a retained cgroup scope");
        }
        Ok(Self::Cgroup(CgroupCaptureScope { scope }))
    }

    pub(crate) fn scope_coverage(&self) -> CaptureScopeCoverage {
        match self {
            Self::System => CaptureScopeCoverage::System,
            Self::Pid(pin) => CaptureScopeCoverage::Pid(ScopeIncarnation {
                pid: pin.pid(),
                start_time: pin.start_time(),
            }),
            Self::Cgroup(_) => CaptureScopeCoverage::Cgroup,
        }
    }

    pub(crate) fn clone_for_prepare(&self) -> Result<Self> {
        match self {
            Self::System => Ok(Self::System),
            Self::Pid(pin) => Ok(Self::Pid(
                pin.try_clone()
                    .map_err(anyhow::Error::msg)
                    .context("cloning the PID custody for a preparation")?,
            )),
            Self::Cgroup(cgroup) => Ok(Self::Cgroup(cgroup.clone())),
        }
    }

    fn into_prepared_scope(self) -> Result<CapturePreparation> {
        Ok(match self {
            Self::System => CapturePreparation {
                scope: Scope::System,
                pid_pin: None,
                held_scope: HeldCaptureScope::System,
            },
            Self::Pid(pin) => {
                require_live_pid_custody(&pin)?;
                let incarnation = ScopeIncarnation {
                    pid: pin.pid(),
                    start_time: pin.start_time(),
                };
                CapturePreparation {
                    scope: Scope::Pid(pin.pid()),
                    pid_pin: Some(pin),
                    held_scope: HeldCaptureScope::Pid(incarnation),
                }
            }
            Self::Cgroup(cgroup) => CapturePreparation {
                held_scope: HeldCaptureScope::Cgroup {
                    _root: std::sync::Arc::clone(cgroup.root()),
                },
                scope: cgroup.scope,
                pid_pin: None,
            },
        })
    }
}

struct CapturePreparation {
    scope: Scope,
    pid_pin: Option<PidPin>,
    held_scope: HeldCaptureScope,
}

enum HeldCaptureScope {
    System,
    Pid(ScopeIncarnation),
    /// Root custody only; this never proves continuous caller membership.
    Cgroup {
        _root: std::sync::Arc<std::fs::File>,
    },
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

    /// The entry bound (scripted facades honour it, like [`ReadWindow::max_rows`]).
    #[cfg(test)]
    pub(crate) fn max_entries(&self) -> usize {
        self.max_entries
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

    /// The row bound (scripted facades honour it).
    pub(crate) fn max_rows(&self) -> usize {
        self.max_rows
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
}

/// One loaded object's identity domain. Cookies are tickets inside one
/// domain only; two domains' cookies are never comparable, so this type
/// has equality and nothing else (no order, no numeric access).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NativeDomainId(u64);

static NEXT_DOMAIN: AtomicU64 = AtomicU64::new(1);

impl NativeDomainId {
    /// The single minting point for every native identity domain in the
    /// process: the Inventory capture here and the Detailed (C6) object
    /// alike must mint through it, so no two loaded objects ever share
    /// a domain.
    pub(crate) fn try_mint() -> Result<Self> {
        mint_domain_from(&NEXT_DOMAIN)
    }

    /// Opaque identity word for sealed journal-domain minting (H8): the
    /// process-unique domain tag as the model domain's native-source word.
    /// Equality only; never ordered or compared across domains beyond the
    /// model key's own equality. Only the journal child may call this.
    pub(crate) fn journal_tag(self) -> u64 {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn mint() -> Self {
        Self::try_mint().expect("test domain allocation is not exhausted")
    }
}

fn mint_domain_from(counter: &AtomicU64) -> Result<NativeDomainId> {
    let value = counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            if next == 0 { None } else { next.checked_add(1) }
        })
        .map_err(|_| anyhow::anyhow!("native identity domain exhausted"))?;
    Ok(NativeDomainId(value))
}

#[cfg(test)]
mod domain_mint_tests {
    use super::*;

    #[test]
    fn domain_mint_refuses_zero_and_exhaustion_without_reusing_identity() {
        for initial in [0, u64::MAX] {
            let counter = AtomicU64::new(initial);
            assert!(mint_domain_from(&counter).is_err());
            assert_eq!(counter.load(Ordering::Relaxed), initial);
        }
        let counter = AtomicU64::new(u64::MAX - 1);
        let last = mint_domain_from(&counter).unwrap();
        assert_eq!(last, NativeDomainId(u64::MAX - 1));
        assert!(mint_domain_from(&counter).is_err());
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}

/// A TASK_COOKIE ticket tagged with the domain that issued it. Equality
/// only: a cookie is comparable with another of the same domain and with
/// nothing else, never as a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DomainCookie {
    domain: NativeDomainId,
    cookie: u64,
}

impl DomainCookie {
    pub(crate) fn new(domain: NativeDomainId, cookie: u64) -> Self {
        Self { domain, cookie }
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    /// A scripted ticket for binder tests (never a host read).
    #[cfg(test)]
    pub(crate) fn scripted(domain: NativeDomainId, cookie: u64) -> Self {
        Self::new(domain, cookie)
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

/// Capture coverage is explicit. A cgroup root does not carry the machine's
/// or one PID incarnation's continuous-membership authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureScopeCoverage {
    System,
    Pid(ScopeIncarnation),
    Cgroup,
}

/// Where the retained targets for a delta's objects come from: the attach
/// set in production. The facade takes shared clones; it never borrows.
pub(crate) trait CaptureTargets {
    fn target(&self, object: AttachObjectId) -> Option<&RetainedInventoryTarget>;
    /// What discovery last knew of the processes mapping `object`: the
    /// first estimate of a uprobe-multi link's cost (`multi_link_sites`).
    fn mappers(&self, _object: AttachObjectId) -> MapperEstimate {
        MapperEstimate::Unknown
    }
}

impl CaptureTargets for InventoryAttachSet {
    fn target(&self, object: AttachObjectId) -> Option<&RetainedInventoryTarget> {
        InventoryAttachSet::target(self, object)
    }

    fn mappers(&self, object: AttachObjectId) -> MapperEstimate {
        InventoryAttachSet::mappers(self, object)
    }
}

/// Retained scope custody. PID states track the original process; cgroup
/// custody tracks the original root through terminal reads. Every non-held
/// PID state is sticky; `at_ns` (CLOCK_MONOTONIC) is the
/// earliest instant the coverage can have stopped being proven: the exec
/// record's own instant, else the last poll or health read that still
/// proved custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScopeCustody {
    System,
    /// The original cgroup root remains held, including after detach. This
    /// says nothing about active links or continuous caller residency.
    CgroupHeld,
    /// The original pidfd is live, its leader thread is alive, and no
    /// lifecycle record was lost or seen: every entry link fires for it.
    PidHeld,
    /// The retained original pidfd proved exit without earlier uncertainty.
    /// This preserves only historical counts of its already-bound image.
    PidExited {
        at_ns: u64,
        proof: OriginalPidExit,
    },
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

/// An irreversible fact about the capture's original pin, never current
/// process or semantic authority. Only a successful original-pidfd poll mints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OriginalPidExit {
    domain: NativeDomainId,
    scope: ScopeIncarnation,
}

impl OriginalPidExit {
    fn from_poll(
        domain: NativeDomainId,
        scope: ScopeIncarnation,
        pin: &PidPin,
        poll: &CustodyPoll,
    ) -> Option<Self> {
        (matches!(poll, CustodyPoll::Exited)
            && pin.pidfd().is_ok()
            && scope.start_time.is_some()
            && scope.pid == pin.pid()
            && scope.start_time == pin.start_time())
        .then_some(Self { domain, scope })
    }

    pub(crate) fn domain(self) -> NativeDomainId {
        self.domain
    }

    pub(crate) fn scope(self) -> ScopeIncarnation {
        self.scope
    }

    #[cfg(test)]
    pub(crate) fn scripted(domain: NativeDomainId, scope: ScopeIncarnation) -> Self {
        assert!(scope.start_time.is_some());
        Self { domain, scope }
    }
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

/// The instant a BPF domain's lifecycle coverage began: stamped by the
/// facade on CLOCK_MONOTONIC only after `activate_roots` returned success,
/// so the exec tracepoint and the DISCOVERY reader were attached before it.
/// An exec at or after `start_ns` that the scope admits produces a
/// lifecycle record (or a ring-loss count); an exec before it left none.
/// Only the facade constructs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecCoverage {
    domain: NativeDomainId,
    start_ns: u64,
}

impl ExecCoverage {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    pub(crate) fn start_ns(&self) -> u64 {
        self.start_ns
    }

    /// A scripted coverage start for binder tests (never a host read).
    #[cfg(test)]
    pub(crate) fn scripted(domain: NativeDomainId, start_ns: u64) -> Self {
        Self { domain, start_ns }
    }
}

/// One attach group the capture created (Multi): its kernel links and its
/// members never change; it is closed whole, at stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachGroup {
    /// The group's serial in this capture (its links' identity).
    pub serial: u32,
    pub object: AttachObjectId,
    pub program: &'static str,
    /// Members whose sites the kernel holds, in delta order.
    pub members: Vec<EndpointId>,
    /// Kernel links the group holds (one, unless the kernel refused a site
    /// and the group was split around it).
    pub links: usize,
}

/// Keymeta Task 7 (spec §17.4, N4): one deferred info return — an
/// endpoint (Singles) or a return group (Multi) whose link met
/// EMFILE. The endpoint stays attached and `known`; the retry
/// re-attaches the return and publishes `INFO_KIND` once.
#[derive(Debug, Clone)]
pub(crate) enum InfoReturnPending {
    Singles(AttachEndpoint),
    Multi {
        object: AttachObjectId,
        sites: Vec<PendingReturnSite>,
        /// The entry group's serial: the retried return group
        /// carries it (the `ReturnGroup` variant distinguishes
        /// custody), so retried groups never share a serial.
        entry_serial: u32,
        /// Next site index to filter in `sites`: the filter resumes
        /// here, so an interrupted group never rescans its visited
        /// prefix nor copies its unvisited suffix. The storage stays
        /// across yields; only this cursor and `excluded` advance.
        validated: usize,
        /// The revocation epoch the prefix before `validated` was
        /// checked against: a newer epoch revalidates from the first
        /// site before publication, under the same visit allowance.
        validated_epoch: u64,
        /// Revoked site indexes (bit `i` = `sites[i]` revoked):
        /// irreversible, so a resumed filter never rechecks them.
        /// Covers the [`MULTI_LINK_MAX_SITES`] maximum (96 sites in
        /// two words); bits past `sites.len()` stay clear.
        excluded: [u64; 2],
        /// Survivors accumulated during credited filter visits, in
        /// site order: one push per visited surviving site, already
        /// charged. Cleared on an epoch change and rebuilt under
        /// the same allowance. Lets every yield and EMFILE requeue
        /// the original `sites` vector, cursor and mask with no
        /// post-filter scan or copy.
        staged: Vec<PendingReturnSite>,
        /// Attach points for `staged`, built alongside each push as
        /// (`file_offset`, `cookie`). Passed directly to the return
        /// group attach; never derived by a second scan.
        staged_points: Vec<(u64, u64)>,
    },
}

/// Whether Multi site `index` is excluded as revoked.
fn multi_site_excluded(excluded: &[u64; 2], index: usize) -> bool {
    let (word, bit) = (index / 64, index % 64);
    word < excluded.len() && (excluded[word] & (1u64 << bit)) != 0
}

/// Mark Multi site `index` excluded as revoked.
fn multi_site_exclude(excluded: &mut [u64; 2], index: usize) {
    let (word, bit) = (index / 64, index % 64);
    if let Some(slot) = excluded.get_mut(word) {
        *slot |= 1u64 << bit;
    }
}

/// One Multi return-group member awaiting its return link.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingReturnSite {
    pub endpoint: u32,
    pub file_offset: u64,
    pub cookie: u64,
    pub kind: u8,
}

/// Keymeta Task 7 ring cross-check (spec §17.4): the INFO drain
/// compares produced vs consumed per quantum, never a silent drop.
/// The difference is derived backlog (produced minus consumed):
/// provisional mid-run — submitted-but-undrained records read as
/// backlog until the next quantum drains them — and reported, never
/// certified, at the terminal cut (exact loss needs producer
/// quiescence, unproven under D3). A regressing read retains the
/// whole prior triple. Reserve failures (a full ring) never reach
/// this counter — no submit, no produced bump — and land in the
/// session's shared ring-loss counter instead, beside DISCOVERY losses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct InfoRingAccounting {
    pub produced: u64,
    pub consumed: u64,
    pub loss: u64,
}

impl InfoRingAccounting {
    pub(crate) fn note_info_quantum(&mut self, produced_now: u64, consumed_now: u64) {
        if produced_now < self.produced || consumed_now < self.consumed {
            return;
        }
        self.produced = produced_now;
        self.consumed = consumed_now;
        self.loss = produced_now.saturating_sub(consumed_now);
    }
}

/// What one `extend` did. Every endpoint of the delta lands in exactly one
/// of `attached`, `failed`, `known`, or `deferred`.
#[derive(Debug, Default)]
pub(crate) struct ExtendReceipt {
    /// This extend activated the object (DISCOVERY reader and roots).
    pub activated_roots: bool,
    /// Set exactly when `activated_roots`: where exec coverage began.
    pub exec_coverage: Option<ExecCoverage>,
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
    /// Keymeta Task 7 (spec §17.4, N4): info returns (Singles) or
    /// info return groups (Multi) that met EMFILE this extend. The
    /// endpoints stay attached (their usage entries still record);
    /// the returns retry from the private pending list.
    pub info_return_deferred: u64,
    /// Keymeta Task 7 (spec §17.4): info endpoints this extend
    /// downgraded to usage-only because the uretprobe-vs-seccomp
    /// admission refused (per endpoint; a dropped Multi group
    /// counts its sites). The entries still link and record; no
    /// return links and no `INFO_KIND` publish happens for them.
    #[allow(dead_code)] // The enforcement commit counts this.
    pub info_return_refused_hazard: u64,
    /// Keymeta Task 7 (spec §17.4): endpoints whose INFO kind this
    /// extend revoked (a later pass proved their names aliased).
    /// Fresh copies downgraded to usage-only, pendings purged and
    /// (FULL only) the INFO_KIND cell cleared.
    pub info_revoked: u64,
    /// Keymeta Task 7 (spec §17.4): revoked endpoints whose INFO_KIND
    /// write failed this extend. Each retries on the next extend;
    /// usage attaches proceed regardless.
    pub info_revoke_failed: u64,
    /// Multi: leaf links a halted group attach (EMFILE, or a kernel
    /// refusing uprobe-multi) had already created and then closed before
    /// they reached custody. Their members are deferred or failed with
    /// the rest of the group; while live, those leaves could only fire
    /// for published, in-scope entries.
    pub halt_closed_links: usize,
    /// Why nothing was attempted, when the whole extend refused.
    pub refused: Option<String>,
    pub custody: Option<ScopeCustody>,
    /// Attach cost: total and worst single-attach wall time (one entry
    /// under Singles, one group under Multi).
    pub attach_ns_total: u64,
    pub attach_ns_max: u64,
    /// The attach groups this extend created (Multi; empty under Singles).
    pub groups: Vec<AttachGroup>,
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
    /// The row's entry count at first sight (saturated): the baseline its
    /// refresh advances from. A lower bound while producers run.
    pub entry_count: u64,
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

    /// A scripted row for binder tests (never a host read): first seen
    /// with a count of one, like a fresh BPF insert.
    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        cookie: u64,
        exec_id: u64,
        object: AttachObjectId,
        endpoint: EndpointId,
        host_tgid: u32,
        recorded_at_ns: u64,
    ) -> Self {
        Self {
            domain,
            image: ImageIdentity {
                task_cookie: cookie,
                exec_id,
            },
            object,
            endpoint,
            host_tgid,
            recorded_at_ns,
            entry_count: 1,
        }
    }
}

/// A row that failed validation: integrity evidence, never dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WitnessIntegrity {
    pub key: CallerObjectKey,
    pub value: Option<CallerObjectUse>,
    pub reason: String,
}

/// One refreshed entry count: a witnessed row's image and object with the
/// saturated count the refresh re-read for it, above every earlier read.
/// A lower bound while producers run; the terminal read after stop is the
/// final word. Joins its witness row on (`image`, `object`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallerCountUpdate {
    pub image: ImageIdentity,
    pub object: AttachObjectId,
    pub count: u64,
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
        Self::from_parts(
            snapshot,
            state.malformed_discovery(),
            state.pin_check_failures(),
        )
    }

    fn from_parts(
        snapshot: InventoryHealthSnapshot,
        malformed_discovery: u64,
        pin_check_failures: u64,
    ) -> Self {
        Self {
            caller_evidence: snapshot.caller_evidence,
            caller_control: snapshot.caller_control,
            usage_evidence: snapshot.usage_evidence,
            evidence: snapshot.evidence,
            discovery_counters: snapshot.discovery_counters,
            owner: snapshot.owner,
            failures: snapshot.failures,
            malformed_discovery,
            pin_check_failures,
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

/// System-scope lifecycle evidence that was lost: `at_ns` is the earliest
/// instant the loss can date from — the last readable health read before
/// a ring-loss rise, or the last proven drain before an undecodable or
/// malformed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LifecycleLoss {
    pub at_ns: u64,
    pub reason: String,
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
    /// Witnessed rows whose entry count advanced since the last read, with
    /// the re-read saturated count. Lower bounds while producers run; the
    /// terminal read after stop carries the final ones. A row whose count
    /// never advanced past its first sight appears only on its witness
    /// row's `entry_count`, never here.
    pub counts: Vec<CallerCountUpdate>,
    /// This read completed a count-refresh sweep: every witnessed row was
    /// re-read (or skipped with `refresh_sweep_gaps`) since the sweep
    /// began.
    pub refresh_sweep_completed: bool,
    /// `refresh_sweep_completed`, but that sweep skipped a tracked row (a
    /// lookup failure): that row's count is stale, and the next sweep
    /// retries it.
    pub refresh_sweep_gaps: bool,
    /// The refresh quantum hit the window deadline before completing
    /// its sweep (F1): tracked rows went unvisited this pass, so
    /// their counts may be stale. The witness and refresh share the
    /// window's deadline and the witness runs first, so a witness
    /// scan that consumes the window starves the refresh with no
    /// failures or gaps. Discovery treats a starved refresh as
    /// count-refresh loss (lossy, never quiet).
    pub refresh_deadline_reached: bool,
    pub refresh_sweeps_completed: u64,
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
    /// CLOCK_MONOTONIC before this read's witness-row quantum. Every
    /// initial count was looked up at or after this batch PRE bound;
    /// it is not an exact per-pair lookup timestamp. `u64::MAX` means the
    /// clock failed; `0` means no row read was attempted.
    pub rows_anchor_ns: u64,
    /// CLOCK_MONOTONIC after this read's rows were read: every row here was
    /// inserted before it (`u64::MAX` when the clock read failed, `0`
    /// when nothing was read). Stamped after the count refresh too, so it
    /// also bounds every count here.
    pub rows_read_ns: u64,
    /// CLOCK_MONOTONIC before this read's count-refresh quantum. Every
    /// refreshed count was looked up at or after this batch PRE bound;
    /// it anchors base reads, never observations. `rows_read_ns` is the
    /// common POST bound for observations. `u64::MAX` means the clock
    /// failed; `0` means no refresh was attempted.
    pub counts_read_ns: u64,
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
    /// The start of the last discovery quantum proven to drain the
    /// lifecycle ring before this read (the book's creation before any
    /// drain): every lifecycle record reserved before it was dequeued, so
    /// any lifecycle loss found later dates at or after it. A read is
    /// clean no later than this (C5.2 closure I-1).
    pub lifecycle_proven_ns: u64,
    /// System scope: the earliest-dated lifecycle loss (DISCOVERY ring loss, a
    /// malformed record, a failed discovery quantum), sticky on every
    /// later batch. A lost exec or exit record may belong to any watched
    /// caller. PID scope reports the same loss as unproven custody.
    pub lifecycle_loss: Option<LifecycleLoss>,
    /// Read after stop began, after a failure, or with unproven health:
    /// never a settled terminal read (FD closure is not a
    /// callback-quiescence protocol, and unproven health proves nothing).
    pub unsettled: bool,
}

/// Whether one `WitnessBatch.read_failures` entry is a count-refresh
/// failure (not a witness failure): the refresh stamps every transport
/// error it hits with [`super::callers::REFRESH_FAILURE_PREFIX`].
pub(crate) fn is_refresh_failure(failure: &str) -> bool {
    failure.starts_with(super::callers::REFRESH_FAILURE_PREFIX)
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

/// Keymeta Task 7 (spec §17.4): one bounded INFO quantum, in
/// dequeue order — raw 176-byte records (decoded at staging) plus
/// the produced-vs-consumed cross-check snapshot.
#[derive(Debug, Clone)]
pub(crate) struct InfoBatch {
    /// The BPF domain these records came from, tagged by the facade
    /// that drained them (never by a caller).
    pub domain: NativeDomainId,
    pub records: Vec<[u8; 176]>,
    /// Malformed frames that ended this quantum (exact evidence).
    pub malformed: u64,
    /// Submitted INFO records over the capture so far (kernel half).
    pub produced: u64,
    /// Consumed INFO records over the capture so far (userspace half).
    pub consumed: u64,
    /// Derived backlog (produced minus consumed): provisional
    /// mid-run, reported at the terminal cut — never certified loss
    /// (exact loss needs producer quiescence, unproven under D3).
    pub loss: u64,
    /// True only for the session's terminal cut: the last quantum
    /// before the domain finishes, carrying the retirement outcome.
    /// Only a terminal batch reports its backlog cut; provisional
    /// mid-run readings stay in the batch (submitted-but-undrained
    /// backlog reads as loss until the next quantum drains it).
    pub terminal: bool,
    /// A dequeue failure stopped the quantum (a ring-read error, a
    /// refused bound): the cause, distinct from the malformed count.
    pub failure: Option<String>,
    /// Keymeta Task 7 evidence deltas (spec §17.4): INFO_EVIDENCE
    /// cells observed since the last quantum — insert failures,
    /// unmatched returns, nested overwrites, stash mismatches —
    /// indexed by the INFO_EVIDENCE_* consts. Zeros for P0.
    pub evidence_delta: [u64; 4],
    /// The INFO_EVIDENCE read failed this quantum (FULL only): the
    /// cause. Counts are not updated on a failed read, so a later
    /// success reports the full delta since the last success.
    pub evidence_error: Option<String>,
    /// True when this quantum drained the ring to empty: no record
    /// bound, no deadline and no dequeue failure stopped it. Only a
    /// complete terminal quantum reports its backlog cut; anything
    /// else reports incomplete.
    pub complete: bool,
    /// The produced counter read succeeded this quantum. False for
    /// P0 (no reader) and for failed map reads.
    pub produced_fresh: bool,
    /// The produced counter read failed this quantum (FULL only):
    /// the cause. The triple retains its prior values.
    pub produced_error: Option<String>,
    /// Retirement had settled when the session cut this terminal
    /// batch. Only the session sets this, only on terminal batches.
    pub retired: bool,
}

impl InfoBatch {
    pub(crate) fn empty(domain: NativeDomainId) -> Self {
        Self {
            domain,
            records: Vec::new(),
            malformed: 0,
            produced: 0,
            consumed: 0,
            loss: 0,
            terminal: false,
            failure: None,
            evidence_delta: [0; 4],
            evidence_error: None,
            complete: true,
            produced_fresh: false,
            produced_error: None,
            retired: false,
        }
    }
}

/// One bounded quantum of lifecycle records, in dequeue order.
pub(crate) struct DiscoveryBatch {
    /// The BPF domain these records came from, tagged by the facade that
    /// drained them (never by a caller).
    pub domain: NativeDomainId,
    /// CLOCK_MONOTONIC before the first dequeue (`u64::MAX` when the clock
    /// read failed): a complete drain covers reads finished before it.
    pub started_ns: u64,
    /// CLOCK_MONOTONIC after the last dequeue: where a failure is dated.
    pub finished_ns: u64,
    pub records: Vec<DiscoveryRecord>,
    pub record_bound_reached: bool,
    pub deadline_reached: bool,
    /// A malformed or unreadable record stopped the quantum. Under PID
    /// scope it makes custody unproven (a lifecycle record was lost).
    pub failure: Option<String>,
    /// The drain stopped at an empty read while the ring still held
    /// unconsumed bytes (`consumer != producer`): a reserved-but-uncommitted
    /// head can hide records committed behind it, so this quantum is not a
    /// complete drain even though no bound, deadline, or failure stopped it.
    pub head_pending: bool,
    /// The drain's high-water: the maximum producer-minus-consumer fill
    /// sampled before each dequeue. `None` when no reader existed (an
    /// empty or scripted batch). Timings telemetry only, never schema.
    pub drain_high_water_bytes: Option<u64>,
}

impl DiscoveryBatch {
    fn empty(domain: NativeDomainId) -> Self {
        let now = monotonic_ns();
        Self {
            domain,
            started_ns: now,
            finished_ns: now,
            records: Vec::new(),
            record_bound_reached: false,
            deadline_reached: false,
            failure: None,
            head_pending: false,
            drain_high_water_bytes: None,
        }
    }

    /// A scripted complete drain of `domain` at `at_ns` (binder tests).
    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        records: Vec<DiscoveryRecord>,
        at_ns: u64,
    ) -> Self {
        Self {
            started_ns: at_ns,
            finished_ns: at_ns,
            records,
            ..Self::empty(domain)
        }
    }

    /// Every record the ring held when the drain stopped was dequeued: no
    /// bound, deadline, failure, or busy head ended the quantum.
    pub(crate) fn drained(&self) -> bool {
        !self.record_bound_reached
            && !self.deadline_reached
            && self.failure.is_none()
            && !self.head_pending
    }
}

impl fmt::Debug for DiscoveryBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryBatch")
            .field("records", &self.records.len())
            .field("record_bound_reached", &self.record_bound_reached)
            .field("deadline_reached", &self.deadline_reached)
            .field("failure", &self.failure)
            .field("head_pending", &self.head_pending)
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
    /// Keymeta Task 7 (spec §17.4): the INFO_START scrub did not
    /// prove an empty stash (retained links refused it). Explicitly
    /// unproven, never silently dirty.
    pub info_teardown_unproven: bool,
    /// Keymeta Task 7 (spec §17.4): the scrub phase's last concrete
    /// failure, if it transferred unproven.
    pub info_scrub_error: Option<String>,
}

/// Facade bookkeeping that travels through every state.
struct CaptureBook {
    promotion_baseline_generation: u64,
    domain: NativeDomainId,
    budget: InventoryBudget,
    /// The backend this capture attaches entries with (fixed at prepare).
    backend: AttachBackend,
    /// Every attach group created so far (Multi), in creation order. Each
    /// endpoint is a member of at most one; bounded by N members.
    groups: Vec<AttachGroup>,
    /// Multi: the per-site attach cost (ns) the last link of each local
    /// object measured, which sizes that object's next link. Bounded by
    /// the retained objects.
    link_ns_per_site: BTreeMap<u32, u64>,
    pair_limit: usize,
    scope: HeldCaptureScope,
    /// Endpoint → object for every ENDPOINT_OBJECT binding this capture
    /// published and read back. Bounded by N. An entry here that is in
    /// neither `attached` nor `failed` is published-but-unattached (its
    /// attach hit EMFILE): a later extend retries the attach only.
    published: BTreeMap<u32, AttachObjectId>,
    attached: BTreeSet<u32>,
    /// Endpoints that failed: never retried. Bounded by N.
    failed: BTreeMap<u32, String>,
    /// Keymeta Task 7 (spec §17.4, N4): the private info-return
    /// pending list. An attached endpoint counts as already handled
    /// (`knows`) and is never resubmitted through the `deferred`
    /// backlog, so deferred info returns wait here instead. Every
    /// extend retries this list first, within the same window; the
    /// endpoints stay `known`.
    info_return_pending: VecDeque<InfoReturnPending>,
    /// Keymeta Task 7 (spec §17.4): the INFO produced-vs-consumed
    /// cross-check, noted per quantum.
    info_accounting: InfoRingAccounting,
    /// Keymeta Task 7 (spec §17.4): INFO records consumed over the
    /// capture so far (the userspace half of the cross-check).
    info_consumed: u64,
    /// Keymeta Task 7 (spec §17.4): malformed INFO frames over the
    /// capture so far (each ends its quantum with exact evidence).
    malformed_info: u64,
    /// Keymeta Task 7 (spec §17.4): last observed INFO_EVIDENCE
    /// cells, for per-quantum deltas.
    last_info_evidence: [u64; 4],
    /// Keymeta Task 7 (spec §17.4): revoked endpoints whose INFO_KIND
    /// cell writes still pend, oldest first. The queue persists
    /// across extends: each extend pops from the front up to its
    /// allowance, paced-out cells keep their place (never rebuilt),
    /// and failed or yielded cells cycle to the back, so unattempted
    /// cells always get a turn.
    pending_info_revoke: VecDeque<EndpointId>,
    /// Keymeta Task 7 (spec §17.4, INV-2): the pending queue's
    /// indexed membership plus each cell's resume substep, so
    /// enqueue dedups directly and a mid-cell yield resumes without
    /// redoing finished map operations.
    pending_info_revoke_step: BTreeMap<EndpointId, super::RevokeSubstep>,
    /// Keymeta Task 7 (spec §17.4): every endpoint ever revoked this
    /// capture, persistent and irreversible. Fresh copies downgrade
    /// and pending info returns drop against this set from their
    /// staging extend on, without rescanning the write queue.
    info_revoked: BTreeSet<u32>,
    /// Keymeta Task 7 (spec §17.4): the revoked set's epoch,
    /// bumped whenever the set grows, so a resumed Multi return
    /// filter revalidates survivors staged under an older set
    /// before publication.
    info_revoked_epoch: u64,
    custody_lost: Option<(u64, String)>,
    original_exit: Option<OriginalPidExit>,
    /// First reason PID-scope coverage became unproven (sticky).
    unproven: Option<(u64, String)>,
    /// System scope: the earliest-dated lifecycle loss (sticky).
    lifecycle_lost: Option<(u64, String)>,
    /// The last instant a custody poll proved the pidfd and leader live.
    held_ns: u64,
    /// The last readable health read; a ring-loss rise (a producer
    /// counter) found after it is dated here.
    health_ns: u64,
    /// The start of the last discovery quantum that drained the ring
    /// (`DiscoveryBatch::drained`; the book's creation before any
    /// producer exists): every record produced before it was dequeued.
    drained_ns: u64,
    /// `drained_ns` as of the previous lifecycle observation. A record
    /// that fails to decode or decodes malformed carries no instant and
    /// may have sat in the ring past any health read, so such a loss is
    /// dated at the last drain proven before it was dequeued (C5.2
    /// review fix 1), never at a health read.
    undatable_floor_ns: u64,
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
    /// Keymeta Task 7 (spec §17.4): the retained info-return
    /// uretprobe-vs-seccomp approval, mirroring the Detailed
    /// session's `return_probe_admission`. The self-probe runs at
    /// most once per capture through this; a refusal sticks in
    /// `info_return_refused` instead so no extend re-probes.
    return_probe_admission: Option<crate::uretprobe_hazard::ReturnProbeAdmission>,
    /// Keymeta Task 7 (spec §17.4): the hazard gate refused once,
    /// so info returns stay off for this capture (sticky,
    /// fail-closed: a kernel verdict cannot turn safe mid-capture).
    info_return_refused: bool,
    /// Keymeta Task 7 (spec §17.4): the hazard verdict source.
    /// Production assesses through `uretprobe_hazard::admit`;
    /// tests inject scripted verdicts (see `set_info_return_gate`).
    info_return_gate: Box<InfoReturnGate>,
}

/// Keymeta Task 7 (spec §17.4): one hazard assessment — the target
/// the trampoline would run in (`None`: any process may run it)
/// and the operator override — over the shared
/// `uretprobe_hazard::admit` shape, so production plugs `admit` in
/// directly.
type InfoReturnGate = dyn Fn(
        Option<u32>,
        bool,
    ) -> std::result::Result<
        crate::uretprobe_hazard::ReturnProbeAdmission,
        crate::uretprobe_hazard::Action,
    > + Send;

/// The one lifecycle-ring loss rule every consumer applies (the capture
/// book, the native binder, the lane's tally): a health read's DISCOVERY
/// ring-loss counter above what the consumer already saw is new loss.
/// Returns the new count, or `None` when nothing new was lost (or the
/// counters were not read).
pub(crate) fn ring_loss_rose(seen: u64, counters: Option<[u64; 5]>) -> Option<u64> {
    let ring_loss = counters?[0];
    (ring_loss > seen).then_some(ring_loss)
}

/// The capture book's demotion for [`ring_loss_rose`]: the new count and
/// the lifecycle-loss reason (custody or watch coverage demoted).
fn ring_loss_demotion(
    seen: u64,
    counters: Option<[u64; 5]>,
    hidden: &str,
) -> Option<(u64, String)> {
    ring_loss_rose(seen, counters).map(|ring_loss| {
        (
            ring_loss,
            format!(
                "the lifecycle ring lost records (DISCOVERY ring loss {seen} -> {ring_loss}): {hidden} may be among them"
            ),
        )
    })
}

/// Test seam for the I3a privileged cells' loaded-host mode: one real
/// health read (`health`, with the usage read's own malformed and pin
/// counts) through the production consumer of a fresh system-scope
/// capture book (`CaptureHealth::from_parts`, then `observe_lifecycle`).
/// Returns the lifecycle-loss mark the book now carries, if any.
#[cfg(test)]
pub(in crate::attach::inventory) fn system_book_lifecycle_loss(
    health: InventoryHealthSnapshot,
    malformed_discovery: u64,
    pin_check_failures: u64,
) -> Option<String> {
    let budget = InventoryBudget::new(1, 8).expect("a valid one-endpoint budget");
    let mut book = CaptureBook::new_scoped(budget, 1, HeldCaptureScope::System, monotonic_ns());
    book.observe_lifecycle(&CaptureHealth::from_parts(
        health,
        malformed_discovery,
        pin_check_failures,
    ));
    book.lifecycle_loss().map(|loss| loss.reason)
}

impl CaptureBook {
    #[cfg(test)]
    fn new(
        budget: InventoryBudget,
        pair_limit: usize,
        scope: Option<ScopeIncarnation>,
        now_ns: u64,
    ) -> Self {
        Self::new_scoped(
            budget,
            pair_limit,
            scope.map_or(HeldCaptureScope::System, HeldCaptureScope::Pid),
            now_ns,
        )
    }

    #[cfg(test)]
    fn new_scoped(
        budget: InventoryBudget,
        pair_limit: usize,
        scope: HeldCaptureScope,
        now_ns: u64,
    ) -> Self {
        // Unit harnesses admit info returns without forking the
        // self-probe; twins that script a refusal install their own
        // gate through `set_info_return_gate`.
        let mut book =
            Self::new_scoped_with_domain(NativeDomainId::mint(), budget, pair_limit, scope, now_ns);
        book.info_return_gate =
            Box::new(|_, _| Ok(crate::uretprobe_hazard::ReturnProbeAdmission::for_test()));
        book
    }

    fn new_scoped_with_domain(
        domain: NativeDomainId,
        budget: InventoryBudget,
        pair_limit: usize,
        scope: HeldCaptureScope,
        now_ns: u64,
    ) -> Self {
        Self {
            promotion_baseline_generation: 0,
            domain,
            budget,
            backend: AttachBackend::Singles,
            groups: Vec::new(),
            link_ns_per_site: BTreeMap::new(),
            pair_limit,
            scope,
            published: BTreeMap::new(),
            attached: BTreeSet::new(),
            failed: BTreeMap::new(),
            info_return_pending: VecDeque::new(),
            info_accounting: InfoRingAccounting::default(),
            info_consumed: 0,
            malformed_info: 0,
            last_info_evidence: [0; 4],
            pending_info_revoke: VecDeque::new(),
            pending_info_revoke_step: BTreeMap::new(),
            info_revoked: BTreeSet::new(),
            info_revoked_epoch: 0,
            custody_lost: None,
            original_exit: None,
            unproven: None,
            lifecycle_lost: None,
            held_ns: now_ns,
            health_ns: now_ns,
            // No producer exists yet; an unstamped creation (clock failure)
            // proves no drain at all, so it floors at 0 (fail safe).
            drained_ns: drain_stamp(now_ns).unwrap_or(0),
            undatable_floor_ns: drain_stamp(now_ns).unwrap_or(0),
            ring_loss: 0,
            malformed: 0,
            cursor: CallerUseCursor::new(pair_limit),
            integrity_total: 0,
            // Preparation proved every counter fresh (zero).
            baseline: Some(WatchCounters::default()),
            changed_objects: BTreeSet::new(),
            recheck_after: None,
            stopping: false,
            return_probe_admission: None,
            info_return_refused: false,
            info_return_gate: Box::new(crate::uretprobe_hazard::admit),
        }
    }

    fn with_backend(mut self, backend: AttachBackend) -> Self {
        self.backend = backend;
        self
    }

    /// Tests script one hazard verdict source: twins inject
    /// affected, unknown or clean verdicts without a kernel. The
    /// production gate stays `uretprobe_hazard::admit`.
    #[cfg(test)]
    fn set_info_return_gate(&mut self, gate: Box<InfoReturnGate>) {
        self.info_return_gate = gate;
    }

    /// Keymeta Task 7 (spec §17.4): whether this capture may attach
    /// info returns — the uretprobe-vs-seccomp admission every other
    /// return-probe path takes, once per capture through the
    /// retained approval. Any refusal (hazard, unknown kernel,
    /// missing privilege or stale object) sticks for the capture:
    /// info endpoints attach usage-only with the named counted gap,
    /// never a return link or an `INFO_KIND` publish. The target is
    /// always `None`, like every Detailed call site: on a PID scope
    /// the trampoline still runs in a sibling that may confine
    /// itself after attach, so no pid narrows the verdict.
    #[allow(dead_code)] // The enforcement commit consults this.
    fn info_returns_admitted(&mut self) -> bool {
        if self.info_return_refused {
            return false;
        }
        let gate = &self.info_return_gate;
        let verdict = crate::uretprobe_hazard::ensure_admission_assessed(
            &mut self.return_probe_admission,
            |overridden| gate(None, overridden),
        );
        match verdict {
            Ok(()) => true,
            Err(_) => {
                self.info_return_refused = true;
                false
            }
        }
    }

    fn scope_pid(&self) -> Option<u32> {
        self.incarnation().map(|scope| scope.pid)
    }

    fn incarnation(&self) -> Option<ScopeIncarnation> {
        match &self.scope {
            HeldCaptureScope::Pid(scope) => Some(*scope),
            HeldCaptureScope::System | HeldCaptureScope::Cgroup { .. } => None,
        }
    }

    fn scope_coverage(&self) -> CaptureScopeCoverage {
        match &self.scope {
            HeldCaptureScope::System => CaptureScopeCoverage::System,
            HeldCaptureScope::Pid(scope) => CaptureScopeCoverage::Pid(*scope),
            HeldCaptureScope::Cgroup { .. } => CaptureScopeCoverage::Cgroup,
        }
    }

    /// Attached or failed: nothing more to do for this ID.
    fn knows(&self, id: u32) -> bool {
        self.attached.contains(&id) || self.failed.contains_key(&id)
    }

    fn custody(&self) -> ScopeCustody {
        match &self.scope {
            HeldCaptureScope::System => return ScopeCustody::System,
            HeldCaptureScope::Cgroup { .. } => return ScopeCustody::CgroupHeld,
            HeldCaptureScope::Pid(_) => {}
        }
        if let Some((lost_ns, lost)) = &self.custody_lost {
            if self.unproven.is_none()
                && self.lifecycle_lost.is_none()
                && self.changed_objects.is_empty()
                && let Some(proof) = self.original_exit
            {
                return ScopeCustody::PidExited {
                    at_ns: *lost_ns,
                    proof,
                };
            }
            // Lost custody never hides an earlier-dated unproven one: the
            // earliest instant coverage stopped being proven stands.
            return match &self.unproven {
                Some((at_ns, reason)) if at_ns < lost_ns => ScopeCustody::PidLost {
                    at_ns: *at_ns,
                    reason: format!("{lost}; unproven since {at_ns}: {reason}"),
                },
                _ => ScopeCustody::PidLost {
                    at_ns: *lost_ns,
                    reason: lost.clone(),
                },
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

    /// PID scope only; the earliest instant (and its reason) stands, so a
    /// later-found loss dated earlier is never masked (C5.2 closure I-1b).
    fn mark_unproven(&mut self, at_ns: u64, reason: String) {
        self.original_exit = None;
        if self.incarnation().is_some() {
            keep_earliest(&mut self.unproven, at_ns, reason);
        }
    }

    /// Lifecycle evidence was lost: PID scope's custody is unproven from
    /// `at_ns`; the machine records the earliest loss for every batch.
    fn mark_lifecycle_loss(&mut self, at_ns: u64, reason: String) {
        if self.incarnation().is_some() {
            self.mark_unproven(at_ns, reason);
        } else {
            keep_earliest(&mut self.lifecycle_lost, at_ns, reason);
        }
    }

    fn lifecycle_loss(&self) -> Option<LifecycleLoss> {
        self.lifecycle_lost
            .as_ref()
            .map(|(at_ns, reason)| LifecycleLoss {
                at_ns: *at_ns,
                reason: reason.clone(),
            })
    }

    fn mark_lost(&mut self, reason: String) {
        self.original_exit = None;
        if self.incarnation().is_some() && self.custody_lost.is_none() {
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
            CustodyPoll::Exited => self.mark_lost("PID custody lost: the PID target exited".into()),
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

    /// Lifecycle loss: under PID scope an exec record may be among what
    /// was lost, so custody since the last clean health read is unproven;
    /// under system scope the loss may hide any caller's exec or exit.
    fn observe_lifecycle(&mut self, health: &CaptureHealth) {
        let hidden = if self.incarnation().is_some() {
            "an exec of the PID target"
        } else {
            "an exec or exit of a watched caller"
        };
        if let Some((ring_loss, reason)) =
            ring_loss_demotion(self.ring_loss, health.discovery_counters, hidden)
        {
            self.mark_lifecycle_loss(self.health_ns, reason);
            self.ring_loss = ring_loss;
        }
        if health.malformed_discovery > self.malformed {
            let reason = format!(
                "{} malformed lifecycle record(s): {hidden} may be among them",
                health.malformed_discovery - self.malformed
            );
            self.mark_lifecycle_loss(self.undatable_floor_ns, reason);
            self.malformed = health.malformed_discovery;
        }
        // Any malformed record counted after this observation was dequeued
        // after it, so after every drain proven so far.
        self.undatable_floor_ns = self.drained_ns;
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

    /// Keymeta Task 7 (spec §17.4): close one INFO quantum — count
    /// the consumed records and malformed frames, note the
    /// produced-vs-consumed cross-check, difference the evidence
    /// cells, and assemble the batch. A missing produced reading
    /// (P0) or a failed one retains the prior triple instead of
    /// regressing it; the failure rides the batch so the terminal
    /// cut never publishes a stale difference as loss. A missing
    /// evidence reading (P0) reports zero deltas; a failed one
    /// reports the cause and keeps the last cells, so a later
    /// success reports the full delta. The batch leaves as
    /// non-terminal and unretired; the session's terminal drain
    /// marks its own batch, whichever capture state serves it.
    fn finish_info_quantum(
        &mut self,
        records: Vec<[u8; 176]>,
        malformed: u64,
        failure: Option<String>,
        complete: bool,
        produced: Option<Result<u64, String>>,
        evidence: Option<Result<[u64; 4], String>>,
    ) -> InfoBatch {
        self.info_consumed = self.info_consumed.saturating_add(records.len() as u64);
        self.malformed_info = self.malformed_info.saturating_add(malformed);
        let (produced_fresh, produced_error) = match produced {
            Some(Ok(now)) => {
                self.info_accounting
                    .note_info_quantum(now, self.info_consumed);
                (true, None)
            }
            Some(Err(error)) => (false, Some(error)),
            None => (false, None),
        };
        let (evidence_delta, evidence_error) = match evidence {
            None => ([0; 4], None),
            Some(Ok(cells)) => {
                let mut delta = [0u64; 4];
                for (slot, (now, was)) in delta
                    .iter_mut()
                    .zip(cells.iter().zip(self.last_info_evidence.iter()))
                {
                    *slot = now.saturating_sub(*was);
                }
                self.last_info_evidence = cells;
                (delta, None)
            }
            Some(Err(error)) => ([0; 4], Some(error)),
        };
        InfoBatch {
            domain: self.domain,
            records,
            malformed,
            produced: self.info_accounting.produced,
            consumed: self.info_consumed,
            loss: self.info_accounting.loss,
            terminal: false,
            failure,
            evidence_delta,
            evidence_error,
            complete,
            produced_fresh,
            produced_error,
            retired: false,
        }
    }
}

/// A clock reading usable as a drain floor: `u64::MAX` marks a failed
/// CLOCK_MONOTONIC read (`monotonic_ns`).
fn drain_stamp(ns: u64) -> Option<u64> {
    (ns != u64::MAX).then_some(ns)
}

/// A sticky loss record: the earliest instant (and its reason) stands.
fn keep_earliest(slot: &mut Option<(u64, String)>, at_ns: u64, reason: String) {
    if slot.as_ref().is_none_or(|(was, _)| at_ns < *was) {
        *slot = Some((at_ns, reason));
    }
}

/// One custody poll's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CustodyPoll {
    Held,
    Exited,
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
        Ok(true) => return CustodyPoll::Exited,
        Err(error) => return CustodyPoll::Lost(error),
    }
    let leader = leader();
    match exited() {
        Ok(false) => {}
        Ok(true) => return CustodyPoll::Exited,
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
#[cfg(test)]
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
/// unit tests), under the book's backend. `custody` is the PID-scope
/// check; `now` stamps attaches.
/// Keymeta Task 7 (spec §17.4, INV-2): pending-return visits per
/// extend for the INFO revocation filter. Each visited Single and
/// each visited Multi site spends one credit; the unvisited suffix
/// requeues for later extends instead of consuming the whole
/// service window ahead of every attach.
const INFO_RETURN_RETRY_PER_EXTEND: usize = 64;

#[allow(clippy::too_many_arguments)]
/// Keymeta Task 7 (spec §17.4, N4): retry the private info-return
/// pending list first on every extend, within the same window and
/// visit allowance. An attached endpoint stays `known`; the retry
/// links its return and publishes `INFO_KIND` once. EMFILE re-parks
/// the rest with the named counted gap and stops (descriptors are
/// still exhausted); deterministic refusals fail disclosed with
/// links retained.
fn retry_info_returns<I: InventoryLinkIo>(
    io: &mut I,
    targets: &InventoryTargets,
    links: &mut Vec<InventoryLinked<I::Link>>,
    book: &mut CaptureBook,
    receipt: &mut ExtendReceipt,
    deadline: Instant,
    now: &mut dyn FnMut() -> Instant,
) {
    // In-place queue: the deque moves out once and moves back once,
    // and every yield pushes the front item back into the SAME deque
    // before moving it back — never `append` across deques, which
    // copies both backing slices scaled to the whole queue. An
    // expired call before any work touches nothing at all.
    if book.info_return_pending.is_empty() {
        return;
    }
    if now() >= deadline {
        return;
    }
    let mut queue: VecDeque<InfoReturnPending> = std::mem::take(&mut book.info_return_pending);
    let mut remaining = INFO_RETURN_RETRY_PER_EXTEND;
    while !queue.is_empty() {
        // The window and allowance gate every visit before popping:
        // nothing — not even a revoked Single's drop — is visited
        // at or past the deadline or past the visit allowance, and
        // an expired or spent extend moves no queue storage.
        if now() >= deadline || remaining == 0 {
            book.info_return_pending = queue;
            return;
        }
        let Some(next) = queue.pop_front() else {
            break;
        };
        match next {
            InfoReturnPending::Singles(endpoint) => {
                remaining -= 1;
                // Revoked endpoints (spec §17.4) drop here, at
                // their retry: the staging extend already recorded
                // the revocation, so no return link is ever
                // attempted for them again.
                if book.info_revoked.contains(&endpoint.id.0) {
                    continue;
                }
                let Some(kind) = endpoint.info_kind else {
                    continue;
                };
                let entry = InventoryEndpoint {
                    id: endpoint.id.0,
                    object: PinnedObjectId(endpoint.object.index()),
                    file_offset: endpoint.file_offset,
                    abi: endpoint.abi,
                    info_kind: Some(kind),
                };
                let before = links.len();
                let attached = attach_published_return_with(io, targets, &entry, links);
                let retained = links.len() > before;
                match attached {
                    Err(error) if !retained && crate::attach::is_fd_exhaustion(&error) => {
                        receipt.info_return_deferred += 1;
                        queue.push_front(InfoReturnPending::Singles(endpoint));
                        book.info_return_pending = queue;
                        return;
                    }
                    Err(error) => {
                        book.fail(receipt, &endpoint, format!("{error:#}"), retained);
                    }
                    Ok(()) => {
                        if let Err(error) =
                            io.publish_info_kind(entry.id, kind).with_context(|| {
                                format!("publishing info kind for endpoint {}", entry.id)
                            })
                        {
                            book.fail(receipt, &endpoint, format!("{error:#}"), true);
                        }
                    }
                }
            }
            InfoReturnPending::Multi {
                object,
                sites,
                entry_serial,
                mut validated,
                mut validated_epoch,
                mut excluded,
                mut staged,
                mut staged_points,
            } => {
                let epoch = book.info_revoked_epoch;
                validated = validated.min(sites.len());
                // A newer revocation epoch revalidates from the first
                // site under the same visit allowance: survivors the
                // filter kept under an older set drop here when the
                // set has since revoked them, before any publication.
                // Excluded bits stay (revocation is irreversible), so
                // a resumed filter never rechecks them; the staged
                // survivors clear and rebuild under the allowance.
                if validated_epoch != epoch {
                    validated = 0;
                    validated_epoch = epoch;
                    staged.clear();
                    staged_points.clear();
                }
                // In-place cursor: the storage stays across yields and
                // only the cursor, the exclusion mask and the staged
                // survivors advance — no `to_vec` of the visited
                // prefix and no `extend_from_slice` of the unvisited
                // suffix. Each visited site spends one visit credit,
                // excluded indexes included (site-index work under
                // INV-2); each surviving visit pushes its site and
                // its attach point, already charged, so completion
                // needs no post-filter scan or copy.
                let mut yielded = false;
                while validated < sites.len() {
                    if multi_site_excluded(&excluded, validated) {
                        if remaining == 0 || now() >= deadline {
                            yielded = true;
                            break;
                        }
                        remaining -= 1;
                        validated += 1;
                        continue;
                    }
                    if remaining == 0 || now() >= deadline {
                        yielded = true;
                        break;
                    }
                    remaining -= 1;
                    let site = sites[validated];
                    if book.info_revoked.contains(&site.endpoint) {
                        multi_site_exclude(&mut excluded, validated);
                    } else {
                        staged.push(site);
                        staged_points.push((site.file_offset, site.cookie));
                    }
                    validated += 1;
                }
                if yielded {
                    queue.push_front(InfoReturnPending::Multi {
                        object,
                        sites,
                        entry_serial,
                        validated,
                        validated_epoch,
                        excluded,
                        staged,
                        staged_points,
                    });
                    book.info_return_pending = queue;
                    return;
                }
                // Filter complete: the staged survivors were built
                // during credited visits, so no scan or copy runs
                // here. An empty stage drops the fully revoked group.
                if staged.is_empty() {
                    continue;
                }
                // The filter spent time: recheck the window before
                // native work. The original vector, cursor, mask and
                // staged survivors requeue unchanged — never a
                // rebuilt survivors-only copy.
                if now() >= deadline {
                    queue.push_front(InfoReturnPending::Multi {
                        object,
                        sites,
                        entry_serial,
                        validated,
                        validated_epoch,
                        excluded,
                        staged,
                        staged_points,
                    });
                    book.info_return_pending = queue;
                    return;
                }
                let local = PinnedObjectId(object.index());
                let retry = |book: &mut CaptureBook,
                             receipt: &mut ExtendReceipt,
                             sites: &[PendingReturnSite],
                             reason: String| {
                    for site in sites {
                        book.failed.insert(site.endpoint, reason.clone());
                        receipt.failed.push(EndpointFailure {
                            id: EndpointId(site.endpoint),
                            object,
                            reason: reason.clone(),
                            link_retained: true,
                        });
                    }
                };
                if let Err(error) = targets.check_object(local) {
                    retry(book, receipt, &staged, format!("{error:#}"));
                    continue;
                }
                let Some(path) = targets.attach_path(local) else {
                    retry(
                        book,
                        receipt,
                        &staged,
                        "missing Inventory target pin".into(),
                    );
                    continue;
                };
                let attached = io.attach_return_group(InventoryGroupRequest {
                    program: "p11_info_return",
                    path: &path,
                    sites: &staged_points,
                });
                match attached {
                    Err(p11scope_bpf_multi::BisectHalt {
                        halt: p11scope_bpf_multi::GroupHalt::Exhausted(_),
                        closed_leaves,
                    }) => {
                        receipt.halt_closed_links += closed_leaves;
                        receipt.info_return_deferred += 1;
                        queue.push_front(InfoReturnPending::Multi {
                            object,
                            sites,
                            entry_serial,
                            validated,
                            validated_epoch,
                            excluded,
                            staged,
                            staged_points,
                        });
                        book.info_return_pending = queue;
                        return;
                    }
                    Err(p11scope_bpf_multi::BisectHalt {
                        halt: p11scope_bpf_multi::GroupHalt::Unsupported(error),
                        closed_leaves,
                    }) => {
                        receipt.halt_closed_links += closed_leaves;
                        retry(
                            book,
                            receipt,
                            &staged,
                            format!("uretprobe-multi refused by the running kernel: {error}"),
                        );
                        continue;
                    }
                    Ok(attach) => {
                        // The return group carries its entry group's
                        // serial (the `ReturnGroup` variant
                        // distinguishes custody): entry serials are
                        // unique, so retried groups never share one.
                        let serial = entry_serial;
                        for handle in attach.links {
                            links.push(InventoryLinked {
                                target: InventoryLinkIdentity::ReturnGroup(serial),
                                handle,
                            });
                        }
                        let refused: BTreeMap<usize, std::io::Error> =
                            attach.refused.into_iter().collect();
                        let mut survivors = Vec::with_capacity(staged.len());
                        for (index, site) in staged.iter().enumerate() {
                            if let Some(error) = refused.get(&index) {
                                book.failed.insert(site.endpoint, format!("{error}"));
                                receipt.failed.push(EndpointFailure {
                                    id: EndpointId(site.endpoint),
                                    object,
                                    reason: format!(
                                        "attaching Inventory return {} in group {serial}: {error}",
                                        site.endpoint
                                    ),
                                    link_retained: true,
                                });
                                continue;
                            }
                            if let Err(error) = io
                                .publish_info_kind(site.endpoint, site.kind)
                                .with_context(|| {
                                    format!("publishing info kind for endpoint {}", site.endpoint)
                                })
                            {
                                book.failed.insert(site.endpoint, format!("{error:#}"));
                                receipt.failed.push(EndpointFailure {
                                    id: EndpointId(site.endpoint),
                                    object,
                                    reason: format!("{error:#}"),
                                    link_retained: true,
                                });
                                continue;
                            }
                            survivors.push(site.endpoint);
                        }
                        if return_group_links(links, serial) > 0 {
                            receipt.groups.push(AttachGroup {
                                serial,
                                object,
                                program: "p11_info_return",
                                members: survivors
                                    .iter()
                                    .map(|endpoint| EndpointId(*endpoint))
                                    .collect(),
                                links: return_group_links(links, serial),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Keymeta Task 7 (spec §17.4, INV-2): cell writes per extend for
/// INFO revocations. Revocation authority (fresh downgrade, pending
/// purge, row rejection) applies to every staged endpoint at once;
/// only the map writes pace out — at most this many per extend and
/// none at or past the extend deadline, the rest requeuing.
const INFO_REVOKE_PER_EXTEND: usize = 64;

/// Keymeta Task 7 (spec §17.4): apply this extend's INFO
/// revocations before any attach or pending retry. Fresh endpoints
/// whose ids revoked downgrade to usage-only (never publish new
/// info state for them); pending info returns for revoked ids are
/// purged; each revoked INFO_KIND cell writes back to zero (FULL
/// only — P0 carries no map). Failed writes requeue for the next
/// extend and count; successes count. Usage attaches proceed
/// regardless.
fn revoke_info_kinds<I: InventoryLinkIo>(
    io: &mut I,
    book: &mut CaptureBook,
    delta: &mut TargetDelta,
    receipt: &mut ExtendReceipt,
    deadline: Instant,
) {
    let fresh = std::mem::take(&mut delta.info_revoked);
    if fresh.is_empty() && book.pending_info_revoke.is_empty() {
        return;
    }
    // P0 counts staged revocations without attempting any write, so
    // it keeps the carried-plus-fresh total even for duplicates.
    let carried = book.pending_info_revoke.len();
    // Revocation authority applies to every staged endpoint at once
    // (spec §17.4): fresh copies downgrade, pending info returns
    // drop at their retry, and the coordinator already rejects their
    // rows — before any map write, paced or not. Staging touches
    // only the fresh delta plus indexed queue membership, never a
    // scan over the whole write backlog.
    let mut revoked_grew = false;
    for id in &fresh {
        revoked_grew |= book.info_revoked.insert(id.0);
        if !book.pending_info_revoke_step.contains_key(id) {
            book.pending_info_revoke.push_back(*id);
            book.pending_info_revoke_step
                .insert(*id, super::RevokeSubstep::ReadInitial);
        }
    }
    if revoked_grew {
        book.info_revoked_epoch = book.info_revoked_epoch.saturating_add(1);
    }
    for endpoint in &mut delta.endpoints {
        if book.info_revoked.contains(&endpoint.id.0) {
            endpoint.info_kind = None;
        }
    }
    // Only the cell writes pace out: at most one extend's allowance,
    // oldest cells first, and none at or past the extend deadline.
    // Paced-out endpoints keep their queue place silently (pacing is
    // not failure); failed writes cycle to the back counted, so
    // unattempted cells always get a turn. Each queued cell attempts
    // at most once per extend, and each attempt spends one credit of
    // the extend's allowance. P0 carries no map, so its revokes cost
    // no native work and pace nothing.
    if cfg!(feature = "stub-object-attributes") {
        let staged = carried.saturating_add(fresh.len()) as u64;
        receipt.info_revoked = receipt.info_revoked.saturating_add(staged);
        book.pending_info_revoke.clear();
        book.pending_info_revoke_step.clear();
        return;
    }
    let mut remaining = book.pending_info_revoke.len().min(INFO_REVOKE_PER_EXTEND);
    while remaining > 0 {
        if Instant::now() >= deadline {
            break;
        }
        let Some(id) = book.pending_info_revoke.pop_front() else {
            break;
        };
        let resume = book
            .pending_info_revoke_step
            .get(&id)
            .copied()
            .unwrap_or(super::RevokeSubstep::ReadInitial);
        remaining -= 1;
        match io.revoke_info_kind(id.0, resume, deadline, &mut Instant::now) {
            Ok(super::RevokeStepOutcome::Done) => {
                book.pending_info_revoke_step.remove(&id);
                receipt.info_revoked = receipt.info_revoked.saturating_add(1);
            }
            Ok(super::RevokeStepOutcome::Yielded { next }) => {
                book.pending_info_revoke_step.insert(id, next);
                book.pending_info_revoke.push_back(id);
            }
            Err(_) => {
                receipt.info_revoke_failed = receipt.info_revoke_failed.saturating_add(1);
                book.pending_info_revoke_step
                    .insert(id, super::RevokeSubstep::ReadInitial);
                book.pending_info_revoke.push_back(id);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn extend_entries_with<I: InventoryLinkIo>(
    io: &mut I,
    targets: &mut InventoryTargets,
    links: &mut Vec<InventoryLinked<I::Link>>,
    book: &mut CaptureBook,
    mut delta: TargetDelta,
    source: &dyn CaptureTargets,
    window: ExtendWindow,
    custody: &mut dyn FnMut() -> std::result::Result<(), String>,
    now: &mut dyn FnMut() -> u64,
    receipt: &mut ExtendReceipt,
) {
    // Keymeta Task 7 (spec §17.4): revocations first — a revoked
    // endpoint must not attach info state or retry a pending info
    // return in this same extend.
    revoke_info_kinds(io, book, &mut delta, receipt, window.deadline);
    // Keymeta Task 7 (spec §17.4, N4): every extend retries the
    // private info-return pending list first, within the same
    // window; the endpoints stay `known`.
    retry_info_returns(
        io,
        targets,
        links,
        book,
        receipt,
        window.deadline,
        &mut Instant::now,
    );
    match book.backend {
        AttachBackend::Singles => extend_singles_with(
            io, targets, links, book, delta, source, window, custody, now, receipt,
        ),
        AttachBackend::Multi => extend_groups_with(
            io, targets, links, book, delta, source, window, custody, now, receipt,
        ),
    }
}

/// The endpoints of `delta[from..]` this capture has not handled, deferred.
fn defer_unknown(book: &CaptureBook, receipt: &mut ExtendReceipt, rest: &[AttachEndpoint]) {
    let rest: Vec<AttachEndpoint> = rest
        .iter()
        .filter(|endpoint| !book.knows(endpoint.id.0))
        .copied()
        .collect();
    defer(receipt, &rest);
}

/// One endpoint's pre-attach transaction, shared by both backends: the
/// object's retained pin (a shared clone of the attach set's), the entry
/// record and its validation, and the ENDPOINT_OBJECT binding published
/// (or, for a published-but-unattached entry, the standing binding
/// checked). `None`: the endpoint failed and is recorded as failed.
fn admit_entry<I: InventoryLinkIo>(
    io: &mut I,
    targets: &mut InventoryTargets,
    book: &mut CaptureBook,
    endpoint: &AttachEndpoint,
    source: &dyn CaptureTargets,
    receipt: &mut ExtendReceipt,
) -> Option<InventoryEndpoint> {
    let local = PinnedObjectId(endpoint.object.index());
    let entry = InventoryEndpoint {
        id: endpoint.id.0,
        object: local,
        file_offset: endpoint.file_offset,
        abi: endpoint.abi,
        // Keymeta Task 7 (spec §17.4): the attach set's kind rides
        // into the entry; P0 forces usage-only (the P0 object
        // carries no info programs).
        info_kind: if cfg!(feature = "stub-object-attributes") {
            None
        } else {
            endpoint.info_kind
        },
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
                return None;
            }
        }
    }
    if republish {
        let checked = targets
            .record_entry(entry)
            .and_then(|()| validate_entry(targets, &entry))
            .and_then(|()| {
                targets
                    .check_object(local)
                    .with_context(|| format!("before publishing Inventory endpoint {}", entry.id))
            });
        if let Err(error) = checked {
            book.fail(receipt, endpoint, format!("{error:#}"), false);
            return None;
        }
        if let Err(error) = io
            .publish_endpoint(entry.id, entry.object)
            .with_context(|| format!("publishing Inventory endpoint {}", entry.id))
        {
            // The cell's content is unknown: no binding is recorded, so
            // a row naming this endpoint is integrity evidence.
            book.fail(receipt, endpoint, format!("{error:#}"), false);
            return None;
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
        return None;
    }
    Some(entry)
}

/// Keymeta Task 7 Singles info return (spec §17.4, N4): attach the
/// return after its entry linked, then publish `INFO_KIND` once.
/// EMFILE (or an expired window) parks the endpoint on the private
/// pending list — counted only on EMFILE — and reports
/// attached-anyway (`None`); a deterministic refusal or a
/// publication failure reports its reason for a disclosed fail with
/// links retained.
#[allow(clippy::too_many_arguments)]
fn attempt_info_return_singles<I: InventoryLinkIo>(
    io: &mut I,
    targets: &InventoryTargets,
    links: &mut Vec<InventoryLinked<I::Link>>,
    book: &mut CaptureBook,
    endpoint: &AttachEndpoint,
    entry: &InventoryEndpoint,
    kind: u8,
    receipt: &mut ExtendReceipt,
    deadline: Instant,
) -> Option<String> {
    if Instant::now() >= deadline {
        book.info_return_pending
            .push_back(InfoReturnPending::Singles(*endpoint));
        return None;
    }
    let before = links.len();
    let attached = attach_published_return_with(io, targets, entry, links);
    let retained = links.len() > before;
    match attached {
        Err(error) if !retained && crate::attach::is_fd_exhaustion(&error) => {
            // Descriptors ran out: nothing about this endpoint is
            // wrong. It stays attached (its usage entry still
            // records); the return retries from the pending list.
            receipt.info_return_deferred += 1;
            book.info_return_pending
                .push_back(InfoReturnPending::Singles(*endpoint));
            None
        }
        Err(error) => Some(format!("{error:#}")),
        Ok(()) => {
            if let Err(error) = io
                .publish_info_kind(entry.id, kind)
                .with_context(|| format!("publishing info kind for endpoint {}", entry.id))
            {
                return Some(format!("{error:#}"));
            }
            None
        }
    }
}

/// Singles: one perf link per entry, each published, attached and checked
/// before the next.
#[allow(clippy::too_many_arguments)]
fn extend_singles_with<I: InventoryLinkIo>(
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
            defer_unknown(book, receipt, &delta.endpoints[index..]);
            receipt.known.extend(
                delta.endpoints[index..]
                    .iter()
                    .filter(|endpoint| book.knows(endpoint.id.0))
                    .map(|endpoint| endpoint.id),
            );
            return;
        }
        attempted += 1;
        let Some(entry) = admit_entry(io, targets, book, endpoint, source, receipt) else {
            continue;
        };
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
                defer_unknown(book, receipt, &delta.endpoints[index..]);
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
            defer_unknown(book, receipt, &delta.endpoints[index + 1..]);
            return;
        }
        // Keymeta Task 7 (spec §17.4): info endpoints attempt one
        // return link after their entry linked.
        if let Some(kind) = entry.info_kind
            && let Some(reason) = attempt_info_return_singles(
                io,
                targets,
                links,
                book,
                endpoint,
                &entry,
                kind,
                receipt,
                window.deadline,
            )
        {
            book.fail(receipt, endpoint, reason, true);
            continue;
        }
        book.attached.insert(entry.id);
        receipt.attached.push(AttachedEndpoint {
            id: endpoint.id,
            object: endpoint.object,
            at_ns: now(),
        });
    }
}

/// The entry program of `abi`, the same choice for both backends.
fn entry_program(abi: p11scope_manifest::elf::ElfAbi) -> &'static str {
    match abi {
        p11scope_manifest::elf::ElfAbi::Lp64 => "p11_usage_entry_lp64",
        p11scope_manifest::elf::ElfAbi::Ilp32 => "p11_usage_entry_ia32",
    }
}

/// Keymeta Task 7 (spec §17.4): the info entry program of `abi`.
fn info_entry_program(abi: p11scope_manifest::elf::ElfAbi) -> &'static str {
    match abi {
        p11scope_manifest::elf::ElfAbi::Lp64 => "p11_info_entry_lp64",
        p11scope_manifest::elf::ElfAbi::Ilp32 => "p11_info_entry_ia32",
    }
}

/// Keymeta Task 7 (spec §17.4): info endpoints link the inventory
/// info entry pair (per ABI); every other endpoint keeps its usage
/// entry. Cold-only proof at selection time: no journal program
/// links at an info endpoint in any mode.
fn entry_program_for(abi: p11scope_manifest::elf::ElfAbi, info_kind: Option<u8>) -> &'static str {
    if info_kind.is_some() {
        info_entry_program(abi)
    } else {
        entry_program(abi)
    }
}

/// A group's key: the local object id and the entry program.
type GroupKey = (u32, &'static str);
/// One admitted group member: its endpoint and published entry.
type GroupMember = (AttachEndpoint, InventoryEndpoint);

/// Keymeta Task 7 Multi info returns (spec §17.4, fix8 I1, N4): an
/// info entry group attempts its return group (+G return-group
/// links) inline, before its members mark attached, so every member
/// still lands in exactly one receipt bucket. The return group
/// carries its entry group's serial (the `ReturnGroup` variant
/// distinguishes custody). EMFILE defers the group to the private
/// pending list with the named counted gap (per group) while the
/// members attach; deterministic refusals and publication failures
/// fail disclosed with links retained. Usage groups pass through
/// untouched. Returns the members to mark attached.
#[allow(clippy::too_many_arguments)]
fn attach_info_return_group<I: InventoryLinkIo>(
    io: &mut I,
    targets: &InventoryTargets,
    links: &mut Vec<InventoryLinked<I::Link>>,
    book: &mut CaptureBook,
    receipt: &mut ExtendReceipt,
    object: u32,
    members: Vec<(AttachEndpoint, InventoryEndpoint)>,
    entry_serial: u32,
    deadline: Instant,
) -> Vec<(AttachEndpoint, InventoryEndpoint)> {
    let info: Vec<(AttachEndpoint, InventoryEndpoint)> = members
        .iter()
        .filter(|(_, entry)| entry.info_kind.is_some())
        .copied()
        .collect();
    if info.is_empty() {
        return members;
    }
    let fail_all = |book: &mut CaptureBook,
                    receipt: &mut ExtendReceipt,
                    members: &[(AttachEndpoint, InventoryEndpoint)],
                    reason: &str| {
        for (endpoint, _) in members {
            book.fail(receipt, endpoint, reason.to_string(), true);
        }
    };
    let pending_sites: Vec<PendingReturnSite> = info
        .iter()
        .map(|(endpoint, entry)| PendingReturnSite {
            endpoint: endpoint.id.0,
            file_offset: entry.file_offset,
            cookie: (u64::from(p11scope_ebpf_common::INVENTORY_COOKIE_TAG) << 32)
                | u64::from(entry.id),
            kind: entry.info_kind.unwrap_or(0),
        })
        .collect();
    if Instant::now() >= deadline {
        let epoch = book.info_revoked_epoch;
        book.info_return_pending
            .push_back(InfoReturnPending::Multi {
                object: info[0].0.object,
                sites: pending_sites,
                entry_serial,
                validated: 0,
                validated_epoch: epoch,
                excluded: [0; 2],
                staged: Vec::new(),
                staged_points: Vec::new(),
            });
        return members;
    }
    // Every failure path below fails the info members and returns
    // the rest (groups are homogeneous, so that is empty today):
    // one convention, so no member lands in no receipt bucket.
    let failures_out = |members: Vec<(AttachEndpoint, InventoryEndpoint)>| {
        members
            .into_iter()
            .filter(|(endpoint, _)| !info.iter().any(|(failed, _)| failed.id == endpoint.id))
            .collect()
    };
    let local = PinnedObjectId(object);
    if let Err(error) = targets.check_object(local) {
        fail_all(book, receipt, &info, &format!("{error:#}"));
        return failures_out(members);
    }
    let Some(path) = targets.attach_path(local) else {
        fail_all(book, receipt, &info, "missing Inventory target pin");
        return failures_out(members);
    };
    let sites: Vec<(u64, u64)> = pending_sites
        .iter()
        .map(|site| (site.file_offset, site.cookie))
        .collect();
    let started = Instant::now();
    let attached = io.attach_return_group(InventoryGroupRequest {
        program: "p11_info_return",
        path: &path,
        sites: &sites,
    });
    let spent = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    receipt.attach_ns_total = receipt.attach_ns_total.saturating_add(spent);
    receipt.attach_ns_max = receipt.attach_ns_max.max(spent);
    let attach = match attached {
        Ok(attach) => attach,
        Err(p11scope_bpf_multi::BisectHalt {
            halt: p11scope_bpf_multi::GroupHalt::Exhausted(_),
            closed_leaves,
        }) => {
            // No return link reached custody; the members stay
            // attached (their usage entries still record) and the
            // group retries from the pending list. The capture never
            // stops: entry groups continue after this one.
            receipt.halt_closed_links += closed_leaves;
            receipt.info_return_deferred += 1;
            let epoch = book.info_revoked_epoch;
            book.info_return_pending
                .push_back(InfoReturnPending::Multi {
                    object: info[0].0.object,
                    sites: pending_sites,
                    entry_serial,
                    validated: 0,
                    validated_epoch: epoch,
                    excluded: [0; 2],
                    staged: Vec::new(),
                    staged_points: Vec::new(),
                });
            return members;
        }
        Err(p11scope_bpf_multi::BisectHalt {
            halt: p11scope_bpf_multi::GroupHalt::Unsupported(error),
            closed_leaves,
        }) => {
            receipt.halt_closed_links += closed_leaves;
            fail_all(
                book,
                receipt,
                &info,
                &format!("uretprobe-multi refused by the running kernel: {error}"),
            );
            return failures_out(members);
        }
    };
    // The return group carries its entry group's serial (the
    // `ReturnGroup` variant distinguishes custody): entry serials
    // are unique, so return groups never share one.
    let serial = entry_serial;
    for handle in attach.links {
        links.push(InventoryLinked {
            target: InventoryLinkIdentity::ReturnGroup(serial),
            handle,
        });
    }
    let refused: BTreeMap<usize, std::io::Error> = attach.refused.into_iter().collect();
    let mut survivors = Vec::with_capacity(info.len());
    for (index, (endpoint, entry)) in info.iter().enumerate() {
        if let Some(error) = refused.get(&index) {
            book.fail(
                receipt,
                endpoint,
                format!(
                    "attaching Inventory return {} in group {serial}: {error}",
                    entry.id
                ),
                true,
            );
            continue;
        }
        let kind = entry.info_kind.unwrap_or(0);
        if let Err(error) = io
            .publish_info_kind(entry.id, kind)
            .with_context(|| format!("publishing info kind for endpoint {}", entry.id))
        {
            book.fail(receipt, endpoint, format!("{error:#}"), true);
            continue;
        }
        survivors.push((*endpoint, *entry));
    }
    if return_group_links(links, serial) > 0 {
        receipt.groups.push(AttachGroup {
            serial,
            object: info[0].0.object,
            program: "p11_info_return",
            members: survivors.iter().map(|(endpoint, _)| endpoint.id).collect(),
            links: return_group_links(links, serial),
        });
    }
    // Usage members (none: groups are homogeneous by program) plus
    // the info survivors mark attached.
    let mut out: Vec<(AttachEndpoint, InventoryEndpoint)> = members
        .into_iter()
        .filter(|(_, entry)| entry.info_kind.is_none())
        .collect();
    out.extend(survivors);
    out
}

/// Links held under one return-group serial.
fn return_group_links<L>(links: &[InventoryLinked<L>], serial: u32) -> usize {
    links
        .iter()
        .filter(|link| link.target == InventoryLinkIdentity::ReturnGroup(serial))
        .count()
}

/// Multi: the window's new entries are admitted (published) first, then
/// attached as one immutable uprobe-multi group per (object, entry
/// program), in object order. Nothing here detaches, replaces, or extends
/// an existing group: a later extend's entries form new groups.
#[allow(clippy::too_many_arguments)]
fn extend_groups_with<I: InventoryLinkIo>(
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
    // Admission: the same per-entry transaction and window as Singles.
    let mut attempted = 0usize;
    let mut admitted: Vec<(AttachEndpoint, InventoryEndpoint)> = Vec::new();
    for (index, endpoint) in delta.endpoints.iter().enumerate() {
        // An endpoint submitted twice in one delta is admitted once (the
        // Singles path finds it attached by then).
        if book.knows(endpoint.id.0) || admitted.iter().any(|(seen, _)| seen.id == endpoint.id) {
            receipt.known.push(endpoint.id);
            continue;
        }
        if attempted >= window.max_entries || Instant::now() >= window.deadline {
            // A later copy of an entry this extend already admitted is
            // handled here (review I1): known, never also deferred, so
            // the receipt keeps exactly one bucket per entry.
            let in_extend = |endpoint: &&AttachEndpoint| {
                book.knows(endpoint.id.0) || admitted.iter().any(|(seen, _)| seen.id == endpoint.id)
            };
            let rest = &delta.endpoints[index..];
            let unknown: Vec<AttachEndpoint> = rest
                .iter()
                .filter(|endpoint| !in_extend(endpoint))
                .copied()
                .collect();
            defer(receipt, &unknown);
            receipt
                .known
                .extend(rest.iter().filter(in_extend).map(|endpoint| endpoint.id));
            break;
        }
        attempted += 1;
        if let Some(entry) = admit_entry(io, targets, book, endpoint, source, receipt) {
            admitted.push((*endpoint, entry));
        }
    }
    // Grouping: one group per (object, entry program), in delta order,
    // attached in links sized by `multi_link_sites` as they go. Every
    // member's binding is already published.
    let mut groups: BTreeMap<GroupKey, Vec<GroupMember>> = BTreeMap::new();
    for (endpoint, entry) in admitted {
        // Keymeta Task 7 (spec §17.4, fix8 I1): the info endpoints
        // split out of their usage groups into their own groups per
        // (object, info entry program).
        groups
            .entry((
                entry.object.0,
                entry_program_for(entry.abi, entry.info_kind),
            ))
            .or_default()
            .push((endpoint, entry));
    }
    let mut pending: Vec<(GroupKey, Vec<GroupMember>)> = groups.into_iter().collect();
    pending.reverse();
    while let Some(((object, program), mut members)) = pending.pop() {
        // One link's worth; the rest of the group goes back first in line,
        // sized after this link measured its cost.
        let sites = multi_link_sites(
            source.mappers(members[0].0.object),
            book.link_ns_per_site.get(&object).copied(),
        );
        if members.len() > sites {
            let rest = members.split_off(sites);
            pending.push(((object, program), rest));
        }
        let defer_members = |receipt: &mut ExtendReceipt,
                             members: &[GroupMember],
                             rest: &[(GroupKey, Vec<GroupMember>)]| {
            let deferred: Vec<AttachEndpoint> = members
                .iter()
                .chain(rest.iter().flat_map(|(_, members)| members))
                .map(|(endpoint, _)| *endpoint)
                .collect();
            defer(receipt, &deferred);
        };
        // A published-but-unattached group retries its attach only.
        if Instant::now() >= window.deadline {
            defer_members(receipt, &members, &pending);
            return;
        }
        let local = PinnedObjectId(object);
        let fail_all = |book: &mut CaptureBook,
                        receipt: &mut ExtendReceipt,
                        members: &[(AttachEndpoint, InventoryEndpoint)],
                        reason: &str,
                        retained: bool| {
            for (endpoint, _) in members {
                book.fail(receipt, endpoint, reason.to_string(), retained);
            }
        };
        if let Err(error) = targets
            .check_object(local)
            .with_context(|| format!("before Inventory group of object {object}"))
        {
            fail_all(book, receipt, &members, &format!("{error:#}"), false);
            continue;
        }
        let Some(path) = targets.attach_path(local) else {
            fail_all(
                book,
                receipt,
                &members,
                "missing Inventory target pin",
                false,
            );
            continue;
        };
        let sites: Vec<(u64, u64)> = members
            .iter()
            .map(|(_, entry)| {
                (
                    entry.file_offset,
                    (u64::from(p11scope_ebpf_common::INVENTORY_COOKIE_TAG) << 32)
                        | u64::from(entry.id),
                )
            })
            .collect();
        let started = Instant::now();
        let attached = io.attach_entry_group(InventoryGroupRequest {
            program,
            path: &path,
            sites: &sites,
        });
        let spent = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        receipt.attach_ns_total = receipt.attach_ns_total.saturating_add(spent);
        receipt.attach_ns_max = receipt.attach_ns_max.max(spent);
        // The measured per-site cost sizes this object's next link (a
        // halted attach measured nothing comparable).
        if attached.is_ok() {
            let per_site = spent / u64::try_from(sites.len()).unwrap_or(u64::MAX).max(1);
            book.link_ns_per_site.insert(object, per_site);
        }
        let attach = match attached {
            Ok(attach) => attach,
            Err(p11scope_bpf_multi::BisectHalt {
                halt: p11scope_bpf_multi::GroupHalt::Exhausted(_),
                closed_leaves,
            }) => {
                // No link reached custody: leaves a bisect had already
                // linked were closed by the halt and are counted, never
                // claimed absent. The members stay published-unattached
                // and they and every later group defer.
                receipt.halt_closed_links += closed_leaves;
                receipt.fd_exhausted = true;
                defer_members(receipt, &members, &pending);
                return;
            }
            Err(p11scope_bpf_multi::BisectHalt {
                halt: p11scope_bpf_multi::GroupHalt::Unsupported(error),
                closed_leaves,
            }) => {
                receipt.halt_closed_links += closed_leaves;
                // The backend was chosen before any producer existed; a
                // kernel refusing it now fails the group, never silently
                // falls back (no fresh object after observations).
                fail_all(
                    book,
                    receipt,
                    &members,
                    &format!("uprobe-multi refused by the running kernel: {error}"),
                    false,
                );
                continue;
            }
        };
        let serial = u32::try_from(book.groups.len()).unwrap_or(u32::MAX);
        let before = links.len();
        // Custody first, before any post-acquisition check can fail.
        for handle in attach.links {
            links.push(InventoryLinked {
                target: InventoryLinkIdentity::EntryGroup(serial),
                handle,
            });
        }
        let retained = links.len() > before;
        let refused: BTreeMap<usize, std::io::Error> = attach.refused.into_iter().collect();
        // Every site refused and no link: a target that died since the
        // extend's custody check refuses every site (ESRCH). Name that,
        // not the per-site errno (review I2).
        if !retained
            && !refused.is_empty()
            && let Err(reason) = custody()
        {
            let reason = format!("PID custody lost before group {serial} could attach: {reason}");
            book.mark_lost(reason.clone());
            fail_all(book, receipt, &members, &reason, false);
            defer_members(receipt, &[], &pending);
            return;
        }
        let mut accepted = Vec::with_capacity(members.len());
        for (index, (endpoint, entry)) in members.iter().enumerate() {
            match refused.get(&index) {
                Some(error) => book.fail(
                    receipt,
                    endpoint,
                    format!(
                        "attaching Inventory entry {} in group {serial}: {error}",
                        entry.id
                    ),
                    false,
                ),
                None => accepted.push((*endpoint, *entry)),
            }
        }
        let post = links[before..]
            .iter()
            .find_map(|link| io.attachment_error(&link.handle))
            .map(|error| anyhow::anyhow!(error))
            .map_or_else(
                || {
                    targets
                        .check_object(local)
                        .with_context(|| format!("during Inventory group {serial} attachment"))
                },
                Err,
            );
        if retained {
            book.groups.push(AttachGroup {
                serial,
                object: members[0].0.object,
                program,
                members: accepted.iter().map(|(endpoint, _)| endpoint.id).collect(),
                links: links.len() - before,
            });
            receipt.groups.push(book.groups.last().unwrap().clone());
        }
        if let Err(error) = post {
            // Every accepted member fails; the group's links stay owned
            // until stop closes them whole.
            fail_all(book, receipt, &accepted, &format!("{error:#}"), retained);
            continue;
        }
        if accepted.is_empty() {
            continue;
        }
        if let Err(reason) = custody() {
            let reason = format!("PID custody lost after attaching group {serial}: {reason}");
            book.mark_lost(reason.clone());
            fail_all(book, receipt, &accepted, &reason, retained);
            defer_members(receipt, &[], &pending);
            return;
        }
        // Keymeta Task 7 (spec §17.4): info entry groups attempt
        // their return group inline, before members mark attached.
        let accepted = attach_info_return_group(
            io,
            targets,
            links,
            book,
            receipt,
            object,
            accepted,
            serial,
            window.deadline,
        );
        if accepted.is_empty() {
            continue;
        }
        let at_ns = now();
        for (endpoint, entry) in accepted {
            book.attached.insert(entry.id);
            receipt.attached.push(AttachedEndpoint {
                id: endpoint.id,
                object: endpoint.object,
                at_ns,
            });
        }
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
        Self::prepare_with_host(
            scope,
            endpoints,
            callers,
            backend,
            crate::attach::require_multi_capable_host(),
        )
    }

    /// Private proof controls exercise preparation independently of live host admission.
    #[cfg(test)]
    pub(crate) fn prepare_for_proof(
        scope: CaptureScope,
        endpoints: InventoryBudget,
        callers: CallerBudget,
        backend: AttachBackend,
    ) -> Result<Self> {
        Self::prepare_with_host(
            scope,
            endpoints,
            callers,
            backend,
            Ok(crate::attach::MultiCapableHost::for_test()),
        )
    }

    fn prepare_with_host(
        scope: CaptureScope,
        endpoints: InventoryBudget,
        callers: CallerBudget,
        backend: AttachBackend,
        host: crate::attach::MultiHostVerdict,
    ) -> Result<Self> {
        let _host = host?;
        let domain = NativeDomainId::try_mint()?;
        if backend == AttachBackend::Multi && matches!(scope, CaptureScope::Pid(_)) {
            crate::attach::kernel_multi_pid_filter().map_err(|reason| {
                anyhow::anyhow!(
                    "Inventory PID capture refuses uprobe-multi: its groups must carry the \
                     kernel pid filter, and {reason}"
                )
            })?;
        }
        let CapturePreparation {
            scope,
            pid_pin,
            held_scope,
        } = scope.into_prepared_scope()?;
        // Every entry link costs a descriptor (the `Session::start`
        // precedent): raise first, then prove the backend's link bound + 3
        // + reserve fit.
        let soft_limit = crate::process::raise_nofile().context("reading RLIMIT_NOFILE")?;
        fd_preflight(
            backend,
            endpoints.endpoint_limit(),
            soft_limit as u64,
            fds_in_use()?,
        )?;
        // The seen set's bound IS the CALLER_USE capacity (pair precondition).
        let pair_limit = super::callers::seen_limit(callers)?;
        let prepared =
            PreparedInventory::prepare_callers_pinned(scope, pid_pin, endpoints, callers, backend)?;
        Ok(Self {
            state: CaptureState::Prepared(Box::new(prepared)),
            book: CaptureBook::new_scoped_with_domain(
                domain,
                endpoints,
                pair_limit,
                held_scope,
                monotonic_ns(),
            )
            .with_backend(backend),
        })
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.book.domain
    }

    /// The backend this capture attaches entries with.
    pub(crate) fn backend(&self) -> AttachBackend {
        self.book.backend
    }

    /// The attach groups created so far (Multi; empty under Singles).
    pub(crate) fn groups(&self) -> &[AttachGroup] {
        &self.book.groups
    }

    /// The kernel links this capture holds now: the lifecycle roots plus
    /// every entry link (one per endpoint under Singles, one per group
    /// leaf under Multi). Zero before activation.
    pub(crate) fn live_links(&self) -> usize {
        match &self.state {
            CaptureState::Active(active) => active.state().live_links(),
            CaptureState::Failed { retiring, .. } => {
                retiring.state().map_or(0, InventoryState::live_links)
            }
            CaptureState::Prepared(_) | CaptureState::Moving => 0,
        }
    }

    pub(crate) fn scope_coverage(&self) -> CaptureScopeCoverage {
        self.book.scope_coverage()
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
        poll_book(&mut self.book, pid_pin_of(&self.state));
    }
}

/// One custody poll of the book's PID scope through `pin` (none for the
/// machine, or once custody is lost). Every read polls first, whatever
/// the phase, so its custody and proof instant are its own.
fn poll_book(book: &mut CaptureBook, pin: Option<&PidPin>) {
    // Revalidate the original pin while an exit fact can authorize a tail.
    // Once custody is uncertain, later polls cannot upgrade that loss.
    if book.incarnation().is_none() || (book.custody_lost.is_some() && book.original_exit.is_none())
    {
        return;
    }
    let now_ns = monotonic_ns();
    let poll = poll_custody(pin);
    let proof = book
        .incarnation()
        .filter(|_| {
            book.unproven.is_none()
                && book.lifecycle_lost.is_none()
                && book.changed_objects.is_empty()
        })
        .and_then(|scope| {
            pin.and_then(|pin| OriginalPidExit::from_poll(book.domain, scope, pin, &poll))
        });
    book.absorb_poll(poll, now_ns);
    book.original_exit = proof;
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
                    // Stamped after the roots are proven attached: an exec
                    // before this instant left no lifecycle record.
                    receipt.exec_coverage = Some(ExecCoverage {
                        domain: self.book.domain,
                        start_ns: monotonic_ns(),
                    });
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
                receipt
                    .deferred
                    .info_revoked
                    .extend(delta.info_revoked.iter().copied());
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
                receipt
                    .deferred
                    .info_revoked
                    .extend(delta.info_revoked.iter().copied());
                return true;
            }
            if let Err(reason) = custody() {
                let reason = format!("PID custody lost before extend: {reason}");
                book.mark_lost(reason.clone());
                receipt.refused = Some(reason);
                defer(&mut receipt, &delta.endpoints);
                receipt
                    .deferred
                    .info_revoked
                    .extend(delta.info_revoked.iter().copied());
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

    /// Explicit pre-view identity acquisition; one exclusive native query can
    /// run at a time. Render/key callbacks never acquire these kernel facts.
    pub(crate) fn query_promotion_baselines(
        &mut self,
        capture: crate::inventory_promotion::CaptureId,
        presentation: Arc<crate::inventory_present::Presentation>,
        targets: &[crate::attach::selected_detailed::baseline::BaselineTarget],
        window: ReadWindow,
        reserve: impl FnOnce(
            usize,
        ) -> std::result::Result<
            crate::semantics_edge::resources::ResourceLease,
            crate::semantics_edge::resources::SemanticResourceRefusal,
        >,
    ) -> Result<crate::attach::selected_detailed::baseline::PromotionBaselineBatch> {
        let generation = self.next_image_query_generation()?;
        match &mut self.state {
            CaptureState::Prepared(prepared) => crate::attach::selected_detailed::baseline::query(
                &mut prepared.ebpf,
                self.book.domain,
                generation,
                capture,
                presentation,
                targets,
                window,
                reserve,
            ),
            CaptureState::Active(active) => active.state_mut().query_promotion_baselines(
                self.book.domain,
                generation,
                capture,
                presentation,
                targets,
                window,
                reserve,
            ),
            CaptureState::Failed { .. } | CaptureState::Moving => {
                bail!("Inventory native owner is unavailable for a baseline")
            }
        }
    }

    /// One genuine identity-only endpoint sample under the same exclusive
    /// native owner/generation as promotion baselines. No Presentation or
    /// permission-bearing receipt is involved. Metadata workers never receive
    /// a mutable query handle and must already name an admitted NativeExact
    /// row; the specifically approved inventory-owner guard is this
    /// operation's one admission-adjacent consumer.
    pub(crate) fn observe_caller_image(
        &mut self,
        original: &Arc<PidPin>,
        window: ReadWindow,
    ) -> Result<CallerImageObservation> {
        let generation = self.next_image_query_generation()?;
        match &mut self.state {
            CaptureState::Prepared(prepared) => {
                crate::attach::selected_detailed::baseline::observe_caller_image(
                    &mut prepared.ebpf,
                    self.book.domain,
                    generation,
                    original,
                    window,
                )
            }
            CaptureState::Active(active) => active.state_mut().observe_caller_image(
                self.book.domain,
                generation,
                original,
                window,
            ),
            CaptureState::Failed { .. } | CaptureState::Moving => {
                bail!("Inventory native owner is unavailable for caller image observation")
            }
        }
    }

    fn next_image_query_generation(&mut self) -> Result<u64> {
        ensure!(!self.book.stopping, "Inventory is stopping");
        self.book.promotion_baseline_generation = self
            .book
            .promotion_baseline_generation
            .checked_add(1)
            .context("Inventory image query generation exhausted")?;
        Ok(self.book.promotion_baseline_generation)
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
                    let mut high_water = state.discovery_fill_bytes();
                    let result = service_inventory_discovery_with(
                        max,
                        deadline,
                        || {
                            high_water = high_water.max(state.discovery_fill_bytes());
                            state.dequeue_discovery()
                        },
                        dispatch,
                    );
                    (result, state.discovery_head_pending(), high_water)
                })
            }
            CaptureState::Failed { retiring, .. } => {
                service_with(&mut self.book, window, |max, deadline, dispatch| {
                    let (result, high_water) = retiring.service_discovery(max, deadline, dispatch);
                    (result, retiring.discovery_head_pending(), high_water)
                })
            }
            CaptureState::Prepared(_) | CaptureState::Moving => {
                DiscoveryBatch::empty(self.book.domain)
            }
        }
    }

    /// Keymeta Task 7 (spec §17.4): up to `window` INFO records.
    /// Raw 176-byte frames (decoded at staging) plus the
    /// produced-vs-consumed cross-check snapshot. A malformed frame
    /// ends its quantum with exact evidence; the derived cross-check
    /// loss never marks lifecycle loss (provider facts are advisory,
    /// never custody) — only a full ring's reserve failures ride the
    /// shared ring-loss counter beside `DISCOVERY` losses.
    pub(crate) fn service_info(&mut self, window: ReadWindow) -> InfoBatch {
        match &mut self.state {
            CaptureState::Active(active) => {
                service_info_quantum(&mut self.book, window, active.state_mut())
            }
            CaptureState::Failed { retiring, .. } => {
                service_info_quantum(&mut self.book, window, retiring.as_mut())
            }
            CaptureState::Prepared(_) | CaptureState::Moving => InfoBatch::empty(self.book.domain),
        }
    }

    /// Starts owned retirement. Reads stay available and are unsettled.
    /// The count-refresh traversal restarts (baselines kept): the
    /// terminal refresh is then a generation begun after this boundary,
    /// never the tail of a pre-stop sweep with stale prefix rows.
    pub(crate) fn begin_stop(self) -> RetiringCapture {
        let Self { state, mut book } = self;
        book.stopping = true;
        book.cursor.restart_refresh_traversal();
        let (inner, failure) = match state {
            // Never activated: no producer ever existed. The PID pin stays
            // held so a read after stop still polls custody.
            CaptureState::Prepared(prepared) => {
                (RetiringInner::Unactivated(prepared.pid_pin), None)
            }
            CaptureState::Moving => (RetiringInner::Unactivated(None), None),
            CaptureState::Active(active) => {
                (RetiringInner::Retiring(Box::new(active.begin_stop())), None)
            }
            CaptureState::Failed { error, retiring } => {
                (RetiringInner::Retiring(retiring), Some(error))
            }
        };
        retiring_capture(inner, book, failure)
    }
}

/// Every begin_stop branch transfers the same root-owning book here, including
/// active and failed captures. No optional root clone or default scope exists.
fn retiring_capture(
    inner: RetiringInner,
    book: CaptureBook,
    failure: Option<String>,
) -> RetiringCapture {
    RetiringCapture {
        inner,
        book,
        failure,
    }
}

enum RetiringInner {
    /// Never activated; holds the prepared PID pin, if any.
    Unactivated(Option<PidPin>),
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
            RetiringInner::Unactivated(_) => Ok(true),
            RetiringInner::Retiring(retiring) => retiring.poll_completion(deadline),
        }
    }

    /// True once every link had its close attempt, even while the
    /// INFO scrub still blocks the ownership transfer.
    pub(crate) fn detach_completed(&self) -> bool {
        match &self.inner {
            RetiringInner::Unactivated(_) => true,
            RetiringInner::Retiring(retiring) => retiring.detach_completed(),
        }
    }

    pub(crate) fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        match &mut self.inner {
            RetiringInner::Unactivated(_) => DiscoveryBatch::empty(self.book.domain),
            RetiringInner::Retiring(retiring) => {
                service_with(&mut self.book, window, |max, deadline, dispatch| {
                    let (result, high_water) = retiring.service_discovery(max, deadline, dispatch);
                    (result, retiring.discovery_head_pending(), high_water)
                })
            }
        }
    }

    /// Keymeta Task 7 (spec §17.4): drain remaining INFO records
    /// after stop began (the session marks the last quantum of its
    /// terminal cut, which reports the observed backlog).
    pub(crate) fn service_info(&mut self, window: ReadWindow) -> InfoBatch {
        match &mut self.inner {
            RetiringInner::Unactivated(_) => InfoBatch::empty(self.book.domain),
            RetiringInner::Retiring(retiring) => {
                service_info_quantum(&mut self.book, window, retiring.as_mut())
            }
        }
    }

    /// A read after stop began: custody is re-polled first (C5.2 M-3), so
    /// the terminal read never reports the last active poll's verdict.
    pub(crate) fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
        // A retiring capture with no state holds no pin: the poll reads
        // lost (the pin is no longer held).
        let pin = match &self.inner {
            RetiringInner::Unactivated(pin) => pin.as_ref(),
            RetiringInner::Retiring(retiring) => retiring.state().and_then(InventoryState::pid_pin),
        };
        poll_book(&mut self.book, pin);
        let state = match &mut self.inner {
            RetiringInner::Unactivated(_) => None,
            RetiringInner::Retiring(retiring) => retiring.state_mut(),
        };
        read_witnesses_from(state, &mut self.book, CapturePhase::Retiring, window)
    }

    pub(crate) fn query_cookie(&self, pin: &PidPin) -> CookieQuery {
        let ebpf = match &self.inner {
            RetiringInner::Unactivated(_) => None,
            RetiringInner::Retiring(retiring) => retiring.state().map(InventoryState::ebpf),
        };
        query_cookie_in(ebpf, self.book.domain, pin)
    }

    /// Transfers the completed retirement, or returns this capture intact.
    /// The stop `deadline` bounds the INFO stash scrub's native work:
    /// nothing starts at or past it.
    pub(crate) fn try_finish(
        self,
        deadline: Instant,
    ) -> std::result::Result<RetiredCapture, Box<Self>> {
        let Self {
            inner,
            book,
            failure,
        } = self;
        match inner {
            RetiringInner::Unactivated(pin) => Ok(RetiredCapture {
                inner: None,
                unactivated_pin: pin,
                book,
                cleanup: CleanupSummary::default(),
                failure,
            }),
            RetiringInner::Retiring(retiring) => match retiring.try_finish(deadline) {
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
                        info_teardown_unproven: retired.cleanup.info_teardown_unproven,
                        info_scrub_error: retired.cleanup.info_scrub_error.clone(),
                    };
                    let mut retired = RetiredCapture {
                        inner: Some(Box::new(retired)),
                        unactivated_pin: None,
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

    /// The INFO stash teardown outcome for the operator (spec §17.4).
    pub(crate) fn info_teardown(&self) -> InfoTeardown {
        match &self.inner {
            RetiringInner::Unactivated(_) => InfoTeardown::Proven,
            RetiringInner::Retiring(retiring) => retiring.info_teardown(),
        }
    }

    /// Give up reclamation for process exit: keep every native owner
    /// alive without joining the retirement job.
    pub(crate) fn abandon_for_process_exit(self) {
        crate::inventory_capture::ExitRetention::hold(self)
    }
}

/// A retired capture: maps and pins stay readable until it drops.
pub(crate) struct RetiredCapture {
    inner: Option<Box<RetiredInventory>>,
    /// The prepared PID pin of a capture that was never activated.
    unactivated_pin: Option<PidPin>,
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

    /// The terminal read: custody is re-polled first (C5.2 M-3).
    pub(crate) fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
        let pin = match &self.inner {
            Some(inner) => inner.state().pid_pin(),
            None => self.unactivated_pin.as_ref(),
        };
        poll_book(&mut self.book, pin);
        let state = self.inner.as_mut().map(|inner| inner.state_mut());
        read_witnesses_from(state, &mut self.book, CapturePhase::Retired, window)
    }

    pub(crate) fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        match self.inner.as_mut() {
            None => DiscoveryBatch::empty(self.book.domain),
            Some(inner) => {
                let state = inner.state_mut();
                service_with(&mut self.book, window, |max, deadline, dispatch| {
                    let mut high_water = state.discovery_fill_bytes();
                    let result = service_inventory_discovery_with(
                        max,
                        deadline,
                        || {
                            high_water = high_water.max(state.discovery_fill_bytes());
                            state.dequeue_discovery()
                        },
                        dispatch,
                    );
                    (result, state.discovery_head_pending(), high_water)
                })
            }
        }
    }

    /// Keymeta Task 7 (spec §17.4): one INFO quantum for the
    /// session's terminal cut, which reports the observed backlog
    /// (never certified loss).
    pub(crate) fn service_info(&mut self, window: ReadWindow) -> InfoBatch {
        match self.inner.as_mut() {
            None => InfoBatch::empty(self.book.domain),
            Some(inner) => service_info_quantum(&mut self.book, window, inner.state_mut()),
        }
    }

    pub(crate) fn query_cookie(&self, pin: &PidPin) -> CookieQuery {
        let ebpf = self.inner.as_ref().map(|inner| inner.state().ebpf());
        query_cookie_in(ebpf, self.book.domain, pin)
    }

    /// Give up reclamation for process exit: keep the retired owners
    /// alive instead of dropping them.
    pub(crate) fn abandon_for_process_exit(self) {
        crate::inventory_capture::ExitRetention::hold(self)
    }
}

type Dispatch<'a> = &'a mut dyn FnMut(DiscoveryRecord) -> Result<()>;

fn service_with(
    book: &mut CaptureBook,
    window: ReadWindow,
    service: impl FnOnce(usize, Instant, Dispatch<'_>) -> ServiceOutcome,
) -> DiscoveryBatch {
    service_with_clock(book, window, &mut monotonic_ns, service)
}

/// Keymeta Task 7 (spec §17.4): one INFO quantum's native
/// source — the ring dequeue plus the produced counter and the four
/// evidence cells. Every capture state serves its quanta through
/// this one trait so the ring+counter window binds them all alike.
trait InfoQuantumSource {
    fn dequeue_info(&mut self) -> Result<Option<super::activation::InfoItem>>;
    fn info_produced(&self) -> Option<Result<u64, String>>;
    fn info_evidence(&self, deadline: Instant) -> Option<super::activation::InfoEvidenceRead>;
}

impl InfoQuantumSource for InventoryState {
    fn dequeue_info(&mut self) -> Result<Option<super::activation::InfoItem>> {
        InventoryState::dequeue_info(self)
    }
    fn info_produced(&self) -> Option<Result<u64, String>> {
        InventoryState::info_produced(self)
    }
    fn info_evidence(&self, deadline: Instant) -> Option<super::activation::InfoEvidenceRead> {
        InventoryState::info_evidence(self, deadline)
    }
}

impl InfoQuantumSource for RetiringInventory {
    fn dequeue_info(&mut self) -> Result<Option<super::activation::InfoItem>> {
        RetiringInventory::dequeue_info(self)
    }
    fn info_produced(&self) -> Option<Result<u64, String>> {
        RetiringInventory::info_produced(self)
    }
    fn info_evidence(&self, deadline: Instant) -> Option<super::activation::InfoEvidenceRead> {
        RetiringInventory::info_evidence(self, deadline)
    }
}

/// Keymeta Task 7 (spec §17.4): one bounded INFO quantum for every
/// capture state — the ring drain plus the produced-vs-consumed
/// cross-check snapshot — through a single ring+counter window.
/// The window binds the counters as well as the ring: no produced
/// or evidence lookup starts at or past it, each of the four
/// evidence cells gating on the window in turn. A skipped counter
/// or a mid-group yield stages the quantum incomplete (the yielded
/// group keeps the previous full sample), so the terminal cut
/// reports the expired window instead of a clean cut over unread
/// or partially read counters.
fn service_info_quantum(
    book: &mut CaptureBook,
    window: ReadWindow,
    source: &mut impl InfoQuantumSource,
) -> InfoBatch {
    let (records, malformed, failure, ring_complete) =
        drain_info_quantum(window, || source.dequeue_info());
    let mut complete = ring_complete;
    let produced = if Instant::now() >= window.deadline() {
        complete = false;
        None
    } else {
        source.info_produced()
    };
    let evidence = if Instant::now() >= window.deadline() {
        complete = false;
        None
    } else {
        match source.info_evidence(window.deadline()) {
            Some(super::activation::InfoEvidenceRead::Done(result)) => Some(result),
            Some(super::activation::InfoEvidenceRead::Yielded) => {
                complete = false;
                None
            }
            None => None,
        }
    };
    book.finish_info_quantum(records, malformed, failure, complete, produced, evidence)
}

/// Keymeta Task 7 (spec §17.4): drain one bounded INFO quantum:
/// collected records, the malformed frames counted at dequeue, and
/// a dequeue failure's text. A malformed frame ends the quantum
/// with exact evidence, like DISCOVERY; any other error — a
/// ring-read failure, a refused bound — surfaces distinctly with
/// its cause instead of hiding behind the malformed count.
fn drain_info_quantum(
    window: ReadWindow,
    mut dequeue: impl FnMut() -> Result<Option<super::activation::InfoItem>>,
) -> (Vec<[u8; 176]>, u64, Option<String>, bool) {
    let mut records = Vec::new();
    let mut malformed = 0u64;
    let result = super::activation::service_inventory_info_with(
        window.max_rows(),
        window.deadline(),
        || match dequeue() {
            Ok(Some(super::activation::InfoItem::Malformed)) => {
                malformed = malformed.saturating_add(1);
                Ok(Some(super::activation::InfoItem::Malformed))
            }
            dequeued => dequeued,
        },
        |record| {
            records.push(record);
            Ok(())
        },
    );
    match result {
        // Complete only when the service drained to empty: a record
        // bound or deadline means the ring may still hold records.
        Ok(service) => (
            records,
            malformed,
            None,
            !service.record_bound_reached && !service.deadline_reached,
        ),
        Err(failure) => {
            // Dispatch never fails here, so a held-back record is
            // unexpected: keep it with the failure, like DISCOVERY.
            // Any error stops the drain early: never complete, even
            // when malformed frames carry the evidence instead.
            let held_back = failure.record.is_some();
            if let Some(record) = failure.record {
                records.push(*record);
            }
            if held_back || malformed == 0 {
                (
                    records,
                    malformed,
                    Some(format!("{:#}", failure.error)),
                    false,
                )
            } else {
                (records, malformed, None, false)
            }
        }
    }
}

/// What one serviced drain reports: its outcome, whether the head was
/// still pending, and the drain's high-water fill.
type ServiceOutcome = (
    std::result::Result<
        super::activation::InventoryDiscoveryService,
        super::activation::InventoryDispatchFailure,
    >,
    bool,
    Option<u64>,
);

/// `service_with` over an injected CLOCK_MONOTONIC (tests script it).
fn service_with_clock(
    book: &mut CaptureBook,
    window: ReadWindow,
    clock: &mut dyn FnMut() -> u64,
    service: impl FnOnce(usize, Instant, Dispatch<'_>) -> ServiceOutcome,
) -> DiscoveryBatch {
    let mut records = Vec::new();
    let mut dispatch = |record: DiscoveryRecord| {
        records.push(record);
        Ok(())
    };
    // `head_pending` is read after the service returns, so it reflects the
    // ring at (or after) the read that came back empty.
    let started_ns = clock();
    let (result, head_pending, high_water) =
        service(window.max_rows, window.deadline, &mut dispatch);
    let finished_ns = clock();
    for record in &records {
        book.observe_record(record);
    }
    if let Err(failure) = &result {
        // A record that could not be decoded may have been an exec of the
        // PID target, produced at any instant since the last drain that
        // emptied the ring: custody since then is unproven.
        book.mark_lifecycle_loss(
            book.drained_ns,
            format!("a lifecycle record was lost: {:#}", failure.error),
        );
    }
    let batch = match result {
        Ok(service) => DiscoveryBatch {
            domain: book.domain,
            started_ns,
            finished_ns,
            records,
            record_bound_reached: service.record_bound_reached,
            deadline_reached: service.deadline_reached,
            failure: None,
            head_pending: head_pending
                && !service.record_bound_reached
                && !service.deadline_reached,
            drain_high_water_bytes: high_water,
        },
        Err(failure) => {
            // Dispatch never fails here, so no consumed record is held back.
            if let Some(record) = failure.record {
                book.observe_record(&record);
                records.push(*record);
            }
            DiscoveryBatch {
                domain: book.domain,
                started_ns,
                finished_ns,
                records,
                record_bound_reached: false,
                deadline_reached: false,
                failure: Some(format!("{:#}", failure.error)),
                head_pending: false,
                drain_high_water_bytes: high_water,
            }
        }
    };
    // A clock failure (`u64::MAX`) is safe for a read stamp, never for a
    // floor: it would date every later undatable loss past any interval.
    if batch.drained()
        && let Some(started) = drain_stamp(batch.started_ns)
    {
        book.drained_ns = started;
    }
    batch
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
        counts: Vec::new(),
        refresh_sweep_completed: false,
        refresh_sweep_gaps: false,
        refresh_deadline_reached: false,
        refresh_sweeps_completed: book.cursor.refresh_sweeps_completed(),
        seen_rows: book.cursor.occupancy(),
        pair_limit: book.pair_limit,
        health: CaptureHealth::default(),
        health_regression: None,
        health_unproven: None,
        health_baseline_ns: book.health_ns,
        health_read_ns: 0,
        rows_anchor_ns: 0,
        rows_read_ns: 0,
        counts_read_ns: 0,
        changed_objects: Vec::new(),
        custody: book.custody(),
        custody_proven_ns: book.incarnation().map(|_| book.held_ns),
        lifecycle_proven_ns: book.drained_ns,
        lifecycle_loss: book.lifecycle_loss(),
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
    let mut io: &Ebpf = state.ebpf();
    read_rows_from_with(&mut io, book, &mut batch, window, capacity);
    batch.custody = book.custody();
    batch.custody_proven_ns = book.incarnation().map(|_| book.held_ns);
    batch.lifecycle_proven_ns = book.drained_ns;
    batch.lifecycle_loss = book.lifecycle_loss();
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

/// The row half of one witness read over any CALLER_USE IO (the real map
/// in production, scripted rows in tests): the witness quantum first — new
/// rows seed their count baselines as they report — then the count-refresh
/// quantum over the witnessed rows within the same window bounds.
fn read_rows_from_with<I: CallerUseIo>(
    io: &mut I,
    book: &mut CaptureBook,
    batch: &mut WitnessBatch,
    window: ReadWindow,
    capacity: u32,
) {
    read_rows_from_with_clock(io, book, batch, window, capacity, &mut monotonic_ns);
}

fn read_rows_from_with_clock<I: CallerUseIo>(
    io: &mut I,
    book: &mut CaptureBook,
    batch: &mut WitnessBatch,
    window: ReadWindow,
    capacity: u32,
    clock: &mut impl FnMut() -> u64,
) {
    let published = &book.published;
    let failed = &book.failed;
    let scope_pid = book.scope_pid();
    batch.rows_anchor_ns = clock();
    let read = book.cursor.read_with(
        io,
        window.max_rows,
        window.deadline,
        capacity,
        |endpoint| published.get(&endpoint).map(|object| object.index()),
        |_, value| witness_rejection(failed, scope_pid, value),
    );
    // The count-lookup stamp goes down before the refresh quantum
    // (round 5, anchor skew): every refreshed count is observed at or
    // after it, so a base read anchors at-or-before its own lookup.
    // The batch stamp stays after the quantum — binding horizons
    // prove their starts strictly after the rows' read finished.
    batch.counts_read_ns = clock();
    let refreshed = book
        .cursor
        .refresh_with(io, window.max_rows, window.deadline);
    batch.rows_read_ns = clock();
    absorb_rows(book, batch, read);
    absorb_counts(book, batch, refreshed);
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
            entry_count: value.saturated_entry_count(),
        });
    }
    for (key, value, fault) in read.faults {
        let reason = row_fault_reason(&key, fault);
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

/// What one row fault means, for the witness and refresh absorbs alike.
fn row_fault_reason(key: &CallerObjectKey, fault: CallerRowFault) -> String {
    match fault {
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
        CallerRowFault::CountDecrease { before, after } => format!(
            "CALLER_USE entry count decreased {before}->{after} for a tracked row (integrity gap; the published count stays {before})"
        ),
    }
}

/// Re-validates one refreshed row's endpoint binding (H-C3R2): the
/// refresh re-reads without validating, so a corrupt re-read faults
/// into integrity here instead of indexing `published`.
fn refreshed_object(
    book: &CaptureBook,
    key: &CallerObjectKey,
    value: &CallerObjectUse,
) -> Result<AttachObjectId, super::callers::CallerRowFault> {
    match book.published.get(&value.witness_endpoint).copied() {
        Some(object) if object.index() == key.object_id => Ok(object),
        Some(object) => Err(super::callers::CallerRowFault::BindingMismatch {
            published: object.index(),
        }),
        None => Err(super::callers::CallerRowFault::UnpublishedEndpoint),
    }
}

fn absorb_counts(
    book: &mut CaptureBook,
    batch: &mut WitnessBatch,
    refreshed: super::callers::CallerCountsRead,
) {
    let integrity_before = batch.integrity.len();
    for (key, value) in refreshed.updates {
        match refreshed_object(book, &key, &value) {
            Ok(object) => batch.counts.push(CallerCountUpdate {
                image: key.image,
                object,
                count: value.saturated_entry_count(),
            }),
            Err(fault) => {
                let reason = row_fault_reason(&key, fault);
                batch.integrity.push(WitnessIntegrity {
                    key,
                    value: Some(value),
                    reason,
                });
            }
        }
    }
    for (key, value, fault) in refreshed.gaps {
        let reason = row_fault_reason(&key, fault);
        batch
            .integrity
            .push(WitnessIntegrity { key, value, reason });
    }
    book.integrity_total = book
        .integrity_total
        .saturating_add((batch.integrity.len() - integrity_before) as u64);
    batch.integrity_total = book.integrity_total;
    batch.refresh_sweep_completed = refreshed.sweep_completed;
    batch.refresh_sweep_gaps = refreshed.sweep_gaps;
    batch.refresh_deadline_reached = refreshed.deadline_reached;
    batch.refresh_sweeps_completed = book.cursor.refresh_sweeps_completed();
    batch.read_failures.extend(refreshed.read_failures);
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
mod cgroup_tests;

#[cfg(test)]
mod privileged_tests;
