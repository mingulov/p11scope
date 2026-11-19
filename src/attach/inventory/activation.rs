//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Private static Inventory activation: entry-only Singles with retained pins,
//! discovery transport and monotonic positive evidence. No caller/count claim.
//! The capture facade additionally attaches entries as immutable uprobe-multi
//! groups (Task 6 C5.11): one link per attach group, closed whole.

use super::{AttachBackend, InventoryBudget, InventoryFlavor, PreparedInventory, Scope, callers};
use crate::discovery::identity::{PinnedObjectId, PinnedObjects, RetainedInventoryTarget};
use crate::events::{DiscoveryItem, OwnedDiscoveryDrain};
use crate::plan::{AdmissionPolicy, AttachPlan};
use crate::process::PidPin;
use anyhow::{Context as _, Result, bail, ensure};
use aya::Ebpf;
use aya::maps::{Array, PerCpuArray};
use aya::programs::links::FdLink;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeLink, UProbeScope};
use aya::programs::{RawTracePoint, UProbe};
use p11scope_ebpf_common::{DiscoveryRecord, ThreadOwnerControl};
use p11scope_manifest::elf::ElfAbi;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Instant;

mod retirement;
use retirement::{
    RetirementFallbackEvidence, RetirementJob, RetirementLink, RetirementStartFailure,
    RetirementWork, abandon_and_reclaim_with,
};

pub(super) struct InventoryTargets {
    budget: InventoryBudget,
    allocated: Vec<u32>,
    entries: Vec<InventoryEndpoint>,
    pins: BTreeMap<PinnedObjectId, RetainedInventoryTarget>,
    changed: Cell<bool>,
}

#[derive(Clone, Copy)]
pub(super) struct InventoryEndpoint {
    pub(super) id: u32,
    pub(super) object: PinnedObjectId,
    pub(super) file_offset: u64,
    pub(super) abi: ElfAbi,
    /// Keymeta Task 7 (spec §17.4): the endpoint's info kind (`None`
    /// = usage-only), carried from the attach set.
    pub(super) info_kind: Option<u8>,
}

impl InventoryTargets {
    fn from_plan(plan: &AttachPlan, objects: &PinnedObjects) -> Result<Self> {
        let AdmissionPolicy::Inventory(budget) = plan.admission_policy() else {
            bail!("Inventory activation requires an Inventory attach plan");
        };
        // Public slots may have changed since plan construction. Reuse the
        // complete validator, including its private exact-target index.
        plan.validate_slot_index().map_err(anyhow::Error::msg)?;
        let mut targets = Self {
            budget,
            allocated: Vec::with_capacity(plan.slots.len()),
            entries: vec![],
            pins: BTreeMap::new(),
            changed: Cell::new(false),
        };
        for slot in &plan.slots {
            targets.allocated.push(slot.index);
            if !plan.is_active(slot.index) {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(entry) =
                targets.pins.entry(slot.object)
            {
                entry.insert(
                    objects
                        .retain_inventory_target(slot.object)
                        .map_err(anyhow::Error::msg)?,
                );
            }
            let pin = &targets.pins[&slot.object];
            targets.entries.push(InventoryEndpoint {
                id: slot.index,
                object: slot.object,
                file_offset: slot.file_offset,
                abi: pin.abi(),
                // The plan path predates the attach set's kind rule;
                // the capture facade (which carries kinds) is the
                // only producer of info endpoints.
                info_kind: None,
            });
        }
        targets.check_unchanged()?;
        Ok(targets)
    }

    /// An empty table the capture facade grows one attach-set delta at a
    /// time. Its object keys are the attach set's capture-lifetime object
    /// indices (published as ENDPOINT_OBJECT object IDs); like every
    /// `PinnedObjectId` they mean nothing outside this table.
    pub(super) fn for_capture(budget: InventoryBudget) -> Self {
        Self {
            budget,
            allocated: Vec::new(),
            entries: Vec::new(),
            pins: BTreeMap::new(),
            changed: Cell::new(false),
        }
    }

    pub(super) fn budget(&self) -> InventoryBudget {
        self.budget
    }

    pub(super) fn holds_object(&self, object: PinnedObjectId) -> bool {
        self.pins.contains_key(&object)
    }

    /// The retained pin's attach path (`/proc/self/fd/<n>` of the held
    /// file): never a reopened pathname.
    pub(super) fn attach_path(&self, object: PinnedObjectId) -> Option<std::path::PathBuf> {
        self.pins
            .get(&object)
            .map(RetainedInventoryTarget::attach_path)
    }

    pub(super) fn object_abi(&self, object: PinnedObjectId) -> Option<ElfAbi> {
        self.pins.get(&object).map(RetainedInventoryTarget::abi)
    }

    /// Takes custody of one object's retained pin (a shared clone of the
    /// attach set's opened file: no reopen, no new descriptor).
    pub(super) fn retain_object(&mut self, object: PinnedObjectId, pin: RetainedInventoryTarget) {
        self.pins.entry(object).or_insert(pin);
    }

    /// Records one attempted endpoint at its sorted position (the bounded
    /// per-ID pin lookups binary-search this table). IDs may arrive in any
    /// order — a deferred backlog after a newer delta — but never twice.
    pub(super) fn record_entry(&mut self, entry: InventoryEndpoint) -> Result<()> {
        let at = self
            .entries
            .partition_point(|recorded| recorded.id < entry.id);
        ensure!(
            self.entries
                .get(at)
                .is_none_or(|recorded| recorded.id != entry.id),
            "Inventory endpoint {} is already recorded",
            entry.id
        );
        self.allocated.push(entry.id);
        self.entries.insert(at, entry);
        Ok(())
    }

    /// The recorded entry IDs, in table order.
    #[cfg(test)]
    pub(super) fn entry_ids(&self) -> Vec<u32> {
        self.entries.iter().map(|entry| entry.id).collect()
    }

    pub(super) fn check_object(&self, object: PinnedObjectId) -> Result<()> {
        self.check_pin(object)
    }

    fn check_unchanged(&self) -> Result<()> {
        for id in self.pins.keys() {
            self.check_pin(*id)?;
        }
        Ok(())
    }

    fn check_pin(&self, id: PinnedObjectId) -> Result<()> {
        let pin = self.pins.get(&id).context("missing Inventory target pin")?;
        if !pin.check_unchanged().map_err(anyhow::Error::msg)? {
            self.changed.set(true);
            bail!("Inventory provider {id:?} changed");
        }
        Ok(())
    }

    fn provider_changed(&self) -> bool {
        self.changed.get()
    }
}

fn validate_activation(
    scope: &Scope,
    backend: AttachBackend,
    budget: InventoryBudget,
    targets: &InventoryTargets,
) -> Result<()> {
    ensure!(
        !matches!(scope, Scope::Pid(_)),
        "Inventory PID activation requires generation-safe I2c scope"
    );
    ensure!(
        backend == AttachBackend::Singles,
        "Inventory I3a activation supports Singles only"
    );
    validate_activation_common(budget, targets)
}

/// The capture facade's activation: the one path that admits PID scope
/// and the Multi backend (entries attach as immutable groups).
/// Its entries attach with `UProbeScope::OneProcess` and the retained
/// original pidfd must be live, so a reused PID can never be selected.
pub(super) fn validate_capture_activation(
    scope: &Scope,
    pin: Option<&PidPin>,
    backend: AttachBackend,
    budget: InventoryBudget,
    targets: &InventoryTargets,
) -> Result<()> {
    match scope {
        Scope::Pid(pid) => {
            let pin = pin.context("Inventory PID capture requires retained PID custody")?;
            ensure!(
                pin.pid() == *pid,
                "Inventory PID capture custody names pid {} instead of {pid}",
                pin.pid()
            );
            require_live_pid_custody(pin)?;
        }
        Scope::System | Scope::Cgroup { .. } => {}
    }
    // Both backends: Multi loads the entries for uprobe-multi and attaches
    // them only through `attach_entry_group`.
    let _ = backend;
    validate_activation_common(budget, targets)
}

/// PID custody the capture facade accepts: the original pidfd (never the
/// start-time fallback) whose process has not exited.
pub(super) fn require_live_pid_custody(pin: &PidPin) -> Result<()> {
    pin.pidfd()
        .context("Inventory PID capture requires the original pidfd, not a start-time pin")?;
    ensure!(
        !pin.original_exited().map_err(anyhow::Error::msg)?,
        "Inventory PID capture target {} exited; its PID may already name another process",
        pin.pid()
    );
    Ok(())
}

fn validate_activation_common(budget: InventoryBudget, targets: &InventoryTargets) -> Result<()> {
    ensure!(
        budget == targets.budget,
        "Inventory plan and prepared object budget differ"
    );
    targets.check_unchanged()
}

pub(super) enum InventoryAttachRequest<'a> {
    Lifecycle {
        program: &'static str,
        tracepoint: &'static str,
    },
    Entry {
        program: &'static str,
        path: &'a Path,
        file_offset: u64,
        cookie: u64,
    },
    /// Keymeta Task 7 (spec §17.4): one info return (uretprobe) at
    /// an info endpoint's site, attempted after its entry links.
    Return {
        program: &'static str,
        path: &'a Path,
        file_offset: u64,
        cookie: u64,
    },
}

/// One attach group's request: every site of one (object, entry program)
/// selection of one extend, as `(file offset, cookie)` pairs. The kernel
/// link is an immutable offset set: it is created once and closed whole.
pub(super) struct InventoryGroupRequest<'a> {
    pub(super) program: &'static str,
    pub(super) path: &'a Path,
    pub(super) sites: &'a [(u64, u64)],
}

/// What one group attach produced: the live links (one per bisect leaf;
/// one in the ordinary case) and the sites the kernel refused, by index
/// into the request's `sites`, each with its own error.
pub(super) struct InventoryGroupAttach<L> {
    pub(super) links: Vec<L>,
    pub(super) refused: Vec<(usize, std::io::Error)>,
}

pub(super) trait InventoryLinkIo {
    type Link;
    fn publish_endpoint(&mut self, endpoint: u32, object: PinnedObjectId) -> Result<()>;
    fn attach(&mut self, request: InventoryAttachRequest<'_>) -> Result<Self::Link>;
    fn detach(&mut self, link: &mut Self::Link) -> Result<()>;
    fn attachment_error(&self, _link: &Self::Link) -> Option<String> {
        None
    }
    /// One uprobe-multi group (Multi backend only). `Unsupported` and
    /// `Exhausted` halt the group: no link reaches custody, and the leaf
    /// links a bisect had already created are closed and counted
    /// (`closed_leaves`). Every other refusal is isolated per site. An IO
    /// without multi support refuses.
    fn attach_entry_group(
        &mut self,
        _request: InventoryGroupRequest<'_>,
    ) -> std::result::Result<InventoryGroupAttach<Self::Link>, p11scope_bpf_multi::BisectHalt> {
        Err(p11scope_bpf_multi::BisectHalt {
            halt: p11scope_bpf_multi::GroupHalt::Unsupported(std::io::Error::from_raw_os_error(
                libc::EOPNOTSUPP,
            )),
            closed_leaves: 0,
        })
    }
    /// Keymeta Task 7 (spec §17.4): one uretprobe-multi group per
    /// (object, info return program), mirroring `attach_entry_group`.
    /// An IO without multi support refuses.
    fn attach_return_group(
        &mut self,
        _request: InventoryGroupRequest<'_>,
    ) -> std::result::Result<InventoryGroupAttach<Self::Link>, p11scope_bpf_multi::BisectHalt> {
        Err(p11scope_bpf_multi::BisectHalt {
            halt: p11scope_bpf_multi::GroupHalt::Unsupported(std::io::Error::from_raw_os_error(
                libc::EOPNOTSUPP,
            )),
            closed_leaves: 0,
        })
    }
    /// Keymeta Task 7 (spec §17.4, fix9 R1): publish one endpoint's
    /// info kind after its return link exists (write-once,
    /// read-back, refused re-publication).
    fn publish_info_kind(&mut self, _endpoint: u32, _kind: u8) -> Result<()> {
        bail!("info kind publication needs an INFO_KIND map")
    }

    /// Keymeta Task 7 (spec §17.4, INV-2): revoke one endpoint's
    /// info kind after a later pass proved its names aliased (read,
    /// zero-write, read-back, idempotent), resuming at `resume`
    /// after an earlier yield and starting no map operation at or
    /// past `deadline`.
    fn revoke_info_kind(
        &mut self,
        _endpoint: u32,
        _resume: super::RevokeSubstep,
        _deadline: Instant,
        _now: &mut dyn FnMut() -> Instant,
    ) -> Result<super::RevokeStepOutcome> {
        bail!("info kind revocation needs an INFO_KIND map")
    }
}

#[derive(Debug, Default)]
pub(super) struct InventoryCleanupReceipt {
    pub(super) attempted: usize,
    pub(super) closed: usize,
    pub(super) failures: Vec<InventoryDetachFailure>,
    callback_quiescence_proven: bool,
    /// Keymeta Task 7 (spec §17.4): the INFO_START scrub did not
    /// prove an empty stash (retained links refused it). Explicitly
    /// unproven, never silently dirty.
    pub(super) info_teardown_unproven: bool,
    /// Keymeta Task 7 (spec §17.4): the scrub phase's last concrete
    /// failure, if it transferred unproven.
    pub(super) info_scrub_error: Option<String>,
}

#[derive(Debug)]
pub(super) struct InventoryDetachFailure {
    pub(super) target: InventoryLinkIdentity,
    pub(super) error: anyhow::Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InventoryLinkIdentity {
    Lifecycle(&'static str),
    Entry(u32),
    /// One link of the capture's attach group with this serial (Multi).
    EntryGroup(u32),
    /// Keymeta Task 7 (spec §17.4): one info return link (Singles).
    Return(u32),
    /// Keymeta Task 7 (spec §17.4): one info return-group link with
    /// this serial (Multi).
    ReturnGroup(u32),
}

pub(super) struct InventoryLinked<L> {
    pub(super) target: InventoryLinkIdentity,
    pub(super) handle: L,
}

struct InventoryAttachFailure<L> {
    error: anyhow::Error,
    cleanup: InventoryCleanupReceipt,
    links: Vec<InventoryLinked<L>>,
}

impl<L> fmt::Display for InventoryAttachFailure<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#}", self.error)
    }
}

fn attach_inventory_with<I: InventoryLinkIo>(
    io: &mut I,
    targets: &InventoryTargets,
) -> std::result::Result<Vec<InventoryLinked<I::Link>>, InventoryAttachFailure<I::Link>> {
    let mut links = Vec::with_capacity(targets.entries.len() + 2);
    let result = (|| -> Result<()> {
        targets.check_unchanged()?;
        // Validate every immutable target before the first lifecycle link too.
        for entry in &targets.entries {
            validate_entry(targets, entry)?;
        }
        for entry in &targets.entries {
            io.publish_endpoint(entry.id, entry.object)
                .with_context(|| format!("publishing Inventory endpoint {}", entry.id))?;
        }
        attach_roots_with(io, &mut links)?;
        for entry in &targets.entries {
            attach_published_entry_with(io, targets, entry, &mut links)?;
        }
        targets.check_unchanged()
    })();
    match result {
        Ok(()) => Ok(links),
        // Acquired resources travel with the original error. Hidden synchronous
        // rollback would starve the same discovery reader as terminal stop.
        Err(error) => Err(InventoryAttachFailure {
            error,
            cleanup: InventoryCleanupReceipt::default(),
            links,
        }),
    }
}

/// One entry's immutable checks: a retained pin, the pin's ABI, and an ID
/// below the prepared object's endpoint capacity N.
pub(super) fn validate_entry(targets: &InventoryTargets, entry: &InventoryEndpoint) -> Result<()> {
    let pin = targets
        .pins
        .get(&entry.object)
        .context("missing Inventory target pin")?;
    ensure!(
        entry.abi == pin.abi(),
        "Inventory target ABI differs from retained pin"
    );
    ensure!(
        u64::from(entry.id) < targets.budget.endpoint_limit(),
        "Inventory endpoint ID exceeds N"
    );
    Ok(())
}

/// The two lifecycle roots, attached once per object. Each link enters
/// custody before its post-acquisition check can fail.
pub(super) fn attach_roots_with<I: InventoryLinkIo>(
    io: &mut I,
    links: &mut Vec<InventoryLinked<I::Link>>,
) -> Result<()> {
    for program in ["sched_process_exec", "sched_process_exit"] {
        let handle = io
            .attach(InventoryAttachRequest::Lifecycle {
                program,
                tracepoint: program,
            })
            .with_context(|| format!("attaching Inventory lifecycle {program}"))?;
        links.push(InventoryLinked {
            target: InventoryLinkIdentity::Lifecycle(program),
            handle,
        });
        if let Some(error) = io.attachment_error(&links.last().unwrap().handle) {
            bail!(error);
        }
    }
    Ok(())
}

/// Attaches one entry whose ENDPOINT_OBJECT binding is already published:
/// pin unchanged before, the link registered immediately, then the
/// post-acquisition custody check and the pin unchanged after. A failure
/// leaves any acquired link in `links`.
pub(super) fn attach_published_entry_with<I: InventoryLinkIo>(
    io: &mut I,
    targets: &InventoryTargets,
    entry: &InventoryEndpoint,
    links: &mut Vec<InventoryLinked<I::Link>>,
) -> Result<()> {
    let pin = targets
        .pins
        .get(&entry.object)
        .context("missing Inventory target pin")?;
    targets
        .check_pin(entry.object)
        .with_context(|| format!("before Inventory entry {}", entry.id))?;
    // Keymeta Task 7 (spec §17.4): info endpoints link the
    // inventory info entry pair; every other endpoint keeps its
    // usage entry.
    let program = match (entry.abi, entry.info_kind) {
        (ElfAbi::Lp64, Some(_)) => "p11_info_entry_lp64",
        (ElfAbi::Ilp32, Some(_)) => "p11_info_entry_ia32",
        (ElfAbi::Lp64, None) => "p11_usage_entry_lp64",
        (ElfAbi::Ilp32, None) => "p11_usage_entry_ia32",
    };
    let path = pin.attach_path();
    let cookie =
        (u64::from(p11scope_ebpf_common::INVENTORY_COOKIE_TAG) << 32) | u64::from(entry.id);
    let handle = io
        .attach(InventoryAttachRequest::Entry {
            program,
            path: &path,
            file_offset: entry.file_offset,
            cookie,
        })
        .with_context(|| format!("attaching Inventory entry {}", entry.id))?;
    // Register immediately, before any post-attach check can fail.
    links.push(InventoryLinked {
        target: InventoryLinkIdentity::Entry(entry.id),
        handle,
    });
    if let Some(error) = io.attachment_error(&links.last().unwrap().handle) {
        bail!(error);
    }
    targets
        .check_pin(entry.object)
        .with_context(|| format!("during Inventory entry {} attachment", entry.id))
}

/// Keymeta Task 7 (spec §17.4): attaches one info return whose entry
/// already linked: pin unchanged before, the link registered
/// immediately, then the post-acquisition custody check and the pin
/// unchanged after. A failure leaves any acquired link in `links`.
/// Callers handle EMFILE (defer + named gap, the endpoint still
/// attaches) apart from deterministic refusals (fail disclosed).
pub(super) fn attach_published_return_with<I: InventoryLinkIo>(
    io: &mut I,
    targets: &InventoryTargets,
    entry: &InventoryEndpoint,
    links: &mut Vec<InventoryLinked<I::Link>>,
) -> Result<()> {
    let pin = targets
        .pins
        .get(&entry.object)
        .context("missing Inventory target pin")?;
    targets
        .check_pin(entry.object)
        .with_context(|| format!("before Inventory return {}", entry.id))?;
    let path = pin.attach_path();
    let cookie =
        (u64::from(p11scope_ebpf_common::INVENTORY_COOKIE_TAG) << 32) | u64::from(entry.id);
    let handle = io
        .attach(InventoryAttachRequest::Return {
            program: "p11_info_return",
            path: &path,
            file_offset: entry.file_offset,
            cookie,
        })
        .with_context(|| format!("attaching Inventory return {}", entry.id))?;
    // Register immediately, before any post-attach check can fail.
    links.push(InventoryLinked {
        target: InventoryLinkIdentity::Return(entry.id),
        handle,
    });
    if let Some(error) = io.attachment_error(&links.last().unwrap().handle) {
        bail!(error);
    }
    targets
        .check_pin(entry.object)
        .with_context(|| format!("during Inventory return {} attachment", entry.id))
}

fn stop_inventory_links_with<I: InventoryLinkIo>(
    io: &mut I,
    links: &mut Vec<InventoryLinked<I::Link>>,
) -> InventoryCleanupReceipt {
    let mut receipt = InventoryCleanupReceipt::default();
    let mut uncertain = vec![];
    // The private transaction inserts lifecycle roots first and all ordinary
    // entries afterward. Reverse retirement therefore preserves both roots
    // until every entry has received an attempt, including after failures.
    while let Some(mut link) = links.pop() {
        receipt.attempted += 1;
        match io.detach(&mut link.handle) {
            Ok(()) => receipt.closed += 1,
            Err(error) => {
                receipt.failures.push(InventoryDetachFailure {
                    target: link.target,
                    error,
                });
                uncertain.push(link);
            }
        }
    }
    uncertain.reverse();
    *links = uncertain;
    // FD closure is not an Inventory callback-quiescence protocol.
    receipt
}

/// Rows cleared per INFO_START scrub step (spec §17.4): each
/// retirement poll does at most this many zero-verify-remove rows,
/// then yields. The poll loop owns the stop deadline; steps resume
/// from carried progress.
#[cfg(not(feature = "stub-object-attributes"))]
const INFO_SCRUB_BATCH: usize = 64;

/// Native map operations per INFO_START scrub poll (spec §17.4,
/// INV-2): one map-shape validation plus the 64-row table batch —
/// one enumeration plus zero, read-back and remove per row
/// (1 + 64×4). A full batch spends the allowance and defers its
/// terminal emptiness observation to the next poll. No native call
/// starts once the allowance is spent or the stop deadline passes.
#[cfg(not(feature = "stub-object-attributes"))]
const INFO_SCRUB_OPS_PER_POLL: u64 = 257;

/// One retirement poll's native-operation allowance for the
/// INFO_START scrub (spec §17.4, INV-2): at most
/// `INFO_SCRUB_OPS_PER_POLL` map operations, and none at or past
/// the stop `deadline`. The clock injects so tests script expiry
/// without racing the wall clock.
#[cfg(not(feature = "stub-object-attributes"))]
struct ScrubBudget<F: FnMut() -> Instant> {
    ops_remaining: u64,
    deadline: Instant,
    now: F,
}

#[cfg(not(feature = "stub-object-attributes"))]
impl<F: FnMut() -> Instant> ScrubBudget<F> {
    fn per_poll(deadline: Instant, now: F) -> Self {
        Self {
            ops_remaining: INFO_SCRUB_OPS_PER_POLL,
            deadline,
            now,
        }
    }

    fn expired(&mut self) -> bool {
        (self.now)() >= self.deadline
    }
}

/// One INFO_START row source for the stop scrub (spec §17.4). The
/// real impl drives the kernel map; tests drive an in-memory fake.
/// The row lifecycle splits into its three native substeps so a
/// step that yields mid-row resumes at the pending substep instead
/// of redoing finished work.
#[cfg(not(feature = "stub-object-attributes"))]
trait InfoScrubTable {
    /// The map's capacity: clearing this many rows without emptying
    /// saturates (concurrent inserts or an unremovable row).
    fn capacity(&self) -> u32;
    /// Any remaining row's key, or `None` when empty.
    fn first_key(&mut self) -> Result<Option<[u8; 16]>>;
    /// Zero one row's value (BPF_EXIST forbids manufacturing an
    /// owner: a failed delete leaves no private pointer bytes).
    fn zero_row(&mut self, key: &[u8; 16]) -> Result<(), ScrubRowError>;
    /// Verify one row reads back zero.
    fn verify_row_zero(&mut self, key: &[u8; 16]) -> Result<(), ScrubRowError>;
    /// Remove one zeroed row.
    fn remove_row(&mut self, key: &[u8; 16]) -> Result<(), ScrubRowError>;
}

/// What one scrub row operation found: the row gone (an in-flight
/// return removed it between polls — the stale cursor clears and
/// the step re-enumerates) or a concrete failure (retryable and
/// reportable, the cursor kept).
#[cfg(not(feature = "stub-object-attributes"))]
#[derive(Debug)]
enum ScrubRowError {
    Missing,
    Failed(anyhow::Error),
}

/// A scrub row interrupted between native substeps: its key plus
/// the next substep to run. Carried in the scrub phase across
/// polls, so a resume never redoes finished work.
#[cfg(not(feature = "stub-object-attributes"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingScrubRow {
    key: [u8; 16],
    next: ScrubSubstep,
}

/// The next native substep for a [`PendingScrubRow`].
#[cfg(not(feature = "stub-object-attributes"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScrubSubstep {
    Zero,
    Verify,
    Remove,
}

/// What one bounded scrub step found.
#[cfg(not(feature = "stub-object-attributes"))]
#[derive(Debug, PartialEq, Eq)]
enum InfoScrubOutcome {
    /// The table observed empty: teardown proven for the rows.
    Complete,
    /// The batch spent with rows remaining: re-poll and resume.
    Pending,
    /// A full capacity cleared without emptying: concurrent inserts
    /// or an unremovable row. The caller resets progress and retries,
    /// bounded by the poll loop's stop budget.
    Saturated,
}

/// One bounded INFO_START scrub step (spec §17.4, INV-2):
/// zero-verify-remove up to `INFO_SCRUB_BATCH` rows, carrying the
/// cleared count in `progress` and the interrupted row in `pending`,
/// and charging every native call to the poll's `budget`. No native
/// call starts without allowance left or at or past the stop
/// deadline — an expired budget yields `Pending` with zero
/// operations, and a short allowance yields mid-row with the
/// pending key and substep kept, so the resume never redoes
/// finished work. Observes emptiness after a full batch before
/// yielding, so a complete table reports `Complete` without a
/// spurious extra poll.
#[cfg(not(feature = "stub-object-attributes"))]
fn scrub_info_start_step<F: FnMut() -> Instant>(
    table: &mut impl InfoScrubTable,
    progress: &mut u64,
    pending: &mut Option<PendingScrubRow>,
    budget: &mut ScrubBudget<F>,
) -> Result<InfoScrubOutcome> {
    if budget.expired() {
        return Ok(InfoScrubOutcome::Pending);
    }
    // Finish a row the last step interrupted, one charged substep
    // at a time. Concrete failures return with the pending row
    // untouched, so the retry resumes at the failed substep; a
    // disappeared row clears the stale cursor and counts resolved,
    // and the step re-enumerates. A resumed removal consumes its row
    // slot in this step's batch.
    let mut rows_this_step = 0usize;
    while let Some(PendingScrubRow { key, next }) = *pending {
        if budget.ops_remaining == 0 || budget.expired() {
            return Ok(InfoScrubOutcome::Pending);
        }
        let outcome = match next {
            ScrubSubstep::Zero => table.zero_row(&key),
            ScrubSubstep::Verify => table.verify_row_zero(&key),
            ScrubSubstep::Remove => table.remove_row(&key),
        };
        match outcome {
            Err(ScrubRowError::Missing) => {
                budget.ops_remaining -= 1;
                *pending = None;
                *progress = progress.saturating_add(1);
                rows_this_step += 1;
            }
            Err(ScrubRowError::Failed(error)) => return Err(error),
            Ok(()) => {
                budget.ops_remaining -= 1;
                match next {
                    ScrubSubstep::Zero => {
                        *pending = Some(PendingScrubRow {
                            key,
                            next: ScrubSubstep::Verify,
                        });
                    }
                    ScrubSubstep::Verify => {
                        *pending = Some(PendingScrubRow {
                            key,
                            next: ScrubSubstep::Remove,
                        });
                    }
                    ScrubSubstep::Remove => {
                        *pending = None;
                        *progress = progress.saturating_add(1);
                        rows_this_step += 1;
                    }
                }
            }
        }
    }
    'rows: for _ in rows_this_step..INFO_SCRUB_BATCH {
        if budget.ops_remaining == 0 || budget.expired() {
            return Ok(InfoScrubOutcome::Pending);
        }
        let Some(key) = table
            .first_key()
            .context("enumerating stopped INFO_START")?
        else {
            return Ok(InfoScrubOutcome::Complete);
        };
        budget.ops_remaining -= 1;
        if *progress >= u64::from(table.capacity()) {
            return Ok(InfoScrubOutcome::Saturated);
        }
        // The pending row records each substep before it runs: a
        // yield or an error resumes (or retries) exactly there. A
        // row disappearing mid-step resolves like a cleared row and
        // the step takes a fresh enumeration.
        for next in [
            ScrubSubstep::Zero,
            ScrubSubstep::Verify,
            ScrubSubstep::Remove,
        ] {
            if budget.ops_remaining == 0 || budget.expired() {
                *pending = Some(PendingScrubRow { key, next });
                return Ok(InfoScrubOutcome::Pending);
            }
            *pending = Some(PendingScrubRow { key, next });
            let outcome = match next {
                ScrubSubstep::Zero => table.zero_row(&key),
                ScrubSubstep::Verify => table.verify_row_zero(&key),
                ScrubSubstep::Remove => table.remove_row(&key),
            };
            match outcome {
                Err(ScrubRowError::Missing) => {
                    budget.ops_remaining -= 1;
                    *pending = None;
                    *progress = progress.saturating_add(1);
                    continue 'rows;
                }
                Err(ScrubRowError::Failed(error)) => return Err(error),
                Ok(()) => {
                    budget.ops_remaining -= 1;
                }
            }
        }
        *pending = None;
        *progress = progress.saturating_add(1);
    }
    if budget.ops_remaining == 0 || budget.expired() {
        return Ok(InfoScrubOutcome::Pending);
    }
    budget.ops_remaining -= 1;
    match table.first_key().context("checking stopped INFO_START")? {
        None => Ok(InfoScrubOutcome::Complete),
        Some(_) => Ok(InfoScrubOutcome::Pending),
    }
}

/// The real scrub table: the kernel INFO_START map, validated like
/// every other inventory map (exact type, key/value sizes and the
/// map's own capacity).
#[cfg(not(feature = "stub-object-attributes"))]
struct KernelScrubTable<'m> {
    table: aya::maps::HashMap<&'m mut aya::maps::MapData, [u8; 16], [u8; 32]>,
    capacity: u32,
}

/// True when a kernel map error means the row is gone: a lookup
/// miss, or an update/delete refused with ENOENT (BPF_EXIST never
/// manufactures the row, deletes never resurrect it).
#[cfg(not(feature = "stub-object-attributes"))]
fn scrub_row_is_missing(error: &aya::maps::MapError) -> bool {
    matches!(error, aya::maps::MapError::KeyNotFound)
        || matches!(
            error,
            aya::maps::MapError::SyscallError(error)
                if error.io_error.raw_os_error() == Some(libc::ENOENT)
        )
}

#[cfg(not(feature = "stub-object-attributes"))]
impl InfoScrubTable for KernelScrubTable<'_> {
    fn capacity(&self) -> u32 {
        self.capacity
    }

    fn first_key(&mut self) -> Result<Option<[u8; 16]>> {
        Ok(self.table.keys().next().transpose()?)
    }

    fn zero_row(&mut self, key: &[u8; 16]) -> Result<(), ScrubRowError> {
        self.table.insert(*key, [0; 32], 2).map_err(|error| {
            if scrub_row_is_missing(&error) {
                ScrubRowError::Missing
            } else {
                ScrubRowError::Failed(
                    anyhow::Error::from(error).context("zeroing stopped INFO_START"),
                )
            }
        })
    }

    fn verify_row_zero(&mut self, key: &[u8; 16]) -> Result<(), ScrubRowError> {
        let value = self.table.get(key, 0).map_err(|error| {
            if scrub_row_is_missing(&error) {
                ScrubRowError::Missing
            } else {
                ScrubRowError::Failed(
                    anyhow::Error::from(error).context("reading stopped INFO_START zero"),
                )
            }
        })?;
        if value != [0; 32] {
            return Err(ScrubRowError::Failed(anyhow::anyhow!(
                "stopped INFO_START zero readback differs"
            )));
        }
        Ok(())
    }

    fn remove_row(&mut self, key: &[u8; 16]) -> Result<(), ScrubRowError> {
        self.table.remove(key).map_err(|error| {
            if scrub_row_is_missing(&error) {
                ScrubRowError::Missing
            } else {
                ScrubRowError::Failed(
                    anyhow::Error::from(error).context("removing stopped INFO_START"),
                )
            }
        })
    }
}

/// Fetch and validate the INFO_START shape once per scrub poll
/// (spec §17.4, INV-2): the map's own capacity plus the exact
/// type/key/value/flags contract. The fetch is injectable so the
/// allowance twin drives production validation without a kernel
/// map. The single metadata read charges one operation to the same
/// poll allowance as the table calls, with the deadline checked at
/// that call. `None`: no allowance was left or the budget expired
/// before the fetch, so the poll runs zero native calls.
#[cfg(not(feature = "stub-object-attributes"))]
fn scrub_table_capacity_with<F: FnMut() -> Instant>(
    fetch: &mut dyn FnMut() -> Result<crate::attach::ExactMapMetadata>,
    budget: &mut ScrubBudget<F>,
) -> Result<Option<u32>> {
    use super::map_metadata;
    use crate::attach::compare_map_metadata;
    use aya::maps::MapType;
    if budget.ops_remaining == 0 || budget.expired() {
        return Ok(None);
    }
    let meta = fetch()?;
    budget.ops_remaining -= 1;
    compare_map_metadata(
        "INFO_START",
        meta,
        map_metadata(MapType::Hash, 16, 32, meta.max_entries, 0),
    )?;
    Ok(Some(meta.max_entries))
}

/// Validate the kernel INFO_START map and run one bounded scrub
/// step against it. An expired budget yields before the map
/// validation, so an expired poll runs zero native calls.
#[cfg(not(feature = "stub-object-attributes"))]
fn scrub_info_start_step_on<F: FnMut() -> Instant>(
    ebpf: &mut Ebpf,
    progress: &mut u64,
    pending: &mut Option<PendingScrubRow>,
    budget: &mut ScrubBudget<F>,
) -> Result<InfoScrubOutcome> {
    use super::read_map_metadata;
    use aya::maps::{HashMap, Map};
    let Some(max_entries) = scrub_table_capacity_with(
        &mut || {
            let map = ebpf
                .map_mut("INFO_START")
                .context("INFO_START map for info scrub")?;
            match &*map {
                Map::HashMap(data) => read_map_metadata("INFO_START", data),
                _ => anyhow::bail!("unexpected INFO_START map variant for info scrub"),
            }
        },
        budget,
    )?
    else {
        return Ok(InfoScrubOutcome::Pending);
    };
    let map = ebpf
        .map_mut("INFO_START")
        .context("INFO_START map for info scrub")?;
    let mut table = KernelScrubTable {
        table: HashMap::try_from(map)?,
        capacity: max_entries,
    };
    scrub_info_start_step(&mut table, progress, pending, budget)
}

/// Bounded INFO_START scrub phase (spec §17.4): explicit retirement
/// work with progress and concrete failures. Refuses while links are
/// retained (probes still mutating); otherwise runs one bounded step
/// per poll.
#[cfg(not(feature = "stub-object-attributes"))]
#[derive(Debug, Default)]
struct InfoScrubPhase {
    cleared: u64,
    pending: Option<PendingScrubRow>,
    error: Option<String>,
}

/// What the scrub phase tells try_finish after one poll.
#[cfg(not(feature = "stub-object-attributes"))]
#[derive(Debug, PartialEq, Eq)]
enum InfoScrubDirective {
    /// Transfer the state: teardown proven (`unproven` false) or
    /// explicitly unproven (retained links refused the scrub).
    Transfer { unproven: bool },
    /// Scrub more on the next poll.
    Retry,
}

#[cfg(not(feature = "stub-object-attributes"))]
impl InfoScrubPhase {
    /// One poll: refuse when links are retained (transfer with
    /// teardown explicitly unproven), else run one bounded step. A
    /// complete table transfers clean (clearing transient errors);
    /// pending work and concrete failures retry with progress and
    /// the failure carried; saturation resets progress and retries,
    /// bounded by the poll loop's stop budget.
    fn poll(
        &mut self,
        retained_links: bool,
        step: impl FnOnce(&mut u64, &mut Option<PendingScrubRow>) -> Result<InfoScrubOutcome, String>,
    ) -> InfoScrubDirective {
        if retained_links {
            self.error = Some("scrub refused: links retained".into());
            return InfoScrubDirective::Transfer { unproven: true };
        }
        match step(&mut self.cleared, &mut self.pending) {
            Ok(InfoScrubOutcome::Complete) => {
                self.error = None;
                InfoScrubDirective::Transfer { unproven: false }
            }
            Ok(InfoScrubOutcome::Pending) => InfoScrubDirective::Retry,
            Ok(InfoScrubOutcome::Saturated) => {
                self.cleared = 0;
                InfoScrubDirective::Retry
            }
            Err(error) => {
                self.error = Some(error);
                InfoScrubDirective::Retry
            }
        }
    }

    /// The teardown outcome for the operator right now: a carried
    /// concrete failure (even while retries continue), else the
    /// running progress.
    fn status(&self) -> InfoTeardown {
        match &self.error {
            Some(error) => InfoTeardown::Failed {
                error: error.clone(),
            },
            None => InfoTeardown::Pending {
                cleared: self.cleared,
            },
        }
    }
}

/// The INFO stash teardown outcome for the operator (spec §17.4):
/// proven (P0 carries no map; FULL proved an empty stash), still
/// running with progress, or failing with its concrete carried
/// error. A transferred-but-unproven teardown (retained links
/// refused the scrub) rides the typed [`InventoryCleanupReceipt`]
/// fields instead — the stop line reads both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InfoTeardown {
    Proven,
    Pending { cleared: u64 },
    Failed { error: String },
}

pub(super) struct InventoryReadWindow {
    max_cells: usize,
    deadline: Instant,
}

impl InventoryReadWindow {
    pub(super) fn new(max_cells: usize, deadline: Instant) -> Result<Self> {
        if max_cells == 0 {
            bail!("Inventory read window must permit a positive number of cells");
        }
        Ok(Self {
            max_cells,
            deadline,
        })
    }
}

struct InventoryUsageHistory {
    allocated: Vec<u32>,
    cursor: usize,
    positive: BTreeSet<u32>,
    integrity_failures: u64,
    read_failures: u64,
}

impl InventoryUsageHistory {
    fn new(allocated: Vec<u32>) -> Self {
        Self {
            allocated,
            cursor: 0,
            positive: BTreeSet::new(),
            integrity_failures: 0,
            read_failures: 0,
        }
    }

    fn is_positive(&self, id: u32) -> bool {
        self.positive.contains(&id)
    }

    fn read_with(
        &mut self,
        window: InventoryReadWindow,
        mut read: impl FnMut(u32) -> Result<u64>,
    ) -> InventoryUsageRead {
        let mut snapshot = InventoryUsageRead::default();
        for _ in 0..window.max_cells.min(self.allocated.len()) {
            if Instant::now() >= window.deadline {
                snapshot.deadline_reached = true;
                break;
            }
            let id = self.allocated[self.cursor];
            self.cursor = (self.cursor + 1) % self.allocated.len();
            snapshot.cells_read += 1;
            match read(id) {
                Ok(0) => {}
                Ok(1) => {
                    if self.positive.insert(id) {
                        snapshot.newly_positive.push(id);
                    }
                }
                Ok(_) => {
                    snapshot.integrity_failures.push(id);
                    self.integrity_failures = self.integrity_failures.saturating_add(1);
                }
                Err(error) => {
                    snapshot
                        .read_failures
                        .push(format!("Inventory USAGE[{id}]: {error:#}"));
                    self.read_failures = self.read_failures.saturating_add(1);
                }
            }
        }
        snapshot.positive_count = self.positive.len();
        snapshot
    }
}

#[derive(Debug, Default)]
struct InventoryUsageRead {
    newly_positive: Vec<u32>,
    cells_read: usize,
    positive_count: usize,
    integrity_failures: Vec<u32>,
    read_failures: Vec<String>,
    deadline_reached: bool,
}

/// One owned kernel link descriptor: an Aya fd link (a Singles entry or a
/// lifecycle root) or a raw uprobe-multi link (one attach group's leaf).
/// Closing either is dropping it.
pub(super) enum InventoryFd {
    Aya(FdLink),
    Multi(OwnedFd),
}

impl InventoryFd {
    /// The Aya link, for link-info inspection (Singles and roots).
    pub(super) fn as_aya(&self) -> Option<&FdLink> {
        match self {
            InventoryFd::Aya(link) => Some(link),
            InventoryFd::Multi(_) => None,
        }
    }
}

/// Ordinary cookies require Aya's fd-backed perf link path. Keep an unexpected
/// representation or registry-transfer error owned and explicitly quarantined.
pub(super) enum KernelInventoryLink {
    Fds(Vec<InventoryFd>),
    UnexpectedUProbe(UProbeLink),
    RegistryUncertain {
        program: &'static str,
        error: String,
    },
}

pub(super) struct AyaInventoryLinkIo<'a> {
    ebpf: &'a mut Ebpf,
    caller: bool,
    /// `OneProcess` only for the capture facade's PID scope; every other
    /// path is process-wide with BPF scoping.
    entry_scope: UProbeScope,
    #[cfg(test)]
    before_attach: Option<&'a mut BeforeAttach<'a>>,
}

#[cfg(test)]
type BeforeAttach<'a> = dyn FnMut(&InventoryAttachRequest<'_>) -> Result<()> + 'a;

impl AyaInventoryLinkIo<'_> {
    /// One entry or info-return uprobe at a site (the program's ELF
    /// section decides entry vs return): attach, transfer link
    /// custody, and quarantine anything unexpected.
    fn attach_uprobe(
        ebpf: &mut Ebpf,
        program: &'static str,
        path: &Path,
        file_offset: u64,
        cookie: u64,
        entry_scope: UProbeScope,
    ) -> Result<KernelInventoryLink> {
        let probe: &mut UProbe = ebpf.program_mut(program).context(program)?.try_into()?;
        let point = UProbeAttachPoint {
            location: UProbeAttachLocation::AbsoluteOffset(file_offset),
            cookie: Some(cookie),
        };
        let id = probe.attach([point], path, entry_scope)?;
        Ok(match probe.take_link(id) {
            Ok(link) => match link.into_fd_links() {
                Ok(links) => {
                    KernelInventoryLink::Fds(links.into_iter().map(InventoryFd::Aya).collect())
                }
                Err(link) => KernelInventoryLink::UnexpectedUProbe(link),
            },
            Err(error) => KernelInventoryLink::RegistryUncertain {
                program,
                error: error.to_string(),
            },
        })
    }
}

impl InventoryLinkIo for AyaInventoryLinkIo<'_> {
    type Link = KernelInventoryLink;

    fn publish_endpoint(&mut self, endpoint: u32, object: PinnedObjectId) -> Result<()> {
        if self.caller {
            callers::publish_caller_endpoint_with(self.ebpf, endpoint, object)
        } else {
            Ok(())
        }
    }

    fn attach(&mut self, request: InventoryAttachRequest<'_>) -> Result<Self::Link> {
        #[cfg(test)]
        if let Some(hook) = self.before_attach.as_mut() {
            hook(&request)?;
        }
        match request {
            InventoryAttachRequest::Lifecycle {
                program,
                tracepoint,
            } => {
                let probe: &mut RawTracePoint = self
                    .ebpf
                    .program_mut(program)
                    .context(program)?
                    .try_into()?;
                let id = probe.attach(tracepoint)?;
                Ok(match probe.take_link(id) {
                    Ok(link) => KernelInventoryLink::Fds(vec![InventoryFd::Aya(link.into())]),
                    Err(error) => KernelInventoryLink::RegistryUncertain {
                        program,
                        error: error.to_string(),
                    },
                })
            }
            InventoryAttachRequest::Entry {
                program,
                path,
                file_offset,
                cookie,
            } => Self::attach_uprobe(
                self.ebpf,
                program,
                path,
                file_offset,
                cookie,
                self.entry_scope,
            ),
            // Keymeta Task 7 (spec §17.4): the info return attaches
            // exactly like an entry (the ELF section makes it a
            // uretprobe), at the same site and cookie.
            InventoryAttachRequest::Return {
                program,
                path,
                file_offset,
                cookie,
            } => Self::attach_uprobe(
                self.ebpf,
                program,
                path,
                file_offset,
                cookie,
                self.entry_scope,
            ),
        }
    }

    fn detach(&mut self, link: &mut Self::Link) -> Result<()> {
        match link {
            KernelInventoryLink::Fds(links) => close_inventory_fds(links),
            KernelInventoryLink::UnexpectedUProbe(_) => {
                bail!("unexpected non-FD Inventory link remains quarantined")
            }
            KernelInventoryLink::RegistryUncertain { program, error } => {
                bail!("Inventory {program} link remains owned by its program registry: {error}")
            }
        }
    }

    fn attachment_error(&self, link: &Self::Link) -> Option<String> {
        match link {
            KernelInventoryLink::Fds(links) if links.len() == 1 => None,
            KernelInventoryLink::Fds(links) => Some(format!(
                "Inventory Singles created {} FD links",
                links.len()
            )),
            KernelInventoryLink::UnexpectedUProbe(_) => {
                Some("Inventory cookie attachment returned a non-FD link".into())
            }
            KernelInventoryLink::RegistryUncertain { program, error } => Some(format!(
                "Inventory {program} could not transfer link custody: {error}"
            )),
        }
    }

    fn attach_entry_group(
        &mut self,
        request: InventoryGroupRequest<'_>,
    ) -> std::result::Result<InventoryGroupAttach<Self::Link>, p11scope_bpf_multi::BisectHalt> {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let InventoryGroupRequest {
            program,
            path,
            sites,
        } = request;
        // The program was loaded for uprobe-multi (`load_multi`); a missing
        // or unloaded program refuses every site, never the backend.
        let prog_fd = (|| -> Result<std::os::fd::RawFd> {
            let probe: &mut UProbe = self
                .ebpf
                .program_mut(program)
                .context(program)?
                .try_into()?;
            Ok(probe.fd()?.as_fd().as_raw_fd())
        })();
        let prog_fd = match prog_fd {
            Ok(fd) => fd,
            Err(error) => {
                return Ok(InventoryGroupAttach {
                    links: Vec::new(),
                    refused: (0..sites.len())
                        .map(|index| {
                            (
                                index,
                                std::io::Error::other(format!("Inventory {program}: {error:#}")),
                            )
                        })
                        .collect(),
                });
            }
        };
        // System scope: pid 0, every process. PID scope: the target, so the
        // kernel filter (proven to cover every thread before `prepare`
        // admitted Multi) keeps the breakpoint and the program out of
        // every other process, including one that reuses the PID; the
        // in-BPF PID_FILTER guard in `scope_auth` stays as a second check.
        // One rule with the classic session (`multi_link_pid`).
        let pid = crate::attach::multi_link_pid(self.entry_scope);
        let (links, refused) = p11scope_bpf_multi::bisect_attach_counted(
            &mut |slice| {
                let (offsets, cookies): (Vec<u64>, Vec<u64>) = slice.iter().copied().unzip();
                p11scope_bpf_multi::attach_group(prog_fd, pid, path, &offsets, &cookies, false)
            },
            sites,
        )?;
        Ok(InventoryGroupAttach {
            links: links
                .into_iter()
                .map(|fd| KernelInventoryLink::Fds(vec![InventoryFd::Multi(fd)]))
                .collect(),
            refused: refused
                .into_iter()
                .map(|site| (site.index, site.error))
                .collect(),
        })
    }

    fn attach_return_group(
        &mut self,
        request: InventoryGroupRequest<'_>,
    ) -> std::result::Result<InventoryGroupAttach<Self::Link>, p11scope_bpf_multi::BisectHalt> {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let InventoryGroupRequest {
            program,
            path,
            sites,
        } = request;
        // The return program was loaded plainly; a missing or
        // unloaded program refuses every site, never the backend.
        let prog_fd = (|| -> Result<std::os::fd::RawFd> {
            let probe: &mut UProbe = self
                .ebpf
                .program_mut(program)
                .context(program)?
                .try_into()?;
            Ok(probe.fd()?.as_fd().as_raw_fd())
        })();
        let prog_fd = match prog_fd {
            Ok(fd) => fd,
            Err(error) => {
                return Ok(InventoryGroupAttach {
                    links: Vec::new(),
                    refused: (0..sites.len())
                        .map(|index| {
                            (
                                index,
                                std::io::Error::other(format!("Inventory {program}: {error:#}")),
                            )
                        })
                        .collect(),
                });
            }
        };
        let pid = crate::attach::multi_link_pid(self.entry_scope);
        let (links, refused) = p11scope_bpf_multi::bisect_attach_counted(
            &mut |slice| {
                let (offsets, cookies): (Vec<u64>, Vec<u64>) = slice.iter().copied().unzip();
                p11scope_bpf_multi::attach_group(prog_fd, pid, path, &offsets, &cookies, true)
            },
            sites,
        )?;
        Ok(InventoryGroupAttach {
            links: links
                .into_iter()
                .map(|fd| KernelInventoryLink::Fds(vec![InventoryFd::Multi(fd)]))
                .collect(),
            refused: refused
                .into_iter()
                .map(|site| (site.index, site.error))
                .collect(),
        })
    }

    fn publish_info_kind(&mut self, endpoint: u32, kind: u8) -> Result<()> {
        struct MapIo<'b> {
            ebpf: &'b mut Ebpf,
        }
        impl super::InfoKindIo for MapIo<'_> {
            fn read_kind(&mut self, endpoint: u32) -> Result<u64> {
                let map: Array<_, u64> =
                    Array::try_from(self.ebpf.map("INFO_KIND").context("INFO_KIND map")?)?;
                Ok(map.get(&endpoint, 0)?)
            }
            fn write_kind(&mut self, endpoint: u32, value: u64) -> Result<()> {
                let mut map: Array<_, u64> =
                    Array::try_from(self.ebpf.map_mut("INFO_KIND").context("INFO_KIND map")?)?;
                Ok(map.set(endpoint, value, 0)?)
            }
        }
        super::publish_info_kind_with(&mut MapIo { ebpf: self.ebpf }, endpoint, kind)
    }

    fn revoke_info_kind(
        &mut self,
        endpoint: u32,
        resume: super::RevokeSubstep,
        deadline: Instant,
        now: &mut dyn FnMut() -> Instant,
    ) -> Result<super::RevokeStepOutcome> {
        struct MapIo<'b> {
            ebpf: &'b mut Ebpf,
        }
        impl super::InfoKindIo for MapIo<'_> {
            fn read_kind(&mut self, endpoint: u32) -> Result<u64> {
                let map: Array<_, u64> =
                    Array::try_from(self.ebpf.map("INFO_KIND").context("INFO_KIND map")?)?;
                Ok(map.get(&endpoint, 0)?)
            }
            fn write_kind(&mut self, endpoint: u32, value: u64) -> Result<()> {
                let mut map: Array<_, u64> =
                    Array::try_from(self.ebpf.map_mut("INFO_KIND").context("INFO_KIND map")?)?;
                Ok(map.set(endpoint, value, 0)?)
            }
        }
        super::revoke_info_kind_step(
            &mut MapIo { ebpf: self.ebpf },
            endpoint,
            resume,
            deadline,
            now,
        )
    }
}

fn close_inventory_fds(links: &mut Vec<InventoryFd>) -> Result<()> {
    // Aya FdLink::detach has exactly this close-on-drop behavior. This leaf
    // needs neither Ebpf nor the reader; its blocking work belongs off-main.
    links.clear();
    Ok(())
}

/// Field custody and Drop keep links ahead of programs, maps and exact pins.
pub(super) struct InventoryState {
    links: Vec<InventoryLinked<KernelInventoryLink>>,
    discovery: Option<OwnedDiscoveryDrain>,
    /// Keymeta Task 7 (spec §17.4): the session's retained INFO
    /// consumer (`None` in P0, whose object carries no INFO ring).
    info: Option<OwnedInfoDrain>,
    prepared: PreparedInventory,
    history: InventoryUsageHistory,
    malformed_discovery: u64,
    health_read_failures: u64,
    pin_check_failures: u64,
    targets: InventoryTargets,
    fallback: RetirementFallbackEvidence,
}

impl InventoryState {
    fn take_retirement_work(&mut self) -> RetirementWork<Vec<InventoryFd>> {
        let leases = self
            .targets
            .pins
            .values()
            .map(RetainedInventoryTarget::retirement_lease)
            .collect();
        let mut work = Vec::with_capacity(self.links.len());
        for InventoryLinked { target, handle } in std::mem::take(&mut self.links) {
            match handle {
                KernelInventoryLink::Fds(fds) => work.push(RetirementLink {
                    target,
                    handle: Some(fds),
                    quarantine: None,
                    _leases: std::sync::Arc::default(),
                }),
                handle => {
                    let error = match &handle {
                        KernelInventoryLink::UnexpectedUProbe(_) => {
                            "unexpected non-FD Inventory link remains quarantined".into()
                        }
                        KernelInventoryLink::RegistryUncertain { program, error } => format!(
                            "Inventory {program} link remains owned by its program registry: {error}"
                        ),
                        KernelInventoryLink::Fds(_) => unreachable!(),
                    };
                    work.push(RetirementLink {
                        target,
                        handle: None,
                        quarantine: Some(error),
                        _leases: std::sync::Arc::default(),
                    });
                    // Opaque custody stays with its owning prepared object.
                    self.links.push(InventoryLinked { target, handle });
                }
            }
        }
        RetirementWork::new(work, leases)
    }

    fn collect_retirement_work(
        &mut self,
        mut work: RetirementWork<Vec<InventoryFd>>,
    ) -> InventoryCleanupReceipt {
        let (receipt, links) = work.take_result();
        for link in links {
            if let Some(fds) = link.handle {
                self.links.push(InventoryLinked {
                    target: link.target,
                    handle: KernelInventoryLink::Fds(fds),
                });
            }
        }
        self.links.sort_by_key(|link| match link.target {
            InventoryLinkIdentity::Lifecycle("sched_process_exec") => (0, 0),
            InventoryLinkIdentity::Lifecycle(_) => (0, 1),
            InventoryLinkIdentity::Entry(id) => (1, id),
            InventoryLinkIdentity::EntryGroup(serial) => (2, serial),
            // Keymeta Task 7 (spec §17.4): info returns retire with
            // their entries and entry groups.
            InventoryLinkIdentity::Return(id) => (1, id),
            InventoryLinkIdentity::ReturnGroup(serial) => (2, serial),
        });
        receipt
    }

    fn drain_abandoned_quantum(&mut self) {
        let Some(drain) = self.discovery.as_mut() else {
            return;
        };
        // This is an explicitly abandoned destructor path, never the normal
        // service API. Mark evidence before dequeuing undispatched records.
        self.fallback.begin_abandonment();
        for _ in 0..256 {
            match drain.dequeue() {
                Some(DiscoveryItem::Record(_)) => self.fallback.record_discard(false),
                Some(DiscoveryItem::Malformed) => {
                    self.malformed_discovery = self.malformed_discovery.saturating_add(1);
                    self.fallback.record_discard(true);
                }
                None => return,
            }
        }
    }

    fn reclaim_unstarted_work(&mut self, mut work: RetirementWork<Vec<InventoryFd>>) {
        self.fallback.begin_abandonment();
        // Thread creation/transfer has already failed. Last-resort reclamation
        // can service only between closes; it makes no responsiveness or loss
        // guarantee, and every undispatched record remains explicitly counted.
        work.run(&mut |fds| {
            self.drain_abandoned_quantum();
            close_inventory_fds(fds)
        });
        let _receipt = self.collect_retirement_work(work);
    }

    fn reclaim_job(&mut self, job: RetirementJob<Vec<InventoryFd>>) {
        let evidence = self.fallback.clone();
        let result = abandon_and_reclaim_with(job, &evidence, || {
            self.discovery
                .as_mut()
                .and_then(OwnedDiscoveryDrain::dequeue)
        });
        if let Ok(work) = result {
            let _receipt = self.collect_retirement_work(work);
        }
    }

    fn discovery_dequeue(&mut self) -> Result<Option<DiscoveryRecord>> {
        let drain = self
            .discovery
            .as_mut()
            .context("Inventory discovery reader unavailable")?;
        match drain.dequeue() {
            Some(DiscoveryItem::Record(record)) => Ok(Some(record)),
            Some(DiscoveryItem::Malformed) => {
                self.malformed_discovery = self.malformed_discovery.saturating_add(1);
                bail!("malformed Inventory DISCOVERY record")
            }
            None => Ok(None),
        }
    }

    fn usage_snapshot(
        &mut self,
        window: InventoryReadWindow,
        retired: bool,
    ) -> InventoryUsageSnapshot {
        let health = read_inventory_health_flavor(
            &self.prepared.ebpf,
            window.deadline,
            self.prepared.flavor,
        );
        self.health_read_failures = self
            .health_read_failures
            .saturating_add(health.failures.len() as u64);
        let mut pin_error = None;
        let mut checked_pins = BTreeSet::new();
        let usage = self.history.read_with(window, |id| {
            // Snapshot work is bounded by selected allocated cells, including
            // pin checks. Never walk all providers on each read window.
            if let Ok(index) = self
                .targets
                .entries
                .binary_search_by_key(&id, |entry| entry.id)
            {
                let object = self.targets.entries[index].object;
                if checked_pins.insert(object)
                    && let Err(error) = self.targets.check_pin(object)
                {
                    self.pin_check_failures = self.pin_check_failures.saturating_add(1);
                    pin_error.get_or_insert_with(|| format!("{error:#}"));
                }
            }
            let map: Array<_, u64> =
                Array::try_from(self.prepared.ebpf.map("USAGE").context("USAGE map")?)?;
            Ok(map.get(&id, 0)?)
        });
        InventoryUsageSnapshot {
            usage,
            health,
            pin_error,
            provider_changed: self.targets.provider_changed(),
            malformed_discovery: self.malformed_discovery,
            usage_integrity_failures: self.history.integrity_failures,
            usage_read_failures: self.history.read_failures,
            health_read_failures: self.health_read_failures,
            pin_check_failures: self.pin_check_failures,
            retirement_fallback: self.fallback.snapshot(),
            terminal_unsettled: retired,
        }
    }
}

/// Read-side accessors the capture facade uses. None of them hands out
/// links, programs, or a mutable object.
impl InventoryState {
    /// Concrete identity-only endpoint operation; no mutable object escapes.
    pub(super) fn observe_caller_image(
        &mut self,
        domain: crate::attach::capture::NativeDomainId,
        generation: u64,
        original: &std::sync::Arc<PidPin>,
        window: crate::attach::capture::ReadWindow,
    ) -> Result<crate::attach::capture::CallerImageObservation> {
        crate::attach::selected_detailed::baseline::observe_caller_image(
            &mut self.prepared.ebpf,
            domain,
            generation,
            original,
            window,
        )
    }

    /// Concrete pre-view identity operation; no mutable object escapes.
    #[allow(clippy::too_many_arguments)] // Thin explicit-args forwarder mirroring baseline::query; bundling would churn both ends for no gain.
    pub(super) fn query_promotion_baselines(
        &mut self,
        domain: crate::attach::capture::NativeDomainId,
        generation: u64,
        capture: crate::inventory_promotion::CaptureId,
        presentation: std::sync::Arc<crate::inventory_present::Presentation>,
        targets: &[crate::attach::selected_detailed::baseline::BaselineTarget],
        window: crate::attach::capture::ReadWindow,
        reserve: impl FnOnce(
            usize,
        ) -> std::result::Result<
            crate::semantics_edge::resources::ResourceLease,
            crate::semantics_edge::resources::SemanticResourceRefusal,
        >,
    ) -> Result<crate::attach::selected_detailed::baseline::PromotionBaselineBatch> {
        crate::attach::selected_detailed::baseline::query(
            &mut self.prepared.ebpf,
            domain,
            generation,
            capture,
            presentation,
            targets,
            window,
            reserve,
        )
    }

    pub(super) fn ebpf(&self) -> &Ebpf {
        &self.prepared.ebpf
    }

    pub(super) fn pid_pin(&self) -> Option<&PidPin> {
        self.prepared.pid_pin.as_ref()
    }

    pub(super) fn endpoint_capacity(&self) -> u32 {
        self.prepared.capacity.get()
    }

    pub(super) fn health(&mut self, deadline: Instant) -> InventoryHealthSnapshot {
        let health =
            read_inventory_health_flavor(&self.prepared.ebpf, deadline, self.prepared.flavor);
        self.health_read_failures = self
            .health_read_failures
            .saturating_add(health.failures.len() as u64);
        health
    }

    /// Rechecks at most `max` held object pins after `after`, in object
    /// order (`fstat` of each retained fd, no reopen): `Ok(true)`
    /// unchanged, `Ok(false)` modified in place, `Err` unreadable. Returns
    /// the cursor for the next call (`None` once the end was reached).
    #[allow(clippy::type_complexity)]
    pub(super) fn recheck_pins(
        &mut self,
        after: Option<PinnedObjectId>,
        max: usize,
    ) -> (
        Vec<(PinnedObjectId, std::result::Result<bool, String>)>,
        Option<PinnedObjectId>,
    ) {
        use std::ops::Bound;
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut checked = Vec::new();
        for (object, pin) in self.targets.pins.range((lower, Bound::Unbounded)).take(max) {
            let verdict = pin.check_unchanged();
            match verdict {
                Ok(true) => {}
                Ok(false) => self.targets.changed.set(true),
                Err(_) => self.pin_check_failures = self.pin_check_failures.saturating_add(1),
            }
            checked.push((*object, verdict));
        }
        let next = (checked.len() == max)
            .then(|| checked.last().map(|(object, _)| *object))
            .flatten();
        (checked, next)
    }

    pub(super) fn malformed_discovery(&self) -> u64 {
        self.malformed_discovery
    }

    pub(super) fn pin_check_failures(&self) -> u64 {
        self.pin_check_failures
    }

    pub(super) fn live_links(&self) -> usize {
        self.links.len()
    }

    pub(super) fn dequeue_discovery(&mut self) -> Result<Option<DiscoveryRecord>> {
        self.discovery_dequeue()
    }

    /// Keymeta Task 7 (spec §17.4): one INFO dequeue (`None` before
    /// the reader exists, including P0).
    pub(super) fn dequeue_info(&mut self) -> Result<Option<InfoItem>> {
        match self.info.as_mut() {
            Some(drain) => drain.dequeue(),
            None => Ok(None),
        }
    }

    /// Keymeta Task 7 (spec §17.4): submitted INFO records now, or
    /// `None` before the reader exists (P0 reads nothing). A failed
    /// map read rides `Some(Err)` with its cause — the terminal cut
    /// must not publish a stale provisional difference as loss.
    pub(super) fn info_produced(&self) -> Option<Result<u64, String>> {
        self.info.as_ref()?;
        Some(read_info_produced(&self.prepared.ebpf).map_err(|error| format!("{error:#}")))
    }

    /// Keymeta Task 7 (spec §17.4): the four INFO_EVIDENCE cells
    /// now (insert failures, unmatched returns, nested overwrites,
    /// stash mismatches), or `None` before the reader exists (P0
    /// reads nothing). No cell lookup starts at or past the quantum
    /// deadline: a mid-group expiry yields (the caller keeps its
    /// previous sample), and a failed map read rides `Done(Err)`
    /// with its cause, distinct from P0 absence.
    pub(super) fn info_evidence(&self, deadline: Instant) -> Option<InfoEvidenceRead> {
        self.info.as_ref()?;
        Some(read_info_evidence(
            &self.prepared.ebpf,
            deadline,
            &mut Instant::now,
        ))
    }

    /// See [`crate::events::discovery_head_pending`].
    pub(super) fn discovery_head_pending(&self) -> bool {
        self.discovery
            .as_ref()
            .is_some_and(crate::events::discovery_head_pending)
    }

    /// Unconsumed lifecycle-ring bytes now, or `None` before the reader
    /// exists. One high-water sample; the drain takes the maximum.
    pub(super) fn discovery_fill_bytes(&self) -> Option<u64> {
        self.discovery.as_ref().map(|drain| {
            crate::events::discovery_pending_bytes(crate::events::discovery_drain_positions(drain))
        })
    }
}

impl Drop for InventoryState {
    fn drop(&mut self) {
        if self.links.is_empty() {
            return;
        }
        self.fallback.begin_abandonment();
        let work = self.take_retirement_work();
        match RetirementJob::start(work, close_inventory_fds) {
            Ok(job) => self.reclaim_job(job),
            Err(failure) => {
                self.fallback.worker_failure();
                self.reclaim_unstarted_work(failure.work);
                if let Some(worker) = failure.empty_worker {
                    let _ = worker.join();
                }
            }
        }
    }
}

pub(super) struct ActiveInventory {
    state: InventoryState,
}

pub(super) struct RetiredInventory {
    state: InventoryState,
    pub(super) cleanup: InventoryCleanupReceipt,
}

/// A deadline returns control with this same owned capability intact. Dropping
/// it is a blocking, explicitly abandoned reclamation path, not bounded stop.
#[must_use]
pub(super) struct RetiringInventory {
    state: Option<InventoryState>,
    job: Option<RetirementJob<Vec<InventoryFd>>>,
    unstarted: Option<RetirementWork<Vec<InventoryFd>>>,
    empty_worker: Option<std::thread::JoinHandle<Option<RetirementWork<Vec<InventoryFd>>>>>,
    cleanup: Option<InventoryCleanupReceipt>,
    control_error: Option<String>,
    /// Keymeta Task 7 (spec §17.4): the bounded INFO_START scrub
    /// phase, carrying progress and concrete failures across polls.
    #[cfg(not(feature = "stub-object-attributes"))]
    scrub: InfoScrubPhase,
}

impl RetiringInventory {
    fn begin(state: InventoryState) -> Self {
        Self::begin_with_close(state, close_inventory_fds)
    }

    fn begin_with_close(
        mut state: InventoryState,
        close: impl Fn(&mut Vec<InventoryFd>) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        let work = state.take_retirement_work();
        let mut retiring = Self {
            state: Some(state),
            job: None,
            unstarted: None,
            empty_worker: None,
            cleanup: None,
            control_error: None,
            #[cfg(not(feature = "stub-object-attributes"))]
            scrub: InfoScrubPhase::default(),
        };
        if work.links.is_empty() {
            retiring.cleanup = Some(InventoryCleanupReceipt::default());
            return retiring;
        }
        match RetirementJob::start(work, close) {
            Ok(job) => retiring.job = Some(job),
            Err(failure) => {
                let RetirementStartFailure {
                    error,
                    work,
                    empty_worker,
                } = *failure;
                retiring.control_error = Some(format!("starting Inventory retirement: {error:#}"));
                retiring.unstarted = Some(work);
                retiring.empty_worker = empty_worker;
                retiring.state.as_ref().unwrap().fallback.worker_failure();
            }
        }
        retiring
    }

    pub(super) fn poll_completion(&mut self, deadline: Instant) -> Result<bool> {
        if self.cleanup.is_some() {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        if let Some(error) = &self.control_error {
            bail!("{error}");
        }
        let result = self
            .job
            .as_mut()
            .context("Inventory retirement job absent")?
            .poll(deadline);
        match result {
            Ok(Some(work)) => {
                self.cleanup = Some(self.state.as_mut().unwrap().collect_retirement_work(work));
                self.job = None;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => {
                self.state.as_ref().unwrap().fallback.worker_failure();
                self.control_error = Some(format!("collecting Inventory retirement: {error:#}"));
                self.job = None;
                Err(error)
            }
        }
    }

    /// One retiring drain plus its high-water: the maximum fill sampled
    /// before each dequeue, or `None` when no reader existed to sample.
    pub(super) fn service_discovery(
        &mut self,
        max_records: usize,
        deadline: Instant,
        dispatch: impl FnMut(DiscoveryRecord) -> Result<()>,
    ) -> (
        std::result::Result<InventoryDiscoveryService, InventoryDispatchFailure>,
        Option<u64>,
    ) {
        let state = self.state.as_mut().unwrap();
        let mut high_water = state.discovery_fill_bytes();
        let result = service_inventory_discovery_with(
            max_records,
            deadline,
            || {
                high_water = high_water.max(state.discovery_fill_bytes());
                state.discovery_dequeue()
            },
            dispatch,
        );
        (result, high_water)
    }

    /// Keymeta Task 7 (spec §17.4): one retiring INFO dequeue
    /// (`None` once the state transfers).
    pub(super) fn dequeue_info(&mut self) -> Result<Option<InfoItem>> {
        match self.state.as_mut() {
            Some(state) => state.dequeue_info(),
            None => Ok(None),
        }
    }

    /// Keymeta Task 7 (spec §17.4): submitted INFO records now, or
    /// `None` once the state transfers (P0 reads nothing). A failed
    /// map read rides `Some(Err)` with its cause.
    pub(super) fn info_produced(&self) -> Option<Result<u64, String>> {
        self.state.as_ref()?.info_produced()
    }

    /// Keymeta Task 7 (spec §17.4): the four INFO_EVIDENCE cells
    /// now, or `None` once the state transfers (P0 reads nothing).
    pub(super) fn info_evidence(&self, deadline: Instant) -> Option<InfoEvidenceRead> {
        self.state.as_ref()?.info_evidence(deadline)
    }

    fn usage_snapshot(&mut self, window: InventoryReadWindow) -> InventoryUsageSnapshot {
        self.state.as_mut().unwrap().usage_snapshot(window, true)
    }

    pub(super) fn discovery_head_pending(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(InventoryState::discovery_head_pending)
    }

    fn fallback_evidence(&self) -> RetirementFallbackEvidence {
        self.state.as_ref().unwrap().fallback.clone()
    }

    /// The retained state, until `try_finish` transfers it.
    pub(super) fn state(&self) -> Option<&InventoryState> {
        self.state.as_ref()
    }

    pub(super) fn state_mut(&mut self) -> Option<&mut InventoryState> {
        self.state.as_mut()
    }

    pub(super) fn control_error(&self) -> Option<&str> {
        self.control_error.as_deref()
    }

    /// True once every link had its close attempt (the detach half
    /// of retirement), even while the INFO scrub still blocks the
    /// ownership transfer.
    pub(super) fn detach_completed(&self) -> bool {
        self.cleanup.is_some()
    }

    /// The INFO stash teardown outcome for the operator (spec §17.4):
    /// the scrub phase's live status on FULL, proven on P0 (no map).
    pub(super) fn info_teardown(&self) -> InfoTeardown {
        #[cfg(feature = "stub-object-attributes")]
        {
            InfoTeardown::Proven
        }
        #[cfg(not(feature = "stub-object-attributes"))]
        {
            self.scrub.status()
        }
    }

    pub(super) fn try_finish(
        mut self,
        deadline: Instant,
    ) -> std::result::Result<RetiredInventory, Box<Self>> {
        // P0 objects carry no INFO_START map: no scrub runs there.
        #[cfg(feature = "stub-object-attributes")]
        let _ = deadline;
        let Some(cleanup) = self.cleanup.take() else {
            return Err(Box::new(self));
        };
        // Keymeta Task 7 (spec §17.4): the links are detached; scrub
        // the info stash in bounded steps before transferring the
        // state, refusing while links are retained (probes still
        // mutating) with teardown explicitly unproven. Each poll
        // spends at most one native-operation allowance and starts
        // nothing at or past the stop deadline. Fresh maps per
        // preparation mean no row survives the session either way. P0
        // objects carry no INFO_START map.
        #[cfg(not(feature = "stub-object-attributes"))]
        let cleanup = if let Some(state) = self.state.as_mut() {
            let retained = !cleanup.failures.is_empty();
            let mut budget = ScrubBudget::per_poll(deadline, Instant::now);
            match self.scrub.poll(retained, |cleared, pending| {
                scrub_info_start_step_on(&mut state.prepared.ebpf, cleared, pending, &mut budget)
                    .map_err(|error| format!("{error:#}"))
            }) {
                InfoScrubDirective::Transfer { unproven } => InventoryCleanupReceipt {
                    info_teardown_unproven: unproven,
                    info_scrub_error: self.scrub.error.clone(),
                    ..cleanup
                },
                InfoScrubDirective::Retry => {
                    self.cleanup = Some(cleanup);
                    return Err(Box::new(self));
                }
            }
        } else {
            cleanup
        };
        Ok(RetiredInventory {
            state: self.state.take().unwrap(),
            cleanup,
        })
    }
}

impl Drop for RetiringInventory {
    fn drop(&mut self) {
        let Some(state) = self.state.as_mut() else {
            return;
        };
        // Even an already-completed job may still have undispatched records.
        // Only try_finish transfers this state as an explicitly owned result.
        state.fallback.begin_abandonment();
        if let Some(job) = self.job.take() {
            // May wait for an arbitrarily slow kernel close. Keep the reader,
            // maps and physical identities alive, with explicit abandonment.
            state.reclaim_job(job);
        }
        if let Some(work) = self.unstarted.take() {
            state.reclaim_unstarted_work(work);
        }
        if let Some(worker) = self.empty_worker.take() {
            let _ = worker.join();
        }
        state.drain_abandoned_quantum();
    }
}

/// Keymeta Task 7 (spec §17.4): one INFO ring dequeue — a raw
/// 176-byte record, or a malformed frame.
pub(super) enum InfoItem {
    Record([u8; 176]),
    Malformed,
}

/// Keymeta Task 7 (spec §17.4): the session's single retained
/// consumer for the private INFO ring. It owns a duplicate
/// descriptor and its mappings (no self-borrow of the prepared
/// object); every dequeued frame counts as consumed, malformed ones
/// included.
pub(super) struct OwnedInfoDrain {
    ring: aya::maps::RingBuf<aya::maps::MapData>,
    consumed: u64,
}

impl OwnedInfoDrain {
    pub(super) fn for_session(ebpf: &Ebpf) -> Result<Self> {
        let aya::maps::Map::RingBuf(data) = ebpf.map("INFO").context("INFO map")? else {
            anyhow::bail!("INFO is not a ring buffer");
        };
        let id = u64::from(data.info()?.id());
        use std::os::fd::AsFd as _;
        let owned = data
            .fd()
            .as_fd()
            .try_clone_to_owned()
            .context("duplicating INFO descriptor")?;
        let data = aya::maps::MapData::from_fd(owned).context("reopening INFO map")?;
        anyhow::ensure!(
            u64::from(data.info()?.id()) == id,
            "INFO map does not match retained allocation"
        );
        let ring = aya::maps::RingBuf::try_from(aya::maps::Map::from_map_data(data)?)?;
        Ok(Self { ring, consumed: 0 })
    }

    pub(super) fn dequeue(&mut self) -> Result<Option<InfoItem>> {
        let Some(record) = self.ring.next() else {
            return Ok(None);
        };
        self.consumed = self.consumed.saturating_add(1);
        let bytes: &[u8] = &record[..];
        if bytes.len() != 176 {
            return Ok(Some(InfoItem::Malformed));
        }
        let mut fixed = [0u8; 176];
        fixed.copy_from_slice(bytes);
        Ok(Some(InfoItem::Record(fixed)))
    }

    pub(super) fn consumed(&self) -> u64 {
        self.consumed
    }
}

/// Keymeta Task 7 (spec §17.4): submitted INFO records from the
/// `PRODUCED` map — the kernel half of the INFO cross-check.
pub(super) fn read_info_produced(ebpf: &Ebpf) -> Result<u64> {
    let map: PerCpuArray<_, u64> =
        PerCpuArray::try_from(ebpf.map("PRODUCED").context("PRODUCED map")?)?;
    Ok(map
        .get(&p11scope_ebpf_common::PRODUCED_INFO, 0)?
        .iter()
        .sum())
}

/// Keymeta Task 7 (spec §17.4): one bounded `INFO_EVIDENCE`
/// group read — all five cells, or the yield when the window
/// expired mid-group (the caller keeps its previous full sample
/// and stages incomplete, never a partial group).
pub(super) enum InfoEvidenceRead {
    Done(Result<[u64; 5], String>),
    Yielded,
}

/// Keymeta Task 7 (spec §17.4): the five `INFO_EVIDENCE` cells —
/// insert failures, unmatched returns, nested overwrites, stash
/// mismatches and INFO ring losses — summed over CPUs. No cell
/// lookup starts at or past the quantum deadline: a mid-group
/// expiry yields with no partial sample. FULL objects only; P0
/// carries no such map and never
/// calls this (the caller gates on the INFO reader).
pub(super) fn read_info_evidence(
    ebpf: &Ebpf,
    deadline: Instant,
    now: &mut dyn FnMut() -> Instant,
) -> InfoEvidenceRead {
    if now() >= deadline {
        return InfoEvidenceRead::Yielded;
    }
    let named = match ebpf.map("INFO_EVIDENCE").context("INFO_EVIDENCE map") {
        Ok(map) => map,
        Err(error) => return InfoEvidenceRead::Done(Err(format!("{error:#}"))),
    };
    let map: PerCpuArray<_, u64> = match PerCpuArray::try_from(named) {
        Ok(map) => map,
        Err(error) => return InfoEvidenceRead::Done(Err(format!("{error:#}"))),
    };
    read_evidence_cells(deadline, now, |index| {
        map.get(&index, 0)
            .map(|values| values.iter().sum())
            .map_err(|error| format!("{error:#}"))
    })
}

/// The five-cell evidence loop over one cell reader: no cell starts
/// at or past the deadline, and a failed cell ends the group with
/// its cause (later cells never start, like the `?` before it).
fn read_evidence_cells(
    deadline: Instant,
    now: &mut dyn FnMut() -> Instant,
    mut read_cell: impl FnMut(u32) -> Result<u64, String>,
) -> InfoEvidenceRead {
    use p11scope_ebpf_common::{
        INFO_EVIDENCE_INSERT_FAILURES, INFO_EVIDENCE_NESTED_OVERWRITES, INFO_EVIDENCE_RING_LOSS,
        INFO_EVIDENCE_STASH_MISMATCHES, INFO_EVIDENCE_UNMATCHED_RETURNS,
    };
    let mut cells = [0u64; 5];
    for (cell, index) in cells.iter_mut().zip([
        INFO_EVIDENCE_INSERT_FAILURES,
        INFO_EVIDENCE_UNMATCHED_RETURNS,
        INFO_EVIDENCE_NESTED_OVERWRITES,
        INFO_EVIDENCE_STASH_MISMATCHES,
        INFO_EVIDENCE_RING_LOSS,
    ]) {
        if now() >= deadline {
            return InfoEvidenceRead::Yielded;
        }
        match read_cell(index) {
            Ok(value) => *cell = value,
            Err(error) => return InfoEvidenceRead::Done(Err(error)),
        }
    }
    InfoEvidenceRead::Done(Ok(cells))
}

#[derive(Default, Debug)]
pub(super) struct InventoryDiscoveryService {
    pub(super) dispatched: usize,
    pub(super) record_bound_reached: bool,
    pub(super) deadline_reached: bool,
}

pub(super) struct InventoryDispatchFailure {
    pub(super) record: Option<Box<DiscoveryRecord>>,
    pub(super) error: anyhow::Error,
    pub(super) dispatched: usize,
}

impl fmt::Debug for InventoryDispatchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InventoryDispatchFailure")
            .field("has_record", &self.record.is_some())
            .field("error", &self.error)
            .field("dispatched", &self.dispatched)
            .finish()
    }
}

pub(super) fn service_inventory_discovery_with(
    max_records: usize,
    deadline: Instant,
    mut dequeue: impl FnMut() -> Result<Option<DiscoveryRecord>>,
    mut dispatch: impl FnMut(DiscoveryRecord) -> Result<()>,
) -> std::result::Result<InventoryDiscoveryService, InventoryDispatchFailure> {
    if max_records == 0 {
        return Err(InventoryDispatchFailure {
            record: None,
            error: anyhow::anyhow!("Inventory discovery service requires a positive record bound"),
            dispatched: 0,
        });
    }
    let mut service = InventoryDiscoveryService::default();
    while service.dispatched < max_records {
        if Instant::now() >= deadline {
            service.deadline_reached = true;
            return Ok(service);
        }
        let record = match dequeue() {
            Ok(Some(record)) => record,
            Ok(None) => return Ok(service),
            Err(error) => {
                return Err(InventoryDispatchFailure {
                    record: None,
                    error,
                    dispatched: service.dispatched,
                });
            }
        };
        if let Err(error) = dispatch(record) {
            // Return exact consumed-but-undelivered evidence to the caller.
            // Never read ahead, silently discard, or queue records internally.
            return Err(InventoryDispatchFailure {
                record: Some(Box::new(record)),
                error,
                dispatched: service.dispatched,
            });
        }
        service.dispatched += 1;
    }
    service.record_bound_reached = true;
    Ok(service)
}

#[derive(Default, Debug)]
pub(super) struct InventoryInfoService {
    pub(super) dispatched: usize,
    pub(super) record_bound_reached: bool,
    pub(super) deadline_reached: bool,
}

pub(super) struct InventoryInfoDispatchFailure {
    pub(super) record: Option<Box<[u8; 176]>>,
    pub(super) error: anyhow::Error,
    pub(super) dispatched: usize,
}

impl fmt::Debug for InventoryInfoDispatchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InventoryInfoDispatchFailure")
            .field("has_record", &self.record.is_some())
            .field("error", &self.error)
            .field("dispatched", &self.dispatched)
            .finish()
    }
}

/// Keymeta Task 7 (spec §17.4): drain the INFO ring alongside
/// DISCOVERY with the same bounded quantum shape — a positive
/// record bound, a deadline, no read-ahead, and exact
/// consumed-but-undelivered evidence on dispatch failure. A
/// malformed frame bails with no record, like DISCOVERY.
pub(super) fn service_inventory_info_with(
    max_records: usize,
    deadline: Instant,
    mut dequeue: impl FnMut() -> Result<Option<InfoItem>>,
    mut dispatch: impl FnMut([u8; 176]) -> Result<()>,
) -> std::result::Result<InventoryInfoService, InventoryInfoDispatchFailure> {
    if max_records == 0 {
        return Err(InventoryInfoDispatchFailure {
            record: None,
            error: anyhow::anyhow!("Inventory INFO service requires a positive record bound"),
            dispatched: 0,
        });
    }
    let mut service = InventoryInfoService::default();
    while service.dispatched < max_records {
        if Instant::now() >= deadline {
            service.deadline_reached = true;
            return Ok(service);
        }
        let record = match dequeue() {
            Ok(Some(InfoItem::Record(record))) => record,
            Ok(Some(InfoItem::Malformed)) => {
                return Err(InventoryInfoDispatchFailure {
                    record: None,
                    error: anyhow::anyhow!("malformed Inventory INFO record"),
                    dispatched: service.dispatched,
                });
            }
            Ok(None) => return Ok(service),
            Err(error) => {
                return Err(InventoryInfoDispatchFailure {
                    record: None,
                    error,
                    dispatched: service.dispatched,
                });
            }
        };
        if let Err(error) = dispatch(record) {
            // Return exact consumed-but-undelivered evidence to the caller.
            // Never read ahead, silently discard, or queue records internally.
            return Err(InventoryInfoDispatchFailure {
                record: Some(Box::new(record)),
                error,
                dispatched: service.dispatched,
            });
        }
        service.dispatched += 1;
    }
    service.record_bound_reached = true;
    Ok(service)
}

pub(super) struct InventoryActivationFailure {
    pub(super) error: anyhow::Error,
    pub(super) retiring: Box<RetiringInventory>,
}

impl fmt::Display for InventoryActivationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#}; Inventory rollback capability retained",
            self.error,
        )
    }
}

impl fmt::Debug for InventoryActivationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InventoryActivationFailure")
            .field("error", &self.error)
            .field("cleanup", &self.retiring.cleanup)
            .field("control_error", &self.retiring.control_error)
            .finish()
    }
}

impl PreparedInventory {
    fn activate(
        self,
        targets: InventoryTargets,
    ) -> std::result::Result<ActiveInventory, InventoryActivationFailure> {
        self.activate_inner(
            targets,
            #[cfg(test)]
            |_| Ok(()),
        )
    }

    fn activate_inner(
        self,
        targets: InventoryTargets,
        #[cfg(test)] mut before_attach: impl FnMut(&InventoryAttachRequest<'_>) -> Result<()>,
    ) -> std::result::Result<ActiveInventory, InventoryActivationFailure> {
        let mut state = InventoryState {
            history: InventoryUsageHistory::new(targets.allocated.clone()),
            links: vec![],
            discovery: None,
            info: None,
            prepared: self,
            targets,
            malformed_discovery: 0,
            health_read_failures: 0,
            pin_check_failures: 0,
            fallback: RetirementFallbackEvidence::default(),
        };
        let ready = (|| -> Result<()> {
            validate_activation(
                &state.prepared.scope,
                state.prepared.backend,
                state.prepared.budget,
                &state.targets,
            )?;
            // Construct the real retained map reader before the first producer.
            state.discovery = Some(OwnedDiscoveryDrain::for_session(
                &state.prepared.ebpf,
                &state.prepared.discovery_domain,
            )?);
            // Keymeta Task 7 (spec §17.4): the retained INFO
            // consumer beside DISCOVERY. P0 objects carry no INFO
            // ring, so the reader stays absent there.
            #[cfg(not(feature = "stub-object-attributes"))]
            {
                state.info = Some(OwnedInfoDrain::for_session(&state.prepared.ebpf)?);
            }
            Ok(())
        })();
        if let Err(error) = ready {
            return Err(InventoryActivationFailure {
                error,
                retiring: Box::new(RetiringInventory::begin(state)),
            });
        }
        let mut io = AyaInventoryLinkIo {
            ebpf: &mut state.prepared.ebpf,
            caller: matches!(state.prepared.flavor, InventoryFlavor::Callers(_)),
            // validate_activation refused PID scope: process-wide only.
            entry_scope: UProbeScope::AllProcesses,
            #[cfg(test)]
            before_attach: Some(&mut before_attach),
        };
        match attach_inventory_with(&mut io, &state.targets) {
            Ok(links) => {
                state.links = links;
                Ok(ActiveInventory { state })
            }
            Err(failure) => {
                state.links = failure.links;
                Err(InventoryActivationFailure {
                    error: failure.error,
                    retiring: Box::new(RetiringInventory::begin(state)),
                })
            }
        }
    }
}

impl PreparedInventory {
    /// The capture facade's one-time activation: validation (the PID-scope
    /// path), the retained DISCOVERY reader, and the two lifecycle roots.
    /// Entries attach later through `ActiveInventory::with_entry_io`. A
    /// failure keeps every acquired link with the retirement capability.
    pub(super) fn activate_roots(
        self,
        targets: InventoryTargets,
    ) -> std::result::Result<ActiveInventory, InventoryActivationFailure> {
        let mut state = InventoryState {
            history: InventoryUsageHistory::new(Vec::new()),
            links: vec![],
            discovery: None,
            info: None,
            prepared: self,
            targets,
            malformed_discovery: 0,
            health_read_failures: 0,
            pin_check_failures: 0,
            fallback: RetirementFallbackEvidence::default(),
        };
        let ready = (|| -> Result<()> {
            validate_capture_activation(
                &state.prepared.scope,
                state.prepared.pid_pin.as_ref(),
                state.prepared.backend,
                state.prepared.budget,
                &state.targets,
            )?;
            state.discovery = Some(OwnedDiscoveryDrain::for_session(
                &state.prepared.ebpf,
                &state.prepared.discovery_domain,
            )?);
            // Keymeta Task 7 (spec §17.4): the retained INFO
            // consumer beside DISCOVERY. P0 objects carry no INFO
            // ring, so the reader stays absent there.
            #[cfg(not(feature = "stub-object-attributes"))]
            {
                state.info = Some(OwnedInfoDrain::for_session(&state.prepared.ebpf)?);
            }
            Ok(())
        })();
        if let Err(error) = ready {
            return Err(InventoryActivationFailure {
                error,
                retiring: Box::new(RetiringInventory::begin(state)),
            });
        }
        let roots = {
            let mut io = AyaInventoryLinkIo {
                ebpf: &mut state.prepared.ebpf,
                caller: matches!(state.prepared.flavor, InventoryFlavor::Callers(_)),
                entry_scope: capture_entry_scope(&state.prepared.scope),
                #[cfg(test)]
                before_attach: None,
            };
            attach_roots_with(&mut io, &mut state.links)
        };
        match roots {
            Ok(()) => Ok(ActiveInventory { state }),
            Err(error) => Err(InventoryActivationFailure {
                error,
                retiring: Box::new(RetiringInventory::begin(state)),
            }),
        }
    }
}

/// The capture facade's entry scope: `OneProcess` for PID scope (the same
/// seam Detailed uses), so the kernel binds each entry to the original
/// task and a reused PID never fires it; process-wide otherwise.
pub(super) fn capture_entry_scope(scope: &Scope) -> UProbeScope {
    match scope {
        Scope::Pid(pid) => match std::num::NonZeroU32::new(*pid) {
            Some(pid) => UProbeScope::OneProcess(pid),
            // prepare refused a zero PID; never widen to every process.
            None => UProbeScope::CallingProcess,
        },
        Scope::Cgroup { .. } | Scope::System => UProbeScope::AllProcesses,
    }
}

impl ActiveInventory {
    /// The incremental entry seam: the real link IO plus the target table
    /// and the link custody vector. Links never leave this object.
    pub(super) fn with_entry_io<R>(
        &mut self,
        f: impl FnOnce(
            &mut AyaInventoryLinkIo<'_>,
            &mut InventoryTargets,
            &mut Vec<InventoryLinked<KernelInventoryLink>>,
            Option<&PidPin>,
        ) -> R,
    ) -> R {
        let state = &mut self.state;
        let mut io = AyaInventoryLinkIo {
            ebpf: &mut state.prepared.ebpf,
            caller: matches!(state.prepared.flavor, InventoryFlavor::Callers(_)),
            entry_scope: capture_entry_scope(&state.prepared.scope),
            #[cfg(test)]
            before_attach: None,
        };
        f(
            &mut io,
            &mut state.targets,
            &mut state.links,
            state.prepared.pid_pin.as_ref(),
        )
    }

    pub(super) fn state(&self) -> &InventoryState {
        &self.state
    }

    pub(super) fn state_mut(&mut self) -> &mut InventoryState {
        &mut self.state
    }

    fn usage_snapshot(&mut self, window: InventoryReadWindow) -> InventoryUsageSnapshot {
        self.state.usage_snapshot(window, false)
    }

    fn discovery_dequeue(&mut self) -> Result<Option<DiscoveryRecord>> {
        self.state.discovery_dequeue()
    }

    pub(super) fn begin_stop(self) -> RetiringInventory {
        RetiringInventory::begin(self.state)
    }
}

impl RetiredInventory {
    pub(super) fn state(&self) -> &InventoryState {
        &self.state
    }

    pub(super) fn state_mut(&mut self) -> &mut InventoryState {
        &mut self.state
    }

    fn usage_snapshot(&mut self, window: InventoryReadWindow) -> InventoryUsageSnapshot {
        self.state.usage_snapshot(window, true)
    }

    fn discovery_dequeue(&mut self) -> Result<Option<DiscoveryRecord>> {
        self.state.discovery_dequeue()
    }
}

#[derive(Debug, Default, Clone)]
pub(super) struct InventoryHealthSnapshot {
    pub(super) discovery_counters: Option<[u64; 5]>,
    pub(super) evidence: Option<[u64; 9]>,
    pub(super) usage_evidence: Option<[u64; 3]>,
    pub(super) owner: Option<ThreadOwnerControl>,
    pub(super) caller_evidence: Option<[u64; 4]>,
    pub(super) caller_control: Option<p11scope_ebpf_common::ImageIdentityControl>,
    pub(super) failures: Vec<String>,
}

#[derive(Debug)]
struct InventoryUsageSnapshot {
    usage: InventoryUsageRead,
    health: InventoryHealthSnapshot,
    pin_error: Option<String>,
    provider_changed: bool,
    malformed_discovery: u64,
    usage_integrity_failures: u64,
    usage_read_failures: u64,
    health_read_failures: u64,
    pin_check_failures: u64,
    retirement_fallback: retirement::RetirementFallbackSnapshot,
    /// An explicit retirement flag, never a final-zero or callback settlement proof.
    terminal_unsettled: bool,
}

fn read_inventory_health(ebpf: &Ebpf, deadline: Instant) -> InventoryHealthSnapshot {
    read_inventory_health_flavor(ebpf, deadline, InventoryFlavor::Global)
}

fn read_inventory_health_flavor(
    ebpf: &Ebpf,
    deadline: Instant,
    flavor: InventoryFlavor,
) -> InventoryHealthSnapshot {
    fn per_cpu<const N: usize>(ebpf: &Ebpf, name: &str, deadline: Instant) -> Result<[u64; N]> {
        let map: PerCpuArray<_, u64> =
            PerCpuArray::try_from(ebpf.map(name).with_context(|| format!("{name} map"))?)?;
        let mut values = [0; N];
        for (index, value) in values.iter_mut().enumerate() {
            ensure!(
                Instant::now() < deadline,
                "Inventory health deadline before {name}[{index}]"
            );
            *value = map
                .get(&(index as u32), 0)?
                .iter()
                .try_fold(0u64, |sum, value| sum.checked_add(*value))
                .with_context(|| format!("{name}[{index}] per-CPU sum overflow"))?;
        }
        Ok(values)
    }
    fn keep<T>(value: Result<T>, failures: &mut Vec<String>) -> Option<T> {
        match value {
            Ok(value) => Some(value),
            Err(error) => {
                failures.push(format!("{error:#}"));
                None
            }
        }
    }
    let mut health = InventoryHealthSnapshot::default();
    health.discovery_counters = keep(per_cpu(ebpf, "COUNTERS", deadline), &mut health.failures);
    health.evidence = keep(per_cpu(ebpf, "EVIDENCE", deadline), &mut health.failures);
    health.usage_evidence = keep(
        per_cpu(ebpf, "USAGE_EVIDENCE", deadline),
        &mut health.failures,
    );
    health.owner = keep(
        (|| -> Result<ThreadOwnerControl> {
            ensure!(
                Instant::now() < deadline,
                "Inventory health deadline before OWNER_CTL"
            );
            let map: Array<_, ThreadOwnerControl> =
                Array::try_from(ebpf.map("OWNER_CTL").context("OWNER_CTL map")?)?;
            Ok(map.get(&0, 0)?)
        })(),
        &mut health.failures,
    );
    if matches!(flavor, InventoryFlavor::Callers(_)) {
        let mut caller_io = ebpf;
        let caller = callers::read_caller_health_with(&mut caller_io, deadline);
        health.caller_evidence = caller.evidence;
        health.caller_control = caller.control;
        health.failures.extend(caller.failures);
    }
    health
}

#[cfg(test)]
pub(super) mod privileged_tests;
#[cfg(test)]
mod tests;
