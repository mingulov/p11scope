//! SPDX-License-Identifier: GPL-3.0-or-later
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
}

#[derive(Debug, Default)]
pub(super) struct InventoryCleanupReceipt {
    pub(super) attempted: usize,
    pub(super) closed: usize,
    pub(super) failures: Vec<InventoryDetachFailure>,
    callback_quiescence_proven: bool,
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
    let program = match entry.abi {
        ElfAbi::Lp64 => "p11_usage_entry_lp64",
        ElfAbi::Ilp32 => "p11_usage_entry_ia32",
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
            } => {
                let probe: &mut UProbe = self
                    .ebpf
                    .program_mut(program)
                    .context(program)?
                    .try_into()?;
                let point = UProbeAttachPoint {
                    location: UProbeAttachLocation::AbsoluteOffset(file_offset),
                    cookie: Some(cookie),
                };
                let id = probe.attach([point], path, self.entry_scope)?;
                Ok(match probe.take_link(id) {
                    Ok(link) => match link.into_fd_links() {
                        Ok(links) => KernelInventoryLink::Fds(
                            links.into_iter().map(InventoryFd::Aya).collect(),
                        ),
                        Err(link) => KernelInventoryLink::UnexpectedUProbe(link),
                    },
                    Err(error) => KernelInventoryLink::RegistryUncertain {
                        program,
                        error: error.to_string(),
                    },
                })
            }
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
}

impl RetiringInventory {
    fn begin(state: InventoryState) -> Self {
        Self::begin_with_close(state, close_inventory_fds)
    }

    fn begin_with_close(
        mut state: InventoryState,
        close: impl FnMut(&mut Vec<InventoryFd>) -> Result<()> + Send + 'static,
    ) -> Self {
        let work = state.take_retirement_work();
        let mut retiring = Self {
            state: Some(state),
            job: None,
            unstarted: None,
            empty_worker: None,
            cleanup: None,
            control_error: None,
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

    pub(super) fn try_finish(mut self) -> std::result::Result<RetiredInventory, Box<Self>> {
        let Some(cleanup) = self.cleanup.take() else {
            return Err(Box::new(self));
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
