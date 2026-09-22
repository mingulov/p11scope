//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private static Inventory activation: entry-only Singles with retained pins,
//! discovery transport and monotonic positive evidence. No caller/count claim.

use super::{AttachBackend, InventoryBudget, InventoryFlavor, PreparedInventory, Scope, callers};
use crate::discovery::identity::{PinnedObjectId, PinnedObjects, RetainedInventoryTarget};
use crate::events::{DiscoveryItem, OwnedDiscoveryDrain};
use crate::plan::{AdmissionPolicy, AttachPlan};
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
use std::path::Path;
use std::time::Instant;

mod retirement;
use retirement::{
    RetirementFallbackEvidence, RetirementJob, RetirementLink, RetirementStartFailure,
    RetirementWork, abandon_and_reclaim_with,
};

struct InventoryTargets {
    budget: InventoryBudget,
    allocated: Vec<u32>,
    entries: Vec<InventoryEndpoint>,
    pins: BTreeMap<PinnedObjectId, RetainedInventoryTarget>,
    changed: Cell<bool>,
}

struct InventoryEndpoint {
    id: u32,
    object: PinnedObjectId,
    file_offset: u64,
    abi: ElfAbi,
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
    ensure!(
        budget == targets.budget,
        "Inventory plan and prepared object budget differ"
    );
    targets.check_unchanged()
}

enum InventoryAttachRequest<'a> {
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

trait InventoryLinkIo {
    type Link;
    fn publish_endpoint(&mut self, endpoint: u32, object: PinnedObjectId) -> Result<()>;
    fn attach(&mut self, request: InventoryAttachRequest<'_>) -> Result<Self::Link>;
    fn detach(&mut self, link: &mut Self::Link) -> Result<()>;
    fn attachment_error(&self, _link: &Self::Link) -> Option<String> {
        None
    }
}

#[derive(Debug, Default)]
struct InventoryCleanupReceipt {
    attempted: usize,
    closed: usize,
    failures: Vec<InventoryDetachFailure>,
    callback_quiescence_proven: bool,
}

#[derive(Debug)]
struct InventoryDetachFailure {
    target: InventoryLinkIdentity,
    error: anyhow::Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventoryLinkIdentity {
    Lifecycle(&'static str),
    Entry(u32),
}

struct InventoryLinked<L> {
    target: InventoryLinkIdentity,
    handle: L,
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
        }
        for entry in &targets.entries {
            io.publish_endpoint(entry.id, entry.object)
                .with_context(|| format!("publishing Inventory endpoint {}", entry.id))?;
        }
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
        for entry in &targets.entries {
            let pin = &targets.pins[&entry.object];
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
                .with_context(|| format!("during Inventory entry {} attachment", entry.id))?;
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

struct InventoryReadWindow {
    max_cells: usize,
    deadline: Instant,
}

impl InventoryReadWindow {
    fn new(max_cells: usize, deadline: Instant) -> Result<Self> {
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

/// Ordinary cookies require Aya's fd-backed perf link path. Keep an unexpected
/// representation or registry-transfer error owned and explicitly quarantined.
enum KernelInventoryLink {
    Fds(Vec<FdLink>),
    UnexpectedUProbe(UProbeLink),
    RegistryUncertain {
        program: &'static str,
        error: String,
    },
}

struct AyaInventoryLinkIo<'a> {
    ebpf: &'a mut Ebpf,
    caller: bool,
    #[cfg(test)]
    before_attach: &'a mut dyn FnMut(&InventoryAttachRequest<'_>) -> Result<()>,
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
        (self.before_attach)(&request)?;
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
                    Ok(link) => KernelInventoryLink::Fds(vec![link.into()]),
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
                let id = probe.attach([point], path, UProbeScope::AllProcesses)?;
                Ok(match probe.take_link(id) {
                    Ok(link) => match link.into_fd_links() {
                        Ok(links) => KernelInventoryLink::Fds(links),
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
}

fn close_inventory_fds(links: &mut Vec<FdLink>) -> Result<()> {
    // Aya FdLink::detach has exactly this close-on-drop behavior. This leaf
    // needs neither Ebpf nor the reader; its blocking work belongs off-main.
    links.clear();
    Ok(())
}

/// Field custody and Drop keep links ahead of programs, maps and exact pins.
struct InventoryState {
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
    fn take_retirement_work(&mut self) -> RetirementWork<Vec<FdLink>> {
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
        mut work: RetirementWork<Vec<FdLink>>,
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

    fn reclaim_unstarted_work(&mut self, mut work: RetirementWork<Vec<FdLink>>) {
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

    fn reclaim_job(&mut self, job: RetirementJob<Vec<FdLink>>) {
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
                if checked_pins.insert(object) {
                    if let Err(error) = self.targets.check_pin(object) {
                        self.pin_check_failures = self.pin_check_failures.saturating_add(1);
                        pin_error.get_or_insert_with(|| format!("{error:#}"));
                    }
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

struct ActiveInventory {
    state: InventoryState,
}

struct RetiredInventory {
    state: InventoryState,
    cleanup: InventoryCleanupReceipt,
}

/// A deadline returns control with this same owned capability intact. Dropping
/// it is a blocking, explicitly abandoned reclamation path, not bounded stop.
#[must_use]
struct RetiringInventory {
    state: Option<InventoryState>,
    job: Option<RetirementJob<Vec<FdLink>>>,
    unstarted: Option<RetirementWork<Vec<FdLink>>>,
    empty_worker: Option<std::thread::JoinHandle<Option<RetirementWork<Vec<FdLink>>>>>,
    cleanup: Option<InventoryCleanupReceipt>,
    control_error: Option<String>,
}

impl RetiringInventory {
    fn begin(state: InventoryState) -> Self {
        Self::begin_with_close(state, close_inventory_fds)
    }

    fn begin_with_close(
        mut state: InventoryState,
        close: impl FnMut(&mut Vec<FdLink>) -> Result<()> + Send + 'static,
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

    fn poll_completion(&mut self, deadline: Instant) -> Result<bool> {
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

    fn service_discovery(
        &mut self,
        max_records: usize,
        deadline: Instant,
        dispatch: impl FnMut(DiscoveryRecord) -> Result<()>,
    ) -> std::result::Result<InventoryDiscoveryService, InventoryDispatchFailure> {
        service_inventory_discovery_with(
            max_records,
            deadline,
            || self.state.as_mut().unwrap().discovery_dequeue(),
            dispatch,
        )
    }

    fn usage_snapshot(&mut self, window: InventoryReadWindow) -> InventoryUsageSnapshot {
        self.state.as_mut().unwrap().usage_snapshot(window, true)
    }

    fn fallback_evidence(&self) -> RetirementFallbackEvidence {
        self.state.as_ref().unwrap().fallback.clone()
    }

    fn try_finish(mut self) -> std::result::Result<RetiredInventory, Box<Self>> {
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
struct InventoryDiscoveryService {
    dispatched: usize,
    record_bound_reached: bool,
    deadline_reached: bool,
}

struct InventoryDispatchFailure {
    record: Option<Box<DiscoveryRecord>>,
    error: anyhow::Error,
    dispatched: usize,
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

fn service_inventory_discovery_with(
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

struct InventoryActivationFailure {
    error: anyhow::Error,
    retiring: Box<RetiringInventory>,
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
            #[cfg(test)]
            before_attach: &mut before_attach,
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

impl ActiveInventory {
    fn usage_snapshot(&mut self, window: InventoryReadWindow) -> InventoryUsageSnapshot {
        self.state.usage_snapshot(window, false)
    }

    fn discovery_dequeue(&mut self) -> Result<Option<DiscoveryRecord>> {
        self.state.discovery_dequeue()
    }

    fn begin_stop(self) -> RetiringInventory {
        RetiringInventory::begin(self.state)
    }
}

impl RetiredInventory {
    fn usage_snapshot(&mut self, window: InventoryReadWindow) -> InventoryUsageSnapshot {
        self.state.usage_snapshot(window, true)
    }

    fn discovery_dequeue(&mut self) -> Result<Option<DiscoveryRecord>> {
        self.state.discovery_dequeue()
    }
}

#[derive(Debug, Default)]
struct InventoryHealthSnapshot {
    discovery_counters: Option<[u64; 5]>,
    evidence: Option<[u64; 9]>,
    usage_evidence: Option<[u64; 3]>,
    owner: Option<ThreadOwnerControl>,
    caller_evidence: Option<[u64; 4]>,
    caller_control: Option<p11scope_ebpf_common::ImageIdentityControl>,
    failures: Vec<String>,
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
mod privileged_tests;
#[cfg(test)]
mod tests;
