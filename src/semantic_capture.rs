//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private collect/audit/route/scan orchestration. This does not activate a
//! semantic reducer or alter physical counts (the later activation tasks).
#![cfg_attr(not(test), allow(dead_code))]

use crate::attach::Session;
use crate::attach::capture::{NativeDomainId, ReadWindow};
use crate::attach::image_query::{ImageQueryRefusal, ImageScanProof};
use crate::discovery::identity::PinnedObjectId;
use crate::discovery::instances::{
    CallFacts, EntryIp, InstanceId, InstanceRouter, MAX_INSTANCES, MAX_PENDING, ObserveOutcome,
    Route, RouterLimits, UnknownReason,
};
use crate::process::PidPin;
use p11scope_ebpf_common::{EventRecord, ImageIdentity, event_type};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) struct Endpoint {
    pub(crate) object: PinnedObjectId,
    pub(crate) file_slot: u32,
    pub(crate) offset: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct TickLimits {
    pub(crate) records: usize,
    pub(crate) scans: usize,
    pub(crate) terminal_reads: usize,
    pub(crate) bindings: usize,
    pub(crate) pending_for: Duration,
    pub(crate) scan_slice: Duration,
}
impl Default for TickLimits {
    fn default() -> Self {
        Self {
            records: MAX_PENDING,
            scans: 4,
            terminal_reads: 16,
            bindings: MAX_INSTANCES,
            pending_for: Duration::from_secs(2),
            scan_slice: Duration::from_millis(50),
        }
    }
}

/// Opaque result of the actual audited router; raw inputs never render.
pub(crate) struct RoutedCall {
    domain: NativeDomainId,
    record: EventRecord,
    route: Route,
    endpoint: Option<Endpoint>,
    token: Option<u64>,
}
impl RoutedCall {
    pub(crate) fn token(&self) -> Option<u64> {
        self.token
    }
    pub(crate) fn position(&self) -> Option<u64> {
        self.token
    }
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn record(&self) -> &EventRecord {
        &self.record
    }
    pub(crate) fn image(&self) -> ImageIdentity {
        self.record.event.image
    }
    pub(crate) fn route(&self) -> Route {
        self.route
    }
    pub(crate) fn endpoint(&self) -> Option<Endpoint> {
        self.endpoint
    }
}
impl fmt::Debug for RoutedCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutedCall")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

pub(crate) enum InvalidationScope {
    CoverageFailed,
    AuthorityExhausted,
    FaultEra,
    ImageRetired(ImageIdentity),
    TaskRetired(u64),
    File {
        image: ImageIdentity,
        file_slot: u32,
    },
    InstancesRetired {
        image: ImageIdentity,
        file_slot: u32,
        ids: Vec<InstanceId>,
    },
    Stopped,
}
pub(crate) struct Invalidation {
    domain: NativeDomainId,
    scope: InvalidationScope,
    position: Option<u64>,
}
impl Invalidation {
    pub(crate) fn position(&self) -> Option<u64> {
        self.position
    }
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn scope(&self) -> &InvalidationScope {
        &self.scope
    }
}
impl fmt::Debug for Invalidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match &self.scope {
            InvalidationScope::CoverageFailed => "Invalidation(CoverageFailed)",
            InvalidationScope::AuthorityExhausted => "Invalidation(AuthorityExhausted)",
            InvalidationScope::FaultEra => "Invalidation(FaultEra)",
            InvalidationScope::ImageRetired(_) => "Invalidation(ImageRetired)",
            InvalidationScope::TaskRetired(_) => "Invalidation(TaskRetired)",
            InvalidationScope::File { .. } => "Invalidation(File)",
            InvalidationScope::InstancesRetired { .. } => "Invalidation(InstancesRetired)",
            InvalidationScope::Stopped => "Invalidation(Stopped)",
        })
    }
}
pub(crate) struct OtherRecord {
    domain: NativeDomainId,
    record: EventRecord,
    position: Option<u64>,
}
impl OtherRecord {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn record(&self) -> &EventRecord {
        &self.record
    }
    pub(crate) fn position(&self) -> Option<u64> {
        self.position
    }
}
impl fmt::Debug for OtherRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtherRecord(<private>)")
    }
}
#[derive(Debug)]
pub(crate) enum TickOutcome {
    Call(RoutedCall),
    Invalidation(Invalidation),
    Other(OtherRecord),
}
#[derive(Default, Debug)]
pub(crate) struct TickReport {
    outcomes: Vec<TickOutcome>,
    pub(crate) collected_calls: usize,
    pub(crate) scans: usize,
    pub(crate) observations: Vec<ObserveOutcome>,
    pub(crate) scan_refusals: Vec<ImageQueryRefusal>,
}
impl TickReport {
    pub(crate) fn into_outcomes(self) -> Vec<TickOutcome> {
        self.outcomes
    }
    pub(crate) fn outcomes(&self) -> &[TickOutcome] {
        &self.outcomes
    }
    pub(crate) fn calls(&self) -> impl Iterator<Item = &RoutedCall> {
        self.outcomes.iter().filter_map(|item| match item {
            TickOutcome::Call(call) => Some(call),
            _ => None,
        })
    }
}

#[derive(Clone, Copy)]
struct Health {
    fault: u64,
    sticky: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CollectionStatus {
    Complete,
    Malformed,
    ReadError,
}
struct Collection {
    records: Vec<EventRecord>,
    status: CollectionStatus,
}

struct ScanJob {
    image: ImageIdentity,
    endpoint: Endpoint,
    pin: Arc<PidPin>,
    deadline: Instant,
}
impl ScanJob {
    fn key(&self) -> (u64, u64, u32) {
        (
            self.image.task_cookie,
            self.image.exec_id,
            self.endpoint.file_slot,
        )
    }
}

/// Only I/O is substituted in tests; all decisions use the same tick below.
trait CaptureIo {
    fn domain(&self) -> Option<NativeDomainId>;
    fn now(&self) -> Instant;
    fn collect(&mut self, limit: usize) -> Collection;
    fn health(&mut self) -> Result<Health, ()>;
    fn raise_fault(&mut self) -> Result<(), ()>;
    fn endpoint(&self, slot: u32) -> Option<Endpoint>;
    fn target(&self, pid: u32) -> Option<Arc<PidPin>>;
    fn scan(
        &mut self,
        job: &ScanJob,
        deadline: Instant,
        fence: u64,
        current_fence: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal>;
    fn scan_selected(
        &mut self,
        pin: &Arc<PidPin>,
        endpoint: Endpoint,
        deadline: Instant,
        fence: u64,
        current_fence: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal>;
}

struct SessionIo<'a> {
    session: &'a mut Session,
    targets: &'a [Arc<PidPin>],
}
impl CaptureIo for SessionIo<'_> {
    fn domain(&self) -> Option<NativeDomainId> {
        self.session.native_domain()
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn collect(&mut self, limit: usize) -> Collection {
        let Ok(drain) = self.session.event_drain() else {
            return Collection {
                records: Vec::new(),
                status: CollectionStatus::ReadError,
            };
        };
        let malformed = drain.malformed();
        let mut records = Vec::with_capacity(limit);
        drain.poll_records(Some(limit), |record| {
            records.push(record);
            ControlFlow::Continue(())
        });
        let status = if drain.malformed() != malformed {
            CollectionStatus::Malformed
        } else {
            CollectionStatus::Complete
        };
        Collection { records, status }
    }
    fn health(&mut self) -> Result<Health, ()> {
        self.session.audit_image_continuity().map_err(|_| ())?;
        let maps = self.session.instance_maps();
        Ok(Health {
            fault: maps.fault().map_err(|_| ())?,
            sticky: maps.sticky().map_err(|_| ())?,
        })
    }
    fn raise_fault(&mut self) -> Result<(), ()> {
        self.session
            .instance_maps()
            .raise_fault()
            .map(|_| ())
            .map_err(|_| ())
    }
    fn endpoint(&self, slot: u32) -> Option<Endpoint> {
        self.session.instance_endpoint(slot)
    }
    fn target(&self, pid: u32) -> Option<Arc<PidPin>> {
        self.targets.iter().find(|pin| pin.pid() == pid).cloned()
    }
    fn scan(
        &mut self,
        job: &ScanJob,
        deadline: Instant,
        fence: u64,
        current: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        let window = ReadWindow::new(16_384, deadline).map_err(|_| ImageQueryRefusal::Deadline)?;
        self.session
            .scan_image(&job.pin, job.endpoint.object, window, fence, current)
    }
    fn scan_selected(
        &mut self,
        pin: &Arc<PidPin>,
        endpoint: Endpoint,
        deadline: Instant,
        fence: u64,
        current: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        let window = ReadWindow::new(16_384, deadline).map_err(|_| ImageQueryRefusal::Deadline)?;
        self.session
            .scan_image(pin, endpoint.object, window, fence, current)
    }
}

struct Awaiting {
    record: EventRecord,
    endpoint: Option<Endpoint>,
}
struct TaskBinding {
    domain: NativeDomainId,
    image: ImageIdentity,
    pin: Arc<PidPin>,
    current: bool,
}

/// Only a retained owning binding can mint this proof, and only after the
/// original pidfd itself becomes READY. Retain the Arc through deadbit commit.
pub(crate) struct TerminalTaskProof {
    domain: NativeDomainId,
    cookie: u64,
    _pin: Arc<PidPin>,
}
impl TerminalTaskProof {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn cookie(&self) -> u64 {
        self.cookie
    }
}

pub(crate) struct SemanticCapture {
    router: InstanceRouter,
    limits: TickLimits,
    next_token: u64,
    awaiting: BTreeMap<u64, Awaiting>,
    jobs: VecDeque<ScanJob>,
    bindings: BTreeMap<u64, TaskBinding>,
    terminal_cursor: u64,
    fault: u64,
    sticky: u64,
    image_failed: bool,
    exhausted: bool,
    stopped: bool,
}
impl SemanticCapture {
    pub(crate) fn new(session: &Session, limits: TickLimits) -> anyhow::Result<Self> {
        let domain = session
            .native_domain()
            .ok_or_else(|| anyhow::anyhow!("native image domain unavailable"))?;
        Self::in_domain(domain, limits)
    }
    fn in_domain(domain: NativeDomainId, limits: TickLimits) -> anyhow::Result<Self> {
        anyhow::ensure!(
            limits.records > 0
                && limits.records <= MAX_PENDING
                && limits.scans > 0
                && limits.scans <= MAX_PENDING
                && limits.terminal_reads > 0
                && limits.terminal_reads <= MAX_INSTANCES
                && limits.bindings > 0
                && limits.bindings <= MAX_INSTANCES
                && !limits.pending_for.is_zero()
                && !limits.scan_slice.is_zero(),
            "invalid semantic work limits"
        );
        Ok(Self {
            router: InstanceRouter::new(domain, RouterLimits::default()),
            limits,
            next_token: 1,
            awaiting: BTreeMap::new(),
            jobs: VecDeque::new(),
            bindings: BTreeMap::new(),
            terminal_cursor: 0,
            fault: 0,
            sticky: 0,
            image_failed: false,
            exhausted: false,
            stopped: false,
        })
    }
    pub(crate) fn router(&self) -> &InstanceRouter {
        &self.router
    }
    pub(crate) fn tick(
        &mut self,
        session: &mut Session,
        targets: &[Arc<PidPin>],
    ) -> anyhow::Result<TickReport> {
        anyhow::ensure!(targets.len() <= MAX_PENDING, "semantic target capacity");
        self.tick_with(&mut SessionIo { session, targets })
    }
    /// One bounded no-call refresh through the same owned Session, endpoint
    /// and original pin. The freshly selected image comes only from the seal.
    pub(crate) fn refresh(
        &mut self,
        session: &mut Session,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> anyhow::Result<TickReport> {
        self.refresh_with(
            &mut SessionIo {
                session,
                targets: &[],
            },
            pin,
            slot,
        )
    }
    fn refresh_with(
        &mut self,
        io: &mut impl CaptureIo,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> anyhow::Result<TickReport> {
        anyhow::ensure!(
            io.domain() == Some(self.router.domain()),
            "foreign semantic Session"
        );
        anyhow::ensure!(!self.stopped, "semantic capture stopped");
        let mut report = TickReport::default();
        if !self.audit(io, &mut report) {
            return Ok(report);
        }
        let Some(endpoint) = io.endpoint(slot) else {
            report.scan_refusals.push(ImageQueryRefusal::Coverage);
            return Ok(report);
        };
        let Some(deadline) = io.now().checked_add(self.limits.scan_slice) else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        let fence = self.router.fence();
        report.scans = 1;
        let result = io.scan_selected(&pin, endpoint, deadline, fence, &|| self.router.fence());
        let healthy = self.audit(io, &mut report);
        if io.now() >= deadline {
            report.scan_refusals.push(ImageQueryRefusal::Deadline);
        } else if healthy {
            match result {
                Ok(proof) => {
                    let job = ScanJob {
                        image: proof.image(),
                        endpoint,
                        pin,
                        deadline,
                    };
                    self.accept_scan(proof, &job, fence, &mut report);
                }
                Err(refusal) => report.scan_refusals.push(refusal),
            }
        }
        Ok(report)
    }
    fn emit(
        &self,
        token: Option<u64>,
        record: EventRecord,
        endpoint: Option<Endpoint>,
        route: Route,
        report: &mut TickReport,
    ) {
        report.outcomes.push(TickOutcome::Call(RoutedCall {
            domain: self.router.domain(),
            record,
            route,
            endpoint,
            token,
        }));
    }
    fn allocate_position(&mut self) -> Option<u64> {
        if self.exhausted {
            return None;
        }
        let next = self
            .next_token
            .checked_add(1)
            .filter(|_| self.next_token != 0)?;
        let position = self.next_token;
        self.next_token = next;
        Some(position)
    }
    fn invalidate(&mut self, scope: InvalidationScope, report: &mut TickReport) {
        let position = self.allocate_position();
        report
            .outcomes
            .push(TickOutcome::Invalidation(Invalidation {
                domain: self.router.domain(),
                scope,
                position,
            }));
        if position.is_none() && !self.exhausted {
            self.exhaust(report);
        }
    }
    fn resolve(&mut self, outcomes: Vec<(u64, Route)>, report: &mut TickReport) {
        for (token, route) in outcomes {
            if let Some(waiting) = self.awaiting.remove(&token) {
                self.emit(Some(token), waiting.record, waiting.endpoint, route, report);
            }
        }
    }
    fn fail_coverage(&mut self, io: &mut impl CaptureIo, report: &mut TickReport) {
        if !self.image_failed {
            self.image_failed = true;
            self.invalidate(InvalidationScope::CoverageFailed, report);
            // Permanent router failure does not depend on this ordinary raise.
            let _ = io.raise_fault();
        }
        let resolved = self.router.fail_image_coverage();
        self.resolve(resolved, report);
        self.jobs.clear();
    }
    fn exhaust(&mut self, report: &mut TickReport) {
        if !self.exhausted {
            let position = self.allocate_position();
            self.exhausted = true;
            report
                .outcomes
                .push(TickOutcome::Invalidation(Invalidation {
                    domain: self.router.domain(),
                    scope: InvalidationScope::AuthorityExhausted,
                    position,
                }));
        }
        let resolved = self.router.refuse_exhaustion();
        self.resolve(resolved, report);
        self.jobs.clear();
    }
    fn audit(&mut self, io: &mut impl CaptureIo, report: &mut TickReport) -> bool {
        let Ok(health) = io.health() else {
            self.fail_coverage(io, report);
            return false;
        };
        if health.fault > u64::from(u32::MAX) || health.fault < self.fault {
            self.exhaust(report);
            return false;
        }
        if health.fault != self.fault || health.sticky != self.sticky {
            self.invalidate(InvalidationScope::FaultEra, report);
            self.fault = health.fault;
            self.sticky = health.sticky;
        }
        let resolved = self.router.audit(health.fault, health.sticky, 0);
        self.resolve(resolved, report);
        self.prune_jobs();
        !self.image_failed && !self.exhausted && health.sticky == 0
    }
    fn pending_key(waiting: &Awaiting) -> (u64, u64, u32) {
        let image = waiting.record.event.image;
        (
            image.task_cookie,
            image.exec_id,
            u32::from(waiting.record.continuity.entry_stamp.file_slot_plus1).saturating_sub(1),
        )
    }
    fn prune_jobs(&mut self) {
        let keys: std::collections::BTreeSet<_> =
            self.awaiting.values().map(Self::pending_key).collect();
        self.jobs.retain(|job| keys.contains(&job.key()));
    }
    fn expire(&mut self, image: ImageIdentity, report: &mut TickReport) {
        let resolved = self.router.expire_image(image);
        self.resolve(resolved, report);
    }

    fn refuse_binding(&mut self, image: ImageIdentity, report: &mut TickReport) {
        let resolved = self.router.refuse_image_pending(
            self.router.domain(),
            image,
            UnknownReason::BindingCapacity,
        );
        self.resolve(resolved, report);
        self.prune_jobs();
    }

    fn terminal_tasks(&mut self, report: &mut TickReport) {
        // Cursor advances for errors and nonready pins too; one READY pin
        // with aliases still spends one work unit per cookie association.
        let mut keys: Vec<_> = self
            .bindings
            .range((
                std::ops::Bound::Excluded(self.terminal_cursor),
                std::ops::Bound::Unbounded,
            ))
            .map(|(&cookie, _)| cookie)
            .take(self.limits.terminal_reads)
            .collect();
        if keys.len() < self.limits.terminal_reads {
            keys.extend(
                self.bindings
                    .range(..=self.terminal_cursor)
                    .map(|(&cookie, _)| cookie)
                    .take(self.limits.terminal_reads - keys.len()),
            );
        }
        for cookie in keys {
            self.terminal_cursor = cookie;
            let binding = &self.bindings[&cookie];
            if binding.domain != self.router.domain()
                || binding.pin.pidfd().is_err()
                || !matches!(binding.pin.wait_ready(Some(Duration::ZERO)), Ok(true))
            {
                continue;
            }
            let proof = TerminalTaskProof {
                domain: binding.domain,
                cookie,
                _pin: binding.pin.clone(),
            };
            if let Some(resolved) = self.router.retire_task(proof) {
                self.invalidate(InvalidationScope::TaskRetired(cookie), report);
                self.resolve(resolved, report);
                self.bindings.remove(&cookie); // deadbit committed before pin release
            }
        }
        self.prune_jobs();
    }

    fn accept_scan(
        &mut self,
        proof: ImageScanProof,
        job: &ScanJob,
        fence: u64,
        report: &mut TickReport,
    ) {
        // Production calls this immediately after the fresh synchronous scan
        // and its postscan audit. No deferred seal queue can roll bindings back.
        if proof.domain() != self.router.domain()
            || proof.image() != job.image
            || proof.file_slot() != job.endpoint.file_slot
            || proof.fence() != fence
            || fence != self.router.fence()
        {
            report.scan_refusals.push(ImageQueryRefusal::Fence);
            return;
        }
        if let Some(existing) = self.bindings.get(&job.image.task_cookie) {
            if existing.domain != self.router.domain()
                || !Arc::ptr_eq(&existing.pin, &job.pin)
                || job.image.exec_id < existing.image.exec_id
                || !existing.current
            {
                report.scan_refusals.push(ImageQueryRefusal::Custody);
                return;
            }
        } else if self.bindings.len() >= self.limits.bindings {
            self.refuse_binding(job.image, report);
            return;
        }
        let prior_ids =
            self.router
                .current_instances(self.router.domain(), job.image, job.endpoint.file_slot);
        let (outcome, resolved) = self.router.observe(proof);
        let accepted = matches!(outcome, ObserveOutcome::New | ObserveOutcome::Continued);
        // These losses come from the actual eviction, not a counter inference.
        for loss in self.router.take_observation_losses() {
            self.invalidate(
                InvalidationScope::InstancesRetired {
                    image: loss.image,
                    file_slot: loss.file_slot,
                    ids: loss.ids,
                },
                report,
            );
        }
        if outcome == ObserveOutcome::New && !prior_ids.is_empty() {
            self.invalidate(
                InvalidationScope::InstancesRetired {
                    image: job.image,
                    file_slot: job.endpoint.file_slot,
                    ids: prior_ids,
                },
                report,
            );
        }
        if outcome == ObserveOutcome::CoverageFault {
            self.invalidate(
                InvalidationScope::File {
                    image: job.image,
                    file_slot: job.endpoint.file_slot,
                },
                report,
            );
        }
        if accepted && !self.exhausted {
            let prior: Vec<_> = self
                .bindings
                .values()
                .filter(|binding| {
                    binding.current
                        && binding.image != job.image
                        && Arc::ptr_eq(&binding.pin, &job.pin)
                })
                .map(|binding| binding.image)
                .collect();
            for image in prior {
                self.bindings
                    .get_mut(&image.task_cookie)
                    .expect("retained binding")
                    .current = false;
                let retired = self.router.retire_image(image);
                self.invalidate(InvalidationScope::ImageRetired(image), report);
                self.resolve(retired, report);
            }
            self.bindings.insert(
                job.image.task_cookie,
                TaskBinding {
                    domain: self.router.domain(),
                    image: job.image,
                    pin: job.pin.clone(),
                    current: true,
                },
            );
        }
        report.observations.push(outcome);
        // Invalidation exhaustion cannot leak a previously computed join.
        if self.exhausted {
            self.resolve(
                resolved
                    .into_iter()
                    .map(|(token, _)| (token, Route::Unknown(UnknownReason::AuthorityExhausted)))
                    .collect(),
                report,
            );
        } else {
            self.resolve(resolved, report);
        }
    }
    fn tick_with(&mut self, io: &mut impl CaptureIo) -> anyhow::Result<TickReport> {
        anyhow::ensure!(
            io.domain() == Some(self.router.domain()),
            "foreign semantic Session"
        );
        anyhow::ensure!(!self.stopped, "semantic capture stopped");
        let mut report = TickReport::default();
        let mut collected = io.collect(self.limits.records);
        let collection_failed = collected.status != CollectionStatus::Complete
            || collected.records.len() > self.limits.records;
        collected.records.truncate(self.limits.records);
        // Positions belong to first collection, including noncalls. Pending
        // resolutions retain them; delivery order is deliberately not FIFO.
        let batch: Vec<_> = collected
            .records
            .into_iter()
            .map(|record| {
                let position = self.allocate_position();
                if position.is_none() {
                    self.exhaust(&mut report);
                }
                (position, record)
            })
            .collect();
        // A malformed/read-error prefix still contains genuine consumed
        // records. Keep their positions, then forbid every positive route.
        if collection_failed {
            self.fail_coverage(io, &mut report);
        }
        // Collection never routes; every batch (including empty batches) audits.
        let _ = self.audit(io, &mut report);
        self.terminal_tasks(&mut report);
        for (position, record) in batch {
            if record.event.event_type != event_type::CALL {
                report.outcomes.push(TickOutcome::Other(OtherRecord {
                    domain: self.router.domain(),
                    record,
                    position,
                }));
                continue;
            }
            report.collected_calls += 1;
            let endpoint = io.endpoint(record.event.slot);
            let Some(token) = position else {
                self.emit(
                    None,
                    record,
                    endpoint,
                    Route::Unknown(UnknownReason::AuthorityExhausted),
                    &mut report,
                );
                continue;
            };
            if endpoint.is_none_or(|ep| {
                u32::from(record.continuity.entry_stamp.file_slot_plus1) != ep.file_slot + 1
            }) {
                self.emit(
                    Some(token),
                    record,
                    endpoint,
                    Route::Unknown(UnknownReason::NoFile),
                    &mut report,
                );
                continue;
            }
            let facts = CallFacts {
                token,
                domain: self.router.domain(),
                image: record.event.image,
                entry: record.continuity.entry_stamp,
                ret: record.continuity.return_stamp,
                ip: EntryIp::new(record.continuity.entry_ip),
                attached_offset: endpoint.map(|e| e.offset),
            };
            let route = self.router.route(facts);
            if route != Route::Pending {
                self.emit(Some(token), record, endpoint, route, &mut report);
                continue;
            }
            self.awaiting.insert(token, Awaiting { record, endpoint });
            let image = record.event.image;
            if !self.bindings.contains_key(&image.task_cookie)
                && self.bindings.len() >= self.limits.bindings
            {
                self.refuse_binding(image, &mut report);
                continue;
            }
            let Some(pin) = io.target((record.event.pid_tgid >> 32) as u32) else {
                self.expire(image, &mut report);
                continue;
            };
            let endpoint = endpoint.expect("checked owned endpoint");
            let key = (image.task_cookie, image.exec_id, endpoint.file_slot);
            if !self.jobs.iter().any(|job| job.key() == key) {
                let Some(deadline) = io.now().checked_add(self.limits.pending_for) else {
                    self.exhaust(&mut report);
                    continue;
                };
                self.jobs.push_back(ScanJob {
                    image,
                    endpoint,
                    pin,
                    deadline,
                });
            }
        }
        self.prune_jobs();
        let expired: Vec<_> = self
            .jobs
            .iter()
            .filter(|job| io.now() >= job.deadline)
            .map(|job| job.image)
            .collect();
        for image in expired {
            self.expire(image, &mut report);
        }
        self.prune_jobs();
        // Visit each initial queued job at most once. Refused peers rotate.
        let attempts = self.limits.scans.min(self.jobs.len());
        for _ in 0..attempts {
            let Some(job) = self.jobs.pop_front() else {
                break;
            };
            if io.now() >= job.deadline {
                self.expire(job.image, &mut report);
                continue;
            }
            report.scans += 1;
            let fence = self.router.fence();
            let Some(slice_end) = io.now().checked_add(self.limits.scan_slice) else {
                self.exhaust(&mut report);
                break;
            };
            let attempt_deadline = slice_end.min(job.deadline);
            let result = io.scan(&job, attempt_deadline, fence, &|| self.router.fence());
            let healthy = self.audit(io, &mut report);
            if io.now() >= job.deadline {
                self.expire(job.image, &mut report);
            } else if healthy && io.now() < attempt_deadline {
                match result {
                    Ok(proof) => {
                        self.accept_scan(proof, &job, fence, &mut report);
                    }
                    Err(refusal) => report.scan_refusals.push(refusal),
                }
            }
            if self
                .awaiting
                .values()
                .any(|waiting| Self::pending_key(waiting) == job.key())
            {
                self.jobs.push_back(job);
            }
        }
        Ok(report)
    }
    pub(crate) fn stop(&mut self) -> TickReport {
        let mut report = TickReport::default();
        if self.stopped {
            return report;
        }
        self.stopped = true;
        self.invalidate(InvalidationScope::Stopped, &mut report);
        let images: Vec<_> = self
            .awaiting
            .values()
            .map(|w| w.record.event.image)
            .collect();
        for image in images {
            self.expire(image, &mut report);
        }
        self.jobs.clear();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::image_query::{CompleteEpochs, acquire_test_scan};
    use crate::discovery::instances::MapRange;
    use p11scope_ebpf_common::{InstanceStamp, instance};

    struct ScriptIo {
        domain: NativeDomainId,
        now: Instant,
        records: VecDeque<EventRecord>,
        health: VecDeque<Result<Health, ()>>,
        last_health: Health,
        pin: Arc<PidPin>,
        fail_cookie: Option<u64>,
        attempts: Vec<(u64, Instant)>,
        raises: usize,
        raise_fails: bool,
        local: u32,
        output_image: Option<ImageIdentity>,
        output_file: Option<u32>,
        scan_advance: Duration,
        collection_status: CollectionStatus,
        extra_range: bool,
    }
    impl ScriptIo {
        fn new(domain: NativeDomainId) -> Self {
            Self {
                domain,
                now: Instant::now(),
                records: VecDeque::new(),
                health: VecDeque::new(),
                last_health: Health {
                    fault: 0,
                    sticky: 0,
                },
                pin: Arc::new(PidPin::open(std::process::id()).unwrap()),
                fail_cookie: None,
                attempts: Vec::new(),
                raises: 0,
                raise_fails: false,
                local: 0,
                output_image: None,
                output_file: None,
                scan_advance: Duration::ZERO,
                collection_status: CollectionStatus::Complete,
                extra_range: false,
            }
        }
        fn call_image(&mut self, cookie: u64, exec_id: u64, fault: u32) {
            self.call(cookie, fault);
            self.records.back_mut().unwrap().event.image.exec_id = exec_id;
        }
        fn call(&mut self, cookie: u64, fault: u32) {
            let stamp = InstanceStamp {
                flags: instance::STAMP_VALID,
                file_slot_plus1: 1,
                fault,
                epoch: self.local,
                global: 0,
            };
            self.records.push_back(EventRecord {
                event: p11scope_ebpf_common::Event {
                    event_type: event_type::CALL,
                    image: ImageIdentity {
                        task_cookie: cookie,
                        exec_id: 1,
                    },
                    pid_tgid: u64::from(self.pin.pid()) << 32,
                    ..Default::default()
                },
                continuity: p11scope_ebpf_common::InstanceContinuity {
                    entry_stamp: stamp,
                    return_stamp: stamp,
                    entry_ip: 0x2200,
                },
            });
        }
    }
    impl CaptureIo for ScriptIo {
        fn domain(&self) -> Option<NativeDomainId> {
            Some(self.domain)
        }
        fn now(&self) -> Instant {
            self.now
        }
        fn collect(&mut self, limit: usize) -> Collection {
            Collection {
                records: (0..limit)
                    .filter_map(|_| self.records.pop_front())
                    .collect(),
                status: std::mem::replace(&mut self.collection_status, CollectionStatus::Complete),
            }
        }
        fn health(&mut self) -> Result<Health, ()> {
            let result = self.health.pop_front().unwrap_or(Ok(self.last_health));
            if let Ok(health) = result {
                self.last_health = health;
            }
            result
        }
        fn raise_fault(&mut self) -> Result<(), ()> {
            self.raises += 1;
            if self.raise_fails { Err(()) } else { Ok(()) }
        }
        fn endpoint(&self, slot: u32) -> Option<Endpoint> {
            (slot == 0).then_some(Endpoint {
                object: PinnedObjectId(0),
                file_slot: 0,
                offset: 0x1200,
            })
        }
        fn target(&self, _: u32) -> Option<Arc<PidPin>> {
            Some(self.pin.clone())
        }
        fn scan(
            &mut self,
            job: &ScanJob,
            deadline: Instant,
            fence: u64,
            _: &dyn Fn() -> u64,
        ) -> Result<ImageScanProof, ImageQueryRefusal> {
            self.attempts.push((job.image.task_cookie, deadline));
            self.now += self.scan_advance;
            if self.fail_cookie == Some(job.image.task_cookie) {
                return Err(ImageQueryRefusal::Unstable);
            }
            let mut ranges = vec![
                MapRange::new(0x1000, 0x2000, 0, false),
                MapRange::new(0x2000, 0x3000, 0x1000, true),
            ];
            if self.extra_range {
                ranges.push(MapRange::new(0x4000, 0x5000, 0, false));
            }
            acquire_test_scan(
                self.domain,
                self.output_image.unwrap_or(job.image),
                self.output_file.unwrap_or(0),
                CompleteEpochs {
                    local: u64::from(self.local),
                    global: 0,
                    fault: self.last_health.fault,
                    sticky: 0,
                    record_flags: 0,
                },
                ranges,
                fence,
            )
        }
        fn scan_selected(
            &mut self,
            pin: &Arc<PidPin>,
            endpoint: Endpoint,
            deadline: Instant,
            fence: u64,
            current: &dyn Fn() -> u64,
        ) -> Result<ImageScanProof, ImageQueryRefusal> {
            let job = ScanJob {
                image: self.output_image.unwrap_or(ImageIdentity {
                    task_cookie: 1,
                    exec_id: 1,
                }),
                endpoint,
                pin: pin.clone(),
                deadline,
            };
            self.scan(&job, deadline, fence, current)
        }
    }
    fn capture(io: &ScriptIo) -> SemanticCapture {
        SemanticCapture::in_domain(io.domain, TickLimits::default()).unwrap()
    }
    fn prime(capture: &mut SemanticCapture, io: &mut ScriptIo) -> Route {
        io.call(1, 0);
        let report = capture.tick_with(io).unwrap();
        assert_eq!(report.calls().count(), 1);
        assert_eq!(capture.router.ranges_retained(), 2);
        assert!(matches!(
            report.calls().next().unwrap().route(),
            Route::Joined(_)
        ));
        report.calls().next().unwrap().route()
    }
    #[test]
    fn healthy_nonempty_tick_and_cached_join_use_one_instance() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        let joined = prime(&mut capture, &mut io);
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert_eq!(report.calls().count(), 1);
        assert_eq!(report.calls().next().unwrap().route(), joined);
        let call = report.calls().next().unwrap();
        assert_eq!(call.position(), call.token());
        assert_eq!(call.domain(), io.domain);
        let endpoint = call.endpoint().expect("retained owned endpoint");
        assert_eq!(endpoint.file_slot, 0);
        assert_eq!(endpoint.offset, 0x1200);
        assert_eq!(capture.router.instances_minted(), 1);
    }
    #[test]
    fn pump_miss_invalidates_before_next_semantic_join_even_when_raise_fails() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        prime(&mut capture, &mut io);
        io.raise_fails = true;
        io.health.push_back(Err(()));
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert_eq!(
            report.calls().next().unwrap().route(),
            Route::Unknown(UnknownReason::CoverageFault)
        );
        assert_eq!(io.raises, 1);
        io.last_health.fault = 1;
        io.call(1, 1);
        assert_eq!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            Route::Unknown(UnknownReason::CoverageFault)
        );
    }
    #[test]
    fn postscan_fault_rejects_original_fence_then_fresh_call_succeeds() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.health.extend([
            Ok(Health {
                fault: 0,
                sticky: 0,
            }),
            Ok(Health {
                fault: 1,
                sticky: 0,
            }),
        ]);
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert_eq!(
            report.calls().next().unwrap().route(),
            Route::Unknown(UnknownReason::FaultEra)
        );
        assert_eq!(capture.router.instances_minted(), 0);
        io.call(1, 1);
        let report = capture.tick_with(&mut io).unwrap();
        assert!(matches!(
            report.calls().next().unwrap().route(),
            Route::Joined(_)
        ));
    }
    #[test]
    fn unstable_job_cannot_starve_a_healthy_peer() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.fail_cookie = Some(1);
        io.call(1, 0);
        io.call(2, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert!(
            report
                .calls()
                .any(|r| r.image().task_cookie == 2 && matches!(r.route(), Route::Joined(_)))
        );
        assert_eq!(
            io.attempts.iter().map(|a| a.0).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }
    #[test]
    fn original_deadline_expires_on_empty_batch_once() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.fail_cookie = Some(1);
        io.call(1, 0);
        assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
        let deadline = capture.jobs[0].deadline;
        io.now = deadline;
        let report = capture.tick_with(&mut io).unwrap();
        assert_eq!(report.calls().count(), 1);
        assert_eq!(
            report.calls().next().unwrap().route(),
            Route::Unknown(UnknownReason::Unobserved)
        );
        assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
        assert_eq!(capture.router.pending_len(), 0);
    }
    #[test]
    fn token_exhaustion_refuses_without_wrap_or_duplicate_outcome() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        capture.next_token = u64::MAX;
        io.call(1, 0);
        io.call(2, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert_eq!(report.calls().count(), 2);
        assert!(
            report
                .calls()
                .all(|r| r.route() == Route::Unknown(UnknownReason::AuthorityExhausted))
        );
        assert_eq!(capture.next_token, u64::MAX);
        assert_eq!(capture.router.instances_minted(), 0);
    }
    #[test]
    fn deadline_overflow_is_ordinary_permanent_refusal() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        capture.limits.pending_for = Duration::MAX;
        io.call(1, 0);
        let report = capture.tick_with(&mut io).unwrap();
        assert_eq!(
            report.calls().next().unwrap().route(),
            Route::Unknown(UnknownReason::AuthorityExhausted)
        );
        assert_eq!(capture.router.instances_minted(), 0);
    }
    #[test]
    fn stop_drains_pending_once_without_late_authority() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.fail_cookie = Some(1);
        io.call(1, 0);
        assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
        let stopped = capture.stop();
        assert_eq!(stopped.calls().count(), 1);
        assert_eq!(
            stopped.calls().next().unwrap().route(),
            Route::Unknown(UnknownReason::Unobserved)
        );
        assert!(capture.stop().calls().next().is_none());
    }
    #[test]
    fn foreign_session_refuses_before_collection_or_state_mutation() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        io.domain = NativeDomainId::mint();
        io.call(1, 0);
        assert!(capture.tick_with(&mut io).is_err());
        assert_eq!(io.records.len(), 1);
        assert_eq!(capture.next_token, 1);
        assert_eq!(capture.router.instances_minted(), 0);
    }
    #[test]
    fn refresh_checks_owning_session_and_endpoint_before_scan() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        let pin = io.pin.clone();
        let owner = io.domain;
        io.domain = NativeDomainId::mint();
        assert!(capture.refresh_with(&mut io, pin.clone(), 0).is_err());
        assert!(io.attempts.is_empty());
        io.domain = owner;
        let refused = capture.refresh_with(&mut io, pin.clone(), 99).unwrap();
        assert_eq!(refused.scan_refusals, vec![ImageQueryRefusal::Coverage]);
        assert!(io.attempts.is_empty());
        let healthy = capture.refresh_with(&mut io, pin, 0).unwrap();
        assert_eq!(healthy.observations, vec![ObserveOutcome::New]);
        assert_eq!(capture.router.instances_minted(), 1);
        assert_eq!(capture.router.ranges_retained(), 2);
        assert!(healthy.outcomes().is_empty());
    }
    #[test]
    fn refresh_requires_pre_and_post_health_and_original_fence() {
        for before in [true, false] {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            let pin = io.pin.clone();
            if before {
                io.health.push_back(Err(()));
            } else {
                io.health.extend([
                    Ok(io.last_health),
                    Ok(Health {
                        fault: 1,
                        sticky: 0,
                    }),
                ]);
            }
            let report = capture.refresh_with(&mut io, pin.clone(), 0).unwrap();
            assert_eq!(report.scans, usize::from(!before));
            assert!(report.observations.is_empty());
            assert!(capture.bindings.is_empty());
            assert_eq!(capture.router.instances_minted(), 0);
            assert!(
                report
                    .outcomes()
                    .iter()
                    .any(|o| matches!(o, TickOutcome::Invalidation(_)))
            );
            if !before {
                let fresh = capture.refresh_with(&mut io, pin, 0).unwrap();
                assert_eq!(fresh.observations, vec![ObserveOutcome::New]);
                assert_eq!(capture.router.ranges_retained(), 2);
            }
        }
    }
    fn decoded_prefix_survives_failure(status: CollectionStatus) {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        prime(&mut capture, &mut io);
        io.call(1, 0);
        io.records.push_back(EventRecord {
            event: p11scope_ebpf_common::Event {
                event_type: u32::MAX,
                session: 0xfeed_1234_5678_9abc,
                ..Default::default()
            },
            ..Default::default()
        });
        io.collection_status = status;
        let report = capture.tick_with(&mut io).unwrap();
        assert_eq!(report.collected_calls, 1);
        assert_eq!(report.calls().count(), 1);
        let call = report.calls().next().unwrap();
        assert_eq!(call.route(), Route::Unknown(UnknownReason::CoverageFault));
        assert_eq!(call.position(), Some(2));
        let other = report
            .outcomes()
            .iter()
            .find_map(|o| match o {
                TickOutcome::Other(other) => Some(other),
                _ => None,
            })
            .unwrap();
        assert_eq!(other.position(), Some(3));
        assert_eq!(other.record().event.session, 0xfeed_1234_5678_9abc);
        let loss = report
            .outcomes()
            .iter()
            .find_map(|o| match o {
                TickOutcome::Invalidation(loss) => Some(loss),
                _ => None,
            })
            .unwrap();
        assert!(matches!(loss.scope(), InvalidationScope::CoverageFailed));
        assert_eq!(loss.domain(), io.domain);
        assert_eq!(loss.position(), Some(4));
        assert!(matches!(report.outcomes()[0], TickOutcome::Invalidation(_)));
        assert_eq!(report.scans, 0);
        assert_eq!(capture.router.instances_minted(), 1);
        assert!(capture.tick_with(&mut io).unwrap().outcomes().is_empty());
        io.last_health.fault = 1;
        io.call(1, 1);
        let later = capture.tick_with(&mut io).unwrap();
        assert_eq!(later.calls().count(), 1);
        assert_eq!(
            later.calls().next().unwrap().route(),
            Route::Unknown(UnknownReason::CoverageFault)
        );
        assert_eq!(later.scans, 0);
        assert_eq!(capture.router.instances_minted(), 1);
    }
    #[test]
    fn malformed_collection_preserves_decoded_calls_and_other_once() {
        decoded_prefix_survives_failure(CollectionStatus::Malformed);
    }
    #[test]
    fn partial_read_error_preserves_decoded_calls_and_other_once() {
        // Session currently fails to obtain its cursor before reading any
        // prefix. This I/O seam also preserves prefixes of future read errors.
        decoded_prefix_survives_failure(CollectionStatus::ReadError);
    }
    #[test]
    fn unchanged_epoch_range_appearance_emits_exact_owned_file_loss() {
        let mut io = ScriptIo::new(NativeDomainId::mint());
        let mut capture = capture(&io);
        prime(&mut capture, &mut io);
        io.extra_range = true;
        let pin = io.pin.clone();
        let report = capture.refresh_with(&mut io, pin, 0).unwrap();
        assert_eq!(report.observations, vec![ObserveOutcome::CoverageFault]);
        let loss = report
            .outcomes()
            .iter()
            .find_map(|o| match o {
                TickOutcome::Invalidation(loss) => Some(loss),
                _ => None,
            })
            .unwrap();
        assert_eq!(loss.domain(), io.domain);
        assert!(
            matches!(loss.scope(), InvalidationScope::File { image, file_slot }
            if *image == (ImageIdentity { task_cookie: 1, exec_id: 1 }) && *file_slot == 0)
        );
        io.call(1, 0);
        assert_eq!(
            capture
                .tick_with(&mut io)
                .unwrap()
                .calls()
                .next()
                .unwrap()
                .route(),
            Route::Unknown(UnknownReason::CoverageFault)
        );
        assert_eq!(capture.router.instances_minted(), 1);
    }
    mod authority_controls {
        use super::*;
        struct ChildGuard(std::process::Child);
        impl ChildGuard {
            fn spawn() -> (Self, Arc<PidPin>) {
                let child = Self(
                    std::process::Command::new("sleep")
                        .arg("30")
                        .spawn()
                        .unwrap(),
                );
                let pin = Arc::new(PidPin::open(child.0.id()).unwrap());
                (child, pin)
            }
            fn end(&mut self) {
                self.0.kill().unwrap();
                self.0.wait().unwrap();
            }
        }
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        #[test]
        fn binding_capacity_is_once_only_and_keeps_existing_live_join() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            capture.limits.bindings = 1;
            let joined = prime(&mut capture, &mut io);
            io.call(2, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert_eq!(report.calls().count(), 1);
            assert_eq!(
                report.calls().next().unwrap().route(),
                Route::Unknown(UnknownReason::BindingCapacity)
            );
            assert_eq!(capture.bindings.len(), 1);
            assert_eq!(capture.router.pending_len(), 0);
            assert!(capture.jobs.is_empty());
            assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
            io.call(1, 0);
            assert_eq!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .next()
                    .unwrap()
                    .route(),
                joined
            );
        }
        #[test]
        fn proven_original_death_releases_capacity_after_permanent_retirement() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let (mut child, pin) = ChildGuard::spawn();
            io.pin = pin.clone();
            let mut capture = capture(&io);
            capture.limits.bindings = 1;
            prime(&mut capture, &mut io);
            child.end();
            assert!(pin.wait_ready(Some(Duration::ZERO)).unwrap());
            let report = capture.tick_with(&mut io).unwrap();
            assert!(
                report
                    .outcomes()
                    .iter()
                    .any(|o| matches!(o, TickOutcome::Invalidation(i)
                if matches!(i.scope(), InvalidationScope::TaskRetired(1))))
            );
            assert!(capture.bindings.is_empty());
            io.pin = Arc::new(PidPin::open(std::process::id()).unwrap());
            io.call(2, 0);
            assert!(matches!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .next()
                    .unwrap()
                    .route(),
                Route::Joined(_)
            ));
            io.call(1, 0);
            assert_eq!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .next()
                    .unwrap()
                    .route(),
                Route::Unknown(UnknownReason::Retired)
            );
            assert_eq!(capture.bindings.len(), 1);
        }
        #[test]
        fn nonready_binding_preserves_the_original_pin_and_cached_positive() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            let joined = prime(&mut capture, &mut io);
            for _ in 0..3 {
                assert!(capture.tick_with(&mut io).unwrap().outcomes().iter().all(|o|
                    !matches!(o, TickOutcome::Invalidation(i) if matches!(i.scope(), InvalidationScope::TaskRetired(_)))));
            }
            assert!(Arc::ptr_eq(&capture.bindings[&1].pin, &io.pin));
            io.call(1, 0);
            assert_eq!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .next()
                    .unwrap()
                    .route(),
                joined
            );
        }
        #[test]
        fn terminal_quota_rotates_past_a_live_prefix_on_empty_batches() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            capture.limits.terminal_reads = 1;
            prime(&mut capture, &mut io);
            let (mut child, pin) = ChildGuard::spawn();
            io.pin = pin;
            io.call(2, 0);
            assert!(matches!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .next()
                    .unwrap()
                    .route(),
                Route::Joined(_)
            ));
            child.end();
            let a = capture.tick_with(&mut io).unwrap();
            let b = capture.tick_with(&mut io).unwrap();
            assert!(
                a.outcomes()
                    .iter()
                    .chain(b.outcomes())
                    .any(|o| matches!(o, TickOutcome::Invalidation(i)
                if matches!(i.scope(), InvalidationScope::TaskRetired(2))))
            );
            assert!(capture.bindings.contains_key(&1));
            assert!(!capture.bindings.contains_key(&2));
        }
        #[test]
        fn live_binding_is_never_replaced_by_a_new_pin() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            prime(&mut capture, &mut io);
            let original = io.pin.clone();
            io.pin = Arc::new(PidPin::open(std::process::id()).unwrap());
            io.local = 1;
            io.call(1, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert!(
                !report
                    .calls()
                    .any(|r| matches!(r.route(), Route::Joined(_)))
            );
            assert!(Arc::ptr_eq(&capture.bindings[&1].pin, &original));
            assert_eq!(capture.router.instances_minted(), 1);
        }
        #[test]
        fn scan_identity_and_file_mismatch_cannot_mint_or_bind() {
            for file in [false, true] {
                let mut io = ScriptIo::new(NativeDomainId::mint());
                let mut capture = capture(&io);
                if file {
                    io.output_file = Some(1);
                } else {
                    io.output_image = Some(ImageIdentity {
                        task_cookie: 2,
                        exec_id: 1,
                    });
                }
                io.call(1, 0);
                let report = capture.tick_with(&mut io).unwrap();
                assert!(
                    !report
                        .calls()
                        .any(|r| matches!(r.route(), Route::Joined(_)))
                );
                assert_eq!(capture.router.instances_minted(), 0);
                assert!(capture.bindings.is_empty());
            }
        }
        #[test]
        fn scan_slice_is_bounded_and_coalescing_keeps_original_deadline() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            io.fail_cookie = Some(1);
            io.call(1, 0);
            capture.tick_with(&mut io).unwrap();
            let original = capture.jobs[0].deadline;
            assert!(io.attempts[0].1 <= io.now.checked_add(capture.limits.scan_slice).unwrap());
            io.now += Duration::from_millis(1);
            io.call(1, 0);
            capture.tick_with(&mut io).unwrap();
            assert_eq!(capture.jobs.len(), 1);
            assert_eq!(capture.jobs[0].deadline, original);
            assert_eq!(capture.awaiting.len(), 2);
        }
        #[test]
        fn noncall_record_is_preserved_in_the_single_private_stream() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            io.records.push_back(EventRecord {
                event: p11scope_ebpf_common::Event {
                    event_type: u32::MAX,
                    image: ImageIdentity {
                        task_cookie: 9,
                        exec_id: 99,
                    },
                    session: 0xfeed_1234_5678_9abc,
                    ..Default::default()
                },
                ..Default::default()
            });
            let report = capture.tick_with(&mut io).unwrap();
            let other = report
                .outcomes()
                .iter()
                .find_map(|o| match o {
                    TickOutcome::Other(r) => Some(r),
                    _ => None,
                })
                .expect("one retained noncall");
            assert_eq!(other.domain(), io.domain);
            assert_eq!(other.position(), Some(1));
            assert_eq!(other.record().event.session, 0xfeed_1234_5678_9abc);
            let debug = format!("{report:?}");
            assert!(!debug.contains("feed") && !debug.contains("183693"));
        }
        #[test]
        fn audit_invalidation_precedes_calls_and_keeps_pending_token_original() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            io.fail_cookie = Some(1);
            io.call(1, 0);
            capture.tick_with(&mut io).unwrap();
            let pending_token = *capture.awaiting.keys().next().unwrap();
            io.health.push_back(Err(()));
            io.call(1, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert!(matches!(report.outcomes()[0], TickOutcome::Invalidation(_)));
            let tokens: Vec<_> = report.calls().map(|r| r.token()).collect();
            assert_eq!(tokens, vec![Some(pending_token), Some(pending_token + 1)]);
            assert!(report.calls().all(|r| r.domain() == io.domain
                && r.route() == Route::Unknown(UnknownReason::CoverageFault)));
        }
        #[test]
        fn shared_positions_do_not_alias_invalidations_and_collected_calls() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            prime(&mut capture, &mut io);
            io.health.push_back(Err(()));
            io.call(1, 0);
            let report = capture.tick_with(&mut io).unwrap();
            let invalidation = report
                .outcomes()
                .iter()
                .find_map(|o| match o {
                    TickOutcome::Invalidation(i) => Some(i),
                    _ => None,
                })
                .unwrap();
            assert_eq!(report.calls().next().unwrap().token(), Some(2));
            assert_eq!(invalidation.position(), Some(3));
            assert_ne!(
                invalidation.position(),
                report.calls().next().unwrap().token()
            );
        }
        #[test]
        fn late_scan_result_cannot_consume_or_bind_after_its_slice() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            io.scan_advance = capture.limits.scan_slice + Duration::from_millis(1);
            io.call(1, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert!(
                !report
                    .calls()
                    .any(|r| matches!(r.route(), Route::Joined(_)))
            );
            assert_eq!(capture.router.instances_minted(), 0);
            assert!(capture.bindings.is_empty());
            assert_eq!(capture.jobs.len(), 1);
        }

        #[test]
        fn initial_pending_positive_does_not_invent_a_loss_barrier() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            io.call(1, 0);
            io.call(1, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert_eq!(report.calls().count(), 2);
            assert!(
                report
                    .calls()
                    .all(|call| matches!(call.route(), Route::Joined(_)))
            );
            assert!(
                !report
                    .outcomes()
                    .iter()
                    .any(|o| matches!(o, TickOutcome::Invalidation(_)))
            );
            assert_eq!(capture.router.instances_minted(), 1);
        }
        #[test]
        fn accepted_epoch_change_retires_only_prior_ids_and_keeps_late_history() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            let Route::Joined(old) = prime(&mut capture, &mut io) else {
                unreachable!()
            };
            io.local = 1;
            io.call(1, 0);
            let report = capture.tick_with(&mut io).unwrap();
            let Route::Joined(new) = report.calls().next().unwrap().route() else {
                panic!("new epoch joins")
            };
            assert_ne!(new, old);
            let retired = report
                .outcomes()
                .iter()
                .find_map(|outcome| match outcome {
                    TickOutcome::Invalidation(change) => match change.scope() {
                        InvalidationScope::InstancesRetired {
                            image,
                            file_slot,
                            ids,
                        } => Some((*image, *file_slot, ids)),
                        _ => None,
                    },
                    _ => None,
                })
                .expect("exact previous partitions retired");
            assert_eq!(
                retired.0,
                ImageIdentity {
                    task_cookie: 1,
                    exec_id: 1
                }
            );
            assert_eq!(retired.1, 0);
            assert_eq!(retired.2, &vec![old]);
            assert!(!retired.2.contains(&new));
            assert!(matches!(report.outcomes()[0], TickOutcome::Invalidation(_)));
            // Delivery after the boundary can still be a historical native call;
            // the explicit ended ID prevents consumers treating it as current.
            io.local = 0;
            io.call(1, 0);
            assert_eq!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .next()
                    .unwrap()
                    .route(),
                Route::Joined(old)
            );
        }
        #[test]
        fn observation_eviction_emits_exact_old_ids_as_typed_loss() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            capture.router = InstanceRouter::new(
                io.domain,
                RouterLimits {
                    observed_keys: 1,
                    ..Default::default()
                },
            );
            let Route::Joined(old) = prime(&mut capture, &mut io) else {
                unreachable!()
            };
            io.call(2, 0);
            let report = capture.tick_with(&mut io).unwrap();
            assert!(
                report
                    .calls()
                    .any(|r| matches!(r.route(), Route::Joined(id) if id != old))
            );
            assert!(report.outcomes().iter().any(
                |o| matches!(o, TickOutcome::Invalidation(change)
                if matches!(change.scope(), InvalidationScope::InstancesRetired { image, ids, .. }
                    if image.task_cookie == 1 && ids == &vec![old]))
            ));
        }

        mod successor_controls {
            use super::*;
            #[test]
            fn same_original_pin_cross_cookie_successor_retires_images_once() {
                let mut io = ScriptIo::new(NativeDomainId::mint());
                let mut capture = capture(&io);
                io.call_image(1, 1_000_000, 0);
                let first = capture.tick_with(&mut io).unwrap();
                let Route::Joined(old) = first.calls().next().unwrap().route() else {
                    panic!("old nonempty positive")
                };
                io.local = 1;
                io.fail_cookie = Some(1);
                io.call_image(1, 1_000_000, 0);
                assert!(capture.tick_with(&mut io).unwrap().calls().next().is_none());
                io.local = 0;
                io.call_image(2, 0, 0);
                let report = capture.tick_with(&mut io).unwrap();
                let images: Vec<_> = report
                    .outcomes()
                    .iter()
                    .filter_map(|outcome| match outcome {
                        TickOutcome::Invalidation(i) => match i.scope() {
                            InvalidationScope::ImageRetired(image) => Some(*image),
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    images,
                    vec![ImageIdentity {
                        task_cookie: 1,
                        exec_id: 1_000_000
                    }]
                );
                assert!(report.calls().any(|call| call.image().task_cookie == 1
                    && call.route() == Route::Unknown(UnknownReason::Retired)));
                assert!(report.calls().any(|call| call.image().task_cookie == 2
                    && matches!(call.route(), Route::Joined(id) if id != old)));
                assert!(
                    report
                        .outcomes()
                        .iter()
                        .all(|outcome| !matches!(outcome, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::TaskRetired(_))))
                );
                assert_eq!(capture.bindings.len(), 2);
                assert!(Arc::ptr_eq(
                    &capture.bindings[&1].pin,
                    &capture.bindings[&2].pin
                ));
                io.call_image(2, 0, 0);
                let again = capture.tick_with(&mut io).unwrap();
                assert!(
                    again
                        .calls()
                        .any(|call| matches!(call.route(), Route::Joined(_)))
                );
                assert!(
                    again
                        .outcomes()
                        .iter()
                        .all(|outcome| !matches!(outcome, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(_))))
                );
            }
            #[test]
            fn same_cookie_forward_exec_never_rolls_back_to_an_old_proof() {
                let mut io = ScriptIo::new(NativeDomainId::mint());
                let mut capture = capture(&io);
                io.call_image(1, 2, 0);
                assert!(
                    capture
                        .tick_with(&mut io)
                        .unwrap()
                        .calls()
                        .any(|r| matches!(r.route(), Route::Joined(_)))
                );
                io.call_image(1, 3, 0);
                let forward = capture.tick_with(&mut io).unwrap();
                assert!(forward.outcomes().iter().any(|o| matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(image) if image.exec_id == 2))));
                assert_eq!(capture.bindings.len(), 1);
                assert_eq!(capture.bindings[&1].image.exec_id, 3);
                io.local = 1;
                io.call_image(1, 2, 0);
                let old = capture.tick_with(&mut io).unwrap();
                assert!(!old.calls().any(|r| matches!(r.route(), Route::Joined(_))));
                assert_eq!(capture.bindings[&1].image.exec_id, 3);
                assert!(old.outcomes().iter().all(|o| !matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(image) if image.exec_id == 3))));
            }
            #[test]
            fn equal_pid_different_arc_cannot_retire_another_cookie_binding() {
                let mut io = ScriptIo::new(NativeDomainId::mint());
                let mut capture = capture(&io);
                prime(&mut capture, &mut io);
                let original = io.pin.clone();
                io.pin = Arc::new(PidPin::open(original.pid()).unwrap());
                assert!(!Arc::ptr_eq(&original, &io.pin));
                io.call_image(2, 0, 0);
                let report = capture.tick_with(&mut io).unwrap();
                assert!(report.outcomes().iter().all(|o| !matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(_) | InvalidationScope::TaskRetired(_)))));
                assert!(Arc::ptr_eq(&capture.bindings[&1].pin, &original));
                assert_eq!(
                    capture.bindings[&1].image,
                    ImageIdentity {
                        task_cookie: 1,
                        exec_id: 1
                    }
                );
            }
            #[test]
            fn ready_aliases_consume_only_the_terminal_association_quota() {
                let mut io = ScriptIo::new(NativeDomainId::mint());
                let (mut child, pin) = ChildGuard::spawn();
                io.pin = pin;
                let mut capture = capture(&io);
                capture.limits.terminal_reads = 1;
                io.call_image(1, 8, 0);
                assert!(
                    capture
                        .tick_with(&mut io)
                        .unwrap()
                        .calls()
                        .any(|r| matches!(r.route(), Route::Joined(_)))
                );
                io.call_image(2, 0, 0);
                assert!(
                    capture
                        .tick_with(&mut io)
                        .unwrap()
                        .calls()
                        .any(|r| matches!(r.route(), Route::Joined(_)))
                );
                assert_eq!(capture.bindings.len(), 2);
                child.end();
                let first = capture.tick_with(&mut io).unwrap();
                assert_eq!(
                    first
                        .outcomes()
                        .iter()
                        .filter(|o| matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::TaskRetired(_))))
                        .count(),
                    1
                );
                assert_eq!(capture.bindings.len(), 1);
                let second = capture.tick_with(&mut io).unwrap();
                assert_eq!(
                    second
                        .outcomes()
                        .iter()
                        .filter(|o| matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::TaskRetired(_))))
                        .count(),
                    1
                );
                assert!(capture.bindings.is_empty());
                io.pin = Arc::new(PidPin::open(std::process::id()).unwrap());
                io.last_health.fault = 1;
                io.call_image(1, 99, 1);
                io.call_image(2, 99, 1);
                let old = capture.tick_with(&mut io).unwrap();
                assert_eq!(old.calls().count(), 2);
                assert!(
                    old.calls()
                        .all(|r| r.route() == Route::Unknown(UnknownReason::Retired))
                );
            }
            #[test]
            fn failed_postscan_health_cannot_promote_or_retire_a_binding() {
                let mut io = ScriptIo::new(NativeDomainId::mint());
                let mut capture = capture(&io);
                prime(&mut capture, &mut io);
                io.health.extend([
                    Ok(Health {
                        fault: 0,
                        sticky: 0,
                    }),
                    Err(()),
                ]);
                io.call_image(2, 0, 0);
                let report = capture.tick_with(&mut io).unwrap();
                assert_eq!(capture.bindings.len(), 1);
                assert_eq!(
                    capture.bindings[&1].image,
                    ImageIdentity {
                        task_cookie: 1,
                        exec_id: 1
                    }
                );
                assert!(
                    report
                        .calls()
                        .all(|r| r.route() == Route::Unknown(UnknownReason::CoverageFault))
                );
                assert!(report.outcomes().iter().all(|o| !matches!(o, TickOutcome::Invalidation(i)
                    if matches!(i.scope(), InvalidationScope::ImageRetired(_) | InvalidationScope::TaskRetired(_)))));
            }
            #[test]
            fn exec_zero_is_a_nonempty_positive_identity() {
                let mut io = ScriptIo::new(NativeDomainId::mint());
                let mut capture = capture(&io);
                io.call_image(1, 0, 0);
                let report = capture.tick_with(&mut io).unwrap();
                assert!(
                    report
                        .calls()
                        .any(|r| matches!(r.route(), Route::Joined(_)))
                );
                assert_eq!(capture.router.ranges_retained(), 2);
                assert_eq!(capture.bindings[&1].image.exec_id, 0);
            }
        }
    }
}
