//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private collect/audit/route/scan orchestration. This does not activate a
//! semantic reducer or alter physical counts (the later activation tasks).
#![cfg_attr(not(test), allow(dead_code))]

use crate::attach::Session;
use crate::attach::capture::{NativeDomainId, ReadWindow};
use crate::attach::image_query::{CompleteEpochs, ImageQueryRefusal, ImageScanProof};
use crate::discovery::identity::{PinnedObjectId, RetainedInventoryTarget};
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
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) object: PinnedObjectId,
    pub(crate) file_slot: u32,
    pub(crate) offset: u64,
}

/// Current registration authority is separate from historical Joined calls.
/// Only the synchronous accepted scan path may mint this move-only receipt.
pub(crate) struct CurrentPartitionReceipt {
    domain: NativeDomainId,
    image: ImageIdentity,
    pin: Arc<PidPin>,
    endpoint: Endpoint,
    attachment_slot: u32,
    watched: RetainedInventoryTarget,
    epochs: CompleteEpochs,
    fence: u64,
    deadline: Instant,
    ids: Vec<InstanceId>,
}
impl CurrentPartitionReceipt {
    /// Tests-only receipt: merge tests script receipt plumbing (order,
    /// bounds) that only the synchronous accepted scan path mints.
    /// Production construction stays move-only.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        image: ImageIdentity,
        pin: Arc<PidPin>,
        endpoint: Endpoint,
        attachment_slot: u32,
        watched: RetainedInventoryTarget,
        epochs: CompleteEpochs,
        fence: u64,
        deadline: Instant,
        ids: Vec<InstanceId>,
    ) -> Self {
        Self {
            domain,
            image,
            pin,
            endpoint,
            attachment_slot,
            watched,
            epochs,
            fence,
            deadline,
            ids,
        }
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn image(&self) -> ImageIdentity {
        self.image
    }
    pub(crate) fn endpoint(&self) -> Endpoint {
        self.endpoint
    }
    pub(crate) fn instances(&self) -> &[InstanceId] {
        &self.ids
    }
    pub(crate) fn original_pin(&self) -> &Arc<PidPin> {
        &self.pin
    }
}
impl fmt::Debug for CurrentPartitionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurrentPartitionReceipt(<private>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CurrentReceiptRefusal {
    Domain,
    Custody,
    Attachment,
    Epoch,
    Partition,
    Deadline,
    Audit,
    Stopped,
}

/// I/O observations only. The capture owner applies all receipt decisions.
struct ReceiptState {
    image: ImageIdentity,
    epochs: CompleteEpochs,
    watched: RetainedInventoryTarget,
}

/// One latch belongs to one retained physical-authority episode, within the
/// coordinator's existing record budgets. H0 scans cannot reopen an episode.
struct PhysicalGapEpisode {
    domain: NativeDomainId,
    image: ImageIdentity,
    pin: Arc<PidPin>,
    applied: AtomicBool,
}

/// Task3's completed physical adjudicator alone gains the production factory.
/// A provisional scan marker or scalar caller fact cannot construct a gap.
/// This slice requires an already accepted H0 cookie-to-original-Arc binding;
/// handling a genuine gap before that first scan remains a Task3 prerequisite.
pub(crate) struct PhysicalSemanticGap {
    episode: Arc<PhysicalGapEpisode>,
}
impl fmt::Debug for PhysicalSemanticGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PhysicalSemanticGap(<private>)")
    }
}
impl PhysicalSemanticGap {
    /// Sole production factory: the coordinator's final physical
    /// adjudication mints one gap per proven genuine-loss episode from
    /// the binding's domain, image and stable custody Arc. Fields stay
    /// private, Debug stays redacted, and the episode starts unapplied;
    /// H0 re-checks custody, image and association at the cut. The finite
    /// loss cause travels with the finalizer's loss mapping, not here.
    pub(crate) fn adjudicated(
        domain: NativeDomainId,
        image: ImageIdentity,
        pin: Arc<PidPin>,
    ) -> Self {
        Self {
            episode: Arc::new(PhysicalGapEpisode {
                domain,
                image,
                pin,
                applied: AtomicBool::new(false),
            }),
        }
    }
    #[cfg(test)]
    fn test_episode(domain: NativeDomainId, image: ImageIdentity, pin: Arc<PidPin>) -> Self {
        Self {
            episode: Arc::new(PhysicalGapEpisode {
                domain,
                image,
                pin,
                applied: AtomicBool::new(false),
            }),
        }
    }
    #[cfg(test)]
    fn test_repeat(&self) -> Self {
        Self {
            episode: self.episode.clone(),
        }
    }
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
    /// Tests-only call: finalizer and terminal tests script Joined calls
    /// with timeline tokens that only the audited router mints.
    /// Production construction stays move-only.
    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        record: EventRecord,
        route: Route,
        endpoint: Option<Endpoint>,
        token: Option<u64>,
    ) -> Self {
        Self {
            domain,
            record,
            route,
            endpoint,
            token,
        }
    }

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

/// Tests-only record: finalizer and terminal tests script Joined calls
/// with routing continuity that only the audited router mints. The helper
/// lives in the allowlisted router plumbing so non-allowed test fixtures
/// never name the private routing fields. Production construction stays
/// move-only.
#[cfg(test)]
pub(crate) fn event_record_with_routing(
    event: p11scope_ebpf_common::Event,
    stamp: p11scope_ebpf_common::InstanceStamp,
    ip: u64,
) -> EventRecord {
    EventRecord {
        event,
        continuity: p11scope_ebpf_common::InstanceContinuity {
            entry_stamp: stamp,
            return_stamp: stamp,
            entry_ip: ip,
        },
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
impl TickOutcome {
    /// Whether this outcome is an H0 invalidation (a negative):
    /// bounded stashes and merges shed positives first so loss
    /// boundaries survive overflow.
    pub(crate) fn is_invalidation(&self) -> bool {
        matches!(self, TickOutcome::Invalidation(_))
    }
}
#[derive(Default, Debug)]
pub(crate) struct TickReport {
    outcomes: Vec<TickOutcome>,
    current: Vec<CurrentPartitionReceipt>,
    pub(crate) collected_calls: usize,
    pub(crate) scans: usize,
    pub(crate) observations: Vec<ObserveOutcome>,
    pub(crate) scan_refusals: Vec<ImageQueryRefusal>,
}
impl TickReport {
    /// Tests-only report: finalizer and terminal tests script batches
    /// that only the audited collect→audit→route path mints. Production
    /// construction stays move-only.
    #[cfg(test)]
    pub(crate) fn scripted(
        outcomes: Vec<TickOutcome>,
        current: Vec<CurrentPartitionReceipt>,
    ) -> Self {
        Self {
            outcomes,
            current,
            ..Self::default()
        }
    }

    /// Drain this report's current-partition receipts (refresh stashing).
    pub(crate) fn take_current(&mut self) -> Vec<CurrentPartitionReceipt> {
        std::mem::take(&mut self.current)
    }

    /// Drain this report's outcomes (refresh stashing preserves
    /// invalidations beside the receipts).
    pub(crate) fn take_outcomes(&mut self) -> Vec<TickOutcome> {
        std::mem::take(&mut self.outcomes)
    }

    /// Merge lane-stashed refresh receipts behind this tick's own: fresh
    /// receipts first, stashed appended, truncated to batch capacity so
    /// the merged batch never refuses on bounds. Returns shed receipts.
    pub(crate) fn merge_stashed_current(&mut self, stashed: Vec<CurrentPartitionReceipt>) -> u64 {
        self.current.extend(stashed);
        let shed = self.current.len().saturating_sub(MAX_INSTANCES);
        self.current.truncate(MAX_INSTANCES);
        debug_assert!(self.current.len() <= MAX_INSTANCES);
        shed as u64
    }

    /// Merge lane-stashed refresh outcomes behind this tick's own,
    /// truncated to batch capacity like the receipts. Returns shed
    /// outcomes. Truncation sheds positives first: a merged
    /// invalidation is H2's loss boundary, while a shed call is
    /// disclosed through the refusal count. Positions increase
    /// monotonically, so the oldest outcome still carries the minimum
    /// barrier when only invalidations remain.
    pub(crate) fn merge_stashed_outcomes(&mut self, stashed: Vec<TickOutcome>) -> u64 {
        self.outcomes.extend(stashed);
        let mut shed = 0u64;
        while self.outcomes.len() > MAX_INSTANCES {
            if let Some(at) = self
                .outcomes
                .iter()
                .position(|outcome| !outcome.is_invalidation())
            {
                self.outcomes.remove(at);
            } else {
                self.outcomes.remove(0);
            }
            shed += 1;
        }
        debug_assert!(self.outcomes.len() <= MAX_INSTANCES);
        shed
    }

    pub(crate) fn into_outcomes(self) -> Vec<TickOutcome> {
        self.outcomes
    }
    pub(crate) fn outcomes(&self) -> &[TickOutcome] {
        &self.outcomes
    }
    pub(crate) fn current(&self) -> &[CurrentPartitionReceipt] {
        &self.current
    }
    pub(crate) fn into_parts(self) -> (Vec<TickOutcome>, Vec<CurrentPartitionReceipt>) {
        (self.outcomes, self.current)
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
    slot: u32,
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
    fn raise_fault(&mut self) -> Result<u64, ()>;
    fn retained_attachment(
        &self,
        slot: u32,
    ) -> Result<RetainedInventoryTarget, CurrentReceiptRefusal>;
    fn receipt_state(
        &mut self,
        pin: &Arc<PidPin>,
        image: ImageIdentity,
        endpoint: Endpoint,
        slot: u32,
        deadline: Instant,
    ) -> Result<ReceiptState, CurrentReceiptRefusal>;
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
    fn raise_fault(&mut self) -> Result<u64, ()> {
        self.session.instance_maps().raise_fault().map_err(|_| ())
    }
    fn retained_attachment(
        &self,
        slot: u32,
    ) -> Result<RetainedInventoryTarget, CurrentReceiptRefusal> {
        self.session.semantic_receipt_target(slot)
    }
    fn receipt_state(
        &mut self,
        pin: &Arc<PidPin>,
        image: ImageIdentity,
        endpoint: Endpoint,
        slot: u32,
        deadline: Instant,
    ) -> Result<ReceiptState, CurrentReceiptRefusal> {
        let (image, epochs, watched) = self
            .session
            .semantic_receipt_state(pin, image, endpoint, slot, deadline)?;
        Ok(ReceiptState {
            image,
            epochs,
            watched,
        })
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
    continuity_cuts: u64,
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
            continuity_cuts: 0,
        })
    }
    pub(crate) fn router(&self) -> &InstanceRouter {
        &self.router
    }
    pub(crate) fn continuity_cuts(&self) -> u64 {
        self.continuity_cuts
    }
    pub(crate) fn validate_current(
        &mut self,
        session: &mut Session,
        receipt: &CurrentPartitionReceipt,
        report: &mut TickReport,
    ) -> Result<(), CurrentReceiptRefusal> {
        self.validate_current_with(
            &mut SessionIo {
                session,
                targets: &[],
            },
            receipt,
            report,
        )
    }
    fn validate_current_with(
        &mut self,
        io: &mut impl CaptureIo,
        receipt: &CurrentPartitionReceipt,
        report: &mut TickReport,
    ) -> Result<(), CurrentReceiptRefusal> {
        use CurrentReceiptRefusal as Refusal;
        if io.domain() != Some(self.router.domain()) || receipt.domain != self.router.domain() {
            return Err(Refusal::Domain);
        }
        if self.stopped {
            return Err(Refusal::Stopped);
        }
        let binding = self
            .bindings
            .get(&receipt.image.task_cookie)
            .ok_or(Refusal::Custody)?;
        if !binding.current
            || binding.domain != receipt.domain
            || binding.image != receipt.image
            || !Arc::ptr_eq(&binding.pin, &receipt.pin)
            || receipt.pin.pidfd().is_err()
        {
            return Err(Refusal::Custody);
        }
        if io.now() >= receipt.deadline {
            return Err(Refusal::Deadline);
        }
        if io.endpoint(receipt.attachment_slot) != Some(receipt.endpoint) {
            return Err(Refusal::Attachment);
        }
        let target = io.retained_attachment(receipt.attachment_slot)?;
        if !Arc::ptr_eq(
            &target.retirement_lease(),
            &receipt.watched.retirement_lease(),
        ) || target.check_unchanged() != Ok(true)
            || receipt.watched.check_unchanged() != Ok(true)
        {
            return Err(Refusal::Attachment);
        }
        if !self.audit(io, report) {
            return Err(Refusal::Audit);
        }
        if !self.receipt_partition_matches(receipt) {
            return Err(Refusal::Partition);
        }
        let Some(slice_end) = io.now().checked_add(self.limits.scan_slice) else {
            self.exhaust(report);
            return Err(Refusal::Deadline);
        };
        let deadline = slice_end.min(receipt.deadline);
        let state = io.receipt_state(
            &receipt.pin,
            receipt.image,
            receipt.endpoint,
            receipt.attachment_slot,
            deadline,
        );
        if !self.audit(io, report) {
            return Err(Refusal::Audit);
        }
        // A failed native read is permanent even when the later audit itself
        // succeeded. Ordinary epoch/attachment refusals do not restamp proof.
        let state = match state {
            Err(Refusal::Audit) => {
                self.fail_coverage(io, report);
                return Err(Refusal::Audit);
            }
            result => result?,
        };
        if io.now() >= deadline {
            return Err(Refusal::Deadline);
        }
        if state.image != receipt.image || state.epochs != receipt.epochs {
            return Err(Refusal::Epoch);
        }
        if io.endpoint(receipt.attachment_slot) != Some(receipt.endpoint)
            || !Arc::ptr_eq(
                &state.watched.retirement_lease(),
                &receipt.watched.retirement_lease(),
            )
            || state.watched.check_unchanged() != Ok(true)
        {
            return Err(Refusal::Attachment);
        }
        if !self.receipt_partition_matches(receipt) {
            return Err(Refusal::Partition);
        }
        Ok(())
    }
    fn receipt_partition_matches(&self, receipt: &CurrentPartitionReceipt) -> bool {
        self.router.current_partition_matches(
            receipt.domain,
            receipt.image,
            receipt.endpoint.file_slot,
            receipt.epochs,
            receipt.fence,
            &receipt.ids,
        )
    }
    pub(crate) fn apply_physical_gaps(
        &mut self,
        session: &mut Session,
        gaps: Vec<PhysicalSemanticGap>,
    ) -> anyhow::Result<TickReport> {
        self.apply_physical_gaps_with(
            &mut SessionIo {
                session,
                targets: &[],
            },
            gaps,
        )
    }
    fn apply_physical_gaps_with(
        &mut self,
        io: &mut impl CaptureIo,
        gaps: Vec<PhysicalSemanticGap>,
    ) -> anyhow::Result<TickReport> {
        anyhow::ensure!(
            io.domain() == Some(self.router.domain()),
            "foreign semantic Session"
        );
        anyhow::ensure!(
            !self.stopped && gaps.len() <= MAX_INSTANCES,
            "invalid physical gap publication"
        );
        // Validate the whole bounded publication before audit, CAS or state
        // mutation. Equal numeric PID or a duplicated fd is not this Arc.
        for gap in &gaps {
            let episode = &gap.episode;
            let binding = self
                .bindings
                .get(&episode.image.task_cookie)
                .ok_or_else(|| anyhow::anyhow!("physical gap custody unavailable"))?;
            anyhow::ensure!(
                episode.domain == self.router.domain()
                    && binding.domain == episode.domain
                    && Arc::ptr_eq(&episode.pin, &binding.pin)
                    && (episode.applied.load(Ordering::SeqCst) || binding.image == episode.image),
                "foreign physical gap authority"
            );
        }
        let mut report = TickReport::default();
        if gaps
            .iter()
            .all(|gap| gap.episode.applied.load(Ordering::SeqCst))
            || self.image_failed
            || self.exhausted
        {
            return Ok(report);
        }
        if !self.audit(io, &mut report) {
            return Ok(report);
        }
        let Some(cuts) = self.continuity_cuts.checked_add(1) else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        let Ok(raised) = io.raise_fault() else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        self.continuity_cuts = cuts; // Count actual successful userspace advances.
        let Ok(health) = io.health() else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        if raised <= self.fault
            || raised > u64::from(u32::MAX)
            || health.fault < raised
            || health.fault > u64::from(u32::MAX)
            || health.sticky != 0
        {
            self.exhaust(&mut report);
            return Ok(report);
        }
        // This shared audited path clears old observations, resolves old
        // pending calls and allocates one position after all issued records.
        if !self.audit_health(health, &mut report) {
            return Ok(report);
        }
        for gap in gaps {
            gap.episode.applied.store(true, Ordering::SeqCst);
        }
        Ok(report)
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
        // The scan I/O window stays one slice (as in the tick path's
        // attempt deadline), while the minted proof stays provable for
        // the full pending window: a quiet provider's refresh receipt
        // waits the normal pass interval for the next tick batch, and a
        // 50ms receipt deadline would expire it first. Validation still
        // re-proves custody, attachment, epochs and partition live.
        let Some(scan_deadline) = io.now().checked_add(self.limits.scan_slice) else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        let Some(proof_deadline) = io.now().checked_add(self.limits.pending_for) else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        let fence = self.router.fence();
        report.scans = 1;
        let result = io.scan_selected(&pin, endpoint, scan_deadline, fence, &|| {
            self.router.fence()
        });
        let healthy = self.audit(io, &mut report);
        if io.now() >= scan_deadline {
            report.scan_refusals.push(ImageQueryRefusal::Deadline);
        } else if healthy {
            match result {
                Ok(proof) => {
                    // Retry custody: when an earlier accepted refresh
                    // retained an Arc for this task and the bind then
                    // failed, the retry offers a fresh duplicate. Adopt
                    // H0's retained Arc instead so the retry reuses the
                    // same custody; `accept_scan` still gates domain,
                    // exec monotonicity and currency afterwards.
                    let pin = self
                        .bindings
                        .get(&proof.image().task_cookie)
                        .map(|binding| binding.pin.clone())
                        .unwrap_or(pin);
                    let job = ScanJob {
                        image: proof.image(),
                        endpoint,
                        slot,
                        pin,
                        deadline: proof_deadline,
                    };
                    self.accept_scan(io, proof, &job, fence, &mut report);
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
        self.audit_health(health, report)
    }
    fn audit_health(&mut self, health: Health, report: &mut TickReport) -> bool {
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
        io: &mut impl CaptureIo,
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
        if io.endpoint(job.slot) != Some(job.endpoint) {
            report.scan_refusals.push(ImageQueryRefusal::Custody);
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
        let epochs = proof.epochs();
        let watched = io.retained_attachment(job.slot).ok();
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
            let ids = self.router.current_instances(
                self.router.domain(),
                job.image,
                job.endpoint.file_slot,
            );
            if self.router.current_partition_matches(
                self.router.domain(),
                job.image,
                job.endpoint.file_slot,
                epochs,
                fence,
                &ids,
            ) && let Some(watched) = watched
                && watched.check_unchanged() == Ok(true)
            {
                report.current.push(CurrentPartitionReceipt {
                    domain: self.router.domain(),
                    image: job.image,
                    pin: job.pin.clone(),
                    endpoint: job.endpoint,
                    attachment_slot: job.slot,
                    watched,
                    epochs,
                    fence,
                    deadline: job.deadline,
                    ids,
                });
            }
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
                    slot: record.event.slot,
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
                        self.accept_scan(io, proof, &job, fence, &mut report);
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

    mod current_receipts_tests {
        //! SPDX-License-Identifier: GPL-3.0-or-later
        //! Shared production orchestration with substituted I/O, never proof decisions.
        use super::*;

        fn initial_pair(capture: &mut SemanticCapture, io: &mut ScriptIo) -> TickReport {
            io.semantic_call("C_SignInit", 0, 0);
            io.semantic_call("C_Sign", 0, 0);
            let report = capture.tick_with(io).unwrap();
            assert_eq!(report.calls().count(), 2);
            assert!(
                report
                    .calls()
                    .all(|call| matches!(call.route(), Route::Joined(_)))
            );
            assert!(
                report
                    .outcomes()
                    .iter()
                    .all(|item| !matches!(item, TickOutcome::Invalidation(_)))
            );
            assert_eq!(capture.router.ranges_retained(), 2);
            report
        }

        fn id(route: Route) -> InstanceId {
            let Route::Joined(id) = route else {
                panic!("nonempty supported join required")
            };
            id
        }

        fn gap(capture: &SemanticCapture) -> PhysicalSemanticGap {
            let binding = &capture.bindings[&1];
            PhysicalSemanticGap::test_episode(binding.domain, binding.image, binding.pin.clone())
        }

        fn barrier(report: &TickReport) -> &Invalidation {
            report
                .outcomes()
                .iter()
                .find_map(|outcome| match outcome {
                    TickOutcome::Invalidation(value)
                        if matches!(value.scope(), InvalidationScope::FaultEra) =>
                    {
                        Some(value)
                    }
                    _ => None,
                })
                .expect("one producer-visible fault barrier")
        }

        #[test]
        fn native_semantic_current_receipt_requires_original_pin_and_accepted_scan() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            let mut report = initial_pair(&mut capture, &mut io);
            let joined = id(report.calls().next().unwrap().route());
            assert_eq!(
                report.current.len(),
                1,
                "accepted complete first scan must yield registration authority"
            );
            let mut receipt = report.current.pop().unwrap();
            assert_eq!(receipt.domain(), io.domain);
            assert_eq!(receipt.image(), io.current_image);
            assert_eq!(receipt.instances(), &[joined]);
            assert!(receipt.endpoint() == io.endpoint(0).unwrap());
            assert!(Arc::ptr_eq(receipt.original_pin(), &io.pin));
            assert!(Arc::ptr_eq(
                &receipt.watched.retirement_lease(),
                &io.watched[0].retirement_lease()
            ));
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Ok(())
            );

            io.semantic_call("C_Sign", 0, 0);
            let cached = capture.tick_with(&mut io).unwrap();
            assert_eq!(
                cached.calls().next().unwrap().route(),
                Route::Joined(joined)
            );
            assert!(
                cached.current().is_empty(),
                "historical cached Joined is not a scan receipt"
            );
            let (owned_cached, no_receipts) = cached.into_parts();
            assert_eq!(owned_cached.len(), 1);
            assert!(no_receipts.is_empty());
            let refresh = capture
                .refresh_with(&mut io, receipt.pin.clone(), 0)
                .unwrap();
            assert_eq!(refresh.collected_calls, 0);
            assert_eq!(refresh.current.len(), 1, "fresh no-call scan can register");

            let original_domain = receipt.domain;
            receipt.domain = NativeDomainId::mint();
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Domain)
            );
            receipt.domain = original_domain;
            let original_pin = receipt.pin.clone();
            receipt.pin = Arc::new(PidPin::open(original_pin.pid()).unwrap());
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Custody)
            );
            receipt.pin = original_pin;
            receipt.image.exec_id += 1;
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Custody)
            );
            receipt.image.exec_id -= 1;
            receipt.endpoint.file_slot = 1;
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Attachment)
            );
            assert_eq!(capture.router.instances_minted(), 1);
            assert_eq!(io.raises, 0);
            receipt.endpoint.file_slot = 0;
            capture.stop();
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Stopped)
            );
        }

        #[test]
        fn native_semantic_receipt_expires_before_finalization() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            let mut report = initial_pair(&mut capture, &mut io);
            let held_route = report.calls().next().unwrap().route();
            let receipt = report.current.pop().expect("accepted original receipt");
            let now = io.now;
            io.now = receipt.deadline;
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Deadline)
            );
            io.now = now;
            io.local = 1; // Actual epoch I/O changes before any subsequent observation.
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Epoch)
            );
            let original_pin = io.pin.clone();
            let mut newer = capture.refresh_with(&mut io, original_pin, 0).unwrap();
            assert_eq!(newer.current.len(), 1);
            let new_receipt = newer.current.pop().unwrap();
            assert_ne!(new_receipt.instances(), receipt.instances());
            assert_eq!(
                capture.validate_current_with(&mut io, &new_receipt, &mut newer),
                Ok(())
            );
            assert_eq!(
                report.calls().next().unwrap().route(),
                held_route,
                "owned history is not restamped"
            );
            assert!(newer.outcomes().iter().any(|item| matches!(item,
                TickOutcome::Invalidation(value) if matches!(value.scope(), InvalidationScope::InstancesRetired { ids, .. } if ids == receipt.instances()))));

            io.local = 0;
            let original_pin = io.pin.clone();
            let historical = capture.refresh_with(&mut io, original_pin, 0).unwrap();
            assert_eq!(historical.observations, vec![ObserveOutcome::Continued]);
            assert!(
                historical.current.is_empty(),
                "a retained historical epoch cannot mint current authority"
            );
            io.semantic_call("C_Sign", 0, 0);
            let late = capture.tick_with(&mut io).unwrap();
            assert_eq!(late.calls().next().unwrap().route(), held_route);
            assert!(late.current.is_empty());
            for epoch in 2..=5 {
                io.local = epoch;
                let pin = io.pin.clone();
                assert_eq!(
                    capture.refresh_with(&mut io, pin, 0).unwrap().current.len(),
                    1
                );
            }
            io.local = 0;
            io.semantic_call("C_Sign", 0, 0);
            assert_eq!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .next()
                    .unwrap()
                    .route(),
                Route::Unknown(UnknownReason::Evicted)
            );
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Partition)
            );
            capture.router.retire_image(receipt.image);
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Partition)
            );
        }

        #[test]
        fn refresh_receipt_survives_realistic_pass_interval_into_next_tick() {
            use crate::inventory_semantics::{
                RefreshReceiptStash, merge_stash_into_report, stash_refresh_report,
            };

            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            let pin = io.pin.clone();
            let minted_at = io.now;
            let mut refresh = capture.refresh_with(&mut io, pin, 0).unwrap();
            assert_eq!(
                refresh.current().len(),
                1,
                "the accepted refresh mints one receipt"
            );
            // The quiet provider's proof waits the normal pass interval
            // for the next tick batch (1s passes; the scan slice is only
            // 50ms), carried by the real lane stash through the shared
            // production round-trip.
            let mut stash = RefreshReceiptStash::new();
            let (images, shed) = stash_refresh_report(&mut stash, &mut refresh);
            assert_eq!(shed, 0);
            assert_eq!(images.len(), 1);
            io.now += Duration::from_secs(1);
            let mut tick = capture.tick_with(&mut io).unwrap();
            assert!(
                tick.calls().next().is_none(),
                "the quiet tick routes no calls"
            );
            assert_eq!(merge_stash_into_report(&mut stash, &mut tick), 0);
            assert_eq!(tick.current().len(), 1);
            assert_eq!(
                tick.current()[0].deadline,
                minted_at + capture.limits.pending_for,
                "a refresh receipt stays provable across the normal pass interval"
            );
            let mut scratch = TickReport::default();
            assert_eq!(
                capture.validate_current_with(&mut io, &tick.current()[0], &mut scratch),
                Ok(()),
                "the stashed quiet proof validates at the next tick"
            );
        }

        #[test]
        fn refresh_outcomes_reach_next_tick_instead_of_dropping() {
            use crate::inventory_semantics::{
                RefreshReceiptStash, merge_stash_into_report, stash_refresh_report,
            };

            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            let pin = io.pin.clone();
            // The second refresh supersedes the first image on the same
            // pin: H0 retires the prior image with an invalidation.
            let first = capture.refresh_with(&mut io, pin.clone(), 0).unwrap();
            assert_eq!(first.current().len(), 1);
            io.output_image = Some(ImageIdentity {
                task_cookie: 2,
                exec_id: 1,
            });
            let mut second = capture.refresh_with(&mut io, pin, 0).unwrap();
            assert_eq!(second.current().len(), 1);
            assert!(
                second.outcomes().iter().any(|item| matches!(
                    item,
                    TickOutcome::Invalidation(value)
                        if matches!(value.scope(), InvalidationScope::ImageRetired(_))
                )),
                "the superseding refresh must carry its invalidation: {:?}",
                second.outcomes()
            );
            // The shared round-trip preserves the outcomes beside the
            // receipts into the next tick batch.
            let mut stash = RefreshReceiptStash::new();
            let (images, shed) = stash_refresh_report(&mut stash, &mut second);
            assert_eq!(shed, 0);
            assert_eq!(images.len(), 1);
            let mut tick = capture.tick_with(&mut io).unwrap();
            assert_eq!(merge_stash_into_report(&mut stash, &mut tick), 0);
            assert_eq!(tick.current().len(), 1);
            assert!(
                tick.outcomes().iter().any(|item| matches!(
                    item,
                    TickOutcome::Invalidation(value)
                        if matches!(value.scope(), InvalidationScope::ImageRetired(_))
                )),
                "the stashed invalidation must reach the tick batch: {:?}",
                tick.outcomes()
            );
        }

        #[test]
        fn drained_receipt_expires_inside_quiescence_wait_but_validates_promptly() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = capture(&io);
            io.call_image(1, 1, 0);
            let tick = capture.tick_with(&mut io).unwrap();
            assert_eq!(
                tick.current().len(),
                1,
                "the drained call mints its receipt"
            );
            let receipt = &tick.current()[0];
            let mut scratch = TickReport::default();
            // A prompt terminal commit (inside `on_batch` during the
            // drain) validates while the receipt is fresh.
            assert_eq!(
                capture.validate_current_with(&mut io, receipt, &mut scratch),
                Ok(())
            );
            // Buffered through a full quiescence wait, the 2s pending
            // window expires inside the 5s stop budget.
            io.now += Duration::from_secs(5);
            assert_eq!(
                capture.validate_current_with(&mut io, receipt, &mut scratch),
                Err(CurrentReceiptRefusal::Deadline)
            );
        }

        #[test]
        fn native_semantic_receipt_revalidates_readback_and_postscan_health() {
            // Exercise the actual Session readback decision, alongside the shared
            // capture's I/O-failure paths; no injected boolean may seal a receipt.
            use crate::attach::{CapturePolicy, semantic_receipt_readback_test};
            let descriptors = crate::kinds::DESCRIPTORS.to_vec();
            assert_eq!(
                semantic_receipt_readback_test(CapturePolicy::Allowlisted, Ok(descriptors.clone())),
                Ok(())
            );
            assert_eq!(
                semantic_receipt_readback_test(
                    CapturePolicy::AggregateOnly,
                    Ok(descriptors.clone())
                ),
                Err(CurrentReceiptRefusal::Attachment)
            );
            assert_eq!(
                semantic_receipt_readback_test(
                    CapturePolicy::Allowlisted,
                    Err(anyhow::anyhow!("readback I/O"))
                ),
                Err(CurrentReceiptRefusal::Attachment)
            );
            let mut truncated = descriptors.clone();
            truncated.pop();
            assert_eq!(
                semantic_receipt_readback_test(CapturePolicy::Allowlisted, Ok(truncated)),
                Err(CurrentReceiptRefusal::Attachment)
            );
            let mut changed = descriptors;
            let positive = changed
                .iter()
                .position(|descriptor| {
                    *descriptor != p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
                })
                .expect("nonempty non-count descriptor inventory");
            changed[positive] = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
            assert_eq!(
                semantic_receipt_readback_test(CapturePolicy::Allowlisted, Ok(changed)),
                Err(CurrentReceiptRefusal::Attachment)
            );
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            let mut report = initial_pair(&mut capture, &mut io);
            let receipt = report.current.pop().expect("accepted original receipt");
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Ok(())
            );
            for (query_refusal, refusal) in [
                (ImageQueryRefusal::Unknown, CurrentReceiptRefusal::Epoch),
                (ImageQueryRefusal::Unstable, CurrentReceiptRefusal::Epoch),
                (ImageQueryRefusal::Deadline, CurrentReceiptRefusal::Deadline),
                (ImageQueryRefusal::Custody, CurrentReceiptRefusal::Custody),
            ] {
                let classified = crate::attach::semantic_receipt_query_refusal_test(query_refusal);
                assert_eq!(
                    classified, refusal,
                    "temporary current-proof refusal is not missed coverage"
                );
                io.receipt_refusal = Some(classified);
                io.health.extend([Ok(io.last_health), Ok(io.last_health)]);
                assert_eq!(
                    capture.validate_current_with(&mut io, &receipt, &mut report),
                    Err(refusal)
                );
                assert!(
                    io.health.is_empty(),
                    "post-read audit still runs after finite refusal"
                );
                assert!(!capture.image_failed && !capture.exhausted);
                io.receipt_refusal = None;
                assert_eq!(
                    capture.validate_current_with(&mut io, &receipt, &mut report),
                    Ok(())
                );
            }
            for query_refusal in [ImageQueryRefusal::Coverage, ImageQueryRefusal::Stream] {
                let classified = crate::attach::semantic_receipt_query_refusal_test(query_refusal);
                assert_eq!(classified, CurrentReceiptRefusal::Audit);
                let mut failed_io = ScriptIo::new(NativeDomainId::mint());
                let mut failed_capture = super::capture(&failed_io);
                let mut failed_report = initial_pair(&mut failed_capture, &mut failed_io);
                let failed_receipt = failed_report.current.pop().unwrap();
                failed_io.receipt_refusal = Some(classified);
                failed_io
                    .health
                    .extend([Ok(failed_io.last_health), Ok(failed_io.last_health)]);
                assert_eq!(
                    failed_capture.validate_current_with(
                        &mut failed_io,
                        &failed_receipt,
                        &mut failed_report
                    ),
                    Err(CurrentReceiptRefusal::Audit)
                );
                assert!(
                    failed_io.health.is_empty(),
                    "both surrounding audits succeed"
                );
                assert!(
                    failed_capture.image_failed,
                    "actual receipt read failure stays permanent"
                );
                failed_io.receipt_refusal = None;
                assert_eq!(
                    failed_capture.validate_current_with(
                        &mut failed_io,
                        &failed_receipt,
                        &mut failed_report
                    ),
                    Err(CurrentReceiptRefusal::Audit)
                );
                let fault = u32::try_from(failed_io.last_health.fault).unwrap();
                failed_io.semantic_call("C_SignInit", 0, fault);
                let retry = failed_capture.tick_with(&mut failed_io).unwrap();
                assert!(retry.current.is_empty());
                assert_eq!(
                    retry.calls().next().unwrap().route(),
                    Route::Unknown(UnknownReason::CoverageFault)
                );
                assert_eq!(failed_capture.router.instances_minted(), 1);
            }
            io.current_image.exec_id += 1;
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Epoch)
            );
            io.current_image.exec_id -= 1;
            for epochs in [
                CompleteEpochs {
                    local: 1,
                    ..receipt.epochs
                },
                CompleteEpochs {
                    global: 1,
                    ..receipt.epochs
                },
                CompleteEpochs {
                    fault: 1,
                    ..receipt.epochs
                },
                CompleteEpochs {
                    sticky: 1,
                    ..receipt.epochs
                },
                CompleteEpochs {
                    record_flags: 1,
                    ..receipt.epochs
                },
            ] {
                io.receipt_epochs = Some(epochs);
                assert_eq!(
                    capture.validate_current_with(&mut io, &receipt, &mut report),
                    Err(CurrentReceiptRefusal::Epoch)
                );
            }
            io.receipt_epochs = None;
            io.attachment_refusal = Some(CurrentReceiptRefusal::Attachment);
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Attachment)
            );
            io.attachment_refusal = None;
            io.receipt_refusal = Some(CurrentReceiptRefusal::Epoch);
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Epoch)
            );
            io.receipt_refusal = None;
            io.health.extend([Ok(io.last_health), Err(())]);
            assert_eq!(
                capture.validate_current_with(&mut io, &receipt, &mut report),
                Err(CurrentReceiptRefusal::Audit)
            );
            assert!(capture.image_failed, "post-read health loss is permanent");
            io.last_health.fault += 1;
            let original_pin = io.pin.clone();
            let retry = capture.refresh_with(&mut io, original_pin, 0).unwrap();
            assert!(retry.current.is_empty());
            assert_eq!(capture.router.instances_minted(), 1);

            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            io.health.extend([Ok(io.last_health), Err(())]);
            io.semantic_call("C_SignInit", 0, 0);
            let failed = capture.tick_with(&mut io).unwrap();
            assert!(failed.current.is_empty());
            assert_eq!(
                failed.calls().next().unwrap().route(),
                Route::Unknown(UnknownReason::CoverageFault)
            );
            assert_eq!(capture.router.instances_minted(), 0);
        }

        #[test]
        fn native_semantic_physical_cut_fences_unread_and_inflight() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            let history = initial_pair(&mut capture, &mut io);
            let old_id = id(history.calls().next().unwrap().route());
            let last_position = history
                .calls()
                .filter_map(RoutedCall::position)
                .max()
                .unwrap();
            io.semantic_call("C_SignInit", 0, 0); // Completed, still unread EVENTS record.
            io.semantic_call("C_SignInit", 0, 0); // Entry was before the cut, return after it.
            io.records.back_mut().unwrap().continuity.return_stamp.fault = 1;
            let queued = io.records.len();
            let episode = gap(&capture);
            let cut = capture
                .apply_physical_gaps_with(&mut io, vec![episode])
                .unwrap();
            assert_eq!(
                io.raises, 1,
                "genuine physical gap must reach producer fault cell"
            );
            assert_eq!(capture.continuity_cuts(), 1);
            assert_eq!(barrier(&cut).domain(), io.domain);
            assert!(barrier(&cut).position().unwrap() > last_position);
            assert_eq!(cut.calls().count(), 0);
            assert_eq!(
                io.records.len(),
                queued,
                "cut neither drains EVENTS nor changes completed physical records"
            );
            assert_eq!(
                history.calls().next().unwrap().route(),
                Route::Joined(old_id)
            );
            let old = capture.tick_with(&mut io).unwrap();
            let routes: Vec<_> = old.calls().map(RoutedCall::route).collect();
            assert_eq!(
                routes,
                vec![
                    Route::Unknown(UnknownReason::FaultEra),
                    Route::Unknown(UnknownReason::Straddle)
                ]
            );
            assert_eq!(capture.router.instances_minted(), 1);
            io.semantic_call("C_SignInit", 0, 1);
            io.semantic_call("C_Sign", 0, 1);
            let fresh = capture.tick_with(&mut io).unwrap();
            assert_eq!(fresh.calls().count(), 2);
            assert!(
                fresh
                    .calls()
                    .all(|call| matches!(call.route(), Route::Joined(new) if new != old_id))
            );
            assert_eq!(capture.router.instances_minted(), 2);
        }

        #[test]
        fn native_semantic_physical_cut_coalesces_and_exhausts() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            initial_pair(&mut capture, &mut io);
            let first = gap(&capture);
            let repeat = first.test_repeat();
            let another_episode = gap(&capture);
            let other_repeat = another_episode.test_repeat();
            let cut = capture
                .apply_physical_gaps_with(&mut io, vec![first, another_episode])
                .unwrap();
            assert_eq!(
                io.raises, 1,
                "distinct new gaps in one publication coalesce"
            );
            assert_eq!(
                cut.outcomes()
                    .iter()
                    .filter(|item| matches!(item, TickOutcome::Invalidation(_)))
                    .count(),
                1
            );
            assert_eq!(capture.continuity_cuts(), 1);
            let repeated = capture
                .apply_physical_gaps_with(&mut io, vec![repeat.test_repeat(), other_repeat])
                .unwrap();
            assert!(repeated.outcomes().is_empty());
            assert_eq!(io.raises, 1);
            io.semantic_call("C_SignInit", 0, 1);
            let healthy = capture.tick_with(&mut io).unwrap();
            assert!(matches!(
                healthy.calls().next().unwrap().route(),
                Route::Joined(_)
            ));
            capture
                .apply_physical_gaps_with(&mut io, vec![repeat])
                .unwrap();
            assert_eq!(
                io.raises, 1,
                "H0 scan alone cannot reset physical uncertainty"
            );
            // Only Task3's completed physical recovery can mint this successor episode.
            let successor = gap(&capture);
            capture
                .apply_physical_gaps_with(&mut io, vec![successor])
                .unwrap();
            assert_eq!(io.raises, 2);
            assert_eq!(capture.continuity_cuts(), 2);
        }

        #[test]
        fn native_semantic_physical_cut_requires_returned_token_readback_and_preserves_cas() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            initial_pair(&mut capture, &mut io);
            io.concurrent_raise = true;
            let episode = gap(&capture);
            let cut = capture
                .apply_physical_gaps_with(&mut io, vec![episode])
                .unwrap();
            assert_eq!(capture.continuity_cuts(), 1);
            assert_eq!(io.fault_cell.load(std::sync::atomic::Ordering::SeqCst), 2);
            assert_eq!(
                capture.fault, 2,
                "readback newer than returned userspace token is another loss"
            );
            assert!(barrier(&cut).position().is_some());
            io.semantic_call("C_SignInit", 0, 2);
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

            for refusal in 0..3 {
                let mut io = ScriptIo::new(NativeDomainId::mint());
                let mut capture = super::capture(&io);
                initial_pair(&mut capture, &mut io);
                let episode = gap(&capture);
                let repeat = episode.test_repeat();
                match refusal {
                    0 => io.raise_fails = true,
                    1 => io.health.extend([Ok(io.last_health), Err(())]),
                    2 => io.health.extend([Ok(io.last_health), Ok(io.last_health)]), // stale readback below CAS result
                    _ => unreachable!(),
                }
                capture
                    .apply_physical_gaps_with(&mut io, vec![episode])
                    .unwrap();
                assert!(
                    capture.image_failed || capture.exhausted,
                    "write/read/token failure permanently refuses"
                );
                let raises = io.raises;
                io.raise_fails = false;
                io.last_health.fault = 3;
                capture
                    .apply_physical_gaps_with(&mut io, vec![repeat])
                    .unwrap();
                assert_eq!(io.raises, raises, "permanent failure never retries the CAS");
                io.semantic_call("C_SignInit", 0, 3);
                let failed = capture.tick_with(&mut io).unwrap();
                assert!(failed.calls().all(|call| matches!(
                    call.route(),
                    Route::Unknown(
                        UnknownReason::CoverageFault | UnknownReason::AuthorityExhausted
                    )
                )));
                assert_eq!(capture.router.instances_minted(), 1);
            }
        }

        #[test]
        fn native_semantic_physical_cut_counter_and_position_exhaustion_never_reopen() {
            for ordinal in [false, true] {
                let mut io = ScriptIo::new(NativeDomainId::mint());
                let mut capture = super::capture(&io);
                initial_pair(&mut capture, &mut io);
                let episode = gap(&capture);
                if ordinal {
                    capture.next_token = u64::MAX;
                } else {
                    io.last_health.fault = u64::from(u32::MAX);
                }
                let failed = capture
                    .apply_physical_gaps_with(&mut io, vec![episode])
                    .unwrap();
                assert!(
                    capture.exhausted,
                    "unrepresentable cut or negative position is permanent"
                );
                assert!(
                    failed
                        .outcomes()
                        .iter()
                        .any(|item| matches!(item, TickOutcome::Invalidation(value)
                    if matches!(value.scope(), InvalidationScope::AuthorityExhausted)))
                );
                if !ordinal {
                    assert_eq!(
                        io.fault_cell.load(std::sync::atomic::Ordering::SeqCst),
                        u64::from(u32::MAX) + 1
                    );
                    assert_eq!(capture.continuity_cuts(), 0);
                }
                let minted = capture.router.instances_minted();
                io.last_health.fault = u64::from(u32::MAX);
                io.semantic_call("C_SignInit", 0, u32::MAX);
                assert_eq!(
                    capture
                        .tick_with(&mut io)
                        .unwrap()
                        .calls()
                        .next()
                        .unwrap()
                        .route(),
                    Route::Unknown(UnknownReason::AuthorityExhausted)
                );
                assert_eq!(capture.router.instances_minted(), minted);
            }
        }

        #[test]
        fn native_semantic_physical_cut_prevalidates_all_gaps_and_costs_healthy_sibling() {
            let mut io = ScriptIo::new(NativeDomainId::mint());
            let mut capture = super::capture(&io);
            let first = initial_pair(&mut capture, &mut io);
            let first_id = id(first.calls().next().unwrap().route());
            io.semantic_call("C_SignInit", 1, 0);
            io.semantic_call("C_Sign", 1, 0);
            let sibling = capture.tick_with(&mut io).unwrap();
            let sibling_id = id(sibling.calls().next().unwrap().route());
            assert_ne!(first_id, sibling_id);
            assert_eq!(capture.router.ranges_retained(), 4);
            let valid = gap(&capture);
            let foreign = PhysicalSemanticGap::test_episode(
                NativeDomainId::mint(),
                io.current_image,
                io.pin.clone(),
            );
            assert!(
                capture
                    .apply_physical_gaps_with(&mut io, vec![valid, foreign])
                    .is_err()
            );
            assert_eq!(
                io.raises, 0,
                "validate entire publication before any mutation"
            );
            let rival = PhysicalSemanticGap::test_episode(
                io.domain,
                io.current_image,
                Arc::new(PidPin::open(io.pin.pid()).unwrap()),
            );
            let valid = gap(&capture);
            assert!(
                capture
                    .apply_physical_gaps_with(&mut io, vec![valid, rival])
                    .is_err()
            );
            assert_eq!(capture.router.ranges_retained(), 4);
            assert_eq!(capture.router.instances_minted(), 2);
            let episode = gap(&capture);
            let cut = capture
                .apply_physical_gaps_with(&mut io, vec![episode])
                .unwrap();
            assert_eq!(io.raises, 1);
            assert_eq!(barrier(&cut).domain(), io.domain);
            io.semantic_call("C_Sign", 1, 0);
            assert_eq!(
                capture
                    .tick_with(&mut io)
                    .unwrap()
                    .calls()
                    .next()
                    .unwrap()
                    .route(),
                Route::Unknown(UnknownReason::FaultEra)
            );
            io.semantic_call("C_SignInit", 0, 1);
            io.semantic_call("C_Sign", 0, 1);
            io.semantic_call("C_SignInit", 1, 1);
            io.semantic_call("C_Sign", 1, 1);
            let recovery = capture.tick_with(&mut io).unwrap();
            assert_eq!(recovery.calls().count(), 4);
            assert!(recovery.calls().all(
                |call| matches!(call.route(), Route::Joined(new) if new != first_id && new != sibling_id)
            ));
            assert_eq!(capture.router.instances_minted(), 4);
        }
    }

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
        watched: [RetainedInventoryTarget; 2],
        attachment_refusal: Option<CurrentReceiptRefusal>,
        receipt_refusal: Option<CurrentReceiptRefusal>,
        receipt_epochs: Option<CompleteEpochs>,
        current_image: ImageIdentity,
        fault_cell: Arc<std::sync::atomic::AtomicU64>,
        concurrent_raise: bool,
    }
    impl ScriptIo {
        fn new(domain: NativeDomainId) -> Self {
            let path = std::env::current_exe().unwrap();
            let pins = crate::discovery::identity::test_fixture::real_scan_pin(
                &path,
                None,
                1,
                "held-test-image",
            );
            let watched = pins.retain_inventory_target(PinnedObjectId(0)).unwrap();
            let sibling = crate::discovery::identity::test_fixture::real_scan_pin(
                std::path::Path::new("/usr/bin/true"),
                None,
                2,
                "held-sibling-image",
            )
            .retain_inventory_target(PinnedObjectId(0))
            .unwrap();
            assert_ne!(
                watched.object_key(),
                sibling.object_key(),
                "sibling must be a distinct physical file"
            );
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
                watched: [watched, sibling],
                attachment_refusal: None,
                receipt_refusal: None,
                receipt_epochs: None,
                current_image: ImageIdentity {
                    task_cookie: 1,
                    exec_id: 1,
                },
                fault_cell: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                concurrent_raise: false,
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
        fn semantic_call(&mut self, name: &str, file: u32, fault: u32) {
            self.call(1, fault);
            let record = self.records.back_mut().unwrap();
            // Native function selection belongs to the retained attach slot;
            // target_function is a different, captured API argument.
            let function_slot = match name {
                "C_SignInit" => 0,
                "C_Sign" => 1,
                _ => panic!("fixture endpoint not retained"),
            };
            record.event.slot = file * 2 + function_slot;
            record.continuity.entry_stamp.file_slot_plus1 = (file + 1) as u16;
            record.continuity.return_stamp.file_slot_plus1 = (file + 1) as u16;
            record.continuity.entry_ip +=
                u64::from(file) * 0x4000 + u64::from(function_slot) * 0x100;
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
        fn raise_fault(&mut self) -> Result<u64, ()> {
            self.raises += 1;
            if self.raise_fails {
                return Err(());
            }
            use std::sync::atomic::Ordering;
            self.fault_cell
                .store(self.last_health.fault, Ordering::SeqCst);
            let raised = crate::attach::raise_fault_test_cell(&self.fault_cell).map_err(|_| ())?;
            if self.concurrent_raise {
                let cell = self.fault_cell.clone();
                std::thread::spawn(move || crate::attach::raise_fault_test_cell(&cell).unwrap())
                    .join()
                    .unwrap();
            }
            self.last_health.fault = self.fault_cell.load(Ordering::SeqCst);
            Ok(raised)
        }
        fn retained_attachment(
            &self,
            slot: u32,
        ) -> Result<RetainedInventoryTarget, CurrentReceiptRefusal> {
            if let Some(refusal) = self.attachment_refusal {
                return Err(refusal);
            }
            self.watched
                .get((slot / 2) as usize)
                .map(RetainedInventoryTarget::share)
                .ok_or(CurrentReceiptRefusal::Attachment)
        }
        fn receipt_state(
            &mut self,
            _: &Arc<PidPin>,
            _: ImageIdentity,
            endpoint: Endpoint,
            _: u32,
            _: Instant,
        ) -> Result<ReceiptState, CurrentReceiptRefusal> {
            if let Some(refusal) = self.receipt_refusal {
                return Err(refusal);
            }
            Ok(ReceiptState {
                image: self.current_image,
                epochs: self.receipt_epochs.unwrap_or(CompleteEpochs {
                    local: u64::from(self.local),
                    global: 0,
                    fault: self.last_health.fault,
                    sticky: self.last_health.sticky,
                    record_flags: 0,
                }),
                watched: self.watched[endpoint.file_slot as usize].share(),
            })
        }
        fn endpoint(&self, slot: u32) -> Option<Endpoint> {
            (slot < 4).then_some(Endpoint {
                object: PinnedObjectId(slot / 2),
                file_slot: slot / 2,
                offset: 0x1200 + u64::from(slot % 2) * 0x100,
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
            let base = u64::from(job.endpoint.file_slot) * 0x4000;
            let mut ranges = vec![
                MapRange::new(base + 0x1000, base + 0x2000, 0, false),
                MapRange::new(base + 0x2000, base + 0x3000, 0x1000, true),
            ];
            if self.extra_range {
                ranges.push(MapRange::new(0x4000, 0x5000, 0, false));
            }
            self.current_image = self.output_image.unwrap_or(job.image);
            acquire_test_scan(
                self.domain,
                self.output_image.unwrap_or(job.image),
                self.output_file.unwrap_or(job.endpoint.file_slot),
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
                slot: endpoint.file_slot * 2,
                pin: pin.clone(),
                deadline,
            };
            self.scan(&job, deadline, fence, current)
        }
    }
    fn capture(io: &ScriptIo) -> SemanticCapture {
        SemanticCapture::in_domain(io.domain, TickLimits::default()).unwrap()
    }
    fn stash_watched() -> RetainedInventoryTarget {
        let pins = crate::discovery::identity::test_fixture::real_scan_pin(
            &std::env::current_exe().unwrap(),
            None,
            1,
            "held-test-image",
        );
        pins.retain_inventory_target(PinnedObjectId(0)).unwrap()
    }
    fn merge_receipt(
        domain: NativeDomainId,
        cookie: u64,
        watched: &RetainedInventoryTarget,
    ) -> CurrentPartitionReceipt {
        CurrentPartitionReceipt::scripted(
            domain,
            ImageIdentity {
                task_cookie: cookie,
                exec_id: 1,
            },
            Arc::new(PidPin::test_proc_only(4321)),
            Endpoint {
                object: PinnedObjectId(0),
                file_slot: 0,
                offset: 0x1200,
            },
            0,
            watched.share(),
            CompleteEpochs {
                local: 0,
                global: 0,
                fault: 0,
                sticky: 0,
                record_flags: 0,
            },
            0,
            Instant::now() + Duration::from_secs(60),
            Vec::new(),
        )
    }
    #[test]
    fn merge_stashed_current_appends_fresh_first() {
        let domain = NativeDomainId::mint();
        let watched = stash_watched();
        let mut report = TickReport::scripted(
            Vec::new(),
            vec![
                merge_receipt(domain, 1, &watched),
                merge_receipt(domain, 2, &watched),
            ],
        );
        let stashed = vec![
            merge_receipt(domain, 3, &watched),
            merge_receipt(domain, 4, &watched),
        ];
        assert_eq!(report.merge_stashed_current(stashed), 0);
        let cookies: Vec<u64> = report
            .current()
            .iter()
            .map(|receipt| receipt.image().task_cookie)
            .collect();
        assert_eq!(
            cookies,
            vec![1, 2, 3, 4],
            "fresh receipts first, stashed appended"
        );
    }
    #[test]
    fn merge_stashed_current_truncates_to_batch_capacity() {
        let domain = NativeDomainId::mint();
        let watched = stash_watched();
        let mut report = TickReport::scripted(Vec::new(), vec![merge_receipt(domain, 0, &watched)]);
        let stashed: Vec<_> = (1..=MAX_INSTANCES as u64)
            .map(|cookie| merge_receipt(domain, cookie, &watched))
            .collect();
        assert_eq!(report.merge_stashed_current(stashed), 1);
        assert_eq!(report.current().len(), MAX_INSTANCES);
        assert_eq!(
            report.current()[0].image().task_cookie,
            0,
            "the fresh receipt survives truncation"
        );
    }
    #[test]
    fn merge_stashed_outcomes_sheds_calls_before_invalidations() {
        let domain = NativeDomainId::mint();
        let call = || {
            let stamp = InstanceStamp::default();
            TickOutcome::Call(RoutedCall::scripted(
                domain,
                event_record_with_routing(p11scope_ebpf_common::Event::default(), stamp, 0x2200),
                Route::Unknown(UnknownReason::PendingCapacity),
                None,
                Some(1),
            ))
        };
        let invalidation = TickOutcome::Invalidation(Invalidation {
            domain,
            scope: InvalidationScope::FaultEra,
            position: Some(1025),
        });
        assert!(invalidation.is_invalidation());
        assert!(!call().is_invalidation());
        let mut report =
            TickReport::scripted((0..MAX_INSTANCES).map(|_| call()).collect(), Vec::new());
        assert_eq!(report.merge_stashed_outcomes(vec![invalidation]), 1);
        assert_eq!(report.outcomes().len(), MAX_INSTANCES);
        assert!(
            report
                .outcomes()
                .iter()
                .any(|outcome| matches!(outcome, TickOutcome::Invalidation(_))),
            "the merged invalidation survives a full batch: a call sheds instead"
        );
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

    mod custody_chain_tests {
        //! One custody Arc through H0 refresh, coordinator binding, tick and
        //! receipt validation: H0's `ptr_eq` gates refuse any re-duplication.
        use super::*;
        use crate::attach::BackendSelection;
        use crate::attach::Scope;
        use crate::attach::capture::{
            CaptureHealth, CapturePhase, CookieQuery, DiscoveryBatch, DomainCookie, ExecCoverage,
            ExtendReceipt, ScopeCustody, WitnessBatch, WitnessRow,
        };
        use crate::discovery::caller_registry::{
            AdmissionState, CallerId, ImageAuthority, ModuleInfo, ModuleKey, OsProcessSource,
            RegistryLimits, now_ns,
        };
        use crate::discovery::engine::inventory_coordinator::{InventoryCoordinator, NativeBatch};
        use crate::discovery::hooks::HookRegistry;
        use crate::discovery::inventory_attach_set::{AttachObjectId, EndpointId};
        use crate::discovery::native_binding::NativeIdentity;
        use crate::inventory_semantics::{
            AttestedSemanticLane, LaneDrainOutcome, LaneTestIo, RefreshReceiptStash, SemanticBatch,
            SemanticRefusal, effective_refresh_custody, merge_stash_into_report,
            stash_refresh_report,
        };
        use std::collections::HashMap;

        mod semantic_validation;

        #[derive(Default)]
        struct ChainIdentity {
            answers: HashMap<(u32, NativeDomainId), CookieQuery>,
        }

        impl NativeIdentity<PidPin> for ChainIdentity {
            fn owner_image(&mut self, _pid: u32) -> Option<ImageIdentity> {
                None
            }

            fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
                self.answers
                    .get(&(pin.pid(), domain))
                    .cloned()
                    .unwrap_or(CookieQuery::NoCookie)
            }
        }

        std::thread_local! {
            static SIGHT_NS: std::cell::Cell<u64> = const { std::cell::Cell::new(1_005) };
        }

        fn sight_clock() -> Option<u64> {
            SIGHT_NS.with(|clock| Some(clock.get()))
        }

        struct CustodyScene {
            coordinator: InventoryCoordinator<OsProcessSource>,
            identity: ChainIdentity,
            detailed: NativeDomainId,
            module: ModuleKey,
        }

        impl CustodyScene {
            fn new() -> Self {
                let mut coordinator = InventoryCoordinator::new(
                    Scope::Pid(std::process::id()),
                    HookRegistry::builtin(),
                    Vec::new(),
                    OsProcessSource,
                    RegistryLimits::default_limits(),
                )
                .unwrap();
                let detailed = NativeDomainId::mint();
                coordinator.note_extend_receipt(&ExtendReceipt {
                    activated_roots: true,
                    exec_coverage: Some(ExecCoverage::scripted(detailed, 0)),
                    ..ExtendReceipt::default()
                });
                coordinator.set_semantic_binding_clock(sight_clock);
                Self {
                    coordinator,
                    identity: ChainIdentity::default(),
                    detailed,
                    module: ModuleKey::physical(7, 7, 777, None, "/task3/provider.so"),
                }
            }

            fn admit(&mut self, pid: u32, at_ns: u64) -> CallerId {
                self.coordinator
                    .adapter_mut()
                    .admit(pid, ImageAuthority::ScanPinned, at_ns)
                    .unwrap()
            }

            fn map(&mut self, caller: CallerId, pid: u32, at_ns: u64) {
                let info = ModuleInfo {
                    path: "/task3/provider.so".into(),
                    key: self.module.clone(),
                    double_loaded: false,
                    build_id: None,
                    identity_source: Some("task3".into()),
                    admission: AdmissionState::Admitted,
                    admission_class: Some("exact".into()),
                    admission_endpoints: Some(1),
                    admission_reasons: Vec::new(),
                };
                self.coordinator
                    .registry_mut()
                    .note_mapping(caller, pid, info, at_ns);
                self.coordinator.commit_batch(false).unwrap();
            }

            fn answer(&mut self, pid: u32, domain: NativeDomainId, ticket: u64) {
                self.identity.answers.insert(
                    (pid, domain),
                    CookieQuery::Cookie(DomainCookie::scripted(domain, ticket)),
                );
            }

            fn witness_read(&mut self, domain: NativeDomainId, rows: Vec<WitnessRow>, at_ns: u64) {
                let batch = WitnessBatch {
                    domain,
                    phase: CapturePhase::Active,
                    rows,
                    integrity: Vec::new(),
                    integrity_total: 0,
                    visited: 0,
                    sweep_completed: true,
                    sweeps_completed: 1,
                    row_bound_reached: false,
                    deadline_reached: false,
                    read_failures: Vec::new(),
                    unrecorded_rows: 0,
                    sweep_gaps: false,
                    counts: Vec::new(),
                    refresh_sweep_completed: true,
                    refresh_sweep_gaps: false,
                    refresh_deadline_reached: false,
                    refresh_sweeps_completed: 1,
                    seen_rows: 0,
                    pair_limit: 65_536,
                    health: CaptureHealth {
                        discovery_counters: Some([0; 5]),
                        ..CaptureHealth::default()
                    },
                    health_regression: None,
                    health_unproven: None,
                    health_baseline_ns: 0,
                    health_read_ns: at_ns,
                    rows_anchor_ns: at_ns + 1,
                    rows_read_ns: at_ns + 1,
                    counts_read_ns: at_ns + 1,
                    changed_objects: Vec::new(),
                    custody: ScopeCustody::System,
                    custody_proven_ns: None,
                    lifecycle_proven_ns: u64::MAX,
                    lifecycle_loss: None,
                    unsettled: false,
                };
                self.coordinator.stage_native(
                    NativeBatch::Witness(Box::new(batch)),
                    &mut self.identity,
                    at_ns + 2,
                );
            }

            fn drain(&mut self, domain: NativeDomainId, at_ns: u64) {
                let batch = DiscoveryBatch::scripted(domain, Vec::new(), at_ns);
                self.coordinator.stage_native(
                    NativeBatch::Lifecycle(batch),
                    &mut self.identity,
                    at_ns + 1,
                );
            }

            fn bind_image(
                &mut self,
                domain: NativeDomainId,
                rows: Vec<(u64, u64, u32, u64)>,
                at_ns: u64,
            ) {
                let rows = rows
                    .into_iter()
                    .map(|(ticket, exec, tgid, t0)| {
                        WitnessRow::scripted(
                            domain,
                            ticket,
                            exec,
                            AttachObjectId::scripted(0),
                            EndpointId(0),
                            tgid,
                            t0,
                        )
                    })
                    .collect();
                self.witness_read(domain, rows, at_ns);
                self.drain(domain, at_ns + 10);
                self.witness_read(domain, Vec::new(), at_ns + 20);
                self.coordinator.commit_batch(false).unwrap();
            }
        }

        /// Attested subset over the two ScriptIo semantic slots, aligned
        /// to `ScriptIo::endpoint` so real routed Init/Sign calls convert.
        fn operation_subset()
        -> crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset {
            use crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset;
            use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
            let slot = |index: u32, name: &str, offset: u64| crate::plan::Slot {
                index,
                descriptor_index: crate::kinds::function_id(name).unwrap() + 1,
                object: PinnedObjectId(0),
                object_path: "/operation-probe.so".into(),
                file_offset: offset,
                names: vec![name.into()],
                aliased: false,
                semantics: crate::kinds::descriptor(name).unwrap(),
                semantic_authorized: true,
                semantic_ambiguous: false,
                fork_safe: true,
                module_ids: vec![crate::plan::ModuleId(0)],
            };
            let plan = crate::plan::AttachPlan::from_slots(vec![
                slot(0, "C_SignInit", 0x1200),
                slot(1, "C_Sign", 0x1300),
            ]);
            AttestedSubset::scripted(
                plan,
                PinnedObjects::empty(),
                std::collections::BTreeMap::new(),
            )
        }

        /// Tests-only substituted H0 I/O behind a lane: the real H0
        /// decisions (refresh/tick/validate/stop) through `ScriptIo`,
        /// with the production stash/merge/batch helpers. Installed
        /// into a shell lane so tests drive the production
        /// stage→finalize→commit path without a live Session.
        struct H0TestIo {
            capture: SemanticCapture,
            io: ScriptIo,
            stash: RefreshReceiptStash,
            last_refresh_deadline: Option<Instant>,
            /// Clock advance applied at the start of every tick:
            /// quiescence tests age receipts per serviced quantum.
            tick_advance: Duration,
            /// Merge/stash shed disclosed while driving (the lane owns
            /// this counter in production).
            shed: u64,
            /// Serviced quanta after which the substituted producer
            /// quiesces; each tick counts one.
            quiesce_after: usize,
            serviced: usize,
        }

        impl H0TestIo {
            fn new(domain: NativeDomainId) -> Self {
                let io = ScriptIo::new(domain);
                let capture = capture(&io);
                Self {
                    capture,
                    io,
                    stash: RefreshReceiptStash::new(),
                    last_refresh_deadline: None,
                    tick_advance: Duration::ZERO,
                    shed: 0,
                    quiesce_after: 0,
                    serviced: 0,
                }
            }
        }

        impl LaneTestIo for H0TestIo {
            fn validate_current(
                &mut self,
                receipt: &CurrentPartitionReceipt,
            ) -> Result<(), CurrentReceiptRefusal> {
                let mut scratch = TickReport::default();
                self.capture
                    .validate_current_with(&mut self.io, receipt, &mut scratch)
            }

            fn tick(&mut self, domain: NativeDomainId) -> Result<SemanticBatch, SemanticRefusal> {
                self.io.now += self.tick_advance;
                self.serviced += 1;
                let mut report = self
                    .capture
                    .tick_with(&mut self.io)
                    .map_err(|_| SemanticRefusal::Unavailable)?;
                self.shed = self
                    .shed
                    .saturating_add(merge_stash_into_report(&mut self.stash, &mut report));
                SemanticBatch::from_tick_report(domain, report, Vec::new(), now_ns())
            }

            fn refresh(
                &mut self,
                pin: Arc<PidPin>,
                slot: u32,
            ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal> {
                let mut report = self
                    .capture
                    .refresh_with(&mut self.io, pin.clone(), slot)
                    .map_err(|_| SemanticRefusal::Unavailable)?;
                self.last_refresh_deadline =
                    report.current().first().map(|receipt| receipt.deadline);
                let effective = effective_refresh_custody(&report, pin);
                let (images, shed) = stash_refresh_report(&mut self.stash, &mut report);
                self.shed = self.shed.saturating_add(shed);
                Ok((images, effective))
            }

            fn has_pending_evidence(&self) -> bool {
                !self.stash.is_empty()
            }

            fn finish(&mut self, domain: NativeDomainId) -> SemanticBatch {
                let report = self.capture.stop();
                SemanticBatch::from_tick_report(domain, report, Vec::new(), now_ns())
                    .expect("H0 stop batches respect lane bounds")
            }

            fn quiescent(&mut self) -> bool {
                self.serviced >= self.quiesce_after
            }

            fn positions(&mut self) -> Option<[(usize, usize); 2]> {
                Some([(0, 0), (0, 0)])
            }

            fn drain_events_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
                LaneDrainOutcome::default()
            }

            fn drain_discovery_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
                LaneDrainOutcome::default()
            }
        }

        /// A coordinator scene bound to a lane's own domain: the bind
        /// proof runs in the lane's domain exactly as in production, so
        /// the lane's receipts finalize against the stored binding.
        struct LaneScene {
            scene: CustodyScene,
            lane: AttestedSemanticLane,
        }

        fn bound_lane_scene(image: ImageIdentity) -> LaneScene {
            let lane = AttestedSemanticLane::start(
                operation_subset(),
                &Scope::Pid(std::process::id()),
                BackendSelection::Auto,
            )
            .expect("shell lane starts");
            let domain = lane.domain();
            let mut scene = CustodyScene::new();
            scene.coordinator.note_extend_receipt(&ExtendReceipt {
                activated_roots: true,
                exec_coverage: Some(ExecCoverage::scripted(domain, 0)),
                ..ExtendReceipt::default()
            });
            let pid = std::process::id();
            let caller = scene.admit(pid, 50);
            scene.map(caller, pid, 60);
            scene.answer(pid, domain, image.task_cookie);
            scene.bind_image(
                domain,
                vec![(image.task_cookie, image.exec_id, pid, 100)],
                1_000,
            );
            let pin = Arc::new(
                scene
                    .coordinator
                    .adapter()
                    .live_pin(pid)
                    .and_then(|(_, pin)| pin.try_clone().ok())
                    .unwrap(),
            );
            scene
                .coordinator
                .bind_semantic_caller_with_pin(
                    caller,
                    scene.module.clone(),
                    domain,
                    image,
                    &mut scene.identity,
                    pin,
                )
                .unwrap();
            LaneScene { scene, lane }
        }

        /// Published semantic edge rows: (api returns, historical-only
        /// returns, lossy, started, completed).
        fn operation_edge_rows(scene: &CustodyScene) -> Vec<(Option<u64>, u64, bool, u64, u64)> {
            scene
                .coordinator
                .registry()
                .instance_semantic_edges()
                .map(|row| {
                    let started = row.semantics.as_ref().map(|s| s.started()).unwrap_or(0);
                    let completed = row.semantics.as_ref().map(|s| s.completed()).unwrap_or(0);
                    (
                        row.api_returns,
                        row.historical_only_returns,
                        row.lossy,
                        started,
                        completed,
                    )
                })
                .collect()
        }

        #[test]
        fn refresh_bind_tick_validate_share_one_custody_arc() {
            let mut scene = CustodyScene::new();
            let pid = std::process::id();
            let caller = scene.admit(pid, 50);
            scene.map(caller, pid, 60);
            let detailed = scene.detailed;
            let module = scene.module.clone();
            let image = ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            };
            scene.answer(pid, detailed, 7);
            scene.bind_image(detailed, vec![(7, 1, pid, 100)], 1_000);
            // The production refresh pin: one duplication off the live pin,
            // given to H0's refresh (inventory.rs `bind_semantic_callers`).
            let pin: Arc<PidPin> = Arc::new(
                scene
                    .coordinator
                    .adapter()
                    .live_pin(pid)
                    .and_then(|(_, pin)| pin.try_clone().ok())
                    .unwrap(),
            );
            // H0 serves this pin's targets through the same Arc.
            let mut io = ScriptIo::new(NativeDomainId::mint());
            io.pin = pin.clone();
            let mut capture = capture(&io);
            let refresh = capture.refresh_with(&mut io, pin.clone(), 0).unwrap();
            assert_eq!(
                refresh.current().len(),
                1,
                "the accepted refresh scan mints one receipt"
            );
            let refreshed = refresh.current()[0].original_pin().clone();
            assert!(
                Arc::ptr_eq(&refreshed, &pin),
                "H0 retains the exact refresh Arc"
            );
            // The binding stores the passed Arc, never a re-duplication.
            scene
                .coordinator
                .bind_semantic_caller_with_pin(
                    caller,
                    module,
                    detailed,
                    image,
                    &mut scene.identity,
                    pin.clone(),
                )
                .unwrap();
            let bound = scene
                .coordinator
                .semantic_bindings()
                .get(caller)
                .unwrap()
                .pin();
            assert!(
                Arc::ptr_eq(&bound, &pin),
                "the stored binding shares the refresh Arc"
            );
            // The refresh receipt validates through the retained Arc.
            let mut scratch = TickReport::default();
            assert_eq!(
                capture.validate_current_with(&mut io, &refresh.current()[0], &mut scratch),
                Ok(())
            );
            // A fresh-image tick scans through the binding pin: the minted
            // receipt shares it and validates.
            io.call_image(2, 1, 0);
            let tick = capture.tick_with(&mut io).unwrap();
            assert!(
                tick.calls().any(|call| matches!(
                    call.route(),
                    crate::discovery::instances::Route::Joined(_)
                )),
                "the tick serves the fresh image"
            );
            assert_eq!(tick.current().len(), 1);
            assert!(
                Arc::ptr_eq(tick.current()[0].original_pin(), &bound),
                "the tick receipt shares the binding Arc"
            );
            assert_eq!(
                capture.validate_current_with(&mut io, &tick.current()[0], &mut scratch),
                Ok(())
            );
        }

        #[test]
        fn failed_bind_retry_reuses_h0_retained_arc_through_production_loop() {
            let mut lane = AttestedSemanticLane::start(
                operation_subset(),
                &Scope::Pid(std::process::id()),
                BackendSelection::Auto,
            )
            .expect("shell lane starts");
            let domain = lane.domain();
            let mut scene = CustodyScene::new();
            scene.coordinator.note_extend_receipt(&ExtendReceipt {
                activated_roots: true,
                exec_coverage: Some(ExecCoverage::scripted(domain, 0)),
                ..ExtendReceipt::default()
            });
            let pid = std::process::id();
            let caller = scene.admit(pid, 50);
            scene.map(caller, pid, 60);
            let module = scene.module.clone();
            let image = ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            };
            // H0 shares the bind domain exactly as a live lane would;
            // the scan proves the same image the coordinator proof
            // expects.
            let mut h0 = H0TestIo::new(domain);
            h0.io.output_image = Some(image);
            lane.install_test_io(Box::new(h0));
            let targets = vec![(caller, pid, 0u32, module)];
            let mut passed: Vec<Arc<PidPin>> = Vec::new();
            let mut minted: Vec<(Vec<ImageIdentity>, Arc<PidPin>)> = Vec::new();
            // The production bind loop over the lane's own refresh: the
            // refresh closure records each pass's offered pin and the
            // images plus effective custody Arc the lane reports.
            macro_rules! drive_pass {
                () => {{
                    let mut refresh = |pin: Arc<PidPin>, slot: u32| {
                        passed.push(pin.clone());
                        let report = lane.refresh_candidate_with_custody(pin, slot)?;
                        minted.push((report.0.clone(), report.1.clone()));
                        Ok(report)
                    };
                    crate::inventory::bind_semantic_candidates(
                        &mut scene.coordinator,
                        domain,
                        &mut scene.identity,
                        &targets,
                        &mut refresh,
                    );
                }};
            }
            // Pass N: the refresh accepts (H0 retains Arc A) but the
            // coordinator proof refuses without identity evidence.
            drive_pass!();
            assert!(
                scene.coordinator.semantic_bindings().get(caller).is_none(),
                "pass N binds nothing without identity evidence"
            );
            assert_eq!(passed.len(), 1);
            assert_eq!(minted[0].0, vec![image]);
            assert!(
                Arc::ptr_eq(&minted[0].1, &passed[0]),
                "H0 retains the exact pass-N refresh Arc"
            );
            // Pass N+1: identity evidence arrives; the retry duplicates
            // a fresh Arc B but must bind through H0's retained Arc A.
            scene.answer(pid, domain, 7);
            scene.bind_image(domain, vec![(7, 1, pid, 100)], 1_000);
            drive_pass!();
            assert_eq!(passed.len(), 2);
            assert!(
                !Arc::ptr_eq(&passed[0], &passed[1]),
                "each pass duplicates its pin fresh: the retry really offers Arc B"
            );
            assert_eq!(minted.len(), 2);
            assert_eq!(minted[1].0, vec![image]);
            assert!(
                Arc::ptr_eq(&minted[1].1, &passed[0]),
                "the retry receipt carries the retained Arc"
            );
            let bound = scene
                .coordinator
                .semantic_bindings()
                .get(caller)
                .expect("the retry binds after an accepted-refresh/failed-bind pass")
                .pin();
            assert!(
                Arc::ptr_eq(&bound, &passed[0]),
                "the retry binding shares H0's retained Arc A, not the fresh duplicate"
            );
            // The retry receipt finalizes through the lane: the next
            // tick stages the stashed retry proof and the commit
            // registers it against the retained Arc.
            let batch = {
                let bindings = scene
                    .coordinator
                    .semantic_bindings_mut()
                    .bindings_for_tick();
                lane.tick(bindings).unwrap()
            };
            assert!(
                !batch.is_empty(),
                "the tick batch carries the stashed retry proof"
            );
            scene.coordinator.stage_semantic_batch(batch);
            scene
                .coordinator
                .commit_batch_with_semantics(false, Some(&mut lane))
                .unwrap();
            let gaps: Vec<(String, String)> = scene
                .coordinator
                .registry()
                .gaps()
                .iter()
                .map(|gap| (gap.subject.clone(), gap.reason.clone()))
                .collect();
            assert!(
                !gaps.iter().any(|gap| gap.0 == "semantic receipt refused"),
                "the retry proof validates through the retained Arc: {gaps:?}"
            );
            assert_eq!(
                scene.coordinator.registry().instances().count(),
                1,
                "the retry receipt registers one instance at commit"
            );
        }

        /// Stash overflow preserves the fault-era invalidation: with
        /// 1024 pending calls, the next audit emits the FaultEra
        /// invalidation first and resolves all 1024 calls behind it, so
        /// the refresh report holds 1025 outcomes against the 1024-item
        /// stash. The shed outcome must be a call, never the
        /// invalidation: the merged batch finalizes the exact
        /// H0-minted loss boundary through the production commit.
        #[test]
        fn stash_overflow_preserves_fault_era_invalidation_at_1024_pending() {
            let image = ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            };
            let mut fixture = bound_lane_scene(image);
            let domain = fixture.lane.domain();
            let mut h0 = H0TestIo::new(domain);
            h0.io.output_image = Some(image);
            // Image 7 never scans: every record parks Pending.
            h0.io.fail_cookie = Some(image.task_cookie);
            for _ in 0..MAX_PENDING {
                h0.io.call(image.task_cookie, 0);
            }
            let parked = h0.tick(domain).unwrap();
            assert!(
                parked.is_empty(),
                "all 1024 records park pending with no scan to resolve them"
            );
            // The fault era moves: the next audit invalidates first,
            // then resolves every pending call behind it.
            h0.io.health.push_back(Ok(Health {
                fault: 1,
                sticky: 0,
            }));
            let pin: Arc<PidPin> = Arc::new(
                fixture
                    .scene
                    .coordinator
                    .adapter()
                    .live_pin(std::process::id())
                    .and_then(|(_, pin)| pin.try_clone().ok())
                    .unwrap(),
            );
            let (images, _effective) = h0.refresh(pin, 0).unwrap();
            assert!(images.is_empty());
            assert_eq!(
                h0.shed, 1,
                "1025 outcomes against the 1024-item stash shed exactly one"
            );
            fixture.lane.install_test_io(Box::new(h0));
            // The next lane tick merges the stashed evidence and the
            // pass commit finalizes it: H2 must see the exact
            // H0-minted FaultEra boundary, not a refusal count.
            let batch = {
                let bindings = fixture
                    .scene
                    .coordinator
                    .semantic_bindings_mut()
                    .bindings_for_tick();
                fixture.lane.tick(bindings).unwrap()
            };
            assert!(
                !batch.is_empty(),
                "the tick batch carries the stashed overflow evidence"
            );
            fixture.scene.coordinator.stage_semantic_batch(batch);
            fixture
                .scene
                .coordinator
                .commit_batch_with_semantics(false, Some(&mut fixture.lane))
                .unwrap();
            assert_eq!(
                fixture.lane.take_last_conversion_barrier(),
                Some(MAX_PENDING as u64 + 1),
                "the FaultEra invalidation survives the stash: its position fences conversion"
            );
        }

        /// Quiet registration end to end through the production lane
        /// and finalizer: a no-call refresh proves the quiet provider's
        /// partition, the proof waits the normal 1s pass schedule, the
        /// next lane tick stages it, and the pass commit finalizes it
        /// into one registration. Past the receipt window the same
        /// proof refuses through the audited path and registers
        /// nothing.
        #[test]
        fn quiet_refresh_registers_through_next_tick_batch() {
            let image = ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            };
            for buffered in [false, true] {
                let mut fixture = bound_lane_scene(image);
                let domain = fixture.lane.domain();
                let mut h0 = H0TestIo::new(domain);
                h0.io.output_image = Some(image);
                let pin: Arc<PidPin> = Arc::new(
                    fixture
                        .scene
                        .coordinator
                        .adapter()
                        .live_pin(std::process::id())
                        .and_then(|(_, pin)| pin.try_clone().ok())
                        .unwrap(),
                );
                // The production refresh: one accepted no-call scan,
                // stashed for the next tick batch.
                let (images, _effective) = h0.refresh(pin, 0).unwrap();
                assert_eq!(images, vec![image]);
                assert_eq!(h0.shed, 0);
                assert!(h0.has_pending_evidence());
                // The normal pass schedule (1s) or past the receipt
                // window (3s > 2s pending): only timing differs.
                h0.io.now += Duration::from_secs(if buffered { 3 } else { 1 });
                fixture.lane.install_test_io(Box::new(h0));
                // The next tick batch through the lane, finalized by
                // the pass commit beside the physical evidence.
                let batch = {
                    let bindings = fixture
                        .scene
                        .coordinator
                        .semantic_bindings_mut()
                        .bindings_for_tick();
                    fixture.lane.tick(bindings).unwrap()
                };
                assert!(
                    !batch.is_empty(),
                    "the tick batch carries the stashed quiet proof"
                );
                fixture.scene.coordinator.stage_semantic_batch(batch);
                fixture
                    .scene
                    .coordinator
                    .commit_batch_with_semantics(false, Some(&mut fixture.lane))
                    .unwrap();
                let gaps: Vec<(String, String)> = fixture
                    .scene
                    .coordinator
                    .registry()
                    .gaps()
                    .iter()
                    .map(|gap| (gap.subject.clone(), gap.reason.clone()))
                    .collect();
                if buffered {
                    assert_eq!(
                        fixture.scene.coordinator.registry().instances().count(),
                        0,
                        "an expired proof registers nothing"
                    );
                    assert!(
                        gaps.contains(&(
                            "semantic receipt refused".to_string(),
                            "deadline".to_string()
                        )),
                        "the expired proof refuses through the audited path: {gaps:?}"
                    );
                    continue;
                }
                assert!(
                    !gaps.iter().any(|gap| gap.0 == "semantic receipt refused"),
                    "the fresh proof validates: {gaps:?}"
                );
                assert_eq!(
                    fixture.scene.coordinator.registry().instances().count(),
                    1,
                    "the quiet proof registers one instance at commit"
                );
            }
        }

        /// Drive a quiet refresh receipt through ClassicDriver using
        /// H0's actual minting, stash merge and receipt validator. The
        /// original proof clock ages before the driver stages it.
        fn classic_tick_with_aged_refresh(remaining: Duration) -> CustodyScene {
            let image = ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            };
            let mut fixture = bound_lane_scene(image);
            let domain = fixture.lane.domain();
            let pin = fixture
                .scene
                .coordinator
                .semantic_bindings()
                .find_by_image(domain, image)
                .unwrap()
                .pin();
            let mut h0 = H0TestIo::new(domain);
            h0.io.output_image = Some(image);
            h0.capture.limits.pending_for = Duration::from_secs(2);
            let staged_at = Instant::now();
            h0.io.now = staged_at - (Duration::from_secs(2) - remaining);
            let (images, retained) = h0.refresh(pin.clone(), 0).unwrap();
            assert_eq!(images, vec![image]);
            assert!(Arc::ptr_eq(&retained, &pin));
            assert!(h0.has_pending_evidence());
            assert_eq!(
                h0.last_refresh_deadline
                    .unwrap()
                    .saturating_duration_since(staged_at),
                remaining,
                "the original H0 receipt has the selected lifetime at staging"
            );
            // Aging preserves the minted deadline: no re-proof or new
            // receipt is supplied by this no-call tick.
            h0.io.now = staged_at;
            fixture.lane.install_test_io(Box::new(h0));
            let _lane = crate::inventory::classic_semantic_tick_for_test(
                &mut fixture.scene.coordinator,
                fixture.lane,
            );
            fixture.scene
        }

        #[test]
        fn short_lived_refresh_receipt_commits_through_classic_driver() {
            for (remaining, expected_instances) in
                [(Duration::from_millis(300), 1), (Duration::ZERO, 0)]
            {
                let scene = classic_tick_with_aged_refresh(remaining);
                assert_eq!(
                    scene.coordinator.registry().instances().count(),
                    expected_instances,
                    "original remaining={remaining:?}: registration follows real H0 validation"
                );
                let refusals: Vec<&str> = scene
                    .coordinator
                    .registry()
                    .gaps()
                    .iter()
                    .filter(|gap| gap.subject == "semantic receipt refused")
                    .map(|gap| gap.reason.as_str())
                    .collect();
                if remaining.is_zero() {
                    assert_eq!(refusals, vec!["deadline"]);
                } else {
                    assert!(
                        refusals.is_empty(),
                        "fresh receipt refuses nothing: {refusals:?}"
                    );
                }
            }
        }

        #[test]
        fn longer_lived_refresh_receipt_commits_through_classic_driver() {
            // Above the old 1s threshold, publication still must be
            // prompt: later tick scheduling cannot guarantee the
            // remaining original receipt window will survive.
            let scene = classic_tick_with_aged_refresh(Duration::from_millis(1_500));
            assert_eq!(scene.coordinator.registry().instances().count(), 1);
            assert!(
                scene
                    .coordinator
                    .registry()
                    .gaps()
                    .iter()
                    .all(|gap| gap.subject != "semantic receipt refused")
            );
        }

        /// Terminal drain through production with real H0 receipts
        /// under delayed quiescence: Q arrives after 4 servicing
        /// quanta, each aging H0 1s (4s total, past the 2s receipt
        /// window). Every drained batch commits promptly in its own
        /// quantum through the production drain and receipt finalizer,
        /// so the drained Init/Sign pair validates fresh and completes
        /// one operation. Both orders run: a receipt minted by the
        /// drain itself, and a refresh receipt stashed before the stop
        /// (flushed by the drain's pre-flush).
        #[test]
        fn prompt_drain_commits_complete_operation_under_delayed_quiescence() {
            use crate::discovery::caller_registry::instance_input::InstanceReason;

            for prestashed in [false, true] {
                let image = ImageIdentity {
                    task_cookie: 7,
                    exec_id: 1,
                };
                let mut fixture = bound_lane_scene(image);
                let domain = fixture.lane.domain();
                let mut h0 = H0TestIo::new(domain);
                h0.io.output_image = Some(image);
                h0.io.semantic_call("C_SignInit", 0, 0);
                h0.io.records.back_mut().unwrap().event.image = image;
                h0.io.semantic_call("C_Sign", 0, 0);
                h0.io.records.back_mut().unwrap().event.image = image;
                if prestashed {
                    // A quiet refresh proves the partition before the
                    // stop; its proof waits stashed for the pre-flush.
                    let pin: Arc<PidPin> = Arc::new(
                        fixture
                            .scene
                            .coordinator
                            .adapter()
                            .live_pin(std::process::id())
                            .and_then(|(_, pin)| pin.try_clone().ok())
                            .unwrap(),
                    );
                    let (images, _effective) = h0.refresh(pin, 0).unwrap();
                    assert_eq!(images, vec![image]);
                    assert!(h0.has_pending_evidence());
                }
                // Delayed quiescence: Q after 4 quanta of the 5s stop
                // budget, each quantum aging H0 1s. The 4s total passes
                // the 2s receipt window: only prompt per-quantum
                // commits validate fresh.
                assert!(
                    Duration::from_secs(4) < crate::run::STOP_QUIESCE_BUDGET,
                    "the delayed quiescence fits the stop budget"
                );
                h0.tick_advance = Duration::from_secs(1);
                h0.quiesce_after = 4;
                fixture.lane.install_test_io(Box::new(h0));
                let summary = fixture.lane.run_semantic_drain_committing(
                    &mut fixture.scene.coordinator,
                    &[],
                    Instant::now,
                );
                assert!(summary.quiesced, "prestashed={prestashed}: quiesces");
                assert!(
                    summary.final_drain,
                    "prestashed={prestashed}: drains exactly to Q"
                );
                assert!(
                    !summary.semantic_loss,
                    "prestashed={prestashed}: no semantic loss"
                );
                assert_eq!(
                    summary.drain_batches, 1,
                    "prestashed={prestashed}: exactly the Init/Sign quantum commits"
                );
                // H0 stops once, after every drained batch published;
                // the terminal Finish batch commits separately.
                let finish = fixture.lane.finish_semantic_stop().unwrap();
                fixture.scene.coordinator.stage_semantic_batch(finish);
                fixture
                    .scene
                    .coordinator
                    .commit_batch_with_semantics(false, Some(&mut fixture.lane))
                    .unwrap();
                let gaps: Vec<(String, String)> = fixture
                    .scene
                    .coordinator
                    .registry()
                    .gaps()
                    .iter()
                    .map(|gap| (gap.subject.clone(), gap.reason.clone()))
                    .collect();
                assert!(
                    !gaps.iter().any(|gap| gap.0 == "semantic receipt refused"),
                    "prestashed={prestashed}: the drained proof validates: {gaps:?}"
                );
                assert_eq!(
                    operation_edge_rows(&fixture.scene),
                    vec![(Some(2), 0, true, 1, 1)],
                    "prestashed={prestashed}: the drained Init/Sign pair completes one operation; \
                     the terminal stop discloses lossy"
                );
                let reasons: Vec<InstanceReason> = fixture
                    .scene
                    .coordinator
                    .registry()
                    .instance_semantic_edges()
                    .next()
                    .unwrap()
                    .reasons
                    .iter()
                    .copied()
                    .collect();
                assert_eq!(
                    reasons,
                    vec![InstanceReason::SemanticLoss, InstanceReason::CaptureStopped],
                    "prestashed={prestashed}: only the terminal stop fences the completed \
                     operation (boundary plus cause)"
                );
            }
        }
    }
}
