//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded preparation, ordered accounting, shared proof and live finish.
//!
//! Speculative maps reads use private work budgets, but every real pin uses
//! one collection reservation owner. Replay previews an attempted-action
//! journal without I/O or capture mutation. Accepted journals commit before
//! any proof; rejected records and speculative tails drop before fresh reads.

use crate::discovery::scan::{
    CaptureWorkBudget, ConfirmMark, MapsReadBudget, MapsReadBuffers, MapsReadLimits,
};
use crate::discovery::sweep_attribution::{
    AttributionLoss, ConfirmIo, Confirmation, FD_RESOURCE_REASON, FdLease, IoResources,
    KnownKeyIndex, MappedIdentities, MemberProbe, PreparationKind, PreparedConfirmation,
    ReservationOwner, ReservedPin, SegmentPolicy, SweepAttribution, attribute_one, budget_refusal,
    confirm_with_resources, finish_confirmation, idle_needs_promotion, lost_with, preparation_kind,
    proof_ranges, read_ranges_reserved,
};
use crate::discovery::sweep_shards::{Transcript, record_read, replay_one};
use p11scope_manifest::maps::{MapEntry, ObjectKey};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

/// Minted only after the shared preparation has committed its charges. The
/// driver keeps the original Io/pin while these request views are borrowed.
pub(crate) struct AcceptedRequest<'a> {
    pid: u32,
    ranges: &'a [(u64, u64)],
    entries: &'a [MapEntry],
    #[allow(dead_code)] // The D3c promotion packet uses this original fd.
    pidfd: Option<std::os::fd::BorrowedFd<'a>>,
    #[allow(dead_code)] // The central segment hook also includes idle plans.
    kind: AcceptedKind,
}

#[derive(Clone, Copy)]
pub(crate) enum AcceptedKind {
    Confirm,
    #[allow(dead_code)]
    Idle,
}

impl AcceptedRequest<'_> {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
    pub(crate) fn ranges(&self) -> &[(u64, u64)] {
        self.ranges
    }
    pub(crate) fn entries(&self) -> &[MapEntry] {
        self.entries
    }
    #[allow(dead_code)]
    pub(crate) fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.pidfd
    }
    #[allow(dead_code)]
    pub(crate) fn kind(&self) -> AcceptedKind {
        self.kind
    }
}

pub(crate) struct AcceptedBatch<'a> {
    requests: Vec<AcceptedRequest<'a>>,
    token: Arc<()>,
}

impl AcceptedBatch<'_> {
    pub(crate) fn requests(&self) -> &[AcceptedRequest<'_>] {
        &self.requests
    }
    pub(crate) fn token(&self) -> &Arc<()> {
        &self.token
    }
}

pub(crate) trait SegmentProof {
    fn prove<'r>(
        &'r mut self,
        batch: &AcceptedBatch<'_>,
        budget: &mut CaptureWorkBudget,
        resources: &IoResources,
    ) -> crate::discovery::kernel_identity::ProofDecision<'r>;
}

/// The standalone adapter uses the same prepared ownership and batch minting
/// seam as the later central segment hook; no scalar request constructor is
/// exposed to the kernel owner.
pub(crate) fn prove_and_finish_prepared<Io: ConfirmIo>(
    io: &mut Io,
    pid: u32,
    prepared: PreparedConfirmation<Io::Pin>,
    hook: &mut impl SegmentProof,
    resources: &IoResources,
    budget: &mut CaptureWorkBudget,
) -> Confirmation {
    let batch = AcceptedBatch {
        requests: vec![AcceptedRequest {
            pid,
            ranges: &prepared.ranges,
            entries: &prepared.entries,
            pidfd: io.borrowed_pidfd(&prepared.pin.pin),
            kind: AcceptedKind::Confirm,
        }],
        token: Arc::new(()),
    };
    let decision = hook.prove(&batch, budget, resources);
    let answers = decision.answer(&batch, 0).cloned();
    drop(batch);
    if let Some(reason) = budget.check_deadline_now() {
        return Confirmation::Lost(AttributionLoss::Budget, reason.into());
    }
    let mapped =
        answers.unwrap_or_else(|| read_ranges_reserved(io, pid, &prepared.ranges, Some(resources)));
    let result = finish_confirmation(io, pid, prepared, mapped, Some(resources), budget);
    // Keep the guard-bound result through final live checks, and consume it
    // before another target run can replace scope or reuse slot numbers.
    drop(decision);
    result
}

pub(crate) trait ShardableIo: ConfirmIo + Send {
    type Maps: Read;
    fn open_maps(&mut self, pid: u32) -> std::io::Result<Self::Maps>;
    fn maps_now(&self) -> Option<u64>;
}

const DIVERGED: &str = "confirmation accounting journal diverged";
const CANCELLED: &str = "confirmation preparation was cancelled";

/// All mutating calls, including failed spends and consumed stop reports,
/// are transactions in their original order. A shadow is never transplanted.
#[derive(Debug)]
enum BudgetAction {
    Deadline(Option<u64>, Option<&'static str>),
    Allowed(usize, usize),
    Io(usize),
    Stop(Option<&'static str>),
    Spend(Result<(), &'static str>),
}

#[derive(Debug, PartialEq, Eq)]
struct JournalState {
    mark: ConfirmMark,
    stop: Option<&'static str>,
    unreported_stop: Option<&'static str>,
    window_exhaustions: u64,
}

impl JournalState {
    fn of(budget: &CaptureWorkBudget) -> Self {
        // Observing a private maps shadow does not consume the capture's
        // report or poll its clock. The mark alone omits these mutations.
        let mut observer = budget.maps_shadow();
        Self {
            mark: budget.confirm_mark(),
            stop: budget.stopped_reason(),
            unreported_stop: observer.take_scan_stop_reason(),
            window_exhaustions: budget.window_exhaustions(),
        }
    }
}

struct BudgetJournal {
    shadow: CaptureWorkBudget,
    start: JournalState,
    actions: Vec<BudgetAction>,
}

impl BudgetJournal {
    fn new(budget: &CaptureWorkBudget) -> Self {
        Self {
            shadow: budget.shard_shadow(),
            start: JournalState::of(budget),
            actions: Vec::new(),
        }
    }

    fn spend(&mut self) -> Result<(), &'static str> {
        let out = self.shadow.spend(1);
        self.actions.push(BudgetAction::Spend(out));
        out
    }

    /// The caller exclusively owns the capture budget between preview and
    /// commit. Any disagreement refuses publication in release builds too.
    fn commit(self, budget: &mut CaptureWorkBudget) -> Result<(), &'static str> {
        if self.start != JournalState::of(budget) {
            return Err(DIVERGED);
        }
        for action in self.actions {
            let agrees = match action {
                BudgetAction::Deadline(now, expected) => budget.check_deadline(now) == expected,
                BudgetAction::Allowed(wanted, expected) => {
                    MapsReadBudget::allowed_capture_io(budget, wanted) == expected
                }
                BudgetAction::Io(bytes) => {
                    budget.record_io(bytes);
                    true
                }
                BudgetAction::Stop(expected) => budget.take_scan_stop_reason() == expected,
                BudgetAction::Spend(expected) => budget.spend(1) == expected,
            };
            if !agrees {
                return Err(DIVERGED);
            }
        }
        if JournalState::of(budget) != JournalState::of(&self.shadow) {
            return Err(DIVERGED);
        }
        Ok(())
    }
}

impl MapsReadBudget for BudgetJournal {
    fn has_deadline(&self) -> bool {
        self.shadow.has_deadline()
    }
    fn check_deadline(&mut self, now: Option<u64>) -> Option<&'static str> {
        let out = self.shadow.check_deadline(now);
        self.actions.push(BudgetAction::Deadline(now, out));
        out
    }
    fn allowed_capture_io(&mut self, wanted: usize) -> usize {
        let out = MapsReadBudget::allowed_capture_io(&mut self.shadow, wanted);
        self.actions.push(BudgetAction::Allowed(wanted, out));
        out
    }
    fn record_io(&mut self, bytes: usize) {
        self.shadow.record_io(bytes);
        self.actions.push(BudgetAction::Io(bytes));
    }
    fn take_scan_stop_reason(&mut self) -> Option<&'static str> {
        let out = self.shadow.take_scan_stop_reason();
        self.actions.push(BudgetAction::Stop(out));
        out
    }
}

/// Declaration order closes a real maps reader before returning its slots.
struct LeasedReader<R> {
    inner: R,
    _lease: FdLease,
}
impl<R: Read> Read for LeasedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(bytes)
    }
}

struct Record<Io: ShardableIo> {
    start: ConfirmMark,
    state: RecordedState<Io>,
}
enum RecordedState<Io: ShardableIo> {
    Settled,
    Idle {
        io: Io,
        ranges: Vec<(u64, u64)>,
    },
    Confirm {
        io: Io,
        pin: ReservedPin<Io::Pin>,
        before: crate::discovery::caller_registry::ExeIdentity,
        maps: Result<Transcript, String>,
    },
    Failed(Confirmation),
}

struct Prepared<Io: ShardableIo> {
    state: PreparedState<Io>,
    mapped: MappedIdentities,
}
enum PreparedState<Io: ShardableIo> {
    Settled,
    Idle {
        io: Io,
        ranges: Vec<(u64, u64)>,
    },
    Confirm {
        io: Io,
        plan: PreparedConfirmation<Io::Pin>,
    },
    Failed(Confirmation),
}

impl<Io: ShardableIo> Prepared<Io> {
    fn new(state: PreparedState<Io>) -> Self {
        Self {
            state,
            mapped: MappedIdentities::new(),
        }
    }
    fn requests(&self) -> usize {
        match &self.state {
            PreparedState::Idle { ranges, .. } => ranges.len(),
            PreparedState::Confirm { plan, .. } => plan.ranges.len(),
            _ => 0,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn record<Io: ShardableIo, F: Fn() -> Io>(
    pid: u32,
    phase_one: &[MapEntry],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    prove: &BTreeSet<ObjectKey>,
    shadow: &mut CaptureWorkBudget,
    resources: &IoResources,
    make_io: &F,
) -> Record<Io> {
    let start = shadow.confirm_mark();
    let state = match preparation_kind(pid, phase_one, unavailable, selected, index) {
        PreparationKind::Settled => RecordedState::Settled,
        PreparationKind::Idle(ranges) => {
            let mut seen = BTreeSet::new();
            for range in &ranges {
                if seen.insert(*range) && shadow.spend(1).is_err() {
                    break;
                }
            }
            RecordedState::Idle {
                io: make_io(),
                ranges,
            }
        }
        PreparationKind::Confirm => {
            let mut io = make_io();
            let prepared = (|| {
                let transient = resources.transient().map_err(|error| {
                    Confirmation::Lost(AttributionLoss::ConfirmUnreadable, error)
                })?;
                let lease = resources.pin().map_err(|error| {
                    Confirmation::Lost(AttributionLoss::ConfirmUnreadable, error)
                })?;
                let pin = io
                    .open(pid)
                    .map(|pin| ReservedPin {
                        pin,
                        _lease: Some(lease),
                    })
                    .map_err(|error| {
                        lost_with(&io, pid, AttributionLoss::ConfirmUnreadable, error)
                    })?;
                let before = io.exe(pid).ok_or_else(|| {
                    lost_with(
                        &io,
                        pid,
                        AttributionLoss::ConfirmUnreadable,
                        "the exe identity could not be read".into(),
                    )
                })?;
                let maps = match io.open_maps(pid) {
                    Err(error) => Err(error.to_string()),
                    Ok(maps) => {
                        let maps = LeasedReader {
                            inner: maps,
                            _lease: transient,
                        };
                        let mut bufs = MapsReadBuffers::default();
                        let (transcript, unclean) = record_read(
                            maps,
                            shadow,
                            MapsReadLimits::LIVE,
                            &|| io.maps_now(),
                            &mut bufs,
                        );
                        let result = unclean
                            .or_else(|| transcript.clean_result().cloned())
                            .unwrap_or_else(|| Err(DIVERGED.into()));
                        if let Ok(entries) = result {
                            for _ in proof_ranges(&entries, prove) {
                                if shadow.spend(1).is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(transcript)
                    }
                };
                Ok((pin, before, maps))
            })();
            match prepared {
                Ok((pin, before, maps)) => RecordedState::Confirm {
                    io,
                    pin,
                    before,
                    maps,
                },
                Err(confirmation) => RecordedState::Failed(confirmation),
            }
        }
    };
    Record { start, state }
}

fn preview<Io: ShardableIo>(
    record: Record<Io>,
    pid: u32,
    prove: &BTreeSet<ObjectKey>,
    budget: &CaptureWorkBudget,
    resources: &IoResources,
) -> (Prepared<Io>, BudgetJournal) {
    let mut journal = BudgetJournal::new(budget);
    let state = match record.state {
        RecordedState::Settled => PreparedState::Settled,
        RecordedState::Failed(confirmation) => PreparedState::Failed(confirmation),
        RecordedState::Idle { io, ranges } => {
            let mut charged = Vec::new();
            let mut seen = BTreeSet::new();
            for range in ranges {
                if !seen.insert(range) {
                    continue;
                }
                if journal.spend().is_err() {
                    break;
                }
                charged.push(range);
            }
            PreparedState::Idle {
                io,
                ranges: charged,
            }
        }
        RecordedState::Confirm {
            io,
            pin,
            before,
            maps,
        } => {
            let mut bufs = MapsReadBuffers::default();
            let entries = match maps {
                Ok(transcript) => replay_one(
                    transcript,
                    &mut journal,
                    MapsReadLimits::LIVE,
                    &crate::attach::monotonic_ns,
                    &mut bufs,
                ),
                Err(error) => Err(error),
            };
            match entries {
                Err(reason) => PreparedState::Failed(if budget_refusal(&reason) {
                    Confirmation::Lost(AttributionLoss::Budget, reason)
                } else {
                    match resources.transient() {
                        Ok(_lease) => {
                            lost_with(&io, pid, AttributionLoss::ConfirmUnreadable, reason)
                        }
                        Err(error) => Confirmation::Lost(AttributionLoss::ConfirmUnreadable, error),
                    }
                }),
                Ok(entries) => {
                    let ranges = proof_ranges(&entries, prove);
                    let mut failed = None;
                    for _ in &ranges {
                        if let Err(reason) = journal.spend() {
                            failed = Some(reason);
                            break;
                        }
                    }
                    match failed {
                        Some(reason) => PreparedState::Failed(Confirmation::Lost(
                            AttributionLoss::Budget,
                            reason.into(),
                        )),
                        None => PreparedState::Confirm {
                            io,
                            plan: PreparedConfirmation {
                                pin,
                                before,
                                entries,
                                ranges,
                            },
                        },
                    }
                }
            }
        }
    };
    (Prepared::new(state), journal)
}

/// At most W running plus completed-unreplayed records exist. Every job is
/// inside the fixed P-prefix; early released pins do not extend its boundary.
#[allow(clippy::too_many_arguments)]
fn prepare_segment<Io, F>(
    sweep: &[(u32, Vec<MapEntry>)],
    range: std::ops::Range<usize>,
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    prove: &BTreeSet<ObjectKey>,
    budget: &mut CaptureWorkBudget,
    policy: SegmentPolicy,
    resources: &IoResources,
    threads: usize,
    make_io: &F,
) -> (Vec<(usize, Prepared<Io>)>, bool)
where
    Io: ShardableIo,
    Io::Pin: Send,
    F: Fn() -> Io + Sync,
{
    let template = budget.shard_shadow();
    let cancel = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let requested_workers = threads.max(1).min(policy.workers).min(range.len());
        let (reply, replies) = mpsc::channel();
        let mut jobs = Vec::new();
        // The caller is worker zero. A refused extra worker leaves the
        // successful partial pool intact and never changes the segment.
        for worker in 1..requested_workers {
            let (send, receive) = mpsc::channel::<usize>();
            let reply = reply.clone();
            let cancel = &cancel;
            let mut shadow = template.shard_shadow();
            let spawned = std::thread::Builder::new()
                .name(format!("p11scope-confirm-prepare-{worker}"))
                .stack_size(256 << 10)
                .spawn_scoped(scope, move || {
                    for position in receive {
                        if cancel.load(Ordering::Acquire) {
                            let _ = reply.send((position, None));
                            continue;
                        }
                        let (pid, entries) = &sweep[position];
                        let recorded =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                record(
                                    *pid,
                                    entries,
                                    unavailable,
                                    selected,
                                    index,
                                    prove,
                                    &mut shadow,
                                    resources,
                                    make_io,
                                )
                            }));
                        let recorded = match recorded {
                            Ok(recorded) => Some(recorded),
                            Err(_) => {
                                cancel.store(true, Ordering::Release);
                                None
                            }
                        };
                        let _ = reply.send((position, recorded));
                    }
                });
            match spawned {
                Ok(_) => jobs.push(send),
                Err(_) => break,
            }
        }
        drop(reply);
        let workers = jobs.len() + 1;
        let mut caller_jobs = VecDeque::new();
        let mut caller_shadow = template.shard_shadow();
        let mut sent = range.start;
        let initial_end = range.start.saturating_add(policy.workers).min(range.end);
        let mut pending = BTreeMap::new();
        let mut accepted = Vec::new();
        let mut ranges = 0usize;
        let dispatch = |position: usize, caller_jobs: &mut VecDeque<usize>| {
            let worker = (position - range.start) % workers;
            if worker == 0 {
                caller_jobs.push_back(position);
                Ok(())
            } else {
                jobs[worker - 1].send(position).map_err(|_| ())
            }
        };
        while sent < initial_end && !cancel.load(Ordering::Acquire) {
            if dispatch(sent, &mut caller_jobs).is_err() {
                cancel.store(true, Ordering::Release);
                break;
            }
            sent += 1;
        }
        for position in range.clone() {
            if cancel.load(Ordering::Acquire) {
                break;
            }
            while !pending.contains_key(&position) {
                if cancel.load(Ordering::Acquire) {
                    break;
                }
                if let Some(at) = caller_jobs.pop_front() {
                    let (pid, entries) = &sweep[at];
                    let recorded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        record(
                            *pid,
                            entries,
                            unavailable,
                            selected,
                            index,
                            prove,
                            &mut caller_shadow,
                            resources,
                            make_io,
                        )
                    }));
                    let recorded = match recorded {
                        Ok(recorded) => Some(recorded),
                        Err(_) => {
                            cancel.store(true, Ordering::Release);
                            None
                        }
                    };
                    pending.insert(at, recorded);
                    continue;
                }
                match replies.recv() {
                    Ok((at, recorded)) => {
                        pending.insert(at, recorded);
                    }
                    Err(_) => {
                        cancel.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            let Some(Some(mut recorded)) = pending.remove(&position) else {
                cancel.store(true, Ordering::Release);
                break;
            };
            if !recorded.start.covers(&budget.confirm_mark()) {
                // Destruction closes the original pin and returns its slot
                // before this position is prepared again, live.
                drop(recorded);
                let (pid, entries) = &sweep[position];
                recorded = record(
                    *pid,
                    entries,
                    unavailable,
                    selected,
                    index,
                    prove,
                    &mut budget.shard_shadow(),
                    resources,
                    make_io,
                );
            }
            let (prepared, journal) =
                preview(recorded, sweep[position].0, prove, budget, resources);
            let Some(next) = ranges
                .checked_add(prepared.requests())
                .filter(|next| *next <= policy.max_ranges)
            else {
                drop(prepared); // No journal action has touched capture state.
                break;
            };
            if journal.commit(budget).is_err() {
                drop(prepared);
                cancel.store(true, Ordering::Release);
                break;
            }
            ranges = next;
            accepted.push((position, prepared));
            if sent < range.end && !cancel.load(Ordering::Acquire) {
                if dispatch(sent, &mut caller_jobs).is_err() {
                    cancel.store(true, Ordering::Release);
                    break;
                }
                sent += 1;
            }
        }
        // No new work after closure. Queued/completed tail records are all
        // joined and destroyed before a fresh segment or immediate reread.
        drop(jobs);
        for (_, recorded) in pending {
            drop(recorded);
        }
        for (_, recorded) in replies {
            drop(recorded);
        }
        (accepted, cancel.load(Ordering::Acquire))
    })
}

/// A whole segment is proved before any member is finished. This is the
/// transaction seam for a later backend's complete-run validation/fallback.
fn prove_segment<Io: ShardableIo>(
    prepared: Vec<(usize, Prepared<Io>)>,
    sweep: &[(u32, Vec<MapEntry>)],
    resources: &IoResources,
    threads: usize,
) -> Result<Vec<(usize, Prepared<Io>)>, ()>
where
    Io::Pin: Send,
{
    let cancel = AtomicBool::new(false);
    let workers = threads.max(1).min(prepared.len());
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        let mut jobs = Vec::new();
        // Build the fallible pool before moving any prepared pin into a
        // worker. A creation refusal only reduces execution concurrency.
        for worker in 1..workers {
            let (send, receive) = mpsc::channel();
            let cancel = &cancel;
            let spawned = std::thread::Builder::new()
                .name(format!("p11scope-confirm-proof-{worker}"))
                .stack_size(256 << 10)
                .spawn_scoped(scope, move || match receive.recv() {
                    Ok(part) => prove_part(part, sweep, resources, cancel),
                    Err(_) => Vec::new(),
                });
            match spawned {
                Ok(handle) => {
                    jobs.push(send);
                    handles.push(handle);
                }
                Err(_) => break,
            }
        }
        let workers = jobs.len() + 1;
        let mut rest = prepared.into_iter();
        let caller_size = rest.len().div_ceil(workers);
        let mut caller_part: Vec<_> = rest.by_ref().take(caller_size).collect();
        for (at, send) in jobs.into_iter().enumerate() {
            let size = rest.len().div_ceil(workers - at - 1);
            let part: Vec<_> = rest.by_ref().take(size).collect();
            if let Err(mpsc::SendError(part)) = send.send(part) {
                caller_part.extend(part);
            }
        }
        let mut out = prove_part(caller_part, sweep, resources, &cancel);
        for handle in handles {
            match handle.join() {
                Ok(part) => out.extend(part),
                Err(_) => cancel.store(true, Ordering::Release),
            }
        }
        if cancel.load(Ordering::Acquire) {
            Err(())
        } else {
            out.sort_by_key(|(position, _)| *position);
            Ok(out)
        }
    })
}

fn prove_part<Io: ShardableIo>(
    part: Vec<(usize, Prepared<Io>)>,
    sweep: &[(u32, Vec<MapEntry>)],
    resources: &IoResources,
    cancel: &AtomicBool,
) -> Vec<(usize, Prepared<Io>)> {
    let mut out = Vec::new();
    for (position, mut prepared) in part {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match &mut prepared.state {
                PreparedState::Idle { io, ranges } => {
                    prepared.mapped =
                        read_ranges_reserved(io, sweep[position].0, ranges, Some(resources))
                }
                PreparedState::Confirm { io, plan } => {
                    prepared.mapped =
                        read_ranges_reserved(io, sweep[position].0, &plan.ranges, Some(resources))
                }
                _ => {}
            }));
        if result.is_err() {
            cancel.store(true, Ordering::Release);
            break;
        }
        out.push((position, prepared));
    }
    out
}

struct FinishedProbe {
    confirmation: Option<Confirmation>,
    mapped: MappedIdentities,
}
impl MemberProbe for FinishedProbe {
    fn confirm(
        &mut self,
        _pid: u32,
        _prove: &BTreeSet<ObjectKey>,
        _budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        self.confirmation.take().unwrap_or_else(|| {
            Confirmation::Lost(AttributionLoss::ConfirmUnreadable, DIVERGED.into())
        })
    }
    fn stat_ranges(
        &mut self,
        _pid: u32,
        _ranges: &[(u64, u64)],
        _budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        std::mem::take(&mut self.mapped)
    }
}

#[allow(clippy::too_many_arguments)]
fn cancel_segment(
    out: &mut SweepAttribution,
    range: std::ops::Range<usize>,
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    prove: &BTreeSet<ObjectKey>,
    budget: &mut CaptureWorkBudget,
) {
    for at in range {
        let (pid, entries) = &sweep[at];
        // These positions already committed their journals. Their refused
        // finish must not charge idle prefixes a second time.
        let mut probe = FinishedProbe {
            confirmation: Some(Confirmation::Lost(
                AttributionLoss::ConfirmUnreadable,
                CANCELLED.into(),
            )),
            mapped: MappedIdentities::new(),
        };
        attribute_one(
            out,
            *pid,
            entries,
            unavailable,
            selected,
            index,
            prove,
            &mut probe,
            budget,
        );
    }
}

struct RefusedProbe<'a> {
    reason: &'a str,
}
impl MemberProbe for RefusedProbe<'_> {
    fn confirm(
        &mut self,
        _pid: u32,
        _prove: &BTreeSet<ObjectKey>,
        _budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        Confirmation::Lost(AttributionLoss::ConfirmUnreadable, self.reason.into())
    }
    fn stat_ranges(
        &mut self,
        _pid: u32,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        let mut seen = BTreeSet::new();
        ranges
            .iter()
            .copied()
            .filter(|range| seen.insert(*range))
            .take_while(|_| budget.spend(1).is_ok())
            .map(|range| {
                (
                    range,
                    crate::discovery::sweep_attribution::RangeProof::Unavailable(
                        self.reason.into(),
                    ),
                )
            })
            .collect()
    }
}

/// Same fixed policy for serial and parallel executors. Production supplies
/// one census/owner; tests inject H and range quotas without changing rlimits.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attribute_unselected_with_policy<Io, F>(
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    budget: &mut CaptureWorkBudget,
    policy: SegmentPolicy,
    owner: &ReservationOwner,
    threads: usize,
    make_io: &F,
) -> SweepAttribution
where
    Io: ShardableIo,
    Io::Pin: Send,
    F: Fn() -> Io + Sync,
{
    let prove = index.map_files_keys();
    let mut out = SweepAttribution::default();
    let batch = owner.batch();
    let immediate = owner.immediate();
    let mut position = 0usize;
    let mut cancelled = false;
    while position < sweep.len() {
        if cancelled || policy.headroom < 3 {
            let reason = if cancelled {
                CANCELLED
            } else {
                FD_RESOURCE_REASON
            };
            let (pid, entries) = &sweep[position];
            attribute_one(
                &mut out,
                *pid,
                entries,
                unavailable,
                selected,
                index,
                &prove,
                &mut RefusedProbe { reason },
                budget,
            );
            position += 1;
            continue;
        }
        if policy.retained == 0 {
            immediate_one(
                &mut out,
                position,
                sweep,
                unavailable,
                selected,
                index,
                &prove,
                budget,
                &immediate,
                make_io,
            );
            position += 1;
            continue;
        }
        let end = position.saturating_add(policy.retained).min(sweep.len());
        let (prepared, failed) = prepare_segment(
            sweep,
            position..end,
            unavailable,
            selected,
            index,
            &prove,
            budget,
            policy,
            &batch,
            threads,
            make_io,
        );
        if failed {
            let next = position + prepared.len();
            drop(prepared);
            cancel_segment(
                &mut out,
                position..next,
                sweep,
                unavailable,
                selected,
                index,
                &prove,
                budget,
            );
            position = next;
            cancelled = true;
            continue;
        }
        if prepared.is_empty() {
            // An oversized single caller is a one-PID immediate segment.
            immediate_one(
                &mut out,
                position,
                sweep,
                unavailable,
                selected,
                index,
                &prove,
                budget,
                &immediate,
                make_io,
            );
            position += 1;
            continue;
        }
        let next = position + prepared.len();
        let proven = match prove_segment(prepared, sweep, &batch, threads.min(policy.workers)) {
            Ok(proven) => proven,
            Err(()) => {
                cancel_segment(
                    &mut out,
                    position..next,
                    sweep,
                    unavailable,
                    selected,
                    index,
                    &prove,
                    budget,
                );
                position = next;
                cancelled = true;
                continue;
            }
        };
        let mut promotions = Vec::new();
        for (at, prepared) in proven {
            let (pid, entries) = &sweep[at];
            if matches!(&prepared.state, PreparedState::Idle { .. })
                && idle_needs_promotion(index, entries, &prepared.mapped)
            {
                promotions.push((at, prepared.mapped));
                continue;
            }
            let (confirmation, mapped) = match prepared.state {
                PreparedState::Confirm { io, plan } => (
                    Some(finish_confirmation(
                        &io,
                        *pid,
                        plan,
                        prepared.mapped,
                        Some(&batch),
                        budget,
                    )),
                    MappedIdentities::new(),
                ),
                PreparedState::Failed(confirmation) => (Some(confirmation), prepared.mapped),
                _ => (None, prepared.mapped),
            };
            let mut probe = FinishedProbe {
                confirmation,
                mapped,
            };
            attribute_one(
                &mut out,
                *pid,
                entries,
                unavailable,
                selected,
                index,
                &prove,
                &mut probe,
                budget,
            );
        }
        // Every retained batch pin is gone before the immediate envelope
        // is used for phase D, and before the next fixed prefix prepares.
        for (at, mapped) in promotions {
            let (pid, entries) = &sweep[at];
            let mut io = make_io();
            let confirmation =
                confirm_with_resources(&mut io, *pid, &prove, budget, Some(&immediate));
            let mut probe = FinishedProbe {
                confirmation: Some(confirmation),
                mapped,
            };
            attribute_one(
                &mut out,
                *pid,
                entries,
                unavailable,
                selected,
                index,
                &prove,
                &mut probe,
                budget,
            );
        }
        position = next;
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn immediate_one<Io: ShardableIo, F: Fn() -> Io>(
    out: &mut SweepAttribution,
    position: usize,
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    prove: &BTreeSet<ObjectKey>,
    budget: &mut CaptureWorkBudget,
    resources: &IoResources,
    make_io: &F,
) {
    let (pid, entries) = &sweep[position];
    let recorded = record(
        *pid,
        entries,
        unavailable,
        selected,
        index,
        prove,
        &mut budget.shard_shadow(),
        resources,
        make_io,
    );
    let (mut prepared, journal) = preview(recorded, *pid, prove, budget, resources);
    if journal.commit(budget).is_err() {
        drop(prepared);
        attribute_one(
            out,
            *pid,
            entries,
            unavailable,
            selected,
            index,
            prove,
            &mut RefusedProbe { reason: DIVERGED },
            budget,
        );
        return;
    }
    match &mut prepared.state {
        PreparedState::Idle { io, ranges } => {
            prepared.mapped = read_ranges_reserved(io, *pid, ranges, Some(resources))
        }
        PreparedState::Confirm { io, plan } => {
            prepared.mapped = read_ranges_reserved(io, *pid, &plan.ranges, Some(resources))
        }
        _ => {}
    }
    let (confirmation, mapped) = match prepared.state {
        PreparedState::Confirm { io, plan } => (
            Some(finish_confirmation(
                &io,
                *pid,
                plan,
                prepared.mapped,
                Some(resources),
                budget,
            )),
            MappedIdentities::new(),
        ),
        PreparedState::Failed(confirmation) => (Some(confirmation), prepared.mapped),
        PreparedState::Idle { .. } if idle_needs_promotion(index, entries, &prepared.mapped) => (
            Some(confirm_with_resources(
                &mut make_io(),
                *pid,
                prove,
                budget,
                Some(resources),
            )),
            prepared.mapped,
        ),
        _ => (None, prepared.mapped),
    };
    attribute_one(
        out,
        *pid,
        entries,
        unavailable,
        selected,
        index,
        prove,
        &mut FinishedProbe {
            confirmation,
            mapped,
        },
        budget,
    );
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn attribute_unselected_sharded<Io, F>(
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    budget: &mut CaptureWorkBudget,
    shards: usize,
    make_io: &F,
) -> SweepAttribution
where
    Io: ShardableIo,
    Io::Pin: Send,
    F: Fn() -> Io + Sync,
{
    let policy = SegmentPolicy::snapshot(
        crate::discovery::sweep_shards::MAX_SHARD_THREADS,
        sweep.len(),
    );
    let owner = ReservationOwner::new(policy);
    attribute_unselected_with_policy(
        sweep,
        unavailable,
        selected,
        index,
        budget,
        policy,
        &owner,
        shards,
        make_io,
    )
}

#[cfg(test)]
#[path = "confirm_shards_tests.rs"]
mod tests;
