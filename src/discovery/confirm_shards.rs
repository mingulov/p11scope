//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Bounded preparation, ordered accounting, shared proof and live finish.
//!
//! Speculative maps reads use private work budgets, but every real pin uses
//! one collection reservation owner. Replay previews an attempted-action
//! journal without I/O or capture mutation. Accepted journals commit before
//! any proof; rejected records and speculative tails drop before fresh reads.

use crate::discovery::identity::PinnedObjects;
use crate::discovery::overlay_witness::SweepWitness;
use crate::discovery::retained_member::RetainedGroupMember;
use crate::discovery::scan::{
    CaptureWorkBudget, ConfirmMark, MapsReadBudget, MapsReadBuffers, MapsReadLimits,
};
use crate::discovery::sweep_attribution::{
    AttributionLoss, ConfirmIo, Confirmation, FD_RESOURCE_REASON, FdLease, IoResources,
    KnownKeyIndex, MappedIdentities, MemberProbe, PreparationKind, PreparedConfirmation,
    RangeProof, ReservationOwner, ReservedPin, SegmentPolicy, SweepAttribution, attribute_one,
    budget_refusal, confirm_with_resources, finish_confirmation, idle_needs_promotion, lost_with,
    preparation_kind, prepare_confirmation, proof_ranges, read_ranges_reserved,
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
    /// The validated survivor for a zombie-group confirm, borrowed from
    /// the preparation that minted it. `Some` exactly for zombie-group
    /// member requests, which only ever run as single-request TID runs.
    member: Option<&'a RetainedGroupMember>,
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
    pub(crate) fn member(&self) -> Option<&RetainedGroupMember> {
        self.member
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

/// Whether refused candidate `index` (counted across the whole pass,
/// in segment order) falls in this pass's witness window: the
/// per-pass budget covers one budget of consecutive candidates
/// starting at `start`, modulo the previous pass's refused count. The
/// window walks over refused candidates rather than sweep positions,
/// so sparse refused sets still rotate instead of pinning one tail
/// caller every pass.
fn witness_window_member(index: usize, start: u64, denominator: usize, per_pass: u32) -> bool {
    let candidates = denominator.max(1) as u64;
    // Distance forward from `start` to `index` modulo the count (a
    // wrapping subtraction would skew past `u64::MAX`, since 2^64 is
    // not a multiple of the count); members sit within one budget.
    let position = (index as u64) % candidates;
    let start = start % candidates;
    let distance = if position >= start {
        position - start
    } else {
        candidates - (start - position)
    };
    distance < u64::from(per_pass)
}

/// Prove overlay-refused ranges via the private witness session (K1-R2,
/// live capture watched providers): one query per (pid, key) over every
/// refused range of the key; SameFile replaces all that key's refused
/// ranges with [`RangeProof::Witnessed`] (join), anything else keeps
/// refused (named loss, never a userspace join). Ranges under no entry,
/// non-overlay keys, keys without a pinned file, candidates outside
/// this pass's window, and budget exhaustion all keep refused
/// (fail-closed). Every grouped key counts into `refused_counter`
/// (the pass-wide candidate index), whether or not it is queried.
#[allow(clippy::too_many_arguments)]
fn witness_overlay_refused(
    pid: u32,
    mapped: &mut MappedIdentities,
    entries: &[MapEntry],
    index: &KnownKeyIndex,
    pins: &PinnedObjects,
    witness: &mut dyn SweepWitness,
    budget: &mut CaptureWorkBudget,
    window_start: u64,
    window_denominator: usize,
    refused_counter: &mut usize,
) {
    use crate::discovery::identity::MappedFile;
    use crate::discovery::overlay_witness::WitnessVerdict;
    use p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC;

    let by_range: BTreeMap<(u64, u64), ObjectKey> = entries
        .iter()
        .map(|entry| ((entry.start, entry.end), ObjectKey::of(entry)))
        .collect();
    let mut by_key: BTreeMap<ObjectKey, Vec<(u64, u64)>> = BTreeMap::new();
    for (range, proof) in mapped.iter() {
        if *proof != RangeProof::OverlayRefused {
            continue;
        }
        let Some(key) = by_range.get(range) else {
            continue;
        };
        if !index.is_overlay_key(*key) {
            continue;
        }
        by_key.entry(*key).or_default().push(*range);
    }
    // Stable key order: the pass-wide window (not a local rotation)
    // decides which candidates prove this pass.
    let keys: Vec<(ObjectKey, Vec<(u64, u64)>)> = by_key.into_iter().collect();
    for (key, ranges) in keys {
        let member = witness_window_member(
            *refused_counter,
            window_start,
            window_denominator,
            witness.queries_per_pass(),
        );
        *refused_counter += 1;
        if !member {
            continue;
        }
        let Some((object, expected)) = index.match_pin(key) else {
            continue;
        };
        let Some(file) = pins.file_for(object) else {
            continue;
        };
        // No new read: identity from the index, magic synthesized overlay
        // (key_is_identity is false for overlay either way).
        let held = MappedFile {
            identity: expected,
            fs_magic: Some(OVERLAYFS_SUPER_MAGIC),
        };
        if ranges.is_empty() {
            continue;
        }
        if witness.prove(pid, file, &held, key, &ranges, budget) == WitnessVerdict::SameFile {
            for range in ranges {
                mapped.insert(range, RangeProof::Witnessed);
            }
        }
    }
}

/// Whether a hook decision with overlay refusals takes a witness query:
/// a partial kernel answer (any refused range; the helper no-ops when
/// there is none) or an unavailable run with no sweep route
/// ([`RunFailure::AnchorNotInstalled`]). Attempt-cap, deadline, stream
/// and other run failures keep the named loss with no query.
fn witness_qualifies(decision: &crate::discovery::kernel_identity::ProofDecision<'_>) -> bool {
    use crate::discovery::kernel_identity::{ProofDecision, RunFailure};
    match decision {
        ProofDecision::Kernel(_) => true,
        ProofDecision::UserspaceExceptOverlay { reason, .. } => {
            *reason == RunFailure::AnchorNotInstalled
        }
        ProofDecision::Userspace(_) => false,
    }
}

/// The standalone adapter uses the same prepared ownership and batch minting
/// seam as the later central segment hook; no scalar request constructor is
/// exposed to the kernel owner. The hook is dynamic so the production
/// driver can route phase-D promotions through it.
pub(crate) fn prove_and_finish_prepared<Io: ConfirmIo>(
    io: &mut Io,
    pid: u32,
    prepared: PreparedConfirmation<Io::Pin>,
    hook: &mut (dyn SegmentProof + '_),
    resources: &IoResources,
    budget: &mut CaptureWorkBudget,
) -> Confirmation {
    // No witness: the window never runs, so the counter is a dummy.
    let mut refused = 0usize;
    prove_and_finish_prepared_with_witness(
        io,
        pid,
        prepared,
        hook,
        resources,
        budget,
        None,
        0,
        0,
        &mut refused,
    )
}

/// Scalar confirm with an optional sweep witness for overlay refusals
/// with no sweep route (live capture watched providers). `None` keeps
/// today's named loss; `Some` proves each refused overlay key through
/// the private session under this pass's witness budget.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_and_finish_prepared_with_witness<Io: ConfirmIo>(
    io: &mut Io,
    pid: u32,
    mut prepared: PreparedConfirmation<Io::Pin>,
    hook: &mut (dyn SegmentProof + '_),
    resources: &IoResources,
    budget: &mut CaptureWorkBudget,
    witness: Option<(&KnownKeyIndex, &PinnedObjects, &mut dyn SweepWitness)>,
    window_start: u64,
    window_denominator: usize,
    refused_counter: &mut usize,
) -> Confirmation {
    let batch = AcceptedBatch {
        requests: vec![AcceptedRequest {
            pid,
            ranges: &prepared.ranges,
            entries: &prepared.entries,
            pidfd: io.borrowed_pidfd(&prepared.pin.pin),
            kind: AcceptedKind::Confirm,
            member: prepared.member.as_ref(),
        }],
        token: Arc::new(()),
    };
    let decision = hook.prove(&batch, budget, resources);
    let mut answers = decision.answer(&batch, 0).cloned();
    drop(batch);
    if let Some(reason) = budget.check_deadline_now() {
        return Confirmation::Lost(AttributionLoss::Budget, reason.into());
    }
    if witness_qualifies(&decision)
        && let (Some((index, pins, runner)), Some(map)) = (witness, answers.as_mut())
    {
        witness_overlay_refused(
            pid,
            map,
            &prepared.entries,
            index,
            pins,
            runner,
            budget,
            window_start,
            window_denominator,
            refused_counter,
        );
    }
    // A complete kernel answer needs no userspace reads; otherwise the
    // member returns to the stash for the fallback proofs, like the scalar
    // confirm path, and is taken back for the finish. A partial overlay
    // refusal answers only its refused ranges; every other range still
    // needs its userspace proof.
    let mapped = match answers {
        Some(mapped)
            if matches!(
                decision,
                crate::discovery::kernel_identity::ProofDecision::Kernel(_)
            ) && prepared
                .ranges
                .iter()
                .all(|range| mapped.contains_key(range)) =>
        {
            mapped
        }
        answers => {
            let mut mapped = answers.unwrap_or_default();
            let missing: Vec<(u64, u64)> = prepared
                .ranges
                .iter()
                .copied()
                .filter(|range| !mapped.contains_key(range))
                .collect();
            // Plain userspace (and a token-mismatched kernel answer) keeps
            // its member roundtrip even with no ranges; a partial refusal
            // with nothing missing skips the reads entirely.
            if !matches!(
                decision,
                crate::discovery::kernel_identity::ProofDecision::UserspaceExceptOverlay { .. }
            ) || !missing.is_empty()
            {
                io.return_member(pid, prepared.member.take());
                mapped.extend(read_ranges_reserved(io, pid, &missing, Some(resources)));
                prepared.member = io.take_member();
            }
            mapped
        }
    };
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

#[cfg(test)]
thread_local! {
    static PREVIEW_RECOMPUTES: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn count_preview_recomputes_for_test<R>(body: impl FnOnce() -> R) -> (R, usize) {
    struct Restore(Option<usize>);
    impl Drop for Restore {
        fn drop(&mut self) {
            PREVIEW_RECOMPUTES.set(self.0);
        }
    }
    let restore = Restore(PREVIEW_RECOMPUTES.replace(Some(0)));
    let result = body();
    let count = PREVIEW_RECOMPUTES
        .get()
        .expect("preview-recompute counter is scoped");
    drop(restore);
    (result, count)
}

#[cfg(test)]
fn record_preview_recompute_for_test() {
    PREVIEW_RECOMPUTES.set(PREVIEW_RECOMPUTES.get().map(|count| count + 1));
}

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
        /// The worker's proof ranges for a clean read, carried so the
        /// preview replays the transcript without recomputing them from
        /// the same entries. `None` when the read was not clean: the
        /// preview then recomputes from its replay exactly as before.
        ranges: Option<Vec<(u64, u64)>>,
    },
    Failed(Confirmation),
}

struct Prepared<Io: ShardableIo> {
    state: PreparedState<Io>,
    mapped: MappedIdentities,
    kernel_proved: bool,
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
            kernel_proved: false,
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
                    Err(error) => (Err(error.to_string()), None),
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
                        // Borrow, never clone: the transcript keeps the
                        // entries for the preview; only the small range
                        // list is carried, and only for a clean read.
                        // Unclean reads keep the exact previous behavior:
                        // charged here, recomputed from the replay there.
                        let (ranges, carry) = match (&unclean, transcript.clean_result()) {
                            (_, Some(Ok(entries))) => (proof_ranges(entries, prove), true),
                            (Some(Ok(entries)), _) => (proof_ranges(entries, prove), false),
                            _ => (Vec::new(), false),
                        };
                        for _ in &ranges {
                            if shadow.spend(1).is_err() {
                                break;
                            }
                        }
                        (Ok(transcript), carry.then_some(ranges))
                    }
                };
                Ok((pin, before, maps))
            })();
            match prepared {
                Ok((pin, before, (maps, ranges))) => RecordedState::Confirm {
                    io,
                    pin,
                    before,
                    maps,
                    ranges,
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
            ranges: carried,
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
                    let ranges = match carried {
                        Some(ranges) => ranges,
                        None => {
                            #[cfg(test)]
                            record_preview_recompute_for_test();
                            proof_ranges(&entries, prove)
                        }
                    };
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
                                // Speculative transcript replay re-reads
                                // recorded bytes; live member custody
                                // belongs to the live prepare path.
                                member: None,
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

/// Test-only batch minting for requests the shard driver cannot form
/// (member-carrying confirms): the caller owns the plans, the batch
/// borrows them, and no pidfd is attached (multi-request batches never
/// promote).
#[cfg(test)]
pub(crate) fn accepted_batch_for_test<'a, P>(
    plans: &'a [(u32, PreparedConfirmation<P>)],
) -> AcceptedBatch<'a> {
    AcceptedBatch {
        requests: plans
            .iter()
            .map(|(pid, plan)| AcceptedRequest {
                pid: *pid,
                ranges: &plan.ranges,
                entries: &plan.entries,
                pidfd: None,
                kind: AcceptedKind::Confirm,
                member: plan.member.as_ref(),
            })
            .collect(),
        token: std::sync::Arc::new(()),
    }
}

/// Only accepted charged preparations can mint these original-pin views.
fn accepted_batch<'a, Io: ShardableIo>(
    prepared: &'a [(usize, Prepared<Io>)],
    sweep: &'a [(u32, Vec<MapEntry>)],
) -> (AcceptedBatch<'a>, Vec<usize>) {
    let mut requests = Vec::new();
    let mut positions = Vec::new();
    for (position, (at, prepared)) in prepared.iter().enumerate() {
        let request = match &prepared.state {
            PreparedState::Confirm { io, plan } => AcceptedRequest {
                pid: sweep[*at].0,
                ranges: &plan.ranges,
                entries: &plan.entries,
                pidfd: io.borrowed_pidfd(&plan.pin.pin),
                kind: AcceptedKind::Confirm,
                member: plan.member.as_ref(),
            },
            PreparedState::Idle { ranges, .. } => AcceptedRequest {
                pid: sweep[*at].0,
                ranges,
                entries: &sweep[*at].1,
                pidfd: None,
                kind: AcceptedKind::Idle,
                member: None,
            },
            _ => continue,
        };
        requests.push(request);
        positions.push(position);
    }
    (
        AcceptedBatch {
            requests,
            token: Arc::new(()),
        },
        positions,
    )
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
                _ if prepared.kernel_proved => {}
                PreparedState::Idle { io, ranges } => {
                    // A partial overlay refusal already answers its refused
                    // ranges; only the missing ranges need userspace reads.
                    let missing: Vec<(u64, u64)> = ranges
                        .iter()
                        .copied()
                        .filter(|range| !prepared.mapped.contains_key(range))
                        .collect();
                    prepared.mapped.extend(read_ranges_reserved(
                        io,
                        sweep[position].0,
                        &missing,
                        Some(resources),
                    ));
                }
                PreparedState::Confirm { io, plan } => {
                    let missing: Vec<(u64, u64)> = plan
                        .ranges
                        .iter()
                        .copied()
                        .filter(|range| !prepared.mapped.contains_key(range))
                        .collect();
                    prepared.mapped.extend(read_ranges_reserved(
                        io,
                        sweep[position].0,
                        &missing,
                        Some(resources),
                    ));
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
#[allow(dead_code)] // Dormant until D3d explicitly activates this entry.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attribute_unselected_with_segment_proof<Io, F>(
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    budget: &mut CaptureWorkBudget,
    policy: SegmentPolicy,
    owner: &ReservationOwner,
    threads: usize,
    make_io: &F,
    hook: &mut impl SegmentProof,
) -> SweepAttribution
where
    Io: ShardableIo,
    Io::Pin: Send,
    F: Fn() -> Io + Sync,
{
    attribute_unselected_with_optional_proof(
        sweep,
        unavailable,
        selected,
        index,
        budget,
        policy,
        owner,
        threads,
        make_io,
        Some(hook),
        None,
        0,
        0,
    )
    .0
}

/// Kernel sweep with an optional private witness for overlay refusals
/// with no sweep route (live capture watched providers). `None` keeps
/// today's named loss; `Some` proves each refused overlay key through
/// the private session under this pass's witness budget. The window
/// (`start`, previous refused count) walks the budget over refused
/// candidates across passes; the returned count is this pass's
/// refused total, the next pass's denominator.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attribute_unselected_with_segment_proof_with_witness<Io, F>(
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    budget: &mut CaptureWorkBudget,
    policy: SegmentPolicy,
    owner: &ReservationOwner,
    threads: usize,
    make_io: &F,
    hook: &mut impl SegmentProof,
    pins: &PinnedObjects,
    witness: &mut dyn SweepWitness,
    window_start: u64,
    window_denominator: usize,
) -> (SweepAttribution, usize)
where
    Io: ShardableIo,
    Io::Pin: Send,
    F: Fn() -> Io + Sync,
{
    attribute_unselected_with_optional_proof(
        sweep,
        unavailable,
        selected,
        index,
        budget,
        policy,
        owner,
        threads,
        make_io,
        Some(hook),
        Some((pins, witness)),
        window_start,
        window_denominator,
    )
}

/// Failed-install sweep for a pass whose anchors never installed
/// because every anchor is capture-watched: no sweep kernel run
/// exists, so the refused hook marks exactly the overlay ranges (no
/// manufactured kernel proofs) and the private witness proves them;
/// non-overlay ranges read from userspace exactly like the plain
/// path. Production and the privileged sweep cell share this
/// function, so the tested route cannot drift from the shipped one.
/// The returned count is this pass's refused total, the next pass's
/// window denominator.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attribute_unselected_capture_excluded_with_witness<Io, F>(
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    budget: &mut CaptureWorkBudget,
    policy: SegmentPolicy,
    owner: &ReservationOwner,
    threads: usize,
    make_io: &F,
    pins: &PinnedObjects,
    witness: &mut dyn SweepWitness,
    window_start: u64,
    window_denominator: usize,
) -> (SweepAttribution, usize)
where
    Io: ShardableIo,
    Io::Pin: Send,
    F: Fn() -> Io + Sync,
{
    let mut hook = crate::discovery::kernel_identity::AnchorRefusedHook::new(index);
    attribute_unselected_with_segment_proof_with_witness(
        sweep,
        unavailable,
        selected,
        index,
        budget,
        policy,
        owner,
        threads,
        make_io,
        &mut hook,
        pins,
        witness,
        window_start,
        window_denominator,
    )
}

/// Failed-install sweep dispatch: a pass whose anchors never installed
/// because every anchor is capture-watched proves its refused overlay
/// keys through the private witness session (no sweep kernel run
/// exists); any other failed install reads from userspace exactly like
/// the plain path. The returned count is this pass's refused total on
/// the witness route (`None` on the plain route, which runs no
/// witness), the next pass's window denominator.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attribute_failed_install_sweep<Io, F>(
    capture_excluded: bool,
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    budget: &mut CaptureWorkBudget,
    policy: SegmentPolicy,
    owner: &ReservationOwner,
    threads: usize,
    make_io: &F,
    pins: &PinnedObjects,
    witness: &mut dyn SweepWitness,
    window_start: u64,
    window_denominator: usize,
) -> (SweepAttribution, Option<usize>)
where
    Io: ShardableIo,
    Io::Pin: Send,
    F: Fn() -> Io + Sync,
{
    if capture_excluded {
        // Every anchor is capture-watched: no sweep kernel run exists,
        // but the refused overlay keys still prove through the private
        // witness session (the refused hook manufactures no kernel
        // proofs; non-overlay ranges read from userspace exactly as on
        // the plain route below).
        let (out, refused) = attribute_unselected_capture_excluded_with_witness(
            sweep,
            unavailable,
            selected,
            index,
            budget,
            policy,
            owner,
            threads,
            make_io,
            pins,
            witness,
            window_start,
            window_denominator,
        );
        (out, Some(refused))
    } else {
        (
            attribute_unselected_with_policy(
                sweep,
                unavailable,
                selected,
                index,
                budget,
                policy,
                owner,
                threads,
                make_io,
            ),
            None,
        )
    }
}

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
    attribute_unselected_with_optional_proof(
        sweep,
        unavailable,
        selected,
        index,
        budget,
        policy,
        owner,
        threads,
        make_io,
        None,
        None,
        0,
        0,
    )
    .0
}

#[allow(clippy::too_many_arguments)]
fn attribute_unselected_with_optional_proof<Io, F>(
    sweep: &[(u32, Vec<MapEntry>)],
    unavailable: &BTreeSet<u32>,
    selected: &BTreeSet<u32>,
    index: &KnownKeyIndex,
    budget: &mut CaptureWorkBudget,
    policy: SegmentPolicy,
    owner: &ReservationOwner,
    threads: usize,
    make_io: &F,
    mut hook: Option<&mut dyn SegmentProof>,
    mut witness: Option<(&PinnedObjects, &mut dyn SweepWitness)>,
    window_start: u64,
    window_denominator: usize,
) -> (SweepAttribution, usize)
where
    Io: ShardableIo,
    Io::Pin: Send,
    F: Fn() -> Io + Sync,
{
    // The witness budget covers one window across the whole pass over
    // refused candidates (not sweep positions, which starve sparse
    // refused sets, and not one prefix per segment, which starves
    // later segments): candidates count up in segment order, and only
    // window members take a query. The returned count is this pass's
    // refused total (0 without a witness), the next pass's window
    // denominator.
    let mut refused_counter = 0usize;
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
                hook.as_deref_mut(),
            );
            position += 1;
            continue;
        }
        let end = position.saturating_add(policy.retained).min(sweep.len());
        let (mut prepared, failed) = prepare_segment(
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
                hook.as_deref_mut(),
            );
            position += 1;
            continue;
        }
        let next = position + prepared.len();
        // Keep the guard-bound result through every live finish, after the
        // borrowed request views end and before another batch replaces scope.
        let decision = if let Some(hook) = hook.as_deref_mut() {
            let (accepted, positions) = accepted_batch(&prepared, sweep);
            let decision = hook.prove(&accepted, budget, &batch);
            let answers: Vec<_> = positions
                .into_iter()
                .enumerate()
                .map(|(request, position)| (position, decision.answer(&accepted, request).cloned()))
                .collect();
            drop(accepted);
            let stopped = budget.check_deadline_now();
            for (position, answer) in answers {
                // Nothing in this segment has finished yet. An observed stop
                // invalidates even its complete kernel answers, closes every
                // retained pin, and prohibits both finish and fallback I/O.
                if let Some(reason) = stopped {
                    prepared[position].1.state = PreparedState::Failed(Confirmation::Lost(
                        AttributionLoss::Budget,
                        reason.into(),
                    ));
                } else if let Some(mapped) = answer {
                    // A partial Kernel answer (overlay ranges only) still
                    // needs userspace proofs for the missing ranges;
                    // `prove_part` reads exactly those.
                    let complete = match &prepared[position].1.state {
                        PreparedState::Idle { ranges, .. } => {
                            ranges.iter().all(|range| mapped.contains_key(range))
                        }
                        PreparedState::Confirm { plan, .. } => {
                            plan.ranges.iter().all(|range| mapped.contains_key(range))
                        }
                        _ => true,
                    };
                    prepared[position].1.mapped = mapped;
                    prepared[position].1.kernel_proved = complete
                        && matches!(
                            decision,
                            crate::discovery::kernel_identity::ProofDecision::Kernel(_)
                        );
                }
            }
            Some(decision)
        } else {
            None
        };
        // K1-R2: watched overlay keys with no sweep route prove via the
        // private witness session (no attach-set exclusions) under this
        // pass's witness budget. Attempt-cap and other run failures keep
        // the named loss with no query.
        if let Some(decision) = decision.as_ref()
            && witness_qualifies(decision)
            && let Some((pins, runner)) = witness.as_mut()
        {
            let pins = *pins;
            // Stable segment order: candidates count into the
            // pass-wide window in this order, so the budget covers
            // one refused window across segments.
            let order: Vec<usize> = prepared
                .iter()
                .enumerate()
                .filter(|(_, entry)| {
                    entry
                        .1
                        .mapped
                        .values()
                        .any(|proof| *proof == RangeProof::OverlayRefused)
                })
                .map(|(slot, _)| slot)
                .collect();
            for slot in order {
                let (at, prepared) = &mut prepared[slot];
                let (pid, sweep_entries) = &sweep[*at];
                let entries: &[MapEntry] = match &prepared.state {
                    PreparedState::Confirm { plan, .. } => &plan.entries,
                    _ => sweep_entries,
                };
                witness_overlay_refused(
                    *pid,
                    &mut prepared.mapped,
                    entries,
                    index,
                    pins,
                    &mut **runner,
                    budget,
                    window_start,
                    window_denominator,
                    &mut refused_counter,
                );
            }
        }
        let proven = match prove_segment(prepared, sweep, &batch, threads.min(policy.workers)) {
            Ok(proven) => proven,
            Err(()) => {
                drop(decision);
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
        drop(decision);
        // Every retained batch pin is gone before the immediate envelope
        // is used for phase D, and before the next fixed prefix prepares.
        for (at, mapped) in promotions {
            let (pid, entries) = &sweep[at];
            let mut io = make_io();
            // With a kernel hook installed, the promotion is a charged
            // per-PID promotion, not a userspace reopen: prepare on a
            // retained pin, prove through the shared hook (counting the
            // attempt on the borrowed pidfd), and finish. A userspace
            // answer falls back inside the same pin and is disclosed by
            // the hook's own ledger. Pure-userspace promotions keep the
            // direct confirmation below.
            let confirmation = match hook.as_deref_mut() {
                Some(hook) => {
                    match prepare_confirmation(&mut io, *pid, &prove, budget, Some(&immediate)) {
                        Ok(prepared) => {
                            let w = witness.as_mut().map(|(pins, runner)| {
                                (index, *pins, &mut **runner as &mut dyn SweepWitness)
                            });
                            prove_and_finish_prepared_with_witness(
                                &mut io,
                                *pid,
                                prepared,
                                hook,
                                &immediate,
                                budget,
                                w,
                                window_start,
                                window_denominator,
                                &mut refused_counter,
                            )
                        }
                        Err(confirmation) => confirmation,
                    }
                }
                None => confirm_with_resources(&mut io, *pid, &prove, budget, Some(&immediate)),
            };
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
    (out, refused_counter)
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
    hook: Option<&mut (dyn SegmentProof + '_)>,
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
        PreparedState::Idle { .. } if idle_needs_promotion(index, entries, &prepared.mapped) => {
            // With a kernel hook installed, the promotion is a charged
            // per-PID promotion, not a userspace reopen: prepare on a
            // retained pin, prove through the shared hook (counting the
            // attempt on the borrowed pidfd), and finish. Pure-userspace
            // (`None`) keeps the direct confirmation below, byte-identical.
            let confirmation = match hook {
                Some(hook) => {
                    let mut io = make_io();
                    match prepare_confirmation(&mut io, *pid, prove, budget, Some(resources)) {
                        Ok(prepared) => prove_and_finish_prepared(
                            &mut io, *pid, prepared, hook, resources, budget,
                        ),
                        Err(confirmation) => confirmation,
                    }
                }
                None => {
                    confirm_with_resources(&mut make_io(), *pid, prove, budget, Some(resources))
                }
            };
            (Some(confirmation), prepared.mapped)
        }
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

/// Phase-D promotions under a kernel hook: the production driver must
/// route them through the shared charged path (prepare on a retained
/// pin, `hook.prove`, finish) instead of bypassing the hook with a
/// userspace reopen. Inline here (not in `confirm_shards_tests.rs`) so
/// the scripted hook and fd-backed pins stay with the driver fix.
#[cfg(test)]
mod kernel_promotion_tests {
    use super::{AcceptedKind, SegmentProof, attribute_unselected_with_segment_proof};
    use crate::discovery::caller_registry::ExeIdentity;
    use crate::discovery::identity::{ExaminedObject, FileIdentity, MappedFile, PinnedObjectId};
    use crate::discovery::kernel_identity::{ProofDecision, RunFailure};
    use crate::discovery::scan::CaptureWorkBudget;
    use crate::discovery::sweep_attribution::{
        AttributionLoss, ConfirmIo, KnownKeyIndex, ObjectChecks, RANGE_NOT_MAPPED,
        ReservationOwner, SegmentPolicy,
    };
    use p11scope_manifest::maps::{Device, MapEntry, ObjectKey};
    use std::collections::{BTreeMap, BTreeSet};
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::sync::{Arc, Mutex};

    const PROVIDER: u64 = 7_001;
    const LIBC: u64 = 7_002;
    const OBJECT: PinnedObjectId = PinnedObjectId(1);
    const PROMOTED: u32 = 1001;

    fn key(inode: u64) -> ObjectKey {
        ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode,
        }
    }

    fn vm_file(inode: u64) -> FileIdentity {
        FileIdentity {
            dev: 37,
            ino: inode,
        }
    }

    fn entry(start: u64, perms: &[u8; 4], inode: u64, path: &str) -> MapEntry {
        MapEntry {
            start,
            end: start + 0x1000,
            permissions: *perms,
            file_offset: 0,
            device: Device { major: 8, minor: 1 },
            inode,
            raw_path: Some(path.as_bytes().to_vec()),
        }
    }

    /// Phase 1 sees libc only (Idle); the confirmation re-read sees the
    /// provider arrive (a caller), so the stale Idle promotes.
    fn phase_one() -> Vec<MapEntry> {
        vec![
            entry(0x2000_0000, b"r--p", LIBC, "/usr/lib/libc.so.6"),
            entry(0x2000_1000, b"r-xp", LIBC, "/usr/lib/libc.so.6"),
        ]
    }

    fn confirm_maps() -> Vec<MapEntry> {
        vec![
            entry(
                0x1000_0000,
                b"r--p",
                PROVIDER,
                "/usr/lib/softhsm/libsofthsm2.so",
            ),
            entry(
                0x1000_1000,
                b"r-xp",
                PROVIDER,
                "/usr/lib/softhsm/libsofthsm2.so",
            ),
            entry(0x2000_0000, b"r--p", LIBC, "/usr/lib/libc.so.6"),
            entry(0x2000_1000, b"r-xp", LIBC, "/usr/lib/libc.so.6"),
        ]
    }

    struct Checks;

    impl ObjectChecks for Checks {
        fn nonunique_inodes(&self, _: PinnedObjectId) -> Result<Option<&'static str>, String> {
            Ok(None)
        }
        fn unchanged(&self, _: PinnedObjectId) -> Result<bool, String> {
            Ok(true)
        }
        fn mapped_identity(&self, _: PinnedObjectId) -> Result<MappedFile, String> {
            Ok(MappedFile {
                identity: vm_file(PROVIDER),
                fs_magic: Some(0x01021994),
            })
        }
    }

    fn index() -> KnownKeyIndex {
        KnownKeyIndex::build(
            [(key(PROVIDER), Some(OBJECT))],
            &BTreeMap::from([(key(PROVIDER), OBJECT)]),
            [ExaminedObject {
                key: key(LIBC),
                identity: vm_file(LIBC),
                key_is_identity: false,
            }],
            &Checks,
        )
        .0
    }

    /// An fd-backed pin: the promotion borrows this fd, never a reopen.
    struct Pin {
        file: std::fs::File,
    }

    /// One pin touch in prepare → prove → finish order, shared by the
    /// scripted I/O and the scripted hook so the test pins the whole
    /// sequence to a single pin identity.
    #[derive(Debug, PartialEq, Eq)]
    enum PinEvent {
        Open { pid: u32, fd: i32 },
        Prove { pid: u32, fd: Option<i32> },
        StillSame { fd: i32 },
        StartTime { fd: i32 },
    }

    /// The scripted `/proc`: libc ranges read stale (remapped since the
    /// sweep), provider ranges read their file. Every `open` is logged
    /// with its fd so the test pins the borrowed pidfd to the charged pin.
    struct FakeIo {
        opens: Arc<Mutex<Vec<(u32, i32)>>>,
        trace: Arc<Mutex<Vec<PinEvent>>>,
    }

    impl ConfirmIo for FakeIo {
        type Pin = Pin;

        fn borrowed_pidfd<'a>(&self, pin: &'a Self::Pin) -> Option<std::os::fd::BorrowedFd<'a>> {
            Some(pin.file.as_fd())
        }

        fn mapped_file(
            &mut self,
            _pid: u32,
            start: u64,
            _end: u64,
        ) -> Result<FileIdentity, String> {
            match start >> 28 {
                1 => Ok(vm_file(PROVIDER)),
                _ => Err(RANGE_NOT_MAPPED.into()),
            }
        }

        fn open(&mut self, pid: u32) -> Result<Pin, String> {
            let file = std::fs::File::open("/dev/null").map_err(|error| error.to_string())?;
            self.opens.lock().unwrap().push((pid, file.as_raw_fd()));
            self.trace.lock().unwrap().push(PinEvent::Open {
                pid,
                fd: file.as_raw_fd(),
            });
            Ok(Pin { file })
        }

        fn start_time(&self, pin: &Pin) -> Option<u64> {
            self.trace.lock().unwrap().push(PinEvent::StartTime {
                fd: pin.file.as_raw_fd(),
            });
            Some(7_007)
        }

        fn still_the_same(&self, pin: &Pin) -> bool {
            self.trace.lock().unwrap().push(PinEvent::StillSame {
                fd: pin.file.as_raw_fd(),
            });
            true
        }

        fn exe(&self, _pid: u32) -> Option<ExeIdentity> {
            Some(ExeIdentity {
                dev: 1,
                ino: 100,
                mtime_secs: 10,
                mtime_nanos: 0,
                path: Some("/usr/bin/caller".into()),
            })
        }

        fn maps(
            &mut self,
            pid: u32,
            _budget: &mut CaptureWorkBudget,
        ) -> Result<Vec<MapEntry>, String> {
            assert_eq!(pid, PROMOTED, "only the promoted pid re-reads its maps");
            Ok(confirm_maps())
        }

        fn gone(&self, _pid: u32) -> bool {
            false
        }
    }

    impl super::ShardableIo for FakeIo {
        type Maps = std::io::Cursor<Vec<u8>>;

        fn open_maps(&mut self, _pid: u32) -> std::io::Result<Self::Maps> {
            panic!("the Idle segment never opens maps");
        }

        fn maps_now(&self) -> Option<u64> {
            Some(1_000_000)
        }
    }

    struct HookCall {
        pids: Vec<u32>,
        confirms: Vec<bool>,
        pidfds: Vec<Option<i32>>,
        userspace: bool,
        reason: Option<RunFailure>,
    }

    /// The scripted kernel hook: records every batch (pids, Confirm vs
    /// Idle, borrowed pidfds) and answers userspace, so the test sees
    /// the substitution the driver must disclose. The recorded
    /// `userspace` flag and `reason` are derived from the answer
    /// actually returned, never hardcoded.
    struct ScriptedHook {
        calls: Arc<Mutex<Vec<HookCall>>>,
        reason: RunFailure,
        trace: Arc<Mutex<Vec<PinEvent>>>,
    }

    impl SegmentProof for ScriptedHook {
        fn prove<'r>(
            &'r mut self,
            batch: &super::AcceptedBatch<'_>,
            _budget: &mut CaptureWorkBudget,
            _resources: &crate::discovery::sweep_attribution::IoResources,
        ) -> ProofDecision<'r> {
            let decision = ProofDecision::Userspace(self.reason);
            let mut call = HookCall {
                pids: Vec::new(),
                confirms: Vec::new(),
                pidfds: Vec::new(),
                userspace: matches!(
                    decision,
                    ProofDecision::Userspace(_) | ProofDecision::UserspaceExceptOverlay { .. }
                ),
                reason: match decision {
                    ProofDecision::Userspace(reason)
                    | ProofDecision::UserspaceExceptOverlay { reason, .. } => Some(reason),
                    ProofDecision::Kernel(_) => None,
                },
            };
            for request in batch.requests() {
                call.pids.push(request.pid());
                call.confirms
                    .push(matches!(request.kind(), AcceptedKind::Confirm));
                call.pidfds.push(request.pidfd().map(|fd| fd.as_raw_fd()));
                self.trace.lock().unwrap().push(PinEvent::Prove {
                    pid: request.pid(),
                    fd: request.pidfd().map(|fd| fd.as_raw_fd()),
                });
            }
            self.calls.lock().unwrap().push(call);
            decision
        }
    }

    /// The production driver consults the hook for the phase-D
    /// promotion: one charged single-Confirm batch on the retained
    /// pin's borrowed pidfd, and the userspace substitution disclosed
    /// by the hook's answer while the member still attributes.
    #[test]
    fn phase_d_promotion_with_hook_charges_prepare_prove_finish_on_the_pin() {
        let opens = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let trace = Arc::new(Mutex::new(Vec::new()));
        let make_io = || FakeIo {
            opens: opens.clone(),
            trace: trace.clone(),
        };
        let sweep = vec![(PROMOTED, phase_one())];
        let policy = SegmentPolicy::from_headroom(16, 1, sweep.len());
        let owner = ReservationOwner::new(policy);
        let mut budget = CaptureWorkBudget::default();
        let mut hook = ScriptedHook {
            calls: calls.clone(),
            reason: RunFailure::TargetLimit,
            trace: trace.clone(),
        };
        let out = attribute_unselected_with_segment_proof(
            &sweep,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index(),
            &mut budget,
            policy,
            &owner,
            1,
            &make_io,
            &mut hook,
        );
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            2,
            "the promotion must consult the hook instead of bypassing it"
        );
        // The segment batch carries the Idle request without a pidfd.
        assert_eq!(calls[0].pids, [PROMOTED]);
        assert_eq!(calls[0].confirms, [false]);
        assert_eq!(calls[0].pidfds, [None]);
        // The promotion is a single charged Confirm borrowing the one
        // retained pin: exactly one open, and the batch borrows its fd.
        let opens = opens.lock().unwrap();
        assert_eq!(
            opens.len(),
            1,
            "the promotion opens one pin, never a reopen"
        );
        assert_eq!(opens[0].0, PROMOTED);
        assert_eq!(calls[1].pids, [PROMOTED]);
        assert_eq!(calls[1].confirms, [true]);
        assert_eq!(
            calls[1].pidfds,
            [Some(opens[0].1)],
            "the promotion proves on the borrowed pin, not a numeric reopen"
        );
        // The hook answered userspace for the promotion (the disclosed
        // substitution), and the member still attributes inside its
        // original pin through the userspace fallback.
        assert!(calls[1].userspace);
        assert_eq!(
            out.members
                .iter()
                .map(|member| member.pid)
                .collect::<Vec<_>>(),
            [PROMOTED],
            "the promoted member attributes through the disclosed fallback"
        );
    }

    /// The immediate path (`retained == 0`) consults the hook for its
    /// phase-D promotion too: prepare → prove → finish in order on one
    /// pin, and the hook's userspace fallback (with its reason) in the
    /// confirmation record — never a hook-bypassing reopen.
    #[test]
    fn immediate_promotion_with_hook_charges_prepare_prove_finish_on_the_pin() {
        let opens = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let trace = Arc::new(Mutex::new(Vec::new()));
        let make_io = || FakeIo {
            opens: opens.clone(),
            trace: trace.clone(),
        };
        let sweep = vec![(PROMOTED, phase_one())];
        // Headroom 5 keeps the immediate envelope (headroom >= 3) while
        // forcing `retained == 0` (no workers), so this PID runs through
        // `immediate_one`.
        let policy = SegmentPolicy::from_headroom(5, 1, sweep.len());
        assert_eq!(policy.retained, 0);
        let owner = ReservationOwner::new(policy);
        let mut budget = CaptureWorkBudget::default();
        let mut hook = ScriptedHook {
            calls: calls.clone(),
            reason: RunFailure::TargetLimit,
            trace: trace.clone(),
        };
        let out = attribute_unselected_with_segment_proof(
            &sweep,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index(),
            &mut budget,
            policy,
            &owner,
            1,
            &make_io,
            &mut hook,
        );
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "the immediate promotion must consult the hook instead of bypassing it"
        );
        let opens = opens.lock().unwrap();
        assert_eq!(
            opens.len(),
            1,
            "the promotion opens one pin, never a reopen"
        );
        assert_eq!(opens[0].0, PROMOTED);
        assert_eq!(calls[0].pids, [PROMOTED]);
        assert_eq!(calls[0].confirms, [true]);
        assert_eq!(
            calls[0].pidfds,
            [Some(opens[0].1)],
            "the promotion proves on the borrowed pin, not a numeric reopen"
        );
        // The hook's answer for the promotion call, as returned: a
        // userspace fallback carrying its reason (both derived from
        // the actual `ProofDecision`, never hardcoded).
        assert!(calls[0].userspace);
        assert_eq!(calls[0].reason, Some(RunFailure::TargetLimit));
        // The full charged sequence ran in order on that one pin:
        // prepare opened it, prove borrowed it, finish held it.
        assert_eq!(
            *trace.lock().unwrap(),
            [
                PinEvent::Open {
                    pid: PROMOTED,
                    fd: opens[0].1
                },
                PinEvent::Prove {
                    pid: PROMOTED,
                    fd: Some(opens[0].1)
                },
                PinEvent::StillSame { fd: opens[0].1 },
                PinEvent::StartTime { fd: opens[0].1 },
            ],
            "prepare, prove and finish must share one pin in order"
        );
        assert_eq!(
            out.members
                .iter()
                .map(|member| member.pid)
                .collect::<Vec<_>>(),
            [PROMOTED],
            "the promoted member attributes through the disclosed fallback"
        );
        // The fallback the hook declared is what the confirmation
        // record holds: the provider match is proven by userspace
        // `map_files` evidence (kernel evidence would be rejected —
        // the index holds no anchor slots), with finish's start time
        // and no losses.
        assert_eq!(out.members.len(), 1);
        let member = &out.members[0];
        assert_eq!(member.start_time, 7_007);
        assert_eq!(member.objects.len(), 1);
        assert_eq!(member.objects[0].key, key(PROVIDER));
        assert_eq!(member.objects[0].object, OBJECT);
        // The only loss is the scripted libc staleness (the fixture
        // reads libc ranges stale by design): nothing rejects the
        // provider fallback evidence itself.
        assert_eq!(
            out.losses,
            BTreeMap::from([(AttributionLoss::MappingChanged, 1)])
        );
        let (loss, detail) = &out.member_losses[&PROMOTED];
        assert_eq!(*loss, AttributionLoss::MappingChanged);
        assert!(
            detail.contains(&format!("inode {LIBC}")),
            "the loss must name the stale libc key, not the provider: {detail}"
        );
    }
}
