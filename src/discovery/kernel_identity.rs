//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pass-local scanner custody and anchor installation. Runtime proof selection
//! is a later slice; these owners never change default userspace collection.

use super::confirm_shards::{
    AcceptedBatch, AcceptedKind, AcceptedRequest, SegmentProof, prove_and_finish_prepared,
};
use super::identity::{ExaminedObject, HeldExaminedObject, PinnedObjectId, PinnedObjects};
use super::scan::CaptureWorkBudget;
use super::sweep_attribution::{
    ConfirmIo, Confirmation, IoResources, KnownKeyIndex, MappedIdentities, MemberProbe,
    prepare_confirmation, stat_unpinned_reserved,
};
use super::sweep_attribution::{ReservationOwner, SegmentPolicy, Slot};
use crate::attach::identity_iter::{
    AnchorArena, Expect, RunKind, RunMode, ScopeBitmap, StrictIdentity, parse,
};
use p11scope_manifest::maps::ObjectKey;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsFd;
use std::sync::Arc;

pub(crate) const EXAMINED_ANCHOR_CAP: usize = 512;
pub(crate) const TOTAL_ANCHOR_CAP: usize = 1024;

/// One shared per-pass count of actual proof target runs: whole-system
/// segment batches and per-PID promotion packets, including failed runs.
/// Anchor setup and the one-time eligibility probe are not target attempts.
pub(crate) const MAX_TARGET_ATTEMPTS_PER_PASS: u32 = 3;

/// Provisional automatic whole-system threshold: proof-needing PIDs inside
/// one resource-bounded segment. Named and internal, with deterministic
/// injection for tests, never a public tuning option. Neither this value
/// nor any latency is a validated production crossover.
pub(crate) const AUTO_KERNEL_PROOF_PID_THRESHOLD: usize = 2_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnchorDeny {
    FdHeadroom,
    AnchorCap,
    AnchorNotInstalled,
}

pub(crate) struct ExaminedCustody {
    pub(crate) owner: ReservationOwner,
    candidates: Vec<HeldExaminedObject>,
    callers: BTreeMap<ObjectKey, usize>,
    missing: BTreeMap<(u64, ObjectKey), AnchorDeny>,
    next_scan: u64,
    ordinal: u64,
    cap: usize,
    failed: bool,
}

impl ExaminedCustody {
    pub(crate) fn new(owner: ReservationOwner, callers: BTreeMap<ObjectKey, usize>) -> Self {
        let cap = owner.examined_capacity().min(EXAMINED_ANCHOR_CAP);
        Self {
            owner,
            candidates: Vec::new(),
            callers,
            missing: BTreeMap::new(),
            next_scan: 0,
            ordinal: 0,
            cap,
            failed: false,
        }
    }

    pub(crate) fn begin_scan(&mut self) -> u64 {
        self.next_scan += 1;
        self.next_scan
    }

    pub(crate) fn offer(&mut self, scan: u64, examined: ExaminedObject, file: File) -> bool {
        self.offer_with_census(scan, examined, file, || SegmentPolicy::try_snapshot(0, 0))
    }

    fn fail(&mut self) {
        self.failed = true;
        for held in self.candidates.drain(..) {
            self.missing
                .insert((held.scan, held.examined.key), AnchorDeny::FdHeadroom);
        }
    }

    pub(crate) fn close(&mut self) {
        self.fail();
    }

    pub(crate) fn failed(&self) -> bool {
        self.failed
    }

    fn rank(&self, key: ObjectKey, ordinal: u64) -> (Reverse<usize>, ObjectKey, u64) {
        (
            Reverse(self.callers.get(&key).copied().unwrap_or(0)),
            key,
            ordinal,
        )
    }

    fn offer_with_census(
        &mut self,
        scan: u64,
        examined: ExaminedObject,
        file: File,
        census: impl FnOnce() -> Result<SegmentPolicy, String>,
    ) -> bool {
        if self.failed || self.owner.examined_capacity() == 0 {
            self.missing
                .insert((scan, examined.key), AnchorDeny::FdHeadroom);
            return false;
        }
        let ordinal = self.ordinal;
        self.ordinal = self.ordinal.saturating_add(1);
        let replace = if self.candidates.len() >= self.cap {
            self.candidates
                .iter()
                .enumerate()
                .max_by_key(|(_, held)| self.rank(held.examined.key, held.ordinal))
                .filter(|(_, held)| {
                    self.rank(examined.key, ordinal) < self.rank(held.examined.key, held.ordinal)
                })
                .map(|(index, _)| index)
        } else {
            None
        };
        if self.candidates.len() >= self.cap && replace.is_none() {
            self.missing
                .insert((scan, examined.key), AnchorDeny::AnchorCap);
            return false;
        }
        match census() {
            Err(_) => {
                self.fail();
                self.missing
                    .insert((scan, examined.key), AnchorDeny::FdHeadroom);
                return false;
            }
            Ok(policy) if policy.headroom < 3 => {
                self.missing
                    .insert((scan, examined.key), AnchorDeny::FdHeadroom);
                return false;
            }
            Ok(_) => {}
        }
        if let Some(index) = replace {
            let removed = self.candidates.remove(index);
            self.missing
                .insert((removed.scan, removed.examined.key), AnchorDeny::AnchorCap);
            drop(removed); // Actual FD closes before acquiring its replacement lease.
        }
        let lease = match self.owner.examined() {
            Ok(lease) => lease,
            Err(_) => {
                self.missing
                    .insert((scan, examined.key), AnchorDeny::FdHeadroom);
                return false;
            }
        };
        self.candidates.push(HeldExaminedObject {
            scan,
            ordinal,
            examined,
            file,
            _lease: lease,
        });
        true
    }

    pub(crate) fn discard_scan(&mut self, scan: u64) {
        self.candidates.retain(|candidate| candidate.scan != scan);
        self.missing
            .retain(|(missing_scan, _), _| *missing_scan != scan);
    }

    #[cfg(test)]
    pub(crate) fn file_for_test(&self, scan: u64) -> Option<&File> {
        self.candidates
            .iter()
            .find(|candidate| candidate.scan == scan)
            .map(|candidate| &candidate.file)
    }

    #[cfg(test)]
    pub(crate) fn offer_for_test(
        &mut self,
        scan: u64,
        examined: ExaminedObject,
        file: File,
    ) -> bool {
        self.offer_with_census(scan, examined, file, || {
            Ok(SegmentPolicy::from_headroom(16, 0, 0))
        })
    }

    pub(crate) fn reconcile(&mut self, policy: SegmentPolicy) -> Result<(), String> {
        if let Err(error) = self.owner.reconcile(policy) {
            self.fail();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn reconcile_census(
        &mut self,
        census: Result<SegmentPolicy, String>,
    ) -> Result<(), String> {
        match census {
            Ok(policy) if !self.failed => self.reconcile(policy),
            _ => {
                self.fail();
                Err(super::sweep_attribution::FD_CENSUS_REASON.into())
            }
        }
    }
}

enum AnchorFile<'p> {
    Pinned { id: PinnedObjectId, file: &'p File },
    Examined(HeldExaminedObject),
}

impl AnchorFile<'_> {
    fn file(&self) -> &File {
        match self {
            Self::Pinned { file, .. } => file,
            Self::Examined(held) => &held.file,
        }
    }
}

struct Candidate<'p> {
    keys: BTreeSet<ObjectKey>,
    slot: Slot,
    file: AnchorFile<'p>,
}

/// `read_run` returns completed bytes only: its descriptors close before
/// this owner can release its arena, then its scanner-opened files.
pub(crate) struct AnchorPass<'p> {
    arena: Option<AnchorArena>,
    #[cfg(test)]
    after_arena: Option<DropObserver>,
    candidates: Vec<Candidate<'p>>,
    #[cfg(test)]
    after_files: Option<DropObserver>,
    pub(crate) fallback: BTreeMap<ObjectKey, AnchorDeny>,
    expected_matches: BTreeMap<(ObjectKey, PinnedObjectId), BTreeSet<Slot>>,
    expected_examined: BTreeMap<ObjectKey, BTreeSet<Slot>>,
    #[cfg(test)] // Custody/alias observations only; never proof authority.
    expected: BTreeMap<ObjectKey, BTreeSet<Slot>>,
    reservations: ReservationOwner,
    binding: Option<PassBinding>,
}

#[derive(Clone)]
struct PassBinding {
    session: Arc<()>,
    generation: u64,
    arena_base: u64,
    arena_len: u64,
}

impl PassBinding {
    fn same_installation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.session, &other.session)
            && self.generation == other.generation
            && self.arena_base == other.arena_base
            && self.arena_len == other.arena_len
    }
}

/// Owns the installed arena and files while exclusively borrowing the loaded
/// object. Scope/configuration cannot be changed through another pass until
/// this guard has released its mappings and files.
pub(crate) struct InstalledAnchorPass<'s, 'p> {
    pass: Option<AnchorPass<'p>>,
    session: &'s mut IdentitySession,
    failed_target: Option<RunFailure>,
    target_attempts: u32,
}

impl InstalledAnchorPass<'_, '_> {
    /// A raw target read without a charged batch: custody probing only, not
    /// a proof attempt, so it never consumes the per-pass attempt budget.
    pub(crate) fn read_target(
        &mut self,
        pid: Option<std::os::fd::BorrowedFd<'_>>,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, &'static str> {
        self.read_target_typed(pid, deadline, max_bytes)
            .map_err(|_| "identity target run is unavailable")
    }

    fn read_target_typed(
        &mut self,
        pid: Option<std::os::fd::BorrowedFd<'_>>,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, RunFailure> {
        let pass = self.pass.as_mut().expect("installed guard owns its pass");
        let lease = pass
            .reservations
            .immediate()
            .transient()
            .map_err(|_| RunFailure::FdHeadroom)?;
        let result = pass.read_run_typed(self.session, RunKind::Target, pid, deadline, max_bytes);
        // The concrete read closes iterator/link before this lease or the
        // enclosing guard can release the arena and examined files.
        drop(lease);
        result
    }

    fn replace_target_scope(&mut self, tgids: &[u32]) -> Result<(), RunFailure> {
        let pass = self.pass.as_ref().expect("installed guard owns its pass");
        if !pass.owns_installation(self.session) {
            return Err(RunFailure::Scope);
        }
        let result = match &mut self.session.object {
            SessionObject::Kernel(loaded) => self
                .session
                .scope
                .replace(&mut loaded.ebpf, tgids)
                .map_err(|_| RunFailure::Scope),
            #[cfg(test)]
            SessionObject::Fixture { scope_words, .. } => self
                .session
                .scope
                .fixture_replace_observed(tgids, |word, bits| {
                    scope_words.borrow_mut().insert(word, bits);
                })
                .map_err(|_| RunFailure::Scope),
        };
        if result.is_err() {
            self.session.binding = None;
            self.session.scope.invalidate();
        }
        result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunFailure {
    Scope,
    AnchorNotInstalled,
    FdHeadroom,
    Deadline,
    Clock,
    StreamInvalid,
    AttachOrRead,
    BelowThreshold,
    TargetLimit,
}

/// Finite userspace-fallback cause for one proof request. Labels and details
/// are fixed strings: they never carry PIDs, paths, verdicts or low-level
/// error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelFallbackReason {
    BelowThreshold,
    FdHeadroom,
    TargetLimit,
    AnchorNotInstalled,
    Scope,
    Deadline,
    Clock,
    StreamInvalid,
    TargetUnavailable,
    Unvisited,
    ConflictingDuplicate,
}

impl KernelFallbackReason {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::BelowThreshold => "below_threshold",
            Self::FdHeadroom | Self::TargetLimit => "fd_headroom",
            Self::AnchorNotInstalled => "anchor_not_installed",
            Self::Scope => "scope_unavailable",
            Self::Deadline => "deadline",
            Self::Clock => "clock_unavailable",
            Self::StreamInvalid => "stream_invalid",
            Self::TargetUnavailable => "target_unavailable",
            Self::Unvisited => "unvisited",
            Self::ConflictingDuplicate => "conflicting_duplicate",
        }
    }

    pub(crate) fn detail(self) -> Option<&'static str> {
        match self {
            Self::TargetLimit => Some("target_run_limit"),
            _ => None,
        }
    }
}

impl From<RunFailure> for KernelFallbackReason {
    fn from(reason: RunFailure) -> Self {
        match reason {
            RunFailure::Scope => Self::Scope,
            RunFailure::AnchorNotInstalled => Self::AnchorNotInstalled,
            RunFailure::FdHeadroom => Self::FdHeadroom,
            RunFailure::Deadline => Self::Deadline,
            RunFailure::Clock => Self::Clock,
            RunFailure::StreamInvalid => Self::StreamInvalid,
            RunFailure::AttachOrRead => Self::TargetUnavailable,
            RunFailure::BelowThreshold => Self::BelowThreshold,
            RunFailure::TargetLimit => Self::TargetLimit,
        }
    }
}

/// Capture-level fallback disclosure input: a pass counts once if any
/// requested proof fell back, distinct affected PIDs/keys once per pass,
/// summed across the capture, with the first finite reason preserved.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct KernelFallbackTotals {
    pub(crate) passes: u64,
    pub(crate) pids: u64,
    pub(crate) keys: u64,
    pub(crate) first_reason: Option<KernelFallbackReason>,
}

#[derive(Debug, Default)]
struct PassFallback {
    pids: BTreeSet<u32>,
    keys: BTreeSet<ObjectKey>,
    reason: Option<KernelFallbackReason>,
}

/// Session-owned fallback accounting. The current pass opens at anchor
/// installation and rolls up when its guard drops; a pass with no fallback
/// requests adds zero at every unit.
#[derive(Debug, Default)]
pub(crate) struct KernelFallbackLedger {
    totals: KernelFallbackTotals,
    current: Option<PassFallback>,
}

impl KernelFallbackLedger {
    pub(crate) fn begin_pass(&mut self) {
        self.end_pass();
        self.current = Some(PassFallback::default());
    }

    pub(crate) fn end_pass(&mut self) {
        let Some(pass) = self.current.take() else {
            return;
        };
        if pass.pids.is_empty() {
            return;
        }
        self.totals.passes = self.totals.passes.saturating_add(1);
        self.totals.pids = self.totals.pids.saturating_add(pass.pids.len() as u64);
        self.totals.keys = self.totals.keys.saturating_add(pass.keys.len() as u64);
        if self.totals.first_reason.is_none() {
            self.totals.first_reason = pass.reason;
        }
    }

    pub(crate) fn note_fallback(
        &mut self,
        pid: u32,
        keys: impl IntoIterator<Item = ObjectKey>,
        reason: KernelFallbackReason,
    ) {
        let Some(current) = self.current.as_mut() else {
            return;
        };
        current.pids.insert(pid);
        current.keys.extend(keys);
        if current.reason.is_none() {
            current.reason = Some(reason);
        }
    }

    pub(crate) fn note_batch(&mut self, batch: &AcceptedBatch<'_>, reason: KernelFallbackReason) {
        for request in batch.requests() {
            self.note_fallback(request.pid(), request_keys(request), reason);
        }
    }

    pub(crate) fn totals(&self) -> KernelFallbackTotals {
        self.totals.clone()
    }
}

fn request_keys(request: &AcceptedRequest<'_>) -> BTreeSet<ObjectKey> {
    let wanted: BTreeSet<(u64, u64)> = request.ranges().iter().copied().collect();
    request
        .entries()
        .iter()
        .filter(|entry| wanted.contains(&(entry.start, entry.end)))
        .map(ObjectKey::of)
        .collect()
}

/// Session-level failure that persists through subsequent passes: an invalid
/// target stream, or three consecutive attempted overdue runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelSticky {
    StreamInvalid,
    Deadlines,
}

impl KernelSticky {
    fn reason(self) -> RunFailure {
        match self {
            Self::StreamInvalid => RunFailure::StreamInvalid,
            Self::Deadlines => RunFailure::Deadline,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegmentSelection {
    Kernel,
    Userspace(KernelFallbackReason),
}

/// The automatic cost gate for one resource-bounded segment: `proof_pids`
/// counts the segment's charged requests, never the whole sweep. `None` is
/// forced kernel, which bypasses this cost threshold only: resource, guard,
/// attempt-cap and run-failure policy still apply where the run is attempted.
pub(crate) fn select_proof_run(
    proof_pids: usize,
    auto_threshold: Option<usize>,
) -> SegmentSelection {
    match auto_threshold {
        Some(threshold) if proof_pids < threshold => {
            SegmentSelection::Userspace(KernelFallbackReason::BelowThreshold)
        }
        _ => SegmentSelection::Kernel,
    }
}

impl From<crate::attach::identity_iter::ReadError> for RunFailure {
    fn from(error: crate::attach::identity_iter::ReadError) -> Self {
        match error {
            crate::attach::identity_iter::ReadError::Deadline => Self::Deadline,
            crate::attach::identity_iter::ReadError::TooLarge => Self::StreamInvalid,
            crate::attach::identity_iter::ReadError::Errno(_) => Self::AttachOrRead,
        }
    }
}

/// Only this module can mint a complete target result. The borrow prevents
/// reconfiguration/release while the shared driver finishes this batch.
pub(crate) struct ValidatedTargetSegment<'r> {
    binding: &'r PassBinding,
    batch: Arc<()>,
    answers: Vec<Option<MappedIdentities>>,
}

pub(crate) enum ProofDecision<'r> {
    Kernel(ValidatedTargetSegment<'r>),
    Userspace(RunFailure),
}

impl ProofDecision<'_> {
    pub(crate) fn answer(
        &self,
        batch: &AcceptedBatch<'_>,
        position: usize,
    ) -> Option<&MappedIdentities> {
        match self {
            Self::Kernel(segment)
                if Arc::ptr_eq(&segment.batch, batch.token()) && segment.binding.generation > 0 =>
            {
                segment.answers.get(position).and_then(Option::as_ref)
            }
            _ => None,
        }
    }
}

impl Drop for InstalledAnchorPass<'_, '_> {
    fn drop(&mut self) {
        self.session.fallback.end_pass();
        self.session.binding = None;
        self.session.scope.invalidate();
        // Explicit Drop keeps the exclusive session borrow alive through
        // arena -> examined File destruction, even when the guard is unused.
        drop(self.pass.take());
    }
}

/// Dormant adapter for the shared charged preparation and live finish path.
/// Target evidence and same-pin fallback share one charged request batch.
pub(crate) struct KernelMemberProbe<'g, 's, 'p, Io> {
    proof: KernelPassProof<'g, 's, 'p>,
    io: Io,
    resources: IoResources,
}

struct KernelPassProof<'g, 's, 'p> {
    installed: &'g mut InstalledAnchorPass<'s, 'p>,
    deadline: std::time::Instant,
    eligible_keys: BTreeSet<ObjectKey>,
    auto_threshold: Option<usize>,
}

struct TargetWorkDeadline {
    deadline: std::time::Instant,
    steps: u32,
}

impl TargetWorkDeadline {
    fn check(&self, budget: &mut CaptureWorkBudget) -> Result<(), RunFailure> {
        if std::time::Instant::now() >= self.deadline || budget.check_deadline_now().is_some() {
            Err(RunFailure::Deadline)
        } else {
            Ok(())
        }
    }

    fn step(&mut self, budget: &mut CaptureWorkBudget) -> Result<(), RunFailure> {
        self.steps += 1;
        if self.steps == 32 {
            self.steps = 0;
            self.check(budget)?;
        }
        Ok(())
    }
}

fn bounded_target_deadline(
    budget: &mut CaptureWorkBudget,
    outer: std::time::Instant,
) -> Result<std::time::Instant, RunFailure> {
    if budget.check_deadline_now().is_some() {
        return Err(RunFailure::Deadline);
    }
    let now = std::time::Instant::now();
    let mut deadline = outer.min(now + std::time::Duration::from_millis(500));
    if let Some(limit) = budget.effective_deadline_ns() {
        let clock = crate::attach::monotonic_ns().ok_or(RunFailure::Clock)?;
        let left = limit.checked_sub(clock).ok_or(RunFailure::Deadline)?;
        deadline = deadline.min(
            now.checked_add(std::time::Duration::from_nanos(left))
                .ok_or(RunFailure::Clock)?,
        );
    }
    if std::time::Instant::now() >= deadline {
        return Err(RunFailure::Deadline);
    }
    Ok(deadline)
}

impl KernelPassProof<'_, '_, '_> {
    fn userspace(&mut self, batch: &AcceptedBatch<'_>, reason: RunFailure) -> ProofDecision<'_> {
        self.installed
            .session
            .fallback
            .note_batch(batch, reason.into());
        ProofDecision::Userspace(reason)
    }

    /// Session bookkeeping for one attempted target run's terminal outcome.
    /// An overdue run advances the consecutive streak (sticky at three); an
    /// invalid stream sticks immediately; any other attempted outcome breaks
    /// the deadline streak without clearing stickiness. No-attempt refusals
    /// never reach this function.
    fn note_attempted_outcome(&mut self, reason: RunFailure) {
        let session = &mut self.installed.session;
        match reason {
            RunFailure::Deadline => {
                session.consecutive_deadlines = session.consecutive_deadlines.saturating_add(1);
                if session.consecutive_deadlines >= 3 {
                    session.sticky = Some(KernelSticky::Deadlines);
                }
            }
            RunFailure::StreamInvalid => {
                session.sticky = Some(KernelSticky::StreamInvalid);
                session.consecutive_deadlines = 0;
            }
            _ => {
                session.consecutive_deadlines = 0;
            }
        }
    }
}

impl SegmentProof for KernelPassProof<'_, '_, '_> {
    fn prove<'r>(
        &'r mut self,
        batch: &AcceptedBatch<'_>,
        budget: &mut CaptureWorkBudget,
        resources: &IoResources,
    ) -> ProofDecision<'r> {
        let (owns, same_owner, failed_target, sticky, attempts) = {
            let pass = self
                .installed
                .pass
                .as_ref()
                .expect("installed guard owns its pass");
            (
                pass.owns_installation(self.installed.session),
                resources.same_owner(&pass.reservations),
                self.installed.failed_target,
                self.installed.session.sticky,
                self.installed.target_attempts,
            )
        };
        if !owns {
            return self.userspace(batch, RunFailure::Scope);
        }
        if !same_owner {
            return self.userspace(batch, RunFailure::FdHeadroom);
        }
        if let Some(sticky) = sticky {
            return self.userspace(batch, sticky.reason());
        }
        if let Some(reason) = failed_target {
            return self.userspace(batch, reason);
        }
        if attempts >= MAX_TARGET_ATTEMPTS_PER_PASS {
            return self.userspace(batch, RunFailure::TargetLimit);
        }
        if matches!(
            select_proof_run(batch.requests().len(), self.auto_threshold),
            SegmentSelection::Userspace(_)
        ) {
            return self.userspace(batch, RunFailure::BelowThreshold);
        }
        let deadline = match bounded_target_deadline(budget, self.deadline) {
            Ok(deadline) => deadline,
            Err(reason) => return self.userspace(batch, reason),
        };
        let mut work = TargetWorkDeadline { deadline, steps: 0 };
        // Exclude a PID before running if any required whole-key expectation
        // is absent. A consumed valid NONE from eligible PIDs is never retried.
        let mut eligible = Vec::with_capacity(batch.requests().len());
        let mut scope = BTreeSet::new();
        let mut examined_entries = 0usize;
        let mut requested_ranges = 0usize;
        let mut maps = 0usize;
        for request in batch.requests() {
            if let Err(reason) = work.check(budget) {
                return self.userspace(batch, reason);
            }
            examined_entries = match examined_entries.checked_add(request.entries().len()) {
                Some(total) if total <= super::scan::MapsReadLimits::LIVE.max_entries => total,
                _ => return self.userspace(batch, RunFailure::FdHeadroom),
            };
            requested_ranges = match requested_ranges.checked_add(request.ranges().len()) {
                Some(total) if total <= super::scan::MapsReadLimits::LIVE.max_entries => total,
                _ => return self.userspace(batch, RunFailure::FdHeadroom),
            };
            // Exact-range lookup is built once from the original prepared maps.
            // Duplicate ranges cannot supply an unambiguous kernel request.
            let mut by_range = BTreeMap::new();
            for entry in request.entries() {
                #[cfg(test)]
                tests::note_eligibility_visit(budget);
                if let Err(reason) = work.step(budget) {
                    return self.userspace(batch, reason);
                }
                if by_range.insert((entry.start, entry.end), entry).is_some() {
                    return self.userspace(batch, RunFailure::StreamInvalid);
                }
            }
            let mut complete = !request.ranges().is_empty();
            for range in request.ranges() {
                let entry = by_range.get(range);
                #[cfg(test)]
                if entry.is_some() {
                    tests::note_eligibility_visit(budget);
                }
                if let Err(reason) = work.step(budget) {
                    return self.userspace(batch, reason);
                }
                if !entry.is_some_and(|entry| self.eligible_keys.contains(&ObjectKey::of(entry))) {
                    complete = false;
                    break;
                }
            }
            if complete {
                scope.insert(request.pid());
                maps += request.entries().len(); // Bounded by examined_entries above.
            }
            eligible.push(complete);
        }
        if let Err(reason) = work.check(budget) {
            return self.userspace(batch, reason);
        }
        if scope.is_empty() {
            return self.userspace(batch, RunFailure::AnchorNotInstalled);
        }
        let (generation, slots) = {
            let pass = self
                .installed
                .pass
                .as_ref()
                .expect("installed guard owns its pass");
            let binding = pass
                .binding
                .as_ref()
                .expect("owned installation has a binding");
            (
                binding.generation,
                (binding.arena_len / crate::attach::identity_iter::ANCHOR_STRIDE) as u32,
            )
        };
        let max_bytes = maps
            .checked_add(slots as usize + 1)
            .and_then(|records| records.checked_mul(crate::attach::identity_iter::RECORD_LEN));
        let Some(max_bytes) = max_bytes else {
            return self.userspace(batch, RunFailure::FdHeadroom);
        };
        if let Err(reason) = self
            .installed
            .replace_target_scope(&scope.iter().copied().collect::<Vec<_>>())
        {
            return self.userspace(batch, reason);
        }
        if let Err(reason) = work.check(budget) {
            return self.userspace(batch, reason);
        }
        // One confirmed request on its original retained pidfd is a per-PID
        // promotion walk; anything else runs whole-system without a pidfd.
        // The fd is only ever borrowed from the charged preparation: a
        // missing pidfd runs whole-system, never a numeric reopen.
        let promotion = match batch.requests() {
            [only] => matches!(only.kind(), AcceptedKind::Confirm)
                .then(|| only.pidfd())
                .flatten(),
            _ => None,
        };
        let (mode, pid) = match promotion {
            Some(pidfd) => (RunMode::PerPid, Some(pidfd)),
            None => (RunMode::WholeSystem, None),
        };
        let bytes = match self.installed.read_target_typed(pid, deadline, max_bytes) {
            Ok(bytes) => {
                self.installed.target_attempts = self.installed.target_attempts.saturating_add(1);
                bytes
            }
            Err(reason) => {
                // Reservation/installation refusals precede target I/O and
                // are not attempts. Only an attempted run's failure demotes
                // later segments and moves the session streak.
                if matches!(reason, RunFailure::FdHeadroom | RunFailure::Scope) {
                    return self.userspace(batch, reason);
                }
                self.installed.target_attempts = self.installed.target_attempts.saturating_add(1);
                self.note_attempted_outcome(reason);
                self.installed.failed_target = Some(reason);
                return self.userspace(batch, reason);
            }
        };
        let run = match parse(
            &bytes,
            &Expect {
                generation,
                slots,
                scope: &scope,
                mode,
                run: RunKind::Target,
            },
        ) {
            Ok(run) => run,
            Err(_) => {
                self.note_attempted_outcome(RunFailure::StreamInvalid);
                self.installed.failed_target = Some(RunFailure::StreamInvalid);
                return self.userspace(batch, RunFailure::StreamInvalid);
            }
        };
        #[cfg(test)]
        tests::maybe_cross_work_deadline(&mut work);
        if let Err(reason) = work.check(budget) {
            self.note_attempted_outcome(reason);
            self.installed.failed_target = Some(reason);
            return self.userspace(batch, reason);
        }
        let mut answers = Vec::with_capacity(batch.requests().len());
        for (request, eligible) in batch.requests().iter().zip(eligible) {
            if let Err(reason) = work.step(budget) {
                self.note_attempted_outcome(reason);
                self.installed.failed_target = Some(reason);
                return self.userspace(batch, reason);
            }
            let demoted = run.demoted_pids.contains(&request.pid());
            let records = eligible
                .then(|| run.by_pid.get(&request.pid()))
                .flatten()
                .filter(|_| !demoted);
            let Some(records) = records else {
                let reason = if !eligible {
                    KernelFallbackReason::AnchorNotInstalled
                } else if demoted {
                    KernelFallbackReason::ConflictingDuplicate
                } else {
                    KernelFallbackReason::Unvisited
                };
                self.installed.session.fallback.note_fallback(
                    request.pid(),
                    request_keys(request),
                    reason,
                );
                answers.push(None);
                continue;
            };
            let mut mapped = MappedIdentities::new();
            for &range in request.ranges() {
                if let Err(reason) = work.step(budget) {
                    self.note_attempted_outcome(reason);
                    self.installed.failed_target = Some(reason);
                    return self.userspace(batch, reason);
                }
                let proof = match records.get(&range) {
                    Some(crate::attach::identity_iter::TargetVerdict::Slot(slot)) => {
                        super::sweep_attribution::RangeProof::Kernel(Slot(*slot))
                    }
                    Some(crate::attach::identity_iter::TargetVerdict::Unmatched) => {
                        super::sweep_attribution::RangeProof::KernelNone
                    }
                    None => super::sweep_attribution::RangeProof::NotMapped,
                };
                mapped.insert(range, proof);
            }
            answers.push(Some(mapped));
        }
        if let Err(reason) = work.check(budget) {
            self.note_attempted_outcome(reason);
            self.installed.failed_target = Some(reason);
            return self.userspace(batch, reason);
        }
        // A completed run breaks any deadline streak; stickiness never clears.
        self.installed.session.consecutive_deadlines = 0;
        let binding = self
            .installed
            .pass
            .as_ref()
            .expect("installed guard owns its pass")
            .binding
            .as_ref()
            .expect("owned installation has a binding");
        ProofDecision::Kernel(ValidatedTargetSegment {
            binding,
            batch: batch.token().clone(),
            answers,
        })
    }
}

impl<'g, 's, 'p, Io: ConfirmIo> KernelMemberProbe<'g, 's, 'p, Io> {
    pub(crate) fn segment_proof(&mut self) -> &mut impl SegmentProof {
        &mut self.proof
    }

    pub(crate) fn new(
        installed: &'g mut InstalledAnchorPass<'s, 'p>,
        io: Io,
        deadline: std::time::Instant,
    ) -> Self {
        let resources = installed
            .pass
            .as_ref()
            .expect("installed guard owns its pass")
            .reservations
            .immediate();
        Self {
            proof: KernelPassProof {
                installed,
                deadline,
                eligible_keys: BTreeSet::new(),
                auto_threshold: None,
            },
            io,
            resources,
        }
    }

    /// The automatic cost gate for this probe's segments: batches with fewer
    /// charged requests fall back with `below_threshold` and never attempt a
    /// target run. Absent, the probe runs every accepted batch (forced shape).
    pub(crate) fn with_auto_threshold(mut self, threshold: usize) -> Self {
        self.proof.auto_threshold = Some(threshold);
        self
    }

    pub(crate) fn install_expectations(
        &mut self,
        index: &mut KnownKeyIndex,
    ) -> Result<(), &'static str> {
        let pass = self
            .proof
            .installed
            .pass
            .as_ref()
            .expect("installed guard owns its pass");
        index.clear_kernel_slots();
        self.proof.eligible_keys.clear();
        // The held object's role is part of the expectation. An examined
        // file under a colliding key must never become its admitted provider.
        for (&(key, id), slots) in &pass.expected_matches {
            if index.classify(key) == super::sweep_attribution::KeyClass::Match(id) {
                index.set_kernel_slots(key, slots.clone())?;
                self.proof.eligible_keys.insert(key);
            }
        }
        for (&key, slots) in &pass.expected_examined {
            if index.classify(key) == super::sweep_attribution::KeyClass::Examined {
                index.set_kernel_slots(key, slots.clone())?;
                self.proof.eligible_keys.insert(key);
            }
        }
        Ok(())
    }
}

impl<Io: ConfirmIo> MemberProbe for KernelMemberProbe<'_, '_, '_, Io> {
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        // Scoped collection keeps its established per-read cancellation and
        // charging boundary; this opt-in substrate does not activate there.
        if budget.has_collection_work() {
            return super::sweep_attribution::confirm_with_resources(
                &mut self.io,
                pid,
                prove,
                budget,
                Some(&self.resources),
            );
        }
        let prepared =
            match prepare_confirmation(&mut self.io, pid, prove, budget, Some(&self.resources)) {
                Ok(prepared) => prepared,
                Err(confirmation) => return confirmation,
            };
        prove_and_finish_prepared(
            &mut self.io,
            pid,
            prepared,
            &mut self.proof,
            &self.resources,
            budget,
        )
    }

    fn stat_ranges(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        stat_unpinned_reserved(&mut self.io, pid, ranges, budget, &self.resources)
    }
}

#[cfg(test)]
struct DropObserver(Option<Box<dyn FnOnce()>>);
#[cfg(test)]
impl Drop for DropObserver {
    fn drop(&mut self) {
        if let Some(observe) = self.0.take() {
            observe();
        }
    }
}

impl<'p> AnchorPass<'p> {
    pub(crate) fn prepare(
        pins: &'p PinnedObjects,
        admitted: impl IntoIterator<Item = (ObjectKey, PinnedObjectId)>,
        custody: ExaminedCustody,
    ) -> Self {
        Self::prepare_limits(
            pins,
            admitted,
            custody,
            EXAMINED_ANCHOR_CAP,
            TOTAL_ANCHOR_CAP,
        )
    }

    fn prepare_limits(
        pins: &'p PinnedObjects,
        admitted: impl IntoIterator<Item = (ObjectKey, PinnedObjectId)>,
        mut custody: ExaminedCustody,
        examined_cap: usize,
        total_cap: usize,
    ) -> Self {
        let mut pass = Self {
            arena: None,
            #[cfg(test)]
            after_arena: None,
            candidates: Vec::new(),
            #[cfg(test)]
            after_files: None,
            fallback: custody
                .missing
                .into_iter()
                .map(|((_, key), reason)| (key, reason))
                .collect(),
            expected_matches: BTreeMap::new(),
            expected_examined: BTreeMap::new(),
            #[cfg(test)]
            expected: BTreeMap::new(),
            reservations: custody.owner.clone(),
            binding: None,
        };
        let mut admitted_by_id: BTreeMap<PinnedObjectId, BTreeSet<ObjectKey>> = BTreeMap::new();
        for (key, id) in admitted {
            admitted_by_id.entry(id).or_default().insert(key);
        }
        for (id, keys) in admitted_by_id {
            let Some(file) = pins.file_for(id) else {
                for key in keys {
                    pass.fallback.insert(key, AnchorDeny::AnchorNotInstalled);
                }
                continue;
            };
            if pass.candidates.len() >= total_cap.min(TOTAL_ANCHOR_CAP) {
                for key in keys {
                    pass.fallback.insert(key, AnchorDeny::AnchorCap);
                }
                continue;
            }
            pass.candidates.push(Candidate {
                keys,
                slot: Slot(pass.candidates.len() as u32),
                file: AnchorFile::Pinned { id, file },
            });
        }
        let callers = &custody.callers;
        custody.candidates.sort_by_key(|held| {
            (
                Reverse(callers.get(&held.examined.key).copied().unwrap_or(0)),
                held.examined.key,
                held.ordinal,
            )
        });
        for (index, held) in custody.candidates.into_iter().enumerate() {
            if index >= examined_cap.min(EXAMINED_ANCHOR_CAP)
                || pass.candidates.len() >= total_cap.min(TOTAL_ANCHOR_CAP)
            {
                pass.fallback
                    .insert(held.examined.key, AnchorDeny::AnchorCap);
                continue;
            }
            pass.candidates.push(Candidate {
                keys: BTreeSet::from([held.examined.key]),
                slot: Slot(pass.candidates.len() as u32),
                file: AnchorFile::Examined(held),
            });
        }
        if pass.candidates.is_empty() {
            return pass;
        }
        let arena = match AnchorArena::reserve(pass.candidates.len() as u32) {
            Ok(arena) => arena,
            Err(_) => {
                for candidate in &pass.candidates {
                    for key in &candidate.keys {
                        pass.fallback.insert(*key, AnchorDeny::AnchorNotInstalled);
                    }
                }
                pass.candidates.clear();
                return pass;
            }
        };
        pass.candidates.retain(|candidate| {
            let file = candidate.file.file();
            let mapped = file.metadata().is_ok_and(|meta| meta.len() > 0)
                && arena.map_slot(candidate.slot.0, file.as_fd()).is_ok();
            if !mapped {
                for key in &candidate.keys {
                    pass.fallback.insert(*key, AnchorDeny::AnchorNotInstalled);
                }
            }
            mapped
        });
        pass.arena = Some(arena);
        pass
    }

    fn accept_anchor_run(&mut self, bytes: &[u8], generation: u64) -> Result<(), String> {
        self.expected_matches.clear();
        self.expected_examined.clear();
        #[cfg(test)]
        self.expected.clear();
        let run = parse(
            bytes,
            &Expect {
                generation,
                slots: self.arena.as_ref().map_or(0, |arena| {
                    (arena.len() / crate::attach::identity_iter::ANCHOR_STRIDE) as u32
                }),
                scope: &BTreeSet::from([std::process::id()]),
                mode: RunMode::PerPid,
                run: RunKind::Anchor,
            },
        )
        .map_err(|_| "anchor installation stream is invalid".to_string())?;
        for candidate in &self.candidates {
            let root = match run.anchors.get(&candidate.slot.0) {
                Some(crate::attach::identity_iter::AnchorOutcome::Ok) => candidate.slot,
                Some(crate::attach::identity_iter::AnchorOutcome::Dup(root)) => Slot(*root),
                _ => {
                    for key in &candidate.keys {
                        self.fallback.insert(*key, AnchorDeny::AnchorNotInstalled);
                    }
                    continue;
                }
            };
            // Parser aliases are valid only relative to installed OK records.
            // A failed userspace mapping may leave a reserved slot gap: it
            // cannot supply an alias root even if an injected stream says OK.
            if !self
                .candidates
                .iter()
                .any(|installed| installed.slot == root)
            {
                for key in &candidate.keys {
                    self.fallback.insert(*key, AnchorDeny::AnchorNotInstalled);
                }
                continue;
            }
            for key in &candidate.keys {
                match &candidate.file {
                    AnchorFile::Pinned { id, .. } => {
                        self.expected_matches
                            .entry((*key, *id))
                            .or_default()
                            .insert(root);
                    }
                    AnchorFile::Examined(_) => {
                        self.expected_examined.entry(*key).or_default().insert(root);
                    }
                }
                #[cfg(test)]
                self.expected.entry(*key).or_default().insert(root);
            }
        }
        self.expected_matches
            .retain(|(key, _), _| !self.fallback.contains_key(key));
        self.expected_examined
            .retain(|key, _| !self.fallback.contains_key(key));
        #[cfg(test)]
        self.expected
            .retain(|key, _| !self.fallback.contains_key(key));
        Ok(())
    }

    fn read_run(
        &mut self,
        session: &IdentitySession,
        run: RunKind,
        pid: Option<std::os::fd::BorrowedFd<'_>>,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, &'static str> {
        self.read_run_typed(session, run, pid, deadline, max_bytes)
            .map_err(|_| "identity pass installation is unavailable")
    }

    fn owns_installation(&self, session: &IdentitySession) -> bool {
        let Some(binding) = &self.binding else {
            return false;
        };
        session.binding.as_ref().is_some_and(|installed| {
            binding.same_installation(installed)
                && Arc::ptr_eq(&binding.session, &session.token)
                && binding.generation == session.generation
                && self.arena.as_ref().is_some_and(|arena| {
                    arena.base() == binding.arena_base && arena.len() == binding.arena_len
                })
        })
    }

    fn read_run_typed(
        &mut self,
        session: &IdentitySession,
        run: RunKind,
        pid: Option<std::os::fd::BorrowedFd<'_>>,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, RunFailure> {
        if !self.owns_installation(session) || !session.scope.ready() {
            return Err(RunFailure::Scope);
        }
        session.read(run, pid, deadline, max_bytes)
    }

    #[cfg(test)]
    fn read_fixture_run(
        &mut self,
        iter: std::os::fd::OwnedFd,
        link: std::os::fd::OwnedFd,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, crate::attach::identity_iter::ReadError> {
        crate::attach::identity_iter::consume_owned_run(iter, link, deadline, max_bytes)
    }
}

/// The scope tracker belongs to this one fresh object; a failed replacement
/// cannot be bypassed by calling its iterator with an unrelated ready tracker.
pub(crate) struct IdentitySession {
    object: SessionObject,
    scope: ScopeBitmap,
    generation: u64,
    token: Arc<()>,
    binding: Option<PassBinding>,
    sticky: Option<KernelSticky>,
    consecutive_deadlines: u32,
    fallback: KernelFallbackLedger,
}

enum SessionObject {
    Kernel(StrictIdentity),
    #[cfg(test)]
    Fixture {
        _object: File,
        anchor: Vec<u8>,
        target: Vec<u8>,
        config: Option<crate::attach::identity_iter::IdentityConfig>,
        fail_config: bool,
        reads: std::cell::Cell<usize>,
        target_steps: std::cell::RefCell<std::collections::VecDeque<FixtureTarget>>,
        target_trace: Arc<std::sync::Mutex<FixtureRunTrace>>,
        scope_words: std::cell::RefCell<BTreeMap<u32, u64>>,
    },
}

#[cfg(test)]
enum FixtureTarget {
    Bytes(Vec<u8>),
    Deadline(Vec<u8>),
    Failure(RunFailure),
}

#[cfg(test)]
#[derive(Default)]
struct FixtureRunTrace {
    scopes: Vec<BTreeSet<u32>>,
    closed: Vec<(tests::FdToken, tests::FdToken)>,
    outcomes: Vec<Result<(), RunFailure>>,
    pidfds: Vec<Option<i32>>,
}

fn probe_succeeded(report: &crate::attach::identity_iter::FunctionalProbeReport) -> bool {
    use crate::attach::identity_iter::{AnchorOutcome, TargetVerdict};
    report.anchor_outcomes == [(0, AnchorOutcome::Ok), (1, AnchorOutcome::Ok)]
        && report.hardlink_verdict == TargetVerdict::Slot(0)
        && report.second_verdict == TargetVerdict::Slot(1)
        && report.copy_verdict == TargetVerdict::Unmatched
        && report.pids_seen == [report.child_pid]
        && report.demoted_pids.is_empty()
        && report.stale_unmatched
}

impl IdentitySession {
    #[cfg(test)]
    fn install_unowned_for_test<'p>(
        &mut self,
        pass: AnchorPass<'p>,
        generation: u64,
        deadline: std::time::Instant,
    ) -> Result<AnchorPass<'p>, &'static str> {
        self.install_pass(pass, generation, deadline)
    }

    pub(crate) fn probe_and_load(
        btf: &aya::Btf,
        dir: &std::path::Path,
    ) -> Result<Self, &'static str> {
        let loaded = probe_then_fresh(
            || {
                crate::attach::identity_iter::load_identity_object_strict(btf)
                    .map_err(|_| "identity object load failed")
            },
            |loaded| {
                let report = crate::attach::identity_iter::run_functional_probe(dir, loaded, 1)
                    .map_err(|_| "identity functional probe failed")?;
                if probe_succeeded(&report) {
                    Ok(())
                } else {
                    Err("identity functional probe failed")
                }
            },
        )?;
        Ok(Self {
            object: SessionObject::Kernel(loaded),
            scope: ScopeBitmap::default(),
            generation: 0,
            token: Arc::new(()),
            binding: None,
            sticky: None,
            consecutive_deadlines: 0,
            fallback: KernelFallbackLedger::default(),
        })
    }

    pub(crate) fn replace_scope(&mut self, tgids: &[u32]) -> Result<(), &'static str> {
        self.binding = None;
        match &mut self.object {
            SessionObject::Kernel(loaded) => self
                .scope
                .replace(&mut loaded.ebpf, tgids)
                .map_err(|_| "identity scope is unavailable"),
            #[cfg(test)]
            SessionObject::Fixture { scope_words, .. } => {
                self.scope.fixture_replace_observed(tgids, |word, bits| {
                    scope_words.borrow_mut().insert(word, bits);
                })
            }
        }
    }

    fn configure(
        &mut self,
        config: crate::attach::identity_iter::IdentityConfig,
    ) -> Result<(), &'static str> {
        match &mut self.object {
            SessionObject::Kernel(loaded) => {
                crate::attach::identity_iter::write_identity_config(&mut loaded.ebpf, &config)
                    .map_err(|_| "identity anchor configuration failed")
            }
            #[cfg(test)]
            SessionObject::Fixture {
                config: installed,
                fail_config,
                ..
            } => {
                if *fail_config {
                    return Err("injected configuration failure");
                }
                *installed = Some(config);
                Ok(())
            }
        }
    }

    fn read(
        &self,
        run: RunKind,
        pid: Option<std::os::fd::BorrowedFd<'_>>,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, RunFailure> {
        match &self.object {
            SessionObject::Kernel(loaded) => {
                let program = match run {
                    RunKind::Anchor => &loaded.anchor_fd,
                    RunKind::Target => &loaded.target_fd,
                };
                crate::attach::identity_iter::attach_and_read_run_typed(
                    program.as_fd(),
                    pid,
                    deadline,
                    max_bytes,
                )
                .map_err(|error| match error {
                    crate::attach::identity_iter::OwnedRunError::Attach(_) => {
                        RunFailure::AttachOrRead
                    }
                    crate::attach::identity_iter::OwnedRunError::Read(error) => error.into(),
                })
            }
            #[cfg(test)]
            SessionObject::Fixture {
                anchor,
                target,
                reads,
                target_steps,
                target_trace,
                scope_words,
                ..
            } => {
                use std::os::unix::fs::FileExt;
                reads.set(reads.get() + 1);
                let step = (run == RunKind::Target)
                    .then(|| target_steps.borrow_mut().pop_front())
                    .flatten();
                let scope: BTreeSet<_> = scope_words
                    .borrow()
                    .iter()
                    .flat_map(|(&word, &bits)| {
                        (0..64).filter_map(move |bit| {
                            (bits & (1u64 << bit) != 0).then_some(word * 64 + bit)
                        })
                    })
                    .collect();
                if run == RunKind::Target {
                    let mut trace = target_trace.lock().unwrap();
                    trace.scopes.push(scope);
                    trace
                        .pidfds
                        .push(pid.map(|fd| std::os::fd::AsRawFd::as_raw_fd(&fd)));
                }
                if let Some(FixtureTarget::Failure(reason)) = step {
                    target_trace.lock().unwrap().outcomes.push(Err(reason));
                    return Err(reason);
                }
                let bytes = match &step {
                    Some(FixtureTarget::Bytes(bytes) | FixtureTarget::Deadline(bytes)) => bytes,
                    _ => match run {
                        RunKind::Anchor => anchor,
                        RunKind::Target => target,
                    },
                };
                let file = tempfile::tempfile().unwrap();
                file.write_at(bytes, 0).unwrap();
                let link = tempfile::tempfile().unwrap();
                let tokens = (tests::FdToken::of(&file), tests::FdToken::of(&link));
                let read_deadline = if matches!(step, Some(FixtureTarget::Deadline(_))) {
                    std::time::Instant::now() - std::time::Duration::from_millis(1)
                } else {
                    deadline
                };
                let result = crate::attach::identity_iter::consume_owned_run(
                    file.into(),
                    link.into(),
                    read_deadline,
                    max_bytes,
                )
                .map_err(RunFailure::from);
                if run == RunKind::Target {
                    let mut trace = target_trace.lock().unwrap();
                    trace.closed.push(tokens);
                    trace
                        .outcomes
                        .push(result.as_ref().map(|_| ()).map_err(|reason| *reason));
                }
                result
            }
        }
    }

    /// Install only this pass's observer anchors. Target-range proof belongs
    /// to D3c. A generation is spent before I/O so a failed pass cannot reuse it.
    pub(crate) fn install_anchors<'s, 'p>(
        &'s mut self,
        pass: AnchorPass<'p>,
        generation: u64,
        deadline: std::time::Instant,
    ) -> Result<InstalledAnchorPass<'s, 'p>, &'static str> {
        let pass = self.install_pass(pass, generation, deadline)?;
        Ok(InstalledAnchorPass {
            pass: Some(pass),
            session: self,
            failed_target: None,
            target_attempts: 0,
        })
    }

    fn install_pass<'p>(
        &mut self,
        pass: AnchorPass<'p>,
        generation: u64,
        deadline: std::time::Instant,
    ) -> Result<AnchorPass<'p>, &'static str> {
        self.binding = None;
        self.scope.invalidate();
        self.fallback.begin_pass();
        let result = self.install_pass_inner(pass, generation, deadline);
        if result.is_err() {
            self.binding = None;
            self.scope.invalidate();
        }
        result
    }

    fn install_pass_inner<'p>(
        &mut self,
        mut pass: AnchorPass<'p>,
        generation: u64,
        deadline: std::time::Instant,
    ) -> Result<AnchorPass<'p>, &'static str> {
        pass.expected_matches.clear();
        pass.expected_examined.clear();
        #[cfg(test)]
        pass.expected.clear();
        if generation <= self.generation || generation >= u64::from(u32::MAX) {
            return Err("identity generation is unavailable");
        }
        self.generation = generation;
        let Some(arena) = pass.arena.as_ref() else {
            return Err("identity anchor arena is unavailable");
        };
        let slots = (arena.len() / crate::attach::identity_iter::ANCHOR_STRIDE) as u32;
        let config = arena.config(generation, slots, std::process::id());
        self.replace_scope(&[std::process::id()])?;
        self.configure(config)?;
        let binding = PassBinding {
            session: self.token.clone(),
            generation,
            arena_base: arena.base(),
            arena_len: arena.len(),
        };
        pass.binding = Some(binding.clone());
        self.binding = Some(binding);
        let pid_lease = pass
            .reservations
            .immediate()
            .pin()
            .map_err(|_| "identity anchor FD headroom is unavailable")?;
        let pid = crate::attach::identity_iter::open_pidfd(std::process::id())
            .map_err(|_| "identity anchor observer is unavailable")?;
        let run_lease = pass
            .reservations
            .immediate()
            .transient()
            .map_err(|_| "identity anchor FD headroom is unavailable")?;
        let result = pass.read_run(
            self,
            RunKind::Anchor,
            Some(pid.as_fd()),
            deadline,
            (slots as usize + 1) * crate::attach::identity_iter::RECORD_LEN,
        );
        drop(run_lease);
        drop(pid);
        drop(pid_lease);
        let bytes = result?;
        pass.accept_anchor_run(&bytes, generation)
            .map_err(|_| "identity anchor installation failed")?;
        Ok(pass)
    }
}

/// The probe mutates scope/config/generation. Production requires a distinct
/// fresh strict-loaded object after the complete probe owner has been dropped.
fn probe_then_fresh<L, E>(
    mut load: impl FnMut() -> Result<L, E>,
    probe: impl FnOnce(&mut L) -> Result<(), E>,
) -> Result<L, E> {
    let mut loaded = load()?;
    probe(&mut loaded)?;
    drop(loaded);
    load()
}

#[cfg(test)]
#[path = "kernel_identity_tests.rs"]
mod tests;
