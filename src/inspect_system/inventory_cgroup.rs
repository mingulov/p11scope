//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded cgroup transactions. Candidates schedule work; only borrowed
//! transaction permits can authorize admission. Custody survives publication.

use super::*;
use crate::discovery::engine::sweep_process_maps_with;
use crate::discovery::scan::{CollectionWork, MapsReadLimits};
use crate::scope::inventory_cgroup::{
    CandidateBatch, CandidateQuota, CgroupIncomplete, CgroupWalkBudget, CgroupWalkLimits,
    CgroupWalkState, CollectionControl, CollectionOutcome, CollectionStop, MemberLocator,
    MembershipOutcome, MembershipSamples, next_candidates, sample_members,
};
use std::fs::File;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// Private processing/custody ceilings, not a release qualification envelope.
const PROCESS_PIN_LIMIT: usize = 128;
const DEFAULT_DEEP_SCAN_LIMIT: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScopedCollectionOutcome {
    Complete,
    Incomplete(ScopedCollectionGap),
    Cancelled(CollectionStop),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScopedCollectionGap {
    Membership(CgroupIncomplete),
    ProcessUnavailable,
    GenerationChanged,
    ScanIncomplete,
}
impl ScopedCollectionOutcome {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Complete => {
                "sampled cgroup transaction completed; continuous membership remains unproved"
            }
            Self::Cancelled(CollectionStop::OperatorStop) => {
                "cgroup collection cancelled by the operator"
            }
            Self::Cancelled(CollectionStop::Deadline) => "cgroup collection deadline reached",
            Self::Incomplete(ScopedCollectionGap::Membership(CgroupIncomplete::WorkLimit)) => {
                "cgroup collection shared work allowance exhausted"
            }
            Self::Incomplete(ScopedCollectionGap::Membership(_)) => {
                "cgroup membership collection incomplete"
            }
            Self::Incomplete(ScopedCollectionGap::ProcessUnavailable) => {
                "cgroup member generation could not be pinned or read"
            }
            Self::Incomplete(ScopedCollectionGap::GenerationChanged) => {
                "cgroup member generation or image changed during its transaction"
            }
            Self::Incomplete(ScopedCollectionGap::ScanIncomplete) => {
                "cgroup member scan was incomplete"
            }
        }
    }
}
impl From<CollectionOutcome> for ScopedCollectionOutcome {
    fn from(outcome: CollectionOutcome) -> Self {
        match outcome {
            CollectionOutcome::Complete => Self::Complete,
            CollectionOutcome::Incomplete(reason) => {
                Self::Incomplete(ScopedCollectionGap::Membership(reason))
            }
            CollectionOutcome::Cancelled(stop) => Self::Cancelled(stop),
        }
    }
}

/// Coordinator-owned job freshness. It detects witnessed EXEC even while a
/// job is outside the coordinator; exhaustion never wraps into old authority.
#[derive(Clone, Default)]
pub(crate) struct CgroupFence(Arc<AtomicU64>);
#[derive(Clone)]
pub(crate) struct CgroupJobFence {
    owner: CgroupFence,
    issued: u64,
}
impl CgroupFence {
    pub(crate) fn issue(&self) -> CgroupJobFence {
        CgroupJobFence {
            owner: self.clone(),
            issued: self.0.load(Ordering::SeqCst),
        }
    }
    pub(crate) fn invalidate(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            });
    }
    #[cfg(test)]
    pub(crate) fn exhaust(&self) {
        self.0.store(u64::MAX, Ordering::SeqCst);
    }
}
impl CgroupJobFence {
    fn current(&self) -> bool {
        self.issued != u64::MAX && self.owner.0.load(Ordering::SeqCst) == self.issued
    }
    fn issued_by(&self, owner: &CgroupFence) -> bool {
        Arc::ptr_eq(&self.owner.0, &owner.0)
    }
}

/// One remaining allowance shared by walking, both samples, actual scanner
/// checkpoints and publication. It is never renewed inside a transaction.
#[derive(Clone)]
pub(crate) struct SharedCollectionWork {
    budget: Arc<Mutex<CgroupWalkBudget>>,
    control: CollectionControl,
    fence: CgroupJobFence,
    stopped: Arc<Mutex<Option<CollectionOutcome>>>,
}
impl SharedCollectionWork {
    fn new(limits: CgroupWalkLimits, control: CollectionControl, fence: CgroupJobFence) -> Self {
        Self {
            budget: Arc::new(Mutex::new(CgroupWalkBudget::new(limits))),
            control,
            fence,
            stopped: Arc::new(Mutex::new(None)),
        }
    }
    fn note_stop(&self, outcome: CollectionOutcome) {
        let mut stopped = self.stopped.lock().unwrap();
        if stopped.is_none() || matches!(outcome, CollectionOutcome::Cancelled(_)) {
            *stopped = Some(outcome);
        }
    }
    pub(crate) fn charge(&self, units: usize) -> bool {
        if let Err(stop) = self.control.check() {
            self.note_stop(CollectionOutcome::Cancelled(stop));
            return false;
        }
        if !self.fence.current() {
            self.note_stop(CollectionOutcome::Incomplete(
                CgroupIncomplete::ChangedMembership,
            ));
            return false;
        }
        if self.stopped.lock().unwrap().is_some() {
            return false;
        }
        let result = self
            .budget
            .lock()
            .unwrap()
            .charge_work(&self.control, units);
        if let Err(outcome) = result {
            self.note_stop(outcome);
            return false;
        }
        true
    }
    fn hook(&self) -> CollectionWork {
        let shared = self.clone();
        CollectionWork::new(move |units| {
            shared.charge(usize::try_from(units).unwrap_or(usize::MAX))
        })
    }
    fn sample(
        &self,
        root: &Arc<File>,
        requests: &BTreeMap<u32, MemberLocator>,
    ) -> MembershipSamples {
        sample_members(
            root,
            requests,
            &mut self.budget.lock().unwrap(),
            &self.control,
        )
    }
    fn stopped(&self) -> Option<CollectionOutcome> {
        self.charge(0);
        *self.stopped.lock().unwrap()
    }
}

struct MemberTransaction {
    original: Arc<ProcessView>,
    generation: MemberGeneration,
}
/// Pin preparation can read identity, but cannot mint an ID or authorize it.
pub(crate) struct CgroupPreparation<'a> {
    member: &'a MemberTransaction,
    work: &'a SharedCollectionWork,
}
impl CgroupPreparation<'_> {
    pub(crate) fn pid(&self) -> u32 {
        self.member.original.pid()
    }
    pub(crate) fn generation(&self) -> &MemberGeneration {
        &self.member.generation
    }
    pub(crate) fn check(&self) -> bool {
        self.work.charge(4) && original_matches(self.member)
    }
}
/// Non-Clone borrowed authority from one final sampled transaction. Keeping
/// the collection borrowed retains its original process handle and root.
pub(crate) struct CgroupAdmissionPermit<'a> {
    member: &'a MemberTransaction,
    work: &'a SharedCollectionWork,
}
impl CgroupAdmissionPermit<'_> {
    pub(crate) fn pid(&self) -> u32 {
        self.member.original.pid()
    }
    pub(crate) fn generation(&self) -> &MemberGeneration {
        &self.member.generation
    }
    pub(crate) fn check(&self) -> bool {
        self.work.charge(2) && self.member.original.still_the_same()
    }
    /// Poll after the returning source liveness operation. This final guard
    /// performs no identity I/O, so it cannot open another unchecked gap.
    pub(crate) fn finish_check(&self) -> bool {
        self.work.charge(1)
    }
}
fn original_matches(member: &MemberTransaction) -> bool {
    let generation = &member.generation;
    generation.start_time.is_some()
        && generation.exe.is_some()
        && member.original.still_the_same()
        && member.original.start_time() == generation.start_time
        && read_exe_identity(member.original.pid()) == generation.exe
}

/// The job owns its continuation and immutable scan policy. Cg4 moves this
/// into one worker and returns the continuation only after publication.
pub(crate) struct CgroupCollectRequest {
    pub(crate) root: Arc<File>,
    pub(crate) fence: CgroupJobFence,
    pub(crate) state: CgroupWalkState,
    pub(crate) limits: CgroupWalkLimits,
    pub(crate) control: CollectionControl,
    pub(crate) max_scan_pids: Option<usize>,
    pub(crate) scan_budget: CaptureWorkBudget,
}

pub(crate) struct CgroupCollection {
    root: Arc<File>,
    state: CgroupWalkState,
    originals: BTreeMap<u32, MemberTransaction>,
    locators: BTreeMap<u32, MemberLocator>,
    collection: Option<Collection>,
    bound: Option<Bound>,
    attributed: Option<Attributed>,
    policy: AdmissionPolicy,
    work: SharedCollectionWork,
    outcome: ScopedCollectionOutcome,
    end: Option<MembershipSamples>,
    ready: BTreeSet<u32>,
    invalidated: BTreeSet<u32>,
    eligible: BTreeSet<u32>,
    timings: StageTimings,
}
impl CgroupCollection {
    pub(crate) fn root(&self) -> &Arc<File> {
        &self.root
    }
    pub(crate) fn issued_by(&self, fence: &CgroupFence) -> bool {
        self.work.fence.issued_by(fence)
    }
    pub(crate) fn provider_inputs(&self) -> &PinnedObjects {
        &self
            .bound
            .as_ref()
            .expect("retained raw aggregate")
            .aggregate
    }
    pub(crate) fn preparation_incomplete(&mut self) {
        self.note(ScopedCollectionOutcome::Incomplete(
            ScopedCollectionGap::ScanIncomplete,
        ));
    }
    pub(crate) fn work(&self) -> SharedCollectionWork {
        self.work.clone()
    }
    pub(crate) fn member_pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.originals.keys().copied()
    }
    pub(crate) fn outcome(&self) -> ScopedCollectionOutcome {
        let stopped = self.work.stopped();
        if let Some(CollectionOutcome::Cancelled(stop)) = stopped {
            return ScopedCollectionOutcome::Cancelled(stop);
        }
        if !self.work.fence.current() {
            return ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::GenerationChanged);
        }
        stopped.map_or(self.outcome, ScopedCollectionOutcome::from)
    }
    fn note(&mut self, outcome: ScopedCollectionOutcome) {
        if matches!(self.outcome, ScopedCollectionOutcome::Complete)
            || matches!(outcome, ScopedCollectionOutcome::Cancelled(_))
        {
            self.outcome = outcome;
        }
    }
    pub(crate) fn preparation_failed(&mut self) {
        self.note(ScopedCollectionOutcome::Incomplete(
            ScopedCollectionGap::ProcessUnavailable,
        ));
    }
    pub(crate) fn invalidate(&mut self, pid: u32) {
        if self.originals.contains_key(&pid) {
            self.invalidated.insert(pid);
            self.note(ScopedCollectionOutcome::Incomplete(
                ScopedCollectionGap::GenerationChanged,
            ));
        }
    }
    pub(crate) fn preparation(&self, pid: u32) -> Option<CgroupPreparation<'_>> {
        if !self.work.fence.current()
            || self.invalidated.contains(&pid)
            || !self.eligible.contains(&pid)
        {
            return None;
        }
        let member = self.originals.get(&pid)?;
        Some(CgroupPreparation {
            member,
            work: &self.work,
        })
    }
    /// Final identity reads and source-pin preparation precede this fresh
    /// zero-origin grouped end sample. It runs in commit_batch, not apply.
    pub(crate) fn sample_end(&mut self, prepared: &BTreeSet<u32>) {
        if !self
            .work
            .charge(self.locators.len().saturating_mul(2).saturating_add(1))
        {
            self.locators.clear();
            self.end = None;
            return;
        }
        for &pid in prepared {
            if !self.work.charge(4) {
                break;
            }
            if let Some(member) = self.originals.get(&pid)
                && !self.invalidated.contains(&pid)
                && original_matches(member)
            {
                self.ready.insert(pid);
            } else {
                self.note(ScopedCollectionOutcome::Incomplete(
                    ScopedCollectionGap::GenerationChanged,
                ));
            }
        }
        // Move the walker-owned locator allocation through the transaction;
        // no extra path copies escape the walker path budget.
        self.locators.retain(|pid, _| self.ready.contains(pid));
        let end = self.work.sample(&self.root, &self.locators);
        self.note(end.outcome.into());
        if self
            .locators
            .keys()
            .any(|pid| end.answer(*pid) != MembershipOutcome::Present)
        {
            self.note(ScopedCollectionOutcome::Incomplete(
                ScopedCollectionGap::Membership(CgroupIncomplete::ChangedMembership),
            ));
        }
        self.end = Some(end);
    }
    pub(crate) fn permit(&self, pid: u32) -> Option<CgroupAdmissionPermit<'_>> {
        if !self.ready.contains(&pid)
            || self.invalidated.contains(&pid)
            || self.end.as_ref()?.answer(pid) != MembershipOutcome::Present
        {
            return None;
        }
        let permit = CgroupAdmissionPermit {
            member: self.originals.get(&pid)?,
            work: &self.work,
        };
        permit.check().then_some(permit)
    }
    /// Reserve bounded pure lowering/projection work before final sampling.
    /// Count metadata by charged container quanta; never walk retained edges
    /// merely to discover their count. Heavy general lowering remains capped.
    pub(crate) fn reserve_projection(&self, edges: usize) -> bool {
        let Some(collection) = &self.collection else {
            return false;
        };
        let Some(bound) = &self.bound else {
            return false;
        };
        if !self.work.charge(
            edges
                .saturating_mul(8)
                .saturating_add(self.originals.len().saturating_mul(8))
                .saturating_add(1),
        ) {
            return false;
        }
        let mut entries = 0usize;
        for member in &collection.members {
            if !self.work.charge(
                member
                    .modules
                    .len()
                    .saturating_mul(4)
                    .saturating_add(member.gaps.len())
                    .saturating_add(1),
            ) {
                return false;
            }
            for module in &member.modules {
                if !self.work.charge(
                    module
                        .tables
                        .len()
                        .saturating_mul(4)
                        .saturating_add(module.interfaces.len().saturating_mul(4))
                        .saturating_add(1),
                ) {
                    return false;
                }
                for table in &module.tables {
                    if !self
                        .work
                        .charge(table.entries.len().saturating_mul(16).saturating_add(1))
                    {
                        return false;
                    }
                    entries = entries.saturating_add(table.entries.len());
                }
            }
        }
        let modules = bound
            .reconciled
            .len()
            .saturating_add(bound.unresolved.len());
        let mut pins = 0usize;
        for pin in bound.aggregate.pinned() {
            if !self
                .work
                .charge(pin.path.len().div_ceil(16).saturating_add(4))
            {
                return false;
            }
            pins = pins.saturating_add(1);
        }
        self.work.charge(
            entries
                .saturating_mul(modules.saturating_add(1))
                .saturating_mul(8)
                .saturating_add(pins.saturating_mul(pins).saturating_mul(4))
                .saturating_add(
                    collection
                        .sweep
                        .iter()
                        .map(|(_, maps)| maps.len())
                        .sum::<usize>()
                        .saturating_mul(8),
                ),
        )
    }

    /// Pure lowering is delayed until validation. Invalid members cannot
    /// contribute objects through a previously computed attach plan.
    pub(crate) fn catalog(&mut self, allowed: &BTreeSet<u32>) -> Catalog {
        let mut collection = self
            .collection
            .take()
            .expect("one collection consumes its facts once");
        let mut bound = self
            .bound
            .take()
            .expect("one collection consumes its bound facts once");
        let mut attributed = self.attributed.take();
        let units = collection
            .members
            .len()
            .saturating_add(bound.reconciled.len())
            .saturating_add(bound.unresolved.len())
            .saturating_add(bound.bind_gaps.len())
            .saturating_mul(8);
        if !self.work.charge(units) {
            // Only cleanup traverses existing allocations after exhaustion.
            // No bulk unknown map or new fact materialization is required.
            collection.members.clear();
            collection.sweep.clear();
            collection.enumerated.clear();
            collection.selected.clear();
            bound = empty_bound();
            attributed = None;
        } else {
            collection
                .members
                .retain(|member| allowed.contains(&member.pid));
            bound.reconciled.retain(|(pid, _, _)| allowed.contains(pid));
            bound
                .unresolved
                .retain(|(pid, _, _, _)| allowed.contains(pid));
            bound
                .bind_gaps
                .retain(|gap| gap.pid.is_none_or(|pid| allowed.contains(&pid)));
            if let Some(attributed) = &mut attributed {
                attributed
                    .attribution
                    .members
                    .retain(|member| allowed.contains(&member.pid));
                attributed
                    .attribution
                    .unexamined
                    .retain(|pid, _| allowed.contains(pid));
            }
        }
        if allowed.len() != self.originals.len() {
            self.note(ScopedCollectionOutcome::Incomplete(
                ScopedCollectionGap::ScanIncomplete,
            ));
        }
        let outcome = self.outcome();
        if outcome != ScopedCollectionOutcome::Complete {
            collection.scope_gaps.push(scope_gap(outcome.reason()));
        }
        let mut catalog = assemble(collection, bound, attributed, self.policy);
        catalog.stage_timings = std::mem::take(&mut self.timings);
        catalog
    }
    pub(crate) fn finish(self) -> (CgroupWalkState, ScopedCollectionOutcome) {
        let outcome = self.outcome();
        (self.state, outcome)
    }
    #[cfg(test)]
    pub(crate) fn used_work(&self) -> usize {
        self.work.budget.lock().unwrap().used.units
    }
    #[cfg(test)]
    pub(crate) fn original_weak(&self, pid: u32) -> Option<std::sync::Weak<ProcessView>> {
        self.originals
            .get(&pid)
            .map(|member| Arc::downgrade(&member.original))
    }
}
struct ControlledObjectChecks<'a> {
    checks: &'a dyn ObjectChecks,
    work: &'a SharedCollectionWork,
}
impl ObjectChecks for ControlledObjectChecks<'_> {
    fn nonunique_inodes(&self, object: PinnedObjectId) -> Result<Option<&'static str>, String> {
        if !self.work.charge(2) {
            return Err("cgroup object check interrupted".into());
        }
        self.checks.nonunique_inodes(object)
    }
    fn unchanged(&self, object: PinnedObjectId) -> Result<bool, String> {
        if !self.work.charge(2) {
            return Err("cgroup object check interrupted".into());
        }
        self.checks.unchanged(object)
    }
    fn mapped_identity(
        &self,
        object: PinnedObjectId,
    ) -> Result<crate::discovery::identity::MappedFile, String> {
        if !self.work.charge(4) {
            return Err("cgroup object check interrupted".into());
        }
        self.checks.mapped_identity(object)
    }
}

fn empty_bound() -> Bound {
    Bound {
        aggregate: PinnedObjects::empty(),
        reconciled: Vec::new(),
        unresolved: Vec::new(),
        bind_gaps: Vec::new(),
    }
}
fn scope_gap(reason: &str) -> PidGap {
    PidGap {
        pid: None,
        subject: "cgroup scope transaction incomplete".into(),
        reason: reason.into(),
        generic: false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CollectionStage {
    Traversed,
    Begin,
    Sweep,
    DeepScan,
    Confirm,
    Prepared,
}

pub(crate) fn collect(
    request: CgroupCollectRequest,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    policy: AdmissionPolicy,
) -> CgroupCollection {
    collect_with(request, hints, hooks, policy, &mut |_| {})
}
fn collect_with(
    mut request: CgroupCollectRequest,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    policy: AdmissionPolicy,
    checkpoint: &mut dyn FnMut(CollectionStage),
) -> CgroupCollection {
    let started = monotonic_ns();
    let work = SharedCollectionWork::new(request.limits.clone(), request.control, request.fence);
    let quota = CandidateQuota {
        candidates: PROCESS_PIN_LIMIT,
        work_units: request.limits.work_units.min(1 << 16),
    };
    let candidates = if work.charge(1) {
        next_candidates(
            &request.root,
            &mut request.state,
            &mut work.budget.lock().unwrap(),
            &work.control,
            quota,
        )
    } else {
        CandidateBatch {
            candidates: BTreeMap::new(),
            outcome: work.stopped().unwrap(),
            work: Default::default(),
        }
    };
    let mut outcome = ScopedCollectionOutcome::from(candidates.outcome);
    checkpoint(CollectionStage::Traversed);
    let mut pinned = BTreeMap::new();
    let mut requests = BTreeMap::new();
    for (index, (pid, locator)) in candidates.candidates.into_iter().enumerate() {
        if !work.charge(6) {
            break;
        }
        match ProcessView::open(ProcessViewId(index as u32), pid) {
            Ok(view) => {
                let generation = MemberGeneration {
                    start_time: view.start_time(),
                    exe: read_exe_identity(pid),
                };
                if generation.start_time.is_some()
                    && generation.exe.is_some()
                    && view.still_the_same()
                {
                    requests.insert(pid, locator);
                    pinned.insert(
                        pid,
                        MemberTransaction {
                            original: Arc::new(view),
                            generation,
                        },
                    );
                } else if outcome == ScopedCollectionOutcome::Complete {
                    outcome = ScopedCollectionOutcome::Incomplete(
                        ScopedCollectionGap::ProcessUnavailable,
                    );
                }
            }
            Err(_) => {
                if outcome == ScopedCollectionOutcome::Complete {
                    outcome = ScopedCollectionOutcome::Incomplete(
                        ScopedCollectionGap::ProcessUnavailable,
                    );
                }
            }
        }
    }
    checkpoint(CollectionStage::Begin);
    let begin = work.sample(&request.root, &requests);
    if outcome == ScopedCollectionOutcome::Complete {
        outcome = begin.outcome.into();
    }
    pinned.retain(|pid, _| begin.answer(*pid) == MembershipOutcome::Present);
    if pinned.len() != requests.len() && outcome == ScopedCollectionOutcome::Complete {
        outcome = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
            CgroupIncomplete::ChangedMembership,
        ));
    }
    requests.retain(|pid, _| pinned.contains_key(pid));
    if !work.charge(pinned.len().saturating_mul(6).saturating_add(1)) {
        pinned.clear();
        requests.clear();
    }
    let pids: Vec<_> = pinned.keys().copied().collect();
    let cap = request
        .max_scan_pids
        .unwrap_or(DEFAULT_DEEP_SCAN_LIMIT)
        .clamp(1, PROCESS_PIN_LIMIT);
    let mut budget = request.scan_budget;
    budget.set_collection_work(work.hook());
    let scan_window = if matches!(
        budget.policy(),
        crate::discovery::scan::DiscoveryPolicy::Inventory(_)
    ) {
        let token = budget
            .begin_window(crate::discovery::scan::WindowId::new(1), u64::MAX)
            .expect("collector owns a fresh Inventory budget");
        let scan = budget
            .checkpoint(token.clone())
            .expect("fresh collection window has no scan");
        Some((token, scan))
    } else {
        None
    };
    let mut timings = StageTimings::new();
    let mut sweep = Vec::new();
    let mut sweep_unavailable = BTreeSet::new();
    let mut selected = pids.clone();
    if pids.len() > cap {
        checkpoint(CollectionStage::Sweep);
        for &pid in &pids {
            if !work.charge(2) {
                break;
            }
            let (mut swept, unavailable, skip) = sweep_process_maps_with(
                &[pid],
                &mut budget,
                1,
                MapsReadLimits::LIVE,
                &|pid| File::open(format!("/proc/{pid}/maps")),
                &monotonic_ns,
            )
            .into_selection_with_unavailable();
            sweep.append(&mut swept);
            sweep_unavailable.extend(unavailable);
            if skip.is_some() && outcome == ScopedCollectionOutcome::Complete {
                outcome = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::ScanIncomplete);
            }
        }
        selected = select_deep_scan_candidates(&sweep, cap);
    }
    let mut noise = DiscoveryNoiseAggregator::default();
    let mut members = Vec::new();
    for pid in &selected {
        checkpoint(CollectionStage::DeepScan);
        if !work.charge(6) {
            break;
        }
        let original = &pinned[pid];
        let before = (budget.stopped_reason(), budget.refusal_counts());
        let started = monotonic_ns();
        let mut reader = ProcessViewImageReader::new(&original.original);
        let member = scan_member_application_with(&mut reader, |reader| {
            scan_pinned_member(
                reader.view(),
                hints,
                hooks,
                &mut budget,
                &mut noise,
                started,
                before,
            )
        });
        members.push(member);
    }
    noise.report();
    let mut collection = Collection {
        enumerated: pids.clone(),
        selected,
        cap,
        cap_hit: pids.len() > cap,
        members,
        scope_gaps: Vec::new(),
        proc_list_failed: false,
        sweep,
        sweep_unavailable,
        budget,
    };
    let bound = if work.charge(
        collection
            .members
            .iter()
            .map(|member| member.modules.len().saturating_add(member.examined.len()))
            .sum::<usize>()
            .saturating_add(1),
    ) {
        bind_collection(&mut collection)
    } else {
        empty_bound()
    };
    checkpoint(CollectionStage::Confirm);
    // Cgroup work stays serial: shard shadows do not spend this transaction's
    // allowance at the real read boundary. Each confirmation uses its hook.
    let attributed = if work.charge(1) {
        attribute_sweep(
            &mut collection,
            &bound,
            &mut OsMemberProbe { pool: None },
            &ControlledObjectChecks {
                checks: &bound.aggregate,
                work: &work,
            },
        )
    } else {
        None
    };
    if collection.budget.stopped_reason().is_some() && outcome == ScopedCollectionOutcome::Complete
    {
        outcome = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::ScanIncomplete);
    }
    if let Some((token, scan)) = scan_window {
        collection
            .budget
            .finish_scan(scan)
            .expect("collector finishes its own scan");
        collection
            .budget
            .finish_window(token)
            .expect("collector finishes its own window");
    }
    checkpoint(CollectionStage::Prepared);
    // Materialization after a stop is limited to already bounded custody and
    // cleanup. The final membership sample and authorization run at commit.
    timings.span(StageKind::Scan, "cgroup_collect", started, monotonic_ns());
    let mut eligible = BTreeSet::new();
    for member in &collection.members {
        if !work.charge(member.gaps.len().saturating_add(3)) {
            break;
        }
        if outcome == ScopedCollectionOutcome::Complete
            && (!matches!(member.status, MemberStatus::Scanned)
                || member
                    .gaps
                    .iter()
                    .any(|gap| scan_skip_truncates(&gap.reason)))
        {
            outcome = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::ScanIncomplete);
        }
        if member.status.attributable()
            && member.generation.as_ref()
                == pinned.get(&member.pid).map(|original| &original.generation)
        {
            eligible.insert(member.pid);
        } else if outcome == ScopedCollectionOutcome::Complete {
            outcome = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::ScanIncomplete);
        }
    }
    if let Some(attributed) = &attributed {
        if outcome == ScopedCollectionOutcome::Complete
            && (attributed.attribution.unavailable > 0
                || !attributed.attribution.unexamined.is_empty()
                || !attributed.attribution.losses.is_empty()
                || !attributed.changed.is_empty()
                || !attributed.refused.is_empty())
        {
            outcome = ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::ScanIncomplete);
        }
        for member in &attributed.attribution.members {
            if !work.charge(3) {
                break;
            }
            if pinned.get(&member.pid).is_some_and(|original| {
                original.generation.start_time == Some(member.start_time)
                    && original.generation.exe.as_ref() == Some(&member.exe)
            }) {
                eligible.insert(member.pid);
            }
        }
    }
    CgroupCollection {
        root: request.root,
        state: request.state,
        originals: pinned,
        locators: requests,
        collection: Some(collection),
        bound: Some(bound),
        attributed,
        policy,
        work,
        outcome,
        end: None,
        ready: BTreeSet::new(),
        invalidated: BTreeSet::new(),
        eligible,
        timings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(root: Arc<File>) -> CgroupCollectRequest {
        CgroupCollectRequest {
            root,
            fence: CgroupFence::default().issue(),
            state: CgroupWalkState::default(),
            limits: CgroupWalkLimits::default(),
            control: CollectionControl::new(None),
            max_scan_pids: None,
            scan_budget: CaptureWorkBudget::new(crate::discovery::scan::ScanLimits {
                per_object_bytes: 8 << 20,
                total_bytes: 16 << 20,
            }),
        }
    }
    fn fixture(pid: u32) -> (tempfile::TempDir, Arc<File>) {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("cgroup.procs"), format!("{pid}\n")).unwrap();
        let Scope::Cgroup { dir, .. } = crate::scope::cgroup(fixture.path()).unwrap() else {
            unreachable!()
        };
        (fixture, dir)
    }
    fn policy() -> AdmissionPolicy {
        AdmissionPolicy::Inventory(crate::capacity::inventory_endpoint_budget(None).unwrap())
    }
    fn sampled(collection: &mut CgroupCollection, pid: u32) {
        collection.sample_end(&BTreeSet::from([pid]));
    }

    #[test]
    fn cgroup_live_member_is_retained_for_commit() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let (_fixture, root) = fixture(pid);
        let mut collection = collect(request(root), &[], &HookRegistry::default(), policy());
        assert_eq!(collection.member_pids().collect::<Vec<_>>(), vec![pid]);
        let original = collection.original_weak(pid).unwrap();
        assert!(
            collection.permit(pid).is_none(),
            "begin sample alone never authorizes admission"
        );
        sampled(&mut collection, pid);
        assert!(
            collection.permit(pid).is_some(),
            "stable held member needs fresh begin and final end"
        );
        assert!(original.upgrade().is_some());
        drop(collection.finish());
        assert!(
            original.upgrade().is_none(),
            "transaction completion releases original custody"
        );
    }

    #[test]
    fn empty_cgroup_is_empty_without_a_system_fallback() {
        let (fixture, root) = fixture(1);
        std::fs::write(fixture.path().join("cgroup.procs"), b"").unwrap();
        let mut collection = collect(request(root), &[], &HookRegistry::default(), policy());
        assert_eq!(collection.member_pids().count(), 0);
        collection.sample_end(&BTreeSet::new());
        let catalog = collection.catalog(&BTreeSet::new());
        assert_eq!(catalog.enumerated, 0);
        assert!(catalog.objects.is_empty());
        assert_eq!(collection.outcome(), ScopedCollectionOutcome::Complete);
    }

    #[test]
    fn root_rename_and_operator_path_replacement_cannot_retarget_samples() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let outer = tempfile::tempdir().unwrap();
        let path = outer.path().join("group");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("cgroup.procs"), format!("{pid}\n")).unwrap();
        let Scope::Cgroup { dir, .. } = crate::scope::cgroup(&path).unwrap() else {
            unreachable!()
        };
        std::fs::rename(&path, outer.path().join("retained")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("cgroup.procs"), b"").unwrap();
        let mut collection = collect(request(dir), &[], &HookRegistry::default(), policy());
        assert_eq!(collection.member_pids().collect::<Vec<_>>(), vec![pid]);
        sampled(&mut collection, pid);
        assert!(collection.permit(pid).is_some());
    }

    #[test]
    fn buffered_candidate_is_not_fresh_begin_authority() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let (fixture, root) = fixture(pid);
        let collection = collect_with(
            request(root),
            &[],
            &HookRegistry::default(),
            policy(),
            &mut |stage| {
                if stage == CollectionStage::Traversed {
                    std::fs::write(fixture.path().join("cgroup.procs"), b"").unwrap();
                }
            },
        );
        assert_eq!(collection.member_pids().count(), 0);
        assert_ne!(collection.outcome(), ScopedCollectionOutcome::Complete);
    }

    #[test]
    fn movement_before_commit_is_not_scope_absence_or_admission() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let (fixture, root) = fixture(pid);
        let mut collection = collect(request(root), &[], &HookRegistry::default(), policy());
        assert_eq!(collection.member_pids().count(), 1);
        std::fs::write(fixture.path().join("cgroup.procs"), b"").unwrap();
        sampled(&mut collection, pid);
        assert!(collection.permit(pid).is_none());
        assert_ne!(collection.outcome(), ScopedCollectionOutcome::Complete);
        assert!(
            collection.originals[&pid].original.still_the_same(),
            "leaf absence does not prove exit"
        );
    }

    #[test]
    fn replaced_leaf_cannot_reauthorize_the_retained_generation() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let (fixture, root) = fixture(1);
        std::fs::write(fixture.path().join("cgroup.procs"), b"").unwrap();
        let leaf = fixture.path().join("leaf");
        std::fs::create_dir(&leaf).unwrap();
        std::fs::write(leaf.join("cgroup.procs"), format!("{pid}\n")).unwrap();
        let mut collection = collect(request(root), &[], &HookRegistry::default(), policy());
        assert_eq!(collection.member_pids().count(), 1);
        std::fs::rename(&leaf, fixture.path().join("old")).unwrap();
        std::fs::create_dir(&leaf).unwrap();
        std::fs::write(leaf.join("cgroup.procs"), format!("{pid}\n")).unwrap();
        sampled(&mut collection, pid);
        assert!(collection.permit(pid).is_none());
        assert_ne!(collection.outcome(), ScopedCollectionOutcome::Complete);
    }

    #[test]
    fn an_exec_changes_image_under_the_same_original_process_pin() {
        let child = crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::with_command(
            "kill -STOP $$; exec /bin/sleep 30",
        );
        let pid = child.id();
        let (_fixture, root) = fixture(pid);
        let mut collection = collect(request(root), &[], &HookRegistry::default(), policy());
        let before = collection.originals[&pid].generation.clone();
        // SAFETY: this signal addresses only the retained owned child; Drop kills/reaps it.
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) }, 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while read_exe_identity(pid) == before.exe {
            assert!(
                std::time::Instant::now() < deadline,
                "owned child did not exec"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            collection.originals[&pid].original.still_the_same(),
            "exec preserves the process generation pin"
        );
        sampled(&mut collection, pid);
        assert!(collection.permit(pid).is_none());
        assert_eq!(
            collection.outcome(),
            ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::GenerationChanged)
        );
    }

    #[test]
    fn shared_work_is_not_reset_for_final_membership_and_commit() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let (_fixture, root) = fixture(pid);
        let limits = CgroupWalkLimits::default();
        let mut collection = collect(request(root), &[], &HookRegistry::default(), policy());
        let used = collection.work.budget.lock().unwrap().used.units;
        assert!(used > 0);
        assert!(collection.work.charge(limits.work_units - used));
        sampled(&mut collection, pid);
        assert!(collection.permit(pid).is_none());
        assert_eq!(
            collection.outcome(),
            ScopedCollectionOutcome::Incomplete(ScopedCollectionGap::Membership(
                CgroupIncomplete::WorkLimit
            ))
        );
    }

    #[test]
    fn operator_stop_after_traversal_interrupts_later_collection_stages() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let (_fixture, root) = fixture(child.id());
        let request = request(root);
        let control = request.control.clone();
        let collection = collect_with(
            request,
            &[],
            &HookRegistry::default(),
            policy(),
            &mut |stage| {
                if stage == CollectionStage::Traversed {
                    control.cancel();
                }
            },
        );
        assert_eq!(
            collection
                .collection
                .as_ref()
                .unwrap()
                .budget
                .attempted_io_bytes(),
            0
        );
        assert_eq!(
            collection.outcome(),
            ScopedCollectionOutcome::Cancelled(CollectionStop::OperatorStop)
        );
    }

    #[test]
    fn deadline_inside_deep_scan_cannot_produce_a_complete_receipt() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let (_fixture, root) = fixture(pid);
        let armed = Arc::new(AtomicBool::new(false));
        let checks = Arc::new(AtomicUsize::new(0));
        let clock_armed = armed.clone();
        let clock_checks = checks.clone();
        let now = std::time::Instant::now();
        let later = now + std::time::Duration::from_secs(1);
        let mut request = request(root);
        request.control = CollectionControl::with_clock(Some(later), move || {
            if clock_armed.load(Ordering::SeqCst)
                && clock_checks.fetch_add(1, Ordering::SeqCst) >= 3
            {
                later
            } else {
                now
            }
        });
        let collection = collect_with(
            request,
            &[],
            &HookRegistry::default(),
            policy(),
            &mut |stage| {
                if stage == CollectionStage::DeepScan {
                    armed.store(true, Ordering::SeqCst);
                }
            },
        );
        assert!(
            checks.load(Ordering::SeqCst) >= 4,
            "deadline was polled inside the real scanner, after the outer deep-scan check"
        );
        assert_eq!(
            collection.outcome(),
            ScopedCollectionOutcome::Cancelled(CollectionStop::Deadline)
        );
        assert!(
            collection
                .collection
                .as_ref()
                .unwrap()
                .members
                .iter()
                .all(|member| member.complete_scan.is_none())
        );
    }

    #[test]
    fn stop_before_confirmation_prevents_final_scope_authority() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let (_fixture, root) = fixture(pid);
        let request = request(root);
        let control = request.control.clone();
        let mut collection = collect_with(
            request,
            &[],
            &HookRegistry::default(),
            policy(),
            &mut |stage| {
                if stage == CollectionStage::Confirm {
                    control.cancel();
                }
            },
        );
        assert!(
            collection
                .collection
                .as_ref()
                .unwrap()
                .budget
                .attempted_io_bytes()
                > 0,
            "actual deep scan ran before the stop"
        );
        sampled(&mut collection, pid);
        assert!(collection.permit(pid).is_none());
        assert_eq!(
            collection.outcome(),
            ScopedCollectionOutcome::Cancelled(CollectionStop::OperatorStop)
        );
    }

    #[test]
    fn deadline_after_a_returning_sweep_read_stops_later_member_work() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let first =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let second =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let (_fixture, root) = fixture(first.id());
        std::fs::write(
            _fixture.path().join("cgroup.procs"),
            format!("{}\n{}\n", first.id(), second.id()),
        )
        .unwrap();
        let armed = Arc::new(AtomicBool::new(false));
        let returned = Arc::new(AtomicBool::new(false));
        let clock_returned = returned.clone();
        let now = std::time::Instant::now();
        let deadline = now + std::time::Duration::from_secs(1);
        let mut request = request(root);
        request.max_scan_pids = Some(1);
        request.control = CollectionControl::with_clock(Some(deadline), move || {
            if clock_returned.load(Ordering::SeqCst) {
                deadline
            } else {
                now
            }
        });
        let mut entered_sweep = false;
        let entered_deep = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let deep_reads = Arc::new(AtomicUsize::new(0));
        let read_armed = armed.clone();
        let read_returned = returned.clone();
        let read_stage = entered_deep.clone();
        let read_count = reads.clone();
        let deep_read_count = deep_reads.clone();
        let collection = crate::discovery::scan::maps_read_test::observe(
            move |bytes| {
                if bytes > 0 {
                    read_count.fetch_add(1, Ordering::SeqCst);
                    if read_stage.load(Ordering::SeqCst) {
                        deep_read_count.fetch_add(1, Ordering::SeqCst);
                    }
                    if read_armed.load(Ordering::SeqCst) {
                        read_returned.store(true, Ordering::SeqCst);
                    }
                }
            },
            || {
                collect_with(
                    request,
                    &[],
                    &HookRegistry::default(),
                    policy(),
                    &mut |stage| {
                        if stage == CollectionStage::Sweep {
                            entered_sweep = true;
                            armed.store(true, Ordering::SeqCst);
                        }
                        if stage == CollectionStage::DeepScan {
                            entered_deep.store(true, Ordering::SeqCst);
                        }
                    },
                )
            },
        );
        assert!(
            returned.load(Ordering::SeqCst),
            "an actual maps read returned"
        );
        assert!(entered_sweep);
        assert!(
            collection
                .collection
                .as_ref()
                .unwrap()
                .budget
                .attempted_io_bytes()
                > 0,
            "at least one real sweep maps read returned before the stop"
        );
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "no second member maps read after stop"
        );
        assert_eq!(
            deep_reads.load(Ordering::SeqCst),
            0,
            "no deep maps read after stop"
        );
        assert_eq!(
            collection.outcome(),
            ScopedCollectionOutcome::Cancelled(CollectionStop::Deadline)
        );
    }

    #[test]
    fn object_confirmation_stop_after_returning_metadata_blocks_next_check() {
        use std::os::unix::fs::MetadataExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct ReturningChecks {
            file: File,
            control: CollectionControl,
            reads: AtomicUsize,
        }
        impl ObjectChecks for ReturningChecks {
            fn nonunique_inodes(&self, _: PinnedObjectId) -> Result<Option<&'static str>, String> {
                Ok(None)
            }
            fn unchanged(&self, _: PinnedObjectId) -> Result<bool, String> {
                self.file.metadata().map_err(|error| error.to_string())?;
                self.reads.fetch_add(1, Ordering::SeqCst);
                self.control.cancel();
                Ok(true)
            }
            fn mapped_identity(
                &self,
                _: PinnedObjectId,
            ) -> Result<crate::discovery::identity::MappedFile, String> {
                let metadata = self.file.metadata().map_err(|error| error.to_string())?;
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(crate::discovery::identity::MappedFile {
                    identity: crate::discovery::identity::FileIdentity {
                        dev: metadata.dev(),
                        ino: metadata.ino(),
                    },
                    fs_magic: None,
                })
            }
        }
        let control = CollectionControl::new(None);
        let work = SharedCollectionWork::new(
            CgroupWalkLimits::default(),
            control.clone(),
            CgroupFence::default().issue(),
        );
        let checks = ReturningChecks {
            file: tempfile::tempfile().unwrap(),
            control,
            reads: AtomicUsize::new(0),
        };
        let controlled = ControlledObjectChecks {
            checks: &checks,
            work: &work,
        };
        assert_eq!(controlled.unchanged(PinnedObjectId(0)), Ok(true));
        assert!(controlled.mapped_identity(PinnedObjectId(0)).is_err());
        assert_eq!(checks.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            work.stopped(),
            Some(CollectionOutcome::Cancelled(CollectionStop::OperatorStop))
        );
    }

    #[test]
    fn stopped_prepared_collection_keeps_custody_but_never_authority() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let (_fixture, root) = fixture(pid);
        let request = request(root);
        let control = request.control.clone();
        let mut collection = collect(request, &[], &HookRegistry::default(), policy());
        let original = collection.original_weak(pid).unwrap();
        control.cancel();
        sampled(&mut collection, pid);
        assert!(original.upgrade().is_some());
        assert!(collection.permit(pid).is_none());
        assert_eq!(
            collection.outcome(),
            ScopedCollectionOutcome::Cancelled(CollectionStop::OperatorStop)
        );
        drop(collection);
        assert!(original.upgrade().is_none());
    }
}
