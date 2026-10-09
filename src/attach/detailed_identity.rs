//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private same-Session executable proof custody; disabled until trace wiring.

use super::{CapturePolicy, Scope, Session};
use crate::discovery::caller_registry::ExeIdentity;
use crate::events::{DiscoveryDomain, EventsDomain};
use crate::process::{ProcessViewId, ViewAdmission};
use crate::semantics::ProcessKey;
use p11scope_ebpf_common::{DiscoveryRecord, Event};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

const ENTRY_CAP: usize = 16384;
const PATH_CAP: usize = 8 * 1024 * 1024;
const IMAGE_PATH_CAP: usize = 4096;
const SAMPLE_WORK_BYTES: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TraceProofUnknown {
    NotSeeded,
    AfterEvent,
    ExecChanged,
    LifecycleLoss,
    DomainMismatch,
    NamespaceMismatch,
    TargetGone,
    Unreadable,
    ProofPending,
    Budget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SeedId(u64);

#[derive(Clone, Copy)]
enum CoveredScope {
    Pid(u32),
    System,
    Cgroup,
}

/// Parent-only initialization follows successful frozen scope/lifecycle activation.
#[derive(Clone, Copy)]
pub(super) struct TraceCoverage {
    scope: CoveredScope,
    started_ns: u64,
}
impl TraceCoverage {
    pub(super) fn after_activation(scope: &Scope, started_ns: Option<u64>) -> Option<Self> {
        Some(Self {
            scope: match scope {
                Scope::Pid(pid) => CoveredScope::Pid(*pid),
                Scope::System => CoveredScope::System,
                Scope::Cgroup { .. } => CoveredScope::Cgroup,
            },
            started_ns: started_ns?,
        })
    }
}

struct Authority {
    events: EventsDomain,
    discovery: DiscoveryDomain,
    coverage: TraceCoverage,
    numbering_agrees: bool,
    ledger: Mutex<ProofLedger>,
    #[cfg(test)]
    clock: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    clock_calls: std::sync::atomic::AtomicU64,
}
#[derive(Default)]
struct ProofLedger {
    entries: usize,
    path_bytes: usize,
    next_seed: u64,
    exhausted: bool,
    loss_epoch: u64,
    last_loss: Option<u64>,
    health: Option<(u64, u64)>,
    horizon: Option<u64>,
    pending: BTreeMap<SeedId, PendingSlot>,
    pids: BTreeMap<u32, SeedId>,
}

#[derive(Clone)]
pub(crate) struct ProofSession {
    authority: Arc<Authority>,
}

/// Non-Clone charge; retained through transfer, then returned once on drop.
pub(crate) struct EntryReservation {
    authority: Arc<Authority>,
    id: SeedId,
    bytes: usize,
    epoch: u64,
}
impl ProofSession {
    fn new(
        events: EventsDomain,
        discovery: DiscoveryDomain,
        coverage: TraceCoverage,
        numbering_agrees: bool,
    ) -> Self {
        Self {
            authority: Arc::new(Authority {
                events,
                discovery,
                coverage,
                numbering_agrees,
                ledger: Mutex::new(ProofLedger::default()),
                #[cfg(test)]
                clock: std::sync::atomic::AtomicU64::new(100),
                #[cfg(test)]
                clock_calls: std::sync::atomic::AtomicU64::new(0),
            }),
        }
    }
    fn ledger(&self) -> Result<MutexGuard<'_, ProofLedger>, TraceProofUnknown> {
        self.authority
            .ledger
            .lock()
            .map_err(|_| TraceProofUnknown::Unreadable)
    }
    pub(crate) fn reserve(&self, bytes: usize) -> Result<EntryReservation, TraceProofUnknown> {
        let mut ledger = self.ledger()?;
        if ledger.exhausted {
            return Err(TraceProofUnknown::LifecycleLoss);
        }
        let total = ledger
            .path_bytes
            .checked_add(bytes)
            .ok_or(TraceProofUnknown::Budget)?;
        if ledger.entries >= ENTRY_CAP || total > PATH_CAP {
            return Err(TraceProofUnknown::Budget);
        }
        let next = match ledger.next_seed.checked_add(1) {
            Some(next) if next != u64::MAX => next,
            _ => {
                ledger.exhausted = true;
                return Err(TraceProofUnknown::Budget);
            }
        };
        ledger.next_seed = next;
        ledger.entries += 1;
        ledger.path_bytes = total;
        Ok(EntryReservation {
            authority: self.authority.clone(),
            id: SeedId(next),
            bytes,
            epoch: ledger.loss_epoch,
        })
    }
    fn owns(&self, entry: &EntryReservation) -> bool {
        Arc::ptr_eq(&self.authority, &entry.authority)
    }
    #[cfg(test)]
    pub(crate) fn test_session() -> Self {
        Self::new(
            EventsDomain::test_standin(7),
            DiscoveryDomain::test_standin(8),
            TraceCoverage {
                scope: CoveredScope::System,
                started_ns: 1,
            },
            true,
        )
    }
    #[cfg(test)]
    pub(crate) fn usage(&self) -> (usize, usize) {
        let ledger = self
            .authority
            .ledger
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        (ledger.entries, ledger.path_bytes)
    }
}
impl EntryReservation {
    fn shrink(&mut self, bytes: usize) -> Result<(), TraceProofUnknown> {
        if bytes > self.bytes || bytes > IMAGE_PATH_CAP {
            return Err(TraceProofUnknown::Budget);
        }
        let mut ledger = self
            .authority
            .ledger
            .lock()
            .map_err(|_| TraceProofUnknown::Unreadable)?;
        ledger.path_bytes -= self.bytes - bytes;
        self.bytes = bytes;
        Ok(())
    }
}
impl Drop for EntryReservation {
    fn drop(&mut self) {
        // Poison denies all proof, but cannot strand bounded accounting on cleanup.
        let mut ledger = self
            .authority
            .ledger
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        ledger.remove(self.id);
        ledger.entries -= 1;
        ledger.path_bytes -= self.bytes;
    }
}

fn checked_cookie(
    has_original: bool,
    mut exited: impl FnMut() -> Result<bool, ()>,
    lookup: impl FnOnce() -> Result<Option<u64>, ()>,
) -> Result<u64, TraceProofUnknown> {
    if !has_original {
        return Err(TraceProofUnknown::Unreadable);
    }
    if exited().map_err(|_| TraceProofUnknown::Unreadable)? {
        return Err(TraceProofUnknown::TargetGone);
    }
    let cookie = lookup().map_err(|_| TraceProofUnknown::Unreadable)?;
    if exited().map_err(|_| TraceProofUnknown::Unreadable)? {
        return Err(TraceProofUnknown::TargetGone);
    }
    cookie
        .filter(|cookie| *cookie != 0)
        .ok_or(TraceProofUnknown::Unreadable)
}

#[derive(Clone, Copy)]
struct Witness {
    key: ProcessKey,
    event_ns: u64,
    copied_ns: u64,
}
struct PendingSlot {
    pid: u32,
    sample_start: u64,
    eligible_after: u64,
    epoch: u64,
    witness: Option<Witness>,
    armed: Option<u64>,
    problem: Option<TraceProofUnknown>,
}
struct SampleInterval {
    start: u64,
    completed: u64,
}
pub(crate) struct TraceSeed {
    identity: ExeIdentity,
    view: ProcessViewId,
    admission: ViewAdmission,
    sample_completed: u64,
    // Field drop order frees the sole path before returning its byte charge.
    entry: EntryReservation,
}
impl TraceSeed {
    pub(crate) fn id(&self) -> SeedId {
        self.entry.id
    }
    pub(crate) fn view_id(&self) -> ProcessViewId {
        self.view
    }
}
#[derive(Clone)]
pub(crate) struct ProofTap {
    proof: ProofSession,
}
impl ProofTap {
    pub(crate) fn matches_events(&self, domain: &EventsDomain) -> bool {
        self.proof.authority.events.same_allocation(domain)
    }
    pub(crate) fn matches_discovery(&self, domain: &DiscoveryDomain) -> bool {
        self.proof.authority.discovery.same_allocation(domain)
    }
    pub(crate) fn read_started(&self) -> Option<u64> {
        self.proof.now()
    }
    pub(crate) fn observe_call(&self, event: &Event) {
        if event.event_type == p11scope_ebpf_common::event_type::CALL {
            self.proof.call(
                (event.pid_tgid >> 32) as u32,
                event.ts_ns,
                event.image.task_cookie,
                event.image.exec_id,
                self.proof.now(),
            );
        }
    }
    pub(crate) fn observe_discovery(&self, record: &DiscoveryRecord) {
        match record.kind {
            p11scope_ebpf_common::DISCOVERY_KIND_EXEC => {
                self.proof
                    .lifecycle((record.pid_tgid >> 32) as u32, record.hook_ts_ns, true)
            }
            p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT => {
                self.proof
                    .lifecycle((record.pid_tgid >> 32) as u32, record.hook_ts_ns, false)
            }
            _ => {}
        }
    }
    pub(crate) fn observe_failure(&self) {
        if let Ok(mut ledger) = self.proof.ledger() {
            ledger.advance_epoch();
        }
    }
    pub(crate) fn observe_empty(&self, started: Option<u64>, complete: bool) {
        self.proof.empty(started, complete);
    }
}
impl ProofLedger {
    /// One scalar update, never a scan of pending entries at a cursor lock.
    fn advance_epoch(&mut self) {
        self.health = None;
        match self.loss_epoch.checked_add(1) {
            Some(epoch) if epoch != u64::MAX => self.loss_epoch = epoch,
            _ => self.exhausted = true,
        }
    }
    /// Record a completed counter observation independently of work allowance.
    fn observe_loss(
        &mut self,
        loss: Result<u64, TraceProofUnknown>,
    ) -> Result<u64, TraceProofUnknown> {
        if self.exhausted {
            return Err(TraceProofUnknown::LifecycleLoss);
        }
        let loss = match loss {
            Ok(loss) if loss != u64::MAX => loss,
            Ok(_) => {
                self.exhausted = true;
                self.health = None;
                return Err(TraceProofUnknown::LifecycleLoss);
            }
            Err(reason) => {
                self.advance_epoch();
                return Err(reason);
            }
        };
        if let Some(prior) = self.last_loss
            && loss != prior
        {
            self.advance_epoch();
            self.last_loss = Some(loss);
            if self.exhausted || loss < prior {
                return Err(TraceProofUnknown::LifecycleLoss);
            }
        }
        self.last_loss = Some(loss);
        Ok(self.loss_epoch)
    }
    fn slot_problem(&self, slot: &PendingSlot) -> Option<TraceProofUnknown> {
        if self.exhausted || slot.epoch != self.loss_epoch {
            Some(TraceProofUnknown::LifecycleLoss)
        } else {
            slot.problem
        }
    }
    fn remove(&mut self, id: SeedId) {
        if let Some(slot) = self.pending.remove(&id)
            && self.pids.get(&slot.pid) == Some(&id)
        {
            self.pids.remove(&slot.pid);
        }
    }
}
impl Drop for TraceSeed {
    fn drop(&mut self) {
        // Only fixed metadata is stored in the ledger. Unlock before entry drop.
        let mut ledger = self
            .entry
            .authority
            .ledger
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        ledger.remove(self.id());
    }
}
impl ProofSession {
    pub(crate) fn now(&self) -> Option<u64> {
        #[cfg(test)]
        {
            self.authority
                .clock_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let now = self
                .authority
                .clock
                .load(std::sync::atomic::Ordering::Relaxed);
            (now != u64::MAX).then_some(now)
        }
        #[cfg(not(test))]
        {
            super::monotonic_ns()
        }
    }
    pub(crate) fn same_allocation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
    }
    pub(crate) fn can_seed(
        &self,
        view: &crate::process::ProcessView,
    ) -> Result<(), TraceProofUnknown> {
        if !self.authority.numbering_agrees {
            return Err(TraceProofUnknown::NamespaceMismatch);
        }
        match self.authority.coverage.scope {
            CoveredScope::Cgroup => return Err(TraceProofUnknown::ProofPending),
            CoveredScope::Pid(pid) if pid != view.pid() => {
                return Err(TraceProofUnknown::ProofPending);
            }
            _ => {}
        }
        view.retained_pin()
            .pidfd()
            .map_err(|_| TraceProofUnknown::Unreadable)?;
        view.start_time().ok_or(TraceProofUnknown::Unreadable)?;
        let ledger = self.ledger()?;
        if ledger.exhausted {
            return Err(TraceProofUnknown::LifecycleLoss);
        }
        if ledger.pids.contains_key(&view.pid()) {
            return Err(TraceProofUnknown::ProofPending);
        }
        if ledger.entries >= ENTRY_CAP || ledger.path_bytes > PATH_CAP - SAMPLE_WORK_BYTES {
            return Err(TraceProofUnknown::Budget);
        }
        Ok(())
    }
    pub(crate) fn has_baseline(&self) -> bool {
        self.ledger()
            .is_ok_and(|ledger| !ledger.exhausted && ledger.health.is_some())
    }
    pub(crate) fn seed_status(
        &self,
        seed: &TraceSeed,
        view: &crate::process::ProcessView,
    ) -> Result<(bool, bool), TraceProofUnknown> {
        if !self.owns(&seed.entry)
            || view.id() != seed.view
            || !view.view_admission().same_allocation(&seed.admission)
        {
            return Err(TraceProofUnknown::TargetGone);
        }
        let ledger = self.ledger()?;
        let slot = ledger
            .pending
            .get(&seed.id())
            .ok_or(TraceProofUnknown::NotSeeded)?;
        if let Some(reason) = ledger.slot_problem(slot) {
            return Err(reason);
        }
        Ok((
            slot.witness.is_some() && slot.armed.is_none(),
            slot.armed
                .is_some_and(|armed| !ledger.health.is_some_and(|(start, _)| start > armed)),
        ))
    }
    pub(crate) fn confirm(
        &self,
        seed: &TraceSeed,
        view: &crate::process::ProcessView,
        cookie: u64,
    ) -> Result<(), TraceProofUnknown> {
        self.seed_status(seed, view)?;
        #[cfg(test)]
        let completed = Some(self.test_tick());
        #[cfg(not(test))]
        let completed = self.now();
        self.arm(
            seed,
            cookie,
            completed.ok_or(TraceProofUnknown::Unreadable)?,
        )
    }
    /// Final receipt construction stays here, and rechecks the ledger atomically.
    pub(crate) fn verified(
        &self,
        seed: TraceSeed,
        view: &crate::process::ProcessView,
    ) -> Result<VerifiedTraceSeed, TraceProofUnknown> {
        self.seed_status(&seed, view)?;
        let key = {
            let mut ledger = self.ledger()?;
            let slot = ledger
                .pending
                .get(&seed.id())
                .ok_or(TraceProofUnknown::NotSeeded)?;
            if let Some(reason) = ledger.slot_problem(slot) {
                return Err(reason);
            }
            let (Some(witness), Some(armed)) = (slot.witness, slot.armed) else {
                return Err(TraceProofUnknown::ProofPending);
            };
            if !ledger.health.is_some_and(|(start, _)| start > armed)
                || !ledger.horizon.is_some_and(|start| start > armed)
            {
                return Err(TraceProofUnknown::ProofPending);
            }
            let key = witness.key;
            ledger.remove(seed.id());
            key
        };
        Ok(VerifiedTraceSeed { seed, key })
    }
    pub(crate) fn ready_to_transfer(&self, seed: &TraceSeed) -> Result<bool, TraceProofUnknown> {
        self.ready(seed).map(|key| key.is_some())
    }
    fn register(
        &self,
        entry: EntryReservation,
        pid: u32,
        view: ProcessViewId,
        admission: ViewAdmission,
        identity: ExeIdentity,
        interval: SampleInterval,
    ) -> Result<TraceSeed, TraceProofUnknown> {
        let SampleInterval { start, completed } = interval;
        if !self.owns(&entry) {
            return Err(TraceProofUnknown::DomainMismatch);
        }
        if !self.authority.numbering_agrees {
            return Err(TraceProofUnknown::NamespaceMismatch);
        }
        match self.authority.coverage.scope {
            CoveredScope::Cgroup => return Err(TraceProofUnknown::ProofPending),
            CoveredScope::Pid(selected) if selected != pid => {
                return Err(TraceProofUnknown::ProofPending);
            }
            _ => {}
        }
        if start < self.authority.coverage.started_ns || completed < start {
            return Err(TraceProofUnknown::Unreadable);
        }
        let path = identity
            .path
            .as_deref()
            .filter(|path| !path.is_empty())
            .ok_or(TraceProofUnknown::Unreadable)?;
        if path.len() > IMAGE_PATH_CAP || path.len() != entry.bytes {
            return Err(TraceProofUnknown::Budget);
        }
        {
            let mut ledger = self.ledger()?;
            if ledger.exhausted || entry.epoch != ledger.loss_epoch {
                return Err(TraceProofUnknown::LifecycleLoss);
            }
            let (_, baseline_end) = ledger.health.ok_or(TraceProofUnknown::Unreadable)?;
            if start <= baseline_end {
                return Err(TraceProofUnknown::ProofPending);
            }
            if ledger.pids.get(&pid).is_some_and(|id| *id != entry.id) {
                return Err(TraceProofUnknown::ProofPending);
            }
            let epoch = ledger.loss_epoch;
            if let Some(slot) = ledger.pending.get_mut(&entry.id) {
                if let Some(reason) = slot.problem {
                    return Err(reason);
                }
                slot.eligible_after = completed.max(self.authority.coverage.started_ns);
            } else {
                ledger.pending.insert(
                    entry.id,
                    PendingSlot {
                        pid,
                        sample_start: start,
                        eligible_after: completed.max(self.authority.coverage.started_ns),
                        epoch,
                        witness: None,
                        armed: None,
                        problem: None,
                    },
                );
            }
            ledger.pids.insert(pid, entry.id);
        }
        Ok(TraceSeed {
            entry,
            identity,
            view,
            admission,
            sample_completed: completed,
        })
    }
    #[cfg(test)]
    fn health(
        &self,
        loss: Result<u64, TraceProofUnknown>,
        start: Option<u64>,
        completed: Option<u64>,
    ) -> Result<(), TraceProofUnknown> {
        let mut ledger = self.ledger()?;
        let epoch = ledger.observe_loss(loss)?;
        Self::complete_health(&mut ledger, epoch, start, completed)
    }
    fn complete_health(
        ledger: &mut ProofLedger,
        observed_epoch: u64,
        start: Option<u64>,
        completed: Option<u64>,
    ) -> Result<(), TraceProofUnknown> {
        if ledger.exhausted || ledger.loss_epoch != observed_epoch {
            return Err(TraceProofUnknown::LifecycleLoss);
        }
        let (Some(start), Some(completed)) = (start, completed) else {
            ledger.advance_epoch();
            return Err(TraceProofUnknown::Unreadable);
        };
        if completed < start {
            ledger.exhausted = true;
            ledger.health = None;
            return Err(TraceProofUnknown::Unreadable);
        }
        ledger.health = Some((start, completed));
        Ok(())
    }
    fn call(&self, pid: u32, timestamp: u64, cookie: u64, exec: u64, copied: Option<u64>) {
        let Ok(mut ledger) = self.ledger() else {
            return;
        };
        let Some(id) = ledger.pids.get(&pid).copied() else {
            return;
        };
        let Some(slot) = ledger.pending.get_mut(&id) else {
            return;
        };
        if timestamp <= slot.eligible_after || slot.problem.is_some() {
            return;
        }
        let Some(copied) = copied.filter(|copied| *copied >= timestamp) else {
            slot.problem = Some(TraceProofUnknown::Unreadable);
            return;
        };
        if cookie == 0 {
            slot.problem = Some(TraceProofUnknown::Unreadable);
            return;
        }
        let key = ProcessKey::history(self.authority.events.id(), cookie, exec, pid);
        if let Some(witness) = slot.witness {
            if witness.key.generation != cookie {
                slot.problem = Some(TraceProofUnknown::DomainMismatch);
            } else if witness.key.exec_id != exec {
                slot.problem = Some(TraceProofUnknown::ExecChanged);
            }
        } else {
            slot.witness = Some(Witness {
                key,
                event_ns: timestamp,
                copied_ns: copied,
            });
        }
    }
    fn lifecycle(&self, pid: u32, timestamp: u64, exec: bool) {
        let Ok(mut ledger) = self.ledger() else {
            return;
        };
        let Some(id) = ledger.pids.get(&pid).copied() else {
            return;
        };
        let Some(slot) = ledger.pending.get_mut(&id) else {
            return;
        };
        if timestamp >= slot.sample_start && slot.problem.is_none() {
            slot.problem = Some(if exec {
                TraceProofUnknown::ExecChanged
            } else {
                TraceProofUnknown::TargetGone
            });
        }
    }
    fn empty(&self, start: Option<u64>, complete: bool) {
        if !complete {
            return;
        }
        let Ok(mut ledger) = self.ledger() else {
            return;
        };
        match start {
            Some(start) => {
                ledger.horizon = Some(ledger.horizon.map_or(start, |prior| prior.max(start)))
            }
            None => ledger.advance_epoch(),
        }
    }
    fn ready(&self, seed: &TraceSeed) -> Result<Option<ProcessKey>, TraceProofUnknown> {
        if !self.owns(&seed.entry) {
            return Err(TraceProofUnknown::DomainMismatch);
        }
        let ledger = self.ledger()?;
        let slot = ledger
            .pending
            .get(&seed.id())
            .ok_or(TraceProofUnknown::NotSeeded)?;
        if let Some(reason) = ledger.slot_problem(slot) {
            return Err(reason);
        }
        let (Some(witness), Some(armed)) = (slot.witness, slot.armed) else {
            return Ok(None);
        };
        let covering_health = ledger.health.is_some_and(|(start, _)| start > armed);
        let covering_drain = ledger.horizon.is_some_and(|start| start > armed);
        Ok((covering_health && covering_drain).then_some(witness.key))
    }
    fn arm(&self, seed: &TraceSeed, cookie: u64, completed: u64) -> Result<(), TraceProofUnknown> {
        if !self.owns(&seed.entry) {
            return Err(TraceProofUnknown::DomainMismatch);
        }
        let mut ledger = self.ledger()?;
        let slot = ledger
            .pending
            .get(&seed.id())
            .ok_or(TraceProofUnknown::NotSeeded)?;
        if let Some(reason) = ledger.slot_problem(slot) {
            return Err(reason);
        }
        let slot = ledger
            .pending
            .get_mut(&seed.id())
            .ok_or(TraceProofUnknown::NotSeeded)?;
        if slot.armed.is_some() {
            return Ok(());
        }
        let witness = slot.witness.ok_or(TraceProofUnknown::ProofPending)?;
        if witness.event_ns <= slot.eligible_after {
            slot.problem = Some(TraceProofUnknown::AfterEvent);
            return Err(TraceProofUnknown::AfterEvent);
        }
        if cookie == 0 || cookie != witness.key.generation {
            slot.problem = Some(TraceProofUnknown::DomainMismatch);
            return Err(TraceProofUnknown::DomainMismatch);
        }
        if completed < witness.copied_ns {
            slot.problem = Some(TraceProofUnknown::Unreadable);
            return Err(TraceProofUnknown::Unreadable);
        }
        slot.armed = Some(completed.max(witness.copied_ns));
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn test_pending(&self, pid: u32, start: u64, completed: u64) -> TraceSeed {
        self.health(Ok(0), Some(7), Some(8))
            .expect("finite pre-sample baseline");
        let mut entry = self.reserve(SAMPLE_WORK_BYTES).unwrap();
        entry.shrink(14).unwrap();
        self.register(
            entry,
            pid,
            ProcessViewId(0),
            ViewAdmission::test_new(),
            ExeIdentity {
                dev: 1,
                ino: 2,
                mtime_secs: 3,
                mtime_nanos: 4,
                path: Some("/owned/fixture".into()),
            },
            SampleInterval { start, completed },
        )
        .expect("stable original sample registers")
    }
    #[cfg(test)]
    pub(crate) fn test_events_domain(&self) -> EventsDomain {
        self.authority.events.clone()
    }
    #[cfg(test)]
    pub(crate) fn test_discovery_domain(&self) -> DiscoveryDomain {
        self.authority.discovery.clone()
    }
    #[cfg(test)]
    pub(crate) fn test_events_tap(&self) -> ProofTap {
        ProofTap {
            proof: self.clone(),
        }
    }
    #[cfg(test)]
    pub(crate) fn test_discovery_tap(&self) -> ProofTap {
        ProofTap {
            proof: self.clone(),
        }
    }
    #[cfg(test)]
    pub(crate) fn test_witness(&self, id: SeedId) -> Option<(u64, u64, u64)> {
        self.ledger()
            .unwrap()
            .pending
            .get(&id)?
            .witness
            .map(|w| (w.key.generation, w.key.exec_id, w.event_ns))
    }
    #[cfg(test)]
    pub(crate) fn test_problem(&self, id: SeedId) -> Option<TraceProofUnknown> {
        let ledger = self.ledger().unwrap();
        ledger.slot_problem(ledger.pending.get(&id)?)
    }
    #[cfg(test)]
    pub(crate) fn test_horizon(&self) -> Option<u64> {
        self.ledger().unwrap().horizon
    }
    #[cfg(test)]
    pub(crate) fn test_epoch(&self) -> u64 {
        self.ledger().unwrap().loss_epoch
    }
    #[cfg(test)]
    fn test_call(&self, pid: u32, ts: u64, cookie: u64, exec: u64, read: u64) {
        self.call(pid, ts, cookie, exec, Some(read));
    }
    #[cfg(test)]
    fn test_exec(&self, pid: u32, ts: u64) {
        self.lifecycle(pid, ts, true);
    }
    #[cfg(test)]
    fn test_health(
        &self,
        loss: Result<u64, TraceProofUnknown>,
        start: u64,
        end: u64,
    ) -> Result<(), TraceProofUnknown> {
        self.health(loss, Some(start), Some(end))
    }
    #[cfg(test)]
    fn test_empty(&self, start: u64) {
        self.empty(Some(start), true);
    }
    #[cfg(test)]
    fn test_arm(&self, seed: &TraceSeed, cookie: u64, end: u64) -> Result<(), TraceProofUnknown> {
        self.arm(seed, cookie, end)
    }
    #[cfg(test)]
    fn settle(&self, seed: &TraceSeed) -> Result<Option<ProcessKey>, TraceProofUnknown> {
        self.ready(seed)
    }
}

impl Session {
    pub(crate) fn enable_trace_proof(&mut self) -> Result<(), TraceProofUnknown> {
        if self.trace_proof.is_some() {
            return Ok(());
        }
        if !matches!(
            self.policy,
            CapturePolicy::Allowlisted | CapturePolicy::UnsafeUnvalidatedMetadata
        ) {
            return Err(TraceProofUnknown::Unreadable);
        }
        let coverage = self.trace_coverage.ok_or(TraceProofUnknown::Unreadable)?;
        self.trace_proof = Some(ProofSession::new(
            self.events_domain.clone(),
            self.discovery_domain.clone(),
            coverage,
            crate::pidns::numbering().agrees(),
        ));
        self.wire_trace_consumers()?;
        Ok(())
    }
    pub(crate) fn trace_proof(&self) -> Option<&ProofSession> {
        self.trace_proof.as_ref()
    }
    pub(super) fn wire_trace_consumers(&mut self) -> Result<(), TraceProofUnknown> {
        if let Some(proof) = &self.trace_proof {
            if let Some(drain) = &mut self.events_consumer {
                drain.attach_trace_tap(ProofTap {
                    proof: proof.clone(),
                })?;
            }
            if let Some(drain) = &mut self.discovery_consumer {
                drain.attach_trace_tap(ProofTap {
                    proof: proof.clone(),
                })?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TraceWorkError {
    Deferred,
    Unknown(TraceProofUnknown),
}
impl From<TraceProofUnknown> for TraceWorkError {
    fn from(reason: TraceProofUnknown) -> Self {
        Self::Unknown(reason)
    }
}
pub(crate) use crate::discovery::engine::TraceWorkTicket;

pub(crate) struct VerifiedTraceSeed {
    seed: TraceSeed,
    key: ProcessKey,
}
impl VerifiedTraceSeed {
    pub(crate) fn key(&self) -> ProcessKey {
        self.key
    }
    pub(crate) fn path(&self) -> &str {
        self.seed.identity.path.as_deref().unwrap_or("")
    }
    pub(crate) fn eligible_after_ns(&self) -> u64 {
        self.seed
            .sample_completed
            .max(self.seed.entry.authority.coverage.started_ns)
    }
    pub(crate) fn identity(&self) -> &ExeIdentity {
        &self.seed.identity
    }
}
#[derive(Default, Debug)]
pub(crate) struct TraceServiceProgress {
    pub(crate) visited: u32,
    pub(crate) seeded: u32,
    pub(crate) transferred: u32,
    pub(crate) deferred: u32,
}

/// Production Session only; private scripted I/O feeds the same decisions in tests.
pub(crate) trait TraceIo {
    fn proof(&self) -> Option<&ProofSession>;
    fn cookie(
        &self,
        pin: &crate::process::PidPin,
        work: &mut TraceWorkTicket,
    ) -> Result<u64, TraceWorkError>;
    fn refresh_health(&self, work: &mut TraceWorkTicket) -> Result<(), TraceWorkError>;
    fn sample(
        &self,
        view: &crate::process::ProcessView,
        work: &mut TraceWorkTicket,
    ) -> Result<TraceSeed, TraceWorkError>;
}
impl TraceIo for Session {
    fn proof(&self) -> Option<&ProofSession> {
        self.trace_proof()
    }
    fn cookie(
        &self,
        pin: &crate::process::PidPin,
        work: &mut TraceWorkTicket,
    ) -> Result<u64, TraceWorkError> {
        self.trace_cookie(pin, work)
    }
    fn refresh_health(&self, work: &mut TraceWorkTicket) -> Result<(), TraceWorkError> {
        self.refresh_trace_health(work)
    }
    fn sample(
        &self,
        view: &crate::process::ProcessView,
        work: &mut TraceWorkTicket,
    ) -> Result<TraceSeed, TraceWorkError> {
        let proof = self.trace_proof().ok_or(TraceProofUnknown::Unreadable)?;
        proof.sample_from(view, work, &mut OsSample { view })
    }
}
impl ProofSession {
    #[cfg(test)]
    pub(crate) fn test_stage_once<S: crate::events::BoundedRecordSource>(
        drain: &mut crate::events::DiscoveryDrain<S>,
    ) -> Vec<crate::events::DiscoveryItem> {
        let mut stage = super::DiscoveryStage::default();
        stage.stage(1, || drain.dequeue());
        stage.take()
    }
    #[cfg(test)]
    pub(crate) fn test_scope(scope: &Scope, numbering_agrees: bool) -> Self {
        Self::new(
            EventsDomain::test_standin(7),
            DiscoveryDomain::test_standin(8),
            TraceCoverage::after_activation(scope, Some(1)).unwrap(),
            numbering_agrees,
        )
    }
    #[cfg(test)]
    pub(crate) fn test_time(&self) -> u64 {
        self.authority
            .clock
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    pub(crate) fn test_clock_calls(&self) -> u64 {
        self.authority
            .clock_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    pub(crate) fn test_set_time(&self, time: u64) {
        self.authority
            .clock
            .store(time, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(test)]
    pub(crate) fn test_tick(&self) -> u64 {
        self.authority
            .clock
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1
    }
    #[cfg(test)]
    pub(crate) fn test_sample_view(
        &self,
        view: &crate::process::ProcessView,
        work: &mut TraceWorkTicket,
    ) -> Result<TraceSeed, TraceWorkError> {
        self.sample_from(
            view,
            work,
            &mut FixtureSample {
                view,
                proof: self,
                link: b"/owned/fixture",
                after_first_link: None,
            },
        )
    }
    #[cfg(test)]
    pub(crate) fn test_refresh_read(
        &self,
        work: &mut TraceWorkTicket,
        loss: Result<u64, TraceProofUnknown>,
    ) -> Result<(), TraceWorkError> {
        self.health_from(work, || loss)
    }
    #[cfg(test)]
    pub(crate) fn test_refresh_read_after(
        &self,
        work: &mut TraceWorkTicket,
        loss: Result<u64, TraceProofUnknown>,
        after: impl FnOnce(),
    ) -> Result<(), TraceWorkError> {
        self.health_from(work, || {
            after();
            loss
        })
    }
    #[cfg(test)]
    pub(crate) fn test_health_interval(&self) -> Option<(u64, u64)> {
        self.ledger().unwrap().health
    }
    #[cfg(test)]
    pub(crate) fn test_cookie_read_after(
        &self,
        pin: &crate::process::PidPin,
        work: &mut TraceWorkTicket,
        cookie: Option<u64>,
        after: impl FnOnce(),
    ) -> Result<u64, TraceWorkError> {
        self.cookie_from(pin, work, || {
            after();
            Ok(cookie)
        })
    }
    #[cfg(test)]
    pub(crate) fn test_sample_view_after_link(
        &self,
        view: &crate::process::ProcessView,
        work: &mut TraceWorkTicket,
        after: &mut dyn FnMut(),
    ) -> Result<TraceSeed, TraceWorkError> {
        self.sample_from(
            view,
            work,
            &mut FixtureSample {
                view,
                proof: self,
                link: b"/owned/fixture",
                after_first_link: Some(after),
            },
        )
    }
    #[cfg(test)]
    pub(crate) fn test_cookie_read(
        &self,
        pin: &crate::process::PidPin,
        work: &mut TraceWorkTicket,
        cookie: Option<u64>,
    ) -> Result<u64, TraceWorkError> {
        self.cookie_from(pin, work, || Ok(cookie))
    }
}

impl Session {
    pub(crate) fn trace_cookie(
        &self,
        pin: &crate::process::PidPin,
        work: &mut TraceWorkTicket,
    ) -> Result<u64, TraceWorkError> {
        let proof = self.trace_proof().ok_or(TraceProofUnknown::Unreadable)?;
        proof.cookie_from(pin, work, || {
            self.instance_maps()
                .cookie(pin.pidfd().map_err(|_| TraceProofUnknown::Unreadable)?)
                .map_err(|_| TraceProofUnknown::Unreadable)
        })
    }
    pub(crate) fn refresh_trace_health(
        &self,
        work: &mut TraceWorkTicket,
    ) -> Result<(), TraceWorkError> {
        let proof = self.trace_proof().ok_or(TraceProofUnknown::Unreadable)?;
        proof.health_from(work, || {
            let map = self
                .ebpf
                .map("COUNTERS")
                .ok_or(TraceProofUnknown::Unreadable)?;
            let counters: aya::maps::PerCpuArray<_, u64> =
                aya::maps::PerCpuArray::try_from(map).map_err(|_| TraceProofUnknown::Unreadable)?;
            let values = counters
                .get(&p11scope_ebpf_common::DISCOVERY_COUNTER_RING_LOSS, 0)
                .map_err(|_| TraceProofUnknown::Unreadable)?;
            // MAX is also unusable: it cannot distinguish an exact sum from saturation.
            Ok(values
                .iter()
                .copied()
                .try_fold(0u64, |total, n| total.checked_add(n))
                .unwrap_or(u64::MAX))
        })
    }
}
impl ProofSession {
    fn cookie_from(
        &self,
        pin: &crate::process::PidPin,
        work: &mut TraceWorkTicket,
        read: impl FnOnce() -> Result<Option<u64>, TraceProofUnknown>,
    ) -> Result<u64, TraceWorkError> {
        pin.pidfd().map_err(|_| TraceProofUnknown::Unreadable)?;
        work.external_read(self)?;
        let before = pin
            .original_exited()
            .map_err(|_| TraceProofUnknown::Unreadable)?;
        if before {
            return Err(TraceProofUnknown::TargetGone.into());
        }
        work.external_read(self)?;
        let cookie = read()?;
        work.external_read(self)?;
        let after = pin
            .original_exited()
            .map_err(|_| TraceProofUnknown::Unreadable)?;
        // Use the same finite cookie decision tested by the original-pin fixture.
        let mut checks = 0;
        checked_cookie(
            true,
            || {
                checks += 1;
                Ok(if checks == 1 { before } else { after })
            },
            || Ok(cookie),
        )
        .map_err(Into::into)
    }
    fn health_from(
        &self,
        work: &mut TraceWorkTicket,
        read: impl FnOnce() -> Result<u64, TraceProofUnknown>,
    ) -> Result<(), TraceWorkError> {
        work.claim_health(self)?;
        #[cfg(test)]
        let start = Some(self.test_tick());
        #[cfg(not(test))]
        let start = self.now();
        work.external_read(self)?;
        let loss = read();
        #[cfg(test)]
        let completed = Some(self.test_tick());
        #[cfg(not(test))]
        let completed = self.now();
        // Any completed loss observation is evidence, even if this one read
        // exhausted the ticket. Publish a horizon only after the allowance check.
        let observation = self.ledger()?.observe_loss(loss);
        if loss.is_err() || loss == Ok(u64::MAX) {
            return observation.map(|_| ()).map_err(Into::into);
        }
        work.check(self)?;
        let epoch = observation?;
        let mut ledger = self.ledger()?;
        Self::complete_health(&mut ledger, epoch, start, completed).map_err(Into::into)
    }
    fn sample_from(
        &self,
        view: &crate::process::ProcessView,
        work: &mut TraceWorkTicket,
        source: &mut impl SampleSource,
    ) -> Result<TraceSeed, TraceWorkError> {
        self.can_seed(view)?;
        work.check(self)?;
        // Scratch, the single output path, and one slot are charged before any read.
        let mut entry = self.reserve(SAMPLE_WORK_BYTES)?;
        #[cfg(test)]
        let start = Some(self.test_tick());
        #[cfg(not(test))]
        let start = self.now();
        let start = start.ok_or(TraceProofUnknown::Unreadable)?;
        if start < self.authority.coverage.started_ns {
            return Err(TraceProofUnknown::Unreadable.into());
        }
        {
            // A cursor can invalidate the in-flight interval without owning scratch.
            let mut ledger = self.ledger()?;
            if ledger.exhausted || entry.epoch != ledger.loss_epoch {
                return Err(TraceProofUnknown::LifecycleLoss.into());
            }
            let (_, baseline_end) = ledger.health.ok_or(TraceProofUnknown::Unreadable)?;
            if start <= baseline_end {
                return Err(TraceProofUnknown::ProofPending.into());
            }
            if ledger.pids.contains_key(&view.pid()) {
                return Err(TraceProofUnknown::ProofPending.into());
            }
            let epoch = ledger.loss_epoch;
            ledger.pending.insert(
                entry.id,
                PendingSlot {
                    pid: view.pid(),
                    sample_start: start,
                    eligible_after: u64::MAX,
                    epoch,
                    witness: None,
                    armed: None,
                    problem: None,
                },
            );
            ledger.pids.insert(view.pid(), entry.id);
        }
        let identity = sample_identity(self, view, work, source)?;
        #[cfg(test)]
        let completed = Some(self.test_tick());
        #[cfg(not(test))]
        let completed = self.now();
        work.check(self)?;
        let completed = completed.ok_or(TraceProofUnknown::Unreadable)?;
        // Both fixed link buffers and bounded stat scratch have left scope now.
        entry.shrink(
            identity
                .path
                .as_ref()
                .ok_or(TraceProofUnknown::Unreadable)?
                .len(),
        )?;
        self.register(
            entry,
            view.pid(),
            view.id(),
            view.view_admission(),
            identity,
            SampleInterval { start, completed },
        )
        .map_err(Into::into)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ExeStat {
    dev: u64,
    ino: u64,
    mtime_secs: i64,
    mtime_nanos: i64,
}
/// This seam supplies reads, never a caller-selected success receipt.
trait SampleSource {
    fn exited(&mut self) -> Result<bool, TraceProofUnknown>;
    fn stat(&mut self) -> Result<ExeStat, TraceProofUnknown>;
    fn link(&mut self, buf: &mut [u8; IMAGE_PATH_CAP + 1]) -> Result<usize, TraceProofUnknown>;
    fn birth(
        &mut self,
        proof: &ProofSession,
        work: &mut TraceWorkTicket,
    ) -> Result<u64, TraceWorkError>;
    fn namespace(&mut self) -> Result<crate::process::MountNamespaceId, TraceProofUnknown>;
}
fn sample_identity(
    proof: &ProofSession,
    view: &crate::process::ProcessView,
    work: &mut TraceWorkTicket,
    source: &mut impl SampleSource,
) -> Result<ExeIdentity, TraceWorkError> {
    work.external_read(proof)?;
    if source.exited()? {
        return Err(TraceProofUnknown::TargetGone.into());
    }
    work.external_read(proof)?;
    let birth = source.birth(proof, work)?;
    if Some(birth) != view.start_time() {
        return Err(TraceProofUnknown::TargetGone.into());
    }
    work.external_read(proof)?;
    let namespace = source.namespace()?;
    if namespace != view.mount_namespace() {
        return Err(TraceProofUnknown::NamespaceMismatch.into());
    }
    work.external_read(proof)?;
    let before = source.stat()?;
    let mut first = [0u8; IMAGE_PATH_CAP + 1];
    work.external_read(proof)?;
    let first_len = source.link(&mut first)?;
    if first_len == 0 || first_len > IMAGE_PATH_CAP {
        return Err(TraceProofUnknown::Budget.into());
    }
    let mut last = [0u8; IMAGE_PATH_CAP + 1];
    work.external_read(proof)?;
    let last_len = source.link(&mut last)?;
    if last_len == 0 || last_len > IMAGE_PATH_CAP {
        return Err(TraceProofUnknown::Budget.into());
    }
    work.external_read(proof)?;
    if source.stat()? != before || first[..first_len] != last[..last_len] {
        return Err(TraceProofUnknown::ExecChanged.into());
    }
    work.external_read(proof)?;
    if source.namespace()? != namespace {
        return Err(TraceProofUnknown::NamespaceMismatch.into());
    }
    work.external_read(proof)?;
    if source.birth(proof, work)? != birth {
        return Err(TraceProofUnknown::TargetGone.into());
    }
    work.external_read(proof)?;
    if source.exited()? {
        return Err(TraceProofUnknown::TargetGone.into());
    }
    work.check(proof)?;
    // Count lossy UTF-8 expansion before allocating its sole owned String.
    let mut rest = &first[..first_len];
    let mut utf8_len = 0usize;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                utf8_len += text.len();
                break;
            }
            Err(error) => {
                utf8_len += error.valid_up_to() + 3;
                if utf8_len > IMAGE_PATH_CAP {
                    return Err(TraceProofUnknown::Budget.into());
                }
                let consumed = error.valid_up_to()
                    + error
                        .error_len()
                        .unwrap_or(rest.len() - error.valid_up_to());
                rest = &rest[consumed..];
            }
        }
    }
    if utf8_len > IMAGE_PATH_CAP {
        return Err(TraceProofUnknown::Budget.into());
    }
    // Allocate exactly once at the validated output size; lossy conversion's
    // usual growth strategy can retain excess capacity beyond its byte charge.
    let mut path = String::with_capacity(utf8_len);
    let mut rest = &first[..first_len];
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                path.push_str(text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                path.push_str(
                    std::str::from_utf8(&rest[..valid])
                        .map_err(|_| TraceProofUnknown::Unreadable)?,
                );
                path.push('\u{fffd}');
                let consumed = valid + error.error_len().unwrap_or(rest.len() - valid);
                rest = &rest[consumed..];
            }
        }
    }
    Ok(ExeIdentity {
        dev: before.dev,
        ino: before.ino,
        mtime_secs: before.mtime_secs,
        mtime_nanos: before.mtime_nanos,
        path: Some(path),
    })
}
struct OsSample<'a> {
    view: &'a crate::process::ProcessView,
}
impl SampleSource for OsSample<'_> {
    fn exited(&mut self) -> Result<bool, TraceProofUnknown> {
        self.view
            .retained_pin()
            .original_exited()
            .map_err(|_| TraceProofUnknown::Unreadable)
    }
    fn stat(&mut self) -> Result<ExeStat, TraceProofUnknown> {
        use std::os::unix::fs::MetadataExt as _;
        let m = std::fs::metadata(format!("/proc/{}/exe", self.view.pid()))
            .map_err(|_| TraceProofUnknown::Unreadable)?;
        Ok(ExeStat {
            dev: m.dev(),
            ino: m.ino(),
            mtime_secs: m.mtime(),
            mtime_nanos: m.mtime_nsec(),
        })
    }
    fn link(&mut self, buf: &mut [u8; IMAGE_PATH_CAP + 1]) -> Result<usize, TraceProofUnknown> {
        let name = std::ffi::CString::new(format!("/proc/{}/exe", self.view.pid()))
            .map_err(|_| TraceProofUnknown::Unreadable)?;
        // SAFETY: valid NUL-terminated path and writable, bounded fixed buffer.
        let n = unsafe { libc::readlink(name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(TraceProofUnknown::Unreadable)
        } else {
            Ok(n as usize)
        }
    }
    fn birth(
        &mut self,
        proof: &ProofSession,
        work: &mut TraceWorkTicket,
    ) -> Result<u64, TraceWorkError> {
        use std::io::Read as _;
        let mut file = std::fs::File::open(format!("/proc/{}/stat", self.view.pid()))
            .map_err(|_| TraceProofUnknown::Unreadable)?;
        let mut buf = [0u8; 4097];
        let mut len = 0;
        loop {
            work.external_read(proof)?;
            let n = file
                .read(&mut buf[len..])
                .map_err(|_| TraceProofUnknown::Unreadable)?;
            if n == 0 {
                break;
            }
            len += n;
            if len == buf.len() {
                return Err(TraceProofUnknown::Budget.into());
            }
        }
        let text = std::str::from_utf8(&buf[..len]).map_err(|_| TraceProofUnknown::Unreadable)?;
        let end = text.rfind(')').ok_or(TraceProofUnknown::Unreadable)?;
        // Field 3 follows the command; field 22 is its zero-based index 19.
        text[end + 1..]
            .split_whitespace()
            .nth(19)
            .and_then(|n| n.parse().ok())
            .ok_or(TraceProofUnknown::Unreadable.into())
    }
    fn namespace(&mut self) -> Result<crate::process::MountNamespaceId, TraceProofUnknown> {
        use std::os::unix::fs::MetadataExt as _;
        let m = std::fs::metadata(format!("/proc/{}/ns/mnt", self.view.pid()))
            .map_err(|_| TraceProofUnknown::Unreadable)?;
        Ok(crate::process::MountNamespaceId {
            device: m.dev(),
            inode: m.ino(),
        })
    }
}
#[cfg(test)]
struct FixtureSample<'a> {
    view: &'a crate::process::ProcessView,
    proof: &'a ProofSession,
    link: &'a [u8],
    after_first_link: Option<&'a mut dyn FnMut()>,
}
#[cfg(test)]
impl SampleSource for FixtureSample<'_> {
    fn exited(&mut self) -> Result<bool, TraceProofUnknown> {
        assert!(self.proof.usage().1 >= SAMPLE_WORK_BYTES);
        self.view
            .original_exited()
            .map_err(|_| TraceProofUnknown::Unreadable)
    }
    fn stat(&mut self) -> Result<ExeStat, TraceProofUnknown> {
        Ok(ExeStat {
            dev: 1,
            ino: 2,
            mtime_secs: 3,
            mtime_nanos: 4,
        })
    }
    fn link(&mut self, buf: &mut [u8; IMAGE_PATH_CAP + 1]) -> Result<usize, TraceProofUnknown> {
        let n = self.link.len().min(buf.len());
        buf[..n].copy_from_slice(&self.link[..n]);
        if let Some(after) = self.after_first_link.take() {
            after();
        }
        Ok(n)
    }
    fn birth(
        &mut self,
        _proof: &ProofSession,
        _work: &mut TraceWorkTicket,
    ) -> Result<u64, TraceWorkError> {
        self.view
            .start_time()
            .ok_or(TraceProofUnknown::Unreadable.into())
    }
    fn namespace(&mut self) -> Result<crate::process::MountNamespaceId, TraceProofUnknown> {
        Ok(self.view.mount_namespace())
    }
}

#[cfg(test)]
mod tests;
