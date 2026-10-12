//! SPDX-License-Identifier: GPL-3.0-or-later
//! Session-private physical pair facts. These facts cannot spare an Engine
//! replacement without an exact request-bound preservation receipt.

use super::{ProbeSide, RegisteredLink, RetainedStaticTarget, StaticEndpoint};
use crate::discovery::identity::{PinnedObjects, RetainedInventoryTarget};
use crate::events::DiscoveryDomain;
use crate::plan::Slot;
use p11scope_ebpf_common::{
    DISCOVERY_EXEC_SAME_TASK_CANDIDATE, DISCOVERY_EXEC_TASK_REPLACED, DISCOVERY_EXEC_UNKNOWN,
    DISCOVERY_KIND_EXEC, DISCOVERY_KIND_LEADER_EXIT, DiscoveryRecord,
};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PidContinuityRefusal {
    Domain,
    Time,
    Loss,
    Fault,
    Serial,
    Registration,
    Target,
    Terminal,
    Unavailable,
}

#[derive(Default)]
pub(super) struct OwnerHealth {
    last: Option<[u64; 4]>,
    last_loss: Option<u64>,
    terminal_poison: bool,
}
impl OwnerHealth {
    pub(super) fn terminal(&self) -> bool {
        self.terminal_poison
    }
    pub(super) fn check(
        &mut self,
        owner: Result<p11scope_ebpf_common::ThreadOwnerControl, PidContinuityRefusal>,
        loss: Result<u64, PidContinuityRefusal>,
        expected_limit: u64,
        tap: &PidLifecycleTap,
    ) -> Result<u64, PidContinuityRefusal> {
        let checked = (|| {
            if self.terminal_poison {
                return Err(PidContinuityRefusal::Terminal);
            }
            let owner = owner?;
            if owner.poison != 0 {
                self.terminal_poison = true;
                return Err(PidContinuityRefusal::Terminal);
            }
            if expected_limit == 0
                || expected_limit == u64::MAX
                || owner.limit != expected_limit
                || owner.outstanding > owner.limit
            {
                return Err(PidContinuityRefusal::Unavailable);
            }
            let counters = [
                owner.admission_failures,
                owner.reclamation_failures,
                owner.abandoned_start,
                owner.abandoned_discovery,
            ];
            if counters.contains(&u64::MAX)
                || self.last.is_some_and(|previous| {
                    counters.iter().zip(previous).any(|(now, old)| *now < old)
                })
            {
                return Err(PidContinuityRefusal::Fault);
            }
            let loss = loss?;
            if loss == u64::MAX || self.last_loss.is_some_and(|previous| loss < previous) {
                return Err(PidContinuityRefusal::Loss);
            }
            if self.last.is_some_and(|previous| previous != counters)
                || self.last_loss.is_some_and(|previous| loss > previous)
            {
                tap.observe_failure();
            }
            self.last = Some(counters);
            self.last_loss = Some(loss);
            Ok(loss)
        })();
        if checked.is_err() {
            tap.observe_failure();
        }
        checked
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RegistrationId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AttachBaseline {
    pub(super) loss: u64,
    pub(super) fault: u64,
}

#[derive(Debug, Clone)]
pub(super) struct AttachRound {
    pub(super) slots: Vec<u32>,
    pub(super) started_ns: Option<u64>,
    pub(super) last_call_ns: Option<u64>,
}

/// The timestamp comes from immediately before the real native attach call,
/// including failed wide calls that subsequently bisect into kept leaves.
pub(super) struct NativeAttempt<T, E> {
    pub(super) started_ns: Option<u64>,
    pub(super) result: Result<T, E>,
}

impl<T, E> NativeAttempt<T, E> {
    pub(super) fn run(
        clock: impl FnOnce() -> Option<u64>,
        attach: impl FnOnce() -> Result<T, E>,
    ) -> Self {
        let started_ns = clock();
        Self {
            started_ns,
            result: attach(),
        }
    }

    pub(super) fn not_attempted(error: E) -> Self {
        Self {
            started_ns: None,
            result: Err(error),
        }
    }
}

#[derive(Default)]
pub(super) struct RoundClock {
    first: Option<u64>,
    last: Option<u64>,
    invalid: bool,
}

impl RoundClock {
    pub(super) fn observe_call(&mut self, started: Option<u64>) {
        let Some(started) = started.filter(|value| *value != 0) else {
            self.invalid = true;
            return;
        };
        if self.last.is_some_and(|previous| started < previous) {
            self.invalid = true;
        }
        self.first.get_or_insert(started);
        self.last = Some(started);
    }

    pub(super) fn finish(self, slots: Vec<u32>) -> AttachRound {
        AttachRound {
            slots,
            started_ns: self.first.filter(|_| !self.invalid),
            last_call_ns: self.last.filter(|_| !self.invalid),
        }
    }
}

#[derive(Debug)]
pub(super) struct PairStamp {
    pub(super) generation: u64,
    pub(super) slot: Slot,
    pub(super) target: RetainedInventoryTarget,
    pub(super) entry: RegistrationId,
    pub(super) return_: RegistrationId,
    pub(super) started_ns: u64,
    pub(super) completed_ns: u64,
    pub(super) baseline: AttachBaseline,
}

#[derive(Default)]
pub(super) struct PairBook {
    registration_serial: u64,
    generation_serial: u64,
    last_loss: Option<u64>,
    stamps: BTreeMap<u32, PairStamp>,
    exhausted: bool,
    gaps: PhysicalGaps,
}

impl PairBook {
    pub(super) fn register(&mut self) -> Option<RegistrationId> {
        if self.exhausted {
            return None;
        }
        let Some(next) = self
            .registration_serial
            .checked_add(1)
            .filter(|next| *next != u64::MAX)
        else {
            self.exhausted = true;
            self.stamps.clear();
            return None;
        };
        self.registration_serial = next;
        Some(RegistrationId(next))
    }

    pub(super) fn prepare_baseline(
        &mut self,
        loss: Result<u64, PidContinuityRefusal>,
        fault: Option<u64>,
    ) -> Option<AttachBaseline> {
        let loss = loss.ok().filter(|loss| *loss != u64::MAX)?;
        if self.last_loss.is_some_and(|previous| loss < previous) {
            return None;
        }
        self.last_loss = Some(loss);
        let fault = fault.filter(|fault| *fault != u64::MAX)?;
        (!self.exhausted).then_some(AttachBaseline { loss, fault })
    }

    pub(super) fn invalidate(&mut self, slots: &BTreeSet<u32>) {
        self.stamps.retain(|slot, _| !slots.contains(slot));
    }

    pub(super) fn gap_summary(&self) -> PhysicalGapSummary {
        self.gaps.summary
    }
    pub(super) fn begin_gap(
        &mut self,
        slots: &BTreeSet<u32>,
        start: Option<u64>,
        retained: &BTreeMap<u32, RetainedStaticTarget>,
    ) {
        self.gaps.begin(slots, start);
        for slot in slots {
            if !self.gaps.affected.contains(slot) {
                continue;
            }
            if let Some(target) = retained.get(slot).and_then(|target| {
                target
                    .held
                    .as_ref()
                    .map(|held| (target.slot.clone(), held.share()))
            }) {
                self.gaps.targets.entry(*slot).or_insert(target);
            } else {
                self.gaps.summary.unknown = true;
            }
        }
    }

    /// A failed pair keeps its old aggregate cookie inactive. A later retry
    /// may use a fresh cookie, but closes this episode only for the same held
    /// target and offset once its exact final pair seals. The current sealed
    /// pair supplies the approved descriptor, which may have been downgraded.
    pub(super) fn retarget_gap(&mut self, slots: &[Slot], objects: &PinnedObjects) {
        let remapped: Vec<_> = self
            .gaps
            .targets
            .iter()
            .filter_map(|(old, (original, held))| {
                slots
                    .iter()
                    .find(|candidate| {
                        original.file_offset == candidate.file_offset
                            && held.check_unchanged() == Ok(true)
                            && held.same_object_as(objects, candidate.object)
                    })
                    .map(|candidate| (*old, candidate.clone(), held.share()))
            })
            .collect();
        for (old, candidate, held) in remapped {
            self.gaps.affected.remove(&old);
            self.gaps.targets.remove(&old);
            self.gaps.affected.insert(candidate.index);
            self.gaps.targets.insert(candidate.index, (candidate, held));
        }
    }

    pub(super) fn invalidate_all(&mut self) {
        self.stamps.clear();
    }

    #[cfg(test)]
    pub(super) fn recorded_generation(&self, slot: u32) -> Option<u64> {
        self.stamps.get(&slot).map(|stamp| stamp.generation)
    }

    #[allow(clippy::too_many_arguments)] // One current registry and its retained facts, never a second registry.
    pub(super) fn seal(
        &mut self,
        rounds: &[AttachRound],
        baseline: Option<AttachBaseline>,
        fault_serial: Option<u64>,
        links: &[RegisteredLink],
        sides: &BTreeSet<StaticEndpoint>,
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        mut completed_at: impl FnMut() -> Option<u64>,
    ) {
        self.invalidate(
            &rounds
                .iter()
                .flat_map(|round| round.slots.iter().copied())
                .collect(),
        );
        let Some(baseline) = baseline.filter(|baseline| Some(baseline.fault) == fault_serial)
        else {
            if self.gaps.summary.open {
                self.gaps.summary.unknown = true;
            }
            return;
        };
        if self.exhausted {
            return;
        }
        for round in rounds {
            let Some(started_ns) = round.started_ns.filter(|start| *start != 0) else {
                if self.gaps.summary.open {
                    self.gaps.summary.unknown = true;
                }
                continue;
            };
            let Some(last_call_ns) = round.last_call_ns.filter(|last| *last >= started_ns) else {
                continue;
            };
            // Both concrete sides are already in the registry before this sample.
            let Some(completed_ns) =
                completed_at().filter(|end| *end > started_ns && *end >= last_call_ns)
            else {
                if self.gaps.summary.open {
                    self.gaps.summary.unknown = true;
                }
                continue;
            };
            let selected: BTreeSet<_> = round.slots.iter().copied().collect();
            if selected.is_empty() || selected.len() != round.slots.len() {
                continue;
            }
            let pairs: Option<Vec<_>> = selected
                .iter()
                .map(|slot| {
                    let target = retained.get(slot)?;
                    let held = target.held.as_ref()?;
                    if target.slot.index != *slot
                        || target.abi != held.abi()
                        || target.path != held.attach_path()
                        || held.check_unchanged() != Ok(true)
                    {
                        return None;
                    }
                    let (entry, return_) = current_pair(*slot, links, sides)?;
                    Some((*slot, target, entry, return_))
                })
                .collect();
            let Some(pairs) = pairs else {
                continue;
            };
            let Some(generation) = self
                .generation_serial
                .checked_add(1)
                .filter(|next| *next != u64::MAX)
            else {
                self.exhausted = true;
                self.stamps.clear();
                return;
            };
            self.generation_serial = generation;
            for (slot, target, entry, return_) in pairs {
                self.stamps.insert(
                    slot,
                    PairStamp {
                        generation,
                        slot: target.slot.clone(),
                        target: target.held.as_ref().expect("checked held target").share(),
                        entry,
                        return_,
                        started_ns,
                        completed_ns,
                        baseline,
                    },
                );
            }
        }
        self.gaps.complete(&self.stamps);
    }

    pub(super) fn stamp_for(
        &self,
        slot: &Slot,
        objects: &PinnedObjects,
        links: &[RegisteredLink],
        sides: &BTreeSet<StaticEndpoint>,
        retained: &BTreeMap<u32, RetainedStaticTarget>,
    ) -> Option<&PairStamp> {
        if self.exhausted {
            return None;
        }
        let stamp = self.stamps.get(&slot.index)?;
        let actual = retained.get(&slot.index)?;
        let held = actual.held.as_ref()?;
        let (entry, return_) = current_pair(slot.index, links, sides)?;
        (stamp.slot == *slot
            && actual.slot == *slot
            && actual.abi == held.abi()
            && actual.path == held.attach_path()
            && entry == stamp.entry
            && return_ == stamp.return_
            && stamp.target.check_unchanged() == Ok(true)
            && held.check_unchanged() == Ok(true)
            && stamp.target.same_object_as(objects, slot.object)
            && held.same_object_as(objects, slot.object))
        .then_some(stamp)
    }
}

pub(super) fn current_pair(
    slot: u32,
    links: &[RegisteredLink],
    sides: &BTreeSet<StaticEndpoint>,
) -> Option<(RegistrationId, RegistrationId)> {
    if !sides.contains(&(slot, ProbeSide::Entry)) || !sides.contains(&(slot, ProbeSide::Return)) {
        return None;
    }
    let mut entry = None;
    let mut return_ = None;
    for link in links.iter().filter(|link| link.slots().contains(&slot)) {
        let (program, registration) = match link {
            RegisteredLink::UProbe {
                program,
                registration,
                ..
            } => (*program, *registration),
            RegisteredLink::MultiUProbe {
                program,
                registration,
                fds,
                ..
            } => {
                if fds.is_empty() {
                    return None;
                }
                (*program, *registration)
            }
            _ => continue,
        };
        let Some(side) = super::static_probe_side(program) else {
            continue;
        };
        let registration = registration?;
        let stored = match side {
            ProbeSide::Entry => &mut entry,
            ProbeSide::Return => &mut return_,
        };
        if stored.replace(registration).is_some() {
            return None;
        }
    }
    let (entry, return_) = (entry?, return_?);
    (entry != return_).then_some((entry, return_))
}

pub(super) fn checked_discovery_loss(
    values: impl IntoIterator<Item = u64>,
) -> Result<u64, PidContinuityRefusal> {
    let mut seen = false;
    let loss = values.into_iter().try_fold(0u64, |sum, value| {
        seen = true;
        sum.checked_add(value)
            .filter(|sum| *sum != u64::MAX)
            .ok_or(PidContinuityRefusal::Loss)
    })?;
    seen.then_some(loss).ok_or(PidContinuityRefusal::Loss)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecClass {
    Unknown,
    SameTaskCandidate,
    TaskReplaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecObservation {
    pub(crate) pid: u32,
    pub(crate) class: ExecClass,
    pub(crate) hook_ts_ns: u64,
    pub(crate) observation_serial: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmptyRead {
    pub(crate) read_started_ns: u64,
    pub(crate) producer_position: usize,
    pub(crate) observation_serial: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct LifecycleFacts {
    pub(crate) latest_exec: Option<ExecObservation>,
    pub(crate) greatest_break_ns: Option<u64>,
    pub(crate) observation_serial: u64,
    pub(crate) fault_serial: u64,
    pub(crate) empty: Option<EmptyRead>,
}

#[derive(Default)]
struct LifecycleState {
    facts: LifecycleFacts,
    last_lifecycle_ns: Option<u64>,
    last_read_ns: Option<u64>,
    read_valid: bool,
    exhausted: bool,
    terminal: bool,
}

impl LifecycleState {
    fn fault(&mut self) {
        self.facts.empty = None;
        self.facts.latest_exec = None;
        match self
            .facts
            .fault_serial
            .checked_add(1)
            .filter(|serial| *serial != u64::MAX)
        {
            Some(serial) => self.facts.fault_serial = serial,
            None => self.exhausted = true,
        }
    }

    fn next_observation(&mut self) -> Option<u64> {
        let serial = self
            .facts
            .observation_serial
            .checked_add(1)
            .filter(|serial| *serial != u64::MAX);
        if let Some(serial) = serial {
            self.facts.observation_serial = serial;
        } else {
            self.exhausted = true;
            self.fault();
        }
        serial
    }
}

struct LifecycleObserver {
    pid: NonZeroU32,
    domain: DiscoveryDomain,
    state: Mutex<LifecycleState>,
    resample_read_clock: bool,
    #[cfg(test)]
    read_clocks: Mutex<std::collections::VecDeque<Option<u64>>>,
}

/// A clone observes the Session's existing raw cursor; it owns no consumer.
#[derive(Clone)]
pub(crate) struct PidLifecycleTap(Arc<LifecycleObserver>);

impl PidLifecycleTap {
    pub(super) fn new(pid: NonZeroU32, domain: DiscoveryDomain) -> Self {
        Self(Arc::new(LifecycleObserver {
            pid,
            domain,
            state: Mutex::new(LifecycleState::default()),
            resample_read_clock: true,
            #[cfg(test)]
            read_clocks: Mutex::new(std::collections::VecDeque::new()),
        }))
    }

    pub(crate) fn matches_domain(&self, domain: &DiscoveryDomain) -> bool {
        self.0.domain.same_allocation(domain)
    }

    pub(crate) fn same_observer(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    pub(super) fn facts(&self) -> Result<LifecycleFacts, PidContinuityRefusal> {
        let state = self
            .0
            .state
            .lock()
            .map_err(|_| PidContinuityRefusal::Unavailable)?;
        if state.terminal {
            return Err(PidContinuityRefusal::Terminal);
        }
        if state.exhausted {
            return Err(PidContinuityRefusal::Serial);
        }
        Ok(state.facts)
    }

    /// Clear the prior frontier even when the next result is BUSY or malformed.
    pub(crate) fn begin_read(&self, started_ns: Option<u64>) -> Option<u64> {
        // The raw cursor's generic clock is not an origin proof. Production
        // samples again only AFTER origin validation, immediately before read.
        #[cfg(test)]
        let started_ns = self
            .0
            .read_clocks
            .lock()
            .ok()
            .and_then(|mut clocks| clocks.pop_front())
            .unwrap_or(started_ns);
        let started_ns = if self.0.resample_read_clock {
            started_ns.and_then(|_| comparable_monotonic_ns())
        } else {
            started_ns.filter(|_| clock_origins_comparable())
        };
        let mut state = self.0.state.lock().ok()?;
        state.facts.empty = None;
        state.read_valid = false;
        if state.terminal || state.exhausted {
            return None;
        }
        let Some(started) = started_ns.filter(|time| {
            *time != 0 && state.last_read_ns.is_none_or(|previous| *time >= previous)
        }) else {
            state.fault();
            return None;
        };
        state.last_read_ns = Some(started);
        state.read_valid = true;
        Some(started)
    }

    pub(crate) fn observe_record(&self, record: &DiscoveryRecord) {
        let Ok(mut state) = self.0.state.lock() else {
            return;
        };
        state.facts.empty = None;
        if state.terminal || state.exhausted {
            return;
        }
        let Some(serial) = state.next_observation() else {
            return;
        };
        if (record.pid_tgid >> 32) as u32 != self.0.pid.get()
            || !matches!(
                record.kind,
                DISCOVERY_KIND_EXEC | DISCOVERY_KIND_LEADER_EXIT
            )
        {
            return;
        }
        let class = if record.kind == DISCOVERY_KIND_EXEC {
            match record.case_id {
                DISCOVERY_EXEC_UNKNOWN => Some(ExecClass::Unknown),
                DISCOVERY_EXEC_SAME_TASK_CANDIDATE => Some(ExecClass::SameTaskCandidate),
                DISCOVERY_EXEC_TASK_REPLACED => Some(ExecClass::TaskReplaced),
                _ => {
                    state.fault();
                    return;
                }
            }
        } else {
            None
        };
        let timestamp = record.hook_ts_ns;
        // Even an out-of-order breaking record cannot be hidden by a later EXEC.
        if class != Some(ExecClass::SameTaskCandidate) && timestamp != 0 {
            state.facts.greatest_break_ns = Some(
                state
                    .facts
                    .greatest_break_ns
                    .map_or(timestamp, |previous| previous.max(timestamp)),
            );
        }
        if timestamp == 0
            || state
                .last_lifecycle_ns
                .is_some_and(|previous| timestamp <= previous)
        {
            state.fault();
            return;
        }
        state.last_lifecycle_ns = Some(timestamp);
        if !state.read_valid {
            return;
        }
        state.facts.latest_exec = class.map(|class| ExecObservation {
            pid: self.0.pid.get(),
            class,
            hook_ts_ns: timestamp,
            observation_serial: serial,
        });
    }

    pub(crate) fn observe_malformed(&self) {
        let Ok(mut state) = self.0.state.lock() else {
            return;
        };
        if state.terminal || state.exhausted {
            return;
        }
        if state.next_observation().is_some() {
            state.fault();
        }
    }

    /// Construction, wiring and direct map-health failures have no raw record.
    pub(crate) fn observe_failure(&self) {
        if let Ok(mut state) = self.0.state.lock()
            && !state.terminal
            && !state.exhausted
        {
            state.fault();
        }
    }

    pub(crate) fn observe_empty(&self, started_ns: Option<u64>, producer: usize, consumer: usize) {
        let Ok(mut state) = self.0.state.lock() else {
            return;
        };
        state.facts.empty = None;
        if state.terminal || state.exhausted || !state.read_valid || producer != consumer {
            return;
        }
        if let Some(read_started_ns) = started_ns.filter(|time| Some(*time) == state.last_read_ns) {
            state.facts.empty = Some(EmptyRead {
                read_started_ns,
                producer_position: producer,
                observation_serial: state.facts.observation_serial,
            });
        }
    }

    pub(crate) fn invalidate_terminal(&self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.terminal = true;
            state.facts.empty = None;
            state.facts.latest_exec = None;
        }
    }

    #[cfg(test)]
    pub(crate) fn test_for(pid: u32, domain: DiscoveryDomain) -> Self {
        Self(Arc::new(LifecycleObserver {
            pid: NonZeroU32::new(pid).unwrap(),
            domain,
            state: Mutex::new(LifecycleState::default()),
            resample_read_clock: false,
            read_clocks: Mutex::new(std::collections::VecDeque::new()),
        }))
    }

    #[cfg(test)]
    pub(crate) fn test_facts(&self) -> Result<LifecycleFacts, PidContinuityRefusal> {
        self.facts()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PhysicalGapSummary {
    pub(crate) episodes: u64,
    pub(crate) max_gap_ns: Option<u64>,
    pub(crate) open: bool,
    pub(crate) unknown: bool,
}
#[derive(Default)]
pub(super) struct PhysicalGaps {
    summary: PhysicalGapSummary,
    affected: BTreeSet<u32>,
    targets: BTreeMap<u32, (Slot, RetainedInventoryTarget)>,
    started_ns: Option<u64>,
    last_complete_ns: Option<u64>,
    exhausted: bool,
}
impl PhysicalGaps {
    pub(super) fn begin(&mut self, slots: &BTreeSet<u32>, started: Option<u64>) {
        if slots.is_empty() || self.exhausted {
            return;
        }
        if !self.summary.open {
            let Some(episodes) = self.summary.episodes.checked_add(1) else {
                self.summary.unknown = true;
                self.summary.open = true;
                self.exhausted = true;
                return;
            };
            self.summary.episodes = episodes;
            self.started_ns = started.filter(|time| {
                *time != 0
                    && self
                        .last_complete_ns
                        .is_none_or(|previous| *time > previous)
            });
            self.summary.unknown |= self.started_ns.is_none();
            self.summary.open = true;
        }
        for slot in slots {
            if self.affected.len() >= p11scope_ebpf_common::MAX_SLOTS as usize
                && !self.affected.contains(slot)
            {
                self.exhausted = true;
                self.summary.unknown = true;
                return;
            }
            self.affected.insert(*slot);
        }
    }
    pub(super) fn complete(&mut self, stamps: &BTreeMap<u32, PairStamp>) {
        if !self.summary.open || self.exhausted || self.affected.is_empty() {
            return;
        }
        let final_times: Option<Vec<_>> = self
            .affected
            .iter()
            .map(|slot| stamps.get(slot).map(|stamp| stamp.completed_ns))
            .collect();
        let Some(final_times) = final_times else {
            return;
        };
        let Some(completed) = final_times.into_iter().max().filter(|time| *time != 0) else {
            self.summary.unknown = true;
            return;
        };
        match self
            .started_ns
            .and_then(|start| completed.checked_sub(start))
            .filter(|gap| *gap != 0)
        {
            Some(gap) => {
                self.summary.max_gap_ns = Some(
                    self.summary
                        .max_gap_ns
                        .map_or(gap, |previous| previous.max(gap)),
                )
            }
            None => self.summary.unknown = true,
        }
        self.last_complete_ns = Some(completed);
        self.summary.open = false;
        self.affected.clear();
        self.targets.clear();
        self.started_ns = None;
    }
}

/// Fresh clock origin, shared with the inventory coordinator's exit filter.
pub(crate) fn clock_origins_comparable() -> bool {
    let active = std::fs::read_link("/proc/self/ns/time").ok();
    let children = std::fs::read_link("/proc/self/ns/time_for_children").ok();
    let offsets = std::fs::read_to_string("/proc/self/timens_offsets").ok();
    clock_origins_comparable_with(active.as_ref(), children.as_ref(), offsets.as_deref())
}

pub(crate) fn clock_origins_comparable_with(
    active: Option<&std::path::PathBuf>,
    children: Option<&std::path::PathBuf>,
    offsets: Option<&str>,
) -> bool {
    let (Some(active), Some(children), Some(offsets)) = (active, children, offsets) else {
        return false;
    };
    if active != children {
        return false;
    }
    let mut monotonic = None;
    for line in offsets.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("monotonic") {
            continue;
        }
        if monotonic.is_some() {
            return false;
        }
        let (Some(sec), Some(nsec)) = (fields.next(), fields.next()) else {
            return false;
        };
        if fields.next().is_some() {
            return false;
        }
        let (Ok(sec), Ok(nsec)) = (sec.parse::<i64>(), nsec.parse::<i64>()) else {
            return false;
        };
        monotonic = Some(sec == 0 && nsec == 0);
    }
    monotonic == Some(true)
}

pub(super) fn comparable_monotonic_ns() -> Option<u64> {
    clock_origins_comparable()
        .then(super::monotonic_ns)
        .flatten()
}

/// Private retained owners: allocation identity, not reusable numeric IDs.
#[derive(Clone)]
pub(crate) struct ExecBinding {
    tap: PidLifecycleTap,
    domain: DiscoveryDomain,
    admission: crate::process::ViewAdmission,
    pid: u32,
    serial: u64,
    key: ExecObservation,
}
impl std::fmt::Debug for ExecBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecBinding")
            .field("serial", &self.serial)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}
impl PartialEq for ExecBinding {
    fn eq(&self, other: &Self) -> bool {
        self.serial == other.serial
            && self.pid == other.pid
            && self.key == other.key
            && self.tap.same_observer(&other.tap)
            && self.domain.same_allocation(&other.domain)
            && self.admission.same_allocation(&other.admission)
    }
}
impl Eq for ExecBinding {}
impl ExecBinding {
    pub(super) fn bind(
        tap: &PidLifecycleTap,
        domain: &DiscoveryDomain,
        view: &crate::process::ProcessView,
        serial: u64,
        record: &DiscoveryRecord,
    ) -> Option<Self> {
        if serial == 0
            || !tap.matches_domain(domain)
            || !view.still_the_same()
            || tap.0.pid.get() != view.pid()
            || record.kind != DISCOVERY_KIND_EXEC
        {
            return None;
        }
        let key = tap.facts().ok()?.latest_exec?;
        let class = match record.case_id {
            DISCOVERY_EXEC_SAME_TASK_CANDIDATE => ExecClass::SameTaskCandidate,
            DISCOVERY_EXEC_TASK_REPLACED => ExecClass::TaskReplaced,
            DISCOVERY_EXEC_UNKNOWN => ExecClass::Unknown,
            _ => return None,
        };
        if key.pid != view.pid()
            || key.pid != (record.pid_tgid >> 32) as u32
            || key.class != class
            || key.hook_ts_ns != record.hook_ts_ns
        {
            return None;
        }
        Some(Self {
            tap: tap.clone(),
            domain: domain.clone(),
            admission: view.view_admission(),
            pid: view.pid(),
            serial,
            key,
        })
    }
    fn matches(
        &self,
        tap: &PidLifecycleTap,
        domain: &DiscoveryDomain,
        view: &crate::process::ProcessView,
        serial: u64,
    ) -> bool {
        serial == self.serial
            && self.pid == view.pid()
            && view.still_the_same()
            && self.tap.same_observer(tap)
            && self.domain.same_allocation(domain)
            && tap.matches_domain(domain)
            && self.admission.same_allocation(&view.view_admission())
            && tap.facts().ok().and_then(|facts| facts.latest_exec) == Some(self.key)
    }
}

struct ReceiptPair {
    slot: Slot,
    generation: u64,
    entry: RegistrationId,
    return_: RegistrationId,
}
/// Cannot be constructed by Engine, serialized, or converted from a class bit.
pub(crate) struct PreservationReceipt {
    binding: ExecBinding,
    empty: EmptyRead,
    pairs: Vec<ReceiptPair>,
    loss: u64,
    fault: u64,
}

/// Successful physical recovery after one exact EXEC, not preservation across
/// that EXEC. Its private payload shares the current-pair/frontier validator;
/// Engine cannot mint or convert either proof kind.
pub(crate) struct CompletedRearmReceipt {
    proof: PreservationReceipt,
}

pub(super) struct CurrentPairs<'a> {
    pub(super) book: &'a PairBook,
    pub(super) links: &'a [RegisteredLink],
    pub(super) sides: &'a BTreeSet<StaticEndpoint>,
    pub(super) retained: &'a BTreeMap<u32, RetainedStaticTarget>,
}
impl CurrentPairs<'_> {
    #[allow(clippy::too_many_arguments)] // Exact Session-owned facts for one completed request.
    pub(super) fn prepare_completed_rearm(
        &self,
        binding: &ExecBinding,
        tap: &PidLifecycleTap,
        domain: &DiscoveryDomain,
        view: &crate::process::ProcessView,
        serial: u64,
        slots: &[Slot],
        ordinary: &[Slot],
        objects: &PinnedObjects,
        loss: u64,
    ) -> Option<CompletedRearmReceipt> {
        if !binding.matches(tap, domain, view, serial)
            || binding.key.class != ExecClass::SameTaskCandidate
            || binding.key.hook_ts_ns == 0
            || slots.is_empty()
            || !clock_origins_comparable()
        {
            return None;
        }
        let facts = tap.facts().ok()?;
        let empty = facts.empty?;
        if empty.read_started_ns <= binding.key.hook_ts_ns
            || empty.observation_serial != facts.observation_serial
        {
            return None;
        }
        let requested: BTreeSet<_> = ordinary.iter().map(|slot| slot.index).collect();
        let affected = super::plan_group_rebuild(self.links, &requested).unwrap_or(requested);
        let mut seen = BTreeSet::new();
        let pairs: Option<Vec<_>> = slots
            .iter()
            .map(|slot| {
                if !seen.insert(slot.index) || affected.contains(&slot.index) {
                    return None;
                }
                let stamp =
                    self.book
                        .stamp_for(slot, objects, self.links, self.sides, self.retained)?;
                if stamp.started_ns <= binding.key.hook_ts_ns
                    || stamp.completed_ns <= stamp.started_ns
                    || stamp.completed_ns >= empty.read_started_ns
                    || facts
                        .greatest_break_ns
                        .is_some_and(|time| time >= stamp.started_ns)
                    || stamp.baseline.loss != loss
                    || stamp.baseline.fault != facts.fault_serial
                {
                    return None;
                }
                Some(ReceiptPair {
                    slot: slot.clone(),
                    generation: stamp.generation,
                    entry: stamp.entry,
                    return_: stamp.return_,
                })
            })
            .collect();
        Some(CompletedRearmReceipt {
            proof: PreservationReceipt {
                binding: binding.clone(),
                empty,
                pairs: pairs?,
                loss,
                fault: facts.fault_serial,
            },
        })
    }

    #[allow(clippy::too_many_arguments)] // Reuse exact registrations, held files, and the sole frontier.
    pub(super) fn validate_completed_rearm(
        &self,
        receipt: &CompletedRearmReceipt,
        binding: &ExecBinding,
        tap: &PidLifecycleTap,
        domain: &DiscoveryDomain,
        view: &crate::process::ProcessView,
        serial: u64,
        objects: &PinnedObjects,
        health_and_positions: impl FnOnce() -> Option<(u64, aya::maps::ring_buf::RingBufPositions)>,
    ) -> bool {
        self.validate_completed_rearm_with(
            receipt,
            binding,
            tap,
            domain,
            view,
            serial,
            objects,
            health_and_positions,
            clock_origins_comparable,
        )
    }

    #[allow(clippy::too_many_arguments)] // The metadata seam keeps the production validation order.
    fn validate_completed_rearm_with(
        &self,
        receipt: &CompletedRearmReceipt,
        binding: &ExecBinding,
        tap: &PidLifecycleTap,
        domain: &DiscoveryDomain,
        view: &crate::process::ProcessView,
        serial: u64,
        objects: &PinnedObjects,
        health_and_positions: impl FnOnce() -> Option<(u64, aya::maps::ring_buf::RingBufPositions)>,
        mut clock_origin: impl FnMut() -> bool,
    ) -> bool {
        let proof = &receipt.proof;
        if proof.binding != *binding
            || !binding.matches(tap, domain, view, serial)
            || !clock_origin()
            || !self.receipt_pairs_current(proof, objects)
            || !clock_origin()
        {
            return false;
        }
        // Native registry, held-file and clock-origin checks can perform I/O.
        // Read direct health and the sole frontier after all of them finish;
        // only compare retained memory after this final snapshot.
        let Some((loss, positions)) = health_and_positions() else {
            return false;
        };
        loss == proof.loss && Self::receipt_frontier_current(proof, tap, positions)
    }

    #[allow(clippy::too_many_arguments)] // One Session-owned fact set and its exact request.
    pub(super) fn prepare(
        &self,
        binding: &ExecBinding,
        tap: &PidLifecycleTap,
        domain: &DiscoveryDomain,
        view: &crate::process::ProcessView,
        serial: u64,
        slots: &[Slot],
        ordinary: &[Slot],
        objects: &PinnedObjects,
        loss: u64,
    ) -> Option<PreservationReceipt> {
        if !binding.matches(tap, domain, view, serial)
            || binding.key.class != ExecClass::SameTaskCandidate
            || slots.is_empty()
            || !clock_origins_comparable()
        {
            return None;
        }
        let facts = tap.facts().ok()?;
        let empty = facts.empty?;
        if empty.read_started_ns <= binding.key.hook_ts_ns
            || empty.observation_serial != facts.observation_serial
        {
            return None;
        }
        let requested: BTreeSet<_> = ordinary.iter().map(|slot| slot.index).collect();
        let affected = super::plan_group_rebuild(self.links, &requested).unwrap_or(requested);
        let mut seen = BTreeSet::new();
        let pairs: Option<Vec<_>> = slots
            .iter()
            .map(|slot| {
                if !seen.insert(slot.index) || affected.contains(&slot.index) {
                    return None;
                }
                let stamp =
                    self.book
                        .stamp_for(slot, objects, self.links, self.sides, self.retained)?;
                if stamp.completed_ns >= binding.key.hook_ts_ns
                    || facts
                        .greatest_break_ns
                        .is_some_and(|time| time >= stamp.started_ns)
                    || stamp.baseline.loss != loss
                    || stamp.baseline.fault != facts.fault_serial
                {
                    return None;
                }
                Some(ReceiptPair {
                    slot: slot.clone(),
                    generation: stamp.generation,
                    entry: stamp.entry,
                    return_: stamp.return_,
                })
            })
            .collect();
        Some(PreservationReceipt {
            binding: binding.clone(),
            empty,
            pairs: pairs?,
            loss,
            fault: facts.fault_serial,
        })
    }

    #[allow(clippy::too_many_arguments)] // Revalidate exactly the carried private proof against current owners.
    pub(super) fn validate(
        &self,
        receipt: &PreservationReceipt,
        binding: &ExecBinding,
        tap: &PidLifecycleTap,
        domain: &DiscoveryDomain,
        view: &crate::process::ProcessView,
        serial: u64,
        objects: &PinnedObjects,
        loss: u64,
        positions: impl FnOnce() -> Option<aya::maps::ring_buf::RingBufPositions>,
    ) -> bool {
        if receipt.binding != *binding
            || !binding.matches(tap, domain, view, serial)
            || !clock_origins_comparable()
            || loss != receipt.loss
        {
            return false;
        }
        if !self.receipt_pairs_current(receipt, objects) {
            return false;
        }
        // Held-file and registry checks can perform I/O. Sample the retained
        // cursor only after those checks, then compare its observation serial.
        let Some(positions) = positions() else {
            return false;
        };
        Self::receipt_frontier_current(receipt, tap, positions)
    }

    fn receipt_pairs_current(
        &self,
        receipt: &PreservationReceipt,
        objects: &PinnedObjects,
    ) -> bool {
        receipt.pairs.iter().all(|pair| {
            self.book
                .stamp_for(&pair.slot, objects, self.links, self.sides, self.retained)
                .is_some_and(|stamp| {
                    stamp.generation == pair.generation
                        && stamp.entry == pair.entry
                        && stamp.return_ == pair.return_
                })
        })
    }

    fn receipt_frontier_current(
        receipt: &PreservationReceipt,
        tap: &PidLifecycleTap,
        positions: aya::maps::ring_buf::RingBufPositions,
    ) -> bool {
        let Ok(facts) = tap.facts() else {
            return false;
        };
        facts.fault_serial == receipt.fault
            && facts.empty == Some(receipt.empty)
            && facts.observation_serial == receipt.empty.observation_serial
            && positions.producer == receipt.empty.producer_position
            && positions.consumer == positions.producer
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::discovery::identity::{PinnedObjectId, test_fixture};
    use p11scope_ebpf_common::SlotSemantics;
    use p11scope_manifest::elf::ElfAbi;
    use std::fs::File;

    pub(in crate::attach) fn fixture() -> (tempfile::TempDir, PinnedObjects, RetainedStaticTarget) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider");
        std::fs::write(&path, b"held provider bytes").unwrap();
        let pins = test_fixture::real_scan_pin(&path, None, 1, test_fixture::SHA);
        let object = pins.pinned().next().unwrap().id;
        let slot = Slot {
            index: 0,
            descriptor_index: 0,
            object,
            object_path: path.to_str().unwrap().into(),
            file_offset: 0x10,
            names: vec!["C_Sign".into()],
            aliased: false,
            semantics: SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![crate::plan::ModuleId(0)],
        };
        let target = RetainedStaticTarget {
            path: pins.attach_path_for(object).unwrap(),
            held: Some(pins.retain_inventory_target(object).unwrap()),
            slot,
            abi: ElfAbi::Lp64,
        };
        (dir, pins, target)
    }

    pub(in crate::attach) fn pair(book: &mut PairBook) -> Vec<RegisteredLink> {
        ["p11_return", "p11_entry"]
            .into_iter()
            .map(|program| RegisteredLink::MultiUProbe {
                program,
                slots: vec![0],
                fds: vec![File::open("/dev/null").unwrap().into()],
                registration: book.register(),
            })
            .collect()
    }

    #[test]
    fn pid_continuity_requires_current_registered_pair_and_exact_target() {
        let (_dir, pins, target) = fixture();
        let slot = target.slot.clone();
        let retained = BTreeMap::from([(0, target)]);
        let mut book = PairBook::default();
        let links = pair(&mut book);
        let sides = BTreeSet::from([(0, ProbeSide::Return), (0, ProbeSide::Entry)]);
        book.seal(
            &[AttachRound {
                slots: vec![0],
                started_ns: Some(10),
                last_call_ns: Some(20),
            }],
            Some(AttachBaseline { loss: 7, fault: 0 }),
            Some(0),
            &links,
            &sides,
            &retained,
            || Some(30),
        );
        assert!(
            book.stamp_for(&slot, &pins, &links, &sides, &retained)
                .is_some(),
            "both concrete current registrations and the exact held target must publish a generation"
        );
        assert!(
            book.stamp_for(&slot, &pins, &links[..1], &sides, &retained)
                .is_none()
        );
        let mut changed = slot.clone();
        changed.descriptor_index = 1;
        assert!(
            book.stamp_for(&changed, &pins, &links, &sides, &retained)
                .is_none()
        );
        changed = slot.clone();
        changed.file_offset += 1;
        assert!(
            book.stamp_for(&changed, &pins, &links, &sides, &retained)
                .is_none()
        );
        changed = slot.clone();
        changed.object = PinnedObjectId(u32::MAX);
        assert!(
            book.stamp_for(&changed, &pins, &links, &sides, &retained)
                .is_none()
        );
        let replacement = pair(&mut book);
        assert!(
            book.stamp_for(&slot, &pins, &replacement, &sides, &retained)
                .is_none()
        );
        let mut empty = pair(&mut book);
        if let RegisteredLink::MultiUProbe { fds, .. } = &mut empty[0] {
            fds.clear();
        }
        assert!(
            book.stamp_for(&slot, &pins, &empty, &sides, &retained)
                .is_none()
        );
        let mut ambiguous = pair(&mut book);
        ambiguous.push(pair(&mut book).remove(0));
        assert!(
            book.stamp_for(&slot, &pins, &ambiguous, &sides, &retained)
                .is_none()
        );
        let mut changed_retained = BTreeMap::from([(0, retained[&0].clone())]);
        changed_retained.get_mut(&0).unwrap().abi = ElfAbi::Ilp32;
        assert!(
            book.stamp_for(&slot, &pins, &links, &sides, &changed_retained)
                .is_none()
        );
        assert!(
            book.stamp_for(&slot, &pins, &links, &BTreeSet::new(), &retained)
                .is_none()
        );
    }

    #[test]
    fn pid_continuity_metrics_retains_the_same_open_file() {
        use std::os::unix::fs::FileExt as _;
        let (dir, pins, target) = fixture();
        let lease = target.held.as_ref().unwrap().retirement_lease();
        let shared = target.clone();
        assert!(std::sync::Arc::ptr_eq(
            &lease,
            &shared.held.as_ref().unwrap().retirement_lease()
        ));
        let slot = target.slot.clone();
        let mut book = PairBook::default();
        let links = pair(&mut book);
        let sides = BTreeSet::from([(0, ProbeSide::Entry), (0, ProbeSide::Return)]);
        let retained = BTreeMap::from([(0, target)]);
        book.seal(
            &[AttachRound {
                slots: vec![0],
                started_ns: Some(10),
                last_call_ns: Some(20),
            }],
            Some(AttachBaseline { loss: 3, fault: 0 }),
            Some(0),
            &links,
            &sides,
            &retained,
            || Some(30),
        );
        assert!(
            book.stamp_for(&slot, &pins, &links, &sides, &retained)
                .is_some()
        );
        drop(pins);
        let path = dir.path().join("provider");
        std::fs::rename(&path, dir.path().join("retired-provider")).unwrap();
        std::fs::write(&path, b"replacement bytes!").unwrap();
        let later = test_fixture::real_scan_pin(&path, None, 1, test_fixture::SHA);
        let mut bytes = [0u8; 19];
        assert_eq!(lease.read_at(&mut bytes, 0).unwrap(), 19);
        assert_eq!(&bytes, b"held provider bytes");
        assert!(
            !shared
                .held
                .as_ref()
                .unwrap()
                .same_kernel_file_as(&later, later.pinned().next().unwrap().id)
        );
        assert!(
            book.stamp_for(&slot, &later, &links, &sides, &retained)
                .is_none()
        );
    }

    #[test]
    fn pid_continuity_refuses_bad_time_loss_fault_and_serial() {
        let (_dir, pins, target) = fixture();
        let slot = target.slot.clone();
        let retained = BTreeMap::from([(0, target)]);
        let sides = BTreeSet::from([(0, ProbeSide::Entry), (0, ProbeSide::Return)]);
        for (start, last, end) in [
            (None, Some(20), Some(30)),
            (Some(0), Some(20), Some(30)),
            (Some(10), Some(9), Some(30)),
            (Some(10), Some(20), None),
            (Some(10), Some(20), Some(0)),
            (Some(10), Some(20), Some(19)),
            (Some(10), Some(10), Some(10)),
        ] {
            let mut book = PairBook::default();
            let links = pair(&mut book);
            book.seal(
                &[AttachRound {
                    slots: vec![0],
                    started_ns: start,
                    last_call_ns: last,
                }],
                Some(AttachBaseline { loss: 7, fault: 0 }),
                Some(0),
                &links,
                &sides,
                &retained,
                || end,
            );
            assert!(
                book.stamp_for(&slot, &pins, &links, &sides, &retained)
                    .is_none()
            );
        }
        for samples in [
            vec![],
            vec![u64::MAX],
            vec![u64::MAX - 1, 2],
            vec![u64::MAX - 1, 1],
        ] {
            assert_eq!(
                checked_discovery_loss(samples),
                Err(PidContinuityRefusal::Loss)
            );
        }
        assert_eq!(checked_discovery_loss([3, 4]), Ok(7));
        let mut book = PairBook::default();
        assert!(
            book.prepare_baseline(Err(PidContinuityRefusal::Loss), Some(0))
                .is_none()
        );
        assert!(book.prepare_baseline(Ok(7), None).is_none());
        assert!(
            book.prepare_baseline(Ok(6), Some(0)).is_none(),
            "loss regression refuses"
        );
        let baseline = book.prepare_baseline(Ok(9), Some(2));
        assert_eq!(baseline, Some(AttachBaseline { loss: 9, fault: 2 }));
        let links = pair(&mut book);
        let round = [AttachRound {
            slots: vec![0],
            started_ns: Some(10),
            last_call_ns: Some(20),
        }];
        book.seal(&round, baseline, Some(3), &links, &sides, &retained, || {
            Some(30)
        });
        assert!(
            book.stamp_for(&slot, &pins, &links, &sides, &retained)
                .is_none()
        );
        let fresh = book.prepare_baseline(Ok(9), Some(3));
        book.seal(&round, fresh, Some(3), &links, &sides, &retained, || {
            Some(30)
        });
        assert!(
            book.stamp_for(&slot, &pins, &links, &sides, &retained)
                .is_some(),
            "historical nonzero loss/fault permits a fresh generation"
        );
        book.generation_serial = u64::MAX - 1;
        book.seal(&round, fresh, Some(3), &links, &sides, &retained, || {
            Some(30)
        });
        assert!(
            book.stamp_for(&slot, &pins, &links, &sides, &retained)
                .is_none()
        );
        let mut exhausted = PairBook {
            registration_serial: u64::MAX - 1,
            ..PairBook::default()
        };
        assert!(exhausted.register().is_none());
        assert!(exhausted.register().is_none());
        for observation in [true, false] {
            let tap = PidLifecycleTap::test_for(7, DiscoveryDomain::test_standin(901));
            {
                let mut state = tap.0.state.lock().unwrap();
                if observation {
                    state.facts.observation_serial = u64::MAX - 1;
                } else {
                    state.facts.fault_serial = u64::MAX - 1;
                }
            }
            if observation {
                tap.begin_read(Some(40));
                let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
                record.kind = DISCOVERY_KIND_EXEC;
                record.case_id = DISCOVERY_EXEC_SAME_TASK_CANDIDATE;
                record.pid_tgid = (7u64 << 32) | 7;
                record.hook_ts_ns = 20;
                tap.observe_record(&record);
            } else {
                tap.observe_failure();
            }
            assert_eq!(tap.facts(), Err(PidContinuityRefusal::Serial));
            assert!(tap.begin_read(Some(50)).is_none());
            tap.observe_empty(Some(50), 0, 0);
            assert_eq!(
                tap.facts(),
                Err(PidContinuityRefusal::Serial),
                "exhausted serials never wrap or recover"
            );
        }
        let poisoned = PidLifecycleTap::test_for(7, DiscoveryDomain::test_standin(902));
        let tap = poisoned.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = tap.0.state.lock().unwrap();
                panic!("poison observer stand-in");
            })
            .join()
            .is_err()
        );
        assert_eq!(poisoned.facts(), Err(PidContinuityRefusal::Unavailable));
        assert!(poisoned.begin_read(Some(60)).is_none());
        let mut timing = RoundClock::default();
        timing.observe_call(Some(20));
        timing.observe_call(Some(19));
        assert!(timing.finish(vec![0]).started_ns.is_none());
    }
}

#[cfg(test)]
pub(crate) mod engine_fixture {
    use super::*;
    use crate::events::{BoundedRecord, BoundedRecordSource, DiscoveryDrain, RecordSource};
    use crate::process::ProcessView;
    use aya::maps::ring_buf::RingBufPositions;
    use p11scope_ebpf_common::ThreadOwnerControl;
    use std::collections::VecDeque;

    type RawHealthRead = (
        Result<ThreadOwnerControl, PidContinuityRefusal>,
        Result<Vec<u64>, PidContinuityRefusal>,
    );

    pub(crate) enum PreflightChange {
        Producer,
        Observation,
        Health,
        Registration,
        Stop,
        Clock,
        Terminal,
        ProducersDetached,
        Exit(u32),
        Cancel(Arc<std::sync::atomic::AtomicBool>),
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum AttachmentBoundaryChange {
        Stop,
        Terminal,
        ProducersDetached,
        DetachFailure,
    }

    enum CompletedClockChange {
        Producer,
        Origins {
            active: Option<std::path::PathBuf>,
            children: Option<std::path::PathBuf>,
            offsets: Option<String>,
        },
    }

    struct Cursor {
        records: std::cell::RefCell<VecDeque<Vec<u8>>>,
        producer: std::cell::Cell<usize>,
        consumer: std::cell::Cell<usize>,
    }
    impl RecordSource for Cursor {
        fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
            let bytes = self.records.borrow_mut().pop_front()?;
            self.consumer.set(self.consumer.get() + bytes.len());
            Some(bytes)
        }
    }
    impl BoundedRecordSource for Cursor {
        fn positions(&self) -> RingBufPositions {
            RingBufPositions {
                producer: self.producer.get(),
                consumer: self.consumer.get(),
                capacity: 1 << 20,
            }
        }
        fn consumer(&self) -> usize {
            self.consumer.get()
        }
        fn bounded_record(
            &mut self,
            _: usize,
        ) -> anyhow::Result<BoundedRecord<impl std::ops::Deref<Target = [u8]> + '_>> {
            Ok(BoundedRecord::Item(Vec::<u8>::new()))
        }
    }

    /// Only native handles/maps/clocks are scripted. Current pairs, held files,
    /// generation publication and raw cursor observation use production reducers.
    pub(crate) struct PidSessionFixture {
        pub(super) book: PairBook,
        pub(super) links: Vec<RegisteredLink>,
        pub(super) retained: BTreeMap<u32, RetainedStaticTarget>,
        pub(super) tap: PidLifecycleTap,
        drain: DiscoveryDrain<Cursor>,
        health: OwnerHealth,
        pub(crate) owner: Result<ThreadOwnerControl, PidContinuityRefusal>,
        pub(crate) loss: Result<Vec<u64>, PidContinuityRefusal>,
        pub(crate) prepared_limit: u64,
        pub(crate) health_reads: usize,
        pub(crate) health_phases: Vec<&'static str>,
        prepared_count: usize,
        pub(crate) health_script: VecDeque<RawHealthRead>,
        pub(crate) preflight_change: Option<PreflightChange>,
        pub(crate) clock_offsets: Option<String>,
        completed_clock_change: Option<CompletedClockChange>,
        pub(crate) completed_clock_frontiers: Vec<(usize, usize)>,
        pub(crate) completed_health_frontiers: Vec<(usize, usize)>,
        pub(crate) stop_word: u64,
        pub(crate) uprobe_scope: aya::programs::uprobe::UProbeScope,
        pub(crate) producers_detached: bool,
        pub(crate) detach_failures: Vec<String>,
        pub(crate) attachment_boundary_change: Option<AttachmentBoundaryChange>,
        pub(crate) target_map_prepares: usize,
        pub(crate) native_attach_calls: usize,
        pub(crate) native_failures: BTreeSet<(u32, &'static str)>,
        pub(crate) native_clocks: std::collections::VecDeque<Option<u64>>,
        pub(crate) completion_clocks: std::collections::VecDeque<Option<u64>>,
        pub(crate) detach_clocks: std::collections::VecDeque<Option<u64>>,
        pub(crate) ended_original_state:
            Option<Result<crate::process::OriginalGenerationState, String>>,
        pub(crate) detach_delay: std::time::Duration,
        pub(crate) completion_delay: std::time::Duration,
    }
    impl PidSessionFixture {
        pub(crate) fn new(view: &ProcessView) -> Self {
            let domain = DiscoveryDomain::test_standin(7);
            let tap = PidLifecycleTap::test_for(view.pid(), domain.clone());
            let mut drain = DiscoveryDrain::over_domain(
                Cursor {
                    records: std::cell::RefCell::new(VecDeque::new()),
                    producer: std::cell::Cell::new(0),
                    consumer: std::cell::Cell::new(0),
                },
                domain,
            );
            drain.attach_pid_lifecycle_tap(tap.clone()).unwrap();
            Self {
                book: PairBook::default(),
                links: Vec::new(),
                retained: BTreeMap::new(),
                tap,
                drain,
                health: OwnerHealth::default(),
                owner: Ok(ThreadOwnerControl {
                    limit: 17,
                    ..Default::default()
                }),
                loss: Ok(vec![0]),
                prepared_limit: 17,
                health_reads: 0,
                health_phases: Vec::new(),
                prepared_count: 0,
                health_script: VecDeque::new(),
                preflight_change: None,
                clock_offsets: Some("monotonic 0 0".into()),
                completed_clock_change: None,
                completed_clock_frontiers: Vec::new(),
                completed_health_frontiers: Vec::new(),
                stop_word: 0,
                uprobe_scope: aya::programs::uprobe::UProbeScope::OneProcess(
                    NonZeroU32::new(view.pid()).unwrap(),
                ),
                producers_detached: false,
                detach_failures: Vec::new(),
                attachment_boundary_change: None,
                target_map_prepares: 0,
                native_attach_calls: 0,
                native_failures: BTreeSet::new(),
                native_clocks: VecDeque::new(),
                completion_clocks: VecDeque::new(),
                detach_clocks: VecDeque::new(),
                ended_original_state: None,
                detach_delay: std::time::Duration::ZERO,
                completion_delay: std::time::Duration::ZERO,
            }
        }
        fn sides(&self) -> BTreeSet<StaticEndpoint> {
            super::super::current_static_sides_from(&self.links)
        }
        pub(crate) fn attach(
            &mut self,
            slots: &[Slot],
            objects: &PinnedObjects,
        ) -> anyhow::Result<super::super::TargetAttachResult> {
            if slots.is_empty() {
                return Ok((Vec::new(), Vec::new()));
            }
            if self.stopped() {
                anyhow::bail!("static attachment refused while Session is stopping or detached");
            }
            self.book.retarget_gap(slots, objects);
            super::super::attachment_admission(&self.detach_failures, true)?;
            let baseline = super::super::static_attachment_baseline_with(
                self,
                Self::attach_baseline,
                Self::stopped,
            )?;
            self.target_map_prepares += 1;
            for slot in slots {
                assert!(
                    !self.has_slot_link(slot.index),
                    "no overlapping registered pairs"
                );
                let held = objects.retain_inventory_target(slot.object).unwrap();
                self.retained.insert(
                    slot.index,
                    RetainedStaticTarget {
                        slot: slot.clone(),
                        path: held.attach_path(),
                        abi: held.abi(),
                        held: Some(held),
                    },
                );
            }
            let origin = self.origin_inputs();
            let links = &mut self.links;
            let book = &mut self.book;
            let failures = &self.native_failures;
            let clocks = &mut self.native_clocks;
            let native_calls = &mut self.native_attach_calls;
            let outcome = super::super::attach_targets_observed_with(
                slots,
                super::super::CapturePolicy::Allowlisted,
                false,
                |slot| {
                    objects
                        .abi_for(slot.object)
                        .ok_or_else(|| anyhow::anyhow!("missing exact ABI"))
                },
                |program, slot, _| {
                    let started = clocks.pop_front().unwrap_or_else(|| Self::sample(&origin));
                    NativeAttempt::run(
                        || started,
                        || {
                            *native_calls += 1;
                            if failures.contains(&(slot.index, program))
                                || failures.contains(&(u32::MAX, program))
                            {
                                return Err(anyhow::anyhow!("scripted native side failure"));
                            }
                            let fd = std::fs::File::open("/dev/null")?;
                            links.push(RegisteredLink::MultiUProbe {
                                program,
                                slots: vec![slot.index],
                                fds: vec![fd.into()],
                                registration: book.register(),
                            });
                            Ok(())
                        },
                    )
                },
                |_| Self::sample(&origin),
            )
            .unwrap();
            std::thread::sleep(self.completion_delay);
            let sides = super::super::current_static_sides_from(&self.links);
            let completion_clocks = &mut self.completion_clocks;
            self.book.seal(
                &outcome.continuity_rounds,
                baseline,
                self.tap.facts().ok().map(|f| f.fault_serial),
                &self.links,
                &sides,
                &self.retained,
                || {
                    completion_clocks
                        .pop_front()
                        .unwrap_or_else(|| Self::sample(&origin))
                },
            );
            Ok((
                outcome.failures.into_iter().map(|(slot, _)| slot).collect(),
                outcome.completed,
            ))
        }
        pub(crate) fn group_all(&mut self) {
            let members: Vec<_> = self.retained.keys().copied().collect();
            self.links.clear();
            self.book.invalidate_all();
            let mut timing = RoundClock::default();
            for program in ["p11_return", "p11_entry"] {
                let attempt = NativeAttempt::run(comparable_monotonic_ns, || {
                    self.native_attach_calls += 1;
                    std::fs::File::open("/dev/null")
                });
                timing.observe_call(attempt.started_ns);
                self.links.push(RegisteredLink::MultiUProbe {
                    program,
                    slots: members.clone(),
                    fds: vec![attempt.result.unwrap().into()],
                    registration: self.book.register(),
                });
            }
            self.health_phases.push("attach");
            let loss = self.read_health();
            let baseline = self
                .book
                .prepare_baseline(loss, self.tap.facts().ok().map(|facts| facts.fault_serial));
            let sides = super::super::current_static_sides_from(&self.links);
            self.book.seal(
                &[timing.finish(members)],
                baseline,
                self.tap.facts().ok().map(|facts| facts.fault_serial),
                &self.links,
                &sides,
                &self.retained,
                comparable_monotonic_ns,
            );
        }
        pub(crate) fn prepare_ended_pid_retirement(
            &self,
            view: &ProcessView,
            slots: &[Slot],
        ) -> Option<super::super::EndedPidRetirement> {
            if self.stopped() {
                return None;
            }
            super::super::EndedPidRetirement::prepare(
                &self.tap.0.domain,
                self.uprobe_scope,
                view,
                slots,
                &self.links,
                &self.retained,
            )
        }

        pub(crate) fn detach(&mut self, slots: &[Slot]) -> super::super::DetachOutcome {
            self.detach_with_ended(slots, None)
        }

        pub(crate) fn detach_ended_pid_slots(
            &mut self,
            slots: &[Slot],
            owner: &ProcessView,
            proof: &super::super::EndedPidRetirement,
        ) -> super::super::DetachOutcome {
            self.detach_with_ended(slots, Some((owner, proof)))
        }

        fn detach_with_ended(
            &mut self,
            slots: &[Slot],
            ended: Option<(&ProcessView, &super::super::EndedPidRetirement)>,
        ) -> super::super::DetachOutcome {
            let requested: BTreeSet<_> = slots.iter().map(|slot| slot.index).collect();
            let affected = super::super::plan_group_rebuild(&self.links, &requested);
            let survivors: Vec<_> = affected
                .as_ref()
                .map(|affected| {
                    affected
                        .difference(&requested)
                        .filter_map(|slot| self.retained.get(slot).cloned())
                        .collect()
                })
                .unwrap_or_default();
            let missing: Vec<_> = affected
                .as_ref()
                .map(|affected| {
                    affected
                        .difference(&requested)
                        .filter(|slot| !self.retained.contains_key(slot))
                        .copied()
                        .collect()
                })
                .unwrap_or_default();
            let regrouped: Vec<_> = survivors.iter().map(|target| target.slot.clone()).collect();
            let targets = survivors
                .iter()
                .map(|target| (target.slot.index, (target.path.clone(), target.abi)))
                .collect();
            let groups = super::super::group_static_slots(
                &regrouped,
                super::super::CapturePolicy::Allowlisted,
                false,
                &targets,
            );
            let rebuilt_groups = affected.as_ref().map_or(0, |affected| {
                super::super::affected_group_count(&self.links, affected)
            });
            let ended = ended
                .filter(|_| !self.stopped())
                .and_then(|(owner, proof)| match &self.ended_original_state {
                    Some(state) => proof.check_with_original_state(
                        &self.tap.0.domain,
                        self.uprobe_scope,
                        owner,
                        slots,
                        &self.links,
                        &self.retained,
                        || state.clone(),
                    ),
                    None => proof.check(
                        &self.tap.0.domain,
                        self.uprobe_scope,
                        owner,
                        slots,
                        &self.links,
                        &self.retained,
                    ),
                });
            let selected =
                super::super::extract_selected_links(&mut self.links, &mut self.book, |link| {
                    link.slots()
                        .iter()
                        .any(|slot| affected.as_ref().unwrap_or(&requested).contains(slot))
                });
            let actual = selected
                .iter()
                .flat_map(|link| link.slots().iter().copied())
                .collect();
            let start = self
                .detach_clocks
                .pop_front()
                .unwrap_or_else(|| Self::sample(&self.origin_inputs()));
            super::super::ended_pid_retirement::begin_detach_gap(
                &mut self.book,
                &actual,
                start,
                &self.retained,
                ended,
            );
            // The gap has already begun before the native close/detach work.
            std::thread::sleep(self.detach_delay);
            drop(selected);
            super::super::prune_linkless_retained(&mut self.retained, &self.links);
            let Some(affected) = affected else {
                return super::super::DetachOutcome::default();
            };
            let baseline = match super::super::static_attachment_baseline_with(
                self,
                Self::attach_baseline,
                Self::stopped,
            ) {
                Ok(baseline) => baseline,
                Err(error) => {
                    return super::super::refused_group_rebuild(
                        affected.difference(&requested).copied(),
                        rebuilt_groups,
                        &error.to_string(),
                    );
                }
            };
            let failures = &self.native_failures;
            let native_calls = &mut self.native_attach_calls;
            let (bundles, outcome) = super::super::reattach_rebuilt_groups_observed_with(
                &groups,
                |_| comparable_monotonic_ns(),
                |program, _, sites, _| {
                    NativeAttempt::run(comparable_monotonic_ns, || {
                        *native_calls += 1;
                        if sites
                            .iter()
                            .any(|(_, cookie)| failures.contains(&(*cookie as u32, program)))
                        {
                            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                        }
                        std::fs::File::open("/dev/null").map(Into::into)
                    })
                },
                drop,
            );
            super::super::publish_kept_multi_bundles(
                &mut self.links,
                &mut self.retained,
                bundles,
                &survivors,
                &mut self.book,
            );
            let sides = super::super::current_static_sides_from(&self.links);
            self.book.seal(
                &outcome.continuity_rounds,
                baseline,
                self.tap.facts().ok().map(|facts| facts.fault_serial),
                &self.links,
                &sides,
                &self.retained,
                comparable_monotonic_ns,
            );
            let mut report = super::super::DetachOutcome {
                pending: None,
                recompleted: outcome.completed,
                rebuild_failures: outcome.failures,
                rebuilt_groups,
            };
            report.rebuild_failures.extend(missing.into_iter().map(|member| {
                (member, format!("slot {member} was not reattached: no retained attach facts for a live group member"))
            }));
            report
        }
        fn origin_inputs(
            &self,
        ) -> (
            Option<std::path::PathBuf>,
            Option<std::path::PathBuf>,
            Option<String>,
        ) {
            let ns = std::path::PathBuf::from("time:[7]");
            (Some(ns.clone()), Some(ns), self.clock_offsets.clone())
        }
        pub(crate) fn advance_producer_during_completed_clock(&mut self) {
            self.completed_clock_change = Some(CompletedClockChange::Producer);
        }
        pub(crate) fn script_completed_clock_origins(
            &mut self,
            active: Option<&str>,
            children: Option<&str>,
            offsets: Option<&str>,
        ) {
            self.completed_clock_change = Some(CompletedClockChange::Origins {
                active: active.map(std::path::PathBuf::from),
                children: children.map(std::path::PathBuf::from),
                offsets: offsets.map(str::to_owned),
            });
        }
        pub(crate) fn completed_frontier(&self) -> (usize, usize) {
            let positions = crate::events::discovery_drain_positions(&self.drain);
            (positions.producer, positions.consumer)
        }
        fn sample(
            origin: &(
                Option<std::path::PathBuf>,
                Option<std::path::PathBuf>,
                Option<String>,
            ),
        ) -> Option<u64> {
            clock_origins_comparable_with(origin.0.as_ref(), origin.1.as_ref(), origin.2.as_deref())
                .then(comparable_monotonic_ns)
                .flatten()
        }
        pub(crate) fn identities(&self) -> Vec<(u32, u64, u64)> {
            self.retained
                .keys()
                .filter_map(|slot| {
                    let (entry, return_) = current_pair(*slot, &self.links, &self.sides())?;
                    Some((*slot, entry.0, return_.0))
                })
                .collect()
        }
        pub(crate) fn invalidate_generations(&mut self) {
            self.book.invalidate_all();
        }
        pub(crate) fn forget_retained_target(&mut self, slot: u32) {
            self.retained.remove(&slot);
        }
        pub(crate) fn pair_times(&self, slot: u32) -> (u64, u64) {
            let stamp = &self.book.stamps[&slot];
            (stamp.started_ns, stamp.completed_ns)
        }
        pub(crate) fn current_pair_times(
            &self,
            slots: &[Slot],
            objects: &PinnedObjects,
        ) -> Vec<(u32, u64, u64)> {
            let sides = self.sides();
            slots
                .iter()
                .filter_map(|slot| {
                    let stamp =
                        self.book
                            .stamp_for(slot, objects, &self.links, &sides, &self.retained)?;
                    Some((slot.index, stamp.started_ns, stamp.completed_ns))
                })
                .collect()
        }
        pub(crate) fn fresh_empty_started_ns(&mut self) -> u64 {
            assert!(self.drain.dequeue().is_none());
            self.tap.facts().unwrap().empty.unwrap().read_started_ns
        }
        pub(crate) fn scripted_read_clocks(&self, values: impl IntoIterator<Item = Option<u64>>) {
            *self.tap.0.read_clocks.lock().unwrap() = values.into_iter().collect();
        }
        pub(crate) fn terminal(&self) {
            self.tap.invalidate_terminal();
        }
        pub(crate) fn gap_summary(&self) -> PhysicalGapSummary {
            self.book.gap_summary()
        }
        pub(crate) fn stopped(&self) -> bool {
            self.stop_word & p11scope_ebpf_common::STOP_GATE_STOP != 0
                || self.producers_detached
                || !self.detach_failures.is_empty()
                || self.tap.facts().is_err()
                || self.health.terminal()
        }
        fn attach_baseline(&mut self) -> Option<AttachBaseline> {
            let baseline = if !matches!(
                self.uprobe_scope,
                aya::programs::uprobe::UProbeScope::OneProcess(_)
            ) || self.stopped()
            {
                None
            } else {
                self.health_phases.push("attach");
                let loss = self.read_health();
                let baseline = self
                    .book
                    .prepare_baseline(loss, self.tap.facts().ok().map(|facts| facts.fault_serial));
                if baseline.is_none() {
                    self.tap.observe_failure();
                }
                baseline
            };
            match self.attachment_boundary_change.take() {
                Some(AttachmentBoundaryChange::Stop) => {
                    self.stop_word = p11scope_ebpf_common::STOP_GATE_STOP | 3;
                }
                Some(AttachmentBoundaryChange::Terminal) => self.tap.invalidate_terminal(),
                Some(AttachmentBoundaryChange::ProducersDetached) => {
                    self.producers_detached = true;
                }
                Some(AttachmentBoundaryChange::DetachFailure) => {
                    self.detach_failures
                        .push("scripted detach uncertainty".into());
                }
                None => {}
            }
            baseline
        }
        fn origin(&self) -> bool {
            let ns = std::path::PathBuf::from("time:[7]");
            clock_origins_comparable_with(Some(&ns), Some(&ns), self.clock_offsets.as_deref())
        }
        fn read_health(&mut self) -> Result<u64, PidContinuityRefusal> {
            Self::read_health_with(
                &mut self.health,
                &mut self.owner,
                &mut self.loss,
                &mut self.health_script,
                &mut self.health_reads,
                self.prepared_limit,
                &self.tap,
            )
        }
        fn read_health_with(
            health: &mut OwnerHealth,
            owner: &mut Result<ThreadOwnerControl, PidContinuityRefusal>,
            loss: &mut Result<Vec<u64>, PidContinuityRefusal>,
            script: &mut VecDeque<RawHealthRead>,
            reads: &mut usize,
            limit: u64,
            tap: &PidLifecycleTap,
        ) -> Result<u64, PidContinuityRefusal> {
            *reads += 1;
            if let Some((next_owner, next_loss)) = script.pop_front() {
                *owner = next_owner;
                *loss = next_loss;
            }
            health.check(
                *owner,
                loss.clone().and_then(checked_discovery_loss),
                limit,
                tap,
            )
        }
        pub(crate) fn bind(
            &self,
            view: &ProcessView,
            serial: u64,
            record: &DiscoveryRecord,
        ) -> Option<ExecBinding> {
            if self.stopped() {
                return None;
            }
            ExecBinding::bind(&self.tap, &self.tap.0.domain, view, serial, record)
        }
        pub(crate) fn has_slot_link(&self, slot: u32) -> bool {
            self.links.iter().any(|link| link.slots().contains(&slot))
        }
        pub(crate) fn prepare(
            &mut self,
            binding: &ExecBinding,
            view: &ProcessView,
            serial: u64,
            slots: &[Slot],
            ordinary: &[Slot],
            objects: &PinnedObjects,
        ) -> Option<PreservationReceipt> {
            if self.stopped() || !self.origin() {
                return None;
            }
            self.health_phases.push("prepare");
            let loss = self.read_health().ok()?;
            let sides = self.sides();
            let pairs = CurrentPairs {
                book: &self.book,
                links: &self.links,
                sides: &sides,
                retained: &self.retained,
            };
            let receipt = pairs.prepare(
                binding,
                &self.tap,
                &self.tap.0.domain,
                view,
                serial,
                slots,
                ordinary,
                objects,
                loss,
            )?;
            if !pairs.validate(
                &receipt,
                binding,
                &self.tap,
                &self.tap.0.domain,
                view,
                serial,
                objects,
                loss,
                || Some(crate::events::discovery_drain_positions(&self.drain)),
            ) {
                return None;
            }
            self.prepared_count += 1;
            Some(receipt)
        }
        pub(crate) fn prepare_completed_rearm(
            &mut self,
            binding: &ExecBinding,
            view: &ProcessView,
            serial: u64,
            slots: &[Slot],
            ordinary: &[Slot],
            objects: &PinnedObjects,
        ) -> Option<CompletedRearmReceipt> {
            if self.stopped() || !self.origin() {
                return None;
            }
            self.health_phases.push("prepare_completed");
            let loss = self.read_health().ok()?;
            let sides = self.sides();
            let pairs = CurrentPairs {
                book: &self.book,
                links: &self.links,
                sides: &sides,
                retained: &self.retained,
            };
            let receipt = pairs.prepare_completed_rearm(
                binding,
                &self.tap,
                &self.tap.0.domain,
                view,
                serial,
                slots,
                ordinary,
                objects,
                loss,
            )?;
            if !pairs.validate_completed_rearm(
                &receipt,
                binding,
                &self.tap,
                &self.tap.0.domain,
                view,
                serial,
                objects,
                || {
                    let loss = Self::read_health_with(
                        &mut self.health,
                        &mut self.owner,
                        &mut self.loss,
                        &mut self.health_script,
                        &mut self.health_reads,
                        self.prepared_limit,
                        &self.tap,
                    )
                    .ok()?;
                    Some((loss, crate::events::discovery_drain_positions(&self.drain)))
                },
            ) || self.stopped()
            {
                return None;
            }
            self.prepared_count += 1;
            Some(receipt)
        }
        pub(crate) fn validate_completed_rearm(
            &mut self,
            receipt: &CompletedRearmReceipt,
            binding: &ExecBinding,
            view: &ProcessView,
            serial: u64,
            objects: &PinnedObjects,
        ) -> bool {
            if self.stopped() || !self.origin() {
                return false;
            }
            self.health_phases.push("apply_completed");
            let sides = self.sides();
            let pairs = CurrentPairs {
                book: &self.book,
                links: &self.links,
                sides: &sides,
                retained: &self.retained,
            };
            let mut clock_reads = 0;
            pairs.validate_completed_rearm_with(
                receipt,
                binding,
                &self.tap,
                &self.tap.0.domain,
                view,
                serial,
                objects,
                || {
                    let loss = Self::read_health_with(
                        &mut self.health,
                        &mut self.owner,
                        &mut self.loss,
                        &mut self.health_script,
                        &mut self.health_reads,
                        self.prepared_limit,
                        &self.tap,
                    )
                    .ok()?;
                    let positions = crate::events::discovery_drain_positions(&self.drain);
                    self.completed_health_frontiers
                        .push((positions.producer, positions.consumer));
                    Some((loss, positions))
                },
                || {
                    clock_reads += 1;
                    let comparable = clock_origins_comparable();
                    if clock_reads != 2 {
                        return comparable;
                    }
                    let cursor = self.drain.source();
                    let metadata = match self.completed_clock_change.take() {
                        Some(CompletedClockChange::Producer) => {
                            cursor.producer.set(cursor.producer.get() + 8);
                            true
                        }
                        Some(CompletedClockChange::Origins {
                            active,
                            children,
                            offsets,
                        }) => clock_origins_comparable_with(
                            active.as_ref(),
                            children.as_ref(),
                            offsets.as_deref(),
                        ),
                        None => true,
                    };
                    self.completed_clock_frontiers
                        .push((cursor.producer.get(), cursor.consumer.get()));
                    comparable && metadata
                },
            ) && !self.stopped()
        }
        pub(crate) fn validate(
            &mut self,
            receipt: &PreservationReceipt,
            binding: &ExecBinding,
            view: &ProcessView,
            serial: u64,
            objects: &PinnedObjects,
        ) -> bool {
            if self.stopped() || !self.origin() {
                return false;
            }
            self.health_phases.push("apply");
            let Ok(loss) = self.read_health() else {
                return false;
            };
            let sides = self.sides();
            let pairs = CurrentPairs {
                book: &self.book,
                links: &self.links,
                sides: &sides,
                retained: &self.retained,
            };
            pairs.validate(
                receipt,
                binding,
                &self.tap,
                &self.tap.0.domain,
                view,
                serial,
                objects,
                loss,
                || Some(crate::events::discovery_drain_positions(&self.drain)),
            )
        }
        pub(crate) fn raw_fault(&mut self) {
            let cursor = self.drain.source();
            cursor.records.borrow_mut().push_back(vec![0]);
            cursor.producer.set(cursor.producer.get() + 1);
            assert!(matches!(
                self.drain.dequeue(),
                Some(crate::events::DiscoveryItem::Malformed)
            ));
            assert!(self.drain.dequeue().is_none());
        }
        pub(crate) fn busy_frontier(&mut self) {
            let cursor = self.drain.source();
            cursor.producer.set(cursor.producer.get() + 8);
            assert!(self.drain.dequeue().is_none());
        }
        pub(crate) fn at_preflight(&mut self) {
            if self.prepared_count == 0 {
                return;
            }
            match self.preflight_change.take() {
                Some(PreflightChange::Producer) => self
                    .drain
                    .source()
                    .producer
                    .set(self.drain.source().producer.get() + 8),
                Some(PreflightChange::Observation) => self.raw_fault(),
                Some(PreflightChange::Health) => {
                    self.owner = self
                        .owner
                        .map(|owner| ThreadOwnerControl { poison: 1, ..owner })
                }
                Some(PreflightChange::Registration) => self.book.invalidate_all(),
                Some(PreflightChange::Stop) => {
                    self.stop_word = p11scope_ebpf_common::STOP_GATE_STOP | 3
                }
                Some(PreflightChange::Clock) => self.clock_offsets = Some("monotonic 1 0".into()),
                Some(PreflightChange::Terminal) => self.tap.invalidate_terminal(),
                Some(PreflightChange::ProducersDetached) => self.producers_detached = true,
                Some(PreflightChange::Exit(pid)) => {
                    let pid = pid as libc::pid_t;
                    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
                    let mut status = 0;
                    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                }
                Some(PreflightChange::Cancel(flag)) => {
                    flag.store(true, std::sync::atomic::Ordering::Relaxed)
                }
                None => (),
            }
        }
        pub(crate) fn observe(&mut self, record: DiscoveryRecord) {
            // DiscoveryRecord is the strict fixed-width wire type. Copy its full
            // bytes into the source consumed by the actual decoder/observer.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&record as *const DiscoveryRecord).cast::<u8>(),
                    std::mem::size_of::<DiscoveryRecord>(),
                )
            }
            .to_vec();
            if !self.origin() {
                self.scripted_read_clocks([None, None]);
            }
            let cursor = self.drain.source();
            cursor.records.borrow_mut().push_back(bytes);
            cursor
                .producer
                .set(cursor.producer.get() + std::mem::size_of::<DiscoveryRecord>());
            assert!(
                matches!(
                    self.drain.dequeue(),
                    Some(crate::events::DiscoveryItem::Record(_))
                ),
                "the positive/finite lifecycle fixture must decode as a genuine Record"
            );
            assert!(self.drain.dequeue().is_none());
        }
    }
}

#[cfg(test)]
mod b3_health_tests {
    use super::*;
    use p11scope_ebpf_common::ThreadOwnerControl;
    #[test]
    fn pid_continuity_checked_owner_health_uses_gauge_and_sticky_faults() {
        let tap = PidLifecycleTap::test_for(1, DiscoveryDomain::test_standin(7));
        let mut health = OwnerHealth::default();
        let mut owner = ThreadOwnerControl {
            limit: 17,
            outstanding: 9,
            ..Default::default()
        };
        assert_eq!(
            health.check(Ok(owner), Ok(4), 17, &tap),
            Ok(4),
            "healthy exact prepared map control grants a checked baseline"
        );
        owner.outstanding = 3;
        assert_eq!(
            health.check(Ok(owner), Ok(4), 17, &tap),
            Ok(4),
            "outstanding is a decreasing gauge"
        );
        let initial = tap.facts().unwrap().fault_serial;
        owner.admission_failures = 1;
        assert!(health.check(Ok(owner), Ok(4), 17, &tap).is_ok());
        assert!(
            tap.facts().unwrap().fault_serial > initial,
            "new cumulative uncertainty invalidates old generations"
        );
        let before = tap.facts().unwrap().fault_serial;
        assert!(
            health
                .check(Err(PidContinuityRefusal::Unavailable), Ok(4), 17, &tap)
                .is_err()
        );
        assert!(
            tap.facts().unwrap().fault_serial > before,
            "an unreadable interval cannot disappear after recovery"
        );
        let unknown_interval = tap.facts().unwrap().fault_serial;
        assert_eq!(health.check(Ok(owner), Ok(4), 17, &tap), Ok(4));
        assert_eq!(
            tap.facts().unwrap().fault_serial,
            unknown_interval,
            "readability recovery retains the fault that invalidated old generations"
        );
        assert_eq!(
            health.check(
                Ok(p11scope_ebpf_common::ThreadOwnerControl {
                    admission_failures: 0,
                    ..owner
                }),
                Ok(4),
                17,
                &tap
            ),
            Err(PidContinuityRefusal::Fault),
            "cumulative counters may not decline like the outstanding gauge"
        );
        assert!(health.check(Ok(owner), Ok(3), 17, &tap).is_err());
        let before_loss = tap.facts().unwrap().fault_serial;
        assert_eq!(health.check(Ok(owner), Ok(5), 17, &tap), Ok(5));
        assert!(
            tap.facts().unwrap().fault_serial > before_loss,
            "fresh transport loss faults the old generation while allowing a later checked recovery baseline"
        );
        owner.poison = 1;
        assert!(health.check(Ok(owner), Ok(4), 17, &tap).is_err());
        owner.poison = 0;
        assert!(
            health.check(Ok(owner), Ok(4), 17, &tap).is_err(),
            "poison is terminal for the frozen maps"
        );
        for bad in [
            ThreadOwnerControl { limit: 16, ..owner },
            ThreadOwnerControl {
                outstanding: 18,
                ..owner
            },
            ThreadOwnerControl {
                abandoned_discovery: u64::MAX,
                ..owner
            },
        ] {
            let mut health = OwnerHealth::default();
            assert!(health.check(Ok(bad), Ok(4), 17, &tap).is_err());
        }
    }
}

#[cfg(test)]
mod gap_tests {
    use super::*;
    #[test]
    fn pid_continuity_physical_gap_boundaries_are_cumulative() {
        let (_dir, pins, target) = tests::fixture();
        let retained = BTreeMap::from([(0, target)]);
        let mut book = PairBook::default();
        let sides = BTreeSet::from([(0, ProbeSide::Return), (0, ProbeSide::Entry)]);
        for (start, complete) in [(10, 30), (100, 150)] {
            book.begin_gap(&BTreeSet::from([0]), Some(start), &retained);
            assert!(
                book.gap_summary().open,
                "first necessary detach must persist before reattachment"
            );
            let links = tests::pair(&mut book);
            book.seal(
                &[AttachRound {
                    slots: vec![0],
                    started_ns: Some(start + 1),
                    last_call_ns: Some(start + 2),
                }],
                Some(AttachBaseline { loss: 0, fault: 0 }),
                Some(0),
                &links,
                &sides,
                &retained,
                || Some(complete),
            );
            assert!(
                book.stamp_for(&retained[&0].slot, &pins, &links, &sides, &retained)
                    .is_some()
            );
            assert!(!book.gap_summary().open);
        }
        assert_eq!(book.gap_summary().episodes, 2);
        assert_eq!(
            book.gap_summary().max_gap_ns,
            Some(50),
            "healthy time between separate episodes must never count as dark time"
        );
        book.begin_gap(&BTreeSet::from([0]), None, &retained);
        assert!(book.gap_summary().unknown);
    }
}
