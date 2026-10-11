//! SPDX-License-Identifier: GPL-3.0-or-later
//! Session-private physical pair facts. These facts cannot spare an Engine
//! replacement; request-bound validation belongs to the later Engine service.

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
            return;
        };
        if self.exhausted {
            return;
        }
        for round in rounds {
            let Some(started_ns) = round.started_ns.filter(|start| *start != 0) else {
                continue;
            };
            let Some(last_call_ns) = round.last_call_ns.filter(|last| *last >= started_ns) else {
                continue;
            };
            // Both concrete sides are already in the registry before this sample.
            let Some(completed_ns) =
                completed_at().filter(|end| *end > started_ns && *end >= last_call_ns)
            else {
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

fn current_pair(
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
        Self::new(NonZeroU32::new(pid).unwrap(), domain)
    }

    #[cfg(test)]
    pub(crate) fn test_facts(&self) -> Result<LifecycleFacts, PidContinuityRefusal> {
        self.facts()
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
