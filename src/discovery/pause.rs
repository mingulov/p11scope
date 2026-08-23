#![allow(dead_code)] // Task 8 wires this reviewed internal coordinator into the binary loop.

use crate::run::OwnedChild;
use crate::{attach, attach::Session, discovery::engine::Engine};
use p11scope_ebpf_common::{
    COALESCED_NO_HELPER_RC, DISCOVERY_STATUS_COALESCED_NO_HELPER, DiscoveryRecord, PAUSE_ARMED,
    PAUSE_REQUESTED,
};
use std::collections::BTreeMap;
use std::time::Duration;

pub(crate) use crate::events::DiscoveryItem;

const CYCLE_NS: u64 = 100_000_000;
const SAMPLE_NS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PausePolicy {
    Never,
    Auto,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PauseStatus {
    None,
    Sigstop,
    Partial,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PauseCounters {
    pub(crate) attempts: u64,
    pub(crate) confirmed: u64,
    pub(crate) partial: u64,
}

impl PauseCounters {
    fn confirmed(attempts: u64) -> Self {
        Self {
            attempts,
            confirmed: attempts,
            partial: 0,
        }
    }

    fn partial(attempts: u64) -> Self {
        Self {
            attempts,
            confirmed: 0,
            partial: attempts,
        }
    }

    pub(crate) fn status(self) -> PauseStatus {
        match (self.attempts, self.partial) {
            (0, _) => PauseStatus::None,
            (_, 0) => PauseStatus::Sigstop,
            _ => PauseStatus::Partial,
        }
    }

    fn valid(self) -> bool {
        self.confirmed.saturating_add(self.partial) == self.attempts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArmResult {
    Disabled,
    Armed,
}

#[derive(Debug)]
pub(crate) struct PauseError {
    messages: Vec<String>,
    required: bool,
    lifecycle: bool,
}

impl PauseError {
    fn one(message: impl Into<String>, required: bool, lifecycle: bool) -> Self {
        Self {
            messages: vec![message.into()],
            required,
            lifecycle,
        }
    }

    fn from_lifecycle(messages: Vec<String>) -> Self {
        Self {
            messages,
            required: false,
            lifecycle: true,
        }
    }

    pub(crate) fn required(&self) -> bool {
        self.required
    }

    pub(crate) fn lifecycle(&self) -> bool {
        self.lifecycle
    }
}

impl std::fmt::Display for PauseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.messages.join("; "))
    }
}

impl std::error::Error for PauseError {}

/// The coordinator owns policy, not Aya. This fixed-purpose seam is also the
/// complete failure-injection surface: one clock, task reader, discovery owner,
/// authorization map, Engine batch application, marker, pidfd resume, and
/// terminal detach action.
pub(crate) trait PauseIo {
    fn now_ns(&mut self) -> Result<u64, String>;
    fn wait_one_ms(&mut self) -> Result<(), String>;
    fn task_states(&mut self, pid: u32) -> Result<BTreeMap<u32, u8>, String>;
    fn dequeue(&mut self) -> Result<Option<DiscoveryItem>, String>;
    fn arm(&mut self) -> Result<(), String>;
    fn authorization(&mut self) -> Result<Option<u64>, String>;
    fn remove_authorization(&mut self) -> Result<Option<u64>, String>;
    fn apply_batch(&mut self, records: Vec<DiscoveryRecord>) -> Result<(), String>;
    fn marker_seen(&mut self) -> Result<bool, String>;
    fn resume(&mut self) -> Result<(), String>;
    fn detach_pause_links(&mut self) -> Result<(), String>;

    fn same_generation(&mut self, _pid: u32, _generation: u64) -> Result<bool, String> {
        Ok(true)
    }

    fn ring_loss(&mut self) -> Result<u64, String> {
        Ok(0)
    }

    fn cancelled(&mut self) -> Result<bool, String> {
        Ok(false)
    }
}

#[derive(Debug, Default)]
struct PauseEpoch {
    authorization_consumed: bool,
    accepted: bool,
    rejected: bool,
    resume_attempted: bool,
    resume_succeeded: bool,
    successor_installed: bool,
    successor_unresolved: bool,
    protective_resume_attempted: bool,
}

pub(crate) struct PauseCoordinator {
    policy: PausePolicy,
    pid: u32,
    generation: u64,
    expected_tasks: BTreeMap<u32, u8>,
    counters: PauseCounters,
    epoch: PauseEpoch,
    armed: bool,
    rearming_enabled: bool,
    may_be_stopped: bool,
    attempt_open: bool,
    ring_loss_baseline: u64,
    active_deadline: Option<u64>,
    pending_records: Vec<DiscoveryRecord>,
    cycles: u8,
    cleaning: bool,
    cleaned: bool,
}

impl PauseCoordinator {
    pub(crate) fn preflight(
        policy: PausePolicy,
        child: &OwnedChild,
        io: &mut impl PauseIo,
    ) -> Result<Self, PauseError> {
        if policy == PausePolicy::Never {
            return Ok(Self::new(
                policy,
                child.pid(),
                child.generation().get(),
                BTreeMap::new(),
            ));
        }
        child
            .pin()
            .probe_signal_authority()
            .map_err(|error| Self::policy_error(policy, error, true))?;
        let expected_tasks = io
            .task_states(child.pid())
            .map_err(|error| Self::policy_error(policy, error, true))?;
        if expected_tasks.is_empty() || !child.pin().still_the_same() {
            return Err(Self::policy_error(
                policy,
                "owned child generation changed during pause preflight",
                true,
            ));
        }
        Ok(Self::new(
            policy,
            child.pid(),
            child.generation().get(),
            expected_tasks,
        ))
    }

    fn new(
        policy: PausePolicy,
        pid: u32,
        generation: u64,
        expected_tasks: BTreeMap<u32, u8>,
    ) -> Self {
        Self {
            policy,
            pid,
            generation,
            expected_tasks,
            counters: PauseCounters::default(),
            epoch: PauseEpoch::default(),
            armed: false,
            rearming_enabled: policy != PausePolicy::Never,
            may_be_stopped: false,
            attempt_open: false,
            ring_loss_baseline: 0,
            active_deadline: None,
            pending_records: Vec::new(),
            cycles: 0,
            cleaning: false,
            cleaned: false,
        }
    }

    #[cfg(test)]
    fn for_test(
        policy: PausePolicy,
        pid: u32,
        generation: u64,
        expected_tasks: BTreeMap<u32, u8>,
    ) -> Self {
        Self::new(policy, pid, generation, expected_tasks)
    }

    #[cfg(test)]
    fn arm_for_test(&mut self) {
        self.armed = true;
    }

    pub(crate) fn arm(&mut self, io: &mut impl PauseIo) -> Result<ArmResult, PauseError> {
        if self.policy == PausePolicy::Never || !self.rearming_enabled {
            return Ok(ArmResult::Disabled);
        }
        if self.armed {
            return Ok(ArmResult::Armed);
        }
        if !io
            .same_generation(self.pid, self.generation)
            .map_err(|error| Self::policy_error(self.policy, error, true))?
        {
            return self.arm_failed("owned child generation changed before pause arm");
        }
        self.ring_loss_baseline = match io.ring_loss() {
            Ok(loss) => loss,
            Err(error) => return Err(Self::policy_error(self.policy, error, true)),
        };
        if let Err(error) = io.arm() {
            return self.arm_cleanup_failed(io, error, false);
        }
        match io.authorization() {
            Ok(Some(PAUSE_ARMED)) => {
                self.armed = true;
                Ok(ArmResult::Armed)
            }
            Ok(_) => {
                self.arm_cleanup_failed(io, "pause authorization did not read back ARMED", true)
            }
            Err(error) => self.arm_cleanup_failed(io, error, true),
        }
    }

    fn arm_failed(&mut self, message: impl Into<String>) -> Result<ArmResult, PauseError> {
        self.counters.attempts = self.counters.attempts.saturating_add(1);
        self.rearming_enabled = false;
        match self.policy {
            PausePolicy::Auto => {
                self.counters.partial = self.counters.partial.saturating_add(1);
                Ok(ArmResult::Disabled)
            }
            PausePolicy::Always => Err(PauseError::one(message, true, false)),
            PausePolicy::Never => Ok(ArmResult::Disabled),
        }
    }

    fn arm_cleanup_failed(
        &mut self,
        io: &mut impl PauseIo,
        message: impl Into<String>,
        lifecycle: bool,
    ) -> Result<ArmResult, PauseError> {
        self.begin_attempt();
        self.may_be_stopped = true;
        self.epoch.authorization_consumed = true;
        self.fail_cycle(io, message, lifecycle)
            .map(|()| ArmResult::Disabled)
    }

    pub(crate) fn service(&mut self, io: &mut impl PauseIo) -> Result<(), PauseError> {
        if self.policy == PausePolicy::Never {
            return Ok(());
        }
        let received = match self.timed_dequeue(io, None) {
            Ok(received) => received,
            Err(error) => return self.fail_cycle(io, error, true),
        };
        let Some(received) = received else {
            let ring_loss = match io.ring_loss() {
                Ok(loss) => loss,
                Err(error) => return self.fail_cycle(io, error, true),
            };
            if self.armed && ring_loss > self.ring_loss_baseline {
                self.begin_attempt();
                return self.fail_cycle(io, "discovery record reservation loss", false);
            }
            return Ok(());
        };
        match io.cancelled() {
            Ok(false) => {}
            Ok(true) => return self.fail_cycle(io, "pause coordination cancelled", true),
            Err(error) => return self.fail_cycle(io, error, true),
        }
        let DiscoveryItem::Record(first) = received.item else {
            return self.fail_cycle(io, "malformed discovery record in pause epoch", true);
        };
        self.pending_records.push(first);
        if exact_pid(&first) != self.pid {
            return self.fail_cycle(io, "unaccounted discovery record in pause epoch", false);
        }

        if !self.armed {
            if first.send_signal_rc == 0 {
                match io.authorization() {
                    Ok(Some(PAUSE_REQUESTED)) => {
                        self.may_be_stopped = true;
                        return self.fail_cycle(
                            io,
                            "REQUESTED authorization existed without an active epoch",
                            true,
                        );
                    }
                    Ok(_) => self.may_be_stopped = false,
                    Err(error) => return self.fail_cycle(io, error, true),
                }
            }
            return io
                .apply_batch(std::mem::take(&mut self.pending_records))
                .map_err(|error| Self::policy_error(self.policy, error, false));
        }
        let state = match io.authorization() {
            Ok(state) => state,
            Err(error) => return self.fail_cycle(io, error, true),
        };
        if state != Some(PAUSE_REQUESTED) {
            self.may_be_stopped = false;
            return io
                .apply_batch(std::mem::take(&mut self.pending_records))
                .map_err(|error| Self::policy_error(self.policy, error, false));
        }
        self.may_be_stopped = true;
        self.begin_attempt();
        let successor = self.epoch.successor_installed && self.epoch.successor_unresolved;
        if successor && !self.epoch.resume_succeeded {
            return self.fail_cycle(io, "successor was consumed before prior resume", true);
        }
        self.epoch = PauseEpoch {
            authorization_consumed: true,
            ..PauseEpoch::default()
        };

        let mut records = Vec::new();
        let winner = if first.send_signal_rc == COALESCED_NO_HELPER_RC {
            if first.status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER == 0 {
                return self.fail_cycle(io, "unknown coalesced record status", false);
            }
            let provisional = match cycle_deadline(first.hook_ts_ns) {
                Ok(deadline) => deadline,
                Err(error) => return self.fail_cycle(io, error, false),
            };
            if let Err(error) = validate_received(&received, first.hook_ts_ns, provisional) {
                return self.fail_cycle(io, error, false);
            }
            records.push(first);
            loop {
                let next = match self.timed_dequeue(io, Some(provisional)) {
                    Ok(next) => next,
                    Err(error) => return self.fail_cycle(io, error, false),
                };
                let Some(next) = next else {
                    let now = match io.now_ns() {
                        Ok(now) => now,
                        Err(error) => return self.fail_cycle(io, error, true),
                    };
                    if now >= provisional {
                        return self.fail_cycle(io, "coalesced record had no winner", false);
                    }
                    if let Err(error) = io.wait_one_ms() {
                        return self.fail_cycle(io, error, true);
                    }
                    continue;
                };
                let DiscoveryItem::Record(record) = next.item else {
                    return self.fail_cycle(io, "malformed discovery record before winner", false);
                };
                if exact_pid(&record) != self.pid {
                    return self.fail_cycle(
                        io,
                        "unaccounted discovery record before winner",
                        false,
                    );
                }
                if record.send_signal_rc == COALESCED_NO_HELPER_RC {
                    if record.status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER == 0 {
                        return self.fail_cycle(io, "unknown coalesced record status", false);
                    }
                    if let Err(error) = validate_received(&next, record.hook_ts_ns, provisional) {
                        return self.fail_cycle(io, error, false);
                    }
                    records.push(record);
                    self.pending_records.push(record);
                    continue;
                }
                self.pending_records.push(record);
                break (next, record);
            }
        } else {
            (received, first)
        };
        let (winner_received, winner_record) = winner;
        if winner_record.status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER != 0 {
            return self.fail_cycle(io, "winner carried coalesced status", false);
        }
        if winner_record.send_signal_rc == 0 {
            // The record plus REQUESTED proves an accepted request, even if a
            // later timestamp/deadline check makes confirmation impossible.
            self.epoch.accepted = true;
        }
        let deadline = match cycle_deadline(winner_record.hook_ts_ns) {
            Ok(deadline) => deadline,
            Err(error) => return self.fail_cycle(io, error, false),
        };
        self.active_deadline = Some(deadline);
        if let Err(error) = validate_received(&winner_received, winner_record.hook_ts_ns, deadline)
        {
            return self.fail_cycle(io, error, false);
        }
        if records.iter().any(|record| record.hook_ts_ns > deadline) {
            return self.fail_cycle(io, "coalesced record crossed winner deadline", false);
        }
        records.push(winner_record);

        if winner_record.send_signal_rc != 0 {
            self.epoch.rejected = true;
            self.may_be_stopped = false;
            self.pending_records.clear();
            return self.reject_cycle(io, deadline, records);
        }
        self.may_be_stopped = true;
        let ring_loss = match io.ring_loss() {
            Ok(loss) => loss,
            Err(error) => return self.fail_cycle(io, error, true),
        };
        if ring_loss > self.ring_loss_baseline {
            return self.fail_cycle(io, "discovery ring loss in pause epoch", false);
        }

        let first_sample = match self.sample_stopped(io, deadline) {
            Ok(sample) => sample,
            Err(error) => return self.fail_cycle(io, error, false),
        };
        if let Err(error) = io.wait_one_ms() {
            return self.fail_cycle(io, error, true);
        }
        let second_sample = match self.sample_stopped(io, deadline) {
            Ok(sample) => sample,
            Err(error) => return self.fail_cycle(io, error, false),
        };
        if second_sample
            .checked_sub(first_sample)
            .is_none_or(|delta| delta < SAMPLE_NS)
        {
            return self.fail_cycle(io, "stopped snapshots were less than 1 ms apart", false);
        }
        match io.cancelled() {
            Ok(false) => {}
            Ok(true) => return self.fail_cycle(io, "pause coordination cancelled", true),
            Err(error) => return self.fail_cycle(io, error, true),
        }

        loop {
            let received = match self.timed_dequeue(io, Some(deadline)) {
                Ok(received) => received,
                Err(error) => return self.fail_cycle(io, error, false),
            };
            let Some(received) = received else { break };
            let DiscoveryItem::Record(record) = received.item else {
                return self.fail_cycle(io, "malformed discovery record in causal drain", false);
            };
            if exact_pid(&record) != self.pid
                || record.send_signal_rc != COALESCED_NO_HELPER_RC
                || record.status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER == 0
            {
                return self.fail_cycle(io, "duplicate or unaccounted pause record", false);
            }
            if let Err(error) = validate_received(&received, record.hook_ts_ns, deadline) {
                return self.fail_cycle(io, error, false);
            }
            records.push(record);
            self.pending_records.push(record);
        }
        let marker_seen = match io.marker_seen() {
            Ok(seen) => seen,
            Err(error) => return self.fail_cycle(io, error, true),
        };
        if marker_seen {
            return self.fail_cycle(io, "protected marker preceded attachment", false);
        }
        let record_count = records.len();
        self.pending_records.clear();
        if let Err(error) = io.apply_batch(records) {
            return self.fail_cycle(io, error, false);
        }
        if let Err(error) = io.wait_one_ms() {
            return self.fail_cycle(io, error, true);
        }
        if let Err(error) = self.sample_stopped(io, deadline) {
            return self.fail_cycle(io, error, false);
        }
        let marker_seen = match io.marker_seen() {
            Ok(seen) => seen,
            Err(error) => return self.fail_cycle(io, error, true),
        };
        if marker_seen {
            return self.fail_cycle(io, "protected marker raced attachment", false);
        }
        match self.timed_dequeue(io, Some(deadline)) {
            Ok(None) => {}
            Ok(Some(_)) => return self.fail_cycle(io, "queue was not empty before resume", false),
            Err(error) => return self.fail_cycle(io, error, false),
        }

        let install_successor = record_count == 1 && self.cycles == 0 && self.rearming_enabled;
        if install_successor {
            if let Err(error) = io.remove_authorization() {
                return self.fail_cycle(io, error, true);
            }
            if let Err(error) = io.arm() {
                return self.fail_cycle(io, error, true);
            }
            let authorization = match io.authorization() {
                Ok(state) => state,
                Err(error) => return self.fail_cycle(io, error, true),
            };
            if authorization != Some(PAUSE_ARMED) {
                return self.fail_cycle(io, "successor was consumed before prior resume", true);
            }
            self.epoch.successor_installed = true;
            self.epoch.successor_unresolved = true;
            if let Err(error) = io.wait_one_ms() {
                return self.fail_cycle(io, error, true);
            }
            if let Err(error) = self.sample_stopped(io, deadline) {
                return self.fail_cycle(io, error, false);
            }
            match io.marker_seen() {
                Ok(false) => {}
                Ok(true) => return self.fail_cycle(io, "marker raced successor pre-arm", false),
                Err(error) => return self.fail_cycle(io, error, true),
            }
            match self.timed_dequeue(io, Some(deadline)) {
                Ok(None) => {}
                Ok(Some(_)) => {
                    return self.fail_cycle(io, "successor was consumed before prior resume", true);
                }
                Err(error) => return self.fail_cycle(io, error, false),
            }
        } else if let Err(error) = io.remove_authorization() {
            return self.fail_cycle(io, error, true);
        }

        match io.cancelled() {
            Ok(false) => {}
            Ok(true) => return self.fail_cycle(io, "pause coordination cancelled", true),
            Err(error) => return self.fail_cycle(io, error, true),
        }
        self.epoch.resume_attempted = true;
        if let Err(error) = io.resume() {
            return self.fail_cycle(io, error, true);
        }
        self.epoch.resume_succeeded = true;
        self.counters.confirmed = self.counters.confirmed.saturating_add(1);
        self.attempt_open = false;
        self.active_deadline = None;
        self.cycles = self.cycles.saturating_add(1);
        self.armed = install_successor;
        if !install_successor {
            self.may_be_stopped = false;
            self.epoch = PauseEpoch::default();
        } else {
            self.epoch = PauseEpoch {
                successor_installed: true,
                successor_unresolved: true,
                resume_attempted: true,
                resume_succeeded: true,
                ..PauseEpoch::default()
            };
        }
        debug_assert!(self.counters.valid());
        Ok(())
    }

    fn reject_cycle(
        &mut self,
        io: &mut impl PauseIo,
        deadline: u64,
        mut records: Vec<DiscoveryRecord>,
    ) -> Result<(), PauseError> {
        let mut retained_error = None;
        let mut lifecycle_errors = Vec::new();
        loop {
            match self.timed_dequeue(io, Some(deadline)) {
                Ok(None) => match io.now_ns() {
                    Ok(now) if now < deadline => {
                        if let Err(error) = io.wait_one_ms() {
                            retained_error.get_or_insert(error);
                            break;
                        }
                    }
                    Ok(_) => break,
                    Err(error) => {
                        retained_error.get_or_insert(error);
                        break;
                    }
                },
                Ok(Some(TimedItem {
                    item: DiscoveryItem::Record(record),
                    ..
                })) if exact_pid(&record) == self.pid
                    && record.send_signal_rc == COALESCED_NO_HELPER_RC
                    && record.status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER != 0 =>
                {
                    records.push(record);
                }
                Ok(Some(_)) => {
                    retained_error
                        .get_or_insert_with(|| "rejected epoch contained an invalid record".into());
                }
                Err(error) => {
                    retained_error.get_or_insert(error);
                    break;
                }
            }
        }
        if let Err(error) = io.remove_authorization() {
            lifecycle_errors.push(error);
        }
        if let Err(error) = io.apply_batch(records) {
            retained_error.get_or_insert(error);
        }
        match io.same_generation(self.pid, self.generation) {
            Ok(true) => {}
            Ok(false) => lifecycle_errors.push("owned child generation changed".into()),
            Err(error) => lifecycle_errors.push(error),
        }
        self.may_be_stopped = false;
        self.armed = false;
        self.rearming_enabled = false;
        self.epoch = PauseEpoch::default();
        self.active_deadline = None;
        if !lifecycle_errors.is_empty() {
            return Err(PauseError::from_lifecycle(lifecycle_errors));
        }
        self.finish_nonconfirmed(
            retained_error.unwrap_or_else(|| "pause helper rejected SIGSTOP".into()),
        )
    }

    fn sample_stopped(&self, io: &mut impl PauseIo, deadline: u64) -> Result<u64, String> {
        let states = io.task_states(self.pid)?;
        let now = io.now_ns()?;
        if now > deadline {
            return Err("pause confirmation deadline crossed".into());
        }
        if states.keys().ne(self.expected_tasks.keys())
            || states.values().any(|state| *state != b'T')
        {
            return Err("task set changed or was not entirely stopped".into());
        }
        Ok(now)
    }

    fn timed_dequeue(
        &mut self,
        io: &mut impl PauseIo,
        deadline: Option<u64>,
    ) -> Result<Option<TimedItem>, String> {
        let before_ns = io.now_ns()?;
        if deadline.is_some_and(|deadline| before_ns > deadline) {
            return Err("deadline crossed before discovery dequeue".into());
        }
        let item = io.dequeue()?;
        if let Some(DiscoveryItem::Record(record)) = item.as_ref()
            && exact_pid(record) == self.pid
            && record.send_signal_rc == 0
        {
            // A zero helper result is a stop candidate, not proof. This mark
            // deliberately precedes the post-dequeue clock and every map read.
            self.may_be_stopped = true;
        }
        let after_ns = io.now_ns()?;
        if deadline.is_some_and(|deadline| after_ns > deadline) {
            return Err("deadline crossed after discovery dequeue".into());
        }
        if item.is_some() && !io.same_generation(self.pid, self.generation)? {
            return Err("owned child generation changed after discovery decode".into());
        }
        Ok(item.map(|item| TimedItem {
            before_ns,
            after_ns,
            item,
        }))
    }

    fn fail_cycle(
        &mut self,
        io: &mut impl PauseIo,
        message: impl Into<String>,
        mut lifecycle: bool,
    ) -> Result<(), PauseError> {
        let message = message.into();
        let mut errors = vec![message.clone()];
        loop {
            match self.timed_dequeue(io, self.active_deadline) {
                Ok(Some(TimedItem {
                    item: DiscoveryItem::Record(record),
                    ..
                })) => self.pending_records.push(record),
                Ok(Some(TimedItem {
                    item: DiscoveryItem::Malformed,
                    ..
                })) => errors.push("malformed discovery record during failure cleanup".into()),
                Ok(None) => break,
                Err(error) => {
                    errors.push(error);
                    break;
                }
            }
        }
        if let Err(error) = io.apply_batch(std::mem::take(&mut self.pending_records)) {
            errors.push(error);
        }
        match io.authorization() {
            Ok(Some(PAUSE_REQUESTED)) => {
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
                self.begin_attempt();
            }
            Ok(Some(PAUSE_ARMED)) | Ok(None) => {
                if self.epoch.successor_installed && !self.epoch.accepted {
                    self.epoch.successor_unresolved = false;
                    self.may_be_stopped = false;
                }
            }
            Ok(Some(_)) => {
                errors.push("unknown pause authorization state".into());
                lifecycle = true;
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
            }
            Err(error) => {
                errors.push(error);
                lifecycle = true;
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
            }
        }
        if let Err(error) = io.remove_authorization() {
            errors.push(error);
            lifecycle = true;
        }
        self.armed = false;
        self.rearming_enabled = false;
        if self.epoch.accepted && self.may_be_stopped && !self.epoch.resume_attempted {
            self.epoch.resume_attempted = true;
            if let Err(error) = io.resume() {
                errors.push(error);
                return Err(PauseError::from_lifecycle(errors));
            }
            self.epoch.resume_succeeded = true;
            self.may_be_stopped = false;
        } else if !self.epoch.accepted
            && self.may_be_stopped
            && (self.epoch.authorization_consumed
                || (self.epoch.successor_installed
                    && self.epoch.successor_unresolved
                    && self.epoch.resume_succeeded))
            && !self.epoch.protective_resume_attempted
        {
            self.epoch.protective_resume_attempted = true;
            if let Err(error) = io.resume() {
                errors.push(error);
                lifecycle = true;
            } else {
                self.may_be_stopped = false;
            }
        }
        self.epoch = PauseEpoch::default();
        self.active_deadline = None;
        if lifecycle {
            return Err(PauseError::from_lifecycle(errors));
        }
        self.finish_nonconfirmed(message)
    }

    fn finish_nonconfirmed(&mut self, message: String) -> Result<(), PauseError> {
        match self.policy {
            PausePolicy::Auto => {
                self.counters.partial = self.counters.partial.saturating_add(1);
                self.attempt_open = false;
                debug_assert!(self.counters.valid());
                Ok(())
            }
            PausePolicy::Always => Err(PauseError::one(message, true, false)),
            PausePolicy::Never => Ok(()),
        }
    }

    pub(crate) fn cleanup(&mut self, io: &mut impl PauseIo) -> Result<(), PauseError> {
        if self.cleaned || self.cleaning {
            return Ok(());
        }
        self.cleaning = true;
        let mut errors = Vec::new();
        if let Err(error) = io.detach_pause_links() {
            errors.push(error);
        }
        let mut records = std::mem::take(&mut self.pending_records);
        loop {
            match self.timed_dequeue(io, None) {
                Ok(Some(TimedItem {
                    item: DiscoveryItem::Malformed,
                    ..
                })) => {
                    errors.push("malformed discovery record during cleanup".into());
                }
                Ok(Some(TimedItem {
                    item: DiscoveryItem::Record(record),
                    ..
                })) => records.push(record),
                Ok(None) => break,
                Err(error) => {
                    errors.push(error);
                    break;
                }
            }
        }
        if let Err(error) = io.apply_batch(records) {
            errors.push(error);
        }
        match io.authorization() {
            Ok(Some(PAUSE_REQUESTED)) => {
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
                self.epoch.successor_unresolved |= self.epoch.successor_installed;
            }
            Ok(Some(PAUSE_ARMED)) | Ok(None) => {
                if self.epoch.successor_installed && !self.epoch.accepted {
                    self.epoch.successor_unresolved = false;
                    self.may_be_stopped = false;
                }
            }
            Ok(Some(_)) => {
                errors.push("unknown pause authorization state".into());
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
            }
            Err(error) => {
                errors.push(error);
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
            }
        }
        if let Err(error) = io.remove_authorization() {
            errors.push(error);
        }
        self.armed = false;
        if self.epoch.accepted && self.may_be_stopped && !self.epoch.resume_attempted {
            self.epoch.resume_attempted = true;
            if let Err(error) = io.resume() {
                errors.push(error);
            } else {
                self.may_be_stopped = false;
                self.epoch.resume_succeeded = true;
            }
        } else if !self.epoch.accepted
            && self.may_be_stopped
            && (self.epoch.authorization_consumed
                || (self.epoch.successor_installed
                    && self.epoch.successor_unresolved
                    && self.epoch.resume_succeeded))
            && !self.epoch.protective_resume_attempted
        {
            self.epoch.protective_resume_attempted = true;
            if let Err(error) = io.resume() {
                errors.push(error);
            } else {
                self.may_be_stopped = false;
            }
        }
        self.cleaned = true;
        self.cleaning = false;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(PauseError::from_lifecycle(errors))
        }
    }

    pub(crate) fn counters(&self) -> PauseCounters {
        self.counters
    }

    pub(crate) fn status(&self) -> PauseStatus {
        self.counters.status()
    }

    pub(crate) fn is_armed(&self) -> bool {
        self.armed
    }

    pub(crate) fn rearming_enabled(&self) -> bool {
        self.rearming_enabled
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    fn begin_attempt(&mut self) {
        if !self.attempt_open {
            self.counters.attempts = self.counters.attempts.saturating_add(1);
            self.attempt_open = true;
        }
    }

    fn policy_error(
        policy: PausePolicy,
        message: impl Into<String>,
        lifecycle: bool,
    ) -> PauseError {
        PauseError::one(message, policy == PausePolicy::Always, lifecycle)
    }
}

/// Fixed production adapter. It lends the coordinator the existing Session
/// queue/map/link surface and the existing Engine application authority for
/// one service call; it never exposes Aya handles or creates a second scanner.
pub(crate) struct SessionPauseIo<'a> {
    engine: &'a mut Engine,
    session: &'a mut Session,
    child: &'a OwnedChild,
    marker_seen: &'a dyn Fn() -> Result<bool, String>,
    cancelled: &'a dyn Fn() -> Result<bool, String>,
    plan_changed: bool,
    malformed: u64,
}

impl<'a> SessionPauseIo<'a> {
    pub(crate) fn new(
        engine: &'a mut Engine,
        session: &'a mut Session,
        child: &'a OwnedChild,
        marker_seen: &'a dyn Fn() -> Result<bool, String>,
        cancelled: &'a dyn Fn() -> Result<bool, String>,
    ) -> Self {
        Self {
            engine,
            session,
            child,
            marker_seen,
            cancelled,
            plan_changed: false,
            malformed: 0,
        }
    }

    pub(crate) fn plan_changed(&self) -> bool {
        self.plan_changed
    }
}

impl PauseIo for SessionPauseIo<'_> {
    fn now_ns(&mut self) -> Result<u64, String> {
        attach::monotonic_ns().ok_or_else(|| "monotonic clock read failed".into())
    }

    fn wait_one_ms(&mut self) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }

    fn task_states(&mut self, pid: u32) -> Result<BTreeMap<u32, u8>, String> {
        read_task_states(pid)
    }

    fn dequeue(&mut self) -> Result<Option<DiscoveryItem>, String> {
        let item = self
            .session
            .discovery_dequeue()
            .map_err(|error| format!("discovery dequeue failed: {error:#}"))?;
        if matches!(item, Some(DiscoveryItem::Malformed)) {
            self.malformed = self.malformed.saturating_add(1);
        }
        Ok(item)
    }

    fn arm(&mut self) -> Result<(), String> {
        self.session
            .arm_pause()
            .map_err(|error| format!("pause arm failed: {error:#}"))
    }

    fn authorization(&mut self) -> Result<Option<u64>, String> {
        self.session
            .pause_state()
            .map_err(|error| format!("pause authorization read failed: {error:#}"))
    }

    fn remove_authorization(&mut self) -> Result<Option<u64>, String> {
        self.session
            .remove_pause()
            .map_err(|error| format!("pause authorization removal failed: {error:#}"))
    }

    fn apply_batch(&mut self, records: Vec<DiscoveryRecord>) -> Result<(), String> {
        let changed = self
            .engine
            .apply_discovery_batch(self.session, records, std::mem::take(&mut self.malformed))
            .map_err(|error| format!("discovery batch application failed: {error:#}"))?;
        self.plan_changed |= changed;
        Ok(())
    }

    fn marker_seen(&mut self) -> Result<bool, String> {
        (self.marker_seen)()
    }

    fn resume(&mut self) -> Result<(), String> {
        self.child.pin().send_signal(libc::SIGCONT)
    }

    fn detach_pause_links(&mut self) -> Result<(), String> {
        self.session
            .detach_producers()
            .map_err(|error| format!("pause-capable link detach failed: {error:#}"))
    }

    fn same_generation(&mut self, pid: u32, generation: u64) -> Result<bool, String> {
        Ok(self.child.pid() == pid
            && self.child.generation().get() == generation
            && self.child.pin().still_the_same())
    }

    fn ring_loss(&mut self) -> Result<u64, String> {
        self.session
            .counter_snapshot()
            .map(|snapshot| snapshot.ring_loss)
            .map_err(|error| format!("discovery ring-loss read failed: {error:#}"))
    }

    fn cancelled(&mut self) -> Result<bool, String> {
        (self.cancelled)()
    }
}

fn read_task_states(pid: u32) -> Result<BTreeMap<u32, u8>, String> {
    let directory = std::fs::read_dir(format!("/proc/{pid}/task"))
        .map_err(|error| format!("cannot enumerate task set for pid {pid}: {error}"))?;
    let mut states = BTreeMap::new();
    for entry in directory {
        let entry =
            entry.map_err(|error| format!("cannot enumerate task for pid {pid}: {error}"))?;
        let name = entry.file_name();
        let tid: u32 = name
            .to_string_lossy()
            .parse()
            .map_err(|_| format!("invalid task directory for pid {pid}"))?;
        let stat = std::fs::read(entry.path().join("stat"))
            .map_err(|error| format!("cannot read task {tid} state: {error}"))?;
        let state =
            parse_task_state(&stat).ok_or_else(|| format!("cannot parse task {tid} state"))?;
        states.insert(tid, state);
    }
    if states.is_empty() {
        Err(format!("pid {pid} has an empty task set"))
    } else {
        Ok(states)
    }
}

fn parse_task_state(stat: &[u8]) -> Option<u8> {
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    (stat.get(close + 1) == Some(&b' '))
        .then(|| stat.get(close + 2).copied())
        .flatten()
}

struct TimedItem {
    before_ns: u64,
    after_ns: u64,
    item: DiscoveryItem,
}

fn exact_pid(record: &DiscoveryRecord) -> u32 {
    (record.pid_tgid >> 32) as u32
}

fn cycle_deadline(hook_ns: u64) -> Result<u64, String> {
    hook_ns
        .checked_add(CYCLE_NS)
        .ok_or_else(|| "pause deadline overflow".into())
}

fn validate_received(received: &TimedItem, record_ns: u64, deadline: u64) -> Result<(), String> {
    if received.before_ns > deadline || received.after_ns > deadline || record_ns > deadline {
        return Err("pause causal deadline crossed".into());
    }
    if record_ns > received.after_ns {
        return Err("pause record timestamp is in the future".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::{
        COALESCED_NO_HELPER_RC, DISCOVERY_KIND_EXEC, DISCOVERY_STATUS_COALESCED_NO_HELPER,
        DiscoveryRecord, PAUSE_ARMED, PAUSE_REQUESTED,
    };
    use std::collections::{BTreeMap, VecDeque};

    struct FakeIo {
        now: VecDeque<Result<u64, String>>,
        fallback_now: u64,
        states: VecDeque<Result<BTreeMap<u32, u8>, String>>,
        queue: VecDeque<Result<Option<DiscoveryItem>, String>>,
        authorization: Option<u64>,
        marker: bool,
        events: Vec<&'static str>,
        applied: Vec<DiscoveryRecord>,
        fail_detach: bool,
        fail_remove: bool,
        fail_read: bool,
        fail_resume: bool,
        fail_apply: bool,
        fail_wait: bool,
        cancelled: bool,
        same_generation: bool,
        ring_loss: u64,
    }

    impl Default for FakeIo {
        fn default() -> Self {
            Self {
                now: VecDeque::new(),
                fallback_now: 0,
                states: VecDeque::new(),
                queue: VecDeque::new(),
                authorization: None,
                marker: false,
                events: Vec::new(),
                applied: Vec::new(),
                fail_detach: false,
                fail_remove: false,
                fail_read: false,
                fail_resume: false,
                fail_apply: false,
                fail_wait: false,
                cancelled: false,
                same_generation: true,
                ring_loss: 0,
            }
        }
    }

    impl PauseIo for FakeIo {
        fn now_ns(&mut self) -> Result<u64, String> {
            match self.now.pop_front() {
                Some(Ok(now)) => {
                    self.fallback_now = now;
                    Ok(now)
                }
                Some(Err(error)) => Err(error),
                None => {
                    self.fallback_now = self.fallback_now.saturating_add(1);
                    Ok(self.fallback_now)
                }
            }
        }

        fn wait_one_ms(&mut self) -> Result<(), String> {
            self.events.push("wait");
            if self.fail_wait {
                return Err("wait".into());
            }
            self.fallback_now = self.fallback_now.saturating_add(SAMPLE_NS);
            Ok(())
        }

        fn task_states(&mut self, _: u32) -> Result<BTreeMap<u32, u8>, String> {
            self.states.pop_front().unwrap_or_else(|| Ok(stopped()))
        }

        fn dequeue(&mut self) -> Result<Option<DiscoveryItem>, String> {
            self.events.push("dequeue");
            self.queue.pop_front().unwrap_or(Ok(None))
        }

        fn arm(&mut self) -> Result<(), String> {
            self.events.push("arm");
            self.authorization = Some(PAUSE_ARMED);
            Ok(())
        }

        fn authorization(&mut self) -> Result<Option<u64>, String> {
            self.events.push("read");
            if self.fail_read {
                Err("read".into())
            } else {
                Ok(self.authorization)
            }
        }

        fn remove_authorization(&mut self) -> Result<Option<u64>, String> {
            self.events.push("remove");
            if self.fail_remove {
                return Err("remove".into());
            }
            Ok(self.authorization.take())
        }

        fn apply_batch(&mut self, records: Vec<DiscoveryRecord>) -> Result<(), String> {
            self.events.push("apply");
            if self.fail_apply {
                return Err("apply".into());
            }
            self.applied.extend(records);
            Ok(())
        }

        fn marker_seen(&mut self) -> Result<bool, String> {
            Ok(self.marker)
        }

        fn resume(&mut self) -> Result<(), String> {
            self.events.push("resume");
            if self.fail_resume {
                Err("resume".into())
            } else {
                Ok(())
            }
        }

        fn detach_pause_links(&mut self) -> Result<(), String> {
            self.events.push("detach");
            if self.fail_detach {
                Err("detach".into())
            } else {
                Ok(())
            }
        }

        fn same_generation(&mut self, _: u32, _: u64) -> Result<bool, String> {
            Ok(self.same_generation)
        }

        fn ring_loss(&mut self) -> Result<u64, String> {
            Ok(self.ring_loss)
        }

        fn cancelled(&mut self) -> Result<bool, String> {
            Ok(self.cancelled)
        }
    }

    fn stopped() -> BTreeMap<u32, u8> {
        [(41, b'T'), (42, b'T')].into_iter().collect()
    }

    #[test]
    fn task_state_parser_uses_the_final_comm_field_delimiter() {
        assert_eq!(
            parse_task_state(b"41 (name with ) inside) T 1 2 3\n"),
            Some(b'T')
        );
        assert_eq!(parse_task_state(b"missing delimiter"), None);
        let mut child = std::process::Command::new("sleep")
            .arg("1")
            .spawn()
            .unwrap();
        assert!(!read_task_states(child.id()).unwrap().is_empty());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    fn record(ts: u64, rc: i64, coalesced: bool) -> DiscoveryRecord {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.hook_ts_ns = ts;
        record.pid_tgid = 41u64 << 32;
        record.kind = DISCOVERY_KIND_EXEC;
        record.send_signal_rc = rc;
        if coalesced {
            record.status_flags = DISCOVERY_STATUS_COALESCED_NO_HELPER;
        }
        record
    }

    fn successful_io(records: Vec<DiscoveryRecord>) -> FakeIo {
        let mut queue: VecDeque<_> = records
            .into_iter()
            .map(|record| Ok(Some(DiscoveryItem::Record(record))))
            .collect();
        queue.push_back(Ok(None));
        queue.push_back(Ok(None));
        FakeIo {
            now: [10, 11].into_iter().map(Ok).collect(),
            states: VecDeque::from([Ok(stopped()), Ok(stopped()), Ok(stopped())]),
            queue,
            authorization: Some(PAUSE_REQUESTED),
            ..FakeIo::default()
        }
    }

    #[test]
    fn never_has_no_owner_map_signal_or_counter_side_effect() {
        let mut io = FakeIo::default();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Never, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Disabled);
        assert!(io.events.is_empty());
        assert_eq!(coordinator.counters(), PauseCounters::default());
        assert_eq!(coordinator.status(), PauseStatus::None);
    }

    #[test]
    fn preflight_binds_the_real_owned_child_pidfd_generation_and_task_set() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let expected = [(child.pid(), b'S')].into_iter().collect();
        let mut io = FakeIo {
            states: VecDeque::from([Ok(expected)]),
            ..FakeIo::default()
        };

        let coordinator = PauseCoordinator::preflight(PausePolicy::Always, &child, &mut io)
            .expect("the retained real pidfd must authorize preflight");

        assert_eq!(coordinator.pid, child.pid());
        assert_eq!(coordinator.generation(), child.generation().get());
        assert_eq!(
            coordinator.expected_tasks,
            [(child.pid(), b'S')].into_iter().collect()
        );
    }

    #[test]
    fn accepted_zero_requires_requested_epoch_and_is_marked_before_post_dequeue_clock() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters().attempts, 1);
        assert_eq!(coordinator.counters().confirmed, 1);
        assert_eq!(coordinator.status(), PauseStatus::Sigstop);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
        assert_eq!(io.applied.len(), 1);

        let mut ordinary = successful_io(vec![record(10, 0, false)]);
        ordinary.authorization = None;
        let mut no_epoch = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        no_epoch.service(&mut ordinary).unwrap();
        assert_eq!(no_epoch.counters(), PauseCounters::default());
        assert!(!ordinary.events.contains(&"resume"));
    }

    #[test]
    fn confirmation_freezes_task_ids_not_their_pre_stop_states() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let pre_stop = [(41, b'S'), (42, b'R')].into_iter().collect();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, pre_stop);
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
    }

    #[test]
    fn coalesced_outcome_a_uses_one_deadline_one_owner_and_one_resume() {
        let winner = record(10, 0, false);
        let sibling = record(5, COALESCED_NO_HELPER_RC, true);
        let mut io = successful_io(vec![winner, sibling]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();
        assert_eq!(io.applied.len(), 2);
        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
        assert!(!coordinator.is_armed(), "outcome A must not invent owner 2");
    }

    #[test]
    fn coalesced_before_winner_keeps_the_winner_deadline() {
        let winner = record(10, 0, false);
        let sibling = record(5, COALESCED_NO_HELPER_RC, true);
        let mut io = successful_io(vec![sibling, winner]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(io.applied.len(), 2);
        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn successor_is_exactly_one_second_owner_and_never_a_third() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();
        assert!(coordinator.is_armed());
        assert_eq!(io.authorization, Some(PAUSE_ARMED));

        io.authorization = Some(PAUSE_REQUESTED);
        io.queue.extend([
            Ok(Some(DiscoveryItem::Record(record(10, 0, false)))),
            Ok(None),
            Ok(None),
        ]);
        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(2));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            2
        );
        assert!(!coordinator.is_armed());
        assert_eq!(io.authorization, None);
    }

    #[test]
    fn unconsumed_armed_successor_cleanup_does_not_invent_a_protective_resume() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();
        assert_eq!(io.authorization, Some(PAUSE_ARMED));

        coordinator.cleanup(&mut io).unwrap();

        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1,
            "ARMED proves the successor did not request a stop"
        );
        assert_eq!(io.authorization, None);
    }

    #[test]
    fn successor_consumption_before_resume_is_lifecycle_failure_with_one_resume() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.queue
            .push_back(Ok(Some(DiscoveryItem::Record(record(20, 0, false)))));
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
        assert_eq!(io.authorization, None);
    }

    #[test]
    fn cancellation_and_generation_loss_after_decode_protectively_resume() {
        for generation_lost in [false, true] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            io.cancelled = !generation_lost;
            io.same_generation = !generation_lost;
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
            coordinator.arm_for_test();

            let error = coordinator.service(&mut io).unwrap_err();

            assert!(error.lifecycle());
            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                1
            );
            assert_eq!(io.authorization, None);
        }
    }

    #[test]
    fn ordinary_auto_failures_are_sticky_and_disable_rearming_after_safe_resume() {
        for failure in ["tasks", "attach"] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            if failure == "tasks" {
                io.states = VecDeque::from([Ok([(41, b'R'), (42, b'T')].into_iter().collect())]);
            } else {
                io.fail_apply = true;
            }
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(coordinator.counters(), PauseCounters::partial(1));
            assert!(!coordinator.rearming_enabled());
            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                1
            );
            assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Disabled);
        }
    }

    #[test]
    fn malformed_status_duplicate_and_unaccounted_records_all_fail_finitely() {
        let mut wrong_pid = record(20, COALESCED_NO_HELPER_RC, true);
        wrong_pid.pid_tgid = 43u64 << 32;
        for records in [
            vec![record(10, 0, false), record(20, 0, false)],
            vec![record(10, 0, false), wrong_pid],
            vec![
                record(10, 0, false),
                record(20, COALESCED_NO_HELPER_RC, false),
            ],
        ] {
            let mut io = successful_io(records);
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(coordinator.counters(), PauseCounters::partial(1));
            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                1
            );
        }

        let mut marker = successful_io(vec![record(10, 0, false)]);
        marker.marker = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut marker).unwrap();
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(
            marker
                .events
                .iter()
                .filter(|event| **event == "resume")
                .count(),
            1
        );
    }

    #[test]
    fn resume_failure_is_lifecycle_error_and_is_never_retried() {
        let mut io = successful_io(vec![
            record(10, 0, false),
            record(20, COALESCED_NO_HELPER_RC, true),
        ]);
        io.fail_resume = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();
        assert!(error.lifecycle());
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
        let _ = coordinator.cleanup(&mut io);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );

        let mut protective = successful_io(vec![record(10, COALESCED_NO_HELPER_RC, false)]);
        protective.fail_resume = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut protective).unwrap_err();
        assert!(error.lifecycle());
        assert_eq!(coordinator.counters().partial, 0);
        assert_eq!(
            protective
                .events
                .iter()
                .filter(|event| **event == "resume")
                .count(),
            1
        );
        let _ = coordinator.cleanup(&mut protective);
        assert_eq!(
            protective
                .events
                .iter()
                .filter(|event| **event == "resume")
                .count(),
            1
        );
    }

    #[test]
    fn reservation_loss_is_one_finite_unstopped_auto_attempt() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_ARMED),
            ring_loss: 1,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(!io.events.contains(&"resume"));
        assert!(!coordinator.rearming_enabled());
    }

    #[test]
    fn post_insert_map_read_failure_removes_and_protectively_resumes() {
        let mut io = FakeIo {
            fail_read: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());

        let error = coordinator.arm(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(io.authorization, None);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn deadline_checks_wrap_future_and_after_dequeue_fail_without_reset() {
        let mut late = successful_io(vec![record(10, 0, false)]);
        late.now = VecDeque::from([Ok(10), Ok(100_000_011)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut late).unwrap();
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(coordinator.status(), PauseStatus::Partial);
        assert_eq!(
            late.events
                .iter()
                .filter(|event| **event == "resume")
                .count(),
            1
        );

        let mut overflow = successful_io(vec![record(u64::MAX, 0, false)]);
        let mut required = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        required.arm_for_test();
        let error = required.service(&mut overflow).unwrap_err();
        assert!(error.required());
    }

    #[test]
    fn rejected_helper_is_one_partial_attempt_without_sigcont_or_rearm() {
        let mut io = successful_io(vec![record(10, -libc::EPERM as i64, false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(!io.events.contains(&"resume"));
        assert!(!coordinator.is_armed());
        assert!(!coordinator.rearming_enabled());
    }

    #[test]
    fn rejected_helper_map_removal_failure_is_lifecycle_not_partial() {
        let mut io = successful_io(vec![record(10, -libc::EPERM as i64, false)]);
        io.fail_remove = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(coordinator.counters().partial, 0);
        assert!(!io.events.contains(&"resume"));
    }

    #[test]
    fn malformed_requested_cleanup_detaches_drains_removes_and_protectively_resumes() {
        let mut io = FakeIo {
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Malformed)), Ok(None)]),
            authorization: Some(PAUSE_REQUESTED),
            fail_detach: true,
            fail_remove: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();
        let error = coordinator.cleanup(&mut io).unwrap_err();
        assert!(error.lifecycle());
        assert_eq!(
            io.events,
            [
                "detach", "dequeue", "dequeue", "apply", "read", "remove", "resume"
            ],
            "cleanup must retain failures without short-circuiting before resume"
        );
        assert!(
            coordinator.cleanup(&mut io).is_ok(),
            "cleanup must be idempotent"
        );
    }

    #[test]
    fn counters_obey_the_exact_lattice_and_partial_is_sticky() {
        for counters in [
            PauseCounters::default(),
            PauseCounters::confirmed(1),
            PauseCounters::partial(1),
            PauseCounters {
                attempts: 2,
                confirmed: 1,
                partial: 1,
            },
        ] {
            assert_eq!(counters.confirmed + counters.partial, counters.attempts);
            assert_eq!(
                counters.status(),
                match (counters.attempts, counters.partial) {
                    (0, _) => PauseStatus::None,
                    (_, 0) => PauseStatus::Sigstop,
                    _ => PauseStatus::Partial,
                }
            );
        }
    }
}
