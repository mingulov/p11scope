#![allow(dead_code)] // Task 8 wires this reviewed internal coordinator into the binary loop.

use crate::run::OwnedChild;
use crate::{
    attach,
    discovery::engine::{
        DeferredDiscoveryItem, Engine, EngineSession, IncompleteTerminalDrain, TerminalBatch,
    },
};
use p11scope_ebpf_common::{
    COALESCED_NO_HELPER_RC, DISCOVERY_STATUS_COALESCED_NO_HELPER, DiscoveryRecord, PAUSE_ARMED,
    PAUSE_REQUESTED,
};
use std::collections::BTreeMap;
use std::time::Duration;

pub(crate) use crate::events::DiscoveryItem;

const CYCLE_NS: u64 = 100_000_000;
const SAMPLE_NS: u64 = 1_000_000;
const MAX_FAILURE_ITEMS: usize = 128;

/// One source of truth for the policy: the coordinator uses the exact type the
/// CLI parses, so a spelling can never mean one thing at the command line and
/// another here. Re-used, not re-exported: `discovery::pause` stays
/// crate-private.
pub(crate) use crate::cli::PausePolicy;

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

    fn many(messages: Vec<String>, required: bool, lifecycle: bool) -> Self {
        Self {
            messages,
            required,
            lifecycle,
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
    fn apply_batch(
        &mut self,
        records: Vec<DiscoveryRecord>,
        deadline: Option<u64>,
        additions_allowed: bool,
        pause_owned: bool,
        terminal_batch: &mut Option<TerminalBatch>,
    ) -> Result<PauseBatchOutcome, String>;
    fn revalidate_after_release(
        &mut self,
        pause_owned: bool,
    ) -> Result<PauseRevalidationOutcome, String>;
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

    fn take_stop_candidate_seen(&mut self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PauseBatchOutcome {
    pub(crate) required_complete: bool,
}

#[allow(clippy::large_enum_variant)] // The frozen 896-byte item stays allocation-free in transfer.
pub(crate) enum PauseRevalidationOutcome {
    Complete(PauseBatchOutcome),
    Deferred(TimedItem),
}

#[derive(Debug, Default)]
struct PauseEpoch {
    authorization_consumed: bool,
    zero_candidate: bool,
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
    failure_deadline: Option<u64>,
    failure_items: usize,
    pending_records: Vec<DiscoveryRecord>,
    terminal_batch: Option<TerminalBatch>,
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
            failure_deadline: None,
            failure_items: 0,
            pending_records: Vec::new(),
            terminal_batch: None,
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
        let same_generation = match io.same_generation(self.pid, self.generation) {
            Ok(same) => same,
            Err(error) => {
                self.begin_attempt();
                return self
                    .fail_cycle(io, error, true)
                    .map(|()| ArmResult::Disabled);
            }
        };
        if !same_generation {
            return self.arm_failed(io, "owned child generation changed before pause arm");
        }
        self.ring_loss_baseline = match io.ring_loss() {
            Ok(loss) => loss,
            Err(error) => {
                self.begin_attempt();
                return self
                    .fail_cycle(io, error, true)
                    .map(|()| ArmResult::Disabled);
            }
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

    pub(crate) fn revalidate_after_release(
        &mut self,
        io: &mut impl PauseIo,
    ) -> Result<(), PauseError> {
        loop {
            let pause_owned = self.armed || self.attempt_open || self.may_be_stopped;
            match io.revalidate_after_release(pause_owned) {
                Ok(PauseRevalidationOutcome::Deferred(received)) if pause_owned => {
                    self.service_received(io, received)?;
                }
                Ok(PauseRevalidationOutcome::Deferred(_)) => {
                    return Err(Self::policy_error(
                        self.policy,
                        "ordinary revalidation returned a pause-owned discovery item",
                        true,
                    ));
                }
                Ok(PauseRevalidationOutcome::Complete(outcome))
                    if outcome.required_complete || !pause_owned =>
                {
                    return Ok(());
                }
                Ok(PauseRevalidationOutcome::Complete(_)) => {
                    self.begin_attempt();
                    return self.fail_cycle(
                        io,
                        "post-release loader revalidation did not close required discovery",
                        false,
                    );
                }
                Err(error) if !pause_owned => {
                    return Err(Self::policy_error(self.policy, error, true));
                }
                Err(error) => {
                    self.begin_attempt();
                    return self.fail_cycle(io, error, false);
                }
            }
        }
    }

    fn arm_failed(
        &mut self,
        io: &mut impl PauseIo,
        message: impl Into<String>,
    ) -> Result<ArmResult, PauseError> {
        let message = message.into();
        self.counters.attempts = self.counters.attempts.saturating_add(1);
        self.rearming_enabled = false;
        match self.policy {
            PausePolicy::Auto => {
                self.counters.partial = self.counters.partial.saturating_add(1);
                Ok(ArmResult::Disabled)
            }
            PausePolicy::Always => self
                .terminal_cleanup_with_cause(io, vec![message], true, false)
                .map(|()| ArmResult::Disabled),
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
        self.service_received(io, received)
    }

    fn service_received(
        &mut self,
        io: &mut impl PauseIo,
        received: TimedItem,
    ) -> Result<(), PauseError> {
        let mut received = received;
        if let Some(batch) = received.terminal_batch.take() {
            if self.terminal_batch.is_some() {
                return Err(Self::policy_error(
                    self.policy,
                    "more than one terminal discovery batch reached the coordinator",
                    true,
                ));
            }
            self.terminal_batch = Some(batch);
        }
        self.take_stop_candidate_seen(io);
        self.failure_deadline
            .get_or_insert_with(|| received.after_ns.checked_add(CYCLE_NS).unwrap_or(u64::MAX));
        match io.cancelled() {
            Ok(false) => {}
            Ok(true) => return self.fail_cycle(io, "pause coordination cancelled", true),
            Err(error) => return self.fail_cycle(io, error, true),
        }
        let DiscoveryItem::Record(first) = received.item else {
            self.begin_attempt();
            return self.fail_cycle(io, "malformed discovery record in pause epoch", false);
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
                .apply_batch(
                    std::mem::take(&mut self.pending_records),
                    None,
                    true,
                    false,
                    &mut self.terminal_batch,
                )
                .map(|_| ())
                .map_err(|error| Self::policy_error(self.policy, error, false));
        }
        let state = match io.authorization() {
            Ok(state) => state,
            Err(error) => return self.fail_cycle(io, error, true),
        };
        if state != Some(PAUSE_REQUESTED) {
            if self.epoch.zero_candidate {
                self.begin_attempt();
                return self.fail_cycle(
                    io,
                    "zero stop candidate did not retain REQUESTED authorization",
                    false,
                );
            }
            self.may_be_stopped = false;
            return io
                .apply_batch(
                    std::mem::take(&mut self.pending_records),
                    None,
                    true,
                    false,
                    &mut self.terminal_batch,
                )
                .map(|_| ())
                .map_err(|error| Self::policy_error(self.policy, error, false));
        }
        self.may_be_stopped = true;
        self.begin_attempt();
        let successor = self.epoch.successor_installed && self.epoch.successor_unresolved;
        if successor && !self.epoch.resume_succeeded {
            return self.fail_cycle(io, "successor was consumed before prior resume", true);
        }
        let zero_candidate = self.epoch.zero_candidate;
        self.epoch = PauseEpoch {
            authorization_consumed: true,
            zero_candidate,
            ..PauseEpoch::default()
        };

        let mut records = Vec::new();
        let winner = if first.send_signal_rc == COALESCED_NO_HELPER_RC {
            self.failure_items = 1;
            if first.status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER == 0 {
                return self.fail_cycle(io, "unknown coalesced record status", false);
            }
            let provisional = match cycle_deadline(first.hook_ts_ns) {
                Ok(deadline) => deadline,
                Err(error) => return self.fail_cycle(io, error, false),
            };
            self.active_deadline = Some(provisional);
            if let Err(error) = validate_received(&received, first.hook_ts_ns, provisional) {
                return self.fail_cycle(io, error, false);
            }
            records.push(first);
            loop {
                if self.failure_items >= MAX_FAILURE_ITEMS {
                    return self.fail_cycle(
                        io,
                        "coalesced record had no winner within the item budget",
                        false,
                    );
                }
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
                    self.failure_items += 1;
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
        if winner_record.send_signal_rc < 0 {
            self.epoch.rejected = true;
            self.epoch.zero_candidate = false;
            self.may_be_stopped = false;
            self.pending_records.clear();
            let deadline = cycle_deadline(winner_record.hook_ts_ns)
                .unwrap_or_else(|_| self.failure_deadline.unwrap_or(u64::MAX));
            self.active_deadline = Some(deadline);
            records.push(winner_record);
            return self.reject_cycle(io, deadline, records);
        }
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
            return self.fail_cycle(io, "winner carried an unknown helper result", false);
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
        if let Err(error) = self.check_ring_loss(io) {
            return self.fail_cycle(io, error, false);
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
        let outcome = match io.apply_batch(
            records,
            Some(deadline),
            true,
            true,
            &mut self.terminal_batch,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.take_stop_candidate_seen(io);
                return self.fail_cycle(io, error, false);
            }
        };
        if !outcome.required_complete {
            return self.fail_cycle(io, "one or more frozen required attachments failed", false);
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
        let mut successor_baseline = None;
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
            successor_baseline = match io.ring_loss() {
                Ok(loss) => Some(loss),
                Err(error) => return self.fail_cycle(io, error, true),
            };
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
        if let Err(error) = self.check_ring_loss(io) {
            return self.fail_cycle(io, error, false);
        }
        self.epoch.resume_attempted = true;
        if let Err(error) = io.resume() {
            return self.fail_cycle(io, error, true);
        }
        self.epoch.resume_succeeded = true;
        self.counters.confirmed = self.counters.confirmed.saturating_add(1);
        self.attempt_open = false;
        self.active_deadline = None;
        self.failure_deadline = None;
        self.failure_items = 0;
        self.cycles = self.cycles.saturating_add(1);
        self.armed = install_successor;
        if !install_successor {
            self.may_be_stopped = false;
            self.epoch = PauseEpoch::default();
        } else {
            self.ring_loss_baseline = successor_baseline
                .expect("an installed successor froze its stopped ring-loss baseline");
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

    fn check_ring_loss(&mut self, io: &mut impl PauseIo) -> Result<(), String> {
        let loss = io.ring_loss()?;
        if loss > self.ring_loss_baseline {
            Err("discovery ring loss in pause epoch".into())
        } else {
            Ok(())
        }
    }

    fn reject_cycle(
        &mut self,
        io: &mut impl PauseIo,
        deadline: u64,
        mut records: Vec<DiscoveryRecord>,
    ) -> Result<(), PauseError> {
        if self.policy == PausePolicy::Always {
            self.pending_records.append(&mut records);
            return self.terminal_cleanup_with_cause(
                io,
                vec!["pause helper rejected SIGSTOP".into()],
                true,
                false,
            );
        }
        let mut retained_error = None;
        let mut lifecycle_errors = Vec::new();
        if let Err(error) = io.remove_authorization() {
            lifecycle_errors.push(error);
        }
        self.armed = false;
        while self.failure_items < MAX_FAILURE_ITEMS {
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
                    self.failure_items += 1;
                    records.push(record);
                }
                Ok(Some(_)) => {
                    self.failure_items += 1;
                    retained_error
                        .get_or_insert_with(|| "rejected epoch contained an invalid record".into());
                }
                Err(error) => {
                    retained_error.get_or_insert(error);
                    break;
                }
            }
        }
        if let Err(error) = io.apply_batch(
            records,
            Some(deadline),
            true,
            true,
            &mut self.terminal_batch,
        ) {
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
        self.active_deadline = None;
        self.failure_deadline = None;
        self.failure_items = 0;
        if !lifecycle_errors.is_empty() {
            self.pending_records.clear();
            return self.terminal_cleanup_with_errors(io, lifecycle_errors);
        }
        self.epoch = PauseEpoch::default();
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
            self.epoch.zero_candidate = true;
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
            terminal_batch: None,
        }))
    }

    fn fail_cycle(
        &mut self,
        io: &mut impl PauseIo,
        message: impl Into<String>,
        lifecycle: bool,
    ) -> Result<(), PauseError> {
        let message = message.into();
        self.rearming_enabled = false;
        if lifecycle || self.policy == PausePolicy::Always {
            return self.terminal_cleanup_with_cause(
                io,
                vec![message],
                !lifecycle && self.policy == PausePolicy::Always,
                lifecycle,
            );
        }
        let mut errors = vec![message.clone()];
        let deadline = self.failure_bound(io, &mut errors);
        while self.failure_items < MAX_FAILURE_ITEMS {
            match self.timed_dequeue(io, Some(deadline)) {
                Ok(Some(TimedItem {
                    item: DiscoveryItem::Record(record),
                    ..
                })) => {
                    self.failure_items += 1;
                    self.pending_records.push(record);
                }
                Ok(Some(TimedItem {
                    item: DiscoveryItem::Malformed,
                    ..
                })) => {
                    self.failure_items += 1;
                    errors.push("malformed discovery record during failure cleanup".into());
                }
                Ok(None) => break,
                Err(error) => {
                    errors.push(error);
                    break;
                }
            }
        }
        if let Err(error) = io.apply_batch(
            std::mem::take(&mut self.pending_records),
            Some(deadline),
            true,
            self.armed || self.attempt_open || self.may_be_stopped,
            &mut self.terminal_batch,
        ) {
            errors.push(error);
        }
        self.take_stop_candidate_seen(io);
        match io.authorization() {
            Ok(Some(PAUSE_REQUESTED)) => {
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
                self.begin_attempt();
            }
            Ok(Some(PAUSE_ARMED)) | Ok(None) => {
                if !self.epoch.zero_candidate && !self.epoch.accepted {
                    self.epoch.successor_unresolved = false;
                    self.may_be_stopped = false;
                    self.epoch.authorization_consumed = false;
                }
            }
            Ok(Some(_)) => {
                errors.push("unknown pause authorization state".into());
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
                return self.terminal_cleanup_with_errors(io, errors);
            }
            Err(error) => {
                errors.push(error);
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
                return self.terminal_cleanup_with_errors(io, errors);
            }
        }
        if let Err(error) = io.remove_authorization() {
            errors.push(error);
            return self.terminal_cleanup_with_errors(io, errors);
        }
        self.armed = false;
        self.rearming_enabled = false;
        if self.epoch.accepted && self.may_be_stopped && !self.epoch.resume_attempted {
            self.epoch.resume_attempted = true;
            if let Err(error) = io.resume() {
                errors.push(error);
                return self.terminal_cleanup_with_errors(io, errors);
            }
            self.epoch.resume_succeeded = true;
            self.may_be_stopped = false;
        } else if !self.epoch.accepted
            && !self.epoch.rejected
            && self.may_be_stopped
            && (self.epoch.authorization_consumed
                || self.epoch.zero_candidate
                || (self.epoch.successor_installed
                    && self.epoch.successor_unresolved
                    && self.epoch.resume_succeeded))
            && !self.epoch.protective_resume_attempted
        {
            self.epoch.protective_resume_attempted = true;
            if let Err(error) = io.resume() {
                errors.push(error);
                return self.terminal_cleanup_with_errors(io, errors);
            } else {
                self.may_be_stopped = false;
            }
        }
        self.epoch = PauseEpoch::default();
        self.active_deadline = None;
        self.failure_deadline = None;
        self.failure_items = 0;
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
        self.terminal_cleanup(io)
    }

    fn terminal_cleanup(&mut self, io: &mut impl PauseIo) -> Result<(), PauseError> {
        self.terminal_cleanup_with_cause(io, Vec::new(), false, false)
    }

    fn terminal_cleanup_with_errors(
        &mut self,
        io: &mut impl PauseIo,
        errors: Vec<String>,
    ) -> Result<(), PauseError> {
        self.terminal_cleanup_with_cause(io, errors, false, true)
    }

    fn terminal_cleanup_with_cause(
        &mut self,
        io: &mut impl PauseIo,
        mut errors: Vec<String>,
        required: bool,
        lifecycle: bool,
    ) -> Result<(), PauseError> {
        if self.cleaned || self.cleaning {
            return if errors.is_empty() {
                Ok(())
            } else {
                Err(PauseError::many(errors, required, lifecycle))
            };
        }
        let initiating_errors = errors.len();
        self.cleaning = true;
        if let Err(error) = io.detach_pause_links() {
            errors.push(error);
        }
        let mut records = std::mem::take(&mut self.pending_records);
        let deadline = self.failure_bound(io, &mut errors);
        while self.failure_items < MAX_FAILURE_ITEMS {
            match self.timed_dequeue(io, Some(deadline)) {
                Ok(Some(TimedItem {
                    item: DiscoveryItem::Malformed,
                    ..
                })) => {
                    self.failure_items += 1;
                    errors.push("malformed discovery record during cleanup".into());
                }
                Ok(Some(TimedItem {
                    item: DiscoveryItem::Record(record),
                    ..
                })) => {
                    self.failure_items += 1;
                    records.push(record);
                }
                Ok(None) => break,
                Err(error) => {
                    errors.push(error);
                    break;
                }
            }
        }
        if let Err(error) = io.apply_batch(
            records,
            Some(deadline),
            false,
            self.armed || self.attempt_open || self.may_be_stopped,
            &mut self.terminal_batch,
        ) {
            errors.push(error);
        }
        self.take_stop_candidate_seen(io);
        match io.authorization() {
            Ok(Some(PAUSE_REQUESTED)) => {
                if self.epoch.rejected {
                    self.may_be_stopped = false;
                    self.epoch.authorization_consumed = false;
                } else {
                    self.may_be_stopped = true;
                    self.epoch.authorization_consumed = true;
                    self.epoch.successor_unresolved |= self.epoch.successor_installed;
                }
            }
            Ok(Some(PAUSE_ARMED)) | Ok(None) => {
                if !self.epoch.zero_candidate && !self.epoch.accepted {
                    self.epoch.successor_unresolved = false;
                    self.may_be_stopped = false;
                    self.epoch.authorization_consumed = false;
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
            && !self.epoch.rejected
            && self.may_be_stopped
            && (self.epoch.authorization_consumed
                || self.epoch.zero_candidate
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
            let cleanup_failed = errors.len() > initiating_errors;
            Err(PauseError::many(
                errors,
                required,
                lifecycle || cleanup_failed,
            ))
        }
    }

    fn failure_bound(&mut self, io: &mut impl PauseIo, errors: &mut Vec<String>) -> u64 {
        if let Some(deadline) = self.active_deadline.or(self.failure_deadline) {
            self.failure_deadline = Some(deadline);
            return deadline;
        }
        let now = match io.now_ns() {
            Ok(now) => now,
            Err(error) => {
                errors.push(error);
                u64::MAX.saturating_sub(CYCLE_NS)
            }
        };
        let deadline = now.checked_add(CYCLE_NS).unwrap_or(u64::MAX);
        self.failure_deadline = Some(deadline);
        deadline
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

    fn take_stop_candidate_seen(&mut self, io: &mut impl PauseIo) {
        let seen = io.take_stop_candidate_seen();
        self.epoch.zero_candidate |= seen;
        self.may_be_stopped |= seen;
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
    session: &'a mut dyn EngineSession,
    child: &'a OwnedChild,
    marker_seen: &'a dyn Fn() -> Result<bool, String>,
    cancelled: &'a dyn Fn() -> Result<bool, String>,
    plan_changed: bool,
    malformed: u64,
    stop_candidate_seen: bool,
}

impl<'a> SessionPauseIo<'a> {
    pub(crate) fn new(
        engine: &'a mut Engine,
        session: &'a mut dyn EngineSession,
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
            stop_candidate_seen: false,
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

    fn apply_batch(
        &mut self,
        records: Vec<DiscoveryRecord>,
        deadline: Option<u64>,
        additions_allowed: bool,
        pause_owned: bool,
        terminal_batch: &mut Option<TerminalBatch>,
    ) -> Result<PauseBatchOutcome, String> {
        let child = self.child;
        let stop_candidate_seen = &mut self.stop_candidate_seen;
        let mut collect = |session: &mut dyn EngineSession| {
            collect_timed_retirement(session, child, deadline, stop_candidate_seen, pause_owned)
        };
        let terminal_dispatch = terminal_batch.is_some();
        if let Some(batch) = terminal_batch.take()
            && let Err(error) = self
                .engine
                .install_terminal_batch(batch.clone(), records.clone())
        {
            *terminal_batch = Some(batch);
            return Err(format!(
                "terminal discovery batch restore failed: {error:#}"
            ));
        }
        let records = terminal_dispatch.then(Vec::new).unwrap_or(records);
        let outcome = match self.engine.apply_discovery_batch_with(
            self.session,
            records,
            std::mem::take(&mut self.malformed),
            additions_allowed,
            terminal_dispatch,
            &mut collect,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                let error = match error.downcast::<DeferredDiscoveryItem>() {
                    Ok(mut deferred) => {
                        *terminal_batch = deferred.terminal_batch.take();
                        return Err(format!("discovery batch application failed: {deferred:#}"));
                    }
                    Err(error) => error,
                };
                if terminal_dispatch {
                    *terminal_batch = Some(
                        self.engine
                            .take_terminal_batch_for_deferred()
                            .map_err(|error| {
                                format!("terminal discovery batch restore failed: {error:#}")
                            })?,
                    );
                }
                return Err(format!("discovery batch application failed: {error:#}"));
            }
        };
        self.plan_changed |= outcome.changed;
        Ok(PauseBatchOutcome {
            required_complete: outcome.required_complete,
        })
    }

    fn revalidate_after_release(
        &mut self,
        pause_owned: bool,
    ) -> Result<PauseRevalidationOutcome, String> {
        let child = self.child;
        let stop_candidate_seen = &mut self.stop_candidate_seen;
        let mut collect = |session: &mut dyn EngineSession| {
            collect_timed_retirement(session, child, None, stop_candidate_seen, pause_owned)
        };
        let outcome =
            match self
                .engine
                .revalidate_owned_session_with(self.child, self.session, &mut collect)
            {
                Ok(outcome) => outcome,
                Err(error) => match error.downcast::<DeferredDiscoveryItem>() {
                    Ok(deferred) => {
                        return Ok(PauseRevalidationOutcome::Deferred(TimedItem {
                            before_ns: deferred.before_ns,
                            after_ns: deferred.after_ns,
                            item: deferred.item,
                            terminal_batch: deferred.terminal_batch,
                        }));
                    }
                    Err(error) => {
                        return Err(format!("owned-child revalidation failed: {error:#}"));
                    }
                },
            };
        self.plan_changed |= outcome.changed;
        Ok(PauseRevalidationOutcome::Complete(PauseBatchOutcome {
            required_complete: outcome.required_complete,
        }))
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

    fn take_stop_candidate_seen(&mut self) -> bool {
        std::mem::take(&mut self.stop_candidate_seen)
    }
}

fn collect_timed_retirement(
    session: &mut dyn EngineSession,
    child: &OwnedChild,
    deadline: Option<u64>,
    stop_candidate_seen: &mut bool,
    pause_owned: bool,
) -> Result<(Vec<DiscoveryRecord>, u64), anyhow::Error> {
    collect_timed_retirement_with(
        child.pid(),
        deadline,
        stop_candidate_seen,
        pause_owned,
        || attach::monotonic_ns().ok_or_else(|| anyhow::anyhow!("monotonic clock read failed")),
        || session.discovery_dequeue(),
        || child.pin().still_the_same(),
    )
}

fn collect_timed_retirement_with(
    child_pid: u32,
    deadline: Option<u64>,
    stop_candidate_seen: &mut bool,
    pause_owned: bool,
    mut now_ns: impl FnMut() -> Result<u64, anyhow::Error>,
    mut dequeue: impl FnMut() -> Result<Option<DiscoveryItem>, anyhow::Error>,
    mut same_generation: impl FnMut() -> bool,
) -> Result<(Vec<DiscoveryRecord>, u64), anyhow::Error> {
    let mut records = Vec::new();
    let mut malformed = 0u64;
    loop {
        let before_ns = match now_ns() {
            Ok(now) => now,
            Err(error) => {
                return Err(IncompleteTerminalDrain::new(records, malformed, error).into());
            }
        };
        if deadline.is_some_and(|deadline| before_ns > deadline) {
            return Err(IncompleteTerminalDrain::new(
                records,
                malformed,
                anyhow::anyhow!("deadline crossed before nested discovery dequeue"),
            )
            .into());
        }
        let item = match dequeue() {
            Ok(item) => item,
            Err(error) => {
                return Err(IncompleteTerminalDrain::new(records, malformed, error).into());
            }
        };
        if let Some(DiscoveryItem::Record(record)) = item.as_ref()
            && pause_owned
            && exact_pid(record) == child_pid
            && record.send_signal_rc == 0
        {
            *stop_candidate_seen = true;
        }
        let after_ns = match now_ns() {
            Ok(now) => now,
            Err(error) => {
                match item {
                    Some(DiscoveryItem::Record(record)) => records.push(record),
                    Some(DiscoveryItem::Malformed) => malformed = malformed.saturating_add(1),
                    None => {}
                }
                return Err(IncompleteTerminalDrain::new(records, malformed, error).into());
            }
        };
        if deadline.is_some_and(|deadline| after_ns > deadline) {
            match item {
                Some(DiscoveryItem::Record(record)) => records.push(record),
                Some(DiscoveryItem::Malformed) => malformed = malformed.saturating_add(1),
                None => {}
            }
            return Err(IncompleteTerminalDrain::new(
                records,
                malformed,
                anyhow::anyhow!("deadline crossed after nested discovery dequeue"),
            )
            .into());
        }
        let Some(item) = item else { break };
        if !same_generation() {
            match item {
                DiscoveryItem::Record(record) => records.push(record),
                DiscoveryItem::Malformed => malformed = malformed.saturating_add(1),
            }
            return Err(IncompleteTerminalDrain::new(
                records,
                malformed,
                anyhow::anyhow!("owned child generation changed after nested discovery decode"),
            )
            .into());
        }
        if pause_owned && deadline.is_none() {
            return Err(DeferredDiscoveryItem {
                before_ns,
                after_ns,
                item,
                terminal_batch: None,
            }
            .into());
        }
        match item {
            DiscoveryItem::Malformed => {
                malformed = malformed.saturating_add(1);
                return Ok((records, malformed));
            }
            DiscoveryItem::Record(record) => {
                // The record already left the ring, so it belongs to the
                // retained prefix before any validation may reject it.
                records.push(record);
                if let Some(deadline) = deadline {
                    let received = TimedItem {
                        before_ns,
                        after_ns,
                        item: DiscoveryItem::Record(record),
                        terminal_batch: None,
                    };
                    if let Err(error) = validate_received(&received, record.hook_ts_ns, deadline) {
                        return Err(IncompleteTerminalDrain::new(
                            records,
                            malformed,
                            anyhow::Error::msg(error),
                        )
                        .into());
                    }
                    if exact_pid(&record) != child_pid
                        || record.send_signal_rc != COALESCED_NO_HELPER_RC
                        || record.status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER == 0
                    {
                        return Err(IncompleteTerminalDrain::new(
                            records,
                            malformed,
                            anyhow::anyhow!("duplicate or unaccounted nested pause record"),
                        )
                        .into());
                    }
                }
            }
        }
    }
    Ok((records, malformed))
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

pub(crate) struct TimedItem {
    before_ns: u64,
    after_ns: u64,
    item: DiscoveryItem,
    terminal_batch: Option<TerminalBatch>,
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
    if received.after_ns < received.before_ns {
        return Err("monotonic dequeue clocks were reversed".into());
    }
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
    use crate::attach::DynamicExportIdentity;
    use crate::discovery::engine::TerminalAuthority;
    use crate::discovery::engine::session_fixture::ScriptedSession;
    use crate::discovery::hooks::HookAbi;
    use crate::discovery::identity::PinnedObjectId;
    use crate::discovery::loader::LoaderContextId;
    use p11scope_ebpf_common::{
        COALESCED_NO_HELPER_RC, DISCOVERY_KIND_EXEC, DISCOVERY_KIND_LOADER,
        DISCOVERY_STATUS_COALESCED_NO_HELPER, DiscoveryRecord, PAUSE_ARMED, PAUSE_REQUESTED,
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
        required_complete: bool,
        fail_wait: bool,
        cancelled: bool,
        same_generation: bool,
        ring_losses: VecDeque<Result<u64, String>>,
        fallback_ring_loss: u64,
        revalidation_required_complete: bool,
        revalidation_consumes_winner: bool,
        revalidation_item: Option<DiscoveryItem>,
        revalidation_deferred: Option<TimedItem>,
        revalidation_error: Option<String>,
        retirement_stop_candidate_seen: bool,
        revalidation_pause_owned: Vec<bool>,
        apply_pause_owned: Vec<bool>,
        terminal_batches: Vec<TerminalBatch>,
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
                required_complete: true,
                fail_wait: false,
                cancelled: false,
                same_generation: true,
                ring_losses: VecDeque::new(),
                fallback_ring_loss: 0,
                revalidation_required_complete: true,
                revalidation_consumes_winner: false,
                revalidation_item: None,
                revalidation_deferred: None,
                revalidation_error: None,
                retirement_stop_candidate_seen: false,
                revalidation_pause_owned: Vec::new(),
                apply_pause_owned: Vec::new(),
                terminal_batches: Vec::new(),
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

        fn apply_batch(
            &mut self,
            records: Vec<DiscoveryRecord>,
            _deadline: Option<u64>,
            additions_allowed: bool,
            pause_owned: bool,
            terminal_batch: &mut Option<TerminalBatch>,
        ) -> Result<PauseBatchOutcome, String> {
            self.events.push(if additions_allowed {
                "apply"
            } else {
                "account"
            });
            if self.fail_apply && additions_allowed {
                return Err("apply".into());
            }
            self.apply_pause_owned.push(pause_owned);
            if let Some(batch) = terminal_batch.take() {
                self.terminal_batches.push(batch);
            }
            self.applied.extend(records);
            Ok(PauseBatchOutcome {
                required_complete: self.required_complete,
            })
        }

        fn revalidate_after_release(
            &mut self,
            pause_owned: bool,
        ) -> Result<PauseRevalidationOutcome, String> {
            self.events.push("revalidate");
            self.revalidation_pause_owned.push(pause_owned);
            if let Some(error) = self.revalidation_error.take() {
                return Err(error);
            }
            if let Some(deferred) = self.revalidation_deferred.take() {
                return Ok(PauseRevalidationOutcome::Deferred(deferred));
            }
            if let Some(item) = self.revalidation_item.take() {
                if pause_owned {
                    self.authorization = Some(PAUSE_REQUESTED);
                    self.revalidation_consumes_winner = matches!(
                        &item,
                        DiscoveryItem::Record(record) if record.send_signal_rc == 0
                    );
                    return Ok(PauseRevalidationOutcome::Deferred(TimedItem {
                        before_ns: 1,
                        after_ns: 2,
                        item,
                        terminal_batch: None,
                    }));
                } else if let DiscoveryItem::Record(record) = item {
                    self.applied.push(record);
                }
            }
            Ok(PauseRevalidationOutcome::Complete(PauseBatchOutcome {
                required_complete: self.revalidation_required_complete,
            }))
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
            match self.ring_losses.pop_front() {
                Some(Ok(loss)) => {
                    self.fallback_ring_loss = loss;
                    Ok(loss)
                }
                Some(Err(error)) => Err(error),
                None => Ok(self.fallback_ring_loss),
            }
        }

        fn cancelled(&mut self) -> Result<bool, String> {
            Ok(self.cancelled)
        }

        fn take_stop_candidate_seen(&mut self) -> bool {
            let seen = self.revalidation_consumes_winner || self.retirement_stop_candidate_seen;
            self.revalidation_consumes_winner = false;
            self.retirement_stop_candidate_seen = false;
            seen
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

    fn collect_owned_retirement_for_test(
        item: DiscoveryItem,
        post_clock: Result<u64, anyhow::Error>,
        same_generation: bool,
    ) -> (Result<(Vec<DiscoveryRecord>, u64), anyhow::Error>, bool) {
        let mut clocks = VecDeque::from([Ok(1), post_clock]);
        let mut item = Some(item);
        let mut stop_candidate_seen = false;
        let result = collect_timed_retirement_with(
            41,
            None,
            &mut stop_candidate_seen,
            true,
            || clocks.pop_front().expect("one before and one after clock"),
            || Ok(item.take()),
            || same_generation,
        );
        (result, stop_candidate_seen)
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
            fallback_ring_loss: 1,
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
    fn rejected_helper_is_classified_before_all_timestamp_failures() {
        let cases = [
            (u64::MAX, VecDeque::new()),
            (10, VecDeque::from([Ok(100_000_011), Ok(100_000_012)])),
            (100, VecDeque::from([Ok(50), Ok(60)])),
            (10, VecDeque::from([Ok(20), Ok(19)])),
        ];
        for (timestamp, now) in cases {
            let mut io = successful_io(vec![record(timestamp, -libc::EPERM as i64, false)]);
            if !now.is_empty() {
                io.now = now;
            }
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(coordinator.counters(), PauseCounters::partial(1));
            assert!(!io.events.contains(&"resume"));
            assert_eq!(io.authorization, None);
        }
    }

    #[test]
    fn required_failure_uses_terminal_detach_before_accounting_and_resume() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.fail_apply = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.required());
        let detach = io
            .events
            .iter()
            .position(|event| *event == "detach")
            .unwrap();
        let resume = io
            .events
            .iter()
            .position(|event| *event == "resume")
            .unwrap();
        assert!(detach < resume);
        assert_eq!(
            io.events.iter().filter(|event| **event == "detach").count(),
            1
        );
    }

    #[test]
    fn real_incomplete_batch_outcome_cannot_confirm_the_pause() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.required_complete = false;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(coordinator.counters().confirmed, 0);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn post_release_revalidation_remains_owned_by_the_pause_ledger() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_ARMED),
            revalidation_required_complete: false,
            revalidation_consumes_winner: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.revalidate_after_release(&mut io).unwrap();

        assert_eq!(io.events.first(), Some(&"revalidate"));
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(io.authorization, None);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1,
            "the coordinator ledger owns the consumed winner's protective resume"
        );
    }

    #[test]
    fn completed_owner_debt_does_not_resume_an_unconsumed_successor() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_ARMED),
            revalidation_required_complete: false,
            revalidation_item: Some(DiscoveryItem::Record(record(1, 0, false))),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.revalidate_after_release(&mut io).unwrap();

        assert_eq!(io.revalidation_pause_owned, [true, true]);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1,
            "owner 1 debt must not invent a resume for the ARMED successor"
        );
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 2,
                confirmed: 1,
                partial: 1,
            }
        );
        assert!(coordinator.counters().valid());
        assert_eq!(io.authorization, None);
        assert!(!coordinator.is_armed());
        assert!(!coordinator.rearming_enabled());
    }

    #[test]
    fn post_release_zero_before_post_clock_failure_protectively_resumes() {
        let (result, stop_candidate_seen) = collect_owned_retirement_for_test(
            DiscoveryItem::Record(record(10, 0, false)),
            Err(anyhow::anyhow!("post-clock")),
            true,
        );
        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("the injected post-dequeue clock must fail"),
        };
        assert!(stop_candidate_seen);
        let mut io = FakeIo {
            authorization: Some(PAUSE_ARMED),
            revalidation_error: Some(error),
            retirement_stop_candidate_seen: stop_candidate_seen,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.revalidate_after_release(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(coordinator.counters().valid());
        assert_eq!(io.authorization, None);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn post_release_zero_before_generation_failure_protectively_resumes() {
        let (result, stop_candidate_seen) = collect_owned_retirement_for_test(
            DiscoveryItem::Record(record(10, 0, false)),
            Ok(2),
            false,
        );
        let error = match result {
            Err(error) => error.to_string(),
            Ok(_) => panic!("the injected generation check must fail"),
        };
        assert!(stop_candidate_seen);
        let mut io = FakeIo {
            revalidation_error: Some(error),
            retirement_stop_candidate_seen: stop_candidate_seen,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.revalidate_after_release(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(coordinator.counters().valid());
        assert_eq!(io.authorization, None);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn post_release_zero_before_classification_cancellation_protectively_resumes() {
        let (result, stop_candidate_seen) = collect_owned_retirement_for_test(
            DiscoveryItem::Record(record(10, 0, false)),
            Ok(2),
            true,
        );
        let deferred = match result {
            Err(error) => error
                .downcast::<DeferredDiscoveryItem>()
                .expect("owned revalidation must transfer the already-clocked item"),
            Ok(_) => panic!("owned revalidation must defer coordinator classification"),
        };
        assert!(stop_candidate_seen);
        let mut io = FakeIo {
            cancelled: true,
            revalidation_deferred: Some(TimedItem {
                before_ns: deferred.before_ns,
                after_ns: deferred.after_ns,
                item: deferred.item,
                terminal_batch: deferred.terminal_batch,
            }),
            retirement_stop_candidate_seen: stop_candidate_seen,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.revalidate_after_release(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(coordinator.counters(), PauseCounters::default());
        assert!(coordinator.counters().valid());
        assert_eq!(io.authorization, None);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn post_release_negative_helper_is_classified_before_failure_cleanup() {
        let rejected = record(10, i64::from(-libc::EPERM), false);
        let mut io = FakeIo {
            authorization: Some(PAUSE_ARMED),
            revalidation_required_complete: false,
            revalidation_item: Some(DiscoveryItem::Record(rejected)),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.revalidate_after_release(&mut io).unwrap();

        assert_eq!(io.revalidation_pause_owned, [true, false]);
        assert_eq!(io.applied.len(), 1);
        assert_eq!(io.applied[0].send_signal_rc, rejected.send_signal_rc);
        assert_eq!(io.authorization, None);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            0,
            "a real negative helper cannot create a protective resume obligation"
        );
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(coordinator.counters().valid());
    }

    #[test]
    fn never_revalidation_uses_only_the_ordinary_retirement_route() {
        let ordinary = record(10, 0, false);
        let mut io = FakeIo {
            revalidation_required_complete: false,
            revalidation_item: Some(DiscoveryItem::Record(ordinary)),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Never, 41, 9, stopped());

        coordinator.revalidate_after_release(&mut io).unwrap();

        assert_eq!(io.revalidation_pause_owned, [false]);
        assert_eq!(io.applied.len(), 1);
        assert_eq!(io.applied[0].send_signal_rc, ordinary.send_signal_rc);
        assert_eq!(io.events, ["revalidate"]);
        assert_eq!(io.authorization, None);
        assert_eq!(coordinator.counters(), PauseCounters::default());
        assert!(coordinator.counters().valid());
    }

    #[test]
    fn classification_transfers_a_terminal_batch_to_its_cleanup_application() {
        let owner = crate::discovery::loader::LoaderContextId::from_case_id(1);
        let mut batch = TerminalBatch::empty(TerminalAuthority {
            owner,
            exports: Vec::new(),
        });
        batch.extend([record(10, -libc::EPERM as i64, false)]);
        let mut io = FakeIo::default();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Never, 41, 9, stopped());

        coordinator
            .service_received(
                &mut io,
                TimedItem {
                    before_ns: 1,
                    after_ns: 2,
                    item: DiscoveryItem::Record(record(10, -libc::EPERM as i64, false)),
                    terminal_batch: Some(batch),
                },
            )
            .unwrap();

        assert_eq!(io.apply_pause_owned, [false]);
        assert_eq!(io.terminal_batches.len(), 1);
        assert_eq!(io.terminal_batches[0].authority.owner, owner);
        assert_eq!(io.terminal_batches[0].record_count(), 1);
    }

    #[test]
    fn failed_classification_application_keeps_the_terminal_batch_for_retry() {
        let owner = crate::discovery::loader::LoaderContextId::from_case_id(1);
        let mut batch = TerminalBatch::empty(TerminalAuthority {
            owner,
            exports: Vec::new(),
        });
        batch.extend([record(10, -libc::EPERM as i64, false)]);
        let mut io = FakeIo {
            fail_apply: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Never, 41, 9, stopped());

        let error = coordinator
            .service_received(
                &mut io,
                TimedItem {
                    before_ns: 1,
                    after_ns: 2,
                    item: DiscoveryItem::Record(record(10, -libc::EPERM as i64, false)),
                    terminal_batch: Some(batch),
                },
            )
            .unwrap_err();

        assert_eq!(error.to_string(), "apply");
        assert!(io.terminal_batches.is_empty());
        assert_eq!(
            coordinator
                .terminal_batch
                .as_ref()
                .map(|batch| batch.authority.owner),
            Some(owner)
        );
    }

    fn terminal_export() -> DynamicExportIdentity {
        DynamicExportIdentity {
            object: PinnedObjectId(7),
            file_offset: 0x10,
            cookie: 1,
            abi: HookAbi::FunctionList,
        }
    }

    fn loader_record_for(context: LoaderContextId, pid: u32) -> DiscoveryRecord {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_LOADER;
        record.case_id = (context.get() - 1) as u8;
        record.pid_tgid = u64::from(pid) << 32;
        record
    }

    fn queued(context: LoaderContextId, pid: u32) -> Result<Option<DiscoveryItem>, anyhow::Error> {
        Ok(Some(DiscoveryItem::Record(loader_record_for(context, pid))))
    }

    /// One turn of the real production adapter over the real Engine.
    fn with_session_io<T>(
        engine: &mut Engine,
        session: &mut ScriptedSession,
        child: &OwnedChild,
        body: impl FnOnce(&mut SessionPauseIo<'_>) -> T,
    ) -> T {
        let marker = || -> Result<bool, String> { Ok(false) };
        let cancelled = || -> Result<bool, String> { Ok(false) };
        let mut io = SessionPauseIo::new(engine, session, child, &marker, &cancelled);
        body(&mut io)
    }

    /// The real `SessionPauseIo` collector loses the ring mid-drain. Every
    /// record it already removed stays with the tombstoned authority, and the
    /// next adapter turn finishes and dispatches that exact batch once.
    #[test]
    fn an_incomplete_real_drain_retains_its_prefix_and_is_continued_through_the_adapter() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        session.dequeues.extend([
            queued(owner, child.pid()),
            Err(anyhow::anyhow!("scripted ring read failed")),
        ]);

        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut None)
                .expect("a failed terminal drain is loss, never a batch error")
        });

        let batch = engine
            .terminal_batch_for_test()
            .expect("the exact prefix stays with its authority");
        assert_eq!(
            batch.record_count(),
            1,
            "a record already off the ring stays in the retained prefix"
        );
        assert!(!batch.complete());
        assert_eq!(batch.tagged_owners(), [Some(owner)]);
        assert_eq!(batch.authority.owner, owner);
        assert_eq!(batch.authority.exports, [terminal_export()]);
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert_eq!(
            engine.loader_context_state_for_test(owner),
            Some("tombstoned")
        );

        session.dequeues.push_back(queued(unrelated, child.pid()));
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut None)
                .expect("the continued drain completes")
        });

        assert_eq!(
            engine.dispatched_loader_records(),
            2,
            "the continuation dispatched the whole batch exactly once"
        );
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
    }

    /// The coordinator/adapter round trip: a real counter failure hands the
    /// exact owner, export snapshot and tagged records back to the coordinator,
    /// and the one retry installs and dispatches that batch exactly once.
    #[test]
    fn the_coordinator_round_trips_the_exact_terminal_owner_and_exports() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        session.dequeues.extend([
            queued(unrelated, child.pid()),
            Err(anyhow::anyhow!("scripted ring read failed")),
        ]);
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut None)
                .expect("a failed terminal drain is loss, never a batch error")
        });
        let carried = engine
            .take_terminal_batch_for_deferred()
            .expect("a deferral hands the exact batch to the coordinator");
        let mut coordinator = PauseCoordinator::for_test(
            PausePolicy::Never,
            child.pid(),
            child.generation().get(),
            stopped(),
        );

        session.fail_counter_reads([true]);
        let error = with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator
                .service_received(
                    io,
                    TimedItem {
                        before_ns: 1,
                        after_ns: 2,
                        item: DiscoveryItem::Record(loader_record_for(owner, child.pid())),
                        terminal_batch: Some(carried),
                    },
                )
                .unwrap_err()
        });

        assert!(
            error
                .to_string()
                .contains("discovery batch application failed"),
            "{error}"
        );
        let retained = coordinator
            .terminal_batch
            .as_ref()
            .expect("the coordinator keeps the exact batch for its one retry");
        assert_eq!(retained.authority.owner, owner);
        assert_eq!(retained.authority.exports, [terminal_export()]);
        assert_eq!(
            retained.tagged_owners(),
            [None, Some(owner)],
            "only the owned record carries terminal authority"
        );
        assert!(retained.complete());
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert_eq!(
            engine.loader_context_state_for_test(owner),
            Some("tombstoned")
        );

        with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator
                .service_received(
                    io,
                    TimedItem {
                        before_ns: 3,
                        after_ns: 4,
                        item: DiscoveryItem::Record(loader_record_for(unrelated, child.pid())),
                        terminal_batch: None,
                    },
                )
                .expect("the retry applies the restored batch")
        });

        assert!(coordinator.terminal_batch.is_none());
        assert_eq!(
            engine.dispatched_loader_records(),
            3,
            "install, take and restore dispatch the whole batch exactly once"
        );
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
    }

    /// The real `revalidate_after_release` collector runs deadline-less and
    /// unowned: it retains its records instead of raising a pause deferral no
    /// pause owner could classify.
    #[test]
    fn ordinary_revalidation_through_the_real_adapter_never_defers() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        session.dequeues.extend([
            queued(owner, child.pid()),
            Err(anyhow::anyhow!("scripted ring read failed")),
            Err(anyhow::anyhow!("scripted ring read failed again")),
        ]);
        let mut coordinator = PauseCoordinator::for_test(
            PausePolicy::Never,
            child.pid(),
            child.generation().get(),
            stopped(),
        );

        with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator
                .revalidate_after_release(io)
                .expect("an ordinary revalidation never returns a pause deferral")
        });

        let batch = engine
            .terminal_batch_for_test()
            .expect("the ordinary collector kept its record");
        assert_eq!(batch.record_count(), 1);
        assert_eq!(batch.tagged_owners(), [Some(owner)]);
        assert!(!batch.complete());
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert_eq!(coordinator.counters(), PauseCounters::default());
        assert!(!coordinator.is_armed());
    }

    #[test]
    fn ordinary_revalidation_rejects_a_pause_owned_deferral() {
        let mut io = FakeIo {
            revalidation_deferred: Some(TimedItem {
                before_ns: 1,
                after_ns: 2,
                item: DiscoveryItem::Record(record(10, 0, false)),
                terminal_batch: None,
            }),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Never, 41, 9, stopped());

        let error = coordinator.revalidate_after_release(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert!(error.to_string().contains("ordinary revalidation"));
        assert_eq!(io.revalidation_pause_owned, [false]);
        assert_eq!(io.events, ["revalidate"]);
    }

    #[test]
    fn disabled_auto_revalidation_keeps_the_single_arm_failure_attempt() {
        let mut io = FakeIo {
            same_generation: false,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Disabled);
        io.same_generation = true;
        io.revalidation_item = Some(DiscoveryItem::Record(record(10, 0, false)));

        coordinator.revalidate_after_release(&mut io).unwrap();

        assert_eq!(io.revalidation_pause_owned, [false]);
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(coordinator.counters().valid());
        assert!(!io.events.contains(&"resume"));
    }

    #[test]
    fn disabled_auto_revalidation_error_is_lifecycle_without_pause_side_effects() {
        let mut io = FakeIo {
            same_generation: false,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Disabled);
        let counters = coordinator.counters();
        io.same_generation = true;
        io.revalidation_error = Some("dynamic loader attachment invariant failed".into());

        let error = coordinator.revalidate_after_release(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert!(!error.required());
        assert_eq!(coordinator.counters(), counters);
        assert!(coordinator.counters().valid());
        assert_eq!(io.revalidation_pause_owned, [false]);
        assert_eq!(io.events, ["revalidate"]);
        assert_eq!(io.authorization, None);
    }

    #[test]
    fn ordinary_retirement_zero_never_creates_pause_debt() {
        let mut clocks = VecDeque::from([Ok(1), Ok(2), Ok(3), Ok(4)]);
        let mut items = VecDeque::from([
            Ok(Some(DiscoveryItem::Record(record(10, 0, false)))),
            Ok(None),
        ]);
        let mut stop_candidate_seen = false;

        let (records, malformed) = collect_timed_retirement_with(
            41,
            None,
            &mut stop_candidate_seen,
            false,
            || clocks.pop_front().expect("two clocks per dequeue"),
            || items.pop_front().expect("one item then empty"),
            || true,
        )
        .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(malformed, 0);
        assert!(!stop_candidate_seen);
    }

    #[test]
    fn terminal_collection_reports_the_dequeued_prefix_on_post_dequeue_failure() {
        let mut clocks = VecDeque::from([Ok(1), Err(anyhow::anyhow!("post-clock"))]);
        let mut items = VecDeque::from([Ok(Some(DiscoveryItem::Record(record(10, 0, false))))]);
        let mut stop_candidate_seen = false;

        let error = match collect_timed_retirement_with(
            41,
            Some(100),
            &mut stop_candidate_seen,
            true,
            || clocks.pop_front().expect("clock for queued record"),
            || items.pop_front().expect("queued record"),
            || true,
        ) {
            Err(error) => error,
            Ok(_) => panic!("post-dequeue clock failure must retain the collected prefix"),
        };

        assert!(
            error
                .to_string()
                .contains("1 terminal record retained for retry"),
            "{error:#}"
        );
        let retained = error.downcast::<IncompleteTerminalDrain>().unwrap();
        assert_eq!(retained.records.len(), 1);
        assert_eq!(retained.records[0].hook_ts_ns, 10);
        assert_eq!(retained.malformed, 0);
    }

    /// Every post-dequeue terminal failure owns the item it already removed
    /// from the ring: generation loss, record-timing validation, and the
    /// duplicate/unaccounted check must all report it in the retained prefix.
    #[test]
    fn every_post_dequeue_terminal_failure_retains_the_current_item() {
        let retained_by =
            |deadline: Option<u64>, item: DiscoveryItem, record_ns: u64, same_generation: bool| {
                let mut clocks = VecDeque::from([Ok(1), Ok(2)]);
                let mut items = VecDeque::from([Ok(Some(item))]);
                let mut stop_candidate_seen = false;
                let error = match collect_timed_retirement_with(
                    41,
                    deadline,
                    &mut stop_candidate_seen,
                    true,
                    || clocks.pop_front().expect("clock for queued record"),
                    || items.pop_front().expect("queued record"),
                    || same_generation,
                ) {
                    Err(error) => error,
                    Ok(_) => panic!("a post-dequeue terminal failure must retain the prefix"),
                };
                let _ = record_ns;
                error
                    .downcast::<IncompleteTerminalDrain>()
                    .expect("the terminal route reports an incomplete drain")
            };

        let generation = retained_by(None, DiscoveryItem::Record(record(1, 0, false)), 1, false);
        assert_eq!(generation.records.len(), 1);
        assert_eq!(generation.records[0].hook_ts_ns, 1);
        assert_eq!(generation.malformed, 0);

        let malformed_generation = retained_by(None, DiscoveryItem::Malformed, 0, false);
        assert!(malformed_generation.records.is_empty());
        assert_eq!(malformed_generation.malformed, 1);

        let timing = retained_by(
            Some(100),
            DiscoveryItem::Record(record(50, COALESCED_NO_HELPER_RC, true)),
            50,
            true,
        );
        assert_eq!(timing.records.len(), 1);
        assert_eq!(timing.records[0].hook_ts_ns, 50);

        let unaccounted = retained_by(
            Some(100),
            DiscoveryItem::Record(record(1, 0, false)),
            1,
            true,
        );
        assert_eq!(unaccounted.records.len(), 1);
        assert_eq!(unaccounted.records[0].hook_ts_ns, 1);
        assert!(
            unaccounted.to_string().contains("duplicate or unaccounted"),
            "{unaccounted:#}"
        );
    }

    #[test]
    fn required_prearm_generation_failure_uses_the_terminal_route() {
        let mut io = FakeIo {
            same_generation: false,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());

        let error = coordinator.arm(&mut io).unwrap_err();

        assert!(error.required());
        assert_eq!(io.events.first(), Some(&"detach"));
        assert!(!io.events.contains(&"resume"));
    }

    #[test]
    fn terminal_preserves_required_failure_and_cleanup_errors() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.fail_apply = true;
        io.fail_detach = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.required());
        assert!(error.lifecycle());
        assert!(error.to_string().contains("apply"));
        assert!(error.to_string().contains("detach"));
        assert!(io.events.contains(&"account"));
        assert!(io.events.contains(&"remove"));
        assert!(io.events.contains(&"resume"));
    }

    #[test]
    fn terminal_preserves_rejected_helper_and_cleanup_errors() {
        let mut io = successful_io(vec![record(10, -libc::EPERM as i64, false)]);
        io.fail_detach = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.required());
        assert!(error.lifecycle());
        assert!(error.to_string().contains("rejected SIGSTOP"));
        assert!(error.to_string().contains("detach"));
        assert!(io.events.contains(&"account"));
        assert!(io.events.contains(&"remove"));
    }

    #[test]
    fn terminal_preserves_required_prearm_and_cleanup_errors() {
        let mut io = FakeIo {
            same_generation: false,
            fail_detach: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());

        let error = coordinator.arm(&mut io).unwrap_err();

        assert!(error.required());
        assert!(error.lifecycle());
        assert!(error.to_string().contains("generation changed"));
        assert!(error.to_string().contains("detach"));
        assert!(io.events.contains(&"account"));
        assert!(io.events.contains(&"remove"));
    }

    #[test]
    fn ring_loss_is_rechecked_after_drain_and_immediately_before_resume() {
        for losses in [
            VecDeque::from([Ok(0), Ok(0), Ok(1)]),
            VecDeque::from([Ok(0), Ok(0), Ok(0), Ok(1)]),
        ] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            io.ring_losses = losses;
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.ring_loss_baseline = io.ring_loss().unwrap();
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(coordinator.counters(), PauseCounters::partial(1));
            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                1
            );
        }
    }

    #[test]
    fn no_winner_failure_cleanup_has_one_fixed_item_budget() {
        let sibling = record(10, COALESCED_NO_HELPER_RC, true);
        let mut io = successful_io(Vec::new());
        io.queue = std::iter::repeat_n(Ok(Some(DiscoveryItem::Record(sibling))), 500)
            .chain(std::iter::once(Ok(None)))
            .collect();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert!(
            io.events
                .iter()
                .filter(|event| **event == "dequeue")
                .count()
                <= 128
        );
        assert_eq!(io.authorization, None);
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
    }

    #[test]
    fn initial_armed_or_absent_clears_only_unconsumed_resume_debt() {
        for authorization in [Some(PAUSE_ARMED), None] {
            let mut io = FakeIo {
                authorization,
                ..FakeIo::default()
            };
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.begin_attempt();
            coordinator.may_be_stopped = true;
            coordinator.epoch.authorization_consumed = true;

            coordinator.cleanup(&mut io).unwrap();

            assert!(!io.events.contains(&"resume"));
        }

        let mut io = successful_io(vec![record(10, 0, false)]);
        io.authorization = Some(PAUSE_ARMED);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();
        coordinator.cleanup(&mut io).unwrap();
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn malformed_auto_epoch_is_partial_not_lifecycle() {
        let mut io = FakeIo {
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Malformed)), Ok(None)]),
            authorization: Some(PAUSE_REQUESTED),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
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
                "detach", "dequeue", "dequeue", "account", "read", "remove", "resume"
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
