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

const CYCLE_NS: u64 = 500_000_000;
const SAMPLE_NS: u64 = 1_000_000;
const MAX_FAILURE_ITEMS: usize = 128;
const MSG_ARM_FAILED: &str = "owned child generation changed before pause arm";
const MSG_POST_RELEASE_REVALIDATION_INCOMPLETE: &str =
    "post-release loader revalidation did not close required discovery";
const MSG_PAUSE_HELPER_REJECTED: &str = "pause helper rejected SIGSTOP";
const MSG_NESTED_DEADLINE_BEFORE: &str = "deadline crossed before nested discovery dequeue";
const MSG_NESTED_DEADLINE_AFTER: &str = "deadline crossed after nested discovery dequeue";
const MSG_DEADLINE_BEFORE_DEQUEUE: &str = "deadline crossed before discovery dequeue";
const MSG_DEADLINE_AFTER_DEQUEUE: &str = "deadline crossed after discovery dequeue";
const MSG_PAUSE_CONFIRMATION_DEADLINE: &str = "pause confirmation deadline crossed";
const MSG_PAUSE_RESUME_DEADLINE: &str = "pause resume observation deadline crossed";
const MSG_PAUSE_CAUSAL_DEADLINE: &str = "pause causal deadline crossed";
const MSG_COALESCED_RECORD_DEADLINE: &str = "coalesced record crossed winner deadline";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PauseDiagnostic {
    ArmFailedBeforeEpoch,
    PostReleaseRevalidationIncomplete,
    PauseHelperRejected,
    DeadlineBeforeEngineApply,
    DeadlineDuringEngineApply,
    EngineIncompleteWithinDeadline,
    NestedCollectorDeadline,
    LaterPauseBoundary,
    OtherAutoNonconfirmed,
}

impl PauseDiagnostic {
    fn token(self) -> &'static str {
        match self {
            Self::ArmFailedBeforeEpoch => "arm_failed_before_epoch",
            Self::PostReleaseRevalidationIncomplete => "post_release_revalidation_incomplete",
            Self::PauseHelperRejected => "pause_helper_rejected",
            Self::DeadlineBeforeEngineApply => "deadline_before_engine_apply",
            Self::DeadlineDuringEngineApply => "deadline_during_engine_apply",
            Self::EngineIncompleteWithinDeadline => "engine_incomplete_within_deadline",
            Self::NestedCollectorDeadline => "nested_collector_deadline",
            Self::LaterPauseBoundary => "later_pause_boundary",
            Self::OtherAutoNonconfirmed => "other_auto_nonconfirmed",
        }
    }
}

fn render_pause_diagnostic(diagnostic: PauseDiagnostic) -> String {
    format!(
        "p11scope: pause: partial [pause_diag={}]",
        diagnostic.token()
    )
}

fn diagnostic_for_message(message: &str) -> Option<PauseDiagnostic> {
    match message {
        MSG_ARM_FAILED => Some(PauseDiagnostic::ArmFailedBeforeEpoch),
        MSG_POST_RELEASE_REVALIDATION_INCOMPLETE => {
            Some(PauseDiagnostic::PostReleaseRevalidationIncomplete)
        }
        MSG_PAUSE_HELPER_REJECTED => Some(PauseDiagnostic::PauseHelperRejected),
        MSG_NESTED_DEADLINE_BEFORE | MSG_NESTED_DEADLINE_AFTER => {
            Some(PauseDiagnostic::NestedCollectorDeadline)
        }
        _ if message == MSG_DEADLINE_BEFORE_DEQUEUE
            || message == MSG_DEADLINE_AFTER_DEQUEUE
            || message == MSG_PAUSE_CONFIRMATION_DEADLINE
            || message == MSG_PAUSE_RESUME_DEADLINE
            || message == MSG_PAUSE_CAUSAL_DEADLINE
            || message == MSG_COALESCED_RECORD_DEADLINE =>
        {
            Some(PauseDiagnostic::LaterPauseBoundary)
        }
        _ => None,
    }
}

fn classify_apply_diagnostic(
    before_ns: Option<u64>,
    after_ns: Option<u64>,
    deadline: Option<u64>,
    required_complete: bool,
    nested_deadline: bool,
) -> Option<PauseDiagnostic> {
    if nested_deadline {
        return Some(PauseDiagnostic::NestedCollectorDeadline);
    }
    let deadline = deadline?;
    if before_ns.is_some_and(|before| before > deadline) {
        return Some(PauseDiagnostic::DeadlineBeforeEngineApply);
    }
    if before_ns.is_some_and(|before| before <= deadline)
        && after_ns.is_some_and(|after| after > deadline)
    {
        return Some(PauseDiagnostic::DeadlineDuringEngineApply);
    }
    if !required_complete && after_ns.is_some_and(|after| after <= deadline) {
        return Some(PauseDiagnostic::EngineIncompleteWithinDeadline);
    }
    None
}

#[derive(Debug)]
pub(crate) struct PauseBatchError {
    message: String,
    diagnostic: Option<PauseDiagnostic>,
}

impl PauseBatchError {
    fn new(message: impl Into<String>, diagnostic: Option<PauseDiagnostic>) -> Self {
        Self {
            message: message.into(),
            diagnostic,
        }
    }
}

impl std::fmt::Display for PauseBatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for PauseBatchError {}

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
    ) -> Result<PauseBatchOutcome, PauseBatchError>;
    fn account_unvalidated_records(&mut self, count: u64);
    fn reconcile_terminal_authority(
        &mut self,
        terminal_batch: &mut Option<TerminalBatch>,
    ) -> Result<(), String>;
    fn cleanup_terminal_batch_without_replay(
        &mut self,
        terminal_batch: &mut Option<TerminalBatch>,
    ) -> Result<(), String>;
    fn terminal_authority_pending(&self) -> bool {
        false
    }
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

    fn original_exited(&mut self) -> Result<bool, String> {
        Ok(false)
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
    diagnostic: Option<PauseDiagnostic>,
}

#[allow(clippy::large_enum_variant)] // The frozen 920-byte item stays allocation-free in transfer.
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

#[derive(Clone, Copy)]
enum RemovalDisposition {
    Normal,
    Rejected,
}

#[derive(Clone, Copy)]
enum AuthorizationSource {
    Observation,
    Removal,
}

pub(crate) struct PauseCoordinator {
    policy: PausePolicy,
    pid: u32,
    generation: u64,
    expected_tasks: BTreeMap<u32, u8>,
    counters: PauseCounters,
    epoch: PauseEpoch,
    armed: bool,
    /// Monotonic clock read immediately *before* the exchange that installed
    /// the live authorization, so it is a lower bound on when the kernel could
    /// first see it. `None` when no arm recorded one, which keeps every record
    /// a candidate.
    armed_at_ns: Option<u64>,
    rearming_enabled: bool,
    may_be_stopped: bool,
    attempt_open: bool,
    ring_loss_baseline: u64,
    active_deadline: Option<u64>,
    failure_deadline: Option<u64>,
    failure_items: usize,
    pending_records: Vec<DiscoveryRecord>,
    unvalidated_records: u64,
    terminal_batch: Option<TerminalBatch>,
    pending_diagnostic: Option<PauseDiagnostic>,
    diagnostic_annotated: bool,
    cycles: u8,
    cleaning: bool,
    cleaned: bool,
}

enum TimedDequeueError {
    Deadline(String),
    Failure(String),
}

impl TimedDequeueError {
    fn lifecycle(&self) -> bool {
        matches!(self, Self::Failure(_))
    }

    fn message(self) -> String {
        match self {
            Self::Deadline(message) | Self::Failure(message) => message,
        }
    }
}

fn clamp_deadline(slot: &mut Option<u64>, candidate: u64) -> u64 {
    let deadline = slot.map_or(candidate, |existing| existing.min(candidate));
    *slot = Some(deadline);
    deadline
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
            armed_at_ns: None,
            rearming_enabled: policy != PausePolicy::Never,
            may_be_stopped: false,
            attempt_open: false,
            ring_loss_baseline: 0,
            active_deadline: None,
            failure_deadline: None,
            failure_items: 0,
            pending_records: Vec::new(),
            unvalidated_records: 0,
            terminal_batch: None,
            pending_diagnostic: None,
            diagnostic_annotated: false,
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
            return self.arm_failed(io, MSG_ARM_FAILED);
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
        let armed_at = io.now_ns().ok();
        if let Err(error) = io.arm() {
            return self.arm_cleanup_failed(io, error, false);
        }
        match io.authorization() {
            Ok(Some(PAUSE_ARMED)) => {
                self.armed = true;
                self.armed_at_ns = armed_at;
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
            let pause_owned = self.active_epoch();
            match io.revalidate_after_release(pause_owned) {
                Ok(PauseRevalidationOutcome::Deferred(received)) if pause_owned => {
                    self.service_deferred(io, received)?;
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
                    self.set_diagnostic(PauseDiagnostic::PostReleaseRevalidationIncomplete);
                    return self.fail_cycle(io, MSG_POST_RELEASE_REVALIDATION_INCOMPLETE, false);
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
        self.begin_attempt();
        self.set_diagnostic(PauseDiagnostic::ArmFailedBeforeEpoch);
        self.rearming_enabled = false;
        match self.policy {
            PausePolicy::Auto => {
                self.counters.partial = self.counters.partial.saturating_add(1);
                let _ = self.emit_partial_diagnostic();
                self.attempt_open = false;
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
        self.set_diagnostic(PauseDiagnostic::ArmFailedBeforeEpoch);
        self.fail_cycle(io, message, lifecycle)
            .map(|()| ArmResult::Disabled)
    }

    pub(crate) fn service(&mut self, io: &mut impl PauseIo) -> Result<(), PauseError> {
        if self.policy == PausePolicy::Never {
            return Ok(());
        }
        let received = match self.timed_dequeue(io, None) {
            Ok(received) => received,
            Err(error) => return self.fail_cycle(io, error.message(), true),
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
            if self.armed {
                let authorization = match io.authorization() {
                    Ok(authorization) => authorization,
                    Err(error) => return self.fail_cycle(io, error, true),
                };
                match authorization {
                    Some(PAUSE_ARMED) => return Ok(()),
                    Some(PAUSE_REQUESTED) => {
                        let now = match io.now_ns() {
                            Ok(now) => now,
                            Err(error) => return self.fail_cycle(io, error, true),
                        };
                        let deadline = now.checked_add(CYCLE_NS).unwrap_or(u64::MAX);
                        return self.service_requested(io, deadline);
                    }
                    Some(_) | None => {
                        return self.fail_cycle(
                            io,
                            "armed pause authorization was absent or unknown",
                            true,
                        );
                    }
                }
            }
            return Ok(());
        };
        self.service_received(io, received)
    }

    fn service_requested(
        &mut self,
        io: &mut impl PauseIo,
        fixed_deadline: u64,
    ) -> Result<(), PauseError> {
        self.begin_attempt();
        self.may_be_stopped = true;
        self.epoch.authorization_consumed = true;
        let deadline = clamp_deadline(&mut self.failure_deadline, fixed_deadline);
        if !self.pending_records.is_empty() {
            if let Err(error) = self.apply_unowned(io, Some(deadline)) {
                return self.fail_cycle(io, error.to_string(), error.lifecycle());
            }
        }
        loop {
            match io.cancelled() {
                Ok(false) => {}
                Ok(true) => return self.fail_cycle(io, "pause coordination cancelled", true),
                Err(error) => return self.fail_cycle(io, error, true),
            }
            if let Err(error) = self.check_ring_loss(io) {
                return self.fail_cycle(io, error, false);
            }
            match self.timed_dequeue(io, Some(deadline)) {
                Ok(Some(received))
                    if matches!(
                        &received.item,
                        DiscoveryItem::Record(record)
                            if exact_pid(record) == self.pid && self.predates_arm(record)
                    ) =>
                {
                    let DiscoveryItem::Record(_) = received.item else {
                        unreachable!("stale-record guard matched a non-record")
                    };
                    if let Err(error) = self.apply_unowned(io, Some(deadline)) {
                        return self.fail_cycle(io, error.to_string(), error.lifecycle());
                    }
                    continue;
                }
                Ok(Some(received)) => return self.service_received(io, received),
                Ok(None) => {
                    let now = match io.now_ns() {
                        Ok(now) => now,
                        Err(error) => return self.fail_cycle(io, error, true),
                    };
                    if now >= deadline {
                        return self.fail_cycle(io, "pause request had no discovery record", false);
                    }
                    if let Err(error) = io.wait_one_ms() {
                        return self.fail_cycle(io, error, true);
                    }
                }
                Err(error) => {
                    let lifecycle = error.lifecycle();
                    return self.fail_cycle(io, error.message(), lifecycle);
                }
            }
        }
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
        let failure_candidate = received.after_ns.checked_add(CYCLE_NS).unwrap_or(u64::MAX);
        clamp_deadline(&mut self.failure_deadline, failure_candidate);
        match io.cancelled() {
            Ok(false) => {}
            Ok(true) => return self.fail_cycle(io, "pause coordination cancelled", true),
            Err(error) => return self.fail_cycle(io, error, true),
        }
        let DiscoveryItem::Record(first) = received.item else {
            self.begin_attempt();
            return self.fail_cycle(io, "malformed discovery record in pause epoch", false);
        };
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
            return self.apply_unowned(io, None);
        }
        if self.predates_arm(&first) {
            let authorization = match io.authorization() {
                Ok(authorization) => authorization,
                Err(error) => return self.fail_cycle(io, error, true),
            };
            let deadline = self.failure_deadline.unwrap_or(u64::MAX);
            match authorization {
                Some(PAUSE_REQUESTED) => return self.service_requested(io, deadline),
                Some(PAUSE_ARMED) => {
                    if let Err(error) = self.apply_unowned(io, Some(deadline)) {
                        return self.fail_cycle(io, error.to_string(), error.lifecycle());
                    }
                    match io.authorization() {
                        Ok(Some(PAUSE_ARMED)) => {
                            self.failure_deadline = None;
                            return Ok(());
                        }
                        Ok(Some(PAUSE_REQUESTED)) => return self.service_requested(io, deadline),
                        Ok(_) => {
                            return self.fail_cycle(
                                io,
                                "stale record authorization was absent or unknown",
                                true,
                            );
                        }
                        Err(error) => return self.fail_cycle(io, error, true),
                    }
                }
                Some(_) | None => {
                    return self.fail_cycle(
                        io,
                        "stale record authorization was absent or unknown",
                        true,
                    );
                }
            }
        }
        let state = match io.authorization() {
            Ok(state) => state,
            Err(error) => return self.fail_cycle(io, error, true),
        };
        if self.epoch.authorization_consumed && state != Some(PAUSE_REQUESTED) {
            return self.fail_cycle(
                io,
                "pause request authorization did not remain REQUESTED",
                true,
            );
        }
        if state != Some(PAUSE_REQUESTED) {
            // An exact ARMED readback refutes the candidate. The kernel is the
            // only writer of REQUESTED and never clears it, and this arm is
            // rewritten only by `arm` (refused while armed) and by a successor
            // installed on a stopped child with a drained queue — so ARMED here
            // proves no hook won this arm's CAS. A zero helper result is not
            // proof of a stop (the producer writes the same zero when there was
            // no authorization to win: a lifecycle record, or any hook that
            // fired between epochs), and this one is explained. Anything else —
            // an authorization that vanished, an unknown value — is unexplained
            // and stays a lost stop authorization.
            if self.epoch.zero_candidate && state != Some(PAUSE_ARMED) {
                self.begin_attempt();
                return self.fail_cycle(
                    io,
                    "zero stop candidate did not retain REQUESTED authorization",
                    false,
                );
            }
            self.epoch.zero_candidate = false;
            self.may_be_stopped = false;
            return self.apply_unowned(io, None);
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
            let provisional_candidate = match cycle_deadline(first.hook_ts_ns) {
                Ok(deadline) => deadline,
                Err(error) => return self.fail_cycle(io, error, false),
            };
            let provisional = clamp_deadline(&mut self.failure_deadline, provisional_candidate);
            let provisional = clamp_deadline(&mut self.active_deadline, provisional);
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
                    Err(error) => {
                        let lifecycle = error.lifecycle();
                        return self.fail_cycle(io, error.message(), lifecycle);
                    }
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
                    continue;
                }
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
            let candidate = cycle_deadline(winner_record.hook_ts_ns)
                .unwrap_or_else(|_| self.failure_deadline.unwrap_or(u64::MAX));
            let deadline = clamp_deadline(&mut self.failure_deadline, candidate);
            let deadline = clamp_deadline(&mut self.active_deadline, deadline);
            records.push(winner_record);
            return self.reject_cycle(io, deadline);
        }
        if winner_record.status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER != 0 {
            return self.fail_cycle(io, "winner carried coalesced status", false);
        }
        if winner_record.send_signal_rc == 0 {
            // The record plus REQUESTED proves an accepted request, even if a
            // later timestamp/deadline check makes confirmation impossible.
            self.epoch.accepted = true;
        }
        let candidate = match cycle_deadline(winner_record.hook_ts_ns) {
            Ok(deadline) => deadline,
            Err(error) => return self.fail_cycle(io, error, false),
        };
        let deadline = clamp_deadline(&mut self.failure_deadline, candidate);
        let deadline = clamp_deadline(&mut self.active_deadline, deadline);
        if let Err(error) = validate_received(&winner_received, winner_record.hook_ts_ns, deadline)
        {
            return self.fail_cycle(io, error, false);
        }
        if records.iter().any(|record| record.hook_ts_ns > deadline) {
            return self.fail_cycle(io, MSG_COALESCED_RECORD_DEADLINE, false);
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
                Err(error) => {
                    let lifecycle = error.lifecycle();
                    return self.fail_cycle(io, error.message(), lifecycle);
                }
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
        let record_count = self.pending_records.len();
        let outcome = match io.apply_batch(
            std::mem::take(&mut self.pending_records),
            Some(deadline),
            true,
            true,
            &mut self.terminal_batch,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(diagnostic) = error.diagnostic {
                    self.set_diagnostic(diagnostic);
                }
                self.take_stop_candidate_seen(io);
                return self.fail_cycle(io, error.to_string(), false);
            }
        };
        if let Some(diagnostic) = outcome.diagnostic {
            self.set_diagnostic(diagnostic);
        }
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
            Err(error) => {
                let lifecycle = error.lifecycle();
                return self.fail_cycle(io, error.message(), lifecycle);
            }
        }

        let install_successor = record_count == 1 && self.cycles == 0 && self.rearming_enabled;
        let mut successor_baseline = None;
        if install_successor {
            if let Err(error) = self.remove_and_account(io) {
                let lifecycle = error.lifecycle();
                return self.fail_cycle(io, error.to_string(), lifecycle);
            }
            let armed_at = io.now_ns().ok();
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
            self.armed_at_ns = armed_at;
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
                Err(error) => {
                    let lifecycle = error.lifecycle();
                    return self.fail_cycle(io, error.message(), lifecycle);
                }
            }
        } else if let Err(error) = self.remove_and_account(io) {
            let lifecycle = error.lifecycle();
            return self.fail_cycle(io, error.to_string(), lifecycle);
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
        if install_successor {
            self.epoch = PauseEpoch {
                successor_installed: true,
                successor_unresolved: true,
                resume_attempted: true,
                resume_succeeded: true,
                ..PauseEpoch::default()
            };
        }
        if let Err(error) = self.observe_resumed(io, deadline, install_successor) {
            return self.fail_cycle(io, error, true);
        }
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
        }
        debug_assert!(self.counters.valid());
        Ok(())
    }

    /// Nested revalidation transfers a generation-validated item directly;
    /// unlike `timed_dequeue`, it has not crossed the coordinator sink yet.
    fn service_deferred(
        &mut self,
        io: &mut impl PauseIo,
        received: TimedItem,
    ) -> Result<(), PauseError> {
        if let DiscoveryItem::Record(record) = received.item {
            self.pending_records.push(record);
        }
        self.service_received(io, received)
    }

    /// A record the live arm cannot have produced. The producer reads its
    /// causal timestamp *after* the exchange that would have stopped the child,
    /// so nothing older than this arm ever won it: it is an ordinary record
    /// left in the ring from before the arm — every hook that fired between
    /// epochs made one, carrying the same zero helper result an accepted stop
    /// has. It is neither this epoch's winner nor a stop candidate. Without a
    /// recorded arm clock nothing is excluded, so the loud reading stands.
    fn predates_arm(&self, record: &DiscoveryRecord) -> bool {
        self.armed
            && self
                .armed_at_ns
                .is_some_and(|armed_at| record.hook_ts_ns < armed_at)
    }

    /// Applies records this coordinator did not own. A bounded deadline is used
    /// while servicing a proven handoff; ordinary/unarmed application is
    /// unbounded and cannot attribute the record to this pause owner.
    fn apply_unowned(
        &mut self,
        io: &mut impl PauseIo,
        deadline: Option<u64>,
    ) -> Result<(), PauseError> {
        if deadline.is_none() && !self.attempt_open {
            self.failure_deadline = None;
        }
        match io.apply_batch(
            std::mem::take(&mut self.pending_records),
            deadline,
            true,
            false,
            &mut self.terminal_batch,
        ) {
            Ok(outcome) => {
                if let Some(diagnostic) = outcome.diagnostic {
                    self.set_diagnostic(diagnostic);
                }
                Ok(())
            }
            Err(error) => {
                if let Some(diagnostic) = error.diagnostic {
                    self.set_diagnostic(diagnostic);
                }
                Err(Self::policy_error(self.policy, error.to_string(), false))
            }
        }
    }

    fn remove_and_account(&mut self, io: &mut impl PauseIo) -> Result<(), PauseError> {
        let disposition = if self.epoch.rejected {
            RemovalDisposition::Rejected
        } else {
            RemovalDisposition::Normal
        };
        let removed = io
            .remove_authorization()
            .map_err(|error| Self::policy_error(self.policy, error, true))?;
        self.classify_authorization(removed, disposition, AuthorizationSource::Removal)
            .map_err(|error| Self::policy_error(self.policy, error, true))?;
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

    fn reject_cycle(&mut self, io: &mut impl PauseIo, deadline: u64) -> Result<(), PauseError> {
        self.set_diagnostic(PauseDiagnostic::PauseHelperRejected);
        if self.policy == PausePolicy::Always {
            return self.terminal_cleanup_with_cause(
                io,
                vec![MSG_PAUSE_HELPER_REJECTED.into()],
                true,
                false,
            );
        }
        let mut retained_error = None;
        let mut lifecycle_errors = Vec::new();
        if let Err(error) = self.remove_and_account(io) {
            lifecycle_errors.push(error.to_string());
        }
        self.armed = false;
        while self.failure_items < MAX_FAILURE_ITEMS {
            match self.timed_dequeue(io, Some(deadline)) {
                Ok(None) => match io.now_ns() {
                    Ok(now) if now < deadline => {
                        if let Err(error) = io.wait_one_ms() {
                            lifecycle_errors.push(error);
                            break;
                        }
                    }
                    Ok(_) => break,
                    Err(error) => {
                        lifecycle_errors.push(error);
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
                }
                Ok(Some(_)) => {
                    self.failure_items += 1;
                    retained_error
                        .get_or_insert_with(|| "rejected epoch contained an invalid record".into());
                }
                Err(error) => {
                    let lifecycle = error.lifecycle();
                    let message = error.message();
                    if lifecycle {
                        lifecycle_errors.push(message);
                    } else {
                        retained_error.get_or_insert(message);
                    }
                    break;
                }
            }
        }
        if let Err(error) = io.apply_batch(
            std::mem::take(&mut self.pending_records),
            Some(deadline),
            true,
            true,
            &mut self.terminal_batch,
        ) {
            if let Some(diagnostic) = error.diagnostic {
                self.set_diagnostic(diagnostic);
            }
            retained_error.get_or_insert(error.to_string());
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
            return self.terminal_cleanup_with_errors(io, lifecycle_errors);
        }
        self.epoch = PauseEpoch::default();
        self.finish_nonconfirmed(retained_error.unwrap_or_else(|| MSG_PAUSE_HELPER_REJECTED.into()))
    }

    fn sample_stopped(&self, io: &mut impl PauseIo, deadline: u64) -> Result<u64, String> {
        let states = io.task_states(self.pid)?;
        let now = io.now_ns()?;
        if now > deadline {
            return Err(MSG_PAUSE_CONFIRMATION_DEADLINE.into());
        }
        if states.keys().ne(self.expected_tasks.keys())
            || states.values().any(|state| *state != b'T')
        {
            return Err("task set changed or was not entirely stopped".into());
        }
        Ok(now)
    }

    fn observe_resumed(
        &self,
        io: &mut impl PauseIo,
        deadline: u64,
        install_successor: bool,
    ) -> Result<(), String> {
        loop {
            if !io.same_generation(self.pid, self.generation)? {
                return Err("owned child generation changed after resume".into());
            }
            let authorization = io.authorization()?;
            if install_successor && authorization == Some(PAUSE_REQUESTED) {
                if io.now_ns()? > deadline {
                    return Err(MSG_PAUSE_RESUME_DEADLINE.into());
                }
                return Ok(());
            }
            let resting = if install_successor {
                Some(PAUSE_ARMED)
            } else {
                None
            };
            if authorization != resting {
                return Err("pause authorization did not reach the expected resting state".into());
            }
            if io.original_exited()? {
                if io.now_ns()? > deadline {
                    return Err(MSG_PAUSE_RESUME_DEADLINE.into());
                }
                return Ok(());
            }
            let states = io.task_states(self.pid)?;
            let now = io.now_ns()?;
            if now > deadline {
                return Err(MSG_PAUSE_RESUME_DEADLINE.into());
            }
            if states.keys().ne(self.expected_tasks.keys()) {
                return Ok(());
            }
            if states.values().any(|state| *state != b'T') {
                return Ok(());
            }
            if now == deadline {
                return Err(MSG_PAUSE_RESUME_DEADLINE.into());
            }
            io.wait_one_ms()?;
        }
    }

    fn timed_dequeue(
        &mut self,
        io: &mut impl PauseIo,
        deadline: Option<u64>,
    ) -> Result<Option<TimedItem>, TimedDequeueError> {
        let before_ns = io.now_ns().map_err(TimedDequeueError::Failure)?;
        if deadline.is_some_and(|deadline| before_ns > deadline) {
            return Err(TimedDequeueError::Deadline(
                MSG_DEADLINE_BEFORE_DEQUEUE.into(),
            ));
        }
        let item = io.dequeue().map_err(TimedDequeueError::Failure)?;
        if self.active_epoch()
            && let Some(DiscoveryItem::Record(record)) = &item
            && exact_pid(record) == self.pid
            && record.send_signal_rc == 0
            && !self.predates_arm(record)
        {
            self.may_be_stopped = true;
            self.epoch.zero_candidate = true;
        }
        if let Some(DiscoveryItem::Record(record)) = &item {
            match io.same_generation(self.pid, self.generation) {
                Ok(true) => self.pending_records.push(*record),
                Ok(false) => {
                    self.unvalidated_records = self.unvalidated_records.saturating_add(1);
                    return Err(TimedDequeueError::Failure(
                        "owned child generation changed after discovery decode".into(),
                    ));
                }
                Err(error) => {
                    self.unvalidated_records = self.unvalidated_records.saturating_add(1);
                    return Err(TimedDequeueError::Failure(error));
                }
            }
        }
        let after_ns = io.now_ns().map_err(TimedDequeueError::Failure)?;
        if deadline.is_some_and(|deadline| after_ns > deadline) {
            return Err(TimedDequeueError::Deadline(
                MSG_DEADLINE_AFTER_DEQUEUE.into(),
            ));
        }
        let Some(item) = item else {
            return Ok(None);
        };
        Ok(Some(TimedItem {
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
        self.set_message_diagnostic(&message);
        if !lifecycle {
            self.set_diagnostic(PauseDiagnostic::OtherAutoNonconfirmed);
        }
        self.rearming_enabled = false;
        if lifecycle || self.policy == PausePolicy::Always || self.unvalidated_records != 0 {
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
                    item: DiscoveryItem::Record(_),
                    ..
                })) => {
                    self.failure_items += 1;
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
                    let lifecycle = error.lifecycle();
                    let message = error.message();
                    self.set_message_diagnostic(&message);
                    errors.push(message);
                    if lifecycle {
                        return self.terminal_cleanup_with_errors(io, errors);
                    }
                    break;
                }
            }
        }
        if let Err(error) = io.apply_batch(
            std::mem::take(&mut self.pending_records),
            Some(deadline),
            true,
            self.active_epoch(),
            &mut self.terminal_batch,
        ) {
            if let Some(diagnostic) = error.diagnostic {
                self.set_diagnostic(diagnostic);
            }
            errors.push(error.to_string());
        }
        self.take_stop_candidate_seen(io);
        match io.authorization() {
            Ok(state) => {
                if let Err(error) = self.classify_authorization(
                    state,
                    RemovalDisposition::Normal,
                    AuthorizationSource::Observation,
                ) {
                    errors.push(error);
                    return self.terminal_cleanup_with_errors(io, errors);
                }
            }
            Err(error) => {
                errors.push(error);
                self.may_be_stopped |= self.has_proven_resume_debt();
                return self.terminal_cleanup_with_errors(io, errors);
            }
        }
        if let Err(error) = self.remove_and_account(io) {
            errors.push(error.to_string());
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
                self.set_diagnostic(PauseDiagnostic::OtherAutoNonconfirmed);
                self.counters.partial = self.counters.partial.saturating_add(1);
                self.attempt_open = false;
                let _ = self.emit_partial_diagnostic();
                debug_assert!(self.counters.valid());
                Ok(())
            }
            PausePolicy::Always => {
                let diagnostic = self
                    .pending_diagnostic
                    .unwrap_or(PauseDiagnostic::OtherAutoNonconfirmed);
                Err(PauseError::one(
                    Self::annotate_primary(message, diagnostic),
                    true,
                    false,
                ))
            }
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
        if let Err(error) = io.reconcile_terminal_authority(&mut self.terminal_batch) {
            errors.push(error);
        }
        if self.terminal_batch.is_none() && io.terminal_authority_pending() {
            if let Err(error) = io.cleanup_terminal_batch_without_replay(&mut self.terminal_batch) {
                errors.push(error);
            }
        }
        if let Err(error) = io.detach_pause_links() {
            errors.push(error);
        }
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
                    item: DiscoveryItem::Record(_),
                    ..
                })) => {
                    self.failure_items += 1;
                }
                Ok(None) => break,
                Err(error) => {
                    let message = error.message();
                    self.set_message_diagnostic(&message);
                    errors.push(message);
                    break;
                }
            }
        }
        let unvalidated = std::mem::take(&mut self.unvalidated_records);
        match io.apply_batch(
            std::mem::take(&mut self.pending_records),
            Some(deadline),
            false,
            self.active_epoch(),
            &mut self.terminal_batch,
        ) {
            Ok(outcome) => {
                if let Some(diagnostic) = outcome.diagnostic {
                    self.set_diagnostic(diagnostic);
                }
            }
            Err(error) => {
                if let Some(diagnostic) = error.diagnostic {
                    self.set_diagnostic(diagnostic);
                }
                errors.push(error.to_string());
                self.annotate_required_primary(&mut errors, required);
            }
        }
        if self.terminal_batch.is_some() {
            match io.apply_batch(
                Vec::new(),
                Some(deadline),
                false,
                self.active_epoch(),
                &mut self.terminal_batch,
            ) {
                Ok(outcome) => {
                    if let Some(diagnostic) = outcome.diagnostic {
                        self.set_diagnostic(diagnostic);
                    }
                }
                Err(error) => {
                    if let Some(diagnostic) = error.diagnostic {
                        self.set_diagnostic(diagnostic);
                    }
                    errors.push(error.to_string());
                    self.annotate_required_primary(&mut errors, required);
                }
            }
            if self.terminal_batch.is_some()
                && let Err(error) =
                    io.cleanup_terminal_batch_without_replay(&mut self.terminal_batch)
            {
                errors.push(error);
            }
        }
        if unvalidated != 0 {
            io.account_unvalidated_records(unvalidated);
        }
        self.take_stop_candidate_seen(io);
        match io.authorization() {
            Ok(state) => {
                let disposition = if self.epoch.rejected {
                    RemovalDisposition::Rejected
                } else {
                    RemovalDisposition::Normal
                };
                if let Err(error) = self.classify_authorization(
                    state,
                    disposition,
                    AuthorizationSource::Observation,
                ) {
                    errors.push(error);
                }
            }
            Err(error) => {
                errors.push(error);
                self.may_be_stopped |= self.has_proven_resume_debt();
            }
        }
        if let Err(error) = self.remove_and_account(io) {
            errors.push(error.to_string());
        }
        self.armed = false;
        if self.epoch.accepted && self.may_be_stopped && !self.epoch.resume_attempted {
            self.epoch.resume_attempted = true;
            if let Err(error) = io.resume() {
                errors.push(error);
            } else {
                self.epoch.resume_succeeded = true;
                self.settle_cleanup_resume_debt();
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
                self.settle_cleanup_resume_debt();
            }
        }
        if self.terminal_batch.is_none()
            && io.terminal_authority_pending()
            && let Err(error) = io.cleanup_terminal_batch_without_replay(&mut self.terminal_batch)
        {
            errors.push(error);
        }
        if self.terminal_batch.is_some() || io.terminal_authority_pending() {
            errors.push("terminal discovery authority remained unresolved after cleanup".into());
            self.annotate_required_primary(&mut errors, required);
            self.cleaning = false;
            return Err(PauseError::many(errors, required, true));
        }
        let cleanup_failed = errors.len() > initiating_errors;
        self.cleaned = !cleanup_failed;
        self.cleaning = false;
        if errors.is_empty() {
            Ok(())
        } else {
            self.annotate_required_primary(&mut errors, required);
            Err(PauseError::many(
                errors,
                required,
                lifecycle || cleanup_failed,
            ))
        }
    }

    fn settle_cleanup_resume_debt(&mut self) {
        self.may_be_stopped = false;
        self.epoch.authorization_consumed = false;
        self.epoch.zero_candidate = false;
        self.epoch.accepted = false;
        self.epoch.successor_unresolved = false;
    }

    fn failure_bound(&mut self, io: &mut impl PauseIo, errors: &mut Vec<String>) -> u64 {
        let existing = match (self.active_deadline, self.failure_deadline) {
            (Some(active), Some(failure)) => Some(active.min(failure)),
            (Some(active), None) | (None, Some(active)) => Some(active),
            (None, None) => None,
        };
        if let Some(deadline) = existing {
            let deadline = clamp_deadline(&mut self.failure_deadline, deadline);
            clamp_deadline(&mut self.active_deadline, deadline);
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
        clamp_deadline(&mut self.failure_deadline, deadline)
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
            self.pending_diagnostic = None;
            self.diagnostic_annotated = false;
            self.counters.attempts = self.counters.attempts.saturating_add(1);
            self.attempt_open = true;
        }
    }

    fn set_diagnostic(&mut self, diagnostic: PauseDiagnostic) {
        self.pending_diagnostic.get_or_insert(diagnostic);
    }

    fn set_message_diagnostic(&mut self, message: &str) {
        if let Some(diagnostic) = diagnostic_for_message(message) {
            self.set_diagnostic(diagnostic);
        }
    }

    fn emit_partial_diagnostic(&mut self) -> String {
        let diagnostic = self
            .pending_diagnostic
            .take()
            .unwrap_or(PauseDiagnostic::OtherAutoNonconfirmed);
        let line = render_pause_diagnostic(diagnostic);
        eprintln!("{line}");
        line
    }

    fn annotate_primary(message: String, diagnostic: PauseDiagnostic) -> String {
        let message = message.replace("pause_diag=", "pause_diag_escaped=");
        format!("{message} [pause_diag={}]", diagnostic.token())
    }

    fn annotate_required_primary(&mut self, errors: &mut [String], required: bool) {
        if required
            && let Some(primary) = errors.first_mut()
            && !self.diagnostic_annotated
        {
            let diagnostic = self
                .pending_diagnostic
                .unwrap_or(PauseDiagnostic::OtherAutoNonconfirmed);
            *primary = Self::annotate_primary(std::mem::take(primary), diagnostic);
            self.diagnostic_annotated = true;
        }
    }

    fn active_epoch(&self) -> bool {
        self.policy != PausePolicy::Never && (self.armed || self.has_proven_resume_debt())
    }

    fn classify_authorization(
        &mut self,
        state: Option<u64>,
        disposition: RemovalDisposition,
        source: AuthorizationSource,
    ) -> Result<(), String> {
        let successor = self.epoch.successor_installed && self.epoch.successor_unresolved;
        match state {
            Some(PAUSE_REQUESTED) if matches!(disposition, RemovalDisposition::Rejected) => {
                self.epoch.authorization_consumed = false;
                self.may_be_stopped = successor;
            }
            Some(PAUSE_REQUESTED) => {
                self.may_be_stopped = true;
                self.epoch.authorization_consumed = true;
                self.epoch.successor_unresolved |= self.epoch.successor_installed;
                self.begin_attempt();
            }
            Some(PAUSE_ARMED) => {
                if self.epoch.zero_candidate
                    && !self.epoch.authorization_consumed
                    && !self.epoch.accepted
                {
                    self.epoch.zero_candidate = false;
                }
                let prior_authorization_debt = self.has_proven_authorization_debt();
                if prior_authorization_debt && !successor {
                    return Err("ARMED authorization followed consumed pause debt".into());
                }
                if matches!(source, AuthorizationSource::Removal) && successor {
                    self.epoch.successor_unresolved = false;
                }
                self.may_be_stopped = if matches!(source, AuthorizationSource::Removal) {
                    prior_authorization_debt
                } else {
                    self.has_proven_resume_debt()
                };
                if !self.may_be_stopped {
                    self.epoch.successor_unresolved = false;
                    self.epoch.authorization_consumed = false;
                }
            }
            None if self.has_proven_resume_debt() => {
                self.may_be_stopped = true;
                return Err("pause authorization disappeared after consumed pause debt".into());
            }
            None if self.policy != PausePolicy::Never && self.armed => {
                return Err("active pause authorization was absent".into());
            }
            None => {
                self.epoch.successor_unresolved = false;
                self.may_be_stopped = false;
                self.epoch.authorization_consumed = false;
            }
            Some(_) => return Err("unknown pause authorization state".into()),
        }
        Ok(())
    }

    fn has_proven_resume_debt(&self) -> bool {
        self.has_proven_authorization_debt()
            || (self.epoch.successor_installed
                && self.epoch.successor_unresolved
                && self.epoch.resume_succeeded)
    }

    fn has_proven_authorization_debt(&self) -> bool {
        self.epoch.authorization_consumed || self.epoch.accepted || self.epoch.zero_candidate
    }

    fn take_stop_candidate_seen(&mut self, io: &mut impl PauseIo) {
        let seen = io.take_stop_candidate_seen();
        if self.active_epoch() {
            self.epoch.zero_candidate |= seen;
            self.may_be_stopped |= seen;
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
    ) -> Result<PauseBatchOutcome, PauseBatchError> {
        self.reconcile_terminal_authority(terminal_batch)
            .map_err(|error| PauseBatchError::new(error, None))?;
        let child = self.child;
        let stop_candidate_seen = &mut self.stop_candidate_seen;
        let nested_deadline = std::cell::Cell::new(false);
        let mut collect = |session: &mut dyn EngineSession| {
            collect_timed_retirement(
                session,
                child,
                deadline,
                stop_candidate_seen,
                pause_owned,
                &nested_deadline,
            )
        };
        let terminal_dispatch = terminal_batch.is_some();
        if let Some(batch) = terminal_batch.take()
            && let Err(error) = self
                .engine
                .install_terminal_batch(batch.clone(), records.clone())
        {
            *terminal_batch = Some(batch);
            return Err(PauseBatchError::new(
                format!("terminal discovery batch restore failed: {error:#}"),
                None,
            ));
        }
        let records = terminal_dispatch.then(Vec::new).unwrap_or(records);
        let before_ns = attach::monotonic_ns();
        let result = match self.engine.apply_discovery_batch_with(
            self.session,
            records,
            std::mem::take(&mut self.malformed),
            additions_allowed,
            terminal_dispatch,
            &mut collect,
            deadline,
        ) {
            Ok(outcome) => {
                self.plan_changed |= outcome.changed;
                Ok(outcome.required_complete)
            }
            Err(error) => {
                let error = match error.downcast::<DeferredDiscoveryItem>() {
                    Ok(mut deferred) => {
                        *terminal_batch = deferred.terminal_batch.take();
                        anyhow::Error::new(deferred)
                    }
                    Err(error) => error,
                };
                Err(format!("discovery batch application failed: {error:#}"))
            }
        };
        let after_ns = attach::monotonic_ns();
        let diagnostic = classify_apply_diagnostic(
            before_ns,
            after_ns,
            deadline,
            result.as_ref().copied().unwrap_or(true),
            nested_deadline.get(),
        );
        let result = result.map_err(|message| PauseBatchError::new(message, diagnostic));
        let result = result.map(|required_complete| PauseBatchOutcome {
            required_complete,
            diagnostic,
        });
        if let Err(error) = self.reconcile_terminal_authority(terminal_batch) {
            let diagnostic = result
                .as_ref()
                .map_or_else(|error| error.diagnostic, |outcome| outcome.diagnostic);
            return Err(match result {
                Ok(_) => PauseBatchError::new(
                    format!("terminal discovery authority reconciliation failed: {error:#}"),
                    diagnostic,
                ),
                Err(apply) => PauseBatchError::new(
                    format!(
                        "{}; terminal discovery authority reconciliation failed: {error:#}",
                        apply.message
                    ),
                    diagnostic.or(apply.diagnostic),
                ),
            });
        }
        result
    }

    fn account_unvalidated_records(&mut self, count: u64) {
        self.engine.account_unvalidated_discovery(count);
    }

    fn reconcile_terminal_authority(
        &mut self,
        terminal_batch: &mut Option<TerminalBatch>,
    ) -> Result<(), String> {
        self.engine
            .reconcile_terminal_authority(terminal_batch)
            .map_err(|error| {
                format!("terminal discovery authority reconciliation failed: {error:#}")
            })
    }

    fn cleanup_terminal_batch_without_replay(
        &mut self,
        terminal_batch: &mut Option<TerminalBatch>,
    ) -> Result<(), String> {
        if terminal_batch.is_some() {
            self.engine
                .cleanup_terminal_batch_without_replay(terminal_batch)
                .map_err(|error| {
                    format!("terminal discovery cleanup without replay failed: {error:#}")
                })?;
        } else {
            self.engine
                .cleanup_started_terminal_journal()
                .map_err(|error| {
                    format!("terminal discovery cleanup-only retry failed: {error:#}")
                })?;
        }
        Ok(())
    }

    fn terminal_authority_pending(&self) -> bool {
        self.engine.terminal_authority_pending()
    }

    fn revalidate_after_release(
        &mut self,
        pause_owned: bool,
    ) -> Result<PauseRevalidationOutcome, String> {
        let child = self.child;
        let stop_candidate_seen = &mut self.stop_candidate_seen;
        let nested_deadline = std::cell::Cell::new(false);
        let mut collect = |session: &mut dyn EngineSession| {
            collect_timed_retirement(
                session,
                child,
                None,
                stop_candidate_seen,
                pause_owned,
                &nested_deadline,
            )
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
            diagnostic: None,
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
        if self.child.pid() != pid || self.child.generation().get() != generation {
            return Ok(false);
        }
        owned_generation_retained(self.child)
    }

    fn original_exited(&mut self) -> Result<bool, String> {
        self.child.pin().original_exited()
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

/// Whether the coordinator's own generation is still exactly the one behind
/// this pid. The retained original pin proves it while the child lives; once
/// the child ends, the *unreaped* fork child still holds the pid, so nothing
/// else can be producing records under it and what the ring still holds is
/// this generation's. The owned child's ordinary end is therefore not a lost
/// generation — the same authority `mark_generation_change` already uses.
/// Reaping is what releases the pid to reuse, and a pin that cannot answer
/// stays an error, so neither is ever read as "still mine".
fn owned_generation_retained(child: &OwnedChild) -> Result<bool, String> {
    if child.pin().still_the_same() {
        return Ok(true);
    }
    Ok(!child.is_reaped() && child.pin().original_exited()?)
}

fn collect_timed_retirement(
    session: &mut dyn EngineSession,
    child: &OwnedChild,
    deadline: Option<u64>,
    stop_candidate_seen: &mut bool,
    pause_owned: bool,
    nested_deadline: &std::cell::Cell<bool>,
) -> Result<(Vec<DiscoveryRecord>, u64), anyhow::Error> {
    collect_timed_retirement_with(
        child.pid(),
        deadline,
        stop_candidate_seen,
        pause_owned,
        Some(nested_deadline),
        || attach::monotonic_ns().ok_or_else(|| anyhow::anyhow!("monotonic clock read failed")),
        || session.discovery_dequeue(),
        || owned_generation_retained(child).map_err(anyhow::Error::msg),
    )
}

// The explicit callbacks keep deadline, dequeue, and process-generation failure paths testable.
#[allow(clippy::too_many_arguments)]
fn collect_timed_retirement_with(
    child_pid: u32,
    deadline: Option<u64>,
    stop_candidate_seen: &mut bool,
    pause_owned: bool,
    nested_deadline: Option<&std::cell::Cell<bool>>,
    mut now_ns: impl FnMut() -> Result<u64, anyhow::Error>,
    mut dequeue: impl FnMut() -> Result<Option<DiscoveryItem>, anyhow::Error>,
    mut same_generation: impl FnMut() -> Result<bool, anyhow::Error>,
) -> Result<(Vec<DiscoveryRecord>, u64), anyhow::Error> {
    let mut records = Vec::new();
    let mut malformed = 0u64;
    let mut unvalidated_records = 0u64;
    loop {
        let before_ns = match now_ns() {
            Ok(now) => now,
            Err(error) => {
                return Err(IncompleteTerminalDrain::new(
                    records,
                    malformed,
                    unvalidated_records,
                    error,
                )
                .into());
            }
        };
        if deadline.is_some_and(|deadline| before_ns > deadline) {
            if let Some(nested_deadline) = nested_deadline {
                nested_deadline.set(true);
            }
            return Err(IncompleteTerminalDrain::new(
                records,
                malformed,
                unvalidated_records,
                anyhow::anyhow!(MSG_NESTED_DEADLINE_BEFORE),
            )
            .into());
        }
        let item = match dequeue() {
            Ok(item) => item,
            Err(error) => {
                return Err(IncompleteTerminalDrain::new(
                    records,
                    malformed,
                    unvalidated_records,
                    error,
                )
                .into());
            }
        };
        if let Some(DiscoveryItem::Record(record)) = item.as_ref()
            && pause_owned
            && exact_pid(record) == child_pid
            && record.send_signal_rc == 0
        {
            *stop_candidate_seen = true;
        }
        if let Some(current) = item.as_ref() {
            match same_generation() {
                Ok(true) => {}
                Ok(false) => {
                    match current {
                        DiscoveryItem::Record(_) => {
                            unvalidated_records = unvalidated_records.saturating_add(1)
                        }
                        DiscoveryItem::Malformed => malformed = malformed.saturating_add(1),
                    }
                    return Err(IncompleteTerminalDrain::new(
                        records,
                        malformed,
                        unvalidated_records,
                        anyhow::anyhow!(
                            "owned child generation changed after nested discovery decode"
                        ),
                    )
                    .into());
                }
                Err(error) => {
                    match current {
                        DiscoveryItem::Record(_) => {
                            unvalidated_records = unvalidated_records.saturating_add(1)
                        }
                        DiscoveryItem::Malformed => malformed = malformed.saturating_add(1),
                    }
                    return Err(IncompleteTerminalDrain::new(
                        records,
                        malformed,
                        unvalidated_records,
                        error,
                    )
                    .into());
                }
            }
        }
        let after_ns = match now_ns() {
            Ok(now) => now,
            Err(error) => {
                match item {
                    Some(DiscoveryItem::Record(record)) => records.push(record),
                    Some(DiscoveryItem::Malformed) => malformed = malformed.saturating_add(1),
                    None => {}
                }
                return Err(IncompleteTerminalDrain::new(
                    records,
                    malformed,
                    unvalidated_records,
                    error,
                )
                .into());
            }
        };
        if deadline.is_some_and(|deadline| after_ns > deadline) {
            if let Some(nested_deadline) = nested_deadline {
                nested_deadline.set(true);
            }
            match item {
                Some(DiscoveryItem::Record(record)) => records.push(record),
                Some(DiscoveryItem::Malformed) => malformed = malformed.saturating_add(1),
                None => {}
            }
            return Err(IncompleteTerminalDrain::new(
                records,
                malformed,
                unvalidated_records,
                anyhow::anyhow!(MSG_NESTED_DEADLINE_AFTER),
            )
            .into());
        }
        let Some(item) = item else { break };
        if pause_owned && deadline.is_none() {
            match item {
                DiscoveryItem::Record(_) => {
                    return Err(DeferredDiscoveryItem {
                        before_ns,
                        after_ns,
                        item,
                        terminal_batch: None,
                    }
                    .into());
                }
                DiscoveryItem::Malformed => {
                    malformed = malformed.saturating_add(1);
                    return Ok((records, malformed));
                }
            }
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
                            unvalidated_records,
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
                            unvalidated_records,
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
        return Err(MSG_PAUSE_CAUSAL_DEADLINE.into());
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

    #[test]
    fn fixed_cycle_deadline_is_500ms_and_bounds_are_inclusive() {
        assert_eq!(cycle_deadline(10), Ok(500_000_010));
        assert_eq!(
            cycle_deadline(u64::MAX),
            Err("pause deadline overflow".into())
        );

        let deadline = 500_000_010;
        let received = TimedItem {
            before_ns: deadline,
            after_ns: deadline,
            item: DiscoveryItem::Record(record(10, 0, false)),
            terminal_batch: None,
        };
        assert!(validate_received(&received, 10, deadline).is_ok());
        let late = TimedItem {
            before_ns: deadline + 1,
            after_ns: deadline + 1,
            item: DiscoveryItem::Record(record(10, 0, false)),
            terminal_batch: None,
        };
        assert_eq!(
            validate_received(&late, 10, deadline),
            Err(MSG_PAUSE_CAUSAL_DEADLINE.into())
        );
    }

    struct FakeIo {
        now: VecDeque<Result<u64, String>>,
        fallback_now: u64,
        states: VecDeque<Result<BTreeMap<u32, u8>, String>>,
        queue: VecDeque<Result<Option<DiscoveryItem>, String>>,
        authorization: Option<u64>,
        authorization_results: VecDeque<Result<Option<u64>, String>>,
        marker: bool,
        events: Vec<&'static str>,
        applied: Vec<DiscoveryRecord>,
        apply_deadlines: Vec<Option<u64>>,
        fail_detach: bool,
        fail_remove: bool,
        fail_read: bool,
        fail_resume: bool,
        fail_apply: bool,
        apply_outcome_diagnostic: Option<PauseDiagnostic>,
        apply_error_diagnostic: Option<PauseDiagnostic>,
        fail_terminal_apply: bool,
        unvalidated_records: u64,
        required_complete: bool,
        fail_wait: bool,
        cancelled: bool,
        same_generation: bool,
        same_generation_results: VecDeque<Result<bool, String>>,
        original_exited: bool,
        resume_authorization: Option<Option<u64>>,
        resumed: bool,
        post_resume_all_stopped: bool,
        post_resume_now: VecDeque<Result<u64, String>>,
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
        reconcile_results: VecDeque<Result<(), String>>,
        terminal_cleanup_results: VecDeque<Result<(), String>>,
        terminal_authority_pending: bool,
    }

    impl Default for FakeIo {
        fn default() -> Self {
            Self {
                now: VecDeque::new(),
                fallback_now: 0,
                states: VecDeque::new(),
                queue: VecDeque::new(),
                authorization: None,
                authorization_results: VecDeque::new(),
                marker: false,
                events: Vec::new(),
                applied: Vec::new(),
                apply_deadlines: Vec::new(),
                fail_detach: false,
                fail_remove: false,
                fail_read: false,
                fail_resume: false,
                fail_apply: false,
                apply_outcome_diagnostic: None,
                apply_error_diagnostic: None,
                fail_terminal_apply: false,
                unvalidated_records: 0,
                required_complete: true,
                fail_wait: false,
                cancelled: false,
                same_generation: true,
                same_generation_results: VecDeque::new(),
                original_exited: false,
                resume_authorization: None,
                resumed: false,
                post_resume_all_stopped: false,
                post_resume_now: VecDeque::new(),
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
                reconcile_results: VecDeque::new(),
                terminal_cleanup_results: VecDeque::new(),
                terminal_authority_pending: false,
            }
        }
    }

    impl PauseIo for FakeIo {
        fn now_ns(&mut self) -> Result<u64, String> {
            if self.resumed
                && let Some(now) = self.post_resume_now.pop_front()
            {
                if let Ok(now) = now {
                    self.fallback_now = now;
                }
                return now;
            }
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
            self.states.pop_front().unwrap_or_else(|| {
                if self.resumed && !self.post_resume_all_stopped {
                    Ok([(41, b'R'), (42, b'T')].into_iter().collect())
                } else {
                    Ok(stopped())
                }
            })
        }

        fn dequeue(&mut self) -> Result<Option<DiscoveryItem>, String> {
            self.events.push("dequeue");
            let item = self.queue.pop_front().unwrap_or(Ok(None));
            if matches!(item, Ok(Some(DiscoveryItem::Record(_)))) {
                self.resumed = false;
            }
            item
        }

        fn arm(&mut self) -> Result<(), String> {
            self.events.push("arm");
            self.authorization = Some(PAUSE_ARMED);
            Ok(())
        }

        fn authorization(&mut self) -> Result<Option<u64>, String> {
            self.events.push("read");
            if let Some(result) = self.authorization_results.pop_front() {
                result
            } else if self.fail_read {
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
            deadline: Option<u64>,
            additions_allowed: bool,
            pause_owned: bool,
            terminal_batch: &mut Option<TerminalBatch>,
        ) -> Result<PauseBatchOutcome, PauseBatchError> {
            self.events.push(if additions_allowed {
                "apply"
            } else {
                "account"
            });
            if self.fail_apply && additions_allowed {
                return Err(PauseBatchError::new("apply", self.apply_error_diagnostic));
            }
            if self.fail_terminal_apply && !additions_allowed {
                return Err(PauseBatchError::new(
                    "terminal apply",
                    self.apply_error_diagnostic,
                ));
            }
            self.apply_deadlines.push(deadline);
            self.apply_pause_owned.push(pause_owned);
            if let Some(batch) = terminal_batch.take() {
                self.terminal_batches.push(batch);
            }
            self.applied.extend(records);
            Ok(PauseBatchOutcome {
                required_complete: self.required_complete,
                diagnostic: self.apply_outcome_diagnostic,
            })
        }

        fn account_unvalidated_records(&mut self, count: u64) {
            self.events.push("unvalidated");
            self.unvalidated_records = self.unvalidated_records.saturating_add(count);
        }

        fn reconcile_terminal_authority(
            &mut self,
            _: &mut Option<TerminalBatch>,
        ) -> Result<(), String> {
            self.reconcile_results.pop_front().unwrap_or(Ok(()))
        }

        fn cleanup_terminal_batch_without_replay(
            &mut self,
            terminal_batch: &mut Option<TerminalBatch>,
        ) -> Result<(), String> {
            self.events.push("discard");
            let result = self.terminal_cleanup_results.pop_front().unwrap_or(Ok(()));
            if result.is_ok() {
                self.terminal_authority_pending = false;
            }
            terminal_batch.take();
            result
        }

        fn terminal_authority_pending(&self) -> bool {
            self.terminal_authority_pending
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
                diagnostic: None,
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
                self.resumed = true;
                if let Some(authorization) = self.resume_authorization {
                    self.authorization = authorization;
                }
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
            self.same_generation_results
                .pop_front()
                .unwrap_or(Ok(self.same_generation))
        }

        fn original_exited(&mut self) -> Result<bool, String> {
            Ok(self.original_exited)
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
            None,
            || clocks.pop_front().expect("one before and one after clock"),
            || Ok(item.take()),
            || Ok(same_generation),
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

    /// The owned child ends; its last records are already in the ring. Nothing
    /// else can be producing under that pid — the unreaped fork child still
    /// holds it — so the records are still this generation's and the ordinary
    /// end is not a lost generation. Reaping is what releases the pid, and only
    /// then must nothing be attributed to it.
    #[test]
    fn the_owned_generation_survives_its_child_ordinary_exit_until_it_is_reaped() {
        let mut child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        child.release().unwrap();
        assert!(
            child
                .pin()
                .wait_ready(Some(Duration::from_secs(5)))
                .unwrap(),
            "the owned child must reach its ordinary end"
        );
        assert!(!child.still_running());

        assert!(
            owned_generation_retained(&child).unwrap(),
            "an unreaped exit still holds the pid: the ring's records are still this generation's"
        );

        child.wait_for(Some(Duration::ZERO), false).unwrap();
        assert!(
            !owned_generation_retained(&child).unwrap(),
            "a reaped pid can be reused, so nothing may still be attributed to it"
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
    fn final_resume_all_stopped_to_deadline_is_lifecycle_fatal_not_partial() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.post_resume_all_stopped = true;
        io.resume_authorization = Some(None);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.cycles = 1;
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 1,
                confirmed: 0,
                partial: 0,
            }
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn successor_requested_after_resume_confirms_even_while_tasks_remain_stopped() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.resume_authorization = Some(Some(PAUSE_REQUESTED));
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn successor_requested_after_resume_deadline_is_protectively_resumed() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.resume_authorization = Some(Some(PAUSE_REQUESTED));
        io.post_resume_now = VecDeque::from([Ok(CYCLE_NS + 11)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(coordinator.counters().confirmed, 0);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            2
        );
    }

    #[test]
    fn final_resume_with_a_running_task_and_no_authorization_confirms() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.resume_authorization = Some(None);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.cycles = 1;
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
    }

    #[test]
    fn final_resume_authorization_mismatch_is_lifecycle_fatal() {
        for authorization in [Some(PAUSE_REQUESTED), Some(999)] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            io.resume_authorization = Some(authorization);
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.cycles = 1;
            coordinator.arm_for_test();

            let error = coordinator.service(&mut io).unwrap_err();

            assert!(error.lifecycle(), "authorization {authorization:?}");
            assert_eq!(
                coordinator.counters(),
                PauseCounters {
                    attempts: 1,
                    confirmed: 0,
                    partial: 0,
                }
            );
            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                1,
                "authorization {authorization:?}"
            );
        }
    }

    #[test]
    fn original_generation_exit_confirms_after_resume() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.post_resume_all_stopped = true;
        io.resume_authorization = Some(None);
        io.original_exited = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.cycles = 1;
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
    }

    #[test]
    fn generation_mismatch_after_resume_is_lifecycle_fatal() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.resume_authorization = Some(None);
        io.same_generation_results = VecDeque::from([Ok(true), Ok(false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.cycles = 1;
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 1,
                confirmed: 0,
                partial: 0,
            }
        );
    }

    #[test]
    fn resume_observation_witnesses_are_bounded_by_the_existing_deadline() {
        for (name, cycles, authorization, exited, now, all_stopped, confirms) in [
            (
                "requested-after-deadline",
                0,
                Some(Some(PAUSE_REQUESTED)),
                false,
                CYCLE_NS + 11,
                false,
                false,
            ),
            (
                "exit-after-deadline",
                1,
                Some(None),
                true,
                CYCLE_NS + 11,
                true,
                false,
            ),
            (
                "running-at-deadline",
                1,
                Some(None),
                false,
                CYCLE_NS + 10,
                false,
                true,
            ),
        ] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            io.resume_authorization = authorization;
            io.original_exited = exited;
            io.post_resume_all_stopped = all_stopped;
            io.post_resume_now = VecDeque::from([Ok(now)]);
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.cycles = cycles;
            coordinator.arm_for_test();

            let result = coordinator.service(&mut io);

            assert_eq!(result.is_ok(), confirms, "{name}: {result:?}");
            assert_eq!(
                coordinator.counters().confirmed,
                u64::from(confirms),
                "{name}"
            );
            assert_eq!(coordinator.counters().partial, 0, "{name}");
        }
    }

    #[test]
    fn changed_task_set_after_resume_is_a_valid_execution_witness() {
        for tasks in [
            [(41, b'R'), (42, b'T'), (43, b'R')].into_iter().collect(),
            [(41, b'R')].into_iter().collect(),
        ] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            io.resume_authorization = Some(None);
            io.states = VecDeque::from([Ok(stopped()), Ok(stopped()), Ok(stopped()), Ok(tasks)]);
            io.post_resume_now = VecDeque::from([Ok(CYCLE_NS + 9)]);
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.cycles = 1;
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        }
    }

    #[test]
    fn all_stopped_at_the_resume_deadline_fails_without_waiting_past_it() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.post_resume_all_stopped = true;
        io.resume_authorization = Some(None);
        io.post_resume_now = VecDeque::from([Ok(CYCLE_NS + 10)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.cycles = 1;
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            io.events.iter().filter(|event| **event == "wait").count(),
            2
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    /// A leader-exit record is produced *after* the arm and still carries the
    /// zero helper result an accepted stop has — its producer is not pause
    /// eligible, so it never enters the exchange at all. The arm clock cannot
    /// tell it from a winner; the map can. An exact ARMED readback proves the
    /// kernel never consumed this arm, so the child was never stopped.
    #[test]
    fn an_unauthorized_zero_record_does_not_cost_an_intact_arm_its_authority() {
        for policy in [PausePolicy::Auto, PausePolicy::Always] {
            let mut io = successful_io(vec![record(6, 0, false)]);
            io.authorization = None;
            io.now = VecDeque::from([Ok(5)]);
            let mut coordinator = PauseCoordinator::for_test(policy, 41, 9, stopped());
            assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);

            coordinator
                .service(&mut io)
                .expect("an intact arm is not a lost stop authorization");

            assert_eq!(
                coordinator.counters(),
                PauseCounters::default(),
                "{policy:?}: an unauthorized zero record is not a stop attempt"
            );
            assert!(coordinator.is_armed(), "{policy:?}: the arm survives");
            assert!(coordinator.rearming_enabled(), "{policy:?}");
            assert_eq!(
                io.applied.len(),
                1,
                "{policy:?}: the record is still applied"
            );
            assert!(!io.events.contains(&"resume"), "{policy:?}");
            assert_eq!(io.authorization, Some(PAUSE_ARMED), "{policy:?}");
        }
    }

    /// The ring still holds records from before the arm — every hook that
    /// fired between epochs produced one, with the same zero helper result an
    /// accepted stop has. None of them won this arm: the producer reads its
    /// causal timestamp *after* the exchange that would have stopped the child.
    /// Consuming the oldest as the epoch's winner must not discard the real
    /// winner still queued behind it.
    #[test]
    fn a_record_older_than_the_arm_is_never_its_epoch_winner() {
        let mut io = successful_io(vec![record(1, 0, false), record(6, 0, false)]);
        io.authorization = None;
        io.now = VecDeque::from([Ok(5)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        coordinator.cycles = 1;
        // The record behind it is the one that won, so the map already reads
        // REQUESTED when the leftover is dequeued.
        io.authorization = Some(PAUSE_REQUESTED);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert!(!coordinator.is_armed());
        assert!(coordinator.rearming_enabled());
        assert_eq!(
            io.applied.len(),
            2,
            "the stale and winner records are each applied once"
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
        assert_eq!(io.authorization, None);
        coordinator.cleanup(&mut io).unwrap();

        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1,
            "the requested map entry is still stop debt, so cleanup resumes the stopped child"
        );
    }

    /// The other half of the same rule: a record this arm *could* have produced
    /// is still confirmed exactly as before.
    #[test]
    fn a_record_the_arm_could_have_produced_still_confirms_the_stop() {
        let mut io = successful_io(vec![record(6, 0, false)]);
        io.authorization = None;
        io.now = VecDeque::from([Ok(5)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        io.authorization = Some(PAUSE_REQUESTED);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    /// Servicing a record this coordinator never owned opens no attempt, so it
    /// must not leave a fixed-cycle failure bound behind either: a cleanup drain one
    /// capture later is bounded from its own clock, not from that record.
    #[test]
    fn an_unowned_record_does_not_bound_a_later_cleanup_drain() {
        let mut io = successful_io(vec![record(6, 0, false)]);
        io.authorization = None;
        io.now = VecDeque::from([Ok(5)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        coordinator.service(&mut io).unwrap();

        io.fallback_now = 2 * CYCLE_NS;
        coordinator
            .cleanup(&mut io)
            .expect("cleanup is bounded from its own clock");
    }

    /// The loud half: without an intact arm to explain it, a zero candidate is
    /// still an unresolved stop — one attempt, one protective resume, retired.
    #[test]
    fn a_zero_candidate_no_arm_explains_is_still_a_lost_stop_authorization() {
        let mut io = successful_io(vec![record(6, 0, false)]);
        io.authorization = None;
        io.now = VecDeque::from([Ok(5)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        // The authorization this arm installed is gone, and nothing consumed
        // it: unexplained, so the candidate stands.
        io.authorization = None;

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 1,
                confirmed: 0,
                partial: 0,
            }
        );
        assert!(!coordinator.rearming_enabled());
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
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
        // The successor's own window: a record this second arm could have
        // produced, not one left over from before it.
        let second = record(io.fallback_now, 0, false);
        io.queue
            .extend([Ok(Some(DiscoveryItem::Record(second))), Ok(None), Ok(None)]);
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
    fn unconsumed_armed_successor_cleanup_preserves_successor_debt() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();
        assert_eq!(io.authorization, Some(PAUSE_ARMED));

        coordinator.cleanup(&mut io).unwrap();

        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1,
            "a bare successor-only debt is cleared when its ARMED state is removed"
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
        assert_eq!(io.applied.len(), 2, "both dequeued records apply once");
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
            vec![
                record(5, COALESCED_NO_HELPER_RC, true),
                record(20, COALESCED_NO_HELPER_RC, true),
            ],
        ] {
            let mut io = successful_io(records);
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(coordinator.counters(), PauseCounters::partial(1));
            assert_eq!(io.applied.len(), 2, "each dequeued record applies once");
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
    fn first_pre_resume_check_applies_its_unexpected_record_once() {
        let first = record(10, 0, false);
        let unexpected = record(20, 0, false);
        let mut io = successful_io(Vec::new());
        io.queue = VecDeque::from([
            Ok(Some(DiscoveryItem::Record(first))),
            Ok(None),
            Ok(Some(DiscoveryItem::Record(unexpected))),
        ]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(io.applied.len(), 2);
        assert_eq!(io.applied[0].hook_ts_ns, 10);
        assert_eq!(io.applied[1].hook_ts_ns, 20);
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
    fn empty_outer_tick_then_bounded_winner_confirms() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            queue: VecDeque::from([
                Ok(None),
                Ok(Some(DiscoveryItem::Record(record(4, 0, false)))),
                Ok(None),
                Ok(None),
            ]),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
    }

    #[test]
    fn requested_empty_tick_is_bounded_auto_partial_with_one_protective_resume() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(!coordinator.rearming_enabled());
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn requested_empty_tick_is_required_always_cleanup() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.required());
        assert_eq!(coordinator.counters().partial, 0);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn armed_empty_tick_has_no_attempt_or_resume() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_ARMED),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::default());
        assert!(!io.events.contains(&"resume"));
    }

    #[test]
    fn armed_empty_tick_then_requested_tick_never_leaves_request_unresolved() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_ARMED),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();
        io.authorization = Some(PAUSE_REQUESTED);
        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn requested_empty_tick_authorization_error_is_lifecycle_fatal() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            fail_read: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(coordinator.counters().partial, 0);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn armed_absent_or_unknown_authorization_is_lifecycle_without_resume() {
        for authorization in [None, Some(999)] {
            let mut io = FakeIo {
                authorization,
                ..FakeIo::default()
            };
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            let error = coordinator.service(&mut io).unwrap_err();

            assert!(error.lifecycle(), "authorization {authorization:?}");
            assert_eq!(
                coordinator.counters().partial,
                0,
                "authorization {authorization:?}"
            );
            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                0,
                "authorization {authorization:?}"
            );
        }
    }

    #[test]
    fn requested_empty_tick_cancellation_is_lifecycle_fatal_and_resumes_once() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            cancelled: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(coordinator.counters().partial, 0);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn requested_empty_tick_ring_loss_is_a_bounded_partial_with_one_resume() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            ring_losses: VecDeque::from([Ok(0), Ok(1)]),
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
    fn first_authorization_read_error_removes_without_resume() {
        let mut io = FakeIo {
            authorization_results: VecDeque::from([Err("first read".into()), Ok(None)]),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert!(io.events.contains(&"remove"));
        assert!(!io.events.contains(&"resume"));
    }

    #[test]
    fn requested_debt_survives_later_auth_error_with_one_resume() {
        let mut io = FakeIo {
            authorization_results: VecDeque::from([
                Ok(Some(PAUSE_REQUESTED)),
                Err("later read".into()),
                Ok(None),
            ]),
            ring_losses: VecDeque::from([Ok(0), Ok(1)]),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn unknown_or_absent_auth_without_debt_never_resumes_even_after_ring_loss() {
        for authorization in [Ok(Some(999)), Err("read".into())] {
            let mut io = FakeIo {
                authorization_results: VecDeque::from([
                    authorization.clone(),
                    authorization.clone(),
                ]),
                ring_losses: VecDeque::from([Ok(1)]),
                ..FakeIo::default()
            };
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            let error = coordinator.service(&mut io).unwrap_err();

            assert!(error.lifecycle(), "authorization {authorization:?}");
            assert!(
                !io.events.contains(&"resume"),
                "authorization {authorization:?}"
            );
        }
    }

    #[test]
    fn unknown_or_absent_auth_after_requested_debt_resumes_once() {
        for authorization in [Ok(Some(999)), Ok(None), Err("read".into())] {
            let mut io = FakeIo {
                authorization_results: VecDeque::from([
                    Ok(Some(PAUSE_REQUESTED)),
                    authorization.clone(),
                    Ok(None),
                ]),
                ring_losses: VecDeque::from([Ok(0), Ok(1)]),
                ..FakeIo::default()
            };
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            let error = coordinator.service(&mut io).unwrap_err();
            assert!(error.lifecycle(), "authorization {authorization:?}");
            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                1,
                "authorization {authorization:?}"
            );
        }
    }

    #[test]
    fn stale_record_is_applied_then_winner_uses_the_same_request_deadline() {
        let stale = record(4, 0, false);
        let winner = record(6, 0, false);
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            queue: VecDeque::from([
                Ok(None),
                Ok(Some(DiscoveryItem::Record(stale))),
                Ok(Some(DiscoveryItem::Record(winner))),
                Ok(None),
                Ok(None),
            ]),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.armed_at_ns = Some(5);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(io.applied.len(), 2);
        assert_eq!(io.applied[0].hook_ts_ns, 4);
        assert_eq!(io.applied[1].hook_ts_ns, 6);
        assert_eq!(io.apply_pause_owned, [false, true]);
        assert_eq!(io.apply_deadlines, [Some(CYCLE_NS + 3), Some(CYCLE_NS + 3)]);
    }

    #[test]
    fn armed_stale_record_rereads_requested_after_bounded_apply() {
        let stale = record(1, 0, false);
        let winner = record(4, 0, false);
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            authorization_results: VecDeque::from([
                Ok(Some(PAUSE_ARMED)),
                Ok(Some(PAUSE_REQUESTED)),
                Ok(Some(PAUSE_REQUESTED)),
            ]),
            queue: VecDeque::from([
                Ok(Some(DiscoveryItem::Record(stale))),
                Ok(Some(DiscoveryItem::Record(winner))),
                Ok(None),
                Ok(None),
            ]),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.armed_at_ns = Some(3);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(io.apply_pause_owned, [false, true]);
        assert_eq!(io.apply_deadlines, [Some(CYCLE_NS + 2), Some(CYCLE_NS + 2)]);
    }

    #[test]
    fn stale_records_until_exact_deadline_resume_once_without_extension() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            queue: VecDeque::from([
                Ok(None),
                Ok(Some(DiscoveryItem::Record(record(9, 0, false)))),
                Ok(None),
            ]),
            now: VecDeque::from([
                Ok(0),
                Ok(0),
                Ok(0),
                Ok(CYCLE_NS - 1),
                Ok(CYCLE_NS - 1),
                Ok(CYCLE_NS),
                Ok(CYCLE_NS),
            ]),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.armed_at_ns = Some(10);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn stale_record_application_failure_resumes_once() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            queue: VecDeque::from([
                Ok(None),
                Ok(Some(DiscoveryItem::Record(record(9, 0, false)))),
            ]),
            fail_apply: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.armed_at_ns = Some(10);

        coordinator.service(&mut io).unwrap();
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn post_insert_map_read_failure_removes_without_resume_without_request() {
        let mut io = FakeIo {
            authorization_results: VecDeque::from([
                Err("post-insert read".into()),
                Ok(Some(PAUSE_ARMED)),
            ]),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());

        let error = coordinator.arm(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(io.authorization, None);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            0
        );
    }

    #[test]
    fn deadline_checks_wrap_future_and_after_dequeue_fail_without_reset() {
        let mut late = successful_io(vec![record(10, 0, false)]);
        late.now = VecDeque::from([Ok(10), Ok(CYCLE_NS + 11)]);
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
    fn timed_dequeue_distinguishes_deadline_from_clock_queue_and_generation_failures() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());

        let mut deadline = FakeIo {
            now: VecDeque::from([Ok(CYCLE_NS + 1)]),
            ..FakeIo::default()
        };
        assert!(matches!(
            coordinator.timed_dequeue(&mut deadline, Some(CYCLE_NS)),
            Err(TimedDequeueError::Deadline(_))
        ));

        let mut clock = FakeIo {
            now: VecDeque::from([Err("clock".into())]),
            ..FakeIo::default()
        };
        assert!(matches!(
            coordinator.timed_dequeue(&mut clock, Some(CYCLE_NS)),
            Err(TimedDequeueError::Failure(_))
        ));

        let mut queue = FakeIo {
            now: VecDeque::from([Ok(0)]),
            queue: VecDeque::from([Err("queue".into())]),
            ..FakeIo::default()
        };
        assert!(matches!(
            coordinator.timed_dequeue(&mut queue, Some(CYCLE_NS)),
            Err(TimedDequeueError::Failure(_))
        ));

        let mut generation = FakeIo {
            now: VecDeque::from([Ok(0), Ok(0)]),
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(record(0, 0, false))))]),
            same_generation_results: VecDeque::from([Ok(false)]),
            ..FakeIo::default()
        };
        assert!(matches!(
            coordinator.timed_dequeue(&mut generation, Some(CYCLE_NS)),
            Err(TimedDequeueError::Failure(_))
        ));
    }

    #[test]
    fn timed_dequeue_sinks_validated_records_and_counts_changed_generation_once() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        let mut clock = FakeIo {
            now: VecDeque::from([Ok(1), Err("post-clock".into())]),
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(record(1, 0, false))))]),
            ..FakeIo::default()
        };
        let error = match coordinator.timed_dequeue(&mut clock, Some(CYCLE_NS)) {
            Err(error) => error,
            Ok(_) => panic!("post-clock failure must retain the removed record"),
        };
        assert!(error.lifecycle());
        assert!(matches!(error, TimedDequeueError::Failure(_)));
        assert_eq!(coordinator.pending_records.len(), 1);
        assert_eq!(coordinator.unvalidated_records, 0);

        let mut changed = FakeIo {
            now: VecDeque::from([Ok(1), Ok(2)]),
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(record(2, 0, false))))]),
            same_generation_results: VecDeque::from([Ok(false)]),
            ..FakeIo::default()
        };
        let error = match coordinator.timed_dequeue(&mut changed, Some(CYCLE_NS)) {
            Err(error) => error,
            Ok(_) => panic!("generation change must reject the removed record"),
        };
        assert!(matches!(error, TimedDequeueError::Failure(_)));
        assert_eq!(coordinator.pending_records.len(), 1);
        assert_eq!(coordinator.unvalidated_records, 1);
    }

    #[test]
    fn direct_generation_loss_precedes_a_coincident_deadline() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        let mut io = FakeIo {
            now: VecDeque::from([Ok(1), Ok(CYCLE_NS + 1)]),
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(record(1, 0, false))))]),
            same_generation_results: VecDeque::from([Ok(false)]),
            ..FakeIo::default()
        };

        let error = match coordinator.timed_dequeue(&mut io, Some(CYCLE_NS)) {
            Err(error) => error,
            Ok(_) => panic!("generation loss must fail the direct dequeue"),
        };

        assert!(matches!(&error, TimedDequeueError::Failure(_)));
        assert!(error.message().contains("generation changed"));
        assert!(coordinator.pending_records.is_empty());
        assert_eq!(coordinator.unvalidated_records, 1);
    }

    #[test]
    fn unvalidated_record_is_counted_only_by_terminal_cleanup() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        let mut io = FakeIo {
            now: VecDeque::from([Ok(1), Ok(2)]),
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(record(2, 0, false))))]),
            same_generation_results: VecDeque::from([Err("generation".into())]),
            ..FakeIo::default()
        };
        let error = match coordinator.timed_dequeue(&mut io, Some(CYCLE_NS)) {
            Err(error) => error,
            Ok(_) => panic!("generation read failure must reject the removed record"),
        };
        assert!(matches!(error, TimedDequeueError::Failure(_)));

        coordinator.terminal_cleanup(&mut io).unwrap();

        assert!(io.applied.is_empty());
        assert_eq!(io.apply_pause_owned, [false]);
        assert_eq!(io.unvalidated_records, 1);
        assert_eq!(coordinator.counters().confirmed, 0);
    }

    #[test]
    fn terminal_cleanup_applies_validated_and_accounts_unvalidated() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.pending_records.push(record(1, 0, false));
        coordinator.unvalidated_records = 3;
        let mut io = FakeIo::default();

        coordinator.terminal_cleanup(&mut io).unwrap();

        assert_eq!(
            io.events,
            [
                "detach",
                "dequeue",
                "account",
                "unvalidated",
                "read",
                "remove"
            ]
        );
        assert_eq!(io.applied.len(), 1);
        assert_eq!(io.unvalidated_records, 3);
    }

    #[test]
    fn terminal_cleanup_reclaims_validated_record_retained_by_drain_failure() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.failure_deadline = Some(CYCLE_NS);
        let mut io = FakeIo {
            now: VecDeque::from([Ok(1), Err("post-clock".into())]),
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(record(1, 1, false))))]),
            ..FakeIo::default()
        };

        let error = coordinator.terminal_cleanup(&mut io).unwrap_err();

        assert!(error.to_string().contains("post-clock"));
        assert_eq!(io.applied.len(), 1);
        assert_eq!(io.applied[0].hook_ts_ns, 1);
        assert_eq!(io.unvalidated_records, 0);
    }

    #[test]
    fn round7_cleanup_only_failures_do_not_skip_child_safe_cleanup_or_resume_twice() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.epoch.authorization_consumed = true;
        coordinator.may_be_stopped = true;
        coordinator.pending_records.push(record(1, 0, false));
        coordinator.unvalidated_records = 2;
        let mut io = FakeIo {
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Malformed)), Ok(None), Ok(None)]),
            terminal_cleanup_results: VecDeque::from([
                Err("registry remove one".into()),
                Err("registry remove two".into()),
                Ok(()),
            ]),
            terminal_authority_pending: true,
            ..FakeIo::default()
        };

        let first = coordinator.cleanup(&mut io).unwrap_err();

        assert!(first.lifecycle());
        assert_eq!(io.applied.len(), 1);
        assert_eq!(io.unvalidated_records, 2);
        assert_eq!(
            io.events.iter().filter(|event| **event == "detach").count(),
            1
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
        assert_eq!(
            io.events
                .iter()
                .filter(|event| **event == "discard")
                .count(),
            2
        );
        assert!(io.terminal_authority_pending);
        assert!(!coordinator.cleaned);

        coordinator.cleanup(&mut io).unwrap();
        assert_eq!(
            io.events.iter().filter(|event| **event == "detach").count(),
            2
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
        assert_eq!(
            io.events
                .iter()
                .filter(|event| **event == "discard")
                .count(),
            3
        );
        assert!(!io.terminal_authority_pending);
        assert!(coordinator.cleaned);
    }

    #[test]
    fn round7_reconciliation_error_still_removes_authorization_and_resumes() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.epoch.authorization_consumed = true;
        coordinator.may_be_stopped = true;
        let mut io = FakeIo {
            reconcile_results: VecDeque::from([Err("authority invariant".into())]),
            ..FakeIo::default()
        };

        let error = coordinator.cleanup(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert!(error.to_string().contains("authority invariant"));
        assert!(io.events.contains(&"detach"));
        assert!(io.events.contains(&"account"));
        assert!(io.events.contains(&"remove"));
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
        assert!(!coordinator.cleaned);
    }

    #[test]
    fn post_dequeue_generation_failure_latches_one_protective_resume() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        let mut io = FakeIo {
            now: VecDeque::from([Ok(1), Ok(2)]),
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(record(1, 0, false))))]),
            same_generation_results: VecDeque::from([Err("generation".into())]),
            authorization: None,
            ..FakeIo::default()
        };

        let error = match coordinator.timed_dequeue(&mut io, Some(CYCLE_NS)) {
            Err(error) => error,
            Ok(_) => panic!("generation failure must fail after dequeue"),
        };
        assert!(coordinator.epoch.zero_candidate);
        assert!(coordinator.may_be_stopped);
        coordinator
            .fail_cycle(&mut io, error.message(), true)
            .unwrap_err();

        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
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
        assert!(!coordinator.may_be_stopped);
        assert!(!coordinator.epoch.authorization_consumed);
    }

    #[test]
    fn rejected_lifecycle_failure_applies_every_validated_record_once_without_resume() {
        let rejected = record(10, -libc::EPERM as i64, false);
        let invalid = record(20, 0, false);
        let mut io = successful_io(Vec::new());
        io.queue = VecDeque::from([
            Ok(Some(DiscoveryItem::Record(rejected))),
            Ok(Some(DiscoveryItem::Record(invalid))),
            Ok(None),
        ]);
        io.same_generation_results = VecDeque::from([Ok(true), Ok(true), Ok(false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(io.applied.len(), 2);
        assert_eq!(io.applied[0].hook_ts_ns, 10);
        assert_eq!(io.applied[1].hook_ts_ns, 20);
        assert!(!io.events.contains(&"resume"));
    }

    #[test]
    fn rejected_helper_is_classified_before_all_timestamp_failures() {
        let cases = [
            (u64::MAX, VecDeque::new()),
            (10, VecDeque::from([Ok(CYCLE_NS + 11), Ok(CYCLE_NS + 12)])),
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
            authorization: None,
            revalidation_required_complete: false,
            revalidation_consumes_winner: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.revalidate_after_release(&mut io).unwrap_err();

        assert_eq!(io.events.first(), Some(&"revalidate"));
        assert!(error.lifecycle());
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 1,
                confirmed: 0,
                partial: 0,
            }
        );
        assert_eq!(io.authorization, None);
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1,
            "the coordinator ledger owns the consumed winner's protective resume"
        );
    }

    #[test]
    fn completed_owner_debt_preserves_an_unconsumed_successor_debt() {
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
            "a bare successor-only debt is cleared when its ARMED state is removed"
        );
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 2,
                confirmed: 1,
                partial: 1,
            }
        );
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
            authorization: None,
            revalidation_error: Some(error),
            retirement_stop_candidate_seen: stop_candidate_seen,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.revalidate_after_release(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 1,
                confirmed: 0,
                partial: 0,
            }
        );
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

        let error = coordinator.revalidate_after_release(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 1,
                confirmed: 0,
                partial: 0,
            }
        );
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
            .service_deferred(
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
            .service_deferred(
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
        let mut terminal_batch = None;

        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("a failed terminal drain is loss, never a batch error")
        });

        let batch = terminal_batch
            .as_ref()
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
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("the continued drain completes")
        });

        assert_eq!(
            engine.dispatched_loader_records(),
            2,
            "the continuation dispatched the whole batch exactly once"
        );
        assert!(terminal_batch.is_none());
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
    }

    /// csf_ce5962b revert guard. The deadline a held pause hands to
    /// `SessionPauseIo::apply_batch` must be installed into the Engine's
    /// capture work budget by `apply_discovery_batch_with`; silently dropping
    /// that forward re-ships unbounded scan work while the target is frozen.
    #[test]
    fn the_held_pause_deadline_reaches_the_engine_budget_through_the_real_adapter() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, _owner) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        let mut terminal_batch = None;

        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), Some(u64::MAX), true, false, &mut terminal_batch)
                .expect("an empty drain under a far-future deadline applies")
        });

        assert_eq!(
            engine.installed_budget_deadline_for_test(),
            Some(u64::MAX),
            "the held-pause deadline was not forwarded into the engine's work budget"
        );
    }

    #[test]
    fn round7_adopted_incomplete_batch_collects_to_empty_before_dispatch() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        let unrelated = LoaderContextId::from_case_id(9);
        let mut session = ScriptedSession::with_records([], 16);
        let carried = carried_empty_terminal_batch(&mut engine, &mut session, &child);
        let mut terminal_batch = Some(carried);
        session
            .dequeues
            .extend([queued(unrelated, child.pid()), Ok(None)]);

        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(
                vec![loader_record_for(owner, child.pid())],
                None,
                true,
                false,
                &mut terminal_batch,
            )
            .unwrap()
        });

        assert_eq!(engine.dispatched_loader_records(), 2);
        assert!(session.dequeues.is_empty());
        assert!(terminal_batch.is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
    }

    #[test]
    fn round7_active_revalidation_counts_nested_malformed_once_without_raw_record() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, _) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        session
            .dequeues
            .extend([Ok(Some(DiscoveryItem::Malformed)), Ok(None)]);
        let mut coordinator = PauseCoordinator::for_test(
            PausePolicy::Auto,
            child.pid(),
            child.generation().get(),
            stopped(),
        );
        coordinator.arm_for_test();

        let error = with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator.revalidate_after_release(io).unwrap_err()
        });

        assert!(error.lifecycle());
        assert_eq!(engine.malformed_discovery_for_test(), 1);
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert!(coordinator.pending_records.is_empty());
    }

    #[test]
    fn round7_started_journal_failure_runs_full_cleanup_and_later_flushes_generic_once() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        engine.start_cleanup_only_terminal_journal_for_test(owner);
        let mut session = ScriptedSession::with_records([], 16);
        session
            .dequeues
            .extend([Ok(Some(DiscoveryItem::Malformed)), Ok(None)]);
        session.fail_counter_reads([true]);
        let mut coordinator = PauseCoordinator::for_test(
            PausePolicy::Auto,
            child.pid(),
            child.generation().get(),
            stopped(),
        );
        coordinator.arm_for_test();
        coordinator.epoch.authorization_consumed = true;
        coordinator.may_be_stopped = true;
        coordinator
            .pending_records
            .push(loader_record_for(owner, child.pid()));
        coordinator.unvalidated_records = 2;

        let first = with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator.cleanup(io).unwrap_err()
        });

        assert!(first.lifecycle());
        assert_eq!(
            engine.terminal_journal_for_test(),
            Some((owner, true, true))
        );
        assert_eq!(engine.pending_discovery_records_for_test(), 1);
        assert_eq!(engine.malformed_discovery_for_test(), 1);
        assert_eq!(engine.unvalidated_discovery_for_test(), 2);
        assert_eq!(engine.capture_facts().discovery_truncated, 3);
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert!(!coordinator.cleaned);

        engine.tombstone_loader_context_for_test(owner);
        with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator.cleanup(io).unwrap()
        });
        assert_eq!(engine.pending_discovery_records_for_test(), 0);
        assert_eq!(engine.dispatched_loader_records(), 1);
        assert_eq!(engine.malformed_discovery_for_test(), 1);
        assert_eq!(engine.unvalidated_discovery_for_test(), 2);
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert!(coordinator.cleaned);

        with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator.cleanup(io).unwrap()
        });
        assert_eq!(engine.dispatched_loader_records(), 1);
    }

    #[test]
    fn round7_rejected_cleanup_keeps_the_coordinator_terminal_batch() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        let mut carried = carried_empty_terminal_batch(&mut engine, &mut session, &child);
        carried.extend([loader_record_for(owner, child.pid())]);
        let mut coordinator = PauseCoordinator::for_test(
            PausePolicy::Never,
            child.pid(),
            child.generation().get(),
            stopped(),
        );
        coordinator.terminal_batch = Some(carried);
        engine.start_cleanup_only_terminal_journal_for_test(owner);
        let truncated = engine.capture_facts().discovery_truncated;

        let error = with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator.cleanup(io).unwrap_err()
        });

        assert!(error.lifecycle());
        assert!(error.to_string().contains("dispatched terminal authority"));
        let carried = coordinator
            .terminal_batch
            .as_ref()
            .expect("rejected cleanup keeps coordinator ownership");
        assert_eq!(carried.authority.owner, owner);
        assert_eq!(carried.authority.exports, [terminal_export()]);
        assert_eq!(carried.record_count(), 1);
        assert_eq!(carried.tagged_owners(), [Some(owner)]);
        assert!(!carried.complete());
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert_eq!(engine.capture_facts().discovery_truncated, truncated);
        assert_eq!(
            engine.terminal_journal_for_test(),
            Some((owner, true, true))
        );
    }

    #[test]
    fn real_adapter_nested_generation_loss_counts_without_retaining_raw_bytes() {
        let mut child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        session
            .dequeues
            .push_back(Err(anyhow::anyhow!("start drain")));
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .unwrap()
        });
        assert_eq!(terminal_batch.as_ref().unwrap().record_count(), 0);

        child.release().unwrap();
        assert!(
            child
                .pin()
                .wait_ready(Some(Duration::from_secs(5)))
                .unwrap(),
            "the owned child must reach its ordinary end"
        );
        child.wait_for(Some(Duration::ZERO), false).unwrap();
        session.dequeues.push_back(queued(owner, child.pid()));
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .unwrap()
        });

        assert_eq!(engine.capture_facts().discovery_truncated, 1);
        assert!(terminal_batch.is_none());
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.dispatched_loader_records(), 0);
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
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("a failed terminal drain is loss, never a batch error")
        });
        let carried = terminal_batch
            .take()
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
                .service_deferred(
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
        assert!(
            !retained.complete(),
            "appending the coordinator record cannot prove the collector empty"
        );
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert_eq!(
            engine.loader_context_state_for_test(owner),
            Some("tombstoned")
        );

        with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator
                .service_deferred(
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

    fn carried_empty_terminal_batch(
        engine: &mut Engine,
        session: &mut ScriptedSession,
        child: &OwnedChild,
    ) -> TerminalBatch {
        session
            .dequeues
            .push_back(Err(anyhow::anyhow!("start drain")));
        let mut terminal_batch = None;
        with_session_io(engine, session, child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .unwrap()
        });
        terminal_batch.take().unwrap()
    }

    #[test]
    fn real_terminal_cleanup_retries_the_same_batch_once_and_dispatches_once() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        let carried = carried_empty_terminal_batch(&mut engine, &mut session, &child);
        let mut coordinator = PauseCoordinator::for_test(
            PausePolicy::Never,
            child.pid(),
            child.generation().get(),
            stopped(),
        );
        coordinator.terminal_batch = Some(carried);
        coordinator
            .pending_records
            .push(loader_record_for(owner, child.pid()));
        session.fail_counter_reads([true]);
        let reads = session.counter_reads();

        let error = with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator.cleanup(io).unwrap_err()
        });

        assert!(error.to_string().contains("application failed"), "{error}");
        assert_eq!(
            session.counter_reads() - reads,
            3,
            "one failed application plus the retry's generic and terminal gates"
        );
        assert_eq!(engine.dispatched_loader_records(), 1);
        assert!(coordinator.terminal_batch.is_none());
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
    }

    #[test]
    fn real_terminal_cleanup_two_failures_clear_without_a_third_or_dispatch() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        let carried = carried_empty_terminal_batch(&mut engine, &mut session, &child);
        let mut coordinator = PauseCoordinator::for_test(
            PausePolicy::Never,
            child.pid(),
            child.generation().get(),
            stopped(),
        );
        coordinator.terminal_batch = Some(carried);
        coordinator
            .pending_records
            .push(loader_record_for(owner, child.pid()));
        session.fail_counter_reads([true, true, false]);
        let reads = session.counter_reads();

        with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator.cleanup(io).unwrap_err()
        });

        assert_eq!(session.counter_reads() - reads, 2, "no third application");
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert!(coordinator.terminal_batch.is_none());
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
    }

    #[test]
    fn round6_initial_ordinary_cleanup_continues_new_terminal_authority_once() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, owner) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        session
            .dequeues
            .extend([Ok(None), Err(anyhow::anyhow!("initial terminal drain"))]);
        let mut coordinator = PauseCoordinator::for_test(
            PausePolicy::Never,
            child.pid(),
            child.generation().get(),
            stopped(),
        );
        coordinator
            .pending_records
            .push(loader_record_for(owner, child.pid()));
        let reads = session.counter_reads();

        with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator.cleanup(io).unwrap()
        });

        assert_eq!(session.counter_reads() - reads, 3);
        assert!(coordinator.terminal_batch.is_none());
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
    }

    #[test]
    fn round6_never_cleanup_does_not_turn_an_ordinary_zero_into_pause_debt() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Never, 41, 9, stopped());
        let mut io = FakeIo {
            now: VecDeque::from([Ok(0), Ok(1), Ok(2), Ok(3)]),
            queue: VecDeque::from([
                Ok(Some(DiscoveryItem::Record(record(1, 0, false)))),
                Ok(None),
            ]),
            ..FakeIo::default()
        };

        coordinator.cleanup(&mut io).unwrap();

        assert_eq!(io.apply_pause_owned, [false]);
        assert!(!coordinator.may_be_stopped);
        assert!(!coordinator.epoch.zero_candidate);
        assert!(!io.events.contains(&"resume"));
    }

    #[test]
    fn round6_active_arm_with_absent_authorization_is_lifecycle_loss_without_resume() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        let mut io = FakeIo {
            now: VecDeque::from([Ok(0), Ok(1)]),
            queue: VecDeque::from([Ok(None)]),
            authorization: None,
            ..FakeIo::default()
        };

        let error = coordinator.cleanup(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert!(!io.events.contains(&"resume"));
    }

    #[test]
    fn round6_nested_malformed_is_counted_once_without_a_raw_record() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (mut engine, _) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        let mut terminal_batch = None;
        session
            .dequeues
            .extend([Ok(Some(DiscoveryItem::Malformed)), Ok(None)]);

        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .unwrap()
        });

        assert_eq!(engine.malformed_discovery_for_test(), 1);
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert!(terminal_batch.is_none());
        assert!(engine.terminal_batch_for_test().is_none());
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

        with_session_io(&mut engine, &mut session, &child, |io| {
            coordinator.cleanup(io).unwrap()
        });
        assert_eq!(engine.dispatched_loader_records(), 1);
        assert!(coordinator.terminal_batch.is_none());
        assert!(engine.terminal_batch_for_test().is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
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
            None,
            || clocks.pop_front().expect("two clocks per dequeue"),
            || items.pop_front().expect("one item then empty"),
            || Ok(true),
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
            None,
            || clocks.pop_front().expect("clock for queued record"),
            || items.pop_front().expect("queued record"),
            || Ok(true),
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

    #[test]
    fn nested_deadline_is_marked_at_its_source_not_from_rendered_text() {
        for clocks in [VecDeque::from([Ok(101)]), VecDeque::from([Ok(1), Ok(101)])] {
            let mut clocks = clocks;
            let mut item = Some(DiscoveryItem::Record(record(1, 0, false)));
            let mut stop_candidate_seen = false;
            let nested_deadline = std::cell::Cell::new(false);
            let result = collect_timed_retirement_with(
                41,
                Some(100),
                &mut stop_candidate_seen,
                true,
                Some(&nested_deadline),
                || clocks.pop_front().expect("bounded deadline clocks"),
                || Ok(item.take()),
                || Ok(true),
            );
            assert!(result.is_err());
            assert!(nested_deadline.get());
        }
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
                    None,
                    || clocks.pop_front().expect("clock for queued record"),
                    || items.pop_front().expect("queued record"),
                    || Ok(same_generation),
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
        assert!(generation.records.is_empty());
        assert_eq!(generation.malformed, 0);
        assert_eq!(generation.unvalidated_records, 1);

        let malformed_generation = retained_by(None, DiscoveryItem::Malformed, 0, false);
        assert!(malformed_generation.records.is_empty());
        assert_eq!(malformed_generation.malformed, 1);
        assert_eq!(malformed_generation.unvalidated_records, 0);

        let timing = retained_by(
            Some(100),
            DiscoveryItem::Record(record(50, COALESCED_NO_HELPER_RC, true)),
            50,
            true,
        );
        assert_eq!(timing.records.len(), 1);
        assert_eq!(timing.records[0].hook_ts_ns, 50);
        assert_eq!(timing.unvalidated_records, 0);

        let unaccounted = retained_by(
            Some(100),
            DiscoveryItem::Record(record(1, 0, false)),
            1,
            true,
        );
        assert_eq!(unaccounted.records.len(), 1);
        assert_eq!(unaccounted.records[0].hook_ts_ns, 1);
        assert_eq!(unaccounted.unvalidated_records, 0);
        assert!(
            unaccounted.to_string().contains("duplicate or unaccounted"),
            "{unaccounted:#}"
        );
    }

    #[test]
    fn nested_generation_loss_precedes_a_coincident_deadline() {
        let mut clocks = VecDeque::from([Ok(1), Ok(101)]);
        let mut item = Some(DiscoveryItem::Record(record(1, 0, false)));
        let mut stop_candidate_seen = false;

        let error = match collect_timed_retirement_with(
            41,
            Some(100),
            &mut stop_candidate_seen,
            true,
            None,
            || clocks.pop_front().expect("before and after clocks"),
            || Ok(item.take()),
            || Ok(false),
        ) {
            Err(error) => error.downcast::<IncompleteTerminalDrain>().unwrap(),
            Ok(_) => panic!("generation loss must fail the nested drain"),
        };

        assert!(error.to_string().contains("generation changed"));
        assert!(error.records.is_empty());
        assert_eq!(error.unvalidated_records, 1);
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
        assert!(
            error
                .to_string()
                .contains("[pause_diag=arm_failed_before_epoch]")
        );
        assert_eq!(io.events.first(), Some(&"detach"));
        assert!(!io.events.contains(&"resume"));
    }

    #[test]
    fn auto_arm_failure_is_one_disabled_partial_with_its_pre_epoch_token() {
        let mut io = FakeIo {
            same_generation: false,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());

        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Disabled);

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(!coordinator.rearming_enabled());
        assert!(!coordinator.is_armed());
        assert_eq!(coordinator.pending_diagnostic, None);
    }

    #[test]
    fn always_post_release_incomplete_keeps_the_primary_diagnostic() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.begin_attempt();
        coordinator.set_diagnostic(PauseDiagnostic::PostReleaseRevalidationIncomplete);

        let error = coordinator
            .finish_nonconfirmed(MSG_POST_RELEASE_REVALIDATION_INCOMPLETE.into())
            .unwrap_err();

        assert!(error.required());
        assert_eq!(
            error.to_string(),
            format!(
                "{MSG_POST_RELEASE_REVALIDATION_INCOMPLETE} [pause_diag=post_release_revalidation_incomplete]"
            )
        );
    }

    #[test]
    fn always_annotation_cannot_be_forged_or_suppressed_by_dynamic_text() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.begin_attempt();
        coordinator.set_diagnostic(PauseDiagnostic::PauseHelperRejected);

        let error = coordinator
            .finish_nonconfirmed("dynamic [pause_diag=forged]".into())
            .unwrap_err()
            .to_string();

        assert!(error.contains("pause_diag_escaped=forged"));
        assert!(error.contains("[pause_diag=pause_helper_rejected]"));
        assert_eq!(error.matches("pause_diag=").count(), 1);
    }

    #[test]
    fn always_boundary_failure_is_annotated_without_changing_cleanup_order() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.begin_attempt();
        coordinator.epoch.accepted = true;
        coordinator.may_be_stopped = true;

        let error = coordinator
            .fail_cycle(&mut io, MSG_PAUSE_CONFIRMATION_DEADLINE, false)
            .unwrap_err();

        assert!(error.required());
        assert!(
            error
                .to_string()
                .contains("[pause_diag=later_pause_boundary]")
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "detach").count(),
            1
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "remove").count(),
            1
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1
        );
    }

    #[test]
    fn apply_error_category_cannot_overwrite_an_earlier_primary_category() {
        let mut io = FakeIo {
            fail_apply: true,
            apply_error_diagnostic: Some(PauseDiagnostic::DeadlineDuringEngineApply),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.begin_attempt();
        coordinator.set_diagnostic(PauseDiagnostic::PauseHelperRejected);

        let error = coordinator
            .fail_cycle(&mut io, "primary pause refusal", false)
            .unwrap_err();

        assert!(error.required());
        assert!(
            error
                .to_string()
                .contains("[pause_diag=pause_helper_rejected]")
        );
        assert_eq!(error.to_string().matches("pause_diag=").count(), 1);
    }

    #[test]
    fn failure_cleanup_apply_category_cannot_overwrite_primary_fallback() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            fail_terminal_apply: true,
            apply_error_diagnostic: Some(PauseDiagnostic::DeadlineBeforeEngineApply),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.epoch.accepted = true;
        coordinator.may_be_stopped = true;

        let error = coordinator
            .fail_cycle(&mut io, "primary pause refusal", false)
            .unwrap_err();

        assert!(error.required());
        assert!(
            error
                .to_string()
                .contains("[pause_diag=other_auto_nonconfirmed]")
        );
        assert_eq!(error.to_string().matches("pause_diag=").count(), 1);
        let detach = io.events.iter().position(|event| *event == "detach");
        let apply = io.events.iter().position(|event| *event == "account");
        let remove = io.events.iter().position(|event| *event == "remove");
        let resume = io.events.iter().position(|event| *event == "resume");
        assert!(
            detach.unwrap() < apply.unwrap()
                && apply.unwrap() < remove.unwrap()
                && remove.unwrap() < resume.unwrap()
        );
    }

    #[test]
    fn successful_failure_cleanup_apply_adopts_its_typed_category() {
        let mut io = FakeIo {
            apply_outcome_diagnostic: Some(PauseDiagnostic::DeadlineDuringEngineApply),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());

        let error = coordinator
            .terminal_cleanup_with_cause(&mut io, vec!["lifecycle".into()], false, true)
            .unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            coordinator.pending_diagnostic,
            Some(PauseDiagnostic::DeadlineDuringEngineApply)
        );
        assert!(io.events.contains(&"account"));
    }

    #[test]
    fn terminal_preserves_required_failure_and_cleanup_errors() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.fail_apply = true;
        io.apply_error_diagnostic = Some(PauseDiagnostic::DeadlineDuringEngineApply);
        io.fail_detach = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.required());
        assert!(error.lifecycle());
        assert!(
            error
                .to_string()
                .contains("[pause_diag=deadline_during_engine_apply]")
        );
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
        assert!(
            error
                .to_string()
                .contains("[pause_diag=pause_helper_rejected]")
        );
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

            coordinator.cleanup(&mut io).unwrap();

            assert!(!io.events.contains(&"resume"));
        }

        // A zero candidate over an *intact* arm is refuted, not debt: ARMED is
        // proof the kernel never consumed it. Only a candidate no arm explains
        // keeps the protective resume.
        for (authorization, resumes) in [(Some(PAUSE_ARMED), 0), (None, 1)] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            io.authorization = authorization;
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();
            let result = coordinator.service(&mut io);
            if authorization.is_none() {
                assert!(result.unwrap_err().lifecycle());
            } else {
                result.unwrap();
            }
            coordinator.cleanup(&mut io).unwrap();
            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                resumes,
                "{authorization:?}"
            );
        }
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
        assert!(!coordinator.cleaned);
        io.fail_detach = false;
        io.fail_remove = false;
        coordinator.cleanup(&mut io).unwrap();
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1,
            "the full retry must not resume twice"
        );
        assert!(coordinator.cleaned);
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

    #[test]
    fn pause_diagnostics_render_one_bounded_line_each() {
        let cases = [
            (
                PauseDiagnostic::ArmFailedBeforeEpoch,
                "arm_failed_before_epoch",
            ),
            (
                PauseDiagnostic::PostReleaseRevalidationIncomplete,
                "post_release_revalidation_incomplete",
            ),
            (
                PauseDiagnostic::PauseHelperRejected,
                "pause_helper_rejected",
            ),
            (
                PauseDiagnostic::DeadlineBeforeEngineApply,
                "deadline_before_engine_apply",
            ),
            (
                PauseDiagnostic::DeadlineDuringEngineApply,
                "deadline_during_engine_apply",
            ),
            (
                PauseDiagnostic::EngineIncompleteWithinDeadline,
                "engine_incomplete_within_deadline",
            ),
            (
                PauseDiagnostic::NestedCollectorDeadline,
                "nested_collector_deadline",
            ),
            (PauseDiagnostic::LaterPauseBoundary, "later_pause_boundary"),
            (
                PauseDiagnostic::OtherAutoNonconfirmed,
                "other_auto_nonconfirmed",
            ),
        ];
        for (diagnostic, token) in cases {
            let line = render_pause_diagnostic(diagnostic);
            assert_eq!(
                line,
                format!("p11scope: pause: partial [pause_diag={token}]"),
                "every diagnostic has one exact bounded rendering"
            );
            assert_eq!(line.matches("pause_diag=").count(), 1);
        }
    }

    #[test]
    fn pause_diagnostic_message_mapping_is_exact_and_unknown_is_fallback() {
        assert_eq!(
            diagnostic_for_message(MSG_ARM_FAILED),
            Some(PauseDiagnostic::ArmFailedBeforeEpoch)
        );
        assert_eq!(
            diagnostic_for_message(MSG_POST_RELEASE_REVALIDATION_INCOMPLETE),
            Some(PauseDiagnostic::PostReleaseRevalidationIncomplete)
        );
        assert_eq!(
            diagnostic_for_message(MSG_PAUSE_HELPER_REJECTED),
            Some(PauseDiagnostic::PauseHelperRejected)
        );
        assert_eq!(
            diagnostic_for_message(MSG_NESTED_DEADLINE_BEFORE),
            Some(PauseDiagnostic::NestedCollectorDeadline)
        );
        assert_eq!(
            diagnostic_for_message(MSG_NESTED_DEADLINE_AFTER),
            Some(PauseDiagnostic::NestedCollectorDeadline)
        );
        assert_eq!(
            diagnostic_for_message("not a recognized pause message"),
            None
        );
        for message in [
            MSG_DEADLINE_BEFORE_DEQUEUE,
            MSG_DEADLINE_AFTER_DEQUEUE,
            MSG_PAUSE_CONFIRMATION_DEADLINE,
            MSG_PAUSE_RESUME_DEADLINE,
            MSG_PAUSE_CAUSAL_DEADLINE,
            MSG_COALESCED_RECORD_DEADLINE,
        ] {
            assert_eq!(
                diagnostic_for_message(message),
                Some(PauseDiagnostic::LaterPauseBoundary)
            );
        }
    }

    #[test]
    fn apply_diagnostic_precedence_requires_strict_deadline_crossing() {
        assert_eq!(
            classify_apply_diagnostic(Some(101), Some(102), Some(100), true, false),
            Some(PauseDiagnostic::DeadlineBeforeEngineApply)
        );
        assert_eq!(
            classify_apply_diagnostic(Some(100), Some(101), Some(100), true, false),
            Some(PauseDiagnostic::DeadlineDuringEngineApply)
        );
        assert_eq!(
            classify_apply_diagnostic(Some(100), Some(100), Some(100), false, false),
            Some(PauseDiagnostic::EngineIncompleteWithinDeadline)
        );
        assert_eq!(
            classify_apply_diagnostic(Some(100), Some(101), Some(100), true, true,),
            Some(PauseDiagnostic::NestedCollectorDeadline)
        );
        assert_eq!(
            classify_apply_diagnostic(None, None, Some(100), false, false),
            None
        );
        assert_eq!(
            classify_apply_diagnostic(Some(100), Some(101), None, false, false),
            None
        );
        assert_eq!(
            classify_apply_diagnostic(Some(100), Some(100), Some(100), true, false),
            None
        );
    }

    #[test]
    fn coordinator_diagnostic_is_first_cause_and_clears_on_emission() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.begin_attempt();
        coordinator.set_diagnostic(PauseDiagnostic::LaterPauseBoundary);
        coordinator.set_diagnostic(PauseDiagnostic::PauseHelperRejected);
        assert_eq!(
            coordinator.pending_diagnostic,
            Some(PauseDiagnostic::LaterPauseBoundary)
        );
        assert_eq!(
            coordinator.emit_partial_diagnostic(),
            "p11scope: pause: partial [pause_diag=later_pause_boundary]"
        );
        assert_eq!(coordinator.pending_diagnostic, None);
        coordinator.attempt_open = false;
        coordinator.begin_attempt();
        assert_eq!(coordinator.pending_diagnostic, None);
    }
}
