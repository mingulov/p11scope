//! SPDX-License-Identifier: GPL-3.0-or-later
use crate::run::OwnedChild;
use crate::{
    attach,
    discovery::engine::{
        DISCOVERY_HELD_CAP, DeferredDiscoveryItem, DiscoveryCapacityBlocked, Engine, EngineSession,
        IncompleteTerminalDrain, TerminalBatch,
    },
};
use p11scope_ebpf_common::{
    COALESCED_NO_HELPER_RC, DISCOVERY_STATUS_COALESCED_NO_HELPER, DiscoveryRecord, PAUSE_ARMED,
    PAUSE_REQUESTED,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub(crate) use crate::events::DiscoveryItem;

/// The fixed causal deadline: a stop's cycle must finish within this long of
/// its hook. Crate-visible so the run loop's gate tests measure against it.
pub(crate) const CYCLE_NS: u64 = 500_000_000;
const SAMPLE_NS: u64 = 1_000_000;
/// Upper bound on the first sample's settling re-samples: one per sample
/// interval of a cycle. The cycle deadline normally ends it first.
const MAX_SETTLE_SAMPLES: u64 = CYCLE_NS / SAMPLE_NS;
/// Stops one arm may chain after its first (GT-4). A confirmed stop installs
/// a successor while the child is still stopped, so the owned child's next
/// pause-eligible event — a loader hit, a `C_GetFunctionList` /
/// `C_GetInterface` return — is stopped too and its discovery is applied
/// before the child runs on. An owned child that `dlopen`s one provider needs
/// about five: two startup loader hits, the `dlopen`'s RT_ADD and
/// RT_CONSISTENT, and the table-publishing return. Sixteen leaves room for the
/// provider's own dependencies and still bounds the cost (a few milliseconds
/// per stop) for a child that loads libraries continuously: after the budget
/// the child runs unpaused until the next frame re-arms, and a table still
/// unpublished then is reported as a gap (`PauseIo::note_unpaused_publication`).
pub(crate) const MAX_SUCCESSORS_PER_ARM: u8 = 16;
/// Consecutive engine-incomplete re-arms before the chain retires with a
/// counted named gap. The run continues (never-stop); only the pause chain
/// ends, loudly, instead of re-arming once per loader hit without bound.
const MAX_CONSECUTIVE_ENGINE_INCOMPLETE: u32 = 3;
const MSG_UNPAUSED_PUBLICATION: &str = "the owned pause chain ended while a provider's function table was still unpublished; calls before its probes attach may be unobserved";
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
const MSG_UNSERVICED_AT_CLEANUP: &str = "the capture ended before a pause cycle serviced its stop";
const MSG_TASK_SET_CHANGED: &str = "task set changed or was not entirely stopped";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

fn render_pause_incomplete_retirement(consecutive: u64) -> String {
    format!(
        "p11scope: pause: partial [pause_diag={}] (retired after {consecutive} consecutive incomplete cycles)",
        PauseDiagnostic::EngineIncompleteWithinDeadline.token()
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
    /// `--pause always` degrades that collected unpaused instead of
    /// aborting (never-stop F-16). Each counts as partial for the
    /// status and the `PARTIAL` verdict.
    pub(crate) unavailable: u64,
}

impl PauseCounters {
    #[allow(dead_code)] // Test-only constructor; production counts via begin_attempt.
    fn confirmed(attempts: u64) -> Self {
        Self {
            attempts,
            confirmed: attempts,
            partial: 0,
            unavailable: 0,
        }
    }

    #[allow(dead_code)] // Test-only constructor; production counts via begin_attempt.
    fn partial(attempts: u64) -> Self {
        Self {
            attempts,
            confirmed: 0,
            partial: attempts,
            unavailable: 0,
        }
    }

    pub(crate) fn status(self) -> PauseStatus {
        match (self.attempts, self.partial, self.unavailable) {
            (0, _, _) => PauseStatus::None,
            (_, 0, 0) => PauseStatus::Sigstop,
            _ => PauseStatus::Partial,
        }
    }

    fn valid(self) -> bool {
        self.confirmed
            .saturating_add(self.partial)
            .saturating_add(self.unavailable)
            == self.attempts
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

/// One task's `/proc` state letter and kernel start time (boot-relative
/// clock ticks), taken from a single read of its `stat` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskSample {
    pub(crate) state: u8,
    pub(crate) start: Option<u64>,
}

/// The coordinator owns policy, not Aya. This fixed-purpose seam is also the
/// complete failure-injection surface: one clock, task reader, task-start
/// reader, hook-attach clock, discovery owner, authorization map, Engine batch
/// application, marker, pidfd resume, and terminal detach action.
pub(crate) trait PauseIo {
    fn now_ns(&mut self) -> Result<u64, String>;
    fn wait_one_ms(&mut self) -> Result<(), String>;
    fn task_states(&mut self, pid: u32) -> Result<BTreeMap<u32, u8>, String>;
    /// Every task of `pid` with its state letter and kernel start time in
    /// boot-relative clock ticks (`/proc/<pid>/task/<tid>/stat` fields 3 and
    /// 22), both from one read of each `stat` file. A `None` start is undated
    /// and never treated as covered.
    fn task_samples(&mut self, pid: u32) -> Result<BTreeMap<u32, TaskSample>, String>;
    /// When the last provider hook attach completed, in `CLOCK_BOOTTIME`
    /// nanoseconds (the start-time-tick domain). `None` when no attach has
    /// completed or one is still in flight: then no thread born after
    /// preflight dates as covered.
    fn last_hook_attach_boot_ns(&mut self) -> Option<u64>;
    /// The `CLOCK_BOOTTIME` reading, in nanoseconds (the hook-attach clock's
    /// domain); `None` when it cannot be read.
    fn boot_now_ns(&mut self) -> Option<u64>;
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

    /// Whether the owned child still has a provider whose function table is
    /// not published: its probes are not all attached yet.
    fn publication_pending(&mut self) -> bool {
        false
    }

    /// The owned pause chain ended while `publication_pending` held.
    fn note_unpaused_publication(&mut self) {}

    /// A cycle did not confirm: its stop protects nothing.
    fn note_unconfirmed_cycle(&mut self) {}
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

/// Gap-free hold of the owned child across the first pause epoch
/// (R2-D1-6 proof source (i)): the pause-proven segment of the from-start
/// hold the pre-arm exactness builder checks. A held child can neither map
/// nor call. The segment alone does not prove the window: the child may
/// run its command before the first *verified* pause stop, so the
/// builder additionally requires every declared first-stamp to precede the
/// barrier release — pre-release windows are barrier-covered exactly, and
/// post-release stamps withhold the proof. The owned `run` path composes
/// the claim start (its pre-spawn scope start, bridged by spawn order and
/// the pre-exec barrier) and the release bound with this segment; the
/// builder emits the proof only when the composed interval covers a
/// pre-release window, and assembly still exact-matches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PauseGateHold {
    /// Lower bound on the arm that opened the hold: the first arm's
    /// `armed_at_ns`, installed before the barrier release. `None` when the
    /// arm clock read failed: unboundable, never exact.
    pub(crate) start_ns: Option<u64>,
    /// Last instant the child was proven stopped before the first resume:
    /// the latest stopped-sample clock of the first completed pause cycle,
    /// sampled after the cycle's attach batch. `None` until the first
    /// resume freezes a hold (an armed-but-never-stopped child ran free).
    pub(crate) end_ns: Option<u64>,
    /// The first epoch stayed gap-free. Anything unproven before the
    /// first resume voids it, sticky: a failed cycle, a rejected or
    /// refuted stop, a revalidation failure, a missing clock. The freeze at
    /// the first completing resume is immutable: a re-arm starts a new
    /// interval (the child ran between), and a later gap is after the
    /// proven end, so neither moves nor voids the frozen hold.
    pub(crate) continuous: bool,
}

pub(crate) struct PauseCoordinator {
    policy: PausePolicy,
    pid: u32,
    generation: u64,
    expected_tasks: BTreeMap<u32, u8>,
    /// Kernel start time (boot-relative ticks) of each expected task: thread
    /// identity is the (tid, start time) pair, so a reused tid never passes
    /// as the thread the preflight saw.
    expected_starts: BTreeMap<u32, u64>,
    counters: PauseCounters,
    epoch: PauseEpoch,
    armed: bool,
    /// Monotonic clock read immediately *before* the exchange that installed
    /// the live authorization, so it is a lower bound on when the kernel could
    /// first see it. `None` when no arm recorded one, which keeps every record
    /// a candidate.
    armed_at_ns: Option<u64>,
    /// First arm's `armed_at_ns` snapshot: the hold's start bound. Never
    /// overwritten by successor installs, which only move the live arm.
    hold_start_ns: Option<u64>,
    /// A first arm already ran: the start snapshot is first-arm-only, so a
    /// re-arm after a clockless first arm cannot smuggle in a later bound.
    hold_armed_once: bool,
    /// Latest stopped-sample instant of the first epoch, frozen at the
    /// first completing resume; later cycles never move it, and the
    /// accessor publishes it only once frozen.
    hold_end_ns: Option<u64>,
    /// Sticky pre-freeze gap latch (fail-closed): any unproven break
    /// before the first resume voids the from-start claim.
    hold_void: bool,
    /// The first pause cycle completed its resume: the hold is frozen.
    hold_frozen: bool,
    rearming_enabled: bool,
    may_be_stopped: bool,
    attempt_open: bool,
    /// A cleanup discovered an unserviced stop (it opened the attempt) that
    /// no successful cleanup has classified yet. Survives a failed cleanup;
    /// the first successful cleanup after discovery applies it, so the retry
    /// does not lose the classification to the attempt-open transition.
    unserviced_stop_pending: bool,
    ring_loss_baseline: u64,
    active_deadline: Option<u64>,
    failure_deadline: Option<u64>,
    failure_items: usize,
    pending_records: Vec<DiscoveryRecord>,
    unvalidated_records: u64,
    terminal_batch: Option<TerminalBatch>,
    pending_diagnostic: Option<PauseDiagnostic>,
    diagnostic_annotated: bool,
    /// Consecutive engine-incomplete cycles. Reset on every confirmed
    /// cycle and on every non-incomplete failure, so "consecutive" stays
    /// literal; reaching the cap retires the chain with a counted named
    /// gap instead of re-arming again.
    consecutive_engine_incomplete: u32,
    /// Engine-incomplete cap retirements this run. Each is one counted
    /// partial with a named retirement line, surfaced in JSON as
    /// `evidence.pause_engine_incomplete_retirements`.
    engine_incomplete_retirements: u64,
    /// Per-kind partial-diagnostic emission counts this run. Stderr
    /// shows each kind once (first occurrence); the retirement count
    /// above is what JSON consumers read.
    diagnostic_emit_counts: BTreeMap<PauseDiagnostic, u64>,
    /// Successors this arm may still install (`MAX_SUCCESSORS_PER_ARM`).
    successors_left: u8,
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
        let samples = io
            .task_samples(child.pid())
            .map_err(|error| Self::policy_error(policy, error, true))?;
        let expected_tasks: BTreeMap<u32, u8> = samples
            .iter()
            .map(|(tid, sample)| (*tid, sample.state))
            .collect();
        if expected_tasks.is_empty() || !child.pin().still_the_same() {
            return Err(Self::policy_error(
                policy,
                "owned child generation changed during pause preflight",
                true,
            ));
        }
        let mut coordinator = Self::new(
            policy,
            child.pid(),
            child.generation().get(),
            expected_tasks,
        );
        let tids: Vec<u32> = coordinator.expected_tasks.keys().copied().collect();
        for tid in tids {
            let Some(start) = samples.get(&tid).and_then(|sample| sample.start) else {
                return Err(Self::policy_error(
                    policy,
                    format!("cannot read task {tid} start time during pause preflight"),
                    true,
                ));
            };
            coordinator.expected_starts.insert(tid, start);
        }
        Ok(coordinator)
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
            expected_starts: BTreeMap::new(),
            counters: PauseCounters::default(),
            epoch: PauseEpoch::default(),
            armed: false,
            armed_at_ns: None,
            hold_start_ns: None,
            hold_armed_once: false,
            hold_end_ns: None,
            hold_void: false,
            hold_frozen: false,
            rearming_enabled: policy != PausePolicy::Never,
            may_be_stopped: false,
            attempt_open: false,
            unserviced_stop_pending: false,
            ring_loss_baseline: 0,
            active_deadline: None,
            failure_deadline: None,
            failure_items: 0,
            pending_records: Vec::new(),
            unvalidated_records: 0,
            terminal_batch: None,
            pending_diagnostic: None,
            diagnostic_annotated: false,
            consecutive_engine_incomplete: 0,
            engine_incomplete_retirements: 0,
            diagnostic_emit_counts: BTreeMap::new(),
            successors_left: MAX_SUCCESSORS_PER_ARM,
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
        let mut coordinator = Self::new(policy, pid, generation, expected_tasks);
        // The scripted seam dates every unscripted task at tick zero, so the
        // default baseline matches it; birth-dating tests overwrite this.
        coordinator.expected_starts = coordinator
            .expected_tasks
            .keys()
            .map(|tid| (*tid, 0))
            .collect();
        coordinator
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
                // The hold's start bound is the first arm's clock only: a
                // re-arm or successor install never moves it, not even
                // after a clockless first arm (which stays unboundable).
                if !self.hold_armed_once {
                    self.hold_armed_once = true;
                    self.hold_start_ns = armed_at;
                }
                self.successors_left = MAX_SUCCESSORS_PER_ARM;
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

    /// Whether a stop may be waiting for `service` between capture frames
    /// (F-T4-2). The run loop asks this on every tick between frames, so it
    /// costs nothing unless an epoch is armed (the initial arm, a frame's
    /// re-arm, or an installed successor), and then exactly one
    /// authorization read. Only an exact ARMED readback proves that no hook
    /// won the arm (see `service_received`). REQUESTED, an absent or unknown
    /// state, and a failed read all count as pending, and `service`
    /// classifies each under its existing deadlines and failure rules.
    pub(crate) fn stop_pending(&self, io: &mut impl PauseIo) -> bool {
        self.policy != PausePolicy::Never
            && self.rearming_enabled
            && self.armed
            && !matches!(io.authorization(), Ok(Some(PAUSE_ARMED)))
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
                        let deadline = now.saturating_add(CYCLE_NS);
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
        if !self.pending_records.is_empty()
            && let Err(error) = self.apply_unowned(io, Some(deadline))
        {
            return self.fail_cycle(io, error.to_string(), error.lifecycle());
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
                self.void_hold();
                return Err(Self::policy_error(
                    self.policy,
                    "more than one terminal discovery batch reached the coordinator",
                    true,
                ));
            }
            self.terminal_batch = Some(batch);
        }
        self.take_stop_candidate_seen(io);
        let failure_candidate = received.after_ns.saturating_add(CYCLE_NS);
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
            self.begin_attempt();
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
                    if let Err(error) = self.apply_unowned_opening_on_error(io, deadline) {
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
            // Refuted: ARMED still held, so no hook won and nothing stopped
            // the child — it ran unstopped past this record.
            self.void_hold();
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

        let first_sample = match self.sample_until_stopped(io, deadline) {
            Ok(sample) => sample,
            Err((error, lifecycle)) => return self.fail_cycle(io, error, lifecycle),
        };
        if let Err(error) = io.wait_one_ms() {
            return self.fail_cycle(io, error, true);
        }
        let second_sample = match self.sample_stopped(io, deadline) {
            Ok(sample) => sample,
            Err(error) => return self.fail_cycle(io, error, false),
        };
        self.note_hold_sample(second_sample);
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
            let engine_incomplete =
                outcome.diagnostic == Some(PauseDiagnostic::EngineIncompleteWithinDeadline);
            return self.fail_cycle_inner(
                io,
                "one or more frozen required attachments failed",
                false,
                engine_incomplete,
            );
        }
        if let Err(error) = io.wait_one_ms() {
            return self.fail_cycle(io, error, true);
        }
        match self.sample_stopped(io, deadline) {
            Ok(sample) => self.note_hold_sample(sample),
            Err(error) => return self.fail_cycle(io, error, false),
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

        let install_successor =
            record_count == 1 && self.successors_left > 0 && self.rearming_enabled;
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
            self.successors_left -= 1;
            if let Err(error) = io.wait_one_ms() {
                return self.fail_cycle(io, error, true);
            }
            match self.sample_stopped(io, deadline) {
                Ok(sample) => self.note_hold_sample(sample),
                Err(error) => return self.fail_cycle(io, error, false),
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

        if let Err(error) = hold_until_the_attach_tick_passes(io, deadline) {
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
        // The first completing resume freezes the from-start hold: the
        // child runs past here, so later cycles start a new interval.
        self.hold_frozen = true;
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
        self.consecutive_engine_incomplete = 0;
        self.attempt_open = false;
        self.active_deadline = None;
        self.failure_deadline = None;
        self.failure_items = 0;
        self.armed = install_successor;
        if !install_successor {
            self.may_be_stopped = false;
            self.epoch = PauseEpoch::default();
            // The chain ends here: the child runs unpaused until the next
            // frame re-arms. A provider whose table is still unpublished may
            // be called before its probes attach, and that is said, not
            // silently absorbed.
            if io.publication_pending() {
                io.note_unpaused_publication();
            }
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

    /// A bounded unowned apply whose failure ends this cycle. On error it
    /// opens the attempt, so the partial closes one, and keeps the category
    /// the failed apply recorded, which opening the attempt would otherwise
    /// clear as a leftover. A category left from before is set aside for the
    /// apply and restored only when it succeeds, as without this wrapper.
    fn apply_unowned_opening_on_error(
        &mut self,
        io: &mut impl PauseIo,
        deadline: u64,
    ) -> Result<(), PauseError> {
        let leftover = if self.attempt_open {
            None
        } else {
            self.pending_diagnostic.take()
        };
        let result = self.apply_unowned(io, Some(deadline));
        if result.is_err() {
            let recorded = self.pending_diagnostic.take();
            self.begin_attempt();
            self.pending_diagnostic = recorded;
        } else if leftover.is_some() {
            self.pending_diagnostic = leftover;
        }
        result
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
        // Rejected: the helper refused the stop, so the child was never
        // held by this epoch.
        self.void_hold();
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

    /// A strict sample: every thread must already be stopped and the task set
    /// must be exactly the expected one. Used once the stop was seen complete:
    /// a stopped group cannot clone, so a running or new thread means
    /// something ran under the stop.
    fn sample_stopped(&mut self, io: &mut impl PauseIo, deadline: u64) -> Result<u64, String> {
        self.sample_tasks(io, deadline, false)?
            .ok_or_else(|| MSG_TASK_SET_CHANGED.into())
    }

    /// The stop's first sample. The helper's SIGSTOP is queued before its
    /// record, but on a loaded host a thread can still be running or about to
    /// be woken into the group stop when the record is serviced. Re-sample at
    /// the existing 1 ms cadence until every thread is stopped, inside the
    /// stop's existing deadline and never more than one cycle of samples. A
    /// thread still on its way at the deadline, or when the samples run out,
    /// reports the deadline; a changed set (vanished, reused or undated thread) or a thread that can
    /// never reach the stop refuses at once. Nothing is attached before this
    /// returns, so a thread that ran while the stop settled only ran before
    /// the hooks changed. The error carries whether it is a lifecycle failure
    /// (a failed wait).
    fn sample_until_stopped(
        &mut self,
        io: &mut impl PauseIo,
        deadline: u64,
    ) -> Result<u64, (String, bool)> {
        for _ in 0..=MAX_SETTLE_SAMPLES {
            if let Some(now) = self
                .sample_tasks(io, deadline, true)
                .map_err(|error| (error, false))?
            {
                return Ok(now);
            }
            io.wait_one_ms().map_err(|error| (error, true))?;
        }
        // Every sample found the threads on their way into the stop: running
        // out of samples is the deadline's twin.
        Err((MSG_PAUSE_CONFIRMATION_DEADLINE.into(), false))
    }

    /// One task sample, a single `stat` read per thread. The task set and
    /// thread states are judged before the deadline. A strict sample that is
    /// not fully stopped, or any sample with a thread that can never reach the
    /// stop, is today's task-set refusal. While `settling`, a sample whose
    /// threads are all in `T`, `R`, `S` or `D` waits (`Ok(None)`) for the
    /// ones on their way into the stop, and once past the deadline reports
    /// the deadline message, as a fully stopped sample past the deadline does.
    /// New threads are adopted only by a fully stopped settling sample.
    fn sample_tasks(
        &mut self,
        io: &mut impl PauseIo,
        deadline: u64,
        settling: bool,
    ) -> Result<Option<u64>, String> {
        let samples = io.task_samples(self.pid)?;
        // Read after the starts: a later read can only see a later attach.
        let last_attach = io.last_hook_attach_boot_ns();
        let now = io.now_ns()?;
        let births = self.covered_births(&samples, last_attach, settling)?;
        if samples.values().any(|sample| sample.state != b'T') {
            let settles = |sample: &TaskSample| matches!(sample.state, b'T' | b'R' | b'S' | b'D');
            if !settling || !samples.values().all(settles) {
                return Err(MSG_TASK_SET_CHANGED.into());
            }
            if now > deadline {
                return Err(MSG_PAUSE_CONFIRMATION_DEADLINE.into());
            }
            return Ok(None);
        }
        if now > deadline {
            return Err(MSG_PAUSE_CONFIRMATION_DEADLINE.into());
        }
        for (tid, start) in births {
            self.expected_tasks.insert(tid, b'T');
            self.expected_starts.insert(tid, start);
        }
        Ok(Some(now))
    }

    /// Threads whose floored birth is strictly after the last completed
    /// provider hook attach (see [`birth_covered`]), which a settling sample
    /// may adopt into the expected set. Uprobes are per file: once attached
    /// they fire for every thread, so such a thread is no more exposed than a
    /// thread that existed at preflight. The pause arm is deliberately not the
    /// instant: a frame or successor re-arm is no attach. Only the first
    /// (`settling`) sample admits a new thread; at a strict sample any unknown
    /// tid is a refusal. Every other change — a missing expected tid, a
    /// reused tid (same tid, different start time), a floored birth at or
    /// before the attach, an unreadable start time, no recorded attach or one
    /// in flight — keeps today's task-set refusal. An adopted thread is then
    /// held to every later sample like a preflight thread, so this stop's own
    /// attach (which it was verified stopped through) does not undo it.
    fn covered_births(
        &self,
        samples: &BTreeMap<u32, TaskSample>,
        last_attach_boot_ns: Option<u64>,
        admit_births: bool,
    ) -> Result<Vec<(u32, u64)>, String> {
        for tid in self.expected_tasks.keys() {
            if !samples.contains_key(tid) {
                return Err(MSG_TASK_SET_CHANGED.into());
            }
        }
        let mut births = Vec::new();
        for (tid, sample) in samples {
            let known = self.expected_tasks.contains_key(tid);
            match (known, self.expected_starts.get(tid), sample.start) {
                (true, Some(recorded), Some(start)) if start == *recorded => {}
                (false, None, Some(start))
                    if admit_births && birth_covered(start, last_attach_boot_ns) =>
                {
                    births.push((*tid, start));
                }
                _ => return Err(MSG_TASK_SET_CHANGED.into()),
            }
        }
        Ok(births)
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
        self.fail_cycle_inner(io, message, lifecycle, false)
    }

    fn fail_cycle_inner(
        &mut self,
        io: &mut impl PauseIo,
        message: impl Into<String>,
        lifecycle: bool,
        engine_incomplete: bool,
    ) -> Result<(), PauseError> {
        self.void_hold();
        let message = message.into();
        self.set_message_diagnostic(&message);
        // An engine-incomplete cycle under `auto` is a counted named gap,
        // not the end of the chain: the cleanup below resumes the child,
        // so a later loader hit arms and is serviced like any other. The
        // cause arrives typed from the incomplete-apply call site, never
        // from the sticky first-cause diagnostic (an earlier unowned apply
        // may have set that for a different failure). Consecutive
        // incompletes retire after the cap with a counted named gap.
        let incomplete_candidate =
            !lifecycle && self.policy == PausePolicy::Auto && engine_incomplete;
        if !incomplete_candidate {
            self.consecutive_engine_incomplete = 0;
        }
        let rearm_after_incomplete = incomplete_candidate
            && self.consecutive_engine_incomplete < MAX_CONSECUTIVE_ENGINE_INCOMPLETE;
        let retire_after_incomplete = incomplete_candidate && !rearm_after_incomplete;
        io.note_unconfirmed_cycle();
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
        self.rearming_enabled = rearm_after_incomplete;
        if rearm_after_incomplete {
            self.consecutive_engine_incomplete =
                self.consecutive_engine_incomplete.saturating_add(1);
        }
        let result = self.finish_nonconfirmed(message);
        if retire_after_incomplete {
            self.consecutive_engine_incomplete =
                self.consecutive_engine_incomplete.saturating_add(1);
            self.engine_incomplete_retirements =
                self.engine_incomplete_retirements.saturating_add(1);
            eprintln!(
                "{}",
                render_pause_incomplete_retirement(u64::from(self.consecutive_engine_incomplete))
            );
        }
        result
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

    /// The capture's final cleanup. When the capture ends (operator stop,
    /// `--duration`, error) after the kernel consumed an arm but before any
    /// service cycle reached it, the helper's stop is still holding the child:
    /// its owner opens only here, where cleanup resumes that child. It never
    /// confirmed, so it closes like every other unconfirmed owner — `auto`
    /// partial, `always` refused — instead of rendering as a confirmed stop.
    /// An owner already open before this call keeps its original outcome,
    /// unless an earlier cleanup discovered its opening and failed before
    /// classifying it: then this call applies that pending classification.
    pub(crate) fn cleanup(&mut self, io: &mut impl PauseIo) -> Result<(), PauseError> {
        let owner_was_open = self.attempt_open;
        let result = self.terminal_cleanup(io);
        if self.attempt_open && !owner_was_open {
            self.unserviced_stop_pending = true;
        }
        result?;
        if self.attempt_open && self.unserviced_stop_pending {
            self.unserviced_stop_pending = false;
            return self.finish_nonconfirmed(MSG_UNSERVICED_AT_CLEANUP.into());
        }
        Ok(())
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
        if self.terminal_batch.is_none()
            && io.terminal_authority_pending()
            && let Err(error) = io.cleanup_terminal_batch_without_replay(&mut self.terminal_batch)
        {
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
        // After every resume is observed: a stopped child must never wait
        // on serialized kernel teardown (F-T4-3).
        if let Err(error) = io.detach_pause_links() {
            errors.push(error);
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
        let deadline = now.saturating_add(CYCLE_NS);
        clamp_deadline(&mut self.failure_deadline, deadline)
    }

    pub(crate) fn counters(&self) -> PauseCounters {
        self.counters
    }

    /// Engine-incomplete cap retirements this run. Each is one counted
    /// partial (already in `counters`); the count is a subset
    /// annotation, not a lattice member. Rendered in JSON as
    /// `evidence.pause_engine_incomplete_retirements`.
    pub(crate) fn engine_incomplete_retirements(&self) -> u64 {
        self.engine_incomplete_retirements
    }

    /// Records one `--pause always` degrade that collected unpaused
    /// instead of aborting (never-stop). The attempt was already counted
    /// by `begin_attempt`; this moves it to `unavailable` (partial).
    pub(crate) fn note_unavailable(&mut self) {
        self.counters.unavailable = self.counters.unavailable.saturating_add(1);
        debug_assert!(
            self.counters.valid(),
            "unavailable must stay within attempts: {:?}",
            self.counters
        );
    }

    /// Records a stopped-sample instant toward the first hold: the child
    /// was proven stopped at `now`. Frozen holds never move.
    fn note_hold_sample(&mut self, now: u64) {
        if !self.hold_frozen {
            let end = self.hold_end_ns.get_or_insert(now);
            *end = (*end).max(now);
        }
    }

    /// Voids the from-start claim after anything unproven. Sticky until
    /// the freeze; frozen holds are immutable (a later gap lands after
    /// the proven end, so it ends nothing).
    fn void_hold(&mut self) {
        if !self.hold_frozen {
            self.hold_void = true;
        }
    }

    /// The first-hold proof for pre-arm exactness, once the coordinator
    /// armed: `None` while no arm proved a hold (a passive capture, a
    /// failed or disabled arm, or a missing arm clock). The end bound
    /// publishes only after the first resume freezes it, so a cycle that
    /// never completes can never lend a partial end to a proof. A
    /// returned hold carries its own gap flag; the builder trusts only a
    /// continuous one.
    pub(crate) fn pause_hold(&self) -> Option<PauseGateHold> {
        let start = self.hold_start_ns?;
        let end = self.hold_end_ns.filter(|_| self.hold_frozen);
        let sane = end.is_none_or(|end| start <= end);
        Some(PauseGateHold {
            start_ns: Some(start),
            end_ns: end,
            continuous: !self.hold_void && sane,
        })
    }

    #[allow(dead_code)] // Introspection accessor; exercised only by the pause tests.
    pub(crate) fn status(&self) -> PauseStatus {
        self.counters.status()
    }

    #[allow(dead_code)] // Introspection accessor; exercised only by the pause tests.
    pub(crate) fn is_armed(&self) -> bool {
        self.armed
    }

    #[allow(dead_code)] // Introspection accessor; exercised only by the pause tests.
    pub(crate) fn rearming_enabled(&self) -> bool {
        self.rearming_enabled
    }

    #[allow(dead_code)] // Introspection accessor; exercised only by the pause tests.
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
        let count = self.diagnostic_emit_counts.entry(diagnostic).or_insert(0);
        *count = count.saturating_add(1);
        let line = render_pause_diagnostic(diagnostic);
        if *count == 1 {
            eprintln!("{line}");
        }
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

    fn task_samples(&mut self, pid: u32) -> Result<BTreeMap<u32, TaskSample>, String> {
        read_task_samples(pid)
    }

    fn last_hook_attach_boot_ns(&mut self) -> Option<u64> {
        last_hook_attach_boot_ns()
    }

    fn boot_now_ns(&mut self) -> Option<u64> {
        boot_ns()
    }

    fn dequeue(&mut self) -> Result<Option<DiscoveryItem>, String> {
        // Shared allowance, enforced structurally: a staged pop is a
        // credit transfer and always proceeds, but a ring read needs a
        // free credit. At zero room the coordinator gets an explicit
        // capacity block — never an empty observation — so its cycle
        // fails honestly instead of over-admitting.
        let staged = self.session.staged_discovery_len();
        if staged == 0
            && staged.saturating_add(self.engine.discovery_held_len()) >= DISCOVERY_HELD_CAP
        {
            return Err("live discovery pull stopped at the shared storage allowance with records still unread".into());
        }
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
        // Every nested pull in this batch shares one budget seeded from
        // the shared allowance beside the batch-local records; merges of
        // those locals into pending are transfers, already counted.
        let malformed = std::mem::take(&mut self.malformed);
        // The reconcile above may hold the terminal batch
        // coordinator-side: its records are still owned, so they count
        // against fresh acquisition until the install below moves them
        // back into the engine.
        let coordinator_held = terminal_batch.as_ref().map_or(0, TerminalBatch::len);
        let pull_budget = std::cell::Cell::new(
            DISCOVERY_HELD_CAP
                .saturating_sub(self.session.staged_discovery_len())
                .saturating_sub(self.engine.discovery_held_len())
                .saturating_sub(records.len())
                .saturating_sub(malformed as usize)
                .saturating_sub(coordinator_held),
        );
        let mut collect = |session: &mut dyn EngineSession| {
            collect_timed_retirement(
                session,
                child,
                deadline,
                stop_candidate_seen,
                pause_owned,
                &nested_deadline,
                &pull_budget,
            )
        };
        let terminal_dispatch = terminal_batch.is_some();
        // Move-only: the batch and its records move into the engine. The
        // install is prechecked before the move, so a refusal restores the
        // batch without needing a second owned copy.
        let records = match terminal_batch.take() {
            Some(batch) => {
                if let Err(error) = self.engine.terminal_batch_installable(&batch) {
                    *terminal_batch = Some(batch);
                    self.malformed = self.malformed.saturating_add(malformed);
                    return Err(PauseBatchError::new(
                        format!("terminal discovery batch restore failed: {error:#}"),
                        None,
                    ));
                }
                if let Err(error) = self.engine.install_terminal_batch(batch, records) {
                    self.malformed = self.malformed.saturating_add(malformed);
                    return Err(PauseBatchError::new(
                        format!("terminal discovery batch restore failed: {error:#}"),
                        None,
                    ));
                }
                Vec::new()
            }
            None => records,
        };
        let before_ns = attach::monotonic_ns();
        self.engine.set_pause_owned_batch(pause_owned);
        let applied = self.engine.apply_discovery_batch_with(
            self.session,
            records,
            malformed,
            additions_allowed,
            terminal_dispatch,
            &mut collect,
            deadline,
        );
        self.engine.set_pause_owned_batch(false);
        let result = match applied {
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
        // Nested pulls in this revalidation share one budget seeded from
        // the shared allowance beside what the Engine already holds.
        let pull_budget = std::cell::Cell::new(
            DISCOVERY_HELD_CAP
                .saturating_sub(self.session.staged_discovery_len())
                .saturating_sub(self.engine.discovery_held_len()),
        );
        let mut collect = |session: &mut dyn EngineSession| {
            collect_timed_retirement(
                session,
                child,
                None,
                stop_candidate_seen,
                pause_owned,
                &nested_deadline,
                &pull_budget,
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
        // The stop gate was requested before pause cleanup; the links move
        // to the background cleanup worker after publication instead of
        // detaching here, so a held child is always resumed first and the
        // run detach time is measured once, at the real teardown.
        Ok(())
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

    fn publication_pending(&mut self) -> bool {
        self.engine.owned_publication_pending(self.child.pid())
    }

    fn note_unpaused_publication(&mut self) {
        self.engine.note_owned_pause_gap(MSG_UNPAUSED_PUBLICATION);
        self.engine.note_unprotected_owned(self.child.pid());
    }

    fn note_unconfirmed_cycle(&mut self) {
        self.engine.note_unprotected_owned(self.child.pid());
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
    budget: &std::cell::Cell<usize>,
) -> Result<(Vec<DiscoveryRecord>, u64), anyhow::Error> {
    collect_timed_retirement_with(
        child.pid(),
        deadline,
        stop_candidate_seen,
        pause_owned,
        Some(nested_deadline),
        || attach::monotonic_ns().ok_or_else(|| anyhow::anyhow!("monotonic clock read failed")),
        // Shared allowance: staged pops are credit transfers and always
        // proceed, but a ring read consumes one shared credit. At zero
        // room with nothing staged the collect stops with a typed
        // capacity block — never an empty observation — and the retained
        // prefix travels with it.
        || {
            let staged_before = session.staged_discovery_len();
            if budget.get() == 0 && staged_before == 0 {
                return Err(DiscoveryCapacityBlocked.into());
            }
            let item = session.discovery_dequeue()?;
            if item.is_some() && session.staged_discovery_len() == staged_before {
                budget.set(budget.get().saturating_sub(1));
            }
            Ok(item)
        },
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
                // A capacity stop keeps its exact prefix and reports the
                // allowance, never a transport failure: the operation
                // retries after owned items settle.
                if error.is::<DiscoveryCapacityBlocked>() {
                    return Err(IncompleteTerminalDrain::capacity_blocked(
                        records,
                        malformed,
                        unvalidated_records,
                    )
                    .into());
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

/// Every task of `pid` and its `/proc` state letter. Crate-visible so the
/// owned-run shutdown tests read tasks exactly as the coordinator does.
pub(crate) fn read_task_states(pid: u32) -> Result<BTreeMap<u32, u8>, String> {
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

/// Every task of `pid` with its state letter and kernel start time, from one
/// read of each `/proc/<pid>/task/<tid>/stat` (fields 3 and 22), so a
/// thread's state and identity come from the same read. As in
/// [`read_task_states`], an unreadable `stat` file or state is an error (the
/// sample then refuses); a start time that cannot be parsed is undated
/// (`None`), which the coordinator treats as a changed set, never as covered.
pub(crate) fn read_task_samples(pid: u32) -> Result<BTreeMap<u32, TaskSample>, String> {
    let directory = std::fs::read_dir(format!("/proc/{pid}/task"))
        .map_err(|error| format!("cannot enumerate task set for pid {pid}: {error}"))?;
    let mut samples = BTreeMap::new();
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
        let start = parse_task_start(&stat);
        samples.insert(tid, TaskSample { state, start });
    }
    if samples.is_empty() {
        Err(format!("pid {pid} has an empty task set"))
    } else {
        Ok(samples)
    }
}

/// Whether a thread's birth provably follows the last completed provider hook
/// attach: `start_ticks * tick_ns > attach_ns` (ruling PT-3).
///
/// Why the floor alone is sound: `fs/proc/array.c` `do_task_stat` reports
/// `nsec_to_clock_t(timens_add_boottime_ns(task->start_boottime))`.
/// `copy_process` (`kernel/fork.c`) sets `start_boottime =
/// ktime_get_boottime_ns()` before the task is made visible or woken, so it
/// precedes anything the thread runs. `timens_add_boottime_ns` adds the
/// *reader's* time-namespace boottime offset, the same offset
/// `posix_get_boottime_timespec` (`kernel/time/posix-timers.c`) adds to this
/// observer's own `CLOCK_BOOTTIME`, so both values share one domain. With
/// `NSEC_PER_SEC % USER_HZ == 0` (USER_HZ 100 on x86-64), `nsec_to_clock_t`
/// is an exact floor division, so `start_ticks * tick_ns <= birth_ns`; a
/// truncated `tick_ns` only lowers the bound. Hence a floor strictly after
/// the attach proves the birth is after it. Checked against the 6.6.157,
/// 6.12.111 and 7.0.14 sources. Without a margin, this also relies on the
/// kernel's boot clock being ordered across CPUs: an attach completion read on
/// one CPU before a `clone` on another never reads later than that child's
/// `start_boottime` (both come from the one system-wide timekeeper). Equality
/// is not covered, and neither is a missing instant (none recorded or one in
/// flight) or a saturated one.
fn birth_covered(start_ticks: u64, last_attach_boot_ns: Option<u64>) -> bool {
    let Some(attach) = last_attach_boot_ns else {
        return false;
    };
    start_ticks.saturating_mul(clock_tick_ns()) > attach
}

/// Holds a confirmed stop's resume until the boot clock has crossed into the
/// clock tick after the last completed provider hook attach. A thread the
/// child starts once resumed is dated by its floored tick ([`birth_covered`]),
/// and a birth inside the attach's own tick floors at or before the attach, so
/// it would keep the stop partial although it came after the hooks. Every
/// such thread is born after the resume, so once the resume is past the next
/// tick boundary its floor is at or past that boundary, strictly after the
/// attach. This changes only when the child resumes, never which births are
/// covered. The hold makes at most one tick's worth of the existing 1 ms
/// waits (each may oversleep). A resume observed after the stop `deadline`
/// fails the run, so the hold only starts a wait while the wait, plus one
/// clock tick of headroom for oversleep, the resume and the observer's first
/// read, still fits before the deadline; otherwise, or when the stop clock
/// cannot be read or the margin overflows, it resumes at once. This makes a
/// late observation unlikely, not impossible: a wait that oversleeps by more
/// than the headroom can still end past the deadline. A birth inside the
/// attach's tick then stays partial at the next stop, the safe direction. With no recorded attach, an unreadable boot
/// clock, a saturated instant or a zero tick there is nothing to wait for.
/// Only a failed wait is an error.
fn hold_until_the_attach_tick_passes(io: &mut impl PauseIo, deadline: u64) -> Result<(), String> {
    let Some(mut boot) = io.boot_now_ns() else {
        return Ok(());
    };
    let Some(attach) = io.last_hook_attach_boot_ns() else {
        return Ok(());
    };
    let tick = clock_tick_ns();
    let Some(boundary) = attach
        .checked_div(tick)
        .and_then(|ticks| ticks.checked_add(1))
        .and_then(|ticks| ticks.checked_mul(tick))
    else {
        return Ok(());
    };
    for _ in 0..=tick / SAMPLE_NS {
        if boot >= boundary {
            return Ok(());
        }
        let wait_end = io.now_ns().ok().and_then(|now| {
            now.checked_add(SAMPLE_NS)
                .and_then(|end| end.checked_add(tick))
        });
        match wait_end {
            Some(end) if end <= deadline => {}
            _ => return Ok(()),
        }
        io.wait_one_ms()?;
        let Some(read) = io.boot_now_ns() else {
            return Ok(());
        };
        boot = read;
    }
    Ok(())
}

fn parse_task_start(stat: &[u8]) -> Option<u64> {
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    let tail = stat.get(close + 1..)?;
    let field = tail
        .split(|byte| *byte == b' ')
        .filter(|token| !token.is_empty())
        .nth(19)?;
    std::str::from_utf8(field).ok()?.parse().ok()
}

/// The kernel clock tick in nanoseconds (`sysconf(_SC_CLK_TCK)`, USER_HZ),
/// cached: start-time ticks floor births to this granularity. Falls back to
/// USER_HZ 100 when the sysconf read fails.
fn clock_tick_ns() -> u64 {
    static TICK_NS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *TICK_NS.get_or_init(|| {
        // SAFETY: `sysconf` takes only the name constant and returns the
        // configured value or -1; it writes through no pointer.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let hz = if hz > 0 { hz as u64 } else { 100 };
        1_000_000_000 / hz
    })
}

/// `CLOCK_BOOTTIME` in nanoseconds: the clock domain of `/proc` starttime
/// ticks (field 22 counts boot-relative ticks), so thread births date against
/// hook attach completions without a suspend-sensitive conversion. Returns
/// `None` exactly when the clock read fails.
pub(crate) fn boot_ns() -> Option<u64> {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `clock_gettime` initializes `timestamp` on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, timestamp.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the successful call above initialized `timestamp`.
    let timestamp = unsafe { timestamp.assume_init() };
    let seconds = u64::try_from(timestamp.tv_sec).ok()?;
    let nanos = u64::try_from(timestamp.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

/// When provider hook attaches completed, in the boot clock. Uprobes are per
/// file, so once a provider's hooks are live they fire for every thread of
/// every process mapping it: a thread born strictly after the last completed
/// attach is no more exposed than a thread that existed at preflight (a
/// provider mapped but not yet attached is unhooked for every thread alike).
/// One process-wide maximum is kept, which is conservative: an attach for any
/// provider anywhere in this observer moves the instant later, never earlier.
pub(crate) struct HookAttachClock {
    in_flight: AtomicU64,
    /// Latest completion stamp; zero when none is recorded. An unreadable
    /// boot clock at completion stamps `u64::MAX`, so nothing dates after it.
    last_boot_ns: AtomicU64,
}

static HOOK_ATTACH_CLOCK: HookAttachClock = HookAttachClock::new();

impl HookAttachClock {
    const fn new() -> Self {
        Self {
            in_flight: AtomicU64::new(0),
            last_boot_ns: AtomicU64::new(0),
        }
    }

    fn open(&self) -> HookAttachWindow<'_> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        HookAttachWindow { clock: self }
    }

    fn close(&self, completed_boot_ns: Option<u64>) {
        let stamp = completed_boot_ns.unwrap_or(u64::MAX).max(1);
        self.last_boot_ns.fetch_max(stamp, Ordering::SeqCst);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    /// The latest completion, or `None` when none is recorded or an attach
    /// is open on either side of the read.
    fn completed(&self) -> Option<u64> {
        if self.in_flight.load(Ordering::SeqCst) != 0 {
            return None;
        }
        let last = self.last_boot_ns.load(Ordering::SeqCst);
        if self.in_flight.load(Ordering::SeqCst) != 0 || last == 0 {
            return None;
        }
        Some(last)
    }
}

/// One provider hook attach in flight. Its completion is stamped when it
/// drops, on every return path (success, error or unwind): whatever the
/// attach made live was live by then, so the stamp is an upper bound on
/// every hook it installed. Bind it to a named variable for the whole attach:
/// `let _ =` drops it at once and stamps an instant before the attach.
#[must_use = "the window stamps the attach completion when it drops"]
pub(crate) struct HookAttachWindow<'a> {
    clock: &'a HookAttachClock,
}

impl Drop for HookAttachWindow<'_> {
    fn drop(&mut self) {
        self.clock.close(boot_ns());
    }
}

/// Opens a window around one provider hook attach (see [`HookAttachClock`]).
pub(crate) fn hook_attach_window() -> HookAttachWindow<'static> {
    HOOK_ATTACH_CLOCK.open()
}

/// The last completed provider hook attach in this observer, in the boot
/// clock, or `None` when none completed yet or one is in flight.
pub(crate) fn last_hook_attach_boot_ns() -> Option<u64> {
    HOOK_ATTACH_CLOCK.completed()
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
    use crate::fixture_guard::DieWithParent as _;
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
        /// Last staged task set, repeated once the queue drains: like the
        /// real `/proc` read, the fake's world persists until scripted
        /// otherwise. `None` until the first staged read.
        stable_states: Option<BTreeMap<u32, u8>>,
        starts: VecDeque<Result<BTreeMap<u32, u64>, String>>,
        last_states: BTreeMap<u32, u8>,
        /// Scripted last-attach instants, one per read; the last one
        /// repeats. Default: none recorded.
        attach_instants: VecDeque<Option<u64>>,
        fallback_attach: Option<u64>,
        /// Scripted boot-clock readings, one per read; then `fallback_boot`.
        /// Default: unreadable.
        boot_clock: VecDeque<Option<u64>>,
        fallback_boot: Option<u64>,
        state_reads: u64,
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
        /// Waits that succeed before every later wait fails. Default: no limit.
        fail_wait_after: Option<usize>,
        waits_done: usize,
        /// Fails the first stop-clock read after the first boot-clock read
        /// (the resume hold's), once.
        fail_first_now_after_boot: bool,
        boot_read: bool,
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
        publication_pending: bool,
        unpaused_publications: u64,
    }

    impl Default for FakeIo {
        fn default() -> Self {
            Self {
                now: VecDeque::new(),
                fallback_now: 0,
                states: VecDeque::new(),
                stable_states: None,
                starts: VecDeque::new(),
                last_states: BTreeMap::new(),
                attach_instants: VecDeque::new(),
                fallback_attach: None,
                boot_clock: VecDeque::new(),
                fallback_boot: None,
                state_reads: 0,
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
                fail_wait_after: None,
                waits_done: 0,
                fail_first_now_after_boot: false,
                boot_read: false,
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
                publication_pending: false,
                unpaused_publications: 0,
            }
        }
    }

    impl FakeIo {
        /// The scripted start times for one sample, read after its states.
        fn scripted_starts(&mut self) -> Result<BTreeMap<u32, u64>, String> {
            if let Some(starts) = self.starts.pop_front() {
                return starts;
            }
            // Unscripted tasks date at tick zero, matching the default test
            // baseline; a scripted birth dates against the scripted attach.
            Ok(self.last_states.keys().map(|tid| (*tid, 0)).collect())
        }
    }

    impl PauseIo for FakeIo {
        fn now_ns(&mut self) -> Result<u64, String> {
            if self.fail_first_now_after_boot && self.boot_read {
                self.fail_first_now_after_boot = false;
                return Err("clock".into());
            }
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
            if self.fail_wait || self.fail_wait_after.is_some_and(|n| self.waits_done >= n) {
                return Err("wait".into());
            }
            self.waits_done += 1;
            self.fallback_now = self.fallback_now.saturating_add(SAMPLE_NS);
            Ok(())
        }

        fn task_states(&mut self, _: u32) -> Result<BTreeMap<u32, u8>, String> {
            self.state_reads = self.state_reads.saturating_add(1);
            let states = match self.states.pop_front() {
                Some(states) => {
                    if let Ok(states) = &states {
                        self.stable_states = Some(states.clone());
                    }
                    states
                }
                None if self.resumed && !self.post_resume_all_stopped => {
                    Ok([(41, b'R'), (42, b'T')].into_iter().collect())
                }
                None => Ok(self.stable_states.clone().unwrap_or_else(stopped)),
            };
            if let Ok(states) = &states {
                self.last_states = states.clone();
            }
            states
        }

        fn task_samples(&mut self, pid: u32) -> Result<BTreeMap<u32, TaskSample>, String> {
            let states = self.task_states(pid)?;
            let starts = self.scripted_starts()?;
            Ok(states
                .into_iter()
                .map(|(tid, state)| {
                    let start = starts.get(&tid).copied();
                    (tid, TaskSample { state, start })
                })
                .collect())
        }

        fn last_hook_attach_boot_ns(&mut self) -> Option<u64> {
            if let Some(instant) = self.attach_instants.pop_front() {
                self.fallback_attach = instant;
            }
            self.fallback_attach
        }

        fn boot_now_ns(&mut self) -> Option<u64> {
            self.boot_read = true;
            self.boot_clock.pop_front().unwrap_or(self.fallback_boot)
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

        fn publication_pending(&mut self) -> bool {
            self.publication_pending
        }

        fn note_unpaused_publication(&mut self) {
            self.unpaused_publications += 1;
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
            .die_with_parent()
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

    /// F-T4-2: the run loop asks `stop_pending` on every tick between frames,
    /// so it performs no I/O unless an epoch is armed, and exactly one
    /// authorization read while one is. `never`, an unarmed pause, and a
    /// retired policy (arm's own gate) all answer without I/O. Only an exact
    /// ARMED readback proves no stop is pending. REQUESTED, an absent or
    /// unknown state, and a failed read send the tick to `service`.
    #[test]
    fn stop_pending_costs_one_authorization_read_and_only_while_armed() {
        for (policy, armed, rearming_enabled) in [
            (PausePolicy::Never, true, true),
            (PausePolicy::Auto, false, true),
            (PausePolicy::Always, false, true),
            (PausePolicy::Auto, true, false),
        ] {
            let mut io = FakeIo {
                authorization: Some(PAUSE_REQUESTED),
                ..FakeIo::default()
            };
            let mut coordinator = PauseCoordinator::for_test(policy, 41, 9, stopped());
            coordinator.armed = armed;
            coordinator.rearming_enabled = rearming_enabled;
            assert!(
                !coordinator.stop_pending(&mut io),
                "{policy:?} armed={armed} rearming={rearming_enabled}"
            );
            assert!(io.events.is_empty(), "{policy:?}: {:?}", io.events);
        }

        for (authorization, pending) in [
            (Ok(Some(PAUSE_ARMED)), false),
            (Ok(Some(PAUSE_REQUESTED)), true),
            (Ok(None), true),
            (Ok(Some(999)), true),
            (Err("read".to_string()), true),
        ] {
            for policy in [PausePolicy::Auto, PausePolicy::Always] {
                let mut io = FakeIo {
                    authorization_results: VecDeque::from([authorization.clone()]),
                    ..FakeIo::default()
                };
                let mut coordinator = PauseCoordinator::for_test(policy, 41, 9, stopped());
                coordinator.arm_for_test();
                assert_eq!(
                    coordinator.stop_pending(&mut io),
                    pending,
                    "{policy:?}: {authorization:?}"
                );
                assert_eq!(io.events, ["read"], "{policy:?}: {authorization:?}");
                assert_eq!(coordinator.counters(), PauseCounters::default());
            }
        }
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

    /// Preflight dates every thread it freezes: a thread whose start time
    /// cannot be read refuses the pause instead of joining the expected set
    /// undated.
    #[test]
    fn preflight_refuses_a_thread_without_a_start_time() {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let expected = [(child.pid(), b'S')].into_iter().collect();
        let mut io = FakeIo {
            states: VecDeque::from([Ok(expected)]),
            starts: VecDeque::from([Ok(BTreeMap::new())]),
            ..FakeIo::default()
        };

        let error = PauseCoordinator::preflight(PausePolicy::Always, &child, &mut io)
            .err()
            .expect("an undated preflight thread must refuse");

        assert!(
            error
                .to_string()
                .contains("start time during pause preflight"),
            "{error}"
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
        coordinator.successors_left = 0;
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 1,
                confirmed: 0,
                partial: 0,
                unavailable: 0,
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
        coordinator.successors_left = 0;
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
            coordinator.successors_left = 0;
            coordinator.arm_for_test();

            let error = coordinator.service(&mut io).unwrap_err();

            assert!(error.lifecycle(), "authorization {authorization:?}");
            assert_eq!(
                coordinator.counters(),
                PauseCounters {
                    attempts: 1,
                    confirmed: 0,
                    partial: 0,
                    unavailable: 0,
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
        coordinator.successors_left = 0;
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
    }

    /// Drives the real `arm` (not `arm_for_test`) so the hold snapshots
    /// the arm clock, then points the scripted authorization at the won
    /// REQUESTED the service cycle consumes. `arm_now` is consumed first.
    fn armed_hold_coordinator(io: &mut FakeIo, arm_now: Result<u64, String>) -> PauseCoordinator {
        io.now.push_front(arm_now);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut *io).unwrap(), ArmResult::Armed);
        io.authorization = Some(PAUSE_REQUESTED);
        coordinator
    }

    /// The first completed pause cycle freezes the from-start hold: the
    /// arm lower bound plus the last stopped sample before the resume. A
    /// re-arm and a second completed cycle neither move the frozen end nor
    /// replace the first arm's start.
    #[test]
    fn pause_hold_freezes_first_hold_at_resume() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.resume_authorization = Some(None);
        let mut coordinator = armed_hold_coordinator(&mut io, Ok(5));
        coordinator.successors_left = 0;

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        let frozen = PauseGateHold {
            start_ns: Some(5),
            end_ns: Some(2_000_016),
            continuous: true,
        };
        assert_eq!(coordinator.pause_hold(), Some(frozen));

        // Re-arm after the freeze: the live arm moves, the snapshot stays.
        io.now.push_front(Ok(20));
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        io.authorization = Some(PAUSE_REQUESTED);
        io.resume_authorization = Some(Some(PAUSE_REQUESTED));
        io.queue = VecDeque::from([
            Ok(Some(DiscoveryItem::Record(record(25, 0, false)))),
            Ok(None),
            Ok(None),
        ]);
        io.now.push_back(Ok(26));
        io.now.push_back(Ok(27));
        io.states = VecDeque::from([Ok(stopped()), Ok(stopped()), Ok(stopped())]);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(2));
        assert_eq!(coordinator.pause_hold(), Some(frozen));
    }

    /// A cycle that fails after stopping voids the from-start claim and
    /// publishes no end: without a completing resume nothing freezes.
    #[test]
    fn pause_hold_failed_cycle_voids() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.fail_apply = true;
        let mut coordinator = armed_hold_coordinator(&mut io, Ok(5));

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(
            coordinator.pause_hold(),
            Some(PauseGateHold {
                start_ns: Some(5),
                end_ns: None,
                continuous: false,
            })
        );
    }

    /// A passive capture never arms: no hold exists at all.
    #[test]
    fn pause_hold_never_policy_yields_none() {
        let mut io = FakeIo::default();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Never, 41, 9, stopped());

        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Disabled);
        assert_eq!(coordinator.pause_hold(), None);
        coordinator.service(&mut io).unwrap();
        assert_eq!(coordinator.pause_hold(), None);
    }

    /// An arm whose clock read failed proves no start bound: even a fully
    /// confirmed cycle afterward yields no hold, and a later re-arm cannot
    /// smuggle in its own clock as the first bound.
    #[test]
    fn pause_hold_missing_arm_clock_yields_none() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.resume_authorization = Some(None);
        let mut coordinator = armed_hold_coordinator(&mut io, Err("clock".into()));
        coordinator.successors_left = 0;

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(coordinator.pause_hold(), None);

        io.now.push_front(Ok(20));
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        assert_eq!(coordinator.pause_hold(), None);
    }

    /// A rejected stop never held the child: the hold voids with no end.
    #[test]
    fn pause_hold_rejected_stop_voids() {
        let mut io = successful_io(vec![record(10, -libc::EPERM as i64, false)]);
        let mut coordinator = armed_hold_coordinator(&mut io, Ok(5));

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(
            coordinator.pause_hold(),
            Some(PauseGateHold {
                start_ns: Some(5),
                end_ns: None,
                continuous: false,
            })
        );
    }

    /// A refuted stop candidate (ARMED still held: no hook won) means the
    /// child ran unstopped: the hold voids even though service succeeds.
    #[test]
    fn pause_hold_refuted_candidate_voids() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.now.push_front(Ok(5));
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        // The arm exchange left ARMED behind: no hook won it.

        coordinator.service(&mut io).unwrap();

        assert_eq!(
            coordinator.pause_hold(),
            Some(PauseGateHold {
                start_ns: Some(5),
                end_ns: None,
                continuous: false,
            })
        );
    }

    /// A refuted first epoch voids sticky: even a fully confirmed later
    /// cycle freezes a gapped hold, never a clean one.
    #[test]
    fn pause_hold_refute_then_complete_freezes_gapped() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.now.push_front(Ok(5));
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        coordinator.successors_left = 0;

        coordinator.service(&mut io).unwrap();
        assert_eq!(
            coordinator.pause_hold(),
            Some(PauseGateHold {
                start_ns: Some(5),
                end_ns: None,
                continuous: false,
            })
        );

        io.authorization = Some(PAUSE_REQUESTED);
        io.queue = VecDeque::from([
            Ok(Some(DiscoveryItem::Record(record(25, 0, false)))),
            Ok(None),
            Ok(None),
        ]);
        io.now.push_back(Ok(26));
        io.now.push_back(Ok(27));
        io.states = VecDeque::from([Ok(stopped()), Ok(stopped()), Ok(stopped())]);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(
            coordinator.pause_hold(),
            Some(PauseGateHold {
                start_ns: Some(5),
                end_ns: Some(2_000_032),
                continuous: false,
            })
        );
    }

    /// A second terminal batch colliding with the coordinator's is a
    /// lifecycle failure before any stop: the hold voids.
    #[test]
    fn pause_hold_terminal_batch_collision_voids() {
        let owner = crate::discovery::loader::LoaderContextId::from_case_id(1);
        let mut held = TerminalBatch::empty(TerminalAuthority {
            owner,
            exports: Vec::new(),
        });
        held.extend([record(10, -libc::EPERM as i64, false)]);
        let mut carried = TerminalBatch::empty(TerminalAuthority {
            owner,
            exports: Vec::new(),
        });
        carried.extend([record(10, -libc::EPERM as i64, false)]);
        let mut io = FakeIo::default();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.hold_start_ns = Some(5);
        coordinator.terminal_batch = Some(held);

        let error = coordinator
            .service_deferred(
                &mut io,
                TimedItem {
                    before_ns: 1,
                    after_ns: 2,
                    item: DiscoveryItem::Record(record(10, -libc::EPERM as i64, false)),
                    terminal_batch: Some(carried),
                },
            )
            .unwrap_err();

        assert!(
            error.to_string().contains("more than one terminal"),
            "{error}"
        );
        // The void latches even though the collision precedes any stop.
        assert_eq!(
            coordinator.pause_hold(),
            Some(PauseGateHold {
                start_ns: Some(5),
                end_ns: None,
                continuous: false,
            })
        );
    }

    #[test]
    fn generation_mismatch_after_resume_is_lifecycle_fatal() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.resume_authorization = Some(None);
        io.same_generation_results = VecDeque::from([Ok(true), Ok(false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.successors_left = 0;
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle());
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 1,
                confirmed: 0,
                partial: 0,
                unavailable: 0,
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
            coordinator.successors_left = if cycles == 0 {
                MAX_SUCCESSORS_PER_ARM
            } else {
                0
            };
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
            coordinator.successors_left = 0;
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
        coordinator.successors_left = 0;
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
        coordinator.successors_left = 0;
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
                unavailable: 0,
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

    /// The kernel clock tick in nanoseconds, read independently of the
    /// coordinator: birth-dating tests script arm and birth instants against
    /// this oracle, not against the code under test.
    fn test_tick_ns() -> u64 {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let hz = if hz > 0 { hz as u64 } else { 100 };
        1_000_000_000 / hz
    }

    /// A birth-dating stop: every stopped sample shows `states` dated by
    /// `starts`, and the last provider hook attach completed at `attach`
    /// (`None`: none recorded, or one in flight). The confirm path takes four
    /// stopped samples (two pre-apply, one post-apply, one post-successor-arm).
    fn birth_dating_io(
        states: BTreeMap<u32, u8>,
        starts: BTreeMap<u32, u64>,
        attach: Option<u64>,
    ) -> FakeIo {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.fallback_attach = attach;
        io.states = VecDeque::from([
            Ok(states.clone()),
            Ok(states.clone()),
            Ok(states.clone()),
            Ok(states),
        ]);
        io.starts = VecDeque::from([
            Ok(starts.clone()),
            Ok(starts.clone()),
            Ok(starts.clone()),
            Ok(starts),
        ]);
        io
    }

    /// An armed stop with the preflight threads 41 and 42 born at tick 50.
    /// The coordinator keeps no arm instant in the boot clock, so no arm (a
    /// fresh frame or a successor re-arm) is an input to birth dating; only
    /// `birth_first_seen_after_a_successor_rearm_keeps_partial` runs a real
    /// successor re-arm.
    fn birth_dating_coordinator() -> PauseCoordinator {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.expected_starts = [(41, 50), (42, 50)].into_iter().collect();
        coordinator
    }

    /// Thread 43 joins the preflight threads, born at `birth_tick`.
    fn grown_by_one(birth_tick: u64) -> (BTreeMap<u32, u8>, BTreeMap<u32, u64>) {
        (
            [(41, b'T'), (42, b'T'), (43, b'T')].into_iter().collect(),
            [(41, 50), (42, 50), (43, birth_tick)].into_iter().collect(),
        )
    }

    /// Runs one stop that sees thread 43 born at `birth_tick` against a last
    /// completed attach at `attach_tick`.
    fn birth_dating_stop(birth_tick: u64, attach_tick: Option<u64>) -> PauseCoordinator {
        let tick = test_tick_ns();
        let (grown, starts) = grown_by_one(birth_tick);
        let mut io = birth_dating_io(
            grown,
            starts,
            attach_tick.map(|attach| attach.saturating_mul(tick)),
        );
        let mut coordinator = birth_dating_coordinator();
        coordinator.service(&mut io).unwrap();
        coordinator
    }

    fn assert_covered(coordinator: &PauseCoordinator) {
        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(
            coordinator.expected_tasks.keys().collect::<Vec<_>>(),
            [&41, &42, &43]
        );
        assert!(coordinator.expected_starts.contains_key(&43));
    }

    fn assert_partial(coordinator: &PauseCoordinator) {
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(!coordinator.rearming_enabled());
    }

    /// A thread whose floored birth is after the last hook attach is no more
    /// exposed than a preflight thread: the stop adopts it into the expected
    /// set and confirms instead of reporting partial.
    #[test]
    fn thread_born_after_last_attach_is_adopted_and_the_stop_confirms() {
        let tick = test_tick_ns();
        let instant = 100u64.saturating_mul(tick);
        let grown: BTreeMap<u32, u8> = [(41, b'T'), (42, b'T'), (43, b'T')].into_iter().collect();
        let starts: BTreeMap<u32, u64> = [(41, 50), (42, 50), (43, 102)].into_iter().collect();
        let mut io = birth_dating_io(grown, starts, Some(instant));
        let mut coordinator = birth_dating_coordinator();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(
            coordinator.expected_tasks.keys().collect::<Vec<_>>(),
            [&41, &42, &43]
        );
    }

    /// The OpenSC shape: worker threads born ten ticks or more after the
    /// provider's hooks attached are covered and the stop confirms. Births
    /// date against the attach alone; no arm is an input.
    #[test]
    fn birth_well_after_the_last_attach_is_covered() {
        for birth_tick in [100, 101] {
            let coordinator = birth_dating_stop(birth_tick, Some(90));
            assert_covered(&coordinator);
        }
    }

    /// A thread born before the last hook attach completed might have run
    /// provider code before that provider's hooks were live: the stop keeps
    /// today's partial.
    #[test]
    fn thread_born_before_last_attach_keeps_partial() {
        assert_partial(&birth_dating_stop(99, Some(100)));
    }

    /// A thread born after one provider attached (tick 90) but before a later
    /// module's attach completed (tick 110) dates against the later attach and
    /// keeps today's partial.
    #[test]
    fn later_module_attach_after_the_birth_keeps_partial() {
        assert_partial(&birth_dating_stop(102, Some(110)));
    }

    /// Runs one stop that sees thread 43 born at `birth_tick` against a last
    /// completed attach at `attach_ns`.
    fn birth_dating_stop_at(birth_tick: u64, attach_ns: u64) -> PauseCoordinator {
        let (grown, starts) = grown_by_one(birth_tick);
        let mut io = birth_dating_io(grown, starts, Some(attach_ns));
        let mut coordinator = birth_dating_coordinator();
        coordinator.service(&mut io).unwrap();
        coordinator
    }

    /// The kernel floors the birth to whole ticks, and the floor is a lower
    /// bound on the birth (ruling PT-3): a floor at or before the attach
    /// instant (equality included) keeps today's partial, and any floor
    /// strictly after it is covered, even inside the attach's own tick.
    #[test]
    fn birth_floor_at_or_before_the_attach_keeps_partial_and_a_later_floor_is_covered() {
        let tick = test_tick_ns();
        for (birth_tick, attach_ns) in [
            (99, 100 * tick),
            (100, 100 * tick),
            (100, 100 * tick + 1),
            (101, 101 * tick),
        ] {
            let coordinator = birth_dating_stop_at(birth_tick, attach_ns);
            assert_eq!(
                coordinator.counters(),
                PauseCounters::partial(1),
                "floor {birth_tick} vs attach {attach_ns} must stay partial"
            );
            assert!(!coordinator.rearming_enabled());
        }
        for (birth_tick, attach_ns) in [
            (101, 100 * tick),
            (101, 101 * tick - 1),
            (101, 100 * tick + tick / 4),
        ] {
            assert_covered(&birth_dating_stop_at(birth_tick, attach_ns));
        }
    }

    /// An attach still in flight reports no completed instant: nothing born
    /// after preflight dates as covered.
    #[test]
    fn attach_in_flight_keeps_partial() {
        let clock = HookAttachClock::new();
        let tick = test_tick_ns();
        let earlier = clock.open();
        drop(earlier);
        let completed = clock.completed().expect("a closed attach is recorded");
        let open = clock.open();
        let in_flight = clock.completed();
        assert_eq!(in_flight, None, "an open attach reports no instant");

        let (grown, starts) = grown_by_one(completed / tick + 1_000);
        let mut io = birth_dating_io(grown, starts, in_flight);
        let mut coordinator = birth_dating_coordinator();
        coordinator.service(&mut io).unwrap();
        drop(open);

        assert_partial(&coordinator);
    }

    /// With no attach completion recorded, nothing born after preflight dates
    /// as covered.
    #[test]
    fn no_attach_instant_recorded_keeps_partial() {
        assert_eq!(HookAttachClock::new().completed(), None);
        assert_partial(&birth_dating_stop(102, None));
    }

    /// A thread adopted before this stop's own attach was verified stopped
    /// through that attach (the post-apply and post-arm samples require it
    /// stopped), so the attach completing after its birth does not undo the
    /// adoption.
    #[test]
    fn adopted_thread_survives_the_stops_own_attach() {
        let tick = test_tick_ns();
        let (grown, starts) = grown_by_one(102);
        let mut io = birth_dating_io(grown, starts, Some(90u64.saturating_mul(tick)));
        io.attach_instants = VecDeque::from([
            Some(90u64.saturating_mul(tick)),
            Some(90u64.saturating_mul(tick)),
            Some(110u64.saturating_mul(tick)),
            Some(110u64.saturating_mul(tick)),
        ]);
        let mut coordinator = birth_dating_coordinator();

        coordinator.service(&mut io).unwrap();

        assert_covered(&coordinator);
    }

    /// Births are adopted only in the stop's first (settling) sample. A stopped
    /// group cannot clone, so a thread first seen after the successor re-arm
    /// means something ran under the stop: today's partial, even when its
    /// floored birth is after the last attach (ruling PT-5).
    #[test]
    fn birth_first_seen_after_a_successor_rearm_keeps_partial() {
        let tick = test_tick_ns();
        for attach_tick in [100, 101, 102] {
            let coordinator = birth_first_seen_at(3, 102, attach_tick * tick);
            assert_partial(&coordinator);
        }
    }

    /// Runs one stop whose thread 43 (born at `birth_tick`) is first seen at
    /// sample `first_seen`: 0 settling, 1 the second sample, 2 post-apply,
    /// 3 post-successor-arm. Earlier samples see only the preflight threads.
    fn birth_first_seen_at(first_seen: usize, birth_tick: u64, attach_ns: u64) -> PauseCoordinator {
        let preflight: BTreeMap<u32, u64> = [(41, 50), (42, 50)].into_iter().collect();
        let (grown, starts) = grown_by_one(birth_tick);
        let mut io = birth_dating_io(grown.clone(), starts.clone(), Some(attach_ns));
        io.states = (0..4)
            .map(|sample| {
                Ok(if sample < first_seen {
                    stopped()
                } else {
                    grown.clone()
                })
            })
            .collect();
        io.starts = (0..4)
            .map(|sample| {
                Ok(if sample < first_seen {
                    preflight.clone()
                } else {
                    starts.clone()
                })
            })
            .collect();
        let mut coordinator = birth_dating_coordinator();
        coordinator.service(&mut io).unwrap();
        coordinator
    }

    /// The strict samples admit no new thread (ruling PT-5): a covered birth
    /// first seen at the second or the post-attach sample keeps today's
    /// partial; the same birth first seen while the stop settles confirms.
    #[test]
    fn birth_first_seen_at_a_strict_sample_keeps_partial() {
        let tick = test_tick_ns();
        assert_covered(&birth_first_seen_at(0, 102, 90 * tick));
        for first_seen in [1, 2] {
            let coordinator = birth_first_seen_at(first_seen, 102, 90 * tick);
            assert_eq!(
                coordinator.counters(),
                PauseCounters::partial(1),
                "first seen at sample {first_seen}"
            );
            assert!(!coordinator.expected_tasks.contains_key(&43));
        }
    }

    /// An adopted thread is held to the later samples like a preflight one:
    /// a changed start time (a reused tid) or a running state at a strict
    /// sample keeps today's partial.
    #[test]
    fn adopted_thread_is_held_to_the_strict_samples() {
        let tick = test_tick_ns();
        for change in ["reused", "running"] {
            let (grown, starts) = grown_by_one(102);
            let mut io = birth_dating_io(grown.clone(), starts.clone(), Some(90 * tick));
            if change == "reused" {
                let mut reused = starts;
                reused.insert(43, 103);
                io.starts[1] = Ok(reused);
            } else {
                let mut running = grown;
                running.insert(43, b'R');
                io.states[1] = Ok(running);
            }
            let mut coordinator = birth_dating_coordinator();

            coordinator.service(&mut io).unwrap();

            assert_eq!(
                coordinator.counters(),
                PauseCounters::partial(1),
                "adopted thread {change} at the second sample"
            );
        }
    }

    /// A preflight thread whose start time becomes unreadable at a later
    /// sample can no longer be identified: today's partial.
    #[test]
    fn known_thread_whose_start_becomes_unreadable_keeps_partial() {
        let preflight: BTreeMap<u32, u64> = [(41, 50), (42, 50)].into_iter().collect();
        let mut io = birth_dating_io(stopped(), preflight, Some(90 * test_tick_ns()));
        io.starts[1] = Ok([(41, 50)].into_iter().collect());
        let mut coordinator = birth_dating_coordinator();

        coordinator.service(&mut io).unwrap();

        assert_partial(&coordinator);
    }

    /// The covered check itself (ruling PT-3): covered exactly when the
    /// floored birth `start_tick * tick_ns` is strictly after the attach;
    /// equality is not covered, nothing is covered without an instant, and
    /// nothing after a saturated (unreadable-clock) instant.
    #[test]
    fn birth_covered_needs_an_instant_and_a_strictly_later_floor() {
        let tick = test_tick_ns();
        assert!(!birth_covered(102, None));
        assert!(!birth_covered(99, Some(100 * tick)));
        assert!(!birth_covered(100, Some(100 * tick)));
        assert!(!birth_covered(100, Some(100 * tick + 1)));
        assert!(birth_covered(100, Some(100 * tick - 1)));
        assert!(birth_covered(101, Some(100 * tick)));
        assert!(birth_covered(101, Some(100 * tick + tick / 2)));
        assert!(!birth_covered(u64::MAX, Some(u64::MAX)));
        assert!(!birth_covered(u64::MAX / tick, Some(u64::MAX - 1)));
    }

    /// The attach clock keeps the latest completion, stamps it in the boot
    /// clock when the window closes, never moves backward, and fails closed
    /// (nothing dates after it) when the boot clock was unreadable at close.
    #[test]
    fn hook_attach_clock_keeps_the_latest_completion_and_fails_closed() {
        let clock = HookAttachClock::new();
        assert_eq!(clock.completed(), None);

        let before = boot_ns().expect("the boot clock reads");
        drop(clock.open());
        let after = boot_ns().expect("the boot clock reads");
        let stamped = clock.completed().expect("a closed attach is recorded");
        assert!(
            (before..=after).contains(&stamped),
            "{before} <= {stamped} <= {after}"
        );

        let outer = clock.open();
        let inner = clock.open();
        drop(inner);
        assert_eq!(clock.completed(), None, "one attach is still in flight");
        drop(outer);
        assert!(clock.completed().unwrap() >= stamped);

        let latest = clock.completed().unwrap();
        let stale = clock.open();
        std::mem::forget(stale);
        clock.close(Some(1));
        assert_eq!(clock.completed(), Some(latest), "an older stamp never wins");

        let unreadable = clock.open();
        std::mem::forget(unreadable);
        clock.close(None);
        assert_eq!(clock.completed(), Some(u64::MAX));
    }

    /// Start time has tick granularity: a floor equal to the instant (the
    /// birth could be at it) or before it keeps today's partial.
    #[test]
    fn birth_at_or_before_the_attach_tick_keeps_partial() {
        let tick = test_tick_ns();
        let instant = 100u64.saturating_mul(tick);
        for birth_tick in [99, 100] {
            let grown: BTreeMap<u32, u8> =
                [(41, b'T'), (42, b'T'), (43, b'T')].into_iter().collect();
            let starts: BTreeMap<u32, u64> =
                [(41, 50), (42, 50), (43, birth_tick)].into_iter().collect();
            let mut io = birth_dating_io(grown, starts, Some(instant));
            let mut coordinator = birth_dating_coordinator();

            coordinator.service(&mut io).unwrap();

            assert_eq!(
                coordinator.counters(),
                PauseCounters::partial(1),
                "birth at tick {birth_tick} must stay partial"
            );
            assert!(!coordinator.rearming_enabled());
        }
    }

    fn running_42() -> BTreeMap<u32, u8> {
        [(41, b'T'), (42, b'R')].into_iter().collect()
    }

    fn waits(io: &FakeIo) -> usize {
        io.events.iter().filter(|event| **event == "wait").count()
    }

    /// A stop's first sample can catch a thread the group stop has not reached
    /// yet (a loaded host). The coordinator re-samples at the 1 ms cadence,
    /// inside the stop's deadline, until every thread is stopped, then
    /// confirms (ruling PT-3).
    #[test]
    fn first_sample_waits_for_a_running_thread_to_stop() {
        let sleeping: BTreeMap<u32, u8> = [(41, b'S'), (42, b'T')].into_iter().collect();
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.states = VecDeque::from([
            Ok(running_42()),
            Ok(sleeping),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
        ]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert!(coordinator.rearming_enabled());
    }

    /// The OpenSC shape under load: a newborn worker (born after the last
    /// attach) is still running at the first sample, then stops; it is
    /// covered and the stop confirms.
    #[test]
    fn covered_newborn_running_at_the_first_sample_settles_and_confirms() {
        let tick = test_tick_ns();
        let (grown, starts) = grown_by_one(101);
        let mut first = grown.clone();
        first.insert(43, b'R');
        let mut io = birth_dating_io(grown, starts.clone(), Some(100 * tick));
        io.states.push_front(Ok(first));
        io.starts.push_front(Ok(starts));
        let mut coordinator = birth_dating_coordinator();

        coordinator.service(&mut io).unwrap();

        assert_covered(&coordinator);
    }

    /// The settling is bounded by the stop's existing deadline: a thread still
    /// running when it passes ends the stop partial on the deadline message
    /// (ruling PT-7), after at most one wait per millisecond of the cycle.
    #[test]
    fn thread_still_running_at_the_stop_deadline_keeps_partial() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.states = std::iter::repeat_with(|| Ok(running_42()))
            .take(2_000)
            .collect();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_partial(&coordinator);
        assert!(
            waits(&io) <= (CYCLE_NS / SAMPLE_NS) as usize + 2,
            "{} waits",
            waits(&io)
        );
        assert!(
            !io.states.is_empty(),
            "the deadline, not the script, ended it"
        );
    }

    /// The settling sample itself: a thread still running when the deadline
    /// passes reports the deadline message (ruling PT-7), a first sample
    /// already past the deadline keeps the deadline message, and a failed wait
    /// is a lifecycle failure.
    #[test]
    fn settling_sample_reports_the_deadline_when_it_runs_out_of_time() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        let mut io = FakeIo {
            states: std::iter::repeat_with(|| Ok(running_42()))
                .take(2_000)
                .collect(),
            ..FakeIo::default()
        };
        assert_eq!(
            coordinator.sample_until_stopped(&mut io, 5 * SAMPLE_NS),
            Err((MSG_PAUSE_CONFIRMATION_DEADLINE.into(), false))
        );
        assert!((4..=6).contains(&waits(&io)), "{} waits", waits(&io));

        let mut late = FakeIo {
            fallback_now: 10,
            ..FakeIo::default()
        };
        assert_eq!(
            coordinator.sample_until_stopped(&mut late, 5),
            Err((MSG_PAUSE_CONFIRMATION_DEADLINE.into(), false))
        );

        let mut failing = FakeIo {
            states: VecDeque::from([Ok(running_42())]),
            fail_wait: true,
            ..FakeIo::default()
        };
        assert_eq!(
            coordinator.sample_until_stopped(&mut failing, CYCLE_NS),
            Err(("wait".into(), true))
        );
    }

    /// The `wait` events immediately before the resume.
    fn waits_before_resume(io: &FakeIo) -> usize {
        let resume = io
            .events
            .iter()
            .position(|event| *event == "resume")
            .expect("the stop resumed");
        io.events[..resume]
            .iter()
            .rev()
            .take_while(|event| **event == "wait")
            .count()
    }

    /// A thread the child starts once resumed dates by its floored tick,
    /// which cannot prove a birth inside the last attach's own tick. The
    /// resume therefore waits, at the 1 ms cadence, until the boot clock has
    /// crossed into the tick after the last completed attach; then every such
    /// birth floors strictly after the attach.
    #[test]
    fn resume_waits_for_the_tick_after_the_last_attach() {
        let tick = test_tick_ns();
        let attach = 100 * tick + tick / 2;
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.fallback_attach = Some(attach);
        io.boot_clock = VecDeque::from([Some(attach + 1), Some(101 * tick - 1), Some(101 * tick)]);
        io.fallback_boot = Some(101 * tick + 1);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(waits_before_resume(&io), 2);
        assert!(
            io.boot_clock.is_empty(),
            "the boundary reading ended the wait"
        );
    }

    /// The hold never delays a stop without a reason or past its bound: no
    /// wait once the boot clock is already past the attach's tick, none with
    /// no recorded attach or an unreadable boot clock, and at most one tick of
    /// 1 ms waits when the boot clock never gets there.
    #[test]
    fn resume_hold_is_skipped_or_bounded() {
        let tick = test_tick_ns();
        for (attach, boot, max_waits) in [
            (Some(100 * tick), Some(101 * tick), 0),
            (None, Some(100 * tick), 0),
            (Some(100 * tick), None, 0),
            (
                Some(100 * tick),
                Some(100 * tick),
                (tick / SAMPLE_NS) as usize + 1,
            ),
        ] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            io.fallback_attach = attach;
            io.fallback_boot = boot;
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(
                coordinator.counters(),
                PauseCounters::confirmed(1),
                "attach {attach:?} boot {boot:?}"
            );
            assert_eq!(
                waits_before_resume(&io),
                max_waits,
                "attach {attach:?} boot {boot:?}"
            );
        }
    }

    /// The hold never costs the stop its deadline: a confirmed stop whose
    /// next 1 ms wait could cross the deadline resumes at once, because a
    /// resume observed late fails the whole run. A birth inside the attach's
    /// tick then stays partial at the next stop, the safe direction.
    #[test]
    fn resume_hold_never_waits_past_the_stop_deadline() {
        let tick = test_tick_ns();
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.now = [10, 11, 496_999_997].into_iter().map(Ok).collect();
        io.fallback_attach = Some(100 * tick + 1);
        io.fallback_boot = Some(100 * tick + 2);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(waits_before_resume(&io), 0, "{:?}", io.events);
    }

    /// A 1 ms wait started with exactly 1 ms left ends past the deadline once
    /// the resume and the observer's first read follow it, so the hold also
    /// keeps a clock tick of headroom: with 1 ms plus less than a tick left it
    /// resumes at once.
    #[test]
    fn resume_hold_keeps_a_tick_of_headroom_before_the_deadline() {
        let tick = test_tick_ns();
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.now = [10, 11, 495_999_999].into_iter().map(Ok).collect();
        io.fallback_attach = Some(100 * tick + 1);
        io.fallback_boot = Some(100 * tick + 2);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(waits_before_resume(&io), 0, "{:?}", io.events);
    }

    /// The hold resumes at once when it cannot read the stop's clock: it has
    /// no way to know the next wait is inside the deadline.
    #[test]
    fn resume_hold_resumes_at_once_without_the_stop_clock() {
        let tick = test_tick_ns();
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.fallback_attach = Some(100 * tick);
        io.fallback_boot = Some(100 * tick);
        io.fail_first_now_after_boot = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(waits_before_resume(&io), 0, "{:?}", io.events);
    }

    /// A saturated attach instant has no next tick: nothing to wait for.
    #[test]
    fn resume_hold_skips_a_saturated_attach_instant() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.fallback_attach = Some(u64::MAX);
        io.fallback_boot = Some(0);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert_eq!(waits_before_resume(&io), 0);
    }

    /// A wait that fails inside the hold is a lifecycle failure like every
    /// other wait in the cycle, and the stopped child is still resumed.
    #[test]
    fn a_failed_wait_inside_the_resume_hold_is_lifecycle_and_still_resumes() {
        let tick = test_tick_ns();
        let held = |fail_wait_after| {
            let mut io = successful_io(vec![record(10, 0, false)]);
            io.fallback_attach = Some(100 * tick);
            io.fallback_boot = Some(100 * tick);
            io.fail_wait_after = fail_wait_after;
            io
        };
        let mut reference = held(None);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut reference).unwrap();
        let hold_waits = waits_before_resume(&reference);
        assert!(hold_waits > 2);
        let resume = reference
            .events
            .iter()
            .position(|e| *e == "resume")
            .unwrap();
        let waits_before_hold = waits(&FakeIo {
            events: reference.events[..resume - hold_waits].to_vec(),
            ..FakeIo::default()
        });

        let mut io = held(Some(waits_before_hold + 2));
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(
            error.lifecycle(),
            "a failed hold wait is lifecycle: {error}"
        );
        assert_eq!(io.waits_done, waits_before_hold + 2);
        let last_wait = io.events.iter().rposition(|e| *e == "wait").unwrap();
        assert!(
            io.events[last_wait..].contains(&"resume"),
            "the child is resumed after the failed wait: {:?}",
            io.events
        );
    }

    /// While the stop settles, a thread still on its way into the stop when
    /// the deadline passes is a late boundary: the deadline message and its
    /// `later_pause_boundary` category, as for a late fully stopped sample.
    #[test]
    fn settling_sample_out_of_time_with_a_thread_on_its_way_reports_the_deadline() {
        for state in *b"RSD" {
            let on_its_way: BTreeMap<u32, u8> = [(41, b'T'), (42, state)].into_iter().collect();
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            let mut io = FakeIo {
                states: VecDeque::from([Ok(on_its_way.clone()), Ok(on_its_way)]),
                ..FakeIo::default()
            };
            assert_eq!(
                coordinator.sample_until_stopped(&mut io, SAMPLE_NS / 2),
                Err((MSG_PAUSE_CONFIRMATION_DEADLINE.into(), false)),
                "state {}",
                state as char
            );
            assert_eq!(waits(&io), 1);
        }
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.states = std::iter::repeat_with(|| Ok(running_42()))
            .take(600)
            .collect();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.required());
        assert!(
            format!("{error}").contains(MSG_PAUSE_CONFIRMATION_DEADLINE),
            "{error}"
        );
    }

    /// The settle loop's sample cap is the deadline's twin: a stop whose
    /// threads are all still on their way into it when the samples run out
    /// reports the deadline message, as when the deadline passes first, while
    /// a thread that can never reach the stop still refuses at once on the
    /// task set.
    #[test]
    fn settle_samples_running_out_report_the_deadline() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        let mut io = FakeIo {
            states: std::iter::repeat_with(|| Ok(running_42()))
                .take(2_000)
                .collect(),
            ..FakeIo::default()
        };
        assert_eq!(
            coordinator.sample_until_stopped(&mut io, u64::MAX / 2),
            Err((MSG_PAUSE_CONFIRMATION_DEADLINE.into(), false))
        );
        assert_eq!(waits(&io), MAX_SETTLE_SAMPLES as usize + 1);

        let unreachable: BTreeMap<u32, u8> = [(41, b'T'), (42, b'Z')].into_iter().collect();
        let mut io = FakeIo {
            states: std::iter::repeat_with(|| Ok(unreachable.clone()))
                .take(2_000)
                .collect(),
            ..FakeIo::default()
        };
        assert_eq!(
            coordinator.sample_until_stopped(&mut io, u64::MAX / 2),
            Err((MSG_TASK_SET_CHANGED.into(), false))
        );
        assert_eq!(waits(&io), 0);
    }

    /// The other direction: a strict sample with a running thread, and a
    /// settling sample with a thread that can never reach the stop, keep the
    /// task-set refusal even past the deadline (ruling PT-6).
    #[test]
    fn late_strict_or_unreachable_samples_keep_the_task_set_refusal() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        let mut io = FakeIo {
            states: VecDeque::from([Ok(running_42())]),
            ..FakeIo::default()
        };
        assert_eq!(
            coordinator.sample_stopped(&mut io, 0),
            Err(MSG_TASK_SET_CHANGED.into())
        );
        for state in *b"ZXxt" {
            let unreachable: BTreeMap<u32, u8> = [(41, b'T'), (42, state)].into_iter().collect();
            let mut io = FakeIo {
                states: VecDeque::from([Ok(unreachable)]),
                ..FakeIo::default()
            };
            assert_eq!(
                coordinator.sample_until_stopped(&mut io, 0),
                Err((MSG_TASK_SET_CHANGED.into(), false)),
                "state {}",
                state as char
            );
            assert_eq!(waits(&io), 0);
        }
    }

    /// While the stop settles, only a thread on its way into the stop (`R`,
    /// `S` or `D`) is waited for. A zombie, a dead or a traced thread can never
    /// reach the group stop: today's partial at once, without re-sampling
    /// (ruling PT-5).
    #[test]
    fn settling_fails_fast_on_a_state_that_cannot_reach_the_stop() {
        for state in *b"ZXxt" {
            let mut io = successful_io(vec![record(10, 0, false)]);
            let unreachable: BTreeMap<u32, u8> = [(41, b'T'), (42, state)].into_iter().collect();
            io.states = std::iter::repeat_with(|| Ok(unreachable.clone()))
                .take(2_000)
                .collect();
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_partial(&coordinator);
            assert_eq!(io.state_reads, 1, "state {}", state as char);
        }
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.states = VecDeque::from([
            Ok([(41, b'D'), (42, b'T')].into_iter().collect()),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
        ]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
    }

    /// A settling sample that finds every thread stopped but lands after the
    /// deadline (an overslept wait on a loaded host) is a late boundary, not a
    /// task-set change: it keeps the deadline message and its
    /// `later_pause_boundary` category.
    #[test]
    fn settled_but_late_first_sample_reports_the_deadline() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        let mut io = FakeIo {
            states: VecDeque::from([Ok(running_42()), Ok(stopped())]),
            ..FakeIo::default()
        };
        assert_eq!(
            coordinator.sample_until_stopped(&mut io, SAMPLE_NS / 2),
            Err((MSG_PAUSE_CONFIRMATION_DEADLINE.into(), false))
        );
        assert_eq!(waits(&io), 1);
        assert_eq!(
            diagnostic_for_message(MSG_PAUSE_CONFIRMATION_DEADLINE),
            Some(PauseDiagnostic::LaterPauseBoundary)
        );
    }

    /// A thread that vanishes while the stop settles changes the task set:
    /// today's partial, without waiting out the deadline.
    #[test]
    fn thread_vanishing_while_the_stop_settles_keeps_partial() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.states = VecDeque::from([
            Ok(running_42()),
            Ok([(41, b'T')].into_iter().collect()),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
        ]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_partial(&coordinator);
        assert!(waits(&io) < 10, "{} waits", waits(&io));
    }

    /// Only the first sample settles. Once every thread was seen stopped, a
    /// thread seen running at the second (pre-apply), the post-apply or the
    /// post-successor-arm sample was continued under the stop: today's
    /// partial, no re-sampling.
    #[test]
    fn thread_running_after_the_stop_was_seen_stopped_keeps_partial() {
        for running_at in [1usize, 2, 3] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            let mut states: VecDeque<_> = (0..6).map(|_| Ok(stopped())).collect();
            states[running_at] = Ok(running_42());
            io.states = states;
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(
                coordinator.counters(),
                PauseCounters::partial(1),
                "running at sample {running_at}"
            );
        }
    }

    /// A new thread whose start time cannot be read cannot be dated: the stop
    /// keeps today's partial.
    #[test]
    fn thread_with_unreadable_start_keeps_partial() {
        let tick = test_tick_ns();
        let instant = 100u64.saturating_mul(tick);
        let grown: BTreeMap<u32, u8> = [(41, b'T'), (42, b'T'), (43, b'T')].into_iter().collect();
        let starts: BTreeMap<u32, u64> = [(41, 50), (42, 50)].into_iter().collect();
        let mut io = birth_dating_io(grown, starts, Some(instant));
        let mut coordinator = birth_dating_coordinator();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(!coordinator.rearming_enabled());
    }

    /// Thread identity is the (tid, start time) pair: an expected tid with a
    /// different start time is a new thread, and an older start keeps today's
    /// partial even though the tid set is unchanged.
    #[test]
    fn reused_tid_with_older_start_keeps_partial() {
        let tick = test_tick_ns();
        let instant = 100u64.saturating_mul(tick);
        let starts: BTreeMap<u32, u64> = [(41, 49), (42, 50)].into_iter().collect();
        let mut io = birth_dating_io(stopped(), starts, Some(instant));
        let mut coordinator = birth_dating_coordinator();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(!coordinator.rearming_enabled());
    }

    /// A reused tid keeps today's partial whatever its start time: even a
    /// start well after the last attach does not adopt a tid the preflight
    /// already knew.
    #[test]
    fn reused_tid_with_newer_start_keeps_partial() {
        let tick = test_tick_ns();
        let instant = 100u64.saturating_mul(tick);
        let starts: BTreeMap<u32, u64> = [(41, 150), (42, 50)].into_iter().collect();
        let mut io = birth_dating_io(stopped(), starts, Some(instant));
        let mut coordinator = birth_dating_coordinator();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(!coordinator.rearming_enabled());
    }

    /// The start-time reader reports `/proc` field 22 and orders a real birth:
    /// a freshly spawned process dates between two boot-clock checkpoints.
    /// The crafted lines pin the field index (past a comm containing `)`)
    /// and the truncation failure the sampler maps to an error.
    #[test]
    fn task_start_reader_reports_field_22_and_orders_a_real_birth() {
        let line = b"123 (a)b) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20";
        assert_eq!(parse_task_start(line), Some(19));
        assert_eq!(parse_task_start(b"123 (a) R 1 2"), None);
        assert_eq!(parse_task_start(b"missing delimiter"), None);

        let tick = test_tick_ns();
        let boot_before = boot_ns().expect("the boot clock reads");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let samples = read_task_samples(child.id()).expect("task samples read");
        let boot_after = boot_ns().expect("the boot clock reads");
        let leader = samples.get(&child.id()).and_then(|sample| sample.start);
        child.kill().unwrap();
        child.wait().unwrap();

        let leader = leader.expect("the leader dates its own birth");
        assert!(
            leader.saturating_mul(tick) <= boot_after.saturating_add(tick),
            "birth tick {leader} starts after the read"
        );
        assert!(
            leader.saturating_add(1).saturating_mul(tick) > boot_before,
            "birth tick {leader} ends before the spawn"
        );
    }

    /// The helper's SIGSTOP is asynchronous: under host load the target is
    /// still running when the first sample reads it, and the stop lands
    /// milliseconds later. The same task set reporting `R` and then `T` is
    /// delivery latency, not a changed child, so the proof waits for the
    /// stop within its causal deadline instead of failing the cycle.
    #[test]
    fn a_stop_still_landing_confirms_once_every_task_reports_stopped() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let landing: BTreeMap<u32, u8> = [(41, b'R'), (42, b'T')].into_iter().collect();
        io.states = VecDeque::from([Ok(landing.clone()), Ok(landing), Ok(stopped())]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
        assert!(
            io.events.iter().filter(|event| **event == "wait").count() >= 2,
            "the proof waits for delivery: {:?}",
            io.events
        );
    }

    /// Delivery tolerance never covers a changed child: paranoia about new or
    /// vanished tasks fails the sample immediately, without spending the
    /// causal deadline waiting for a task set that is already wrong.
    #[test]
    fn a_changed_task_set_fails_without_waiting_for_delivery() {
        for tasks in [
            [(41, b'T'), (42, b'T'), (43, b'T')].into_iter().collect(),
            [(41, b'T')].into_iter().collect(),
        ] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            io.states = VecDeque::from([Ok(tasks)]);
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(coordinator.counters(), PauseCounters::partial(1));
            assert_eq!(
                io.events.iter().filter(|event| **event == "wait").count(),
                0,
                "a changed task set fails fast"
            );
        }
    }

    /// Delivery tolerance covers only a task still on its way to the stop
    /// (R/S/D): a zombie, a dead task or a tracing stop at the first
    /// sample will never become `T`, so the sample fails at once, without
    /// spending the causal deadline waiting for delivery.
    #[test]
    fn a_task_outside_r_s_d_t_fails_without_waiting_for_delivery() {
        for state in *b"ZXt" {
            let mut io = successful_io(vec![record(10, 0, false)]);
            let tasks: BTreeMap<u32, u8> = [(41, state), (42, b'T')].into_iter().collect();
            io.states = VecDeque::from([Ok(tasks)]);
            let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
            coordinator.arm_for_test();

            coordinator.service(&mut io).unwrap();

            assert_eq!(
                coordinator.counters(),
                PauseCounters::partial(1),
                "state {}",
                state as char
            );
            assert_eq!(
                io.events.iter().filter(|event| **event == "wait").count(),
                0,
                "state {} fails fast",
                state as char
            );
        }
    }

    /// Delivery tolerance ends at the first sample: a task running again
    /// after stopped samples means SIGCONT, not a late SIGSTOP, so the
    /// later samples never wait out a re-stop (SIGTTIN, Ctrl-Z). Staged
    /// `[stopped, stopped, running, stopped...]` ends partial, not
    /// confirmed.
    #[test]
    fn a_task_running_after_stopped_samples_is_sigcont_not_delivery() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let running: BTreeMap<u32, u8> = [(41, b'R'), (42, b'T')].into_iter().collect();
        io.states = VecDeque::from([Ok(stopped()), Ok(stopped()), Ok(running), Ok(stopped())]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
    }

    /// The delivery wait's own failure is a lifecycle failure like every
    /// other wait in the cycle, not an unconfirmed pause.
    #[test]
    fn a_failed_delivery_wait_is_a_lifecycle_failure() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.fail_wait = true;
        let running: BTreeMap<u32, u8> = [(41, b'R'), (42, b'T')].into_iter().collect();
        io.states = VecDeque::from([Ok(running)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.lifecycle(), "a failed wait is lifecycle: {error}");
    }

    /// A child that never stops (every sample reports it running) cannot
    /// confirm: the delivery wait ends at the confirmation deadline, which
    /// `always` refuses as a required pause failure.
    #[test]
    fn a_stop_that_never_lands_fails_on_the_confirmation_deadline() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let running: BTreeMap<u32, u8> = [(41, b'R'), (42, b'T')].into_iter().collect();
        io.states = VecDeque::from(vec![Ok(running); 600]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(error.required());
        assert!(
            format!("{error}").contains(MSG_PAUSE_CONFIRMATION_DEADLINE),
            "a running child fails on the deadline, not the task set: {error}"
        );
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

    /// Queues the next stop of an armed owned epoch: the kernel's REQUESTED
    /// authorization and the one winner record the stopping hook produced.
    fn queue_next_stop(io: &mut FakeIo) {
        io.authorization = Some(PAUSE_REQUESTED);
        let next = record(io.fallback_now, 0, false);
        io.queue
            .extend([Ok(Some(DiscoveryItem::Record(next))), Ok(None), Ok(None)]);
    }

    /// GT-4 (H-4). `run --pause auto` confirmed 2/2 stops and still missed the
    /// session setup calls and ~0.7 s of the loop: the two stops were the
    /// startup loader hits, and after them nothing was armed until the next
    /// frame. The child's `dlopen` (RT_ADD, RT_CONSISTENT) and the
    /// `C_GetFunctionList` return that publishes the provider's table then ran
    /// unpaused, and every call before the next frame applied the table was
    /// lost. Each confirmed stop now keeps the owned epoch armed for the next
    /// pause-eligible event, so the table is attached while the child is
    /// still stopped at its publication.
    #[test]
    fn every_confirmed_stop_keeps_the_owned_epoch_armed_for_the_next() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();
        // Startup RT_CONSISTENT, then the provider's dlopen RT_ADD and
        // RT_CONSISTENT, then its C_GetFunctionList return.
        for stop in 2..=5 {
            assert!(coordinator.is_armed(), "stop {stop} finds the epoch armed");
            queue_next_stop(&mut io);
            coordinator.service(&mut io).unwrap();
        }

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(5));
        assert!(
            coordinator.is_armed(),
            "the next pause-eligible event is stopped too"
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            5
        );
    }

    #[test]
    fn the_successor_chain_is_bounded_and_a_fresh_arm_restores_it() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();
        assert!(coordinator.is_armed());
        assert_eq!(io.authorization, Some(PAUSE_ARMED));

        let mut stops = 1;
        while coordinator.is_armed() {
            // The successor's own window: a record this arm could have
            // produced, not one left over from before it.
            queue_next_stop(&mut io);
            coordinator.service(&mut io).unwrap();
            stops += 1;
            assert!(stops <= usize::from(MAX_SUCCESSORS_PER_ARM) + 1);
        }

        assert_eq!(stops, usize::from(MAX_SUCCESSORS_PER_ARM) + 1);
        assert_eq!(
            coordinator.counters(),
            PauseCounters::confirmed(stops as u64)
        );
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            stops
        );
        assert_eq!(io.authorization, None, "the last stop installs nothing");
        assert_eq!(
            io.unpaused_publications, 0,
            "nothing was left unpublished, so nothing is reported"
        );

        // The next frame's fresh arm restores the whole chain.
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        queue_next_stop(&mut io);
        coordinator.service(&mut io).unwrap();
        assert!(coordinator.is_armed());
    }

    /// The bound is honest: a chain that ends while the owned child still has
    /// an unpublished provider table says so, because calls made before the
    /// next frame attaches it may go unobserved.
    #[test]
    fn a_chain_that_ends_with_a_table_unpublished_reports_the_gap() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.publication_pending = true;
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.service(&mut io).unwrap();
        assert_eq!(io.unpaused_publications, 0, "the chain continues");
        while coordinator.is_armed() {
            queue_next_stop(&mut io);
            coordinator.service(&mut io).unwrap();
        }

        assert_eq!(io.unpaused_publications, 1);
        assert_eq!(coordinator.counters().partial, 0, "every stop confirmed");
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
        for failure in ["tasks", "changed", "attach"] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            if failure == "changed" {
                // A changed task set fails at once, inside the deadline.
                io.states = VecDeque::from([Ok([(41, b'T'), (43, b'T')].into_iter().collect())]);
            } else if failure == "tasks" {
                // A thread that never reaches the stop: the first sample now
                // re-samples until the stop deadline (ruling PT-3) and then
                // ends on the deadline message (ruling PT-7), an ordinary
                // failure all the same.
                let running: BTreeMap<u32, u8> = [(41, b'R'), (42, b'T')].into_iter().collect();
                io.states = std::iter::repeat_with(|| Ok(running.clone()))
                    .take(2_000)
                    .collect();
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
    fn stale_record_apply_failure_with_armed_readback_counts_its_attempt() {
        // The field order (`service_received` -> `fail_cycle` ->
        // `finish_nonconfirmed` with no open attempt): an armed epoch
        // dequeues a stale record while the authorization still reads
        // ARMED, and the bounded unowned apply fails. The partial must
        // close an attempt, not outrun the attempt count.
        let mut io = FakeIo {
            authorization: Some(PAUSE_ARMED),
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(record(9, 0, false))))]),
            fail_apply: true,
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.armed_at_ns = Some(10);

        coordinator.service(&mut io).unwrap();
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
    }

    #[test]
    fn stale_record_apply_failure_keeps_its_apply_diagnostic() {
        // Opening the attempt for a failed stale-record apply must not clear
        // the category that apply recorded.
        let mut io = FakeIo {
            authorization: Some(PAUSE_ARMED),
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(record(9, 0, false))))]),
            fail_apply: true,
            apply_error_diagnostic: Some(PauseDiagnostic::DeadlineDuringEngineApply),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.armed_at_ns = Some(10);

        let error = coordinator.service(&mut io).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("[pause_diag=deadline_during_engine_apply]"),
            "{error}"
        );
    }

    #[test]
    fn unaccounted_record_counts_its_attempt() {
        // Same defect class: a record for another pid fails the cycle
        // before any attempt opens, so the partial must open one first.
        let mut foreign = record(9, 0, false);
        foreign.pid_tgid = 42u64 << 32;
        let mut io = FakeIo {
            queue: VecDeque::from([Ok(Some(DiscoveryItem::Record(foreign)))]),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());

        coordinator.service(&mut io).unwrap();
        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
    }

    #[test]
    fn stopped_sample_retries_a_lagging_stop_then_confirms() {
        // Under host load SIGSTOP delivery lags the record: the first
        // sample sees a running task for a stop that is still landing.
        // The cycle must poll within its unchanged deadline, not fail it.
        let mut io = successful_io(vec![record(6, 0, false)]);
        io.authorization = None;
        io.now = VecDeque::from([Ok(5)]);
        let lagging: BTreeMap<u32, u8> = [(41, b'R'), (42, b'T')].into_iter().collect();
        io.states = VecDeque::from([
            Ok(lagging),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
            Ok(stopped()),
        ]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        io.authorization = Some(PAUSE_REQUESTED);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));
    }

    #[test]
    fn stopped_sample_stops_polling_at_the_cycle_deadline() {
        // A stop that never lands must not spin past its deadline: two
        // running polls, then the clock crosses the cycle deadline.
        let mut io = successful_io(vec![record(6, 0, false)]);
        io.authorization = None;
        io.now = VecDeque::from([Ok(5), Ok(10), Ok(11), Ok(12), Ok(13), Ok(u64::MAX)]);
        let lagging: BTreeMap<u32, u8> = [(41, b'R'), (42, b'R')].into_iter().collect();
        io.states = VecDeque::from([Ok(lagging.clone()), Ok(lagging.clone()), Ok(lagging)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        io.authorization = Some(PAUSE_REQUESTED);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(io.state_reads, 3);
    }

    #[test]
    fn stopped_sample_fails_fast_on_exited_tasks() {
        // A zombie never becomes stopped: no polling, one read, partial.
        let mut io = successful_io(vec![record(6, 0, false)]);
        io.authorization = None;
        io.now = VecDeque::from([Ok(5)]);
        let zombie: BTreeMap<u32, u8> = [(41, b'Z'), (42, b'T')].into_iter().collect();
        io.states = VecDeque::from([Ok(zombie)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        io.authorization = Some(PAUSE_REQUESTED);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(io.state_reads, 1);
    }

    #[test]
    fn stopped_sample_fails_fast_on_changed_task_set() {
        // A forked task is a real change, not lag: no polling either.
        let mut io = successful_io(vec![record(6, 0, false)]);
        io.authorization = None;
        io.now = VecDeque::from([Ok(5)]);
        let forked: BTreeMap<u32, u8> = [(41, b'T'), (43, b'T')].into_iter().collect();
        io.states = VecDeque::from([Ok(forked)]);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
        io.authorization = Some(PAUSE_REQUESTED);

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert_eq!(io.state_reads, 1);
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
                "dequeue",
                "account",
                "unvalidated",
                "read",
                "remove",
                "detach"
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
    fn held_child_is_resumed_before_any_link_detach() {
        let mut io = FakeIo {
            authorization: Some(PAUSE_REQUESTED),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        coordinator.begin_attempt();
        coordinator.epoch.accepted = true;
        coordinator.may_be_stopped = true;

        let _ = coordinator.cleanup(&mut io);

        let resume = io
            .events
            .iter()
            .position(|event| *event == "resume")
            .expect("the held child must be resumed during cleanup");
        let detach = io
            .events
            .iter()
            .position(|event| *event == "detach")
            .expect("the links must detach during cleanup");
        assert!(
            resume < detach,
            "a stopped child must never wait on serialized kernel teardown: resume at {resume}, detach at {detach}"
        );
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
    fn required_failure_resumes_the_held_child_before_terminal_detach() {
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
        assert!(resume < detach);
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

    /// An engine-incomplete cycle is a counted named gap, never the end of
    /// the pause chain: the child was resumed, so a later loader hit must
    /// be able to arm and confirm like any other cycle.
    #[test]
    fn an_engine_incomplete_cycle_rearms_for_the_next_loader_hit() {
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.required_complete = false;
        io.apply_outcome_diagnostic = Some(PauseDiagnostic::EngineIncompleteWithinDeadline);
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();

        coordinator.service(&mut io).unwrap();

        assert_eq!(coordinator.counters(), PauseCounters::partial(1));
        assert!(
            coordinator.rearming_enabled(),
            "an incomplete cycle must not retire the pause chain"
        );
        io.fallback_now = 15;
        assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);

        io.required_complete = true;
        io.apply_outcome_diagnostic = None;
        io.authorization = Some(PAUSE_REQUESTED);
        io.queue
            .push_back(Ok(Some(DiscoveryItem::Record(record(18, 0, false)))));
        coordinator.service(&mut io).unwrap();

        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 2,
                confirmed: 1,
                partial: 1,
                unavailable: 0,
            }
        );
        assert_eq!(coordinator.status(), PauseStatus::Partial);
    }

    /// Consecutive engine-incomplete cycles must retire with a counted
    /// named gap, never spin unbounded (one per loader hit). Four straight
    /// incompletes retire the chain; the four partials stay counted.
    #[test]
    fn consecutive_engine_incomplete_cycles_retire_with_a_counted_gap() {
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.arm_for_test();
        let mut io = successful_io(vec![record(10, 0, false)]);
        io.required_complete = false;
        io.apply_outcome_diagnostic = Some(PauseDiagnostic::EngineIncompleteWithinDeadline);

        coordinator.service(&mut io).unwrap();
        assert_eq!(coordinator.counters().partial, 1);
        assert!(
            coordinator.rearming_enabled(),
            "the first incomplete re-arms"
        );

        for (cycle, ts, fallback) in [(2u64, 18u64, 15u64), (3, 26, 23), (4, 34, 31)] {
            io.fallback_now = fallback;
            assert_eq!(
                coordinator.arm(&mut io).unwrap(),
                ArmResult::Armed,
                "cycle {cycle} arms"
            );
            io.authorization = Some(PAUSE_REQUESTED);
            io.queue
                .push_back(Ok(Some(DiscoveryItem::Record(record(ts, 0, false)))));
            io.queue.push_back(Ok(None));
            io.queue.push_back(Ok(None));
            coordinator.service(&mut io).unwrap();
            assert_eq!(
                coordinator.counters().partial,
                cycle,
                "cycle {cycle} stays a counted partial"
            );
        }

        assert!(
            !coordinator.rearming_enabled(),
            "the fourth consecutive incomplete retires the chain"
        );
        assert_eq!(
            coordinator.counters(),
            PauseCounters {
                attempts: 4,
                confirmed: 0,
                partial: 4,
                unavailable: 0,
            }
        );
        assert_eq!(
            coordinator.engine_incomplete_retirements(),
            1,
            "the retirement is counted for the JSON report"
        );
        assert_eq!(
            coordinator.diagnostic_emit_counts,
            BTreeMap::from([(PauseDiagnostic::EngineIncompleteWithinDeadline, 4)]),
            "one stderr line per kind, counted across the streak"
        );
        assert_eq!(
            coordinator.arm(&mut io).unwrap(),
            ArmResult::Disabled,
            "a retired chain stays terminal"
        );
    }

    /// A sticky unowned EngineIncomplete must not re-arm a later
    /// non-lifecycle failure with a different cause.
    #[test]
    fn an_unowned_engine_incomplete_must_not_rearm_a_later_non_lifecycle_failure() {
        let mut io = FakeIo {
            apply_outcome_diagnostic: Some(PauseDiagnostic::EngineIncompleteWithinDeadline),
            ..FakeIo::default()
        };
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.begin_attempt();
        coordinator.pending_records.push(record(1, 0, false));
        coordinator.apply_unowned(&mut io, Some(100)).unwrap();
        assert_eq!(
            coordinator.pending_diagnostic,
            Some(PauseDiagnostic::EngineIncompleteWithinDeadline),
            "the unowned apply sets the sticky diagnostic"
        );

        coordinator
            .fail_cycle(&mut io, "pause request had no discovery record", false)
            .unwrap();

        assert!(
            !coordinator.rearming_enabled(),
            "a different non-lifecycle cause must not re-arm"
        );
        assert_eq!(coordinator.counters().partial, 1);
    }

    /// `--pause always` never re-arms, even with a typed
    /// EngineIncomplete cause.
    #[test]
    fn engine_incomplete_under_always_does_not_rearm() {
        let mut io = FakeIo::default();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Always, 41, 9, stopped());
        coordinator.begin_attempt();

        let error = coordinator
            .fail_cycle_inner(
                &mut io,
                "one or more frozen required attachments failed",
                false,
                true,
            )
            .unwrap_err();

        assert!(error.required());
        assert!(!coordinator.rearming_enabled(), "Always must not re-arm");
    }

    /// Lifecycle failures never re-arm, even with a typed
    /// EngineIncomplete cause.
    #[test]
    fn engine_incomplete_with_a_lifecycle_failure_does_not_rearm() {
        let mut io = FakeIo::default();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.begin_attempt();

        let _ = coordinator
            .fail_cycle_inner(&mut io, "pause coordination cancelled", true, true)
            .unwrap_err();

        assert!(
            !coordinator.rearming_enabled(),
            "a lifecycle failure must not re-arm"
        );
    }

    /// A non-incomplete failure breaks the incomplete streak, so
    /// "consecutive" stays literal: sparse incompletes never retire the
    /// chain early.
    #[test]
    fn non_incomplete_failure_resets_the_incomplete_streak() {
        let mut io = FakeIo::default();
        let mut coordinator = PauseCoordinator::for_test(PausePolicy::Auto, 41, 9, stopped());
        coordinator.begin_attempt();
        coordinator.consecutive_engine_incomplete = 2;

        coordinator
            .fail_cycle(&mut io, "pause request had no discovery record", false)
            .unwrap();

        assert_eq!(coordinator.consecutive_engine_incomplete, 0);
        assert_eq!(coordinator.counters().partial, 1);
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
                unavailable: 0,
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
                unavailable: 0,
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
                unavailable: 0,
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
                unavailable: 0,
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
        assert_eq!(
            io.events,
            ["dequeue", "account", "read", "remove", "detach"]
        );
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
            apply.unwrap() < remove.unwrap()
                && remove.unwrap() < resume.unwrap()
                && resume.unwrap() < detach.unwrap()
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
    fn malformed_requested_cleanup_drains_removes_protectively_resumes_and_detaches() {
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
                "dequeue", "dequeue", "account", "read", "remove", "resume", "detach"
            ],
            "cleanup must retain failures without short-circuiting before resume"
        );
        assert!(!coordinator.cleaned);
        io.fail_detach = false;
        io.fail_remove = false;
        // G4: the failed cleanup discovered the unserviced stop (REQUESTED
        // opened the owner), so the successful retry still closes it
        // unconfirmed — `always` refuses — instead of reporting success.
        let retry = coordinator.cleanup(&mut io).unwrap_err();
        assert!(
            retry.required(),
            "the retry refuses the unserviced stop: {retry}"
        );
        assert!(!retry.lifecycle(), "{retry}");
        assert_eq!(
            io.events.iter().filter(|event| **event == "resume").count(),
            1,
            "the full retry must not resume twice"
        );
        assert!(coordinator.cleaned);
    }

    /// F-25: the capture can end (operator stop, `--duration`) after the
    /// kernel consumed an arm and before the capture tick that would have
    /// serviced it. The helper's SIGSTOP still holds the child, so terminal
    /// cleanup resumes it — and the owner that cleanup opens never confirmed,
    /// so it must close like every other unconfirmed owner: `auto` counts it
    /// partial, `always` refuses. It is never rendered as a confirmed stop.
    #[test]
    fn an_unserviced_stop_at_shutdown_is_resumed_and_never_reported_confirmed() {
        for policy in [PausePolicy::Auto, PausePolicy::Always] {
            let mut io = FakeIo {
                queue: VecDeque::from([
                    Ok(Some(DiscoveryItem::Record(record(10, 0, false)))),
                    Ok(None),
                ]),
                authorization: Some(PAUSE_REQUESTED),
                ..FakeIo::default()
            };
            let mut coordinator = PauseCoordinator::for_test(policy, 41, 9, stopped());
            coordinator.arm_for_test();

            let result = coordinator.cleanup(&mut io);

            assert_eq!(
                io.events,
                [
                    "dequeue", "dequeue", "account", "read", "remove", "resume", "detach"
                ],
                "{policy:?}: the held child is resumed once, after removal"
            );
            assert_eq!(io.authorization, None, "{policy:?}");
            assert_eq!(coordinator.counters().confirmed, 0, "{policy:?}");
            match policy {
                PausePolicy::Auto => {
                    result.expect("an auto owner that never confirmed is a partial attempt");
                    assert_eq!(coordinator.counters(), PauseCounters::partial(1));
                    assert_eq!(coordinator.status(), PauseStatus::Partial);
                }
                PausePolicy::Always => {
                    let error = result.expect_err("always never reports an unconfirmed stop");
                    assert!(error.required(), "{error}");
                    assert!(!error.lifecycle(), "{error}");
                    assert_eq!(
                        error.to_string(),
                        format!("{MSG_UNSERVICED_AT_CLEANUP} [pause_diag=other_auto_nonconfirmed]")
                    );
                }
                PausePolicy::Never => unreachable!(),
            }
        }
    }

    /// G4 (latent): the unserviced-stop classification survives a failed
    /// cleanup. The first cleanup opens the attempt (unserviced stop
    /// discovered) but fails on a detach error; the retry succeeds. The
    /// successful cleanup must still close the owner unconfirmed — `auto`
    /// counts it partial with its diagnostic, `always` refuses — instead of
    /// losing the classification to the attempt-open transition.
    #[test]
    fn a_failed_cleanup_retry_keeps_the_unserviced_stop_classification() {
        for policy in [PausePolicy::Auto, PausePolicy::Always] {
            let mut io = FakeIo {
                queue: VecDeque::from([
                    Ok(Some(DiscoveryItem::Record(record(10, 0, false)))),
                    Ok(None),
                ]),
                authorization: Some(PAUSE_REQUESTED),
                fail_detach: true,
                ..FakeIo::default()
            };
            let mut coordinator = PauseCoordinator::for_test(policy, 41, 9, stopped());
            coordinator.arm_for_test();

            let first = coordinator.cleanup(&mut io).unwrap_err();
            assert!(
                first.lifecycle(),
                "{policy:?}: the detach failure is lifecycle"
            );
            assert_eq!(
                coordinator.counters().attempts,
                1,
                "{policy:?}: the failed cleanup opened the owner"
            );
            assert!(!coordinator.cleaned, "{policy:?}");

            io.fail_detach = false;
            let result = coordinator.cleanup(&mut io);

            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                1,
                "{policy:?}: the retry must not resume twice"
            );
            assert!(coordinator.cleaned, "{policy:?}");
            assert_eq!(coordinator.counters().confirmed, 0, "{policy:?}");
            match policy {
                PausePolicy::Auto => {
                    result.expect("an auto owner that never confirmed is a partial attempt");
                    assert_eq!(coordinator.counters(), PauseCounters::partial(1));
                    assert_eq!(coordinator.status(), PauseStatus::Partial);
                }
                PausePolicy::Always => {
                    let error = result.expect_err("always never reports an unconfirmed stop");
                    assert!(error.required(), "{error}");
                    assert!(!error.lifecycle(), "{error}");
                    assert_eq!(
                        error.to_string(),
                        format!("{MSG_UNSERVICED_AT_CLEANUP} [pause_diag=other_auto_nonconfirmed]")
                    );
                }
                PausePolicy::Never => unreachable!(),
            }
        }
    }

    /// The same unserviced owner when the kernel consumes the arm between
    /// cleanup's authorization read (ARMED, no owner yet) and its removal
    /// (which returns REQUESTED). The removal opens the owner. Cleanup still
    /// resumes the child once, and the owner closes unconfirmed.
    #[test]
    fn a_stop_consumed_between_the_cleanup_read_and_its_removal_is_reported() {
        for policy in [PausePolicy::Auto, PausePolicy::Always] {
            let mut io = FakeIo {
                authorization: Some(PAUSE_REQUESTED),
                authorization_results: VecDeque::from([Ok(Some(PAUSE_ARMED))]),
                ..FakeIo::default()
            };
            let mut coordinator = PauseCoordinator::for_test(policy, 41, 9, stopped());
            coordinator.arm_for_test();

            let result = coordinator.cleanup(&mut io);

            assert_eq!(
                io.events,
                ["dequeue", "account", "read", "remove", "resume", "detach"],
                "{policy:?}: the removal's REQUESTED still earns one resume"
            );
            assert_eq!(io.authorization, None, "{policy:?}");
            assert_eq!(coordinator.counters().attempts, 1, "{policy:?}");
            assert_eq!(coordinator.counters().confirmed, 0, "{policy:?}");
            match policy {
                PausePolicy::Auto => {
                    result.expect("an auto owner opened by the removal is partial");
                    assert_eq!(coordinator.counters(), PauseCounters::partial(1));
                }
                PausePolicy::Always => {
                    let error = result.expect_err("always never reports an unconfirmed stop");
                    assert!(error.required() && !error.lifecycle(), "{error}");
                }
                PausePolicy::Never => unreachable!(),
            }
        }
    }

    /// A confirmed cycle installs its one successor, the kernel consumes the
    /// successor, and the capture ends before any tick services it. The
    /// first owner stays confirmed. The successor's owner, opened by cleanup,
    /// closes unconfirmed after cleanup's one protective resume. `auto` ends
    /// `{attempts 2, confirmed 1, partial 1}`; `always` refuses.
    #[test]
    fn a_successor_consumed_after_a_confirmed_cycle_is_reported_at_shutdown() {
        for policy in [PausePolicy::Auto, PausePolicy::Always] {
            let mut io = successful_io(vec![record(10, 0, false)]);
            let mut coordinator = PauseCoordinator::for_test(policy, 41, 9, stopped());
            coordinator.arm_for_test();
            coordinator.service(&mut io).unwrap();
            assert!(coordinator.is_armed(), "{policy:?}: the successor is armed");
            assert_eq!(io.authorization, Some(PAUSE_ARMED), "{policy:?}");
            assert_eq!(coordinator.counters(), PauseCounters::confirmed(1));

            io.authorization = Some(PAUSE_REQUESTED);
            let successor = record(io.fallback_now, 0, false);
            io.queue
                .extend([Ok(Some(DiscoveryItem::Record(successor))), Ok(None)]);
            let result = coordinator.cleanup(&mut io);

            assert_eq!(
                io.events.iter().filter(|event| **event == "resume").count(),
                2,
                "{policy:?}: the cycle's resume, then cleanup's protective resume"
            );
            assert_eq!(io.authorization, None, "{policy:?}");
            match policy {
                PausePolicy::Auto => {
                    result.expect("the unserviced successor is an auto partial");
                    assert_eq!(
                        coordinator.counters(),
                        PauseCounters {
                            attempts: 2,
                            confirmed: 1,
                            partial: 1,
                            unavailable: 0,
                        }
                    );
                    assert_eq!(coordinator.status(), PauseStatus::Partial);
                }
                PausePolicy::Always => {
                    let error = result.expect_err("always never reports an unconfirmed stop");
                    assert!(error.required() && !error.lifecycle(), "{error}");
                    assert_eq!(
                        coordinator.counters(),
                        PauseCounters {
                            attempts: 2,
                            confirmed: 1,
                            partial: 0,
                            unavailable: 0,
                        }
                    );
                }
                PausePolicy::Never => unreachable!(),
            }
        }
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
                unavailable: 0,
            },
            PauseCounters {
                attempts: 1,
                confirmed: 0,
                partial: 0,
                unavailable: 1,
            },
        ] {
            assert_eq!(
                counters.confirmed + counters.partial + counters.unavailable,
                counters.attempts
            );
            assert_eq!(
                counters.status(),
                match (counters.attempts, counters.partial, counters.unavailable) {
                    (0, _, _) => PauseStatus::None,
                    (_, 0, 0) => PauseStatus::Sigstop,
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
    fn incomplete_retirement_renders_once_with_a_count() {
        assert_eq!(
            render_pause_incomplete_retirement(4),
            "p11scope: pause: partial [pause_diag=engine_incomplete_within_deadline] \
             (retired after 4 consecutive incomplete cycles)"
        );
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

    fn exec_record_for(pid: u32) -> DiscoveryRecord {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.kind = DISCOVERY_KIND_EXEC;
        record.pid_tgid = u64::from(pid) << 32;
        record.hook_ts_ns = u64::MAX;
        record
    }

    /// One retiring harness: a live child, its retiring engine and owner,
    /// and a session authorizing loader records with the terminal export.
    fn pause_credit_harness() -> (OwnedChild, Engine, LoaderContextId, ScriptedSession) {
        let child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        let (engine, owner) = Engine::retiring_loader_context(child.pid());
        let mut session = ScriptedSession::with_records([], 16);
        session.detach_exports = vec![terminal_export()];
        (child, engine, owner, session)
    }

    /// H5 storage: pause and terminal-return batches use the same shared
    /// credits. The real adapter dequeues owned records (malformed counted
    /// beside them), applies a nonempty paused batch to completion with
    /// and without a deadline, returns an error prefix with its original
    /// owner/exports/timestamps, restores it move-only and dispatches
    /// every record exactly once. One predispatch retry survives with the
    /// same batch; owned pending moves with it. At full occupancy the
    /// dequeue guard and the nested budget refuse with typed
    /// capacity-blocked — never empty — while staged transfers still move.
    /// Child cleanup keeps the retained batch owned until its honest
    /// disposal. Work charges are observed exactly through the ceiling.
    #[test]
    fn pressure_credits_survive_pause_and_terminal_handoff() {
        const WORK_CEILING: u64 = 16 * 1024 * 1024;

        // Successful nonempty paused apply, no deadline: three loader
        // records plus one malformed dequeued through the real adapter,
        // applied, retired and dispatched exactly once.
        let (child, mut engine, owner, mut session) = pause_credit_harness();
        for (hook, malformed) in [(11u64, false), (0, true), (22, false), (33, false)] {
            if malformed {
                session
                    .dequeues
                    .push_back(Ok(Some(DiscoveryItem::Malformed)));
            } else {
                let mut record = loader_record_for(owner, child.pid());
                record.hook_ts_ns = hook;
                session
                    .dequeues
                    .push_back(Ok(Some(DiscoveryItem::Record(record))));
            }
        }
        let (records, malformed) = with_session_io(&mut engine, &mut session, &child, |io| {
            let mut records = Vec::new();
            while let Some(item) = io.dequeue().expect("room to dequeue") {
                if let DiscoveryItem::Record(record) = item {
                    records.push(record);
                }
            }
            (records, io.malformed)
        });
        assert_eq!(records.len(), 3);
        assert_eq!(malformed, 1, "dequeue counts malformed beside records");
        let mut terminal_batch = None;
        let outcome = with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(records, None, true, true, &mut terminal_batch)
                .expect("a clean paused apply succeeds")
        });
        // The malformed item honestly withholds required-complete: the
        // batch applied and retired, but one unit was never validated.
        assert!(!outcome.required_complete);
        assert_eq!(engine.dispatched_loader_records(), 3);
        assert!(terminal_batch.is_none());
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
        assert_eq!(engine.discovery_held_len(), 0);
        assert_eq!(engine.unvalidated_discovery_for_test(), 0);

        // The same apply with a deadline installs it into the budget.
        let (child, mut engine, owner, mut session) = pause_credit_harness();
        let mut terminal_batch = None;
        let outcome = with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(
                vec![loader_record_for(owner, child.pid())],
                Some(u64::MAX),
                true,
                true,
                &mut terminal_batch,
            )
            .expect("a deadline apply succeeds")
        });
        // A single loader hit needs revalidation: incomplete is routine
        // pause cycling, not failure — the record still dispatched.
        assert!(!outcome.required_complete);
        assert_eq!(engine.dispatched_loader_records(), 1);
        assert_eq!(engine.installed_budget_deadline_for_test(), Some(u64::MAX));

        // Pure renewals complete: nothing pending, nothing to revalidate.
        let (child, mut engine, _owner, mut session) = pause_credit_harness();
        let mut terminal_batch = None;
        let outcome = with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(
                vec![exec_record_for(5_000_001), exec_record_for(5_000_002)],
                None,
                true,
                true,
                &mut terminal_batch,
            )
            .expect("a renewal apply succeeds")
        });
        assert!(outcome.required_complete);
        assert_eq!(engine.discovery_held_len(), 0);

        // Error prefix round trip: two records plus a ring failure retain
        // with original authority; the restored batch completes and every
        // record dispatches exactly once — no clone, no replay.
        let (child, mut engine, owner, mut session) = pause_credit_harness();
        for hook in [11u64, 22] {
            let mut record = loader_record_for(owner, child.pid());
            record.hook_ts_ns = hook;
            session
                .dequeues
                .push_back(Ok(Some(DiscoveryItem::Record(record))));
        }
        session
            .dequeues
            .push_back(Err(anyhow::anyhow!("scripted ring read failed")));
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("a failed terminal drain is loss, never a batch error")
        });
        let batch = terminal_batch.as_ref().expect("prefix retained");
        assert_eq!((batch.record_count(), batch.complete()), (2, false));
        assert_eq!(batch.authority.owner, owner);
        assert_eq!(batch.authority.exports, [terminal_export()]);
        assert_eq!(batch.tagged_owners(), [Some(owner), Some(owner)]);
        assert_eq!(
            batch.record_hook_stamps_for_test(),
            [11, 22],
            "original timing brackets survive"
        );
        assert_eq!(
            engine.terminal_journal_for_test(),
            Some((owner, false, false))
        );
        assert_eq!(engine.dispatched_loader_records(), 0);
        assert_eq!(
            engine.discovery_held_len(),
            0,
            "the engine released the prefix to its single coordinator owner"
        );
        let mut record = loader_record_for(owner, child.pid());
        record.hook_ts_ns = 33;
        session
            .dequeues
            .push_back(Ok(Some(DiscoveryItem::Record(record))));
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("the restored batch completes")
        });
        assert!(terminal_batch.is_none(), "the batch moved exactly once");
        assert_eq!(
            engine.dispatched_loader_records(),
            3,
            "two retained plus one fresh dispatch exactly once"
        );
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
        assert_eq!(engine.discovery_held_len(), 0);

        // Predispatch retry: the first failure keeps the same batch and
        // owes exactly one retry; owned pending moves with the recovery.
        let (child, mut engine, owner, mut session) = pause_credit_harness();
        for hook in [11u64, 22] {
            let mut record = loader_record_for(owner, child.pid());
            record.hook_ts_ns = hook;
            session
                .dequeues
                .push_back(Ok(Some(DiscoveryItem::Record(record))));
        }
        session
            .dequeues
            .push_back(Err(anyhow::anyhow!("scripted ring read failed")));
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("the prefix retains")
        });
        assert!(terminal_batch.is_some());
        session.fail_counter_reads([true]);
        let regain = vec![exec_record_for(5_000_001), exec_record_for(5_000_002)];
        let error = with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(regain, None, true, false, &mut terminal_batch)
                .expect_err("the failed predispatch errors")
        });
        assert!(
            error.message.contains("batch application failed"),
            "unexpected error: {}",
            error.message
        );
        assert_eq!(
            engine.terminal_journal_for_test(),
            Some((owner, false, true)),
            "exactly one retry is owed"
        );
        let batch = terminal_batch.as_ref().expect("same batch returned");
        // The refused ordinary records joined the install: they ride the
        // retry inside the batch, untagged, behind the retained prefix.
        assert_eq!((batch.record_count(), batch.complete()), (4, false));
        assert_eq!(batch.authority.owner, owner);
        assert_eq!(
            batch.tagged_owners(),
            [Some(owner), Some(owner), None, None]
        );
        assert_eq!(
            engine.discovery_held_len(),
            0,
            "install moved every record into the single returned batch"
        );
        let mut record = loader_record_for(owner, child.pid());
        record.hook_ts_ns = 33;
        session
            .dequeues
            .push_back(Ok(Some(DiscoveryItem::Record(record))));
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("the retry completes")
        });
        assert!(terminal_batch.is_none());
        assert_eq!(engine.dispatched_loader_records(), 3);
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(
            engine.discovery_held_len(),
            0,
            "pending and batch both settled"
        );
        assert_eq!(engine.unvalidated_discovery_for_test(), 0);

        // Owned pending moves: an ordinary apply refused by predispatch
        // parks its records in pending, and the recovery dispatches them.
        let (child, mut engine, _owner, mut session) = pause_credit_harness();
        session.fail_counter_reads([true]);
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(
                vec![exec_record_for(5_000_001), exec_record_for(5_000_002)],
                None,
                true,
                false,
                &mut terminal_batch,
            )
            .expect_err("the failed predispatch errors")
        });
        assert_eq!(
            engine.discovery_held_len(),
            2,
            "refused records park owned in pending"
        );
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("the recovery dispatches pending")
        });
        assert_eq!(engine.discovery_held_len(), 0);
        assert_eq!(engine.unvalidated_discovery_for_test(), 0);

        // Dequeue guard: staged pops are transfers and always proceed, but
        // a ring read at full occupancy is an explicit capacity block.
        let (child, mut engine, owner, mut session) = pause_credit_harness();
        session.dequeues.extend((0..3_996).map(|_| {
            Ok(Some(DiscoveryItem::Record(loader_record_for(
                owner,
                child.pid(),
            ))))
        }));
        session
            .dequeues
            .push_back(Err(anyhow::anyhow!("scripted ring read failed")));
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("the prefix retains")
        });
        let batch = terminal_batch.as_ref().expect("prefix retained");
        assert_eq!(batch.record_count(), 3_996);
        // Install the batch into the engine so it counts as held while
        // staging fills the last 100 credits; staged pops then transfer
        // in order.
        engine
            .install_terminal_batch(terminal_batch.take().expect("prefix retained"), Vec::new())
            .expect("the pending journal accepts its batch");
        assert_eq!(engine.discovery_held_len(), 3_996);
        session.dequeues.extend((0..100u32).map(|index| {
            Ok(Some(DiscoveryItem::Record(exec_record_for(
                5_000_000 + index,
            ))))
        }));
        session.dequeues.extend((0..4u32).map(|index| {
            Ok(Some(DiscoveryItem::Record(exec_record_for(
                6_000_000 + index,
            ))))
        }));
        let staged = session
            .stage_discovery(100, engine.discovery_held_len())
            .unwrap();
        assert_eq!((staged.staged, staged.capacity_blocked), (100, false));
        let pids = with_session_io(&mut engine, &mut session, &child, |io| {
            let mut pids = Vec::new();
            for _ in 0..100 {
                match io.dequeue().expect("staged transfers proceed") {
                    Some(DiscoveryItem::Record(record)) => {
                        pids.push((record.pid_tgid >> 32) as u32)
                    }
                    _other => panic!("expected a staged record"),
                }
            }
            pids
        });
        assert_eq!(pids, (5_000_000..5_000_100).collect::<Vec<_>>());
        assert_eq!(session.staged_discovery_len(), 0);
        // The transfers freed room: the next dequeue reads fresh.
        let fresh = with_session_io(&mut engine, &mut session, &child, |io| {
            io.dequeue().expect("freed room reads fresh")
        });
        assert!(matches!(
            fresh,
            Some(DiscoveryItem::Record(record)) if (record.pid_tgid >> 32) as u32 == 6_000_000
        ));

        // Full occupancy blocks the ring read with a typed refusal.
        let (child, mut engine, owner, mut session) = pause_credit_harness();
        session.dequeues.extend((0..DISCOVERY_HELD_CAP).map(|_| {
            Ok(Some(DiscoveryItem::Record(loader_record_for(
                owner,
                child.pid(),
            ))))
        }));
        session
            .dequeues
            .push_back(Err(anyhow::anyhow!("scripted ring read failed")));
        session.dequeues.extend((0..8u32).map(|index| {
            Ok(Some(DiscoveryItem::Record(exec_record_for(
                6_000_000 + index,
            ))))
        }));
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("the prefix retains")
        });
        engine
            .install_terminal_batch(terminal_batch.take().expect("prefix retained"), Vec::new())
            .expect("the pending journal accepts its batch");
        assert_eq!(engine.discovery_held_len(), DISCOVERY_HELD_CAP);
        assert_eq!(session.staged_discovery_len(), 0);
        let spare_before = session.dequeues.len();
        // The budget stopped the retain at 4,096 before the scripted
        // error: the error plus eight spare records stay queued.
        assert_eq!(spare_before, 9);
        let blocked = with_session_io(&mut engine, &mut session, &child, |io| {
            io.dequeue().err().expect("full occupancy blocks")
        });
        assert!(
            blocked.contains("shared storage allowance"),
            "unexpected refusal: {blocked}"
        );
        assert_eq!(
            session.dequeues.len(),
            spare_before,
            "a blocked dequeue never reads"
        );

        // Nested budget mechanics: staged pops transfer free, ring reads
        // consume, and the stop carries its exact prefix.
        let (child, _engine, _owner, mut session) = pause_credit_harness();
        session.dequeues.extend((0..5u32).map(|index| {
            Ok(Some(DiscoveryItem::Record(exec_record_for(
                5_000_000 + index,
            ))))
        }));
        session.stage_discovery(5, 0).expect("room to stage");
        session.dequeues.extend((0..4u32).map(|index| {
            Ok(Some(DiscoveryItem::Record(exec_record_for(
                6_000_000 + index,
            ))))
        }));
        let mut stop_seen = false;
        let stopped = collect_timed_retirement(
            &mut session,
            &child,
            None,
            &mut stop_seen,
            false,
            &std::cell::Cell::new(false),
            &std::cell::Cell::new(0),
        )
        .err()
        .expect("zero budget stops");
        let stopped = stopped
            .downcast::<IncompleteTerminalDrain>()
            .expect("typed capacity stop");
        assert!(stopped.capacity_blocked && !stopped.backlog);
        assert_eq!(stopped.records.len(), 5, "staged transfers move free");
        assert_eq!(session.staged_discovery_len(), 0);
        assert_eq!(session.dequeues.len(), 4, "no ring read past the stop");
        let spare = collect_timed_retirement(
            &mut session,
            &child,
            None,
            &mut stop_seen,
            false,
            &std::cell::Cell::new(false),
            &std::cell::Cell::new(3),
        )
        .err()
        .expect("three units of room stop at the fourth");
        // The spare EXEC pids never name the child, so no stop is seen.
        assert!(!stop_seen);
        let spare = spare
            .downcast::<IncompleteTerminalDrain>()
            .expect("typed capacity stop");
        assert!(spare.capacity_blocked && !spare.backlog);
        assert_eq!((spare.records.len(), spare.malformed), (3, 0));
        assert_eq!(session.dequeues.len(), 1);

        // Exact pause charges: records plus malformed once, never replayed.
        let (child, mut engine, owner, mut session) = pause_credit_harness();
        assert!(engine.budget_charge_for_test(WORK_CEILING - 4));
        for (hook, malformed) in [(11u64, false), (0, true), (22, false), (33, false)] {
            if malformed {
                session
                    .dequeues
                    .push_back(Ok(Some(DiscoveryItem::Malformed)));
            } else {
                let mut record = loader_record_for(owner, child.pid());
                record.hook_ts_ns = hook;
                session
                    .dequeues
                    .push_back(Ok(Some(DiscoveryItem::Record(record))));
            }
        }
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            let mut records = Vec::new();
            while let Some(item) = io.dequeue().expect("room to dequeue") {
                if let DiscoveryItem::Record(record) = item {
                    records.push(record);
                }
            }
            io.apply_batch(records, None, true, true, &mut terminal_batch)
                .expect("the charged apply succeeds")
        });
        assert!(
            !engine.budget_charge_for_test(1),
            "three records plus one malformed consumed exactly four units"
        );

        // Child cleanup keeps the retained batch owned until honest
        // disposal: exact records out, nothing left behind.
        let (child, mut engine, owner, mut session) = pause_credit_harness();
        for hook in [11u64, 22] {
            let mut record = loader_record_for(owner, child.pid());
            record.hook_ts_ns = hook;
            session
                .dequeues
                .push_back(Ok(Some(DiscoveryItem::Record(record))));
        }
        session
            .dequeues
            .push_back(Err(anyhow::anyhow!("scripted ring read failed")));
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("the prefix retains")
        });
        let batch = terminal_batch.as_ref().expect("prefix retained");
        assert_eq!((batch.record_count(), batch.complete()), (2, false));
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.detach_pause_links().expect("child link cleanup runs");
            io.cleanup_terminal_batch_without_replay(&mut terminal_batch)
                .expect("honest disposal succeeds")
        });
        assert!(terminal_batch.is_none(), "the batch moved out exactly once");
        assert_eq!(engine.terminal_journal_for_test(), None);
        assert_eq!(engine.loader_context_state_for_test(owner), None);
        assert_eq!(engine.discovery_held_len(), 0);
        assert_eq!(
            engine.dispatched_loader_records(),
            0,
            "disposed, never replayed"
        );
    }

    /// H5 transfer seam: a coordinator-held terminal batch still owns its
    /// records while the retry reconciles, so the nested pull budget seeds
    /// against it. At full occupancy the retry reads nothing fresh: the
    /// batch stays retained and the ring stays queued for a later turn.
    #[test]
    fn coordinator_held_terminal_batch_counts_against_nested_pull_budget() {
        // Retain a full-capacity prefix into the coordinator-held batch,
        // then install it so the engine holds full occupancy.
        let (child, mut engine, owner, mut session) = pause_credit_harness();
        session.dequeues.extend((0..DISCOVERY_HELD_CAP).map(|_| {
            Ok(Some(DiscoveryItem::Record(loader_record_for(
                owner,
                child.pid(),
            ))))
        }));
        session
            .dequeues
            .push_back(Err(anyhow::anyhow!("scripted ring read failed")));
        session.dequeues.extend((0..8u32).map(|index| {
            Ok(Some(DiscoveryItem::Record(exec_record_for(
                6_000_000 + index,
            ))))
        }));
        let mut terminal_batch = None;
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect("the prefix retains")
        });
        assert_eq!(
            terminal_batch
                .as_ref()
                .expect("prefix retained")
                .record_count(),
            DISCOVERY_HELD_CAP
        );
        engine
            .install_terminal_batch(terminal_batch.take().expect("prefix retained"), Vec::new())
            .expect("the pending journal accepts its batch");
        assert_eq!(engine.discovery_held_len(), DISCOVERY_HELD_CAP);
        // The retry's ring reads would succeed: drop the scripted error so
        // only the shared allowance stands between the drain and the spares.
        assert!(
            session
                .dequeues
                .pop_front()
                .expect("scripted error queued")
                .is_err()
        );
        assert_eq!(session.dequeues.len(), 8);
        // The retry reconciles the batch coordinator-side before seeding
        // its nested budget: at full occupancy it reads nothing fresh.
        with_session_io(&mut engine, &mut session, &child, |io| {
            io.apply_batch(Vec::new(), None, true, false, &mut terminal_batch)
                .expect_err("full occupancy refuses fresh acquisition");
        });
        assert_eq!(
            session.dequeues.len(),
            8,
            "a refused retry never reads the ring"
        );
        assert_eq!(
            engine.discovery_held_len(),
            0,
            "the refused batch returns coordinator-side"
        );
        assert_eq!(
            terminal_batch
                .as_ref()
                .expect("batch retained")
                .record_count(),
            DISCOVERY_HELD_CAP,
            "nothing acquired past the shared allowance"
        );
    }

    /// The `fn` item enclosing `offset`: the nearest preceding item start,
    /// plus whether a test attribute sits directly above it.
    fn enclosing_item(source: &str, offset: usize) -> (String, bool) {
        let lines: Vec<&str> = source[..offset].split('\n').collect();
        let mut index = lines.len();
        loop {
            assert!(index > 0, "no enclosing item for offset {offset}");
            index -= 1;
            if let Some(name) = item_name(lines[index]) {
                let test = (index.saturating_sub(6)..index)
                    .any(|above| matches!(lines[above].trim(), "#[test]" | "#[cfg(test)]"));
                return (name, test);
            }
        }
    }

    fn item_name(line: &str) -> Option<String> {
        let mut stripped = line.strip_prefix("    ").unwrap_or(line);
        stripped = stripped.strip_prefix("pub(crate) ").unwrap_or(stripped);
        stripped = stripped.strip_prefix("pub ").unwrap_or(stripped);
        for qualifier in ["const ", "async ", "unsafe "] {
            stripped = stripped.strip_prefix(qualifier).unwrap_or(stripped);
        }
        let rest = stripped.strip_prefix("fn ")?;
        let name = rest.split(['(', '<']).next()?.trim().to_string();
        (!name.is_empty()).then_some(name)
    }

    fn offsets_of(haystack: &str, needle: &str) -> Vec<usize> {
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(found) = haystack[from..].find(needle) {
            out.push(from + found);
            from += found + needle.len();
        }
        out
    }

    /// `run` frees its owned PID only after the pause authorization is gone.
    /// The `PAUSE_PIDS` entry is keyed by (tgid, generation token), both
    /// taken from the PID number, so a process reusing the number while an
    /// entry is armed would be stopped by the discovery hook. Reaping (which
    /// frees the number) therefore always follows the coordinator's terminal
    /// cleanup, which removes the authorization. This pins the funnel:
    /// `Owned::finish` requests the stop gate and cleans up before it
    /// settles, settlement has that one call site, and every other
    /// production reap precedes the first arm (setup and preflight
    /// failures return before the coordinator exists).
    /// The capture loops route every end (exit, error, signal, timeout,
    /// kill-on-timeout, second SIGINT) through that same finish; that
    /// routing is an audited property of `run.rs`, documented here:
    /// - `capture_profile`/`capture_trace` return only through
    ///   `finish_capture_error`, `finish_quiesce_error` or
    ///   `finish_capture_with`, each of which runs `Owned::finish` (cleanup
    ///   then settlement) before any reap or detach;
    /// - pre-arm failures (`combine_setup_failure`, the preflight closure)
    ///   reap before `Owned` exists, when no entry was ever armed;
    /// - `OwnedChild::drop` reaps only what that funnel left behind.
    #[test]
    fn owned_reap_follows_pause_cleanup_before_settlement() {
        let run = include_str!("../run.rs");
        let production = run
            .split_once("#[cfg(test)]\nmod tests")
            .expect("tests mod anchor")
            .0;
        // The core ordering: cleanup before settlement in the one finish.
        let finish = production
            .split_once("    fn finish(\n")
            .expect("Owned::finish")
            .1
            .split_once("\n    }\n}")
            .expect("finish end")
            .0;
        let cleanup = finish
            .find("self.coordinator.cleanup(")
            .expect("finish cleans up");
        let settle = finish.find("settle_owned_child(").expect("finish settles");
        assert!(
            cleanup < settle,
            "Owned::finish must remove the pause authorization before settling the child"
        );
        // The stop gate is requested in the same finish before
        // settlement, so the links' background move never outruns it.
        let stop = finish
            .find("stop_gate().request_stop()")
            .expect("finish requests the stop gate");
        assert!(
            stop < settle,
            "Owned::finish must request the stop gate before settling the child"
        );
        // The single funnel: settlement is defined once and called from
        // finish only (test calls live past the tests-mod anchor).
        assert_eq!(
            offsets_of(production, "settle_owned_child(").len(),
            2,
            "settle_owned_child must keep its definition plus the one finish call"
        );
        // No new direct reaps: every production terminate_and_reap call
        // stays in its audited function.
        let mut reapers = std::collections::BTreeSet::new();
        let mut preflight_reap = None;
        for offset in offsets_of(production, "terminate_and_reap(") {
            let line_start = production[..offset].rfind('\n').map_or(0, |at| at + 1);
            let line_end = production[offset..]
                .find('\n')
                .map_or(production.len(), |at| offset + at);
            if production[line_start..line_end].contains("fn terminate_and_reap") {
                continue;
            }
            let (item, test) = enclosing_item(production, offset);
            if test {
                continue;
            }
            if item == "run_owned_inner_with_host" {
                preflight_reap = Some(offset);
            }
            reapers.insert(item);
        }
        assert_eq!(
            reapers,
            std::collections::BTreeSet::from([
                "abort_pending_handoff".to_string(),
                "combine_setup_failure".to_string(),
                "run_owned_inner_with_host".to_string(),
                "settle_owned_child".to_string(),
                "wait_for".to_string(),
            ]),
            "a reap moved outside its audited function: {reapers:?}"
        );
        // The wait_for kill arm stays dead: every call passes false, and
        // production calls come only from the post-cleanup settle paths.
        for line in run.split('\n') {
            if line.contains("wait_for(") && !line.contains("fn wait_for(") {
                assert!(
                    line.contains(", false)"),
                    "wait_for must never take the kill arm: {line:?}"
                );
            }
        }
        let mut waiters = std::collections::BTreeSet::new();
        for offset in offsets_of(production, "wait_for(") {
            let line_start = production[..offset].rfind('\n').map_or(0, |at| at + 1);
            let line_end = production[offset..]
                .find('\n')
                .map_or(production.len(), |at| offset + at);
            if production[line_start..line_end].contains("fn wait_for(") {
                continue;
            }
            let (item, test) = enclosing_item(production, offset);
            assert!(!test, "production wait_for call sits in a test item");
            waiters.insert(item);
        }
        assert_eq!(
            waiters,
            std::collections::BTreeSet::from([
                "settle_after_signal_with_grace_and".to_string(),
                "stage_handoff".to_string(),
            ]),
            "wait_for must stay inside the settle paths: {waiters:?}"
        );
        // Pre-arm reaps: setup failures and the preflight closure run
        // before Owned (and its coordinator) exists, so no entry is armed.
        let owned = production
            .find("let mut owned = Owned {")
            .expect("Owned construction");
        for offset in offsets_of(production, "combine_setup_failure(") {
            assert!(
                offset < owned,
                "setup failure must precede the owned coordinator"
            );
        }
        assert!(
            preflight_reap.is_some_and(|offset| offset < owned),
            "the preflight reap must precede the owned coordinator"
        );
    }

    /// SoftHSM2 provider layouts across hosts (Debian multiarch, the
    /// `/usr/lib` layout of the vng guests, Fedora `/usr/lib64`). The first
    /// present one wins; the run fails loudly when none is installed.
    fn wrapper_softhsm_lib() -> &'static str {
        const CANDIDATES: &[&str] = &[
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib64/pkcs11/libsofthsm2.so",
        ];
        CANDIDATES
            .iter()
            .copied()
            .find(|path| std::path::Path::new(path).is_file())
            .expect("a SoftHSM2 provider must be installed for the wrapper cells")
    }

    /// A fresh SoftHSM token for one cell. Each cell owns its token directory,
    /// so cells never share token state even when run back to back.
    fn wrapper_token(dir: &std::path::Path) -> std::path::PathBuf {
        let tokens = dir.join("tokens");
        std::fs::create_dir_all(&tokens).expect("token dir");
        let conf = dir.join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                tokens.display()
            ),
        )
        .expect("token conf");
        let output = std::process::Command::new("/usr/bin/softhsm2-util")
            .env("SOFTHSM2_CONF", &conf)
            .args([
                "--init-token",
                "--free",
                "--label",
                "pausewrap",
                "--so-pin",
                "5678",
                "--pin",
                "1234",
            ])
            .output()
            .expect("spawn softhsm2-util");
        assert!(
            output.status.success(),
            "token init: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        wrapper_chown_invoker(dir);
        conf
    }

    /// Root-created token state is unusable to the owned child, which runs as
    /// the sudo invoker. Hand the cell dir to that account. Without sudo (or
    /// unprivileged) there is nothing to hand over, and the run itself refuses
    /// loudly below.
    fn wrapper_chown_invoker(dir: &std::path::Path) {
        let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) else {
            return;
        };
        // SAFETY: reading the effective uid has no preconditions.
        if uid == "0" || unsafe { libc::geteuid() } != 0 {
            return;
        }
        let status = std::process::Command::new("chown")
            .arg("-R")
            .arg(format!("{uid}:{gid}"))
            .arg(dir)
            .status()
            .expect("spawn chown");
        assert!(status.success(), "handing the cell dir to the invoker");
        // The campaign runner points TMPDIR at a root-only dir, which the
        // invoker-owned child cannot traverse to reach the cell dir handed
        // over above (its C_Initialize then fails on the unreadable token).
        // Grant search-only on TMPDIR itself; names stay hidden (no read
        // bit) and every higher ancestor is already traversable (the runner
        // creates OUTDIR default, a lane TMPDIR is invoker-owned).
        let tmp = std::env::temp_dir();
        let metadata = std::fs::metadata(&tmp).expect("stat campaign TMPDIR");
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o001);
        std::fs::set_permissions(&tmp, permissions).expect("search bit on campaign TMPDIR");
    }

    /// `run` passes `SOFTHSM2_CONF` through to its child environment, so
    /// the direct oracle needs it in the observer's environment. Restored on
    /// drop; privileged cells run `--exact --test-threads=1`.
    struct WrapperEnvGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl WrapperEnvGuard {
        fn set(conf: &std::path::Path) -> Self {
            let previous = std::env::var_os("SOFTHSM2_CONF");
            // SAFETY: the cell runs alone; nothing else in this process
            // touches the environment while the guard is alive.
            unsafe { std::env::set_var("SOFTHSM2_CONF", conf) };
            Self { previous }
        }
    }

    impl Drop for WrapperEnvGuard {
        fn drop(&mut self) {
            // SAFETY: as above.
            unsafe {
                match self.previous.take() {
                    Some(previous) => std::env::set_var("SOFTHSM2_CONF", previous),
                    None => std::env::remove_var("SOFTHSM2_CONF"),
                }
            }
        }
    }

    fn wrapper_work_dir(cell: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pause-wrap-{cell}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("cell dir");
        dir
    }

    fn wrapper_pkcs11_tool(module: &str) -> Vec<std::ffi::OsString> {
        vec![
            "/usr/bin/pkcs11-tool".into(),
            "--module".into(),
            module.into(),
            "-O".into(),
            "--login".into(),
            "--pin".into(),
            "1234".into(),
        ]
    }

    fn wrapper_profile(
        pause: PausePolicy,
        command: Vec<std::ffi::OsString>,
        out: &std::path::Path,
    ) -> (crate::run::OwnedRunOutcome, serde_json::Value) {
        wrapper_profile_inner(pause, command, out, Vec::new(), Vec::new())
    }

    /// The pre-armed twin: the named provider is armed before the fork,
    /// so a grandchild that loads it mid-run is hooked from its first
    /// call instead of racing discovery's admission passes.
    fn wrapper_profile_prearmed(
        pause: PausePolicy,
        command: Vec<std::ffi::OsString>,
        out: &std::path::Path,
        module: &str,
    ) -> (crate::run::OwnedRunOutcome, serde_json::Value) {
        let path = std::path::PathBuf::from(module);
        wrapper_profile_inner(pause, command, out, vec![path.clone()], vec![path])
    }

    fn wrapper_profile_inner(
        pause: PausePolicy,
        command: Vec<std::ffi::OsString>,
        out: &std::path::Path,
        modules: Vec<std::path::PathBuf>,
        prearm_modules: Vec<std::path::PathBuf>,
    ) -> (crate::run::OwnedRunOutcome, serde_json::Value) {
        let args = crate::cli::RunArgs {
            track_short_lived: false,
            verbose: false,
            quiet: false,
            kind: crate::cli::Kind::Profile,
            modules,
            exclude_modules: vec![],
            manifests: Vec::new(),
            prearm_modules,
            forwarding_modules: Vec::new(),
            hooks: crate::discovery::hooks::HookRegistry::builtin(),
            metrics: false,
            counter_mode: None,
            select_endpoint: None,
            duration: None,
            out: Some(out.to_path_buf()),
            max_events: None,
            max_scan_pids: None,
            ring_bytes: None,
            drain_interval: None,
            unsafe_requested: false,
            allow_confined_uretprobe: false,
            pause,
            attach_backend: crate::attach::BackendSelection::default(),
            kill_on_timeout: false,
            user: None,
            command,
        };
        let outcome = crate::run::run_owned(&args).expect("owned run completes");
        let text = std::fs::read_to_string(out).expect("report exists");
        let document: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        (outcome, document)
    }

    fn wrapper_total_calls(document: &serde_json::Value) -> u64 {
        document["functions"]
            .as_array()
            .expect("functions array")
            .iter()
            .map(|function| function["calls"].as_u64().expect("call count"))
            .sum()
    }

    fn assert_sigstop_lattice(evidence: &crate::render::Evidence) {
        assert_eq!(
            evidence.pause_confirmed + evidence.pause_partial,
            evidence.pause_attempts,
            "pause counters do not add up"
        );
        assert!(evidence.pause_attempts > 0, "auto attempted nothing");
        assert_eq!(evidence.pause_partial, 0, "every stop must confirm");
        assert_eq!(evidence.pause, "sigstop");
        assert_eq!(evidence.pause_confirmed, evidence.pause_attempts);
    }

    /// `run --pause auto -- env VAR=… pkcs11-tool …`: the same task execs a
    /// second image before loading the provider. The pause follows that exec
    /// chain, so the wrapper observes exactly the direct run's calls with
    /// every stop confirmed.
    #[test]
    #[ignore = "privileged: run --pause auto through env with a SoftHSM workload (root, BPF, SoftHSM, pkcs11-tool)"]
    fn privileged_pause_auto_env_wrapper_matches_direct_count_lp64() {
        let dir = wrapper_work_dir("env");
        let conf = wrapper_token(&dir);
        let _env = WrapperEnvGuard::set(&conf);
        let module = wrapper_softhsm_lib();
        let (direct, direct_doc) = wrapper_profile(
            PausePolicy::Auto,
            wrapper_pkcs11_tool(module),
            &dir.join("direct.json"),
        );
        assert_eq!(direct.child_exit_code, Some(0));
        let oracle = wrapper_total_calls(&direct_doc);
        assert!(oracle > 0, "the oracle workload must observe calls");
        assert_sigstop_lattice(&direct.evidence);
        let mut wrapped = vec![
            std::ffi::OsString::from("/usr/bin/env"),
            std::ffi::OsString::from(format!("SOFTHSM2_CONF={}", conf.display())),
        ];
        wrapped.extend(wrapper_pkcs11_tool(module));
        let (outcome, document) =
            wrapper_profile(PausePolicy::Auto, wrapped, &dir.join("wrapped.json"));
        assert_eq!(outcome.child_exit_code, Some(0));
        assert_eq!(
            wrapper_total_calls(&document),
            oracle,
            "the env wrapper must observe exactly the direct count"
        );
        assert_sigstop_lattice(&outcome.evidence);
    }

    /// `run --pause auto -- sh -c 'exec …'`: the shell replaces itself with
    /// the workload in the same task. Same oracle and lattice as the env cell.
    #[test]
    #[ignore = "privileged: run --pause auto through sh -c exec with a SoftHSM workload (root, BPF, SoftHSM, pkcs11-tool)"]
    fn privileged_pause_auto_shexec_wrapper_matches_direct_count_lp64() {
        let dir = wrapper_work_dir("shexec");
        let conf = wrapper_token(&dir);
        let _env = WrapperEnvGuard::set(&conf);
        let module = wrapper_softhsm_lib();
        let (direct, direct_doc) = wrapper_profile(
            PausePolicy::Auto,
            wrapper_pkcs11_tool(module),
            &dir.join("direct.json"),
        );
        assert_eq!(direct.child_exit_code, Some(0));
        let oracle = wrapper_total_calls(&direct_doc);
        assert!(oracle > 0, "the oracle workload must observe calls");
        assert_sigstop_lattice(&direct.evidence);
        let script = format!("exec /usr/bin/pkcs11-tool --module {module} -O --login --pin 1234");
        let wrapped = vec![
            std::ffi::OsString::from("/bin/sh"),
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(script),
        ];
        let (outcome, document) =
            wrapper_profile(PausePolicy::Auto, wrapped, &dir.join("wrapped.json"));
        assert_eq!(outcome.child_exit_code, Some(0));
        assert_eq!(
            wrapper_total_calls(&document),
            oracle,
            "the sh -c exec wrapper must observe exactly the direct count"
        );
        assert_sigstop_lattice(&outcome.evidence);
    }

    /// `run --pause auto -- sh -c '… & wait'`: the provider loads in a
    /// grandchild inside the run-tree cgroup scope, so the pause+tree
    /// follows it. The grandchild's calls land ledger-exact; the
    /// grandchild retires between admission passes, so the verdict is
    /// honestly PARTIAL with one descendant gap. The wrapped lattice is
    /// not strict sigstop: the grandchild's quick exit strands one late
    /// attempt unserviced, while every live window stays protected by a
    /// confirmed stop. The background `& wait` form forces the fork on
    /// every shell: some shells replace themselves with a lone `sh -c`
    /// command instead of forking. The trailing `exec sleep 2` settles
    /// the terminal drain: without it the grandchild's exit strands past
    /// the drain's read position on some hosts and the gap undercounts.
    #[test]
    #[ignore = "privileged: run --pause auto through a forking sh wrapper with a SoftHSM workload (root, BPF, SoftHSM, pkcs11-tool)"]
    fn privileged_pause_auto_shfork_wrapper_reports_honest_gap_lp64() {
        let dir = wrapper_work_dir("shfork");
        let conf = wrapper_token(&dir);
        let _env = WrapperEnvGuard::set(&conf);
        let module = wrapper_softhsm_lib();
        let (direct, direct_doc) = wrapper_profile_prearmed(
            PausePolicy::Auto,
            wrapper_pkcs11_tool(module),
            &dir.join("direct.json"),
            module,
        );
        assert_eq!(direct.child_exit_code, Some(0));
        let oracle = wrapper_total_calls(&direct_doc);
        assert!(oracle > 0, "the oracle proves the token can produce calls");
        assert_sigstop_lattice(&direct.evidence);
        let script = format!(
            "/usr/bin/pkcs11-tool --module {module} -O --login --pin 1234 & wait; exec sleep 2"
        );
        let wrapped = vec![
            std::ffi::OsString::from("/bin/sh"),
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(script),
        ];
        let (outcome, document) = wrapper_profile_prearmed(
            PausePolicy::Auto,
            wrapped,
            &dir.join("wrapped.json"),
            module,
        );
        assert_eq!(
            outcome.child_exit_code,
            Some(0),
            "the grandchild workload must succeed"
        );
        assert_eq!(
            wrapper_total_calls(&document),
            oracle,
            "the grandchild's calls land ledger-exact"
        );
        assert!(
            outcome.evidence.pause_attempts > 0,
            "auto attempted nothing"
        );
        assert_eq!(
            outcome.evidence.pause_confirmed + outcome.evidence.pause_partial,
            outcome.evidence.pause_attempts,
            "pause counters do not add up"
        );
        assert_eq!(
            outcome.evidence.unprotected_live_windows, 0,
            "every live window was protected by a confirmed stop"
        );
        assert_eq!(outcome.evidence.completeness, "PARTIAL");
        assert_eq!(
            outcome.evidence.pid_descendant_gaps, 1,
            "the retired grandchild is one honest gap"
        );
    }

    /// `--pause never` twin: the wrapper shape without any pause completes and
    /// publishes the neutral lattice. Call counts stay out of this cell: an
    /// unpaused child can outrun discovery under load, so exact counts are
    /// verified live, not pinned here.
    #[test]
    #[ignore = "privileged: run --pause never through env with a SoftHSM workload (root, BPF, SoftHSM, pkcs11-tool)"]
    fn privileged_pause_never_env_wrapper_publishes_neutral_lattice_lp64() {
        let dir = wrapper_work_dir("never");
        let conf = wrapper_token(&dir);
        let _env = WrapperEnvGuard::set(&conf);
        let module = wrapper_softhsm_lib();
        let (direct, _) = wrapper_profile(
            PausePolicy::Never,
            wrapper_pkcs11_tool(module),
            &dir.join("direct.json"),
        );
        assert_eq!(direct.child_exit_code, Some(0));
        assert_eq!(direct.evidence.pause, "none");
        assert_eq!(direct.evidence.pause_attempts, 0);
        let mut wrapped = vec![
            std::ffi::OsString::from("/usr/bin/env"),
            std::ffi::OsString::from(format!("SOFTHSM2_CONF={}", conf.display())),
        ];
        wrapped.extend(wrapper_pkcs11_tool(module));
        let (outcome, _) = wrapper_profile(PausePolicy::Never, wrapped, &dir.join("wrapped.json"));
        assert_eq!(outcome.child_exit_code, Some(0));
        assert_eq!(outcome.evidence.pause, "none");
        assert_eq!(outcome.evidence.pause_attempts, 0);
    }

    /// A second exec after the provider already loads: the owned task maps
    /// SoftHSM under its first image (via `LD_PRELOAD`) and then execs the
    /// workload. The exec refresh keeps the observation exact and confirmed.
    #[test]
    #[ignore = "privileged: run --pause auto through a preload-then-exec wrapper with a SoftHSM workload (root, BPF, SoftHSM, pkcs11-tool)"]
    fn privileged_pause_auto_preloaded_exec_matches_direct_count_lp64() {
        let dir = wrapper_work_dir("preload");
        let conf = wrapper_token(&dir);
        let _env = WrapperEnvGuard::set(&conf);
        let module = wrapper_softhsm_lib();
        let (direct, direct_doc) = wrapper_profile(
            PausePolicy::Auto,
            wrapper_pkcs11_tool(module),
            &dir.join("direct.json"),
        );
        assert_eq!(direct.child_exit_code, Some(0));
        let oracle = wrapper_total_calls(&direct_doc);
        assert!(oracle > 0, "the oracle workload must observe calls");
        assert_sigstop_lattice(&direct.evidence);
        let script = format!("exec /usr/bin/pkcs11-tool --module {module} -O --login --pin 1234");
        let wrapped = vec![
            std::ffi::OsString::from("/usr/bin/env"),
            std::ffi::OsString::from(format!("SOFTHSM2_CONF={}", conf.display())),
            std::ffi::OsString::from(format!("LD_PRELOAD={module}")),
            std::ffi::OsString::from("/bin/sh"),
            std::ffi::OsString::from("-c"),
            std::ffi::OsString::from(script),
        ];
        let (outcome, document) =
            wrapper_profile(PausePolicy::Auto, wrapped, &dir.join("wrapped.json"));
        assert_eq!(outcome.child_exit_code, Some(0));
        assert_eq!(
            wrapper_total_calls(&document),
            oracle,
            "the preloaded exec must observe exactly the direct count"
        );
        assert_sigstop_lattice(&outcome.evidence);
    }
}
