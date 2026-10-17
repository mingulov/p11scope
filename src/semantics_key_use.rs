//! SPDX-License-Identifier: GPL-3.0-or-later
//! H9 operation/key delivery: the single S1 feed, joint replay and
//! key-use aggregation.
//!
//! One capture-owned feed per instance/era reduces each authorized
//! call exactly once. [`FeedMode`] is selected at registration before
//! the first semantic mutation: [`FeedMode::Joint`] stages H3-admitted
//! S1 payloads and replays them through the one [`EdgeSemantics`]
//! reducer as sealed H8 calls settle; [`FeedMode::S1Only`] reduces
//! directly and never stages. An S1Only incarnation never becomes
//! Joint, and an already-reduced call is never replayed.
//!
//! Correlation is exact single-quantum: H8 conversion skips blocked
//! entries (a seal's settled set is not a prefix of staged calls),
//! and [`SealedObjectPrefix`] carries no per-call H3 identity, so a
//! seal settling anything but exactly the staged head refuses the
//! quantum loudly. Multi-call batching needs an explicit H8
//! correlation enrichment (carry); production live-loop Joint routing
//! (session-owned adapter/model plumbing) is likewise a carry — the
//! registry reduces S1Only until that wiring lands.

use crate::semantics_edge::{EdgeSemantics, EffectOrigin, OperationSink, SemanticCall};
use crate::semantics_objects::journal::{
    BootstrapReceipt, H3DispositionEvidence, H3EvidenceSource, JournalGap, SealFailure, SealSuccess,
};
use std::collections::VecDeque;

/// At most 1,024 unsettled staged payloads: the H8 pending-call bound
/// mirrored on the H9 side (one logical ticket; byte-charge
/// unification with the H8 lease awaits the production lease-staging
/// design). The N+1 admission backpressures instead of staging.
pub(crate) const JOINT_STAGING_CAPACITY: usize = 1_024;

/// Permanent per-instance/era feed selection, chosen at registration
/// before the first semantic mutation (H9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeedMode {
    /// Reduce directly; never stage, never replay, never upgrade.
    S1Only,
    /// Stage H3-admitted payloads; replay each through the one
    /// reducer as its sealed call settles.
    Joint,
}

/// Why one call was not staged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StagingRefusal {
    /// The feed is S1Only (or degraded there): fresh calls reduce
    /// directly, never stage.
    NotJoint,
    /// Staging holds [`JOINT_STAGING_CAPACITY`] unsettled payloads:
    /// backpressure — attest nothing further until seals drain it.
    Full,
    /// The position is at or below the consumed frontier (or the
    /// staged tail): replaying an already-reduced call is forbidden.
    ReplayRefused,
}

/// How one seal advanced the staging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealApplyOutcome {
    /// The seal settled exactly the staged head (function-verified,
    /// terminally bounded); it replayed once through the reducer.
    ReplayedOne,
    /// Nothing replayed: the seal settled zero calls, the head's
    /// terminal is still open, the quantum needs batching H9 does not
    /// run, or the feed already left Joint. Staging is intact.
    Held,
}

/// How one seal failure advanced the staging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureApplyOutcome {
    /// Transient refusal: staging kept, a later seal may proceed.
    /// The reducer and mode are untouched.
    Retried,
    /// Proof-only refusal with an explicit complete H3 stream: the
    /// retained calls replayed once in original order through
    /// ordinary S1, then the feed continued S1Only.
    FellBack { replayed: usize },
    /// Real loss (or H3's own loss barrier): live operation
    /// authority invalidated first, then each retained payload
    /// disposed once as history-only. The feed degraded to S1Only.
    Degraded { disposed: usize },
    /// Proof-only refusal without a complete H3 stream: journal
    /// silence (or pending work below the watermark) never triggers
    /// the fallback. Staging is intact.
    HeldForCompleteness,
    /// The feed already left Joint (fallback/degraded staging is
    /// empty): seal outcomes no longer route here. Inert by design —
    /// live S1Only machines are never touched.
    Ignored,
}

/// H9's disposition of one seal failure. Exhaustive on purpose: a new
/// [`JournalGap`] must decide here, never default silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealFailureDisposition {
    /// Real loss: fault, malformed/discarded records, H3 loss or H0
    /// exhaustion. Invalidate live authority, dispose history-only.
    HistoryLoss,
    /// Proof-only refusal: object authority ended, the H3 CALL stream
    /// itself unimplicated. Fall back iff H3 completeness is explicit.
    Fallback,
    /// Transient: H3 pending, bound not ready, or a caller-side
    /// frontier regression. Keep staging, retry on a later seal.
    Retry,
}

/// Map one seal gap to its H9 disposition.
pub(crate) fn disposition_of(gap: JournalGap) -> SealFailureDisposition {
    use JournalGap::*;
    use SealFailureDisposition::*;
    match gap {
        FaultChanged | FaultUnreadable | FaultSaturated | Malformed | H3Loss | H3Exhausted
        | Discarded => HistoryLoss,
        H3Pending | BoundNotReady | FrontierRegression => Retry,
        ModelRefused | BootstrapMismatch | ClosureStale | DomainTainted | ImageTainted
        | DomainEnded | AdapterInvalidated | Stopped | DrainMismatch | CutExhausted => Fallback,
    }
}

/// One staged H3-admitted call: its proved S1 payload, the
/// registry-supplied origin, and its H0 ordinal (replay order,
/// frontier and fallback-coverage checks).
struct StagedCall {
    facts: SemanticCall,
    origin: EffectOrigin,
    position: u64,
}

/// The Joint replay adapter (H9): the staging FIFO plus the consumed
/// frontier. The H8 adapter/model and the reducer stay owner-held;
/// each quantum borrows them.
pub(crate) struct JointStaging {
    mode: FeedMode,
    staged: VecDeque<StagedCall>,
    /// Highest consumed H0 position (replayed or disposed): staging
    /// at or below it is a forbidden replay.
    frontier: u64,
    reduced: u64,
    history_disposed: u64,
    correlation_refusals: u64,
}

impl std::fmt::Debug for JointStaging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JointStaging")
            .field("mode", &self.mode)
            .field("staged", &self.staged.len())
            .field("reduced", &self.reduced)
            .field("history_disposed", &self.history_disposed)
            .field("correlation_refusals", &self.correlation_refusals)
            .finish_non_exhaustive()
    }
}

impl JointStaging {
    /// Select S1Only at registration: no receipt, no staging, no
    /// bootstrap-wait queue. Permanent.
    pub(crate) fn select_s1_only() -> Self {
        Self {
            mode: FeedMode::S1Only,
            staged: VecDeque::new(),
            frontier: 0,
            reduced: 0,
            history_disposed: 0,
            correlation_refusals: 0,
        }
    }

    /// Select Joint at registration: only with the current H8
    /// birth/closure receipt already present. Without it, S1Only
    /// immediately — never a bootstrap-wait queue, never a later
    /// upgrade. The receipt evidences selection only; every seal
    /// still verifies birth independently.
    pub(crate) fn select_joint(receipt: Option<&BootstrapReceipt>) -> Self {
        let mut staging = Self::select_s1_only();
        if receipt.is_some() {
            staging.mode = FeedMode::Joint;
        }
        staging
    }

    pub(crate) fn mode(&self) -> FeedMode {
        self.mode
    }

    /// Calls replayed through the one reducer (seal or fallback).
    pub(crate) fn reduced(&self) -> u64 {
        self.reduced
    }

    /// Retained payloads disposed once as history-only.
    pub(crate) fn history_disposed(&self) -> u64 {
        self.history_disposed
    }

    /// Seal quanta refused for correlation (multi-call seals H9 does
    /// not batch, function mismatch, or settled-but-never-staged).
    pub(crate) fn correlation_refusals(&self) -> u64 {
        self.correlation_refusals
    }

    /// Currently staged (unsettled) payloads.
    pub(crate) fn staged_len(&self) -> usize {
        self.staged.len()
    }

    /// Stage one H3-admitted payload in admission order. Positions
    /// must strictly exceed both the consumed frontier and the staged
    /// tail: H0 tokens are unique per admission, so anything else is
    /// a forbidden replay or a caller-ordering bug.
    pub(crate) fn stage(
        &mut self,
        facts: SemanticCall,
        origin: EffectOrigin,
        position: u64,
    ) -> Result<(), StagingRefusal> {
        if self.mode != FeedMode::Joint {
            return Err(StagingRefusal::NotJoint);
        }
        if position <= self.frontier
            || self
                .staged
                .back()
                .is_some_and(|tail| position <= tail.position)
        {
            return Err(StagingRefusal::ReplayRefused);
        }
        if self.staged.len() >= JOINT_STAGING_CAPACITY {
            return Err(StagingRefusal::Full);
        }
        self.staged.push_back(StagedCall {
            facts,
            origin,
            position,
        });
        Ok(())
    }

    /// Apply one seal: replay the staged head iff the seal settled
    /// exactly its call — one settled call, function-verified against
    /// the head, terminally bounded (END cut or abandonment bound).
    /// Anything else holds staging intact. Returns the outcome plus
    /// this quantum's per-edge bound refusals (the owner folds them
    /// into `semantic_refused`, like the direct feed).
    pub(crate) fn apply_seal<S: OperationSink>(
        &mut self,
        seal: &SealSuccess,
        reducer: &mut EdgeSemantics,
        sink: &mut S,
    ) -> (SealApplyOutcome, u64) {
        if self.mode != FeedMode::Joint {
            return (SealApplyOutcome::Held, 0);
        }
        let settled = seal.prefix.settled();
        if settled.is_empty() {
            return (SealApplyOutcome::Held, 0);
        }
        if settled.len() != 1 {
            // Multi-call seals need batched correlation H9 does not
            // run (carry): refuse loudly, keep staging.
            self.correlation_refusals = self.correlation_refusals.saturating_add(1);
            return (SealApplyOutcome::Held, 0);
        }
        let Some(head) = self.staged.front() else {
            self.correlation_refusals = self.correlation_refusals.saturating_add(1);
            return (SealApplyOutcome::Held, 0);
        };
        let function_matches =
            crate::kinds::function_id(&head.facts.function) == Some(settled[0].function);
        if !function_matches {
            self.correlation_refusals = self.correlation_refusals.saturating_add(1);
            return (SealApplyOutcome::Held, 0);
        }
        if settled[0].end_cut.is_none() && !settled[0].abandoned {
            return (SealApplyOutcome::Held, 0);
        }
        let head = self.staged.pop_front().expect("head verified above");
        self.frontier = self.frontier.max(head.position);
        let refused = reducer.observe_with_effects(&head.facts, &head.origin, sink);
        self.reduced = self.reduced.saturating_add(1);
        (SealApplyOutcome::ReplayedOne, refused)
    }

    /// Apply one seal failure: real loss invalidates live operation
    /// authority before history-only disposal; proof-only refusal
    /// with an explicit complete H3 stream replays retained calls
    /// once in order through ordinary S1; anything transient or
    /// completeness-unproven holds staging intact. The H3 receipt is
    /// taken from the actual finalizer (`take_h3_disposition`),
    /// never caller-supplied. Returns the outcome plus fallback
    /// per-edge bound refusals for `semantic_refused`.
    pub(crate) fn apply_failure<S: OperationSink>(
        &mut self,
        failure: &SealFailure,
        finalizer: &mut impl H3EvidenceSource,
        reducer: &mut EdgeSemantics,
        sink: &mut S,
    ) -> (FailureApplyOutcome, u64) {
        if self.mode != FeedMode::Joint {
            return (FailureApplyOutcome::Ignored, 0);
        }
        match disposition_of(failure.gap) {
            SealFailureDisposition::Retry => (FailureApplyOutcome::Retried, 0),
            SealFailureDisposition::HistoryLoss => {
                self.dispose_as_loss(reducer, sink);
                let disposed = self.drain_staged();
                self.mode = FeedMode::S1Only;
                (FailureApplyOutcome::Degraded { disposed }, 0)
            }
            SealFailureDisposition::Fallback => {
                match finalizer.take_h3_disposition() {
                    H3DispositionEvidence::Clean {
                        staged_max,
                        pending_floor: None,
                    } if self.covered_by(staged_max) => {
                        let (replayed, refused) = self.replay_staged(reducer, sink);
                        self.mode = FeedMode::S1Only;
                        (FailureApplyOutcome::FellBack { replayed }, refused)
                    }
                    H3DispositionEvidence::StagedLoss { .. } | H3DispositionEvidence::Exhausted => {
                        // H3's own stream is lossy: the staged calls'
                        // S1 proof with it. Real-loss treatment.
                        self.dispose_as_loss(reducer, sink);
                        let disposed = self.drain_staged();
                        self.mode = FeedMode::S1Only;
                        (FailureApplyOutcome::Degraded { disposed }, 0)
                    }
                    _ => (FailureApplyOutcome::HeldForCompleteness, 0),
                }
            }
        }
    }

    /// Whether an H3 Clean receipt covers every staged position: the
    /// explicit completeness the fallback requires.
    fn covered_by(&self, staged_max: u64) -> bool {
        self.staged.iter().all(|call| call.position <= staged_max)
    }

    /// Invalidate live operation authority (terminals first), before
    /// any disposal accounting.
    fn dispose_as_loss<S: OperationSink>(&self, reducer: &mut EdgeSemantics, sink: &mut S) {
        reducer.invalidate_with_effects(sink);
    }

    /// Dispose every retained payload once as history-only: counted,
    /// frontier-advanced, never reduced, never re-staged.
    fn drain_staged(&mut self) -> usize {
        let disposed = self.staged.len();
        for call in self.staged.drain(..) {
            self.frontier = self.frontier.max(call.position);
            self.history_disposed = self.history_disposed.saturating_add(1);
        }
        disposed
    }

    /// Replay every retained payload once in original H3 order
    /// through ordinary S1. Returns the replay count plus per-edge
    /// bound refusals.
    fn replay_staged<S: OperationSink>(
        &mut self,
        reducer: &mut EdgeSemantics,
        sink: &mut S,
    ) -> (usize, u64) {
        let mut replayed = 0;
        let mut refused = 0u64;
        while let Some(head) = self.staged.pop_front() {
            self.frontier = self.frontier.max(head.position);
            refused = refused.saturating_add(reducer.observe_with_effects(
                &head.facts,
                &head.origin,
                sink,
            ));
            self.reduced = self.reduced.saturating_add(1);
            replayed += 1;
        }
        (replayed, refused)
    }
}
