//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! H9 operation/key delivery: the single S1 feed, joint replay and
//! key-use aggregation.
//!
//! One capture-owned feed per instance/era reduces each authorized
//! call exactly once. [`FeedMode`] is selected at registration before
//! the first semantic mutation: [`FeedMode::Joint`] stages H3-admitted
//! S1 payloads and replays them through the one [`EdgeSemantics`]
//! reducer as sealed H8 calls settle; [`FeedMode::S1Only`] reduces
//! directly and never stages. An incarnation selected S1Only at
//! registration never becomes Joint; one that left Joint through
//! fallback or loss resumes at its next clean point
//! ([`is_clean_point`]). An already-reduced call is never replayed.
//!
//! The original seal retains call-qualified settlement steps and frozen
//! effect spans. Effect emission and the exact admission head advance
//! independently under one bounded budget; only an actual End permits S1
//! replay. Actual bounded loss permits history disposal. The ordinary
//! Session Joint lane remains gated on assembled runtime acceptance.

use crate::discovery::caller_registry::instance_input::RegistryInstanceId;
use crate::key_operation_projection::KEY_OP_ROW_CAPACITY;
use crate::semantics_edge::{
    EdgeSemantics, EffectOrigin, KeyReceipt, KeyRole, NoSink, OperationEffect, OperationId,
    OperationOutcome, OperationSink, SemanticCall,
};
#[cfg(test)]
use crate::semantics_objects::ObjectEffects;
#[cfg(test)]
use crate::semantics_objects::journal::H3EvidenceSource;
use crate::semantics_objects::journal::{
    BootstrapReceipt, H3DispositionEvidence, JournalGap, SealFailure, SealSuccess, SealedCall,
};
use crate::semantics_objects::{ObjectEffect, ObjectId, ObjectSemantics, SessionIncarnation};
use std::collections::{BTreeMap, VecDeque};
use std::mem::size_of;

/// At most 1,024 unsettled staged payloads per feed: one bound, two
/// enforcers — this per-feed ceiling mirrors the shared H8 ticket
/// space, and every staged byte charges to the shared [`StagingLedger`]
/// (no unaccounted duplicate pool, H9 §89). The N+1 admission
/// backpressures instead of staging.
pub(crate) const JOINT_STAGING_CAPACITY: usize =
    crate::semantics_objects::journal::MAX_UNSETTLED_STAGED;

/// Per-instance/era feed selection, chosen at registration before
/// the first semantic mutation (H9). A feed that leaves Joint
/// (fallback or loss) stays S1Only until its next clean point —
/// an operation init, login, or session open — where a feed that
/// still holds its birth receipt re-enters Joint for the new
/// segment. Already-reduced calls are never replayed either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeedMode {
    /// Reduce directly; never stage, never replay. Selected at
    /// registration it is permanent; reached by fallback or loss
    /// with a retained receipt it lasts until the next clean point.
    S1Only,
    /// Stage H3-admitted payloads; replay each through the one
    /// reducer as its sealed call settles.
    Joint,
}

/// Which ending opened a feed's current degraded window: the
/// reason direct reductions count under until the next clean
/// point resumes Joint (see [`JointStaging::note_direct_reduction`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DegradedWindow {
    /// A proof-only or ordered fallback ended the segment.
    Fallback,
    /// Real loss ended the segment.
    Loss,
    /// The no-progress watchdog tripped: the lane is held for exit
    /// and no seal will settle anything again (never resumes).
    Watchdog,
}

/// Whether the frozen endpoint table proves `function` irrelevant
/// to key proof: info and session-state reads that are not key
/// operations and never count as not attributed.
fn proved_irrelevant(function: &str) -> bool {
    crate::kinds::function_id(function).and_then(crate::semantics_objects::journal::endpoint_class)
        == Some(crate::semantics_objects::journal::EndpointClass::ProvedIrrelevant)
}

/// Whether `function` starts a clean segment boundary at which a
/// degraded feed may resume attribution: an operation init (the
/// frozen descriptor's INITIALIZE transition), a login, or a
/// session open. Reads only the function name's frozen descriptor.
pub(crate) fn is_clean_point(function: &str) -> bool {
    use p11scope_ebpf_common::{lifecycle, transition};
    crate::kinds::descriptor(function).is_some_and(|descriptor| {
        descriptor.transition == transition::INITIALIZE
            || descriptor.lifecycle == lifecycle::LOGIN
            || descriptor.lifecycle == lifecycle::OPEN_SESSION
    })
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
    /// H8's frozen endpoint table cannot model this call (async
    /// completions, encapsulate, info calls): it can never settle,
    /// and ingesting it would taint the image. The driver reduces
    /// it S1Only-direct — the async-completion carve-out. Such
    /// operations row unknown-key (no receipt can exist for them).
    Unsealable,
}

/// How one seal advanced the staging.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealApplyOutcome {
    /// The seal settled exactly the staged head (function-verified,
    /// terminally bounded); it replayed once through the reducer.
    ReplayedOne,
    /// Nothing replayed: the seal settled zero calls, the head's
    /// terminal is still open, the legacy algorithm input is multicall,
    /// or the feed already left Joint. Staging is intact.
    Held,
    /// The seal settled exactly the staged head, but H3's resource
    /// pool refused the S1 growth (N14): live S1 invalidated with
    /// terminals teed (opens close as Unknown), the head disposed as
    /// history, the claim consumed. The feed stays Joint: later seals
    /// may still replay once budget frees.
    ResourceRefused,
}

/// Progress within the SAME retained original result and service budget.
/// Counts describe this slice; the feed's frontier owns once-only consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealBatchProgress {
    Complete { replayed: usize, disposed: usize },
    Yielded { replayed: usize, disposed: usize },
    Held,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FailureBatchProgress {
    Complete(FailureApplyOutcome),
    /// An already-S1Only history consumed the authenticated original spans
    /// and any required loss invalidation, without replay or mode reentry.
    NegativeDelivered(crate::semantics_objects::journal::joint_audit::NegativeDelivered),
    Yielded,
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
    /// Legacy algorithm-only input for a feed that already left Joint.
    /// Production affecting negatives require typed actual delivery instead.
    #[cfg(test)]
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

/// Whether a feed whose segment ended with this gap may resume
/// Joint at its next clean point. Record-level and proof-only
/// endings are segment-local: fresh seals can prove a later
/// segment. Endings that name the authority itself — a tainted or
/// ended domain/image, a mismatched or invalidated birth, a
/// stopped adapter, or a faulted journal — have no clean point on
/// this feed; only a new birth (a new feed) can attribute again.
pub(crate) fn segment_resumable_after(gap: JournalGap) -> bool {
    use JournalGap::*;
    !matches!(
        gap,
        DomainTainted
            | ImageTainted
            | DomainEnded
            | AdapterInvalidated
            | Stopped
            | BootstrapMismatch
            | FaultChanged
            | FaultUnreadable
            | FaultSaturated
    )
}

/// Map one seal gap to its H9 disposition.
pub(crate) fn disposition_of(gap: JournalGap) -> SealFailureDisposition {
    use JournalGap::*;
    use SealFailureDisposition::*;
    match gap {
        FaultChanged | FaultUnreadable | FaultSaturated | Malformed | CounterUnprovable
        | H3Loss | H3Exhausted | Discarded => HistoryLoss,
        H3Pending | BoundNotReady | FrontierRegression => Retry,
        ModelRefused | BootstrapMismatch | ClosureStale | DomainTainted | ImageTainted
        | DomainEnded | AdapterInvalidated | Stopped | DrainMismatch | CutExhausted
        | ResourceUnavailable | ClaimUnmatched | IngestBreakLoss => Fallback,
    }
}

/// One staged H3-admitted call: its proved S1 payload, the
/// registry-supplied origin, and its H0 ordinal (replay order,
/// frontier and fallback-coverage checks).
struct StagedCall {
    facts: SemanticCall,
    origin: EffectOrigin,
    position: u64,
    resource_native: Option<crate::attach::capture::NativeDomainId>,
    resource_origin: Option<crate::semantics_objects::journal::StagedResourceOrigin>,
    /// Retained from the actual collected END, never reconstructed from S1
    /// shape. It lets the owner dispose the exact completed H8 row in O(log N).
    original_invocation: Option<(u64, u64)>,
}

impl StagedCall {
    /// Duplicate bytes charged to the shared ledger: the entry plus
    /// both function-name heaps (facts and origin carry separate
    /// copies). Capacities bound the heaps from above.
    fn charged_bytes(&self) -> u64 {
        size_of::<Self>() as u64
            + self.facts.function.capacity() as u64
            + self.origin.function.capacity() as u64
    }

    fn release(self, ledger: &mut crate::semantics_objects::journal::StagingLedger) {
        let (native, position, bytes) = (self.resource_native, self.position, self.charged_bytes());
        drop(self);
        match native {
            Some(native) => ledger.release_collected(native, position),
            None => ledger.release(position, bytes),
        }
    }
}

/// The Joint replay adapter (H9): the staging FIFO plus the consumed
/// frontier. The H8 adapter/model and the reducer stay owner-held;
/// each quantum borrows them.
pub(crate) struct JointStaging {
    mode: FeedMode,
    /// Immutable selection for this per-era feed; delivery never rebinds it.
    selected_receipt: Option<BootstrapReceipt>,
    staged: VecDeque<StagedCall>,
    /// Highest consumed H0 position (replayed or disposed): staging
    /// at or below it is a forbidden replay.
    frontier: u64,
    /// Observability only. C2 consumes admission identity through frontier,
    /// so replay needs no retained ticket set or FIFO allocation. Each real
    /// seal names its exact admitted invocation, every live head is strictly
    /// above frontier, and a redeemed/disposed admission stays at or below
    /// frontier. Namespace selection is checked before this comparison.
    redeemed: u64,
    reduced: u64,
    history_disposed: u64,
    /// Disposed-history count at the last clean resume: the
    /// `authority_lost` latch compares the current count against
    /// this baseline, so a clean resume clears it while the counter
    /// above keeps counting every disposal. Never reset.
    history_disposed_baseline: u64,
    /// Staged calls replayed S1-direct by a fallback (ordered or
    /// proof-only): they keep their S1 counts but no per-key row can
    /// be proved for them, so the projection counts them as not
    /// attributed (`proof_refused_fallback`).
    fallback_replayed: u64,
    /// Affecting calls the frozen endpoint table cannot seal
    /// (negative-only or unclassified), reduced S1-direct: counted
    /// as not attributed (`unmodelled_call_shape`).
    /// Proved-irrelevant calls are not key operations and never
    /// count here.
    unsealable_direct: u64,
    /// Direct reductions on a feed registered without a witnessed
    /// birth (attach after start, or the birth race): counted as
    /// not attributed (`started_before_attach`). The registry
    /// notes each one; the feed itself never sees the call.
    pre_attach_direct: u64,
    /// Direct reductions in the degraded window after a fallback
    /// ended a segment, before its next clean point: counted as
    /// not attributed under that segment's reason
    /// (`proof_refused_fallback`).
    degraded_fallback_direct: u64,
    /// Direct reductions in the degraded window after real loss
    /// ended a segment, before its next clean point: counted as
    /// not attributed under that segment's reason (`record_lost`).
    degraded_loss_direct: u64,
    /// The ending that opened the current degraded window, if a
    /// segment has ended and not yet resumed. Cleared on resume.
    degraded_window: Option<DegradedWindow>,
    /// Staged calls taken out at the no-progress watchdog trip,
    /// plus later direct key calls in the watchdog window: each
    /// counted once as not attributed (`watchdog_no_progress`).
    /// Taken out history-only — never reduced, never replayed.
    watchdog_unsealed: u64,
    /// True once the watchdog trip has been noted for this feed:
    /// the take-out above runs exactly once.
    watchdog_tripped: bool,
    correlation_refusals: u64,
    /// True while the current segment ended in real loss (not
    /// proof-only refusal): the projection reports `authority_lost`,
    /// never a silent empty success. Cleared on clean resume.
    degraded_loss: bool,
    /// True while the current segment ended in proof-only refusal
    /// replayed through ordinary S1: the projection reports
    /// `proof_refused_fallback`. Cleared on clean resume.
    fell_back: bool,
    /// Whether the segment that just ended permits a clean-point
    /// resume (see [`segment_resumable_after`]); ordered fallbacks
    /// always permit it. Cleared on resume.
    segment_resumable: bool,
    /// The running-maximum void fence recorded across endings (see
    /// [`Self::record_fence`]): every void's fence joins it, fenceless
    /// endings never lower it. A retained receipt cut below it never
    /// resumes Joint (see [`Self::resume_joint`]); cleared on resume.
    segment_fence: Option<u64>,
    /// The fence last disclosed as deferring a below-fence resume
    /// (I2): the per-feed reason fires once per recorded fence and a
    /// new void re-arms it. Cleared on resume.
    resume_deferral_disclosed: Option<u64>,
    /// Ledger releases pended by a ledger-less ordered fallback
    /// (C4): flushed on the next ledger contact. One fallback drains
    /// staging, and re-staging after a clean-point resume flushes
    /// first, so one segment's worth is ever pended: bounded by
    /// [`JOINT_STAGING_CAPACITY`].
    pending_releases: Vec<(Option<crate::attach::capture::NativeDomainId>, u64, u64)>,
}

impl std::fmt::Debug for JointStaging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JointStaging")
            .field("mode", &self.mode)
            .field("staged", &self.staged.len())
            .field("redeemed", &self.redeemed)
            .field("reduced", &self.reduced)
            .field("history_disposed", &self.history_disposed)
            .field("correlation_refusals", &self.correlation_refusals)
            .field("degraded_loss", &self.degraded_loss)
            .field("fell_back", &self.fell_back)
            .field("pending_releases", &self.pending_releases.len())
            .finish_non_exhaustive()
    }
}

impl JointStaging {
    /// Select S1Only at registration: no receipt, no staging, no
    /// bootstrap-wait queue. Permanent once the instance has returned
    /// a call; an untouched feed may still select Joint once
    /// ([`Self::upgrade_to_joint`]).
    pub(crate) fn select_s1_only() -> Self {
        Self {
            mode: FeedMode::S1Only,
            selected_receipt: None,
            staged: VecDeque::new(),
            frontier: 0,
            redeemed: 0,
            reduced: 0,
            history_disposed: 0,
            history_disposed_baseline: 0,
            fallback_replayed: 0,
            unsealable_direct: 0,
            pre_attach_direct: 0,
            degraded_fallback_direct: 0,
            degraded_loss_direct: 0,
            degraded_window: None,
            watchdog_unsealed: 0,
            watchdog_tripped: false,
            correlation_refusals: 0,
            degraded_loss: false,
            fell_back: false,
            segment_resumable: false,
            segment_fence: None,
            resume_deferral_disclosed: None,
            pending_releases: Vec::new(),
        }
    }

    /// Select Joint at registration: only with the current H8
    /// birth/closure receipt already present. Without it, S1Only
    /// immediately — never a bootstrap-wait queue. A pristine
    /// never-Joint feed may still upgrade once on a retry birth's
    /// valid receipt ([`Self::upgrade_to_joint`]); refused, fallen
    /// back, degraded and tripped feeds never do. The receipt
    /// evidences selection only; every seal still verifies birth
    /// independently.
    pub(crate) fn select_joint(receipt: Option<&BootstrapReceipt>) -> Self {
        let mut staging = Self::select_s1_only();
        if let Some(receipt) = receipt {
            staging.mode = FeedMode::Joint;
            staging.selected_receipt = Some(*receipt);
        }
        staging
    }

    /// The original selection remains retained even after a feed degrades.
    /// A later broad loss may still invalidate this incarnation's history.
    pub(crate) fn selected_receipt(&self) -> Option<&BootstrapReceipt> {
        self.selected_receipt.as_ref()
    }

    pub(crate) fn accepts_seal(&self, seal: &SealSuccess) -> bool {
        self.selected_receipt.as_ref().map(BootstrapReceipt::domain) == Some(seal.prefix.domain())
    }

    pub(crate) fn accepts_failure(&self, failure: &SealFailure) -> bool {
        self.selected_receipt
            .as_ref()
            .is_some_and(|receipt| failure.affects_domain(receipt.domain()))
    }

    pub(crate) fn mode(&self) -> FeedMode {
        self.mode
    }

    /// Consumed-H0-position frontier for replay tests.
    #[cfg(test)]
    pub(crate) fn frontier_for_test(&self) -> u64 {
        self.frontier
    }

    /// Recorded void fence for fence tests.
    #[cfg(test)]
    pub(crate) fn segment_fence_for_test(&self) -> Option<u64> {
        self.segment_fence
    }

    /// Record a void fence for re-arm tests (running maximum, like
    /// frame delivery does for a later void on a degraded feed).
    #[cfg(test)]
    pub(crate) fn record_fence_for_test(&mut self, fence: Option<u64>) {
        self.record_fence(fence);
    }

    /// Pose a feed mode for tests. Production flows never stage onto
    /// an S1Only feed ("S1Only never owns a staged suffix"), so the
    /// reseed twin poses Joint to stage a remainder, then poses
    /// S1Only back to pin the drained-staging arm alone.
    #[cfg(test)]
    pub(crate) fn pose_mode_for_test(&mut self, mode: FeedMode) {
        self.mode = mode;
    }

    /// Re-enter Joint at a clean point after a fallback or loss
    /// ended the previous segment. Only a feed that was selected
    /// Joint at registration (retained receipt), actually left it,
    /// and holds no staged remainder may resume — and never onto a
    /// receipt cut below the recorded segment fence (see
    /// [`Self::receipt_below_recorded_fence`]). A clean resume clears
    /// the loss/fallback latches and baselines disposed history:
    /// current tracking is healthy again, so the reason clears, while
    /// the retained counters keep counting the closed segment beside
    /// it. Returns whether the mode changed.
    pub(crate) fn resume_joint(&mut self) -> bool {
        if self.mode == FeedMode::S1Only
            && !self.watchdog_tripped
            && self.selected_receipt.is_some()
            && self.segment_resumable
            && self.staged.is_empty()
            && !self.receipt_below_recorded_fence()
        {
            self.mode = FeedMode::Joint;
            self.segment_resumable = false;
            self.segment_fence = None;
            self.resume_deferral_disclosed = None;
            self.degraded_window = None;
            self.degraded_loss = false;
            self.fell_back = false;
            self.history_disposed_baseline = self.history_disposed;
            true
        } else {
            false
        }
    }

    /// Whether the retained receipt cuts below the recorded segment
    /// fence: such a receipt can never seal again (the seal and
    /// attestation checks refuse it), so resuming onto it would only
    /// end the next segment as `BootstrapMismatch`. Only a fresh
    /// receipt at or above the fence (re-selection) resumes.
    fn receipt_below_recorded_fence(&self) -> bool {
        self.selected_receipt.as_ref().is_some_and(|receipt| {
            self.segment_fence
                .is_some_and(|fence| receipt.birth_cut() < fence)
        })
    }

    /// Take the below-fence deferral for disclosure (I2): true once per
    /// recorded fence while the retained receipt cuts below it, so the
    /// Task-1→3 interim (a voided but resumable feed that can only wait
    /// for re-selection) names one counted per-feed reason instead of
    /// refusing silently. Only a resumable segment defers — a
    /// never-resumable ending already names its own seal gap, and
    /// calling its refusal "deferred" would promise a re-selection
    /// that cannot land before Task 3. A new void re-arms it; a clean
    /// resume clears it.
    pub(crate) fn take_below_fence_deferral(&mut self) -> bool {
        if self.segment_resumable
            && self.receipt_below_recorded_fence()
            && self.resume_deferral_disclosed != self.segment_fence
        {
            self.resume_deferral_disclosed = self.segment_fence;
            true
        } else {
            false
        }
    }

    /// Whether a later birth may still select Joint for this feed: it
    /// was registered S1Only only because its sighting pass carried no
    /// birth, and nothing has touched it since (no selection, segment,
    /// fallback, loss or trip history, nothing staged, nothing
    /// reduced, no pre-birth direct call). The registry also requires
    /// that the instance never returned a call.
    pub(crate) fn upgrade_eligible(&self) -> bool {
        self.upgrade_block().is_none()
    }

    /// Why a late Joint selection is refused (`None`: eligible), as a
    /// gap reason: calls the feed already carried, or its own
    /// fallback, loss or trip history.
    pub(crate) fn upgrade_block(&self) -> Option<&'static str> {
        if self.mode != FeedMode::S1Only || self.selected_receipt.is_some() {
            Some("joint_birth_feed_selected")
        } else if !self.staged.is_empty() || self.reduced != 0 || self.pre_attach_direct != 0 {
            Some("joint_birth_after_calls")
        } else if self.fell_back || self.degraded_loss || self.watchdog_tripped {
            Some("joint_birth_feed_degraded")
        } else {
            None
        }
    }

    /// Select Joint late for an untouched S1Only feed, exactly as
    /// [`Self::select_joint`] would have at registration: the replay
    /// frontier is left alone (it counts H0 positions; a birth cut
    /// counts journal consumption and is verified by every seal).
    /// There is no pre-birth call to fence: the feed never saw one.
    /// One-shot: the retained receipt makes a second upgrade refuse.
    /// Returns whether the mode changed.
    pub(crate) fn upgrade_to_joint(
        &mut self,
        receipt: &crate::semantics_objects::journal::BootstrapReceipt,
    ) -> bool {
        if !self.upgrade_eligible() {
            return false;
        }
        self.mode = FeedMode::Joint;
        self.selected_receipt = Some(*receipt);
        true
    }

    /// Whether this degraded feed may reseed onto a fresh receipt: it
    /// ended a Joint segment (fallback or loss, fenced or not), still
    /// holds its old receipt, drained its staging, and never tripped
    /// the watchdog. The fresh receipt itself (same incarnation, cut
    /// above the old cut and at/above the recorded fence) is checked
    /// at [`Self::reselect_joint`]; this gate needs no receipt.
    pub(crate) fn reseed_eligible(&self) -> bool {
        self.mode == FeedMode::S1Only
            && self.selected_receipt.is_some()
            && self.degraded_window.is_some()
            && self.staged.is_empty()
            && !self.watchdog_tripped
    }

    /// Reseed a voided feed onto a fresh birth receipt at or above its
    /// recorded fence (Task 3 re-selection): the old below-fence receipt
    /// never resumes, but a fresh receipt for the same incarnation with
    /// a strictly newer cut starts a new Joint segment. Only a feed that
    /// ended a segment (fallback or loss), drained its staging, and never
    /// tripped may reseed — and never onto another incarnation's receipt
    /// (wrong-key), a cut at/below the old cut (no progress), or a cut
    /// below the recorded fence (would certify voided history). A clean
    /// reseed clears the loss/fallback latches and baselines disposed
    /// history like [`Self::resume_joint`]: the closed segment stays
    /// counted, new disposal latches again. Returns whether the mode
    /// changed.
    pub(crate) fn reselect_joint(
        &mut self,
        receipt: &crate::semantics_objects::journal::BootstrapReceipt,
    ) -> bool {
        let Some(old) = self.selected_receipt.as_ref() else {
            return false;
        };
        if !self.reseed_eligible() {
            return false;
        }
        if receipt.domain() != old.domain() {
            return false;
        }
        if receipt.birth_cut() <= old.birth_cut() {
            return false;
        }
        if self
            .segment_fence
            .is_some_and(|fence| receipt.birth_cut() < fence)
        {
            return false;
        }
        self.mode = FeedMode::Joint;
        self.selected_receipt = Some(*receipt);
        self.segment_resumable = false;
        self.segment_fence = None;
        self.resume_deferral_disclosed = None;
        self.degraded_window = None;
        self.degraded_loss = false;
        self.fell_back = false;
        self.history_disposed_baseline = self.history_disposed;
        true
    }

    /// Calls replayed through the one reducer (seal or fallback).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn reduced(&self) -> u64 {
        self.reduced
    }

    /// Retained payloads disposed once as history-only.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn history_disposed(&self) -> u64 {
        self.history_disposed
    }

    /// Disposed payloads since the last clean resume: the
    /// `authority_lost` latch input. A clean resume baselines the
    /// closed segment away; new disposal latches again.
    pub(crate) fn history_disposed_since_resume(&self) -> u64 {
        self.history_disposed
            .saturating_sub(self.history_disposed_baseline)
    }

    /// Staged calls a fallback replayed S1-direct without proof.
    pub(crate) fn fallback_replayed(&self) -> u64 {
        self.fallback_replayed
    }

    /// Affecting unsealable calls reduced S1-direct.
    pub(crate) fn unsealable_direct(&self) -> u64 {
        self.unsealable_direct
    }

    /// Direct reductions counted against an unwitnessed birth.
    pub(crate) fn pre_attach_direct(&self) -> u64 {
        self.pre_attach_direct
    }

    /// Direct reductions in the degraded window after a fallback.
    pub(crate) fn degraded_fallback_direct(&self) -> u64 {
        self.degraded_fallback_direct
    }

    /// Direct reductions in the degraded window after real loss.
    pub(crate) fn degraded_loss_direct(&self) -> u64 {
        self.degraded_loss_direct
    }

    /// Staged calls counted under the watchdog reason at the trip.
    pub(crate) fn watchdog_unsealed(&self) -> u64 {
        self.watchdog_unsealed
    }

    /// Note the no-progress watchdog trip for this feed, exactly
    /// once: take every staged call out (history-only, like loss
    /// disposal: never reduced, never replayed, releases pended to
    /// the next ledger contact) and count each once as
    /// `watchdog_no_progress`. The segment closes for good: no later
    /// seal, loss or replay can count those calls again, nothing new
    /// stages, and later direct key calls count under the watchdog
    /// reason too. Returns whether this call left Joint mode.
    pub(crate) fn note_watchdog_trip(&mut self) -> bool {
        if self.watchdog_tripped {
            return false;
        }
        self.watchdog_tripped = true;
        while let Some(head) = self.staged.pop_front() {
            let bytes = head.charged_bytes();
            let (position, native) = (head.position, head.resource_native);
            drop(head);
            self.release_or_pend(None, position, bytes, native);
            self.frontier = self.frontier.max(position);
            self.watchdog_unsealed = self.watchdog_unsealed.saturating_add(1);
        }
        let was_joint = self.mode == FeedMode::Joint;
        if was_joint || self.selected_receipt.is_some() {
            self.mode = FeedMode::S1Only;
            self.segment_resumable = false;
            self.degraded_window = Some(DegradedWindow::Watchdog);
        }
        was_joint
    }

    /// Whether the no-progress watchdog tripped on this feed.
    pub(crate) fn watchdog_tripped(&self) -> bool {
        self.watchdog_tripped
    }

    /// Dispose every staged call without delivery (running-rearm
    /// recovery): the abandoned quantum's staged calls can never
    /// reduce — the void fenced their history and dropped staged
    /// custody — so the recovery verifies against exactly its own
    /// history. Releases each head's ledger charge, advances the
    /// frontier and counts each once as disposed history
    /// (`record_lost`), exactly like loss disposal: staged Joint
    /// calls are unreduced by construction, so dropping them
    /// uncounted would lose calls. Never reduces or replays. The
    /// segment stays open: the recovery's own seals stage, then
    /// replay as unknown-key rows when the fenced void delivers
    /// (fallback, never Joint-certified).
    pub(crate) fn drop_abandoned_staged(
        &mut self,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) {
        self.dispose_pure_below_barrier(None, Some(ledger));
    }

    /// Record a void fence as a running maximum: a later void raises
    /// the bound, while a fenceless ending (local fallback, proof-only
    /// refusal) never lowers or clears it. Only a clean resume clears.
    fn record_fence(&mut self, fence: Option<u64>) {
        if let Some(next) = fence {
            self.segment_fence = Some(self.segment_fence.map_or(next, |kept| kept.max(next)));
        }
    }

    /// End the current Joint segment: degrade to S1Only and open
    /// the degraded window in which direct reductions count under
    /// this ending's reason until the next clean point resumes. The
    /// ending failure's void fence (if any) joins the running maximum:
    /// a below-fence receipt never resumes onto it.
    fn close_segment(&mut self, loss: bool, resumable: bool, fence: Option<u64>) {
        self.mode = FeedMode::S1Only;
        self.segment_resumable = resumable;
        self.record_fence(fence);
        if loss {
            self.degraded_loss = true;
            self.degraded_window = Some(DegradedWindow::Loss);
        } else {
            self.fell_back = true;
            self.degraded_window = Some(DegradedWindow::Fallback);
        }
    }

    /// Count one S1-direct reduction on this feed, under the one
    /// reason that kept it from attribution. Proved-irrelevant
    /// calls are not key operations and never count. Without a
    /// selected birth receipt the call started before attach; on
    /// a receipt-holding feed whose last segment ended and has
    /// not yet resumed, it counts under that segment's reason.
    pub(crate) fn note_direct_reduction(&mut self, function: &str) {
        if proved_irrelevant(function) {
            return;
        }
        if self.selected_receipt.is_none() {
            self.pre_attach_direct = self.pre_attach_direct.saturating_add(1);
            return;
        }
        match self.degraded_window {
            Some(DegradedWindow::Fallback) => {
                self.degraded_fallback_direct = self.degraded_fallback_direct.saturating_add(1);
            }
            Some(DegradedWindow::Loss) => {
                self.degraded_loss_direct = self.degraded_loss_direct.saturating_add(1);
            }
            Some(DegradedWindow::Watchdog) => {
                self.watchdog_unsealed = self.watchdog_unsealed.saturating_add(1);
            }
            None => {}
        }
    }

    /// Seal quanta refused for correlation (multi-call seals H9 does
    /// not batch, exact-match failure, repeated seals, or
    /// settled-but-never-staged).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn correlation_refusals(&self) -> u64 {
        self.correlation_refusals
    }

    /// Currently staged (unsettled) payloads.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn staged_len(&self) -> usize {
        self.staged.len()
    }

    /// Read the original retained membership, without copying its payload or
    /// changing replay state. Admission positions strictly increase on stage.
    pub(crate) fn staged_resource(
        &self,
        position: u64,
    ) -> Option<&crate::semantics_objects::journal::StagedResourceOrigin> {
        let mut lower = 0;
        let mut upper = self.staged.len();
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            let head = &self.staged[middle];
            match head.position.cmp(&position) {
                std::cmp::Ordering::Less => lower = middle + 1,
                std::cmp::Ordering::Greater => upper = middle,
                std::cmp::Ordering::Equal => return head.resource_origin.as_ref(),
            }
        }
        None
    }

    pub(crate) fn staged_head_original(&self) -> Option<(u64, Option<(u64, u64)>)> {
        self.staged
            .front()
            .map(|head| (head.position, head.original_invocation))
    }

    /// Borrow the existing FIFO by index during one continuation preflight;
    /// no copied queue or scalar admission can create this native identity.
    pub(crate) fn staged_original_at(&self, index: usize) -> Option<(u64, (u64, u64))> {
        let original = self.staged.get(index)?;
        Some((original.position, original.original_invocation?))
    }

    /// Whether real loss ended this feed's object authority.
    pub(crate) fn degraded_loss(&self) -> bool {
        self.degraded_loss
    }

    /// Whether proof-only refusal fell back to S1Only.
    pub(crate) fn fell_back(&self) -> bool {
        self.fell_back
    }

    /// Stage one H3-admitted payload in admission order. Positions
    /// must strictly exceed both the consumed frontier and the staged
    /// tail: H0 tokens are unique per admission, so anything else is
    /// a forbidden replay or a caller-ordering bug. Only H8-modelable
    /// calls stage: anything the frozen endpoint table leaves
    /// negative-only or irrelevant (async completions, encapsulate,
    /// info calls) can never settle — ingesting one would taint the
    /// image — so the driver reduces those S1Only-direct instead. The
    /// payload's ticket and duplicate bytes charge to the shared H8
    /// ledger before the entry lands (refused staging never holds a
    /// ticket); replay, fallback and loss disposal release.
    #[cfg_attr(not(test), allow(dead_code))] // Staged Joint path: exercised by the key-operation tests; production still reduces S1Only.
    pub(crate) fn stage(
        &mut self,
        facts: SemanticCall,
        origin: EffectOrigin,
        position: u64,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) -> Result<(), StagingRefusal> {
        self.stage_inner(facts, origin, position, None, None, ledger)
    }

    #[allow(clippy::too_many_arguments)] // Opaque resource provenance accompanies the existing admitted payload.
    pub(crate) fn stage_collected(
        &mut self,
        facts: SemanticCall,
        origin: EffectOrigin,
        position: u64,
        native: crate::attach::capture::NativeDomainId,
        resource: Option<crate::semantics_objects::journal::joint_driver::JointResourceOrigin>,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) -> Result<(), StagingRefusal> {
        self.stage_inner(facts, origin, position, Some(native), resource, ledger)
    }

    #[allow(clippy::too_many_arguments)] // Marked legacy fixtures and the collected path share all replay checks.
    fn stage_inner(
        &mut self,
        facts: SemanticCall,
        origin: EffectOrigin,
        position: u64,
        native: Option<crate::attach::capture::NativeDomainId>,
        resource: Option<crate::semantics_objects::journal::joint_driver::JointResourceOrigin>,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) -> Result<(), StagingRefusal> {
        // Ledger contact flushes pended releases first (C4).
        self.flush_pending_releases(ledger);
        if self.mode != FeedMode::Joint {
            return Err(StagingRefusal::NotJoint);
        }
        let class = crate::kinds::function_id(&facts.function)
            .and_then(crate::semantics_objects::journal::endpoint_class);
        let sealable =
            class == Some(crate::semantics_objects::journal::EndpointClass::ModeledAffecting);
        if !sealable {
            // Affecting shapes we cannot seal count as not
            // attributed; proved-irrelevant calls are not key
            // operations and count nothing.
            if class != Some(crate::semantics_objects::journal::EndpointClass::ProvedIrrelevant) {
                self.unsealable_direct = self.unsealable_direct.saturating_add(1);
            }
            return Err(StagingRefusal::Unsealable);
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
        let mut staged = StagedCall {
            facts,
            origin,
            position,
            resource_native: native,
            resource_origin: None,
            original_invocation: resource.as_ref().map(|origin| origin.invocation()),
        };
        let charged = match native {
            Some(native) => ledger
                .charge_collected(native, position, staged.charged_bytes(), resource.as_ref())
                .map(Some),
            None => ledger
                .charge(position, staged.charged_bytes())
                .map(|_| None),
        };
        staged.resource_origin = charged.map_err(|refusal| {
            use crate::semantics_objects::journal::LedgerRefusal::*;
            match refusal {
                Full => StagingRefusal::Full,
                ReplayRefused => StagingRefusal::ReplayRefused,
            }
        })?;
        self.staged.push_back(staged);
        Ok(())
    }

    /// Apply one seal: replay the staged head iff the seal settled
    /// exactly its call — one settled call, exact-matched against
    /// the head (catalog function, session, mechanism shape),
    /// terminally bounded (END cut or abandonment bound) — and
    /// consume that claim once: a repeated seal never replays, even
    /// against a same-shaped head. Anything else holds staging
    /// intact. The replay runs through
    /// [`EdgeSemantics::observe_joint`] with this quantum's
    /// positional receipts (assembled from the seal's ticket-
    /// qualified references plus at-transition metadata snapshots);
    /// its effects feed both the caller's sink and the key-use
    /// reducer from the same single pass. Returns the outcome plus
    /// this quantum's per-edge bound refusals (the owner folds them
    /// into `semantic_refused`, like the direct feed). Resource
    /// refusal disposes the head as history (see
    /// [`SealApplyOutcome::ResourceRefused`]).
    #[allow(clippy::too_many_arguments)] // Staging borrows the exact pipeline facts plus the shared ledger.
    #[cfg(test)]
    pub(crate) fn apply_seal<S: OperationSink>(
        &mut self,
        seal: &SealSuccess,
        model: &ObjectSemantics,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        instance: RegistryInstanceId,
        sink: &mut S,
        assoc_fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> (SealApplyOutcome, u64) {
        // A foreign receipt has no authority even over pending releases.
        if !self.accepts_seal(seal) {
            return (SealApplyOutcome::Held, 0);
        }
        // Ledger contact flushes pended releases first (C4).
        self.flush_pending_releases(ledger);
        // Matching old-domain contact may release already-owned charges,
        // but a degraded feed never consumes semantic evidence again.
        if self.mode != FeedMode::Joint {
            return (SealApplyOutcome::Held, 0);
        }
        // Qualified invalidations apply even when the quantum cannot
        // replay (N3): holding S1 replay must never hold
        // already-applied object invalidations. Runs before every
        // Held return below (idempotent: re-applied retirements find
        // their joins already lost and count nothing twice).
        keyuse.apply_invalidations(&seal.effects, model);
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
        if settled[0].key.admission() <= self.frontier {
            // Spent and disposed admissions can never match a live head:
            // stage() requires position > frontier and exact correlation
            // below requires seal admission == head position. Partial seals
            // do not advance frontier, so their eventual terminal can retry.
            // At MAX, no successor can stage; there is no wrap/reset path.
            self.correlation_refusals = self.correlation_refusals.saturating_add(1);
            return (SealApplyOutcome::Held, 0);
        }
        let Some(head) = self.staged.front() else {
            self.correlation_refusals = self.correlation_refusals.saturating_add(1);
            return (SealApplyOutcome::Held, 0);
        };
        // Exact binding: the settled call must BE the staged head
        // (function, session, mechanism shape) — never merely the
        // same function. The fingerprint rides the seal itself: the
        // model already settled (and pruned) this call, so no
        // model-side lookup can bind it afterwards. Mismatches hold
        // without consuming: a delayed seal can still redeem against
        // its own head later.
        let exact = crate::kinds::function_id(&head.facts.function).is_some_and(|function| {
            settled[0].matches_head(
                function,
                head.facts.session,
                head.facts.capture,
                head.position,
            )
        });
        if !exact {
            self.correlation_refusals = self.correlation_refusals.saturating_add(1);
            return (SealApplyOutcome::Held, 0);
        }
        if settled[0].end_cut.is_none() && !settled[0].abandoned {
            return (SealApplyOutcome::Held, 0);
        }
        self.redeemed = self.redeemed.saturating_add(1);
        let head = self.staged.pop_front().expect("head verified above");
        self.frontier = self.frontier.max(head.position);
        let receipts = keyuse.receipts_for_call(seal, &settled[0], model, head.position);
        // Legacy heads on a reserver-less ledger carry no resource
        // custody: release the staged charge before replay so the
        // replayed open can mint its association at a byte limit
        // (same N15 capacity order as fallback replay). Collected
        // heads hold custody through replay: the assoc mint joins
        // the live staged reservation. Legacy heads on a
        // resource-backed ledger keep the same order — their staged
        // charge holds a real lease — but mint separately: source
        // `None` takes no credit and joins nothing.
        let legacy = head.resource_origin.is_none();
        let early_release = legacy && !ledger.has_reserver();
        if early_release {
            ledger.release(head.position, head.charged_bytes());
        }
        // The seal's retirements already applied above (H9 §66),
        // before this replay: a terminal the replay emits can never
        // complete a binding this seal just unproved.
        let completion =
            KeyUseReducer::completion_evidence_for_effects(&seal.effects.effects, &settled[0]);
        let outcome = {
            let mut tee = KeyUseTee {
                outer: sink,
                keyuse,
                instance,
                shared: Some(&mut *ledger),
                fallback: assoc_fallback,
                source: head.resource_origin.as_ref(),
            };
            match reducer.observe_joint_with_resources(
                &head.facts,
                &head.origin,
                &receipts,
                &completion,
                &mut tee,
            ) {
                Ok(refused) => {
                    self.reduced = self.reduced.saturating_add(1);
                    (SealApplyOutcome::ReplayedOne, refused)
                }
                Err(_) => {
                    // H3 resource refusal (N14): the S1 growth doesn't
                    // fit. Invalidate live S1 with terminals teed (opens
                    // close as Unknown, like S1Only exhaustion), dispose
                    // the un-replayable head as history (claim already
                    // consumed above), and keep
                    // the feed Joint for later seals.
                    reducer.invalidate_with_effects(&mut tee);
                    self.history_disposed = self.history_disposed.saturating_add(1);
                    (SealApplyOutcome::ResourceRefused, 0)
                }
            }
        };
        if early_release {
            drop(head);
        } else {
            head.release(ledger);
        }
        outcome
    }

    /// The real frame supplies original step/index custody. Effect order and
    /// FIFO admission order are independent: apply each span once, then redeem
    /// only the exact head's actual End or explicit bounded history loss.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_seal_batch<S: OperationSink>(
        &mut self,
        batch: &mut crate::semantics_objects::journal::SealBatchDelivery<'_>,
        model: &ObjectSemantics,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        instance: RegistryInstanceId,
        sink: &mut S,
        mut assoc_fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        remaining: &mut usize,
    ) -> (SealBatchProgress, u64) {
        use crate::semantics_objects::journal::SealReplayPhase;
        if !self.accepts_seal(batch.seal()) || self.mode != FeedMode::Joint {
            return (SealBatchProgress::Held, 0);
        }
        self.flush_pending_releases(ledger);
        let (mut replayed, mut disposed, mut refused) = (0, 0, 0u64);
        loop {
            if self.staged.is_empty() && batch.effects_complete() {
                return (SealBatchProgress::Complete { replayed, disposed }, refused);
            }
            if *remaining == 0 {
                return (SealBatchProgress::Yielded { replayed, disposed }, refused);
            }
            let terminal = self
                .staged
                .front()
                .and_then(|head| batch.ready_terminal(head.position));
            if let Some(step) = terminal {
                let seal = batch.seal();
                let Some(call) = seal.prefix.call_for_step(step) else {
                    return (SealBatchProgress::Held, refused);
                };
                let head = self
                    .staged
                    .front()
                    .expect("ready terminal has a retained head");
                let exact =
                    crate::kinds::function_id(&head.facts.function).is_some_and(|function| {
                        call.matches_head(
                            function,
                            head.facts.session,
                            head.facts.capture,
                            head.position,
                        )
                    });
                let end = step.phase() == SealReplayPhase::End
                    && !call.abandoned
                    && call.end_cut.is_some()
                    && step.cut() == call.end_cut;
                let loss = step.phase() == SealReplayPhase::BoundedLoss
                    && call.abandoned
                    && call.end_cut.is_none()
                    && step.cut().is_some();
                if !exact || (!end && !loss) {
                    self.correlation_refusals = self.correlation_refusals.saturating_add(1);
                    return (SealBatchProgress::Held, refused);
                }
                // The immutable original span/subject is checked before any
                // frontier, head, counter, reducer or resource mutation.
                let Some(effects) = seal.effects_for_step(step) else {
                    return (SealBatchProgress::Held, refused);
                };
                *remaining -= 1;
                let head = self.staged.pop_front().expect("exact original checked");
                self.frontier = head.position;
                if loss {
                    // An earlier-emitted B loss can wait behind A's actual
                    // End. Its late exact-head S1 invalidation is distinct
                    // from its already-applied object-retirement span.
                    self.dispose_as_loss(
                        reducer,
                        keyuse,
                        instance,
                        sink,
                        Some(&mut *ledger),
                        assoc_fallback.as_deref_mut(),
                    );
                    self.history_disposed = self.history_disposed.saturating_add(1);
                    head.release(ledger);
                    disposed += 1;
                    continue;
                }
                self.redeemed = self.redeemed.saturating_add(1);
                let receipts = keyuse.receipts_for_effects(effects, call, head.position);
                let completion = KeyUseReducer::completion_evidence_for_effects(effects, call);
                let early_release = head.resource_origin.is_none() && !ledger.has_reserver();
                if early_release {
                    ledger.release(head.position, head.charged_bytes());
                }
                let outcome = {
                    let mut tee = KeyUseTee {
                        outer: sink,
                        keyuse,
                        instance,
                        shared: Some(&mut *ledger),
                        fallback: assoc_fallback.as_deref_mut(),
                        source: head.resource_origin.as_ref(),
                    };
                    match reducer.observe_joint_with_resources(
                        &head.facts,
                        &head.origin,
                        &receipts,
                        &completion,
                        &mut tee,
                    ) {
                        Ok(count) => {
                            self.reduced = self.reduced.saturating_add(1);
                            refused = refused.saturating_add(count);
                            true
                        }
                        Err(_) => {
                            reducer.invalidate_with_effects(&mut tee);
                            self.history_disposed = self.history_disposed.saturating_add(1);
                            false
                        }
                    }
                };
                if early_release {
                    drop(head);
                } else {
                    head.release(ledger);
                }
                if outcome {
                    replayed += 1;
                } else {
                    disposed += 1;
                }
                continue;
            }
            // An unrelated loss subject cannot hide a later End needed by
            // the admission head. Work through the SAME original spans once.
            let Some(effect) = batch.advance_effect() else {
                return (SealBatchProgress::Held, refused);
            };
            *remaining -= 1;
            if let Some(effect) = effect {
                keyuse.apply_invalidation(effect, model);
            }
        }
    }

    /// Classify the complete original negative union before any frontier,
    /// role or mode mutation. The frame's one cursor applies both effect
    /// spans once and yields after at most one exact staged-head disposition.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_failure_batch<S: OperationSink>(
        &mut self,
        batch: &mut crate::semantics_objects::journal::joint_audit::FailureBatchDelivery<'_>,
        model: &ObjectSemantics,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        instance: RegistryInstanceId,
        sink: &mut S,
        mut assoc_fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        remaining: &mut usize,
    ) -> (FailureBatchProgress, u64) {
        let audited = batch.audited();
        if self.selected_receipt.as_ref().map(BootstrapReceipt::domain) != Some(audited.domain())
            || !audited.matches_ledger(ledger)
            || !self.accepts_failure(audited.failure())
            || (self.mode == FeedMode::S1Only && !self.staged.is_empty())
        {
            return (FailureBatchProgress::Held, 0);
        }
        let disposition = audited.disposition();
        let gap = audited.failure().gap;
        let fence = audited.fence();
        let covered = matches!(audited.h3(), H3DispositionEvidence::Clean {
            staged_max, pending_floor: None,
        } if self.covered_by(*staged_max));
        self.flush_pending_releases(ledger);
        while !batch.effects_complete() {
            if *remaining == 0 {
                return (FailureBatchProgress::Yielded, 0);
            }
            let Some(effect) = batch.advance_effect() else {
                return (FailureBatchProgress::Held, 0);
            };
            *remaining -= 1;
            if let Some(effect) = effect {
                keyuse.apply_invalidation(effect, model);
            }
        }
        let loss = disposition == SealFailureDisposition::HistoryLoss;
        if self.mode == FeedMode::Joint && disposition == SealFailureDisposition::Retry {
            return (
                FailureBatchProgress::Complete(FailureApplyOutcome::Retried),
                0,
            );
        }
        // A fenced failure is a void: the lost interval is explicit,
        // so the feed closes on its fence instead of holding for a
        // completeness the void already denied. Only an unfenced
        // fallback waits.
        if self.mode == FeedMode::Joint
            && disposition == SealFailureDisposition::Fallback
            && !covered
            && fence.is_none()
        {
            return (
                FailureBatchProgress::Complete(FailureApplyOutcome::HeldForCompleteness),
                0,
            );
        }
        if loss && batch.needs_loss_invalidation() {
            if *remaining == 0 {
                return (FailureBatchProgress::Yielded, 0);
            }
            *remaining -= 1;
            self.dispose_as_loss(
                reducer,
                keyuse,
                instance,
                sink,
                Some(&mut *ledger),
                assoc_fallback.as_deref_mut(),
            );
            batch.loss_started();
        }
        if self.mode == FeedMode::S1Only {
            // Mode only gates positive replay. A retained selected receipt
            // still binds later original negatives to this exact history.
            // S1Only never owns a staged suffix; refuse before completing if
            // that invariant is broken rather than discarding any head.
            if loss {
                self.degraded_loss = true;
                self.degraded_window = Some(DegradedWindow::Loss);
            }
            // A void that lands on an already-degraded feed still records
            // its fence (running maximum): a below-fence receipt never
            // resumes onto any voided interval, however the feed first
            // degraded.
            self.record_fence(fence);
            return (
                batch.negative_delivered().map_or(
                    FailureBatchProgress::Held,
                    FailureBatchProgress::NegativeDelivered,
                ),
                0,
            );
        }
        if self.staged.is_empty() {
            self.close_segment(loss, segment_resumable_after(gap), fence);
            return (
                FailureBatchProgress::Complete(if loss {
                    FailureApplyOutcome::Degraded { disposed: 0 }
                } else {
                    FailureApplyOutcome::FellBack { replayed: 0 }
                }),
                0,
            );
        }
        if *remaining == 0 {
            return (FailureBatchProgress::Yielded, 0);
        }
        *remaining -= 1;
        let head = self.staged.pop_front().expect("retained original head");
        self.frontier = head.position;
        let mut refused = 0;
        let mut replayed = false;
        if loss || batch.resource_failed() {
            self.history_disposed = self.history_disposed.saturating_add(1);
            head.release(ledger);
        } else {
            let early_release = head.resource_origin.is_none() && !ledger.has_reserver();
            if early_release {
                ledger.release(head.position, head.charged_bytes());
            }
            {
                let mut tee = KeyUseTee {
                    outer: sink,
                    keyuse,
                    instance,
                    shared: Some(&mut *ledger),
                    fallback: assoc_fallback,
                    source: head.resource_origin.as_ref(),
                };
                match reducer.observe_joint_with_resources(
                    &head.facts,
                    &head.origin,
                    &[],
                    &crate::keymeta::CompletionEvidence::NONE,
                    &mut tee,
                ) {
                    Ok(count) => {
                        refused = count;
                        replayed = true;
                        self.reduced = self.reduced.saturating_add(1);
                        self.fallback_replayed = self.fallback_replayed.saturating_add(1);
                    }
                    Err(_) => {
                        reducer.invalidate_with_effects(&mut tee);
                        self.history_disposed = self.history_disposed.saturating_add(1);
                        batch.note_resource_failure();
                    }
                }
            }
            if early_release {
                drop(head);
            } else {
                head.release(ledger);
            }
        }
        if self.staged.is_empty() {
            self.close_segment(loss, segment_resumable_after(gap), fence);
            (
                FailureBatchProgress::Complete(if loss {
                    FailureApplyOutcome::Degraded { disposed: 1 }
                } else {
                    FailureApplyOutcome::FellBack {
                        replayed: usize::from(replayed),
                    }
                }),
                refused,
            )
        } else {
            (FailureBatchProgress::Yielded, refused)
        }
    }

    /// Lower-level algorithm controls only. It creates no AuditedFailure and
    /// is absent from production; real-frame tests cover canonical custody.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_algorithm_failure_for_test<S: OperationSink>(
        &mut self,
        failure: &SealFailure,
        finalizer: &mut impl H3EvidenceSource,
        model: &ObjectSemantics,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        instance: RegistryInstanceId,
        sink: &mut S,
        assoc_fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> (FailureApplyOutcome, u64) {
        let h3 = if self.mode == FeedMode::Joint
            && self.accepts_failure(failure)
            && disposition_of(failure.gap) == SealFailureDisposition::Fallback
        {
            finalizer.take_h3_disposition()
        } else {
            H3DispositionEvidence::genesis()
        };
        self.apply_failure_inner(
            failure,
            &h3,
            model,
            ledger,
            reducer,
            keyuse,
            instance,
            sink,
            assoc_fallback,
        )
    }

    /// Apply one seal failure: real loss invalidates live operation
    /// authority before history-only disposal, preserving observed
    /// S1 completions as unknown-key rows beside the counted loss;
    /// proof-only refusal with an explicit complete H3 stream
    /// replays retained calls once in order through ordinary S1;
    /// anything transient or completeness-unproven holds staging
    /// intact. The H3 receipt is borrowed from the same original
    /// completed audit; this path never takes the finalizer again.
    /// Invalidation terminals and fallback effects feed the key-use
    /// reducer too (open rows close as Unknown on loss; fallback
    /// rows are unknown-key S1Only — object facts are never
    /// invented in fallback). Returns the outcome plus fallback
    /// per-edge bound refusals for `semantic_refused`.
    #[allow(clippy::too_many_arguments)] // Staging borrows the exact pipeline facts plus the model for retirement.
    #[cfg(test)]
    fn apply_failure_inner<S: OperationSink>(
        &mut self,
        failure: &SealFailure,
        h3: &H3DispositionEvidence,
        model: &ObjectSemantics,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        instance: RegistryInstanceId,
        sink: &mut S,
        mut assoc_fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> (FailureApplyOutcome, u64) {
        // A foreign receipt has no authority even over pending releases.
        if !self.accepts_failure(failure) {
            return (FailureApplyOutcome::Ignored, 0);
        }
        // Ledger contact flushes pended releases first (C4).
        self.flush_pending_releases(ledger);
        // Matching old-domain contact may release already-owned charges,
        // but a degraded feed never consumes semantic evidence again.
        if self.mode != FeedMode::Joint {
            return (FailureApplyOutcome::Ignored, 0);
        }
        match disposition_of(failure.gap) {
            SealFailureDisposition::Retry => {
                // Transient waits keep staging, but never swallow
                // the refusal's own invalidations (N3).
                keyuse.apply_invalidations(&failure.effects, model);
                (FailureApplyOutcome::Retried, 0)
            }
            SealFailureDisposition::HistoryLoss => {
                // The failure's own invalidations close affected key
                // associations BEFORE loss disposal emits their
                // Unknown terminals (H9 §66).
                keyuse.apply_invalidations(&failure.effects, model);
                self.dispose_as_loss(
                    reducer,
                    keyuse,
                    instance,
                    sink,
                    Some(&mut *ledger),
                    assoc_fallback.as_deref_mut(),
                );
                // Bulk loss disposal preserves observed S1
                // completions as unknown-key rows beside the counted
                // `record_lost`; custody still releases to the ledger
                // and association mints ride the fallback (the ledger
                // cannot back both roles at once).
                let disposed = self.preserve_and_dispose_below_barrier(
                    None,
                    Some(ledger),
                    instance,
                    keyuse,
                    None,
                    assoc_fallback.as_deref_mut(),
                );
                self.close_segment(true, segment_resumable_after(failure.gap), failure.fence);
                (FailureApplyOutcome::Degraded { disposed }, 0)
            }
            SealFailureDisposition::Fallback => {
                match h3 {
                    H3DispositionEvidence::Clean {
                        staged_max,
                        pending_floor: None,
                    } if self.covered_by(*staged_max) => {
                        // Fallback replays staged S1 without object
                        // proof: the failure's invalidations close
                        // affected associations FIRST, so replayed
                        // terminals cannot complete unproved bindings.
                        keyuse.apply_invalidations(&failure.effects, model);
                        let (replayed, refused) = self.replay_staged(
                            reducer,
                            keyuse,
                            instance,
                            sink,
                            Some(&mut *ledger),
                            assoc_fallback.as_deref_mut(),
                        );
                        self.close_segment(
                            false,
                            segment_resumable_after(failure.gap),
                            failure.fence,
                        );
                        (FailureApplyOutcome::FellBack { replayed }, refused)
                    }
                    H3DispositionEvidence::StagedLoss { .. } | H3DispositionEvidence::Exhausted => {
                        // H3's own stream is lossy, so object proof
                        // for the staged calls is gone with it:
                        // real-loss treatment (invalidate, then
                        // dispose), with their observed S1
                        // completions preserved as unknown-key rows
                        // beside the counted `record_lost`.
                        keyuse.apply_invalidations(&failure.effects, model);
                        self.dispose_as_loss(
                            reducer,
                            keyuse,
                            instance,
                            sink,
                            Some(&mut *ledger),
                            assoc_fallback.as_deref_mut(),
                        );
                        let disposed = self.preserve_and_dispose_below_barrier(
                            None,
                            Some(ledger),
                            instance,
                            keyuse,
                            None,
                            assoc_fallback,
                        );
                        self.close_segment(
                            true,
                            segment_resumable_after(failure.gap),
                            failure.fence,
                        );
                        (FailureApplyOutcome::Degraded { disposed }, 0)
                    }
                    _ => {
                        // Completeness holds keep staging, but never
                        // swallow the refusal's own invalidations
                        // (N3).
                        keyuse.apply_invalidations(&failure.effects, model);
                        (FailureApplyOutcome::HeldForCompleteness, 0)
                    }
                }
            }
        }
    }

    /// Whether an H3 Clean receipt covers every staged position: the
    /// explicit completeness the fallback requires.
    fn covered_by(&self, staged_max: u64) -> bool {
        self.staged
            .back()
            .is_none_or(|call| call.position <= staged_max)
    }

    /// Flush ledger-less fallback releases on ledger contact (C4).
    pub(crate) fn flush_pending_releases(
        &mut self,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) {
        for (native, ticket, bytes) in self.pending_releases.drain(..) {
            match native {
                Some(native) => ledger.release_collected(native, ticket),
                None => ledger.release(ticket, bytes),
            }
        }
    }

    /// Dispose staged payloads at or below `barrier` as history-only
    /// (C5): counted, frontier-advanced, never reduced, never
    /// re-staged. Payloads above the barrier stay queued for their
    /// seals. `None` (a barrier-less exhaustion void) disposes
    /// everything: nothing above an unknown void is provable.
    /// Releases go to the ledger when present, else pend for the
    /// next ledger contact. Returns the disposed count. Test-only:
    /// production C5 preserves observed completions through
    /// [`Self::preserve_and_dispose_below_barrier`]; this pure form
    /// is the tests' barrier/frontier/custody handle.
    #[cfg(test)]
    pub(crate) fn dispose_below_barrier(
        &mut self,
        barrier: Option<u64>,
        ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> usize {
        self.dispose_pure_below_barrier(barrier, ledger)
    }

    /// The pure disposal core shared by the test-only handle above
    /// and the ledger-less preservation fallback below: pop heads at
    /// or below `barrier`, release custody, advance the frontier and
    /// count disposed history. Never reduces.
    fn dispose_pure_below_barrier(
        &mut self,
        barrier: Option<u64>,
        mut ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> usize {
        let mut disposed = 0;
        while let Some(front) = self.staged.front() {
            if !barrier.is_none_or(|at| front.position <= at) {
                break;
            }
            let head = self.staged.pop_front().expect("front verified above");
            let bytes = head.charged_bytes();
            let (position, native) = (head.position, head.resource_native);
            drop(head);
            self.release_or_pend(ledger.as_deref_mut(), position, bytes, native);
            self.frontier = self.frontier.max(position);
            self.history_disposed = self.history_disposed.saturating_add(1);
            disposed += 1;
        }
        disposed
    }

    /// Dispose staged payloads at or below `barrier` like
    /// [`Self::dispose_below_barrier`], but preserve their observed
    /// S1 completions first: each popped head reduces through a
    /// throwaway S1 — never the live reducer, so live machines,
    /// counts and pairing are untouched — with effects into a
    /// throwaway key-use reducer, which then invalidates (truncated
    /// opens close as Unknown, never fabricated completions) and
    /// merges its unknown summaries and evidence into `keyuse`.
    /// Every popped head still advances the frontier, releases
    /// custody and counts as disposed history (`record_lost`); late
    /// seals hold as before. Payloads above the barrier stay queued.
    /// Without any association ledger (direct unit-test delivery
    /// only; production always carries the scene fallback) there is
    /// nothing to mint preserved associations from, so disposal
    /// stays pure counts-only. Returns the disposed count.
    pub(crate) fn preserve_and_dispose_below_barrier(
        &mut self,
        barrier: Option<u64>,
        mut ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        instance: RegistryInstanceId,
        keyuse: &mut KeyUseReducer,
        shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> usize {
        if shared.is_none() && fallback.is_none() {
            return self.dispose_pure_below_barrier(barrier, ledger);
        }
        let mut throwaway = EdgeSemantics::default();
        let mut preserved = KeyUseReducer::new();
        let mut outer = NoSink;
        let mut disposed = 0;
        {
            let mut tee = KeyUseTee::new(&mut outer, &mut preserved, instance, shared, fallback);
            while let Some(front) = self.staged.front() {
                if !barrier.is_none_or(|at| front.position <= at) {
                    break;
                }
                let head = self.staged.pop_front().expect("front verified above");
                throwaway.observe_with_effects(&head.facts, &head.origin, &mut tee);
                let bytes = head.charged_bytes();
                let (position, native) = (head.position, head.resource_native);
                drop(head);
                self.release_or_pend(ledger.as_deref_mut(), position, bytes, native);
                self.frontier = self.frontier.max(position);
                self.history_disposed = self.history_disposed.saturating_add(1);
                disposed += 1;
            }
            throwaway.invalidate_with_effects(&mut tee);
        }
        keyuse.absorb_preserved(preserved);
        disposed
    }

    /// Release one popped head's ticket and bytes to the ledger when
    /// present, else pend it for the next ledger contact (C4).
    fn release_or_pend(
        &mut self,
        ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        position: u64,
        bytes: u64,
        native: Option<crate::attach::capture::NativeDomainId>,
    ) {
        match ledger {
            Some(ledger) => match native {
                Some(native) => ledger.release_collected(native, position),
                None => ledger.release(position, bytes),
            },
            None => self.pending_releases.push((native, position, bytes)),
        }
    }

    /// Ordered capacity fallback (C4): replay every retained payload
    /// once in original H3 order through ordinary S1 (no receipts —
    /// fallback rows are unknown-key, never invented object facts),
    /// then continue S1Only. The driver calls this when staging
    /// cannot hold the order (Full, missing ledger, unsealable with
    /// queued calls): reducing a later fact direct would overtake
    /// queued calls. Releases to the ledger when present, else pends
    /// them for the next ledger contact. Sets `fell_back` (S1
    /// preserved without object proof, like proof-only fallback).
    /// Returns the replay count plus per-edge bound refusals.
    pub(crate) fn ordered_fallback<S: OperationSink>(
        &mut self,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        instance: RegistryInstanceId,
        sink: &mut S,
        ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        assoc_fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> (usize, u64) {
        // Staging order is arrival order (positions strictly ascend),
        // so replaying it is complete by construction — no H3 receipt
        // needed, unlike proof-only fallback across a seal gap.
        let (replayed, refused) =
            self.replay_staged(reducer, keyuse, instance, sink, ledger, assoc_fallback);
        // Ordered fallbacks are local capacity/shape endings: the
        // next clean point may resume Joint for a fresh segment.
        self.close_segment(false, true, None);
        (replayed, refused)
    }

    /// Invalidate live operation authority (terminals first), before
    /// any disposal accounting. Terminals feed the key-use reducer
    /// too, so open rows close as Unknown instead of leaking.
    fn dispose_as_loss<S: OperationSink>(
        &self,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        instance: RegistryInstanceId,
        sink: &mut S,
        shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        let mut tee = KeyUseTee {
            outer: sink,
            keyuse,
            instance,
            shared,
            fallback,
            source: None,
        };
        reducer.invalidate_with_effects(&mut tee);
    }

    /// Replay every retained payload once in original H3 order
    /// through ordinary S1 (S1Only: no receipts — fallback rows are
    /// unknown-key, never invented object facts), reserving H3
    /// resources per replay (N14). Effects feed the key-use reducer
    /// too. Releases to the ledger when present, else pends for the
    /// next ledger contact (C4). On mid-fallback resource refusal,
    /// live S1 invalidates with terminals teed (no leaked opens),
    /// the failed head disposes as history, and every remaining
    /// payload disposes with its observed S1 completion preserved as
    /// an unknown-key row beside the counted `record_lost` (throwaway
    /// S1 — live stays invalidated, exactly like the seal-loss arms).
    /// Returns the replay count plus per-edge bound refusals.
    fn replay_staged<S: OperationSink>(
        &mut self,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        instance: RegistryInstanceId,
        sink: &mut S,
        mut ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        mut assoc_fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> (usize, u64) {
        let mut replayed = 0;
        let mut refused = 0u64;
        while let Some(head) = self.staged.pop_front() {
            let bytes = head.charged_bytes();
            let position = head.position;
            let native = head.resource_native;
            self.frontier = self.frontier.max(position);
            // Legacy heads on a reserver-less ledger carry no
            // resource custody: release the staged charge before
            // replay so the replayed open can mint its association
            // at a byte limit (N15 capacity fallback). Collected
            // heads hold custody through replay: the assoc mint
            // joins the live staged reservation. Legacy heads on a
            // resource-backed ledger keep the same order — their
            // staged charge holds a real lease — but mint
            // separately: source `None` takes no credit and joins
            // nothing. A ledger-less fallback still queues the
            // legacy release early (the unavailable ledger may
            // still hold the lease; nothing is refunded here).
            let legacy = head.resource_origin.is_none();
            let early_release = legacy && !ledger.as_ref().is_some_and(|held| held.has_reserver());
            if early_release {
                self.release_or_pend(ledger.as_deref_mut(), position, bytes, native);
            }
            let failed = {
                let mut tee = KeyUseTee {
                    outer: &mut *sink,
                    keyuse: &mut *keyuse,
                    instance,
                    shared: ledger.as_deref_mut(),
                    fallback: assoc_fallback.as_deref_mut(),
                    source: head.resource_origin.as_ref(),
                };
                match reducer.observe_joint_with_resources(
                    &head.facts,
                    &head.origin,
                    &[],
                    &crate::keymeta::CompletionEvidence::NONE,
                    &mut tee,
                ) {
                    Ok(head_refused) => {
                        refused = refused.saturating_add(head_refused);
                        self.reduced = self.reduced.saturating_add(1);
                        self.fallback_replayed = self.fallback_replayed.saturating_add(1);
                        replayed += 1;
                        false
                    }
                    Err(_) => {
                        reducer.invalidate_with_effects(&mut tee);
                        self.history_disposed = self.history_disposed.saturating_add(1);
                        true
                    }
                }
            };
            drop(head);
            if !early_release {
                self.release_or_pend(ledger.as_deref_mut(), position, bytes, native);
            }
            if failed {
                // Live S1 is already invalidated above, so the
                // throwaway preservation applies unchanged: the
                // remainder rows unknown-key beside its counted
                // loss. Without any association ledger (direct
                // unit-test delivery only) this stays pure
                // counts-only, like the seal-loss arms.
                self.preserve_and_dispose_below_barrier(
                    None,
                    ledger,
                    instance,
                    &mut *keyuse,
                    None,
                    assoc_fallback,
                );
                break;
            }
        }
        (replayed, refused)
    }
}

// ---------------------------------------------------------------------------
// Key-use rows: positional receipts joined to operation transitions
// ---------------------------------------------------------------------------

/// Categories whose S1 activity never binds a key (H9 §62/S3): the
/// reducer drops their receipts at observe time (counted, never
/// silent) and their terminals aggregate as `not_applicable` —
/// existing S1 units, no fabricated missing-key starts.
const NOT_APPLICABLE_CATEGORIES: [&str; 4] =
    ["generate_key", "generate_key_pair", "digest", "direct"];

/// Categories whose receipt-less terminals aggregate as
/// `role_unavailable` (H9 §82): KEM calls without a bound qualified
/// receipt prove no role. Bound qualified KEM receipts resolve
/// independently to their usable metadata outcome; only the
/// receipt-less or unproved terminal maps here. S1 mechanism
/// activity is untouched either way.
const ROLE_UNAVAILABLE_CATEGORIES: [&str; 2] = ["encapsulate", "decapsulate"];

/// Whether an operation category binds key receipts. Generation,
/// ordinary digest and reference-only directs never bind. KEM binds
/// its qualified receipts; receipt-less terminals still partition
/// `role_unavailable` via [`unbound_reason_for`].
pub(crate) fn binds_keys(category: &str) -> bool {
    !NOT_APPLICABLE_CATEGORIES.contains(&category)
}

/// The frozen unknown-key reason for a receipt-less terminal of one
/// category (H9 §82): KEM reports role unavailable, generation and
/// ordinary digest stay not-applicable, everything else is unbound.
pub(crate) fn unbound_reason_for(category: &str) -> &'static str {
    if ROLE_UNAVAILABLE_CATEGORIES.contains(&category) {
        "role_unavailable"
    } else if NOT_APPLICABLE_CATEGORIES.contains(&category) {
        "not_applicable"
    } else {
        "unbound"
    }
}

/// The frozen public unit for one category: message contexts count
/// contexts, never signatures; everything else counts operations.
pub(crate) fn unit_for(category: &str) -> &'static str {
    match category {
        "message_encrypt" | "message_decrypt" | "message_sign" | "message_verify" => {
            "message_contexts"
        }
        _ => "operations",
    }
}

/// The frozen role label for one key role (H9 §82): shared by
/// aggregate reservation and the projection's rows, so admission
/// and publication cannot disagree on buckets.
pub(crate) fn role_label(role: KeyRole) -> &'static str {
    match role {
        KeyRole::OperationKey => "key",
        KeyRole::WrappingKey => "wrapping_key",
        KeyRole::WrappedKey => "wrapped_object",
        KeyRole::BaseKey => "base_key",
        KeyRole::UnwrappingKey => "unwrapping_key",
        KeyRole::EncapsulationKey => "encapsulation_key",
        KeyRole::DecapsulationKey => "decapsulation_key",
        KeyRole::Other => "other",
    }
}

/// The frozen metadata-at-use label for one established key label:
/// shared by aggregate reservation and the projection's rows, so
/// admission and publication cannot disagree on buckets.
pub(crate) fn metadata_label(label: crate::semantics_objects::KeyLabel) -> &'static str {
    use crate::semantics_objects::KeyLabel;
    use crate::semantics_objects::PqcCode;
    use p11scope_ebpf_common::object_policy::SafeCurve;
    match label {
        KeyLabel::Rsa { modulus_bits } => match modulus_bits {
            1024 => "rsa_1024",
            2048 => "rsa_2048",
            3072 => "rsa_3072",
            4096 => "rsa_4096",
            _ => "rsa_other",
        },
        KeyLabel::Aes { value_len } => match value_len {
            16 => "aes_128",
            24 => "aes_192",
            32 => "aes_256",
            _ => "aes_other",
        },
        KeyLabel::Ec { curve } => match curve {
            SafeCurve::Secp256r1 => "ec_p256",
            SafeCurve::Secp384r1 => "ec_p384",
            SafeCurve::Secp521r1 => "ec_p521",
            // R2 new-site: Montgomery/Edwards curve names.
            SafeCurve::X25519 => "x25519",
            SafeCurve::X448 => "x448",
            SafeCurve::Ed25519 => "ed25519",
            SafeCurve::Ed448 => "ed448",
            // Relaxed-dialect fix1 (v9): secp256k1 + brainpool.
            SafeCurve::Secp256k1 => "ec_secp256k1",
            SafeCurve::BrainpoolP256r1 => "ec_brainpoolp256r1",
            SafeCurve::BrainpoolP384r1 => "ec_brainpoolp384r1",
        },
        // R2 new-site: HKDF and generic-secret sizes in bits.
        KeyLabel::Hkdf { value_len } => match value_len {
            12 => "hkdf_96",
            16 => "hkdf_128",
            24 => "hkdf_192",
            32 => "hkdf_256",
            48 => "hkdf_384",
            _ => "hkdf_other",
        },
        KeyLabel::GenericSecret { value_len } => match value_len {
            12 => "generic_96",
            16 => "generic_128",
            24 => "generic_192",
            32 => "generic_256",
            48 => "generic_384",
            _ => "generic_other",
        },
        // F16 (7.05 PQC): the closed eighteen-value vocabulary,
        // exhaustive by construction (see `PqcCode`).
        KeyLabel::Pqc(code) => match code {
            PqcCode::MlDsa44 => "ml_dsa_44",
            PqcCode::MlDsa65 => "ml_dsa_65",
            PqcCode::MlDsa87 => "ml_dsa_87",
            PqcCode::MlKem512 => "ml_kem_512",
            PqcCode::MlKem768 => "ml_kem_768",
            PqcCode::MlKem1024 => "ml_kem_1024",
            PqcCode::SlhDsaSha2128s => "slh_dsa_sha2_128s",
            PqcCode::SlhDsaShake128s => "slh_dsa_shake_128s",
            PqcCode::SlhDsaSha2128f => "slh_dsa_sha2_128f",
            PqcCode::SlhDsaShake128f => "slh_dsa_shake_128f",
            PqcCode::SlhDsaSha2192s => "slh_dsa_sha2_192s",
            PqcCode::SlhDsaShake192s => "slh_dsa_shake_192s",
            PqcCode::SlhDsaSha2192f => "slh_dsa_sha2_192f",
            PqcCode::SlhDsaShake192f => "slh_dsa_shake_192f",
            PqcCode::SlhDsaSha2256s => "slh_dsa_sha2_256s",
            PqcCode::SlhDsaShake256s => "slh_dsa_shake_256s",
            PqcCode::SlhDsaSha2256f => "slh_dsa_sha2_256f",
            PqcCode::SlhDsaShake256f => "slh_dsa_shake_256f",
        },
    }
}

/// The usable metadata-at-use label (H9 §72): resolved-only (own
/// established or pair-inherited size), valid attribution,
/// non-conflicting required fields. Decides
/// admission: usable receipts reserve proved aggregate buckets;
/// unusable ones count in fixed unknown summaries. Later-learned
/// metadata never rewrites a bucket's label: receipts carry the
/// join-time snapshot, and each label is its own bucket.
fn usable_label(receipt: &KeyReceipt) -> Option<&'static str> {
    use crate::semantics_objects::KeyLabel;
    use p11scope_ebpf_common::object_policy::SafeAttributeKind;
    if !receipt.attribution_valid {
        return None;
    }
    let label = receipt.label?;
    let required = match label {
        KeyLabel::Aes { .. } => {
            (1 << crate::semantics_objects::field_index(SafeAttributeKind::Class))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::KeyType))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::ValueLen))
        }
        KeyLabel::Rsa { .. } => {
            (1 << crate::semantics_objects::field_index(SafeAttributeKind::Class))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::KeyType))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::ModulusBits))
        }
        KeyLabel::Ec { .. } => {
            (1 << crate::semantics_objects::field_index(SafeAttributeKind::Class))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::KeyType))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::EcParams))
        }
        // R2 new-site: HKDF and generic-secret labels need their
        // class, key type and value length all non-conflicting.
        KeyLabel::Hkdf { .. } | KeyLabel::GenericSecret { .. } => {
            (1 << crate::semantics_objects::field_index(SafeAttributeKind::Class))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::KeyType))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::ValueLen))
        }
        // F16 (7.05 PQC): a usable PQC label needs its class, key
        // type and parameter set all non-conflicting.
        KeyLabel::Pqc(..) => {
            (1 << crate::semantics_objects::field_index(SafeAttributeKind::Class))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::KeyType))
                | (1 << crate::semantics_objects::field_index(SafeAttributeKind::ParameterSet))
        }
    };
    if receipt.metadata.conflicted & required != 0 {
        return None;
    }
    Some(metadata_label(label))
}

/// The metadata label a receipt rows under: its usable established
/// label, or — for any proved object (first-observed under DEMO-4
/// late attach, or created in the observed window but never given an
/// established type/size, such as a key whose creation template
/// omitted the type or whose attributes were never read back) with
/// valid attribution, no established label and no metadata conflict
/// — the honest `unknown` label. The per-key row is kept with the
/// object id and its exact counts; no type or size is guessed
/// (incomplete requested triples still never label; complete ones
/// establish on successful creation per the v3 R2 amendment). Calls
/// happened on a proved key, so its row shows. Later learned
/// metadata never rewrites this snapshot: a later use after an
/// established attribute read buckets under its own label.
fn row_label(receipt: &KeyReceipt) -> Option<&'static str> {
    if let Some(label) = usable_label(receipt) {
        return Some(label);
    }
    if receipt.attribution_valid && receipt.label.is_none() && receipt.metadata.conflicted == 0 {
        return Some(crate::key_operation_projection::METADATA_UNKNOWN);
    }
    None
}

/// The unknown reason for an unusable label: any conflict at use
/// reports conflicting, otherwise unknown.
fn metadata_reason(receipt: &KeyReceipt) -> &'static str {
    if receipt.metadata.conflicted != 0 {
        "metadata_conflicting"
    } else {
        "metadata_unknown"
    }
}

/// One retained proved-key aggregate bucket key: (instance, object,
/// category, role, metadata_at_use) (H9 §81). The 65,536 ceiling
/// counts these keys: operations sharing one update its counters
/// without new slots; roles and metadata-at-use labels are separate
/// buckets. Carries no raw handles (the object is the opaque exact
/// observation) and no metadata values (frozen labels only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AggKey {
    pub instance: RegistryInstanceId,
    pub object: u64,
    pub category: &'static str,
    pub role: &'static str,
    pub metadata: &'static str,
}

/// One retained proved-key aggregate's counters. The row equation
/// `started = completed + failed + cancelled + unknown + active +
/// key_join_lost` holds before counter saturation. Buckets are
/// never evicted: refused associations land in fixed counters, and
/// terminal increments move within the reserved bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AggCounters {
    pub started: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub unknown: u64,
    pub active: u64,
    pub key_join_lost: u64,
}

impl AggCounters {
    fn add(&mut self, outcome: OperationOutcome) {
        match outcome {
            OperationOutcome::Completed => self.completed = self.completed.saturating_add(1),
            OperationOutcome::Failed => self.failed = self.failed.saturating_add(1),
            OperationOutcome::Cancelled => self.cancelled = self.cancelled.saturating_add(1),
            OperationOutcome::Unknown => self.unknown = self.unknown.saturating_add(1),
        }
    }
}

/// Bounded mechanism ids per unknown summary (controller ruling
/// fix2, F3): at most eight distinct ids in first-seen order.
pub(crate) const UNKNOWN_MECHS_PER_BUCKET: usize = 8;

/// One fixed unknown-key summary's counters (H9 §82): terminal
/// outcomes partitioned once per primary operation role, plus live
/// unknown-key activity, plus the bounded mechanism ids of this
/// bucket's terminals. Fixed vocabulary — always admitted, never
/// a positive row, never a capacity refusal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UnknownCounters {
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub unknown: u64,
    pub active: u64,
    /// Distinct mechanism ids in first-seen order with per-id
    /// terminal counts; only the first `mechs_len` slots read.
    pub mechs: [(u64, u64); UNKNOWN_MECHS_PER_BUCKET],
    pub mechs_len: u8,
    /// Terminals whose ids fell past the eight listed: an exact
    /// terminal count (never a distinct-id guess), so merges add
    /// exactly and row totals always reconcile.
    pub further_mechanism_terminals: u64,
}

impl UnknownCounters {
    fn add(&mut self, outcome: OperationOutcome) {
        match outcome {
            OperationOutcome::Completed => self.completed = self.completed.saturating_add(1),
            OperationOutcome::Failed => self.failed = self.failed.saturating_add(1),
            OperationOutcome::Cancelled => self.cancelled = self.cancelled.saturating_add(1),
            OperationOutcome::Unknown => self.unknown = self.unknown.saturating_add(1),
        }
    }

    /// Record one terminal's mechanism id: repeat ids count up,
    /// new ids append in first-seen order, and ids past the eight
    /// listed count their terminals exactly in
    /// `further_mechanism_terminals`.
    fn add_mech(&mut self, id: u64) {
        for slot in self.mechs.iter_mut().take(self.mechs_len as usize) {
            if slot.0 == id {
                slot.1 = slot.1.saturating_add(1);
                return;
            }
        }
        if (self.mechs_len as usize) < UNKNOWN_MECHS_PER_BUCKET {
            self.mechs[self.mechs_len as usize] = (id, 1);
            self.mechs_len += 1;
        } else {
            self.further_mechanism_terminals = self.further_mechanism_terminals.saturating_add(1);
        }
    }

    /// Merge another bucket's mechanism ids (bulk-disposal
    /// preservation): listed counts add per id in first-seen
    /// order, and overflow terminals add exactly.
    fn absorb_mechs(&mut self, other: &Self) {
        for (id, count) in other.mechs.iter().take(other.mechs_len as usize) {
            let mut placed = false;
            for slot in self.mechs.iter_mut().take(self.mechs_len as usize) {
                if slot.0 == *id {
                    slot.1 = slot.1.saturating_add(*count);
                    placed = true;
                    break;
                }
            }
            if !placed {
                if (self.mechs_len as usize) < UNKNOWN_MECHS_PER_BUCKET {
                    self.mechs[self.mechs_len as usize] = (*id, *count);
                    self.mechs_len += 1;
                } else {
                    self.further_mechanism_terminals =
                        self.further_mechanism_terminals.saturating_add(*count);
                }
            }
        }
        self.further_mechanism_terminals = self
            .further_mechanism_terminals
            .saturating_add(other.further_mechanism_terminals);
    }

    /// Whether any counter is nonzero: only live summaries publish.
    pub(crate) fn is_live(&self) -> bool {
        self.completed != 0
            || self.failed != 0
            || self.cancelled != 0
            || self.unknown != 0
            || self.active != 0
    }
}

/// The fixed unknown-summary category vocabulary: every S1 category
/// the reducer can observe (11 machine + 9 direct + the
/// `operation` / `direct` / `unknown` fallbacks). Mirrors the frozen
/// contract table; the schema contract test pins them equal.
pub(crate) const UNKNOWN_CATEGORIES: [&str; 23] = [
    "digest",
    "sign",
    "verify",
    "encrypt",
    "decrypt",
    "sign_recover",
    "verify_recover",
    "message_encrypt",
    "message_decrypt",
    "message_sign",
    "message_verify",
    "generate_key",
    "generate_key_pair",
    "wrap",
    "unwrap",
    "derive",
    "encapsulate",
    "decapsulate",
    "wrap_authenticated",
    "unwrap_authenticated",
    "operation",
    "direct",
    "unknown",
];

/// The fixed unknown-summary reason vocabulary (H9 §82). Mirrors
/// the frozen contract table; the schema contract test pins them
/// equal.
pub(crate) const UNKNOWN_REASONS: [&str; 6] = [
    "unbound",
    "key_join_lost",
    "metadata_unknown",
    "metadata_conflicting",
    "role_unavailable",
    "not_applicable",
];

/// Fixed unknown summaries: every category × reason pair exists, so
/// terminal increments never allocate. Index `category * 6 + reason`
/// in the tables above.
pub(crate) const UNKNOWN_BUCKETS: usize = 23 * 6;

/// The fixed-summary index for one (category, reason) pair. Total:
/// S1 categories and reducer reasons always land in-vocabulary (a
/// debug assertion guards that), and anything else folds into the
/// `unknown`/`unbound` summary rather than allocating or refusing.
fn unknown_index(category: &str, reason: &str) -> usize {
    let cat = UNKNOWN_CATEGORIES
        .iter()
        .position(|known| *known == category)
        .unwrap_or_else(|| {
            debug_assert!(false, "S1 categories stay within the frozen 23");
            UNKNOWN_CATEGORIES
                .iter()
                .position(|known| *known == "unknown")
                .expect("frozen fallback row")
        });
    let why = UNKNOWN_REASONS
        .iter()
        .position(|known| *known == reason)
        .unwrap_or_else(|| {
            debug_assert!(false, "unknown reasons stay within the frozen 6");
            UNKNOWN_REASONS
                .iter()
                .position(|known| *known == "unbound")
                .expect("frozen fallback reason")
        });
    cat * UNKNOWN_REASONS.len() + why
}

/// Explicit key-use evidence: association outcomes, never silent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KeyUseEvidence {
    /// Admitted receipt-less operations at terminal (S1Only starts,
    /// unassociated starts, async starts): definite S1, unknown key.
    pub unknown_key_rows: u64,
    /// Ends observed without their start (stream splice; unreachable
    /// from one reducer pass): fixed-counter outcomes, no fabricated
    /// starts.
    pub orphan_ends: u64,
    /// Receipts outside the classified role vocabulary.
    pub unclassified_roles: u64,
    /// True once any association was refused at full budget: the
    /// projection's semantic coverage is PARTIAL from then on.
    pub partial: bool,
    /// Associations refused at N+1 (started or direct-completed
    /// without a reserved aggregate slot): S1 preserved, key row
    /// omitted.
    pub rows_refused: u64,
    /// Terminals that landed without a reserved bucket (refused
    /// starts and refused directs): counted, allocation-free, never
    /// rows.
    pub refused_terminals: u64,
    /// Receipts dropped because their category never binds keys
    /// (generation, ordinary digest, reference-only directs, KEM).
    pub dropped_receipts: u64,
    /// Active associations ended by retirement before their S1
    /// terminal (`key_join_lost` applications).
    pub join_lost: u64,
    /// Exact duplicate starts refused without touching the retained
    /// custody (same instance and operation identity delivered
    /// twice): counted, never an overwrite.
    pub duplicate_starts: u64,
    /// Terminal lengths disagreeing with the operation's retained
    /// corroboration (keymeta §5.4): counted as the named
    /// `corroboration_mismatch` residual, never a conflict.
    pub corroboration_mismatches: u64,
    /// Wrapped-material parks refused past the park budget (the
    /// aggregate capacity): counted as the named
    /// `wrapped_park_refused` gap, never silent, never a row, never
    /// coverage loss.
    pub parked_refused: u64,
}

/// One inferred key's lifecycle status (keymeta §10.2): unknown
/// (no evidence, or evidence outside every map), inferred, conflicting
/// (two distinct values, or an incompatible established fact), or
/// unsupported (evidence exists but the subset has no map). Families
/// never report unsupported: unlisted mechanisms are unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum InferredStatus {
    #[default]
    Unknown,
    Inferred,
    Conflicting,
    Unsupported,
}

/// One row's inferred family accumulation (keymeta §4.4): the first
/// value stays pinned with its supporting completions, a second
/// distinct specific family rides the conflict pair, and further
/// distinct values count without listing. The `secret` superclass
/// accumulates beside any family and never flips. `completions`
/// counts every completion carrying family evidence (specific,
/// secret-beside and further values alike); `value_completions`
/// counts the first value's own support for the `-v` pair display.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct FamilyState {
    pub status: InferredStatus,
    pub value: Option<crate::keymeta::KeyFamily>,
    pub completions: u64,
    pub value_completions: u64,
    pub conflict_value: Option<crate::keymeta::KeyFamily>,
    pub conflict_completions: u64,
    pub further: u64,
    pub reason: Option<&'static str>,
    /// Seen further-value bitmask (discriminant bits): repeats never
    /// double-count `further`.
    pub further_seen: u32,
}

/// One row's inferred size accumulation (keymeta §5.4): same
/// keep-first-two-count-extras rule as families. "Same size" means
/// same detail kind plus size params — the evidence tag does not
/// count, and the detail keeps the first tag. `unsupported` never
/// overwrites `inferred` and never flips.
/// RSA further values track exactly in a 1985-bit bitmap (64..=2048
/// modulus octets); wrapped-material further values track exactly in
/// an 8192-bit bitmap (0..=8191 material octets, the
/// [`crate::keymeta::WRAPPED_MATERIAL_MAX`] admission bound); the
/// remaining non-RSA kinds deduplicate in a capped set (their finite
/// total is 20 — 3 EC, 2 EdDSA, 3 DSA, 12 PQC — so the cap never
/// binds them).
pub(crate) const FURTHER_SEEN_CAP: usize = 64;
/// RSA admitted octet bounds (§5.2): 64..=2048 inclusive.
pub(crate) const RSA_FURTHER_MIN: u64 = 64;
pub(crate) const RSA_FURTHER_MAX: u64 = 2048;
/// Bitmap words covering the 1985 RSA octets (32×64).
pub(crate) const RSA_FURTHER_WORDS: usize = 32;
/// Bitmap words covering the 8192 wrapped-material octets (128×64).
pub(crate) const WRAPPED_FURTHER_WORDS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SizeState {
    pub status: InferredStatus,
    pub detail: Option<(crate::keymeta::SizeDetail, crate::keymeta::EvidenceTag)>,
    pub completions: u64,
    pub conflict_detail: Option<(crate::keymeta::SizeDetail, crate::keymeta::EvidenceTag)>,
    pub further: u64,
    pub reason: Option<&'static str>,
    /// Remembered non-RSA, non-wrapped further size details for
    /// repeat suppression (capped at [`FURTHER_SEEN_CAP`]; tags never
    /// compared; the finite kinds total 20, so the cap never binds).
    pub further_seen: Vec<crate::keymeta::SizeDetail>,
    /// Exact RSA further-octet bitmap, bit `octets - 64`.
    pub rsa_further_seen: [u64; RSA_FURTHER_WORDS],
    /// Exact wrapped-material further-octet bitmap, bit
    /// `material_octets`, allocated on the first wrapped further
    /// value: rows without wrapped conflicts carry no bitmap.
    pub wrapped_further_seen: Option<Box<[u64; WRAPPED_FURTHER_WORDS]>>,
}

/// One completion's size input after flag/trailer resolution: the
/// flag is off, the completion carried no trailer, the trailer was
/// BPF-unavailable, or a length value arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SizeInput {
    Off,
    NoEvidence,
    Unavailable,
    Value(u64),
}

/// One proved row's inferred keys (keymeta §10.2): family (both
/// modes) and size (flag-on lengths only).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct RowInference {
    pub family: FamilyState,
    pub size: SizeState,
}

impl RowInference {
    /// Whether either key is non-blank (§10.1 v7 trigger): a valued,
    /// conflicting or unsupported state, or an unknown carrying
    /// completions. Zero-completion reasons (the off-mode hint,
    /// absent evidence) render JSON-identical to blank and never
    /// trigger on their own; `-v` still shows every named reason.
    pub(crate) fn is_v7_content(&self) -> bool {
        let family = self.family.status != InferredStatus::Unknown || self.family.completions > 0;
        let size = self.size.status != InferredStatus::Unknown || self.size.completions > 0;
        family || size
    }
}

/// One parked wrapped-material fact (keymeta §5.4 U1): evidence
/// about a key with no sealed row yet, keyed by its view. The
/// view's first sealed row carries it (forward-fill, never a
/// `metadata_at_use` rewrite); invalidation drops it with the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParkedSize {
    pub detail: crate::keymeta::SizeDetail,
    pub tag: crate::keymeta::EvidenceTag,
}

impl FamilyState {
    /// Accumulate one mechanism-present completion (§4.4): first
    /// value pins with support, a second distinct specific family
    /// rides the conflict pair, further distinct values count once
    /// each, and the `secret` superclass accumulates beside any
    /// family without ever flipping.
    pub(crate) fn accumulate_family(
        &mut self,
        established: Option<crate::keymeta::EstablishedKind>,
        mechanism: u64,
    ) {
        use crate::keymeta::KeyFamily;
        use crate::keymeta::{REASON_UNLISTED_MECHANISM, families_compatible, infer_family};
        // Every mechanism-present terminal is family evidence.
        self.completions = self.completions.saturating_add(1);
        let Some(family) = infer_family(mechanism) else {
            if self.status == InferredStatus::Unknown && self.reason.is_none() {
                self.reason = Some(REASON_UNLISTED_MECHANISM);
            }
            return;
        };
        if family == KeyFamily::Secret {
            // Alone, secret is the value; beside a specific family
            // its count joins the block total without ever flipping.
            if self.value.is_none() && self.status == InferredStatus::Unknown {
                self.value = Some(KeyFamily::Secret);
                self.status = InferredStatus::Inferred;
                self.value_completions = 1;
                self.reason = None;
            }
            return;
        }
        // A specific family upgrades a secret-only value (secret
        // never conflicts, in either direction).
        if self.value == Some(KeyFamily::Secret) {
            self.value = Some(family);
            self.value_completions = 1;
            self.status = InferredStatus::Inferred;
            self.reason = None;
            if let Some(kind) = established
                && !families_compatible(family, mechanism, kind)
            {
                self.status = InferredStatus::Conflicting;
            }
            return;
        }
        match self.value {
            None => {
                // First specific value (blank or reasoned unknown):
                // pin with support, clear any prior unknown reason,
                // then check the frozen established fact (an
                // incompatible pair conflicts with the established
                // side omitted — the label stands on the row).
                self.value = Some(family);
                self.value_completions = 1;
                self.status = InferredStatus::Inferred;
                self.reason = None;
                if let Some(kind) = established
                    && !families_compatible(family, mechanism, kind)
                {
                    self.status = InferredStatus::Conflicting;
                }
            }
            Some(current) if current == family => {
                self.value_completions = self.value_completions.saturating_add(1);
                // Every specific-family completion rechecks its own
                // mechanism qualifier (§4.5): a later ECMQV on a
                // Montgomery key conflicts even though the family name
                // repeats. Only flips to conflicting, never back.
                if let Some(kind) = established
                    && !families_compatible(family, mechanism, kind)
                {
                    self.status = InferredStatus::Conflicting;
                }
            }
            Some(_) => match self.conflict_value {
                None => {
                    self.conflict_value = Some(family);
                    self.conflict_completions = 1;
                    self.status = InferredStatus::Conflicting;
                }
                Some(second) if second == family => {
                    self.conflict_completions = self.conflict_completions.saturating_add(1);
                }
                Some(_) => {
                    let bit = 1u32 << (family as u32);
                    if self.further_seen & bit == 0 {
                        self.further_seen |= bit;
                        self.further = self.further.saturating_add(1);
                    }
                }
            },
        }
    }
}

/// Controller ruling fix2 (F4): seed one proved row's family from
/// the key's creation mechanism when the use provides no valued
/// family for this key and no established label or key type stands
/// against it. The key-type field keeps its own state (no label
/// forms here); the row shows the inferred family. The creation id
/// contributes exactly like any other mechanism evidence through
/// [`FamilyState::accumulate_family`]. `use_mechanism` is the
/// mechanism typing THIS key (`None` for wrapped keys, whose wrap
/// mechanism never applies to them).
fn seed_creation_family(
    family: &mut FamilyState,
    established: Option<crate::keymeta::EstablishedKind>,
    established_type: Option<crate::keymeta::EstablishedKind>,
    use_mechanism: Option<u64>,
    creation_mechanism: Option<u32>,
) {
    use crate::keymeta::infer_family;
    if established.is_some() || established_type.is_some() {
        return;
    }
    if use_mechanism.is_some_and(|id| infer_family(id).is_some()) {
        return;
    }
    let Some(created) = creation_mechanism else {
        return;
    };
    let created = u64::from(created);
    if infer_family(created).is_none() {
        return;
    }
    family.accumulate_family(established_type, created);
}

impl SizeState {
    /// Accumulate one completion's size input (§5.4): valued evidence
    /// upgrades unknowns, same sizes keep the first tag, distinct
    /// sizes conflict with extras counted once each, and
    /// `unsupported` never overwrites `inferred` nor flips.
    /// `established` is the combined size/curve label (exact params);
    /// `established_type` is the key type alone (§4.5 family gate when
    /// no combined label exists).
    pub(crate) fn accumulate_size(
        &mut self,
        established: Option<crate::keymeta::EstablishedKind>,
        established_type: Option<crate::keymeta::EstablishedKind>,
        mechanism: Option<u64>,
        tag: Option<crate::keymeta::EvidenceTag>,
        input: SizeInput,
    ) {
        use crate::keymeta::{
            REASON_LENGTH_UNAVAILABLE, REASON_NO_LENGTH_EVIDENCE, REASON_SIZE_INFERENCE_OFF,
            SizeOutcome, classify_size,
        };
        // The weakest unknowns (no reason yet, or a mode/absence
        // reason) lose to everything; only they accept a new reason.
        let weakest = self.status == InferredStatus::Unknown
            && matches!(
                self.reason,
                None | Some(REASON_SIZE_INFERENCE_OFF) | Some(REASON_NO_LENGTH_EVIDENCE)
            );
        match input {
            SizeInput::Off => {
                if weakest {
                    self.reason = Some(REASON_SIZE_INFERENCE_OFF);
                }
            }
            SizeInput::NoEvidence => {
                if weakest {
                    self.reason = Some(REASON_NO_LENGTH_EVIDENCE);
                }
            }
            SizeInput::Unavailable => {
                self.completions = self.completions.saturating_add(1);
                if weakest {
                    self.reason = Some(REASON_LENGTH_UNAVAILABLE);
                }
            }
            SizeInput::Value(length) => {
                self.completions = self.completions.saturating_add(1);
                let Some(tag) = tag else {
                    // Unreachable: seals trailer only evidence
                    // endpoints, whose categories always map. Treat a
                    // tagless length as absent evidence, never guess.
                    debug_assert!(false, "a classified length always carries its evidence tag");
                    if weakest {
                        self.reason = Some(REASON_NO_LENGTH_EVIDENCE);
                    }
                    return;
                };
                match classify_size(mechanism, tag, length) {
                    SizeOutcome::Unknown { reason } => {
                        if weakest {
                            self.reason = Some(reason);
                        }
                    }
                    SizeOutcome::Unsupported { reason } => {
                        if weakest {
                            self.status = InferredStatus::Unsupported;
                            self.reason = Some(reason);
                        }
                    }
                    SizeOutcome::Inferred(detail) => {
                        self.accumulate_detail(
                            established,
                            established_type,
                            mechanism,
                            tag,
                            detail,
                        );
                    }
                }
            }
        }
    }

    /// Accumulate one classified size detail: first value pins (with
    /// the established-size check), same sizes keep the first tag, a
    /// second distinct size rides the conflict pair, and further
    /// distinct sizes count once each (exact: RSA and wrapped
    /// bitmaps, finite kinds in the capped set).
    fn accumulate_detail(
        &mut self,
        established: Option<crate::keymeta::EstablishedKind>,
        established_type: Option<crate::keymeta::EstablishedKind>,
        mechanism: Option<u64>,
        tag: crate::keymeta::EvidenceTag,
        detail: crate::keymeta::SizeDetail,
    ) {
        use crate::keymeta::{families_compatible, same_size, size_compatible, size_family};
        // `unsupported` pins: a later classified size never flips the
        // row (nor its reason) to inferred or conflicting.
        if self.status == InferredStatus::Unsupported {
            return;
        }
        match self.detail.as_ref() {
            None => {
                self.detail = Some((detail.clone(), tag));
                self.status = InferredStatus::Inferred;
                self.reason = None;
                if let (Some(kind), Some(mechanism)) = (established, mechanism)
                    && !size_compatible(&detail, mechanism, kind)
                {
                    self.status = InferredStatus::Conflicting;
                } else if established.is_none()
                    && let (Some(type_kind), Some(mechanism)) = (established_type, mechanism)
                    && let Some(family) = size_family(&detail)
                    && !families_compatible(family, mechanism, type_kind)
                {
                    // Type-only: no size params to contradict, but the
                    // implied family still gates (§4.5).
                    self.status = InferredStatus::Conflicting;
                }
            }
            Some((current, _)) if same_size(current, &detail) => {
                // Same size: the first tag stands.
            }
            Some(_) => match self.conflict_detail.as_ref() {
                None => {
                    self.conflict_detail = Some((detail, tag));
                    self.status = InferredStatus::Conflicting;
                }
                Some((second, _)) if same_size(second, &detail) => {}
                Some(_) => {
                    // RSA further octets track exactly in the bitmap;
                    // wrapped-material further octets track exactly in
                    // their bitmap; the remaining non-RSA kinds are
                    // finite (20), so the capped set is exact for them.
                    if let crate::keymeta::SizeDetail::Rsa { modulus_bytes, .. } = &detail
                        && (RSA_FURTHER_MIN..=RSA_FURTHER_MAX).contains(modulus_bytes)
                    {
                        let bit = (modulus_bytes - RSA_FURTHER_MIN) as usize;
                        let (word, offset) = (bit / 64, bit % 64);
                        if self.rsa_further_seen[word] & (1u64 << offset) == 0 {
                            self.rsa_further_seen[word] |= 1u64 << offset;
                            self.further = self.further.saturating_add(1);
                        }
                    } else if let crate::keymeta::SizeDetail::WrappedMaterial {
                        material_octets,
                        ..
                    } = &detail
                        && *material_octets <= crate::keymeta::WRAPPED_MATERIAL_MAX
                    {
                        let bit = *material_octets as usize;
                        let (word, offset) = (bit / 64, bit % 64);
                        let seen = self
                            .wrapped_further_seen
                            .get_or_insert_with(|| Box::new([0; WRAPPED_FURTHER_WORDS]));
                        if seen[word] & (1u64 << offset) == 0 {
                            seen[word] |= 1u64 << offset;
                            self.further = self.further.saturating_add(1);
                        }
                    } else if !self
                        .further_seen
                        .iter()
                        .any(|seen| same_size(seen, &detail))
                    {
                        if self.further_seen.len() < FURTHER_SEEN_CAP {
                            self.further_seen.push(detail);
                        }
                        self.further = self.further.saturating_add(1);
                    }
                }
            },
        }
    }
}

/// One open association's bucket: a reserved proved aggregate key
/// or a fixed unknown-summary index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssocBucket {
    Proved(AggKey),
    Unknown(usize),
}

/// One open association: the bucket its terminal will close, the
/// exact key it references (for retirement matching), whether
/// retirement ended its join early, and whether it carries the
/// operation's terminal partition (the primary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenAssoc {
    bucket: AssocBucket,
    key: ObjectId,
    lost: bool,
    primary: bool,
    /// The receipt's frozen combined label (§3 size params),
    /// snapshotted at admission: a later query never re-opens the
    /// compatibility comparison.
    established: Option<crate::keymeta::EstablishedKind>,
    /// The §4.5 left side: the combined label when one exists,
    /// else the receipt's frozen established key type (type-only
    /// receipts). Snapshotted at admission: a later query never
    /// re-opens the comparison.
    established_type: Option<crate::keymeta::EstablishedKind>,
    /// The receipt's frozen creation-mechanism birth fact
    /// (controller ruling fix2, F4): the Generate/GeneratePair
    /// mechanism id in the 32-bit namespace, or `None` for every
    /// other origin.
    creation_mechanism: Option<u32>,
}

/// One receipt resolved to its bucket at admission, before any
/// reservation: the bucket plus whether this receipt is the
/// operation's primary (terminal partition carrier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedAssoc {
    bucket: AssocBucket,
    primary: bool,
}

impl ResolvedAssoc {
    /// Padding for the stack resolution batch: never read (the batch
    /// length guards every access).
    const NONE: Self = Self {
        bucket: AssocBucket::Unknown(usize::MAX),
        primary: false,
    };
}

/// One open (started, unterminated) key association: the buckets its
/// terminal will close. Opens are inherently bounded: one per live
/// machine — every open corresponds to a reducer machine, and every
/// machine end closes exactly its buckets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenKeyUse {
    pub instance: RegistryInstanceId,
    pub category: &'static str,
    pub mechanism: Option<u64>,
    pub started_ts_ns: u64,
    associations: Vec<OpenAssoc>,
    /// Whether any receipt bound (receipt-less opens close to the
    /// unknown-key summary with explicit evidence — never loss).
    bound: bool,
    /// The open's prospective-association ticket plus which ledger
    /// minted it (N1c): ends release to the minting ledger, or pend
    /// a shared release when the shared ledger is absent (C4-style).
    ticket: u64,
    ticket_shared: bool,
}

/// One open association refused at full budget: no slot reserved,
/// S1 still live. Bounded by live machines like [`OpenKeyUse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RefusedOpen {
    pub instance: RegistryInstanceId,
    pub category: &'static str,
    pub started_ts_ns: u64,
    /// The refused start's mechanism (controller ruling fix2, F3):
    /// its terminal lands on the unknown row with this id.
    pub mechanism: Option<u64>,
}

/// The key-use reducer (H9): joins the operation-effect stream to
/// positional receipts into bounded aggregate buckets. Aggregate
/// slots are reserved before admission (`aggregates.len() <=
/// capacity` always): a start or direct needing a new bucket past
/// the bound refuses atomically, while operations sharing retained
/// buckets update their counters without new slots. Terminal
/// increments move within reserved buckets and allocate nothing.
/// Completed history is immutable and never evicted; refused
/// associations land in fixed counters.
///
/// Joins namespace the reducer-local [`OperationId`] by exact
/// instance (H9: the operation identity is the instance/era plus the
/// local ordinal): equal ordinals on sibling instances are disjoint
/// custody, never one entry.
pub(crate) struct KeyUseReducer {
    open: BTreeMap<(RegistryInstanceId, OperationId), OpenKeyUse>,
    refused: BTreeMap<(RegistryInstanceId, OperationId), RefusedOpen>,
    aggregates: BTreeMap<AggKey, AggCounters>,
    /// Boxed: 138 counters ride the heap, not the reducer value.
    /// Scenes hold the reducer by value on test-thread stacks that
    /// already run near the 2 MiB limit; the F3 mechanism ids would
    /// otherwise overflow them (the KEM adapter test pins this).
    unknown: Box<[UnknownCounters; UNKNOWN_BUCKETS]>,
    /// Fixed unknown summaries ever live (N9): once a summary row
    /// emits, its zero-active replacement emits forever after, so the
    /// cumulative consumer never keeps stale activity. Fixed 138
    /// flags — within the finite summary bound, never cleared.
    unknown_ever_live: [bool; UNKNOWN_BUCKETS],
    capacity: usize,
    evidence: KeyUseEvidence,
    /// Per-bucket inferred keys (keymeta §10.2): family (both modes)
    /// and size (flag-on lengths only). Entries exist only beside
    /// proved buckets, so the map never exceeds the aggregate bound.
    inferred: BTreeMap<AggKey, RowInference>,
    /// Wrapped-material parks by viewed object id (keymeta §5.4
    /// U1): evidence about keys with no sealed row yet. Bounded by
    /// the aggregate capacity; invalidation drops the view's park.
    parked: BTreeMap<u64, ParkedSize>,
    /// Whether `--key-sizes` length evidence is admitted (keymeta
    /// §9): with the flag off the reducer drops any length trailer
    /// unclassified (`size_inference_off`), while families join in
    /// both modes. Defaults on: production off-mode carries no
    /// trailers at all (the length programs never load), so the
    /// gate is vacuous there and admitting is the safe default.
    key_sizes: bool,
    /// Shared tickets closed while the shared ledger was absent
    /// (N1c): flushed at the next shared contact, C4-style. Bounded
    /// by the shared census — each pend holds a live shared ticket.
    pending_shared_releases: Vec<u64>,
}

impl std::fmt::Debug for KeyUseReducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyUseReducer")
            .field("open", &self.open.len())
            .field("refused", &self.refused.len())
            .field("aggregates", &self.aggregates.len())
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

impl KeyUseReducer {
    pub(crate) fn new() -> Self {
        Self::with_capacity(KEY_OP_ROW_CAPACITY)
    }

    /// A reducer with an injected aggregate bound (N/N+1 twins): the
    /// production bound is [`KEY_OP_ROW_CAPACITY`].
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            open: BTreeMap::new(),
            refused: BTreeMap::new(),
            aggregates: BTreeMap::new(),
            unknown: Box::new([UnknownCounters::default(); UNKNOWN_BUCKETS]),
            unknown_ever_live: [false; UNKNOWN_BUCKETS],
            capacity,
            evidence: KeyUseEvidence::default(),
            pending_shared_releases: Vec::new(),
            inferred: BTreeMap::new(),
            parked: BTreeMap::new(),
            key_sizes: true,
        }
    }

    /// Admit (`true`) or drop (`false`, `size_inference_off`)
    /// `--key-sizes` length evidence. The run setup poses the flag
    /// through this; on-mode is the default. Even without trailers
    /// off-mode must read `size_inference_off`, never absent
    /// evidence, so the default never substitutes for the wiring.
    pub(crate) fn set_key_sizes(&mut self, key_sizes: bool) {
        self.key_sizes = key_sizes;
    }

    /// Whether this reducer admits length evidence (wiring pin only).
    #[cfg(test)]
    pub(crate) fn key_sizes_enabled(&self) -> bool {
        self.key_sizes
    }

    /// Retained per-bucket inferred keys, for the projection.
    pub(crate) fn inferred_map(&self) -> &BTreeMap<AggKey, RowInference> {
        &self.inferred
    }

    /// Retained key-use evidence counters, for gap publication.
    pub(crate) fn key_use_evidence(&self) -> &KeyUseEvidence {
        &self.evidence
    }

    pub(crate) fn aggregates(&self) -> &BTreeMap<AggKey, AggCounters> {
        &self.aggregates
    }

    pub(crate) fn unknown_counters(&self) -> &[UnknownCounters; UNKNOWN_BUCKETS] {
        &self.unknown
    }

    /// Fixed unknown summaries ever live, by bucket index (N9): the
    /// projection emits these even at all zeros (zero-active
    /// replacements for rows the cumulative consumer already saw).
    pub(crate) fn unknown_ever_live(&self) -> &[bool; UNKNOWN_BUCKETS] {
        &self.unknown_ever_live
    }

    /// Mark one fixed unknown summary ever-live and add a terminal
    /// outcome (N9), recording the terminal's mechanism id when one
    /// is known (controller ruling fix2, F3).
    fn unknown_add(&mut self, index: usize, outcome: OperationOutcome, mechanism: Option<u64>) {
        self.unknown_ever_live[index] = true;
        self.unknown[index].add(outcome);
        if let Some(id) = mechanism {
            self.unknown[index].add_mech(id);
        }
    }

    /// Mark one fixed unknown summary ever-live and count live
    /// activity (N9).
    fn unknown_activate(&mut self, index: usize) {
        self.unknown_ever_live[index] = true;
        self.unknown[index].active = self.unknown[index].active.saturating_add(1);
    }

    /// Merge a fully-closed preservation reducer's unknown summaries
    /// and evidence (bulk-disposal preservation): fixed unknown
    /// counters add (never refuse, never re-partition), ever-live
    /// ORs (N9), evidence counts add. The preserved reducer holds
    /// no opens, refused opens, proved aggregates (receipt-less by
    /// construction) or pended releases — anything left would be a
    /// pairing leak across the loss boundary.
    pub(crate) fn absorb_preserved(&mut self, other: KeyUseReducer) {
        debug_assert!(other.open.is_empty() && other.refused.is_empty());
        debug_assert!(other.aggregates.is_empty());
        debug_assert!(other.pending_shared_releases.is_empty());
        for (slot, add) in self.unknown.iter_mut().zip(other.unknown.iter()) {
            debug_assert_eq!(add.active, 0, "preservation closes every open");
            slot.completed = slot.completed.saturating_add(add.completed);
            slot.failed = slot.failed.saturating_add(add.failed);
            slot.cancelled = slot.cancelled.saturating_add(add.cancelled);
            slot.unknown = slot.unknown.saturating_add(add.unknown);
            slot.active = slot.active.saturating_add(add.active);
            slot.absorb_mechs(add);
        }
        for (live, add) in self
            .unknown_ever_live
            .iter_mut()
            .zip(other.unknown_ever_live.iter())
        {
            *live |= add;
        }
        let (mine, theirs) = (&mut self.evidence, other.evidence);
        mine.unknown_key_rows = mine
            .unknown_key_rows
            .saturating_add(theirs.unknown_key_rows);
        mine.orphan_ends = mine.orphan_ends.saturating_add(theirs.orphan_ends);
        mine.unclassified_roles = mine
            .unclassified_roles
            .saturating_add(theirs.unclassified_roles);
        mine.partial |= theirs.partial;
        mine.rows_refused = mine.rows_refused.saturating_add(theirs.rows_refused);
        mine.refused_terminals = mine
            .refused_terminals
            .saturating_add(theirs.refused_terminals);
        mine.dropped_receipts = mine
            .dropped_receipts
            .saturating_add(theirs.dropped_receipts);
        mine.join_lost = mine.join_lost.saturating_add(theirs.join_lost);
        mine.duplicate_starts = mine
            .duplicate_starts
            .saturating_add(theirs.duplicate_starts);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn open(&self) -> &BTreeMap<(RegistryInstanceId, OperationId), OpenKeyUse> {
        &self.open
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn refused_opens(
        &self,
    ) -> &BTreeMap<(RegistryInstanceId, OperationId), RefusedOpen> {
        &self.refused
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn evidence(&self) -> KeyUseEvidence {
        self.evidence
    }

    /// Return ended associations' shared charges at ledger contact,
    /// including publications which emit no operation effects.
    pub(crate) fn flush_pending_shared_releases(
        &mut self,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) {
        for ticket in self.pending_shared_releases.drain(..) {
            ledger.release_keyassoc(ticket);
        }
    }

    /// Observe one operation effect from one instance: reserve
    /// aggregate buckets on start (refuse at N+1, never evict),
    /// close into the reserved buckets on end, complete atomically
    /// on direct. Terminals move within reserved buckets and fixed
    /// summaries and allocate nothing.
    #[cfg_attr(not(test), allow(dead_code))] // Staged aggregation path: exercised by the key-operation tests; no production feed wires it yet.
    pub(crate) fn observe_effect(
        &mut self,
        instance: RegistryInstanceId,
        effect: &OperationEffect,
        shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        self.observe_effect_from_stage(instance, effect, shared, fallback, None);
    }

    fn observe_effect_from_stage(
        &mut self,
        instance: RegistryInstanceId,
        effect: &OperationEffect,
        mut shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        mut fallback: Option<&mut crate::semantics_objects::journal::StagingLedger>,
        source: Option<&crate::semantics_objects::journal::StagedResourceOrigin>,
    ) {
        // Ledger contact flushes pended shared releases first (N1c,
        // C4-style): tickets closed while the shared ledger was
        // absent return now instead of leaking.
        if let Some(ledger) = shared.as_deref_mut() {
            self.flush_pending_shared_releases(ledger);
        }
        match effect {
            OperationEffect::Started {
                id,
                category,
                mechanism,
                key_receipt,
                origin,
            } => {
                let key = (instance, *id);
                if self.open.contains_key(&key) || self.refused.contains_key(&key) {
                    // Exact duplicate delivery: the retained custody
                    // stands untouched — a duplicate never overwrites,
                    // and totals never shrink, so no slot is freed.
                    self.evidence.duplicate_starts =
                        self.evidence.duplicate_starts.saturating_add(1);
                    return;
                }
                let receipts =
                    Self::bound_slice(category, key_receipt.as_slice(), &mut self.evidence);
                let (slots, len) = Self::resolve(instance, category, receipts);
                let resolved = &slots[..len];
                if !self.admits(resolved) {
                    self.refuse(key, instance, category, origin.ts_ns, *mechanism);
                    return;
                }
                // One shared reservation owner (N1c): the prospective
                // association mints its ticket before its buckets
                // land, so a refusal reserves nothing. The shared
                // ledger mints when present, else the scene's
                // fallback; a full census refuses exactly like a
                // full aggregate table.
                let ticket_shared = shared.is_some();
                let target = shared.as_deref_mut().or(fallback.as_deref_mut());
                let Some(ledger) = target else {
                    debug_assert!(false, "keyassoc mint needs a ledger");
                    self.refuse(key, instance, category, origin.ts_ns, *mechanism);
                    return;
                };
                let assoc_bytes = size_of::<OpenKeyUse>() as u64
                    + (resolved.len() * size_of::<OpenAssoc>()) as u64;
                let ticket = match ledger.mint_keyassoc_from_stage(
                    assoc_bytes,
                    if ticket_shared { source } else { None },
                ) {
                    Ok(ticket) => ticket,
                    Err(_) => {
                        self.refuse(key, instance, category, origin.ts_ns, *mechanism);
                        return;
                    }
                };
                self.open_buckets(resolved);
                let associations: Vec<OpenAssoc> = resolved
                    .iter()
                    .zip(receipts.iter())
                    .map(|(slot, receipt)| {
                        let established = receipt.label.map(crate::keymeta::established_kind);
                        // The combined label governs when present (the
                        // base behavior, including legacy CKK_EC plus
                        // curve shapes); the raw type only fills in
                        // when no label exists.
                        let established_type = established.or_else(|| {
                            receipt
                                .key_type
                                .and_then(crate::keymeta::established_type_kind)
                        });
                        OpenAssoc {
                            bucket: slot.bucket,
                            key: receipt.key,
                            lost: false,
                            primary: slot.primary,
                            established,
                            established_type,
                            creation_mechanism: receipt.creation_mechanism,
                        }
                    })
                    .collect();
                if receipts.is_empty() {
                    // A receipt-less open is live unknown-key S1:
                    // active now, outcome at close.
                    let slot = unknown_index(category, unbound_reason_for(category));
                    self.unknown_activate(slot);
                }
                // Touched proved buckets forward-fill their parks.
                for assoc in associations.iter() {
                    if let AssocBucket::Proved(bucket) = assoc.bucket {
                        self.forward_fill(bucket, assoc.established);
                    }
                }
                self.open.insert(
                    key,
                    OpenKeyUse {
                        instance,
                        category,
                        mechanism: *mechanism,
                        started_ts_ns: origin.ts_ns,
                        associations,
                        bound: !receipts.is_empty(),
                        ticket,
                        ticket_shared,
                    },
                );
            }
            OperationEffect::Ended {
                id,
                category: _,
                outcome,
                origin: _,
                length,
                corroboration,
            } => {
                let key = (instance, *id);
                if let Some(open) = self.open.remove(&key) {
                    let (ticket, ticket_shared) = (open.ticket, open.ticket_shared);
                    // Successful consumption attributes family and
                    // size to the closing buckets (failed/cancelled
                    // terminals prove nothing).
                    if *outcome == OperationOutcome::Completed {
                        self.attribute_completion(&open, *length, *corroboration);
                    } else {
                        // Unproved terminals leave no blank entries
                        // behind (older inference, if any, stands).
                        for assoc in &open.associations {
                            if let AssocBucket::Proved(bucket) = assoc.bucket
                                && self.inferred.get(&bucket) == Some(&RowInference::default())
                            {
                                self.inferred.remove(&bucket);
                            }
                        }
                    }
                    self.close_open(open, *outcome);
                    // The ticket returns to its minting ledger; a
                    // shared ticket closed without shared contact
                    // pends for the next one (flushed above), never
                    // leaks.
                    if ticket_shared {
                        match shared {
                            Some(ledger) => ledger.release_keyassoc(ticket),
                            None => self.pending_shared_releases.push(ticket),
                        }
                    } else if let Some(ledger) = fallback {
                        ledger.release_keyassoc(ticket);
                    } else {
                        debug_assert!(false, "fallback ticket needs its ledger");
                    }
                    return;
                }
                if let Some(refused) = self.refused.remove(&key) {
                    // A refused start's terminal: S1 owns the
                    // outcome; the key side preserves it in the
                    // fixed unknown summary — never a positive row.
                    let slot =
                        unknown_index(refused.category, unbound_reason_for(refused.category));
                    self.unknown[slot].active = self.unknown[slot].active.saturating_sub(1);
                    self.unknown_add(slot, *outcome, refused.mechanism);
                    self.evidence.refused_terminals =
                        self.evidence.refused_terminals.saturating_add(1);
                    return;
                }
                // An end without a start: no fabricated start — the
                // outcome lands in the fixed unknown summary, which
                // needs no positive row and never refuses.
                self.evidence.orphan_ends = self.evidence.orphan_ends.saturating_add(1);
                self.unknown_add(unknown_index("unknown", "unbound"), *outcome, None);
            }
            OperationEffect::DirectCompleted {
                category,
                mechanism,
                key_receipts,
                length,
                fresh_view,
                ..
            } => {
                let receipts =
                    Self::bound_slice(category, key_receipts.as_slice(), &mut self.evidence);
                let (slots, len) = Self::resolve(instance, category, receipts);
                let resolved = &slots[..len];
                if !self.admits(resolved) {
                    // A refused direct's terminal outcome (directs
                    // complete atomically) preserves into the fixed
                    // unknown summary — never a positive row.
                    let slot = unknown_index(category, unbound_reason_for(category));
                    self.unknown_add(slot, OperationOutcome::Completed, *mechanism);
                    self.evidence.rows_refused = self.evidence.rows_refused.saturating_add(1);
                    self.evidence.partial = true;
                    self.evidence.refused_terminals =
                        self.evidence.refused_terminals.saturating_add(1);
                    return;
                }
                if receipts.is_empty() {
                    self.evidence.unknown_key_rows =
                        self.evidence.unknown_key_rows.saturating_add(1);
                    let slot = unknown_index(category, unbound_reason_for(category));
                    self.unknown_add(slot, OperationOutcome::Completed, *mechanism);
                    return;
                }
                let mut saw_primary = false;
                for slot in resolved {
                    saw_primary = saw_primary || slot.primary;
                    match slot.bucket {
                        AssocBucket::Proved(bucket) => {
                            let counters = self.aggregates.entry(bucket).or_default();
                            counters.started = counters.started.saturating_add(1);
                            counters.add(OperationOutcome::Completed);
                        }
                        AssocBucket::Unknown(index) => {
                            // The terminal partitions once, by the
                            // primary role only.
                            if slot.primary {
                                self.unknown_add(index, OperationOutcome::Completed, *mechanism);
                            }
                        }
                    }
                }
                if !saw_primary {
                    // Secondary-only direct: the proved secondary
                    // associations stand above while the missing
                    // primary's terminal partitions unknown.
                    let slot = unknown_index(category, unbound_reason_for(category));
                    self.unknown_add(slot, OperationOutcome::Completed, *mechanism);
                }
                // Atomic completion attributes family and size per
                // proved association (role-split for wrap/unwrap),
                // parks wrapped material about rowless views, and
                // forward-fills parks onto touched buckets.
                self.attribute_direct(
                    category,
                    *mechanism,
                    receipts,
                    resolved,
                    *length,
                    *fresh_view,
                );
            }
        }
    }

    /// Attribute one successful Init-based completion (§4.3/§9):
    /// the terminal length evidence (when admitted) and the
    /// Init-bound mechanism join the open's proved associations; a
    /// terminal disagreeing with the retained corroboration records
    /// the named residual, never a conflict.
    fn attribute_completion(
        &mut self,
        open: &OpenKeyUse,
        length: Option<crate::keymeta::LengthOutcome>,
        corroboration: Option<u64>,
    ) {
        use crate::keymeta::{LengthOutcome, evidence_tag_for_category};
        // Residuals attach to rows: unattributed completions partition
        // unknown (existing) and feed no mismatch counter, so the gap
        // never escapes a v7 section (mismatches imply admitted
        // lengths, which always leave non-blank rows behind). A lost
        // join feeds neither inference nor the mismatch denominator:
        // the terminal's key proof was invalidated (§§5.4, 9).
        let attributed = open
            .associations
            .iter()
            .any(|assoc| matches!(assoc.bucket, AssocBucket::Proved(_)) && !assoc.lost);
        // Off-mode counts nothing (§9 stale/replayed rule): without
        // admitted lengths a terminal pair is not evidence.
        if self.key_sizes
            && attributed
            && let (Some(LengthOutcome::Value(terminal)), Some(expected)) = (length, corroboration)
            && terminal != expected
        {
            self.evidence.corroboration_mismatches =
                self.evidence.corroboration_mismatches.saturating_add(1);
        }
        let tag = evidence_tag_for_category(open.category);
        let input = match (self.key_sizes, length) {
            (false, _) => SizeInput::Off,
            (true, None) => SizeInput::NoEvidence,
            (true, Some(LengthOutcome::Unavailable)) => SizeInput::Unavailable,
            (true, Some(LengthOutcome::Value(value))) => SizeInput::Value(value),
        };
        for assoc in &open.associations {
            if assoc.lost {
                continue;
            }
            let AssocBucket::Proved(bucket) = assoc.bucket else {
                continue;
            };
            if let Some(mechanism) = open.mechanism {
                self.inferred
                    .entry(bucket)
                    .or_default()
                    .family
                    .accumulate_family(assoc.established_type, mechanism);
            }
            seed_creation_family(
                &mut self.inferred.entry(bucket).or_default().family,
                assoc.established,
                assoc.established_type,
                open.mechanism,
                assoc.creation_mechanism,
            );
            self.inferred
                .entry(bucket)
                .or_default()
                .size
                .accumulate_size(
                    assoc.established,
                    assoc.established_type,
                    open.mechanism,
                    tag,
                    input,
                );
        }
    }

    /// Attribute one atomic direct completion (§4.3/§9) with the
    /// wrap/unwrap role split: the mechanism types the operation
    /// (wrapping/unwrapping/base/encapsulation) key only, while
    /// AES-KW lengths size the wrapped key (or park on the fresh
    /// unwrap view). Unclassifiable roles attribute nothing, never
    /// guess. Touched proved buckets forward-fill their parks.
    fn attribute_direct(
        &mut self,
        category: &str,
        mechanism: Option<u64>,
        receipts: &[KeyReceipt],
        resolved: &[ResolvedAssoc],
        length: Option<crate::keymeta::LengthOutcome>,
        fresh_view: Option<u64>,
    ) {
        use crate::keymeta::{
            EvidenceTag, LengthOutcome, REASON_OPERATION_KEY_ONLY, SizeOutcome, classify_size,
            evidence_tag_for_category, is_aes_kw_family,
        };
        let tag = evidence_tag_for_category(category);
        // Which key this call's length evidence is about (determinable
        // without the value: AES-KW-family wrap/unwrap lengths concern
        // the wrapped key or fresh view; every other classified shape
        // concerns the operation key).
        let wrapped_about = matches!(mechanism, Some(id) if is_aes_kw_family(id))
            && matches!(
                tag,
                Some(EvidenceTag::WrapOutput) | Some(EvidenceTag::UnwrapInput)
            );
        for (slot, receipt) in resolved.iter().zip(receipts.iter()) {
            let established = receipt.label.map(crate::keymeta::established_kind);
            // The combined label governs when present (the base
            // behavior, including legacy CKK_EC plus curve shapes);
            // the raw type only fills in when no label exists.
            let established_type = established.or_else(|| {
                receipt
                    .key_type
                    .and_then(crate::keymeta::established_type_kind)
            });
            match slot.bucket {
                AssocBucket::Proved(bucket) => {
                    self.forward_fill(bucket, established);
                    // Family by role: the mechanism types the
                    // operation key; the wrapped key gains nothing
                    // from it; unclassifiable roles stay blank.
                    match receipt.role {
                        KeyRole::WrappedKey => {
                            if mechanism.is_some() {
                                let state = &mut self.inferred.entry(bucket).or_default().family;
                                // The wrap mechanism is family
                                // evidence (of its operation-key
                                // limit), so it counts.
                                state.completions = state.completions.saturating_add(1);
                                if state.status == InferredStatus::Unknown && state.reason.is_none()
                                {
                                    state.reason = Some(REASON_OPERATION_KEY_ONLY);
                                }
                            }
                            // The wrap mechanism never types this
                            // key, so the use side is `None`: only
                            // the creation side can seed.
                            seed_creation_family(
                                &mut self.inferred.entry(bucket).or_default().family,
                                established,
                                established_type,
                                None,
                                receipt.creation_mechanism,
                            );
                        }
                        KeyRole::WrappingKey
                        | KeyRole::UnwrappingKey
                        | KeyRole::BaseKey
                        | KeyRole::EncapsulationKey
                        | KeyRole::DecapsulationKey => {
                            if let Some(mechanism) = mechanism {
                                self.inferred
                                    .entry(bucket)
                                    .or_default()
                                    .family
                                    .accumulate_family(established_type, mechanism);
                            }
                            seed_creation_family(
                                &mut self.inferred.entry(bucket).or_default().family,
                                established,
                                established_type,
                                mechanism,
                                receipt.creation_mechanism,
                            );
                        }
                        KeyRole::OperationKey | KeyRole::Other => {}
                    }
                    // Size by role: wrapped material (or its padding
                    // ambiguity) is about the wrapped key; every
                    // other classified shape is about the operation
                    // key; anything else is absent evidence for this
                    // key. The accumulator re-resolves the selected
                    // input so transitions stay uniform.
                    let about_this_key = match receipt.role {
                        KeyRole::WrappedKey => wrapped_about,
                        KeyRole::WrappingKey | KeyRole::UnwrappingKey => {
                            tag.is_some() && !wrapped_about
                        }
                        KeyRole::BaseKey
                        | KeyRole::EncapsulationKey
                        | KeyRole::DecapsulationKey => tag.is_some(),
                        KeyRole::OperationKey | KeyRole::Other => false,
                    };
                    let input = if about_this_key {
                        self.size_input_for(length)
                    } else if !self.key_sizes {
                        SizeInput::Off
                    } else {
                        SizeInput::NoEvidence
                    };
                    self.inferred
                        .entry(bucket)
                        .or_default()
                        .size
                        .accumulate_size(established, established_type, mechanism, tag, input);
                }
                AssocBucket::Unknown(_) => {
                    // An unusable wrapped association still names its
                    // view: park admitted AES-KW material about it —
                    // the same admission decision as the direct path,
                    // so no route publishes a refused size.
                    if category == "wrap"
                        && receipt.role == KeyRole::WrappedKey
                        && mechanism == Some(crate::keymeta::AES_KW_ID)
                        && let Some(LengthOutcome::Value(value)) = length
                        && let SizeOutcome::Inferred(detail) =
                            classify_size(mechanism, EvidenceTag::WrapOutput, value)
                    {
                        self.park_wrapped(
                            receipt.key.as_u64(),
                            ParkedSize {
                                detail,
                                tag: EvidenceTag::WrapOutput,
                            },
                        );
                    }
                }
            }
        }
        // U1: admitted AES-KW unwrap material about the fresh view
        // parks on the view (exact-one seal proof, valued admitted
        // lengths only — refused lengths park nothing and consume no
        // slot).
        if category == "unwrap"
            && mechanism == Some(crate::keymeta::AES_KW_ID)
            && let Some(LengthOutcome::Value(value)) = length
            && let Some(view) = fresh_view
            && let SizeOutcome::Inferred(detail) =
                classify_size(mechanism, EvidenceTag::UnwrapInput, value)
        {
            self.park_wrapped(
                view,
                ParkedSize {
                    detail,
                    tag: EvidenceTag::UnwrapInput,
                },
            );
        }
    }

    /// Resolve one completion's size input from the flag and trailer.
    fn size_input_for(&self, length: Option<crate::keymeta::LengthOutcome>) -> SizeInput {
        use crate::keymeta::LengthOutcome;
        match (self.key_sizes, length) {
            (false, _) => SizeInput::Off,
            (true, None) => SizeInput::NoEvidence,
            (true, Some(LengthOutcome::Unavailable)) => SizeInput::Unavailable,
            (true, Some(LengthOutcome::Value(value))) => SizeInput::Value(value),
        }
    }

    /// Park wrapped-material evidence about a rowless view (§5.4 U1):
    /// first park wins, the map stays within the aggregate bound,
    /// and overflow counts instead of silently dropping. Off-mode
    /// drops parks on arrival (§9 stale/replayed rule — the flag
    /// never flips mid-run, so gating the store covers every park
    /// site); a refused park is inference-side, never row loss (no
    /// partial — the count publishes as the named gap).
    fn park_wrapped(&mut self, view: u64, parked: ParkedSize) {
        if !self.key_sizes {
            return;
        }
        if self.parked.contains_key(&view) {
            return;
        }
        if self.parked.len() >= self.capacity {
            self.evidence.parked_refused = self.evidence.parked_refused.saturating_add(1);
            return;
        }
        self.parked.insert(view, parked);
    }

    /// Forward-fill a parked fact onto a touched proved bucket: the
    /// view's first sealed row carries it through the ordinary size
    /// transitions (same rules, same conflicts — never a
    /// `metadata_at_use` rewrite).
    fn forward_fill(
        &mut self,
        bucket: AggKey,
        established: Option<crate::keymeta::EstablishedKind>,
    ) {
        let Some(parked) = self.parked.remove(&bucket.object) else {
            return;
        };
        let state = self.inferred.entry(bucket).or_default();
        // The parked completion carried admitted length evidence, so
        // it counts; the detail then competes through the shared
        // path (wrapped shapes imply no mechanism qualifier and no
        // family, so the type gate is vacuous).
        state.size.completions = state.size.completions.saturating_add(1);
        state
            .size
            .accumulate_detail(established, None, None, parked.tag, parked.detail);
    }

    /// Whether every new proved bucket in one resolution fits the
    /// retained budget. Existing buckets update without new slots;
    /// unknown summaries are fixed and always admit.
    fn admits(&self, resolved: &[ResolvedAssoc]) -> bool {
        let mut fresh = 0usize;
        for (i, slot) in resolved.iter().enumerate() {
            let AssocBucket::Proved(bucket) = slot.bucket else {
                continue;
            };
            let seen = resolved[..i]
                .iter()
                .any(|earlier| earlier.bucket == AssocBucket::Proved(bucket));
            if !seen && !self.aggregates.contains_key(&bucket) {
                fresh = fresh.saturating_add(1);
            }
        }
        self.aggregates.len().saturating_add(fresh) <= self.capacity
    }

    /// Open one admitted start's buckets: proved buckets start and
    /// go active; unknown associations go active (their terminal
    /// partitions once, at close).
    fn open_buckets(&mut self, resolved: &[ResolvedAssoc]) {
        for slot in resolved {
            match slot.bucket {
                AssocBucket::Proved(bucket) => {
                    let counters = self.aggregates.entry(bucket).or_default();
                    counters.started = counters.started.saturating_add(1);
                    counters.active = counters.active.saturating_add(1);
                    // Reserve the inference entry with its bucket, so
                    // terminals mutate in place and allocate nothing.
                    self.inferred.entry(bucket).or_default();
                }
                AssocBucket::Unknown(index) => {
                    self.unknown_activate(index);
                }
            }
        }
    }

    /// Close one open's buckets at its terminal: live proved buckets
    /// take the outcome, retired ones close `key_join_lost`, and the
    /// terminal partitions once to the unknown summary unless a live
    /// proved primary already counted it. Allocation-free: reserved
    /// buckets and fixed summaries only.
    fn close_open(&mut self, open: OpenKeyUse, outcome: OperationOutcome) {
        // The open's mechanism rides every unknown terminal below
        // (controller ruling fix2, F3); captured before the
        // associations move out.
        let mechanism = open.mechanism;
        if !open.bound {
            self.evidence.unknown_key_rows = self.evidence.unknown_key_rows.saturating_add(1);
            let slot = unknown_index(open.category, unbound_reason_for(open.category));
            self.unknown[slot].active = self.unknown[slot].active.saturating_sub(1);
            self.unknown_add(slot, outcome, mechanism);
            return;
        }
        let mut saw_primary = false;
        for assoc in open.associations {
            saw_primary = saw_primary || assoc.primary;
            match assoc.bucket {
                AssocBucket::Proved(bucket) => {
                    if assoc.lost {
                        // Closed at invalidation time (active to
                        // `key_join_lost`); the terminal only routes
                        // once below, never double-closes.
                    } else {
                        let counters = self
                            .aggregates
                            .get_mut(&bucket)
                            .expect("admission reserved every proved bucket");
                        counters.active = counters.active.saturating_sub(1);
                        counters.add(outcome);
                    }
                }
                AssocBucket::Unknown(index) => {
                    self.unknown[index].active = self.unknown[index].active.saturating_sub(1);
                    if assoc.primary && !assoc.lost {
                        self.unknown_add(index, outcome, mechanism);
                    }
                }
            }
            if assoc.primary && assoc.lost {
                // A retired primary's S1 terminal routes once to the
                // unknown-key summary; its proved bucket already
                // closed `key_join_lost` above.
                self.unknown_add(
                    unknown_index(open.category, "key_join_lost"),
                    outcome,
                    mechanism,
                );
            }
        }
        if !saw_primary {
            // A secondary-only operation has no primary: its proved
            // secondary associations stand above while the missing
            // primary's terminal partitions unknown (never a
            // promotion of the secondary).
            let slot = unknown_index(open.category, unbound_reason_for(open.category));
            self.unknown_add(slot, outcome, mechanism);
        }
    }

    /// Count one refused start: no bucket, S1 untouched, PARTIAL
    /// cover. The refused open stays tracked (bounded by live
    /// machines) so its terminal lands counted; its live S1 shows in
    /// the fixed unknown summary.
    fn refuse(
        &mut self,
        key: (RegistryInstanceId, OperationId),
        instance: RegistryInstanceId,
        category: &'static str,
        started_ts_ns: u64,
        mechanism: Option<u64>,
    ) {
        self.refused.insert(
            key,
            RefusedOpen {
                instance,
                category,
                started_ts_ns,
                mechanism,
            },
        );
        let slot = unknown_index(category, unbound_reason_for(category));
        self.unknown_activate(slot);
        self.evidence.rows_refused = self.evidence.rows_refused.saturating_add(1);
        self.evidence.partial = true;
    }

    /// Bind receipts for one category: binding categories keep them,
    /// generation/digest/reference-only/KEM categories drop them
    /// with evidence (their key side is `not_applicable` or
    /// `role_unavailable`, never a fabricated association).
    /// Borrows the effect's slice (S1 emits at most two receipts per
    /// effect), so even refused terminals allocate nothing.
    fn bound_slice<'a>(
        category: &str,
        receipts: &'a [KeyReceipt],
        evidence: &mut KeyUseEvidence,
    ) -> &'a [KeyReceipt] {
        if !binds_keys(category) {
            evidence.dropped_receipts = evidence
                .dropped_receipts
                .saturating_add(receipts.len() as u64);
            return &[];
        }
        if receipts.len() > 2 {
            // Unreachable: S1 emits at most two receipts per effect
            // (asserted at emission) — counted loudly if it ever does.
            debug_assert!(false, "at most two receipts per effect");
            evidence.dropped_receipts = evidence
                .dropped_receipts
                .saturating_add(receipts.len().saturating_sub(2) as u64);
            return &receipts[..2];
        }
        receipts
    }

    /// Resolve one operation's bound receipts to their buckets:
    /// usable receipts to proved aggregate keys, unusable ones to
    /// fixed unknown summaries. The primary (first non-secondary
    /// receipt — `wrapped_object` is secondary, H9 §82) carries the
    /// terminal's partition; a secondary-only operation has no
    /// primary, so its terminal partitions unknown while its proved
    /// secondary associations stand. Stack-held (at most two
    /// receipts per effect), so even refused terminals allocate
    /// nothing.
    fn resolve(
        instance: RegistryInstanceId,
        category: &'static str,
        receipts: &[KeyReceipt],
    ) -> ([ResolvedAssoc; 2], usize) {
        debug_assert!(receipts.len() <= 2, "bound_slice truncates first");
        let primary = receipts
            .iter()
            .position(|receipt| receipt.role != KeyRole::WrappedKey);
        let mut slots = [ResolvedAssoc::NONE; 2];
        let mut len = 0usize;
        for (index, receipt) in receipts.iter().enumerate().take(slots.len()) {
            let bucket = match row_label(receipt) {
                Some(label) => AssocBucket::Proved(AggKey {
                    instance,
                    object: receipt.key.as_u64(),
                    category,
                    role: role_label(receipt.role),
                    metadata: label,
                }),
                None => AssocBucket::Unknown(unknown_index(category, metadata_reason(receipt))),
            };
            slots[len] = ResolvedAssoc {
                bucket,
                primary: Some(index) == primary,
            };
            len += 1;
        }
        (slots, len)
    }

    /// Apply one seal's (or failure's) retirement effects to the
    /// open associations (H9 §66): object retirements by exact key,
    /// session ends by model attribution. Runs BEFORE any replay or
    /// disposal the same seal/failure triggers, so a terminal can
    /// never complete a binding its own seal just unproved.
    #[cfg(test)]
    pub(crate) fn apply_invalidations(&mut self, effects: &ObjectEffects, model: &ObjectSemantics) {
        for effect in &effects.effects {
            self.apply_invalidation(effect, model);
        }
    }

    /// Shared core for a budgeted original span and the legacy whole-result
    /// adapter. No model lookup can replace a frozen metadata-at-use receipt.
    fn apply_invalidation(&mut self, effect: &ObjectEffect, model: &ObjectSemantics) {
        match effect {
            ObjectEffect::Destroyed { object, .. }
            | ObjectEffect::Retired { object, .. }
            | ObjectEffect::AccessEnded { object, .. } => {
                // Parked evidence expires with its view (every end
                // path ends the view exactly once; nothing makes it
                // live again).
                self.parked.remove(&object.as_u64());
                self.retire_object(*object);
            }
            ObjectEffect::Downgraded { object, .. }
            | ObjectEffect::MetadataInvalidated { object, .. }
            | ObjectEffect::MetadataConflict { object, .. } => self.retire_object(*object),
            ObjectEffect::SessionEnded { session, .. } => self.retire_session(*session, model),
            _ => {}
        }
    }

    /// End every active association on one object before its S1
    /// terminal (H9 §66): each loses its join once, closing active
    /// to `key_join_lost` immediately; the terminal still lands
    /// later through the ordinary path (routing once to the
    /// unknown-key summary, never double-closing).
    pub(crate) fn retire_object(&mut self, object: ObjectId) {
        let mut lost = Vec::new();
        for open in self.open.values_mut() {
            for assoc in &mut open.associations {
                if assoc.key == object && !assoc.lost {
                    assoc.lost = true;
                    lost.push(assoc.bucket);
                }
            }
        }
        self.close_lost_buckets(&lost);
    }

    /// End every active association whose key the model attributes
    /// to one ended session (domain/session loss, H9 §66). Closes
    /// like [`Self::retire_object`].
    pub(crate) fn retire_session(&mut self, session: SessionIncarnation, model: &ObjectSemantics) {
        let mut lost = Vec::new();
        for open in self.open.values_mut() {
            for assoc in &mut open.associations {
                if assoc.lost {
                    continue;
                }
                let ended = model
                    .receipt_snapshot(assoc.key)
                    .is_some_and(|snapshot| snapshot.session == session);
                if ended {
                    assoc.lost = true;
                    lost.push(assoc.bucket);
                }
            }
        }
        self.close_lost_buckets(&lost);
    }

    /// Close newly-lost associations' proved buckets at invalidation
    /// time: active out, `key_join_lost` in. Unknown-bucket
    /// associations keep their live S1 active until the terminal
    /// (which routes the outcome); the evidence counts every join
    /// lost, proved or not.
    fn close_lost_buckets(&mut self, lost: &[AssocBucket]) {
        for bucket in lost {
            self.evidence.join_lost = self.evidence.join_lost.saturating_add(1);
            if let AssocBucket::Proved(key) = bucket {
                let counters = self
                    .aggregates
                    .get_mut(key)
                    .expect("lost joins close reserved buckets");
                counters.active = counters.active.saturating_sub(1);
                counters.key_join_lost = counters.key_join_lost.saturating_add(1);
            }
        }
    }

    /// Assemble this quantum's positional receipts: the seal's
    /// references qualified to the settled call's ticket (never
    /// another call's), each carrying the input ordinal the qualified
    /// model join minted — never a renumbering of successful
    /// references (holes stay holes; equal handles keep both
    /// positions). Found-handle references join no input and yield no
    /// receipt. Metadata (presence, label, attribution) is the
    /// snapshot the join froze into the effect — never the model's
    /// current state, so routing delay cannot backfill an earlier
    /// use. Callers pass the seal's verified single settled call
    /// (see [`JointStaging::apply_seal`]).
    #[cfg(test)]
    pub(crate) fn receipts_for_call(
        &mut self,
        seal: &SealSuccess,
        settled: &SealedCall,
        _model: &ObjectSemantics,
        position: u64,
    ) -> Vec<KeyReceipt> {
        self.receipts_for_effects(&seal.effects.effects, settled, position)
    }

    /// This replay's completion evidence (keymeta §9): the settled
    /// call's length trailer outcome plus, for result-creating
    /// directs, the exact-one fresh view. Fail-closed: anything but
    /// an exact-one created view yields no fresh view, never a guess.
    pub(crate) fn completion_evidence_for_effects(
        effects: &[ObjectEffect],
        settled: &SealedCall,
    ) -> crate::keymeta::CompletionEvidence {
        let mut fresh_view = None;
        let mut created = 0u32;
        for effect in effects {
            if let ObjectEffect::Created { call, object, .. } = effect
                && *call == settled.ticket
            {
                created = created.saturating_add(1);
                fresh_view = Some(object.as_u64());
            }
        }
        crate::keymeta::CompletionEvidence {
            length: settled.length,
            fresh_view: if created == 1 { fresh_view } else { None },
        }
    }

    /// New H9 reads only its exact original End span. Ticket/input filtering
    /// preserves holes and equal-handle roles without a scan of other calls.
    fn receipts_for_effects(
        &mut self,
        effects: &[ObjectEffect],
        settled: &SealedCall,
        position: u64,
    ) -> Vec<KeyReceipt> {
        let mut receipts = Vec::new();
        for effect in effects {
            let ObjectEffect::Referenced {
                call,
                object,
                input,
                metadata,
                label,
                key_type,
                attribution_valid,
                first_observed,
                creation_mechanism,
                ..
            } = effect
            else {
                continue;
            };
            if *call != settled.ticket {
                continue;
            }
            let Some(input) = input else {
                continue;
            };
            let role = self.classify_role(settled.function, *input);
            receipts.push(KeyReceipt {
                key: *object,
                function: settled.function,
                input: *input,
                role,
                position,
                metadata: *metadata,
                label: *label,
                key_type: *key_type,
                attribution_valid: *attribution_valid,
                first_observed: *first_observed,
                lost: false,
                creation_mechanism: *creation_mechanism,
            });
        }
        receipts
    }

    /// Classify one input's role from its descriptor action, function
    /// and input ordinal. Unclassified inputs keep their receipt
    /// with [`KeyRole::Other`] plus evidence — never a guessed role,
    /// never a dropped reference.
    fn classify_role(&mut self, function: u32, ordinal: u8) -> KeyRole {
        let name = pkcs11_module::function_name(usize::try_from(function).unwrap_or(usize::MAX));
        let action = p11scope_ebpf_common::object_policy::object_descriptor(function)
            .map(|descriptor| descriptor.action);
        match (name, action, ordinal) {
            (Some("C_WrapKey"), _, 0) => KeyRole::WrappingKey,
            (Some("C_WrapKey"), _, 1) => KeyRole::WrappedKey,
            (Some("C_DeriveKey"), _, _) => KeyRole::BaseKey,
            (Some("C_UnwrapKey"), _, _) => KeyRole::UnwrappingKey,
            (Some("C_EncapsulateKey"), _, _) => KeyRole::EncapsulationKey,
            (Some("C_DecapsulateKey"), _, _) => KeyRole::DecapsulationKey,
            (_, Some(p11scope_ebpf_common::object_policy::ObjectAction::Access), 0) => {
                KeyRole::OperationKey
            }
            _ => {
                self.evidence.unclassified_roles =
                    self.evidence.unclassified_roles.saturating_add(1);
                KeyRole::Other
            }
        }
    }
}

/// A sink tee: every effect feeds the key-use reducer and the outer
/// sink. Used by [`JointStaging::apply_seal`] so one replay drives
/// both consumers from the same single pass.
pub(crate) struct KeyUseTee<'a, S: OperationSink> {
    outer: &'a mut S,
    keyuse: &'a mut KeyUseReducer,
    instance: RegistryInstanceId,
    /// Prospective-association ledgers (N1c): the shared owner when
    /// present, else the scene fallback; ends release to the minter.
    shared: Option<&'a mut crate::semantics_objects::journal::StagingLedger>,
    fallback: Option<&'a mut crate::semantics_objects::journal::StagingLedger>,
    source: Option<&'a crate::semantics_objects::journal::StagedResourceOrigin>,
}

impl<'a, S: OperationSink> KeyUseTee<'a, S> {
    /// Tee one reduction's effects into the shared reducer plus an
    /// outer sink (the registry's guarded Joint arm uses a
    /// no-op outer: effects feed only the reducer there).
    pub(crate) fn new(
        outer: &'a mut S,
        keyuse: &'a mut KeyUseReducer,
        instance: RegistryInstanceId,
        shared: Option<&'a mut crate::semantics_objects::journal::StagingLedger>,
        fallback: Option<&'a mut crate::semantics_objects::journal::StagingLedger>,
    ) -> Self {
        Self {
            outer,
            keyuse,
            instance,
            shared,
            fallback,
            source: None,
        }
    }
}

impl<S: OperationSink> OperationSink for KeyUseTee<'_, S> {
    const WANTS_EFFECTS: bool = true;

    fn emit(&mut self, effect: OperationEffect) {
        self.keyuse.observe_effect_from_stage(
            self.instance,
            &effect,
            self.shared.as_deref_mut(),
            self.fallback.as_deref_mut(),
            self.source,
        );
        self.outer.emit(effect);
    }
}
