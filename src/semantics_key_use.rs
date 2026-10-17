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

use crate::semantics_edge::{
    EdgeSemantics, EffectOrigin, KeyReceipt, KeyRole, OperationEffect, OperationId,
    OperationOutcome, OperationSink, SemanticCall,
};
use crate::semantics_objects::journal::{
    BootstrapReceipt, H3DispositionEvidence, H3EvidenceSource, JournalGap, SealFailure,
    SealSuccess, SealedCall,
};
use crate::semantics_objects::{KeyMetadataFlags, ObjectEffect, ObjectSemantics};
use std::collections::{BTreeMap, VecDeque};

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
    /// H8's frozen endpoint table cannot model this call (async
    /// completions, encapsulate, info calls): it can never settle,
    /// and ingesting it would taint the image. The driver reduces
    /// it S1Only-direct — the async-completion carve-out. Such
    /// operations row unknown-key (no receipt can exist for them).
    Unsealable,
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
    /// a forbidden replay or a caller-ordering bug. Only H8-modelable
    /// calls stage: anything the frozen endpoint table leaves
    /// negative-only or irrelevant (async completions, encapsulate,
    /// info calls) can never settle — ingesting one would taint the
    /// image — so the driver reduces those S1Only-direct instead.
    pub(crate) fn stage(
        &mut self,
        facts: SemanticCall,
        origin: EffectOrigin,
        position: u64,
    ) -> Result<(), StagingRefusal> {
        if self.mode != FeedMode::Joint {
            return Err(StagingRefusal::NotJoint);
        }
        let sealable = crate::kinds::function_id(&facts.function)
            .and_then(crate::semantics_objects::journal::endpoint_class)
            .is_some_and(|class| {
                class == crate::semantics_objects::journal::EndpointClass::ModeledAffecting
            });
        if !sealable {
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
    /// Anything else holds staging intact. The replay runs through
    /// [`EdgeSemantics::observe_joint`] with this quantum's
    /// positional receipts (assembled from the seal's ticket-
    /// qualified references plus at-transition metadata snapshots);
    /// its effects feed both the caller's sink and the key-use
    /// reducer from the same single pass. Returns the outcome plus
    /// this quantum's per-edge bound refusals (the owner folds them
    /// into `semantic_refused`, like the direct feed).
    pub(crate) fn apply_seal<S: OperationSink>(
        &mut self,
        seal: &SealSuccess,
        model: &ObjectSemantics,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
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
        let receipts = keyuse.receipts_for_call(seal, &settled[0], model, head.position);
        let mut tee = KeyUseTee {
            outer: sink,
            keyuse,
        };
        let refused = reducer.observe_joint(&head.facts, &head.origin, &receipts, &mut tee);
        self.reduced = self.reduced.saturating_add(1);
        (SealApplyOutcome::ReplayedOne, refused)
    }

    /// Apply one seal failure: real loss invalidates live operation
    /// authority before history-only disposal; proof-only refusal
    /// with an explicit complete H3 stream replays retained calls
    /// once in order through ordinary S1; anything transient or
    /// completeness-unproven holds staging intact. The H3 receipt is
    /// taken from the actual finalizer (`take_h3_disposition`),
    /// never caller-supplied. Invalidation terminals and fallback
    /// effects feed the key-use reducer too (open rows close as
    /// Unknown on loss; fallback rows are unknown-key S1Only —
    /// object facts are never invented in fallback). Returns the
    /// outcome plus fallback per-edge bound refusals for
    /// `semantic_refused`.
    pub(crate) fn apply_failure<S: OperationSink>(
        &mut self,
        failure: &SealFailure,
        finalizer: &mut impl H3EvidenceSource,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        sink: &mut S,
    ) -> (FailureApplyOutcome, u64) {
        if self.mode != FeedMode::Joint {
            return (FailureApplyOutcome::Ignored, 0);
        }
        match disposition_of(failure.gap) {
            SealFailureDisposition::Retry => (FailureApplyOutcome::Retried, 0),
            SealFailureDisposition::HistoryLoss => {
                self.dispose_as_loss(reducer, keyuse, sink);
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
                        let (replayed, refused) = self.replay_staged(reducer, keyuse, sink);
                        self.mode = FeedMode::S1Only;
                        (FailureApplyOutcome::FellBack { replayed }, refused)
                    }
                    H3DispositionEvidence::StagedLoss { .. } | H3DispositionEvidence::Exhausted => {
                        // H3's own stream is lossy: the staged calls'
                        // S1 proof with it. Real-loss treatment.
                        self.dispose_as_loss(reducer, keyuse, sink);
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
    /// any disposal accounting. Terminals feed the key-use reducer
    /// too, so open rows close as Unknown instead of leaking.
    fn dispose_as_loss<S: OperationSink>(
        &self,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        sink: &mut S,
    ) {
        let mut tee = KeyUseTee {
            outer: sink,
            keyuse,
        };
        reducer.invalidate_with_effects(&mut tee);
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
    /// through ordinary S1 (S1Only: no receipts — fallback rows are
    /// unknown-key, never invented object facts). Effects feed the
    /// key-use reducer too. Returns the replay count plus per-edge
    /// bound refusals.
    fn replay_staged<S: OperationSink>(
        &mut self,
        reducer: &mut EdgeSemantics,
        keyuse: &mut KeyUseReducer,
        sink: &mut S,
    ) -> (usize, u64) {
        let mut replayed = 0;
        let mut refused = 0u64;
        while let Some(head) = self.staged.pop_front() {
            self.frontier = self.frontier.max(head.position);
            let mut tee = KeyUseTee {
                outer: &mut *sink,
                keyuse: &mut *keyuse,
            };
            refused = refused.saturating_add(reducer.observe_with_effects(
                &head.facts,
                &head.origin,
                &mut tee,
            ));
            self.reduced = self.reduced.saturating_add(1);
            replayed += 1;
        }
        (replayed, refused)
    }
}

// ---------------------------------------------------------------------------
// Key-use rows: positional receipts joined to operation transitions
// ---------------------------------------------------------------------------

/// Retained completed key-operation rows: oldest-first, drops
/// counted with the evicted row's identity.
pub(crate) const KEY_OP_ROW_CAPACITY: usize = 65_536;

/// Why the oldest row was dropped. Capacity overflow is the only
/// reason: retention never erases for any other cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetentionDropReason {
    CapacityOverflow,
}

/// The explicit record of one oldest-first eviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetentionDrop {
    pub reason: RetentionDropReason,
    /// Sequence of the evicted row.
    pub seq: u64,
    /// End timestamp of the evicted row.
    pub ended_ts_ns: u64,
}

/// One completed key-operation row: the S1 transition joined to its
/// positional key receipts. Frozen at completion — later-learned
/// metadata never rewrites a row. Carries no raw handles (keys are
/// opaque exact observations) and no metadata values (presence
/// bitmaps only). Internal identities ([`OperationId`]) never reach
/// rows: joins happen inside the reducer; rows carry only their own
/// output-safe sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyOpRow {
    pub seq: u64,
    pub category: &'static str,
    pub mechanism: Option<u64>,
    /// Positional receipts bound at the operation's start (empty =
    /// unknown-key, with explicit evidence — never loss).
    pub keys: Vec<KeyReceipt>,
    pub outcome: OperationOutcome,
    /// Start timestamp (`None` for partial rows: an end without a
    /// start, counted — never a fabricated start).
    pub started_ts_ns: Option<u64>,
    pub ended_ts_ns: u64,
    pub partial: bool,
}

/// Explicit key-use evidence: association outcomes, never silent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KeyUseEvidence {
    /// Completed non-partial rows with no bound key (S1Only starts,
    /// unassociated starts, async starts): definite S1, unknown key.
    pub unknown_key_rows: u64,
    /// Ends observed without their start (stream splice; unreachable
    /// from one reducer pass): partial rows, no fabricated starts.
    pub orphan_ends: u64,
    /// Receipts outside the classified role vocabulary.
    pub unclassified_roles: u64,
    /// Receipts whose key view was already gone at snapshot time
    /// (unreachable in-quantum; absence is unavailable metadata,
    /// never proof of no metadata).
    pub metadata_unavailable: u64,
}

struct OpenKeyUse {
    keys: Vec<KeyReceipt>,
    category: &'static str,
    mechanism: Option<u64>,
    started_ts_ns: u64,
}

/// The key-use reducer (H9): joins the operation-effect stream to
/// positional receipts into bounded, immutable rows. Open rows are
/// inherently bounded: one per live machine (at most 2,048 —
/// every open corresponds to a reducer machine, and every machine
/// end closes exactly its row).
pub(crate) struct KeyUseReducer {
    open: BTreeMap<OperationId, OpenKeyUse>,
    rows: VecDeque<KeyOpRow>,
    next_seq: u64,
    drops: u64,
    last_drop: Option<RetentionDrop>,
    evidence: KeyUseEvidence,
}

impl std::fmt::Debug for KeyUseReducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyUseReducer")
            .field("open", &self.open.len())
            .field("rows", &self.rows.len())
            .field("drops", &self.drops)
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

impl KeyUseReducer {
    pub(crate) fn new() -> Self {
        Self {
            open: BTreeMap::new(),
            rows: VecDeque::new(),
            next_seq: 0,
            drops: 0,
            last_drop: None,
            evidence: KeyUseEvidence::default(),
        }
    }

    pub(crate) fn rows(&self) -> &VecDeque<KeyOpRow> {
        &self.rows
    }

    pub(crate) fn evidence(&self) -> KeyUseEvidence {
        self.evidence
    }

    pub(crate) fn drops(&self) -> u64 {
        self.drops
    }

    pub(crate) fn last_drop(&self) -> Option<RetentionDrop> {
        self.last_drop
    }

    /// Observe one operation effect: open on start, close on end,
    /// complete immediately on direct. Rows freeze at completion.
    pub(crate) fn observe_effect(&mut self, effect: &OperationEffect) {
        match effect {
            OperationEffect::Started {
                id,
                category,
                mechanism,
                key_receipt,
                origin,
            } => {
                self.open.insert(
                    *id,
                    OpenKeyUse {
                        keys: key_receipt.iter().copied().collect(),
                        category,
                        mechanism: *mechanism,
                        started_ts_ns: origin.ts_ns,
                    },
                );
            }
            OperationEffect::Ended {
                id,
                category: _,
                outcome,
                origin,
            } => match self.open.remove(id) {
                Some(open) => self.push_row(KeyOpRow {
                    seq: 0,
                    category: open.category,
                    mechanism: open.mechanism,
                    keys: open.keys,
                    outcome: *outcome,
                    started_ts_ns: Some(open.started_ts_ns),
                    ended_ts_ns: origin.ts_ns,
                    partial: false,
                }),
                None => {
                    self.evidence.orphan_ends = self.evidence.orphan_ends.saturating_add(1);
                    self.push_row(KeyOpRow {
                        seq: 0,
                        category: "unknown",
                        mechanism: None,
                        keys: Vec::new(),
                        outcome: *outcome,
                        started_ts_ns: None,
                        ended_ts_ns: origin.ts_ns,
                        partial: true,
                    });
                }
            },
            OperationEffect::DirectCompleted {
                category,
                mechanism,
                key_receipts,
                origin,
                ..
            } => self.push_row(KeyOpRow {
                seq: 0,
                category,
                mechanism: *mechanism,
                keys: key_receipts.clone(),
                outcome: OperationOutcome::Completed,
                started_ts_ns: Some(origin.ts_ns),
                ended_ts_ns: origin.ts_ns,
                partial: false,
            }),
        }
    }

    /// Freeze one completed row with the next sequence, evicting the
    /// oldest past capacity with its explicit drop record.
    fn push_row(&mut self, mut row: KeyOpRow) {
        row.seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        if !row.partial && row.keys.is_empty() {
            self.evidence.unknown_key_rows = self.evidence.unknown_key_rows.saturating_add(1);
        }
        if self.rows.len() >= KEY_OP_ROW_CAPACITY {
            if let Some(evicted) = self.rows.pop_front() {
                self.drops = self.drops.saturating_add(1);
                self.last_drop = Some(RetentionDrop {
                    reason: RetentionDropReason::CapacityOverflow,
                    seq: evicted.seq,
                    ended_ts_ns: evicted.ended_ts_ns,
                });
            }
        }
        self.rows.push_back(row);
    }

    /// Assemble this quantum's positional receipts: the seal's
    /// references qualified to the settled call's ticket (never
    /// another call's), in model emission order (input ordinals),
    /// each snapshotting metadata presence known by — not after —
    /// this transition. Callers pass the seal's verified single
    /// settled call (see [`JointStaging::apply_seal`]).
    pub(crate) fn receipts_for_call(
        &mut self,
        seal: &SealSuccess,
        settled: &SealedCall,
        model: &ObjectSemantics,
        position: u64,
    ) -> Vec<KeyReceipt> {
        let mut receipts = Vec::new();
        let mut ordinal = 0u8;
        for effect in &seal.effects.effects {
            let ObjectEffect::Referenced { call, object, .. } = effect else {
                continue;
            };
            if *call != settled.ticket {
                continue;
            }
            let role = self.classify_role(settled.function, ordinal);
            let metadata = model.key_metadata_flags(*object).unwrap_or_else(|| {
                self.evidence.metadata_unavailable =
                    self.evidence.metadata_unavailable.saturating_add(1);
                KeyMetadataFlags::ZERO
            });
            receipts.push(KeyReceipt {
                key: *object,
                function: settled.function,
                input: ordinal,
                role,
                position,
                metadata,
            });
            ordinal = ordinal.saturating_add(1);
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
        let role = match (name, action, ordinal) {
            (Some("C_WrapKey"), _, 0) => KeyRole::WrappingKey,
            (Some("C_WrapKey"), _, 1) => KeyRole::WrappedKey,
            (Some("C_DeriveKey"), _, _) => KeyRole::BaseKey,
            (Some("C_UnwrapKey"), _, _) => KeyRole::UnwrappingKey,
            (_, Some(p11scope_ebpf_common::object_policy::ObjectAction::Access), 0) => {
                KeyRole::OperationKey
            }
            _ => {
                self.evidence.unclassified_roles =
                    self.evidence.unclassified_roles.saturating_add(1);
                KeyRole::Other
            }
        };
        role
    }
}

/// A sink tee: every effect feeds the key-use reducer and the outer
/// sink. Used by [`JointStaging::apply_seal`] so one replay drives
/// both consumers from the same single pass.
pub(crate) struct KeyUseTee<'a, S: OperationSink> {
    outer: &'a mut S,
    keyuse: &'a mut KeyUseReducer,
}

impl<S: OperationSink> OperationSink for KeyUseTee<'_, S> {
    const WANTS_EFFECTS: bool = true;

    fn emit(&mut self, effect: OperationEffect) {
        self.keyuse.observe_effect(&effect);
        self.outer.emit(effect);
    }
}
