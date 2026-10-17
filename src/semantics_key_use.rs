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

use crate::discovery::caller_registry::instance_input::RegistryInstanceId;
use crate::key_operation_projection::KEY_OP_ROW_CAPACITY;
use crate::semantics_edge::{
    EdgeSemantics, EffectOrigin, KeyReceipt, KeyRole, OperationEffect, OperationId,
    OperationOutcome, OperationSink, SemanticCall,
};
use crate::semantics_objects::journal::{
    BootstrapReceipt, H3DispositionEvidence, H3EvidenceSource, JournalGap, SealFailure,
    SealSuccess, SealedCall,
};
use crate::semantics_objects::{
    KeyMetadataFlags, ObjectEffect, ObjectId, ObjectSemantics, SessionIncarnation,
};
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
    /// True once real loss (not proof-only refusal) ended this
    /// feed's object authority: the projection reports
    /// `authority_lost`, never a silent empty success.
    degraded_loss: bool,
    /// True once proof-only refusal replayed retained calls through
    /// ordinary S1 and degraded to S1Only: the projection reports
    /// `proof_refused_fallback`.
    fell_back: bool,
}

impl std::fmt::Debug for JointStaging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JointStaging")
            .field("mode", &self.mode)
            .field("staged", &self.staged.len())
            .field("reduced", &self.reduced)
            .field("history_disposed", &self.history_disposed)
            .field("correlation_refusals", &self.correlation_refusals)
            .field("degraded_loss", &self.degraded_loss)
            .field("fell_back", &self.fell_back)
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
            degraded_loss: false,
            fell_back: false,
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
        instance: RegistryInstanceId,
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
            instance,
        };
        let refused = reducer.observe_joint(&head.facts, &head.origin, &receipts, &mut tee);
        self.reduced = self.reduced.saturating_add(1);
        // Retirement in the same seal ends active key associations
        // before any later terminal (H9 §66); the S1 terminal still
        // lands later through the ordinary path.
        for effect in &seal.effects.effects {
            match effect {
                ObjectEffect::Destroyed { object, .. }
                | ObjectEffect::AccessEnded { object, .. }
                | ObjectEffect::Retired { object, .. }
                | ObjectEffect::Downgraded { object, .. }
                | ObjectEffect::MetadataConflict { object, .. }
                | ObjectEffect::MetadataInvalidated { object, .. } => {
                    keyuse.retire_object(*object);
                }
                ObjectEffect::SessionEnded { session, .. } => {
                    keyuse.retire_session(*session, model);
                }
                _ => {}
            }
        }
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
        instance: RegistryInstanceId,
        sink: &mut S,
    ) -> (FailureApplyOutcome, u64) {
        if self.mode != FeedMode::Joint {
            return (FailureApplyOutcome::Ignored, 0);
        }
        match disposition_of(failure.gap) {
            SealFailureDisposition::Retry => (FailureApplyOutcome::Retried, 0),
            SealFailureDisposition::HistoryLoss => {
                self.dispose_as_loss(reducer, keyuse, instance, sink);
                let disposed = self.drain_staged();
                self.mode = FeedMode::S1Only;
                self.degraded_loss = true;
                (FailureApplyOutcome::Degraded { disposed }, 0)
            }
            SealFailureDisposition::Fallback => {
                match finalizer.take_h3_disposition() {
                    H3DispositionEvidence::Clean {
                        staged_max,
                        pending_floor: None,
                    } if self.covered_by(staged_max) => {
                        let (replayed, refused) =
                            self.replay_staged(reducer, keyuse, instance, sink);
                        self.mode = FeedMode::S1Only;
                        self.fell_back = true;
                        (FailureApplyOutcome::FellBack { replayed }, refused)
                    }
                    H3DispositionEvidence::StagedLoss { .. } | H3DispositionEvidence::Exhausted => {
                        // H3's own stream is lossy: the staged calls'
                        // S1 proof with it. Real-loss treatment.
                        self.dispose_as_loss(reducer, keyuse, instance, sink);
                        let disposed = self.drain_staged();
                        self.mode = FeedMode::S1Only;
                        self.degraded_loss = true;
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
        instance: RegistryInstanceId,
        sink: &mut S,
    ) {
        let mut tee = KeyUseTee {
            outer: sink,
            keyuse,
            instance,
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
        instance: RegistryInstanceId,
        sink: &mut S,
    ) -> (usize, u64) {
        let mut replayed = 0;
        let mut refused = 0u64;
        while let Some(head) = self.staged.pop_front() {
            self.frontier = self.frontier.max(head.position);
            let mut tee = KeyUseTee {
                outer: &mut *sink,
                keyuse: &mut *keyuse,
                instance,
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

/// Categories whose S1 activity never binds a key (H9 §62/S3): the
/// reducer drops their receipts at observe time (counted, never
/// silent) and their terminals aggregate as `not_applicable` —
/// existing S1 units, no fabricated missing-key starts.
const NOT_APPLICABLE_CATEGORIES: [&str; 4] =
    ["generate_key", "generate_key_pair", "digest", "direct"];

/// Categories with no approved object role (H9 §64: no KEM object
/// descriptor exists): receipts dropped, terminals aggregate as
/// `role_unavailable`, S1 mechanism activity untouched.
const ROLE_UNAVAILABLE_CATEGORIES: [&str; 2] = ["encapsulate", "decapsulate"];

/// Whether an operation category binds key receipts. Generation,
/// ordinary digest, reference-only directs and KEM never bind.
pub(crate) fn binds_keys(category: &str) -> bool {
    !NOT_APPLICABLE_CATEGORIES.contains(&category)
        && !ROLE_UNAVAILABLE_CATEGORIES.contains(&category)
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

/// One completed key-operation row: the S1 transition joined to its
/// positional key receipts. Frozen at completion — later-learned
/// metadata never rewrites a row. Carries no raw handles (keys are
/// opaque exact observations) and no metadata values (presence
/// bitmaps plus established size/curve labels only). Internal
/// identities ([`OperationId`]) never reach rows: joins happen
/// inside the reducer; rows carry only their own output-safe
/// sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyOpRow {
    pub seq: u64,
    pub instance: RegistryInstanceId,
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
    /// True once any association was refused at full budget: the
    /// projection's semantic coverage is PARTIAL from then on.
    pub partial: bool,
    /// Associations refused at N+1 (started or direct-completed
    /// without a reserved slot): S1 preserved, key row omitted.
    pub rows_refused: u64,
    /// Terminals that landed without a reserved row (refused starts
    /// and refused partials): counted, allocation-free, never rows.
    pub refused_terminals: u64,
    /// Receipts dropped because their category never binds keys
    /// (generation, ordinary digest, reference-only directs, KEM).
    pub dropped_receipts: u64,
    /// Active associations ended by retirement before their S1
    /// terminal (`key_join_lost` applications).
    pub join_lost: u64,
}

/// One open (started, unterminated) key association. Open rows are
/// inherently bounded: one per live machine — every open
/// corresponds to a reducer machine, and every machine end closes
/// exactly its row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenKeyUse {
    pub instance: RegistryInstanceId,
    pub keys: Vec<KeyReceipt>,
    pub category: &'static str,
    pub mechanism: Option<u64>,
    pub started_ts_ns: u64,
}

/// One open association refused at full budget: no slot reserved,
/// S1 still live. Bounded by live machines like [`OpenKeyUse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RefusedOpen {
    pub instance: RegistryInstanceId,
    pub category: &'static str,
    pub started_ts_ns: u64,
}

/// The key-use reducer (H9): joins the operation-effect stream to
/// positional receipts into bounded, immutable rows. Row slots are
/// reserved at start (`rows + open <= capacity` always): terminal
/// increments move an entry from open to its reserved row and
/// allocate no new slot. Completed history is immutable and never
/// evicted; refused associations land in fixed counters.
pub(crate) struct KeyUseReducer {
    open: BTreeMap<OperationId, OpenKeyUse>,
    refused: BTreeMap<OperationId, RefusedOpen>,
    rows: VecDeque<KeyOpRow>,
    capacity: usize,
    next_seq: u64,
    evidence: KeyUseEvidence,
}

impl std::fmt::Debug for KeyUseReducer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyUseReducer")
            .field("open", &self.open.len())
            .field("refused", &self.refused.len())
            .field("rows", &self.rows.len())
            .field("evidence", &self.evidence)
            .finish_non_exhaustive()
    }
}

impl KeyUseReducer {
    pub(crate) fn new() -> Self {
        Self::with_capacity(KEY_OP_ROW_CAPACITY)
    }

    /// A reducer with an injected row bound (N/N+1 twins): the
    /// production bound is [`KEY_OP_ROW_CAPACITY`].
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            open: BTreeMap::new(),
            refused: BTreeMap::new(),
            rows: VecDeque::new(),
            capacity,
            next_seq: 0,
            evidence: KeyUseEvidence::default(),
        }
    }

    pub(crate) fn rows(&self) -> &VecDeque<KeyOpRow> {
        &self.rows
    }

    pub(crate) fn open(&self) -> &BTreeMap<OperationId, OpenKeyUse> {
        &self.open
    }

    pub(crate) fn refused_opens(&self) -> &BTreeMap<OperationId, RefusedOpen> {
        &self.refused
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn evidence(&self) -> KeyUseEvidence {
        self.evidence
    }

    /// Observe one operation effect from one instance: reserve on
    /// start (refuse at N+1, never evict), close into the reserved
    /// row on end, complete atomically on direct. Rows freeze at
    /// completion; terminals allocate no new slot.
    pub(crate) fn observe_effect(
        &mut self,
        instance: RegistryInstanceId,
        effect: &OperationEffect,
    ) {
        match effect {
            OperationEffect::Started {
                id,
                category,
                mechanism,
                key_receipt,
                origin,
            } => {
                if self.open.contains_key(id) {
                    // Same-id restarts overwrite the open entry (no
                    // new slot); same-id refused stays refused (the
                    // totals never shrink, so no slot freed).
                    self.open.insert(
                        *id,
                        OpenKeyUse {
                            instance,
                            keys: Self::bound_receipts(
                                category,
                                key_receipt.iter().copied(),
                                &mut self.evidence,
                            ),
                            category,
                            mechanism: *mechanism,
                            started_ts_ns: origin.ts_ns,
                        },
                    );
                    return;
                }
                if self.refused.contains_key(id) {
                    return;
                }
                if self.rows.len().saturating_add(self.open.len()) >= self.capacity {
                    self.refuse(*id, instance, category, origin.ts_ns);
                    return;
                }
                self.open.insert(
                    *id,
                    OpenKeyUse {
                        instance,
                        keys: Self::bound_receipts(
                            category,
                            key_receipt.iter().copied(),
                            &mut self.evidence,
                        ),
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
            } => {
                if let Some(open) = self.open.remove(id) {
                    self.push_row(KeyOpRow {
                        seq: 0,
                        instance: open.instance,
                        category: open.category,
                        mechanism: open.mechanism,
                        keys: open.keys,
                        outcome: *outcome,
                        started_ts_ns: Some(open.started_ts_ns),
                        ended_ts_ns: origin.ts_ns,
                        partial: false,
                    });
                    return;
                }
                if self.refused.remove(id).is_some() {
                    // A refused start's terminal: S1 owns the
                    // outcome; the key side counts it without a row.
                    self.evidence.refused_terminals =
                        self.evidence.refused_terminals.saturating_add(1);
                    return;
                }
                self.evidence.orphan_ends = self.evidence.orphan_ends.saturating_add(1);
                if self.rows.len().saturating_add(self.open.len()) >= self.capacity {
                    self.evidence.rows_refused = self.evidence.rows_refused.saturating_add(1);
                    self.evidence.partial = true;
                    self.evidence.refused_terminals =
                        self.evidence.refused_terminals.saturating_add(1);
                    return;
                }
                self.push_row(KeyOpRow {
                    seq: 0,
                    instance,
                    category: "unknown",
                    mechanism: None,
                    keys: Vec::new(),
                    outcome: *outcome,
                    started_ts_ns: None,
                    ended_ts_ns: origin.ts_ns,
                    partial: true,
                });
            }
            OperationEffect::DirectCompleted {
                category,
                mechanism,
                key_receipts,
                origin,
                ..
            } => {
                if self.rows.len().saturating_add(self.open.len()) >= self.capacity {
                    self.evidence.rows_refused = self.evidence.rows_refused.saturating_add(1);
                    self.evidence.partial = true;
                    self.evidence.refused_terminals =
                        self.evidence.refused_terminals.saturating_add(1);
                    return;
                }
                let keys = Self::bound_receipts(
                    category,
                    key_receipts.iter().copied(),
                    &mut self.evidence,
                );
                self.push_row(KeyOpRow {
                    seq: 0,
                    instance,
                    category,
                    mechanism: *mechanism,
                    keys,
                    outcome: OperationOutcome::Completed,
                    started_ts_ns: Some(origin.ts_ns),
                    ended_ts_ns: origin.ts_ns,
                    partial: false,
                });
            }
        }
    }

    /// Count one refused start: no slot, S1 untouched, PARTIAL cover.
    fn refuse(
        &mut self,
        id: OperationId,
        instance: RegistryInstanceId,
        category: &'static str,
        started_ts_ns: u64,
    ) {
        self.refused.insert(
            id,
            RefusedOpen {
                instance,
                category,
                started_ts_ns,
            },
        );
        self.evidence.rows_refused = self.evidence.rows_refused.saturating_add(1);
        self.evidence.partial = true;
    }

    /// Bind receipts for one category: binding categories keep them,
    /// generation/digest/reference-only/KEM categories drop them
    /// with evidence (their key side is `not_applicable` or
    /// `role_unavailable`, never a fabricated association).
    fn bound_receipts(
        category: &str,
        receipts: impl Iterator<Item = KeyReceipt>,
        evidence: &mut KeyUseEvidence,
    ) -> Vec<KeyReceipt> {
        if binds_keys(category) {
            return receipts.collect();
        }
        let mut dropped = 0u64;
        for _ in receipts {
            dropped = dropped.saturating_add(1);
        }
        evidence.dropped_receipts = evidence.dropped_receipts.saturating_add(dropped);
        Vec::new()
    }

    /// Freeze one completed row with the next sequence. The caller
    /// reserved the slot (start reservation or direct admission):
    /// history is never evicted for a new row.
    fn push_row(&mut self, mut row: KeyOpRow) {
        row.seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        if !row.partial && row.keys.is_empty() {
            self.evidence.unknown_key_rows = self.evidence.unknown_key_rows.saturating_add(1);
        }
        debug_assert!(
            self.rows.len().saturating_add(self.open.len()) < self.capacity,
            "rows are pushed only into reserved slots"
        );
        self.rows.push_back(row);
    }

    /// End every active association on one object before its S1
    /// terminal (H9 §66): each loses its join once; the terminal
    /// still lands later through the ordinary path.
    pub(crate) fn retire_object(&mut self, object: ObjectId) {
        for open in self.open.values_mut() {
            for receipt in &mut open.keys {
                if receipt.key == object && !receipt.lost {
                    receipt.lost = true;
                    self.evidence.join_lost = self.evidence.join_lost.saturating_add(1);
                }
            }
        }
    }

    /// End every active association whose key the model attributes
    /// to one ended session (domain/session loss, H9 §66).
    pub(crate) fn retire_session(&mut self, session: SessionIncarnation, model: &ObjectSemantics) {
        for open in self.open.values_mut() {
            for receipt in &mut open.keys {
                if receipt.lost {
                    continue;
                }
                let ended = model
                    .receipt_snapshot(receipt.key)
                    .is_some_and(|snapshot| snapshot.session == session);
                if ended {
                    receipt.lost = true;
                    self.evidence.join_lost = self.evidence.join_lost.saturating_add(1);
                }
            }
        }
    }

    /// Assemble this quantum's positional receipts: the seal's
    /// references qualified to the settled call's ticket (never
    /// another call's), each carrying the input ordinal the qualified
    /// model join minted — never a renumbering of successful
    /// references (holes stay holes; equal handles keep both
    /// positions). Found-handle references join no input and yield no
    /// receipt. Each receipt snapshots metadata presence known by —
    /// not after — this transition. Callers pass the seal's verified
    /// single settled call (see [`JointStaging::apply_seal`]).
    pub(crate) fn receipts_for_call(
        &mut self,
        seal: &SealSuccess,
        settled: &SealedCall,
        model: &ObjectSemantics,
        position: u64,
    ) -> Vec<KeyReceipt> {
        let mut receipts = Vec::new();
        for effect in &seal.effects.effects {
            let ObjectEffect::Referenced {
                call, object, input, ..
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
            let snapshot = model.receipt_snapshot(*object);
            if snapshot.is_none() {
                self.evidence.metadata_unavailable =
                    self.evidence.metadata_unavailable.saturating_add(1);
            }
            let metadata = model
                .key_metadata_flags(*object)
                .unwrap_or(KeyMetadataFlags::ZERO);
            receipts.push(KeyReceipt {
                key: *object,
                function: settled.function,
                input: *input,
                role,
                position,
                metadata,
                label: snapshot.and_then(|seen| seen.label),
                attribution_valid: snapshot.is_some_and(|seen| seen.attribution_valid),
                lost: false,
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
}

impl<S: OperationSink> OperationSink for KeyUseTee<'_, S> {
    const WANTS_EFFECTS: bool = true;

    fn emit(&mut self, effect: OperationEffect) {
        self.keyuse.observe_effect(self.instance, &effect);
        self.outer.emit(effect);
    }
}
