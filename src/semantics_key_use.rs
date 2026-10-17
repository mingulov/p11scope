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
use crate::semantics_objects::{ObjectEffect, ObjectId, ObjectSemantics, SessionIncarnation};
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
        KeyRole::Other => "other",
    }
}

/// The frozen metadata-at-use label for one established key label:
/// shared by aggregate reservation and the projection's rows, so
/// admission and publication cannot disagree on buckets.
pub(crate) fn metadata_label(label: crate::semantics_objects::KeyLabel) -> &'static str {
    use crate::semantics_objects::KeyLabel;
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
        },
    }
}

/// The usable metadata-at-use label (H9 §72): established-only,
/// valid attribution, non-conflicting required fields. Decides
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
    };
    if receipt.metadata.conflicted & required != 0 {
        return None;
    }
    Some(metadata_label(label))
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

/// One fixed unknown-key summary's counters (H9 §82): terminal
/// outcomes partitioned once per primary operation role, plus live
/// unknown-key activity. Fixed vocabulary — always admitted, never
/// a positive row, never a capacity refusal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UnknownCounters {
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub unknown: u64,
    pub active: u64,
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
    unknown: [UnknownCounters; UNKNOWN_BUCKETS],
    capacity: usize,
    evidence: KeyUseEvidence,
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
            unknown: [UnknownCounters::default(); UNKNOWN_BUCKETS],
            capacity,
            evidence: KeyUseEvidence::default(),
        }
    }

    pub(crate) fn aggregates(&self) -> &BTreeMap<AggKey, AggCounters> {
        &self.aggregates
    }

    pub(crate) fn unknown_counters(&self) -> &[UnknownCounters; UNKNOWN_BUCKETS] {
        &self.unknown
    }

    pub(crate) fn open(&self) -> &BTreeMap<(RegistryInstanceId, OperationId), OpenKeyUse> {
        &self.open
    }

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

    /// Observe one operation effect from one instance: reserve
    /// aggregate buckets on start (refuse at N+1, never evict),
    /// close into the reserved buckets on end, complete atomically
    /// on direct. Terminals move within reserved buckets and fixed
    /// summaries and allocate nothing.
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
                    self.refuse(key, instance, category, origin.ts_ns);
                    return;
                }
                self.open_buckets(resolved);
                let associations = resolved
                    .iter()
                    .zip(receipts.iter())
                    .map(|(slot, receipt)| OpenAssoc {
                        bucket: slot.bucket,
                        key: receipt.key,
                        lost: false,
                        primary: slot.primary,
                    })
                    .collect();
                if receipts.is_empty() {
                    // A receipt-less open is live unknown-key S1:
                    // active now, outcome at close.
                    let slot = unknown_index(category, unbound_reason_for(category));
                    self.unknown[slot].active = self.unknown[slot].active.saturating_add(1);
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
                    },
                );
            }
            OperationEffect::Ended {
                id,
                category: _,
                outcome,
                origin: _,
            } => {
                let key = (instance, *id);
                if let Some(open) = self.open.remove(&key) {
                    self.close_open(open, *outcome);
                    return;
                }
                if let Some(refused) = self.refused.remove(&key) {
                    // A refused start's terminal: S1 owns the
                    // outcome; the key side preserves it in the
                    // fixed unknown summary — never a positive row.
                    let slot =
                        unknown_index(refused.category, unbound_reason_for(refused.category));
                    self.unknown[slot].active = self.unknown[slot].active.saturating_sub(1);
                    self.unknown[slot].add(*outcome);
                    self.evidence.refused_terminals =
                        self.evidence.refused_terminals.saturating_add(1);
                    return;
                }
                // An end without a start: no fabricated start — the
                // outcome lands in the fixed unknown summary, which
                // needs no positive row and never refuses.
                self.evidence.orphan_ends = self.evidence.orphan_ends.saturating_add(1);
                self.unknown[unknown_index("unknown", "unbound")].add(*outcome);
            }
            OperationEffect::DirectCompleted {
                category,
                key_receipts,
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
                    self.unknown[slot].add(OperationOutcome::Completed);
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
                    self.unknown[slot].add(OperationOutcome::Completed);
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
                                self.unknown[index].add(OperationOutcome::Completed);
                            }
                        }
                    }
                }
                if !saw_primary {
                    // Secondary-only direct: the proved secondary
                    // associations stand above while the missing
                    // primary's terminal partitions unknown.
                    let slot = unknown_index(category, unbound_reason_for(category));
                    self.unknown[slot].add(OperationOutcome::Completed);
                }
            }
        }
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
                }
                AssocBucket::Unknown(index) => {
                    self.unknown[index].active = self.unknown[index].active.saturating_add(1);
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
        if !open.bound {
            self.evidence.unknown_key_rows = self.evidence.unknown_key_rows.saturating_add(1);
            let slot = unknown_index(open.category, unbound_reason_for(open.category));
            self.unknown[slot].active = self.unknown[slot].active.saturating_sub(1);
            self.unknown[slot].add(outcome);
            return;
        }
        let mut saw_primary = false;
        for assoc in open.associations {
            saw_primary = saw_primary || assoc.primary;
            match assoc.bucket {
                AssocBucket::Proved(bucket) => {
                    let counters = self
                        .aggregates
                        .get_mut(&bucket)
                        .expect("admission reserved every proved bucket");
                    counters.active = counters.active.saturating_sub(1);
                    if assoc.lost {
                        counters.key_join_lost = counters.key_join_lost.saturating_add(1);
                    } else {
                        counters.add(outcome);
                    }
                }
                AssocBucket::Unknown(index) => {
                    self.unknown[index].active = self.unknown[index].active.saturating_sub(1);
                    if assoc.primary && !assoc.lost {
                        self.unknown[index].add(outcome);
                    }
                }
            }
            if assoc.primary && assoc.lost {
                // A retired primary's S1 terminal routes once to the
                // unknown-key summary; its proved bucket already
                // closed `key_join_lost` above.
                self.unknown[unknown_index(open.category, "key_join_lost")].add(outcome);
            }
        }
        if !saw_primary {
            // A secondary-only operation has no primary: its proved
            // secondary associations stand above while the missing
            // primary's terminal partitions unknown (never a
            // promotion of the secondary).
            let slot = unknown_index(open.category, unbound_reason_for(open.category));
            self.unknown[slot].add(outcome);
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
    ) {
        self.refused.insert(
            key,
            RefusedOpen {
                instance,
                category,
                started_ts_ns,
            },
        );
        let slot = unknown_index(category, unbound_reason_for(category));
        self.unknown[slot].active = self.unknown[slot].active.saturating_add(1);
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
            let bucket = match usable_label(receipt) {
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

    /// End every active association on one object before its S1
    /// terminal (H9 §66): each loses its join once; the terminal
    /// still lands later through the ordinary path.
    pub(crate) fn retire_object(&mut self, object: ObjectId) {
        for open in self.open.values_mut() {
            for assoc in &mut open.associations {
                if assoc.key == object && !assoc.lost {
                    assoc.lost = true;
                    self.evidence.join_lost = self.evidence.join_lost.saturating_add(1);
                }
            }
        }
    }

    /// End every active association whose key the model attributes
    /// to one ended session (domain/session loss, H9 §66).
    pub(crate) fn retire_session(&mut self, session: SessionIncarnation, model: &ObjectSemantics) {
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
    /// receipt. Metadata (presence, label, attribution) is the
    /// snapshot the join froze into the effect — never the model's
    /// current state, so routing delay cannot backfill an earlier
    /// use. Callers pass the seal's verified single settled call
    /// (see [`JointStaging::apply_seal`]).
    pub(crate) fn receipts_for_call(
        &mut self,
        seal: &SealSuccess,
        settled: &SealedCall,
        _model: &ObjectSemantics,
        position: u64,
    ) -> Vec<KeyReceipt> {
        let mut receipts = Vec::new();
        for effect in &seal.effects.effects {
            let ObjectEffect::Referenced {
                call,
                object,
                input,
                metadata,
                label,
                attribution_valid,
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
                attribution_valid: *attribution_valid,
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
