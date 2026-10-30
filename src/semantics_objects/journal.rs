//! SPDX-License-Identifier: GPL-3.0-or-later
//! Sealed object-journal authority (H8): the private consumer that turns the
//! inactive journal wire into proven model inputs.
//!
//! This child owns the frozen effect-neutral S1 vocabulary, the finite
//! ABANDON reason-to-disposition matrix, the retained-cursor consumer
//! (frontier/audit), endpoint closure, birth witnesses and the sealed
//! prefix H9 consumes. It produces sealed authority, never public object
//! rows: conversion into the existing model lives here, projection stays
//! with H9.
//!
//! The native producer is inactive: no BPF root emits journal records, so
//! every ingest below consumes Session-decoded bytes plus Session-owned
//! audit evidence, never live ring state. Slices land in order: vocabulary
//! and disposition first, then ingest/terminal matching, then frontier and
//! capacity, then closure and bootstrap.
//!
//! Provenance: `docs/superpowers/plans/2026-10-09-object-journal-bootstrap.md`.
//! Privacy: raw handles, words, cuts and keys stay in the model's private
//! newtypes; this module adds no target-memory read, pointer output or
//! capture beyond allowlist v1/v2 and the six approved v3 attributes.

#[path = "journal/joint_audit.rs"]
pub(crate) mod joint_audit;
#[path = "joint_driver.rs"]
pub(crate) mod joint_driver;
#[cfg(test)]
mod native_producer_tests;
mod reservations;
#[cfg(all(test, p11scope_journal_roots))]
mod root_proof_tests;
mod seal_replay;
use seal_replay::ReplayPreparation;
pub(crate) use seal_replay::{SealBatchDelivery, SealReplayPhase, SealReplayStep};

// ---------------------------------------------------------------------------
// Frozen effect-neutral S1 vocabulary
// ---------------------------------------------------------------------------

/// The exact finite effect-neutral S1 operation vocabulary, in plan order.
/// Neutral calls participate in BEGIN/END, overlap, loss and replay ordering
/// and carry existing S1 facts; they mint no object references, results or
/// new selector-read authority. Existing object descriptors retain precedence
/// for key-bearing Init, DigestKey and direct object calls; async controls,
/// token initialization, KEM and authenticated-wrap neighbors do not become
/// neutral by analogy. A later catalog addition requires an explicit
/// classification amendment here, never a prefix match.
pub(crate) const NEUTRAL_S1_FUNCTIONS: [&str; 41] = [
    "C_DigestInit",
    "C_Encrypt",
    "C_Decrypt",
    "C_Digest",
    "C_Sign",
    "C_SignRecover",
    "C_Verify",
    "C_VerifyRecover",
    "C_EncryptUpdate",
    "C_DecryptUpdate",
    "C_DigestUpdate",
    "C_SignUpdate",
    "C_VerifyUpdate",
    "C_EncryptFinal",
    "C_DecryptFinal",
    "C_DigestFinal",
    "C_SignFinal",
    "C_VerifyFinal",
    "C_DigestEncryptUpdate",
    "C_DecryptDigestUpdate",
    "C_SignEncryptUpdate",
    "C_DecryptVerifyUpdate",
    "C_EncryptMessage",
    "C_EncryptMessageBegin",
    "C_EncryptMessageNext",
    "C_DecryptMessage",
    "C_DecryptMessageBegin",
    "C_DecryptMessageNext",
    "C_SignMessage",
    "C_SignMessageBegin",
    "C_SignMessageNext",
    "C_VerifyMessage",
    "C_VerifyMessageBegin",
    "C_VerifyMessageNext",
    "C_MessageEncryptFinal",
    "C_MessageDecryptFinal",
    "C_MessageSignFinal",
    "C_MessageVerifyFinal",
    "C_VerifySignature",
    "C_VerifySignatureUpdate",
    "C_VerifySignatureFinal",
];

/// Whether a canonical function ordinal names an effect-neutral S1
/// operation: exact catalog-name membership, never a prefix or operation
/// bit. Unknown ordinals are not neutral.
pub(crate) fn is_neutral_function(function: u32) -> bool {
    let Some(name) = pkcs11_module::function_name(usize::try_from(function).unwrap_or(usize::MAX))
    else {
        return false;
    };
    NEUTRAL_S1_FUNCTIONS.contains(&name)
}

// ---------------------------------------------------------------------------
// Frozen endpoint classification: the closure's per-function table
// ---------------------------------------------------------------------------

/// What the journal owes one catalog function: full BEGIN/END tracking,
/// negative-only uncertainty, or provably nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointClass {
    /// The model accepts this function (object, lifecycle or neutral):
    /// the journal tracks its BEGIN/END for proof or ordering.
    ModeledAffecting,
    /// Affecting but unmodeled: never tracked for proof. An invocation
    /// arrives only as the NO_END invalidation signal and withholds
    /// proof as negative uncertainty.
    NegativeOnlyAffecting,
    /// Proved to touch nothing the proof relies on. Neither tracked for
    /// proof nor counted as affecting; ordinary observations still sight
    /// the image for birth chains.
    ProvedIrrelevant,
}

/// Affecting but unmodeled: never journaled, represented only as
/// negative uncertainty. C_Initialize resets cryptoki state (the init
/// era); C_InitToken wipes token objects and sessions; KEM and
/// authenticated-wrap calls create and use objects through unwired
/// protocols; async controls defer effects to unmodeled completions.
/// Both initializers share descriptor shapes with pure reads, and the
/// rest must survive descriptor-shape edits, so all nine are listed
/// explicitly rather than derived.
pub(crate) const NEGATIVE_ONLY_FUNCTIONS: [&str; 9] = [
    "C_Initialize",
    "C_InitToken",
    "C_EncapsulateKey",
    "C_DecapsulateKey",
    "C_WrapKeyAuthenticated",
    "C_UnwrapKeyAuthenticated",
    "C_AsyncComplete",
    "C_AsyncGetID",
    "C_AsyncJoin",
];

/// Proved irrelevant: calls that change nothing object proof relies
/// on (observed handles, return values, join validity, ordering,
/// session liveness, init era, token presence). Info/interface reads
/// observe without mutating and touch token/slot presence only as
/// observed facts; PIN changes touch only authorization; session-info
/// and operation-state reads observe without mutating; RNG calls touch
/// only RNG state; legacy cancel/status touch only untracked
/// operation/parallel state; slot-event wait and validation-flag reads
/// observe without mutating. Every entry is explicit: no function is
/// irrelevant by omission, and the default below stays conservative for
/// future additions. Classification reads no call arguments.
pub(crate) const PROVED_IRRELEVANT_FUNCTIONS: [&str; 19] = [
    "C_GetInfo",
    "C_GetFunctionList",
    "C_GetSlotList",
    "C_GetSlotInfo",
    "C_GetTokenInfo",
    "C_GetMechanismList",
    "C_GetMechanismInfo",
    "C_InitPIN",
    "C_SetPIN",
    "C_GetSessionInfo",
    "C_GetOperationState",
    "C_GenerateRandom",
    "C_SeedRandom",
    "C_GetFunctionStatus",
    "C_CancelFunction",
    "C_WaitForSlotEvent",
    "C_GetInterfaceList",
    "C_GetInterface",
    "C_GetSessionValidationFlags",
];

/// Classify one canonical function ordinal for the closure: modeled iff
/// the object model accepts it; proved irrelevant iff explicitly listed;
/// negative-only otherwise. Unlisted named functions default to
/// negative-only, never irrelevant by omission: a future catalog
/// addition, or a function the model stops accepting, conservatively
/// invalidates rather than vanishing.
/// Unknown ordinals and names outside the published inventory are
/// unclassified (`None`): the closure refuses them, never defaults
/// them. A catalog addition requires an explicit classification
/// amendment: the frozen census test fails on any unlisted name.
pub(crate) fn endpoint_class(function: u32) -> Option<EndpointClass> {
    if super::state::is_modeled_function(function) {
        return Some(EndpointClass::ModeledAffecting);
    }
    let name = pkcs11_module::function_name(usize::try_from(function).ok()?)?;
    if NEGATIVE_ONLY_FUNCTIONS.contains(&name) {
        return Some(EndpointClass::NegativeOnlyAffecting);
    }
    if PROVED_IRRELEVANT_FUNCTIONS.contains(&name) {
        return Some(EndpointClass::ProvedIrrelevant);
    }
    // Unlisted named functions default to negative-only, never
    // irrelevant by omission.
    Some(EndpointClass::NegativeOnlyAffecting)
}

// ---------------------------------------------------------------------------
// Finite ABANDON reason-to-disposition matrix
// ---------------------------------------------------------------------------

/// What one ABANDON reason permits. A wire reason alone never certifies a
/// bounded terminal witness: even the candidate below still requires
/// independent evidence of an upper cut after which the invocation cannot
/// affect provider state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AbandonDisposition {
    /// Observer custody was lost with unknown continuing effects: the
    /// affected exact incarnation's object proof is irreversibly refused
    /// before bounded resources are disposed. Never a `LostOutcome`.
    UnboundedInvalidation,
    /// The only reason that may accompany a bounded terminal witness: an
    /// observed completed synchronous provider return whose result is
    /// unavailable. Still requires the independent return evidence; without
    /// it the call invalidates like every other reason.
    BoundedWitnessCandidate,
}

/// The frozen reason-to-disposition matrix over the nine finite wire codes.
/// Unknown codes have no disposition.
pub(crate) fn abandon_disposition(reason: u32) -> Option<AbandonDisposition> {
    use AbandonDisposition::{BoundedWitnessCandidate, UnboundedInvalidation};
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_REASON_ABI_REFUSED, JOURNAL_REASON_ENTRY_COLLISION, JOURNAL_REASON_EXEC_EXIT,
        JOURNAL_REASON_IDENTITY_REFUSED, JOURNAL_REASON_INSERT_FAILED,
        JOURNAL_REASON_PARTIAL_TRANSACTION, JOURNAL_REASON_SCOPE_LOST, JOURNAL_REASON_STOP_CLEANUP,
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
    };
    match reason {
        JOURNAL_REASON_ENTRY_COLLISION
        | JOURNAL_REASON_INSERT_FAILED
        | JOURNAL_REASON_SCOPE_LOST
        | JOURNAL_REASON_ABI_REFUSED
        | JOURNAL_REASON_IDENTITY_REFUSED
        | JOURNAL_REASON_EXEC_EXIT
        | JOURNAL_REASON_STOP_CLEANUP
        | JOURNAL_REASON_PARTIAL_TRANSACTION => Some(UnboundedInvalidation),
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST => Some(BoundedWitnessCandidate),
        _ => None,
    }
}

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem::size_of;

use p11scope_ebpf_common::ImageIdentity;
use p11scope_ebpf_common::MAX_DESCRIPTORS;
use p11scope_ebpf_common::capture;
use p11scope_ebpf_common::object_journal::{
    JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, JournalRecord, ValidatedJournalAbandon,
    ValidatedJournalBegin, ValidatedJournalEnd,
};
use p11scope_ebpf_common::object_policy::SafeAttributeKind;

use super::{
    AttrObservation, AttributeList, CallKey, CallToken, CompleteInputPrefix, CompletedFact,
    FieldValue, FindResult, HandleInput, MechanismEvidence, ObjectDomain, ObjectEffect,
    ObjectEffects, ObjectGap, ObjectSemantics, OriginFact, QueryStatus, RefCut, ResultSlot,
    SessionHandle,
};
use crate::attach::capture::NativeDomainId;
use crate::discovery::caller_registry::instance_input::AdmittedInstanceCall;

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Injectable journal bounds. [`JournalLimits::policy`] is the H8 proposal:
/// 1,024 open plus completed-unsettled calls, 16,448 capture-lifetime
/// thread floors, 1,024 refused begins awaiting a bound, 4,096 domain keys,
/// 16,448 image birth sightings. Marker admissions (16,384) arrive with the
/// native marker experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JournalLimits {
    pub(crate) open_calls: usize,
    pub(crate) thread_floors: usize,
    pub(crate) refused_begins: usize,
    pub(crate) domain_keys: usize,
    pub(crate) image_sightings: usize,
}

impl JournalLimits {
    pub(crate) const fn policy() -> Self {
        Self {
            open_calls: 1_024,
            thread_floors: 16_448,
            refused_begins: 1_024,
            domain_keys: 4_096,
            image_sightings: 16_448,
        }
    }
}

/// Unsettled payloads across the whole capture (H9 §89): at most
/// 1,024 open H8 calls, staged H9 payloads and prospective key
/// associations share one logical ticket space. The H9 staging
/// bound mirrors this ceiling; the [`StagingLedger`] enforces it
/// across all feeds.
pub(crate) const MAX_UNSETTLED_STAGED: usize = 1_024;

#[path = "journal/ledger.rs"]
mod ledger;
pub(in crate::semantics_objects) use ledger::ExistingReservation;
pub(crate) use ledger::{LedgerRefusal, StagedResourceOrigin, StagingLedger};

// ---------------------------------------------------------------------------
// Sealed primitives: only the adapter mints these
// ---------------------------------------------------------------------------

/// One checked immutable consumption ordinal in reservation-consumption
/// order over the retained drain. Minted only by collection; the only path
/// to a production [`RefCut`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConsumptionOrdinal(u64);

impl ConsumptionOrdinal {
    pub(in crate::semantics_objects) fn cut(self) -> u64 {
        self.0
    }
}

/// One checked nonrecycled call ticket from the reservation owner. Minted
/// only by the adapter; the only path to a production [`CallKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct JournalTicket(u64);

impl JournalTicket {
    pub(in crate::semantics_objects) fn key(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Sealed domain identity: only actual H3 admission proves these
// ---------------------------------------------------------------------------

/// One journal-tracked incarnation key: the native domain tag, the H3-bound
/// caller, the exact image (task cookie plus exec id) and the H3 router.
/// Keys are never removed until the adapter drops, so a refused or ended
/// incarnation is never silently reborn under the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct JournalDomainKey {
    domain_tag: u64,
    caller: u32,
    cookie: u64,
    exec: u64,
    router: u64,
}

/// Production domain proof: a key plus the adapter-tracked initialization
/// era, built only from actual H3 admission evidence. The only path to a
/// production [`ObjectDomain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JournalDomainProof {
    key: JournalDomainKey,
    era: u64,
}

/// One admitted call's journal-attribution shape: the exact overlap
/// between H3's admitted facts and a staged BEGIN's wire scalars (plus
/// the image both sides bind). Original Event duration reconstructs
/// the exact retained START timestamp; physical thread and attested slot
/// distinguish same-shaped invocations. Return time stays claim-side
/// until checked against an END and advanced into its physical fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CallFingerprint {
    pub(crate) image: (u64, u64),
    pub(crate) function: u32,
    pub(crate) pid_tgid: u64,
    pub(crate) entry_ns: u64,
    pub(crate) slot: u32,
    pub(crate) session: u64,
    pub(crate) mechanism: u64,
    pub(crate) capture: u32,
    pub(crate) slot_id: u64,
    pub(crate) flags: u64,
    pub(crate) user_type: u32,
}

fn fingerprint_matches_event(
    fingerprint: &CallFingerprint,
    event: &p11scope_ebpf_common::Event,
) -> bool {
    fingerprint.image == (event.image.task_cookie, event.image.exec_id)
        && fingerprint.pid_tgid == event.pid_tgid
        && event.duration_ns != 0
        && Some(fingerprint.entry_ns) == event.ts_ns.checked_sub(event.duration_ns)
        && fingerprint.slot == event.slot
        && fingerprint.session == event.session
        && fingerprint.mechanism == event.mechanism
        && fingerprint.capture == event.capture
        && fingerprint.slot_id == event.slot_id
        && fingerprint.flags == event.flags
        && fingerprint.user_type == event.user_type
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AdmittedJournalClaim {
    admission: u64,
    return_ns: u64,
}

/// One staged entry's attribution under a sealing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallAttribution {
    /// Sole live claim is this key (or this key is the sole live key
    /// for the image, whose admission completeness the H3-disposition
    /// gate covers): convertible here.
    Mine,
    /// Another key owns this entry (a live sibling's claim, or solely
    /// dead claims): skipped by this seal, never converted here.
    Sibling,
    /// No claim names this entry, or two live keys collide on it:
    /// the seal waits rather than attribute.
    Unclaimed,
}

impl JournalDomainProof {
    pub(crate) fn matches_admitted(&self, admitted: &AdmittedInstanceCall) -> bool {
        let (native, image, router, caller) = admitted.journal_binding();
        self.key.domain_tag == native.journal_tag()
            && self.key.cookie == image.task_cookie
            && self.key.exec == image.exec_id
            && self.key.router == router.get()
            && self.key.caller == caller.0
    }
    pub(in crate::semantics_objects) fn domain(&self) -> ObjectDomain {
        ObjectDomain::from_sealed_parts(
            u64::from(self.key.caller),
            self.key.cookie,
            self.key.domain_tag,
            self.key.router,
            self.era,
        )
    }
}

/// One image's birth evidence: its first consumed ordinal in any form
/// and its first affecting ordinal (any journal record, or an ordinary
/// record naming a modeled, negative-only or unclassified function).
/// Ordinary records naming proved-irrelevant functions observe the image
/// without affecting it; a fork sighting of a child image always counts
/// as affecting (inherited provider state). Consumed-history facts:
/// voids never clear them, so a voided interval stays unbridgeable and
/// only genuinely new images birth after a void.
#[derive(Debug, Clone, Copy)]
struct ImageSighting {
    first_seen: u64,
    first_affecting: Option<u64>,
}

/// Per-key adapter state: the current era, refusal stickiness, model
/// registration, the bootstrap cuts and bounded-loss uppers that gate
/// later seals, and the void fence (history at or below it is explicitly
/// lost, so later proof resumes at or above it).
#[derive(Debug, Default)]
struct JournalDomainState {
    era: u64,
    refused: bool,
    /// A genuinely marked S1Only original was disposed for this retained
    /// exact key. This negative provenance survives image-independent voids;
    /// it never restores a live key, changes its era or authorizes a seal.
    s1only_original_refused: bool,
    tainted: bool,
    era_ended: bool,
    sealed_through: u64,
    bootstraps: BTreeMap<u64, u64>,
    /// The maximum recorded bounded-loss upper for this key. The fence
    /// needs the max alone, so no per-loss vector is retained.
    bounded_upper: Option<u64>,
    void_fence: u64,
    model_registered: bool,
}

// ---------------------------------------------------------------------------
// Fault audit seam
// ---------------------------------------------------------------------------

/// Finite checked-fault read failure. Any failure withholds proof; it never
/// reads as a clean zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultReadError {
    Unreadable,
    /// The cell exceeds the u32 domain: saturated, permanently disabling
    /// proof for this adapter.
    Saturated,
}

/// The checked-fault epoch reader the seal audits. Production reads the
/// session's mmapable fault cell through the existing instance maps; tests
/// script an equivalent cell. A read/CAS error is not a clean audit.
pub(crate) trait FaultEpoch {
    fn fault_epoch(&self) -> Result<u64, FaultReadError>;
}

impl FaultEpoch for crate::attach::InstanceMaps<'_> {
    fn fault_epoch(&self) -> Result<u64, FaultReadError> {
        let epoch = self.fault().map_err(|_| FaultReadError::Unreadable)?;
        if epoch > u64::from(u32::MAX) {
            return Err(FaultReadError::Saturated);
        }
        Ok(epoch)
    }
}

// ---------------------------------------------------------------------------
// Ingest records and dispositions
// ---------------------------------------------------------------------------

/// One journal record with its Session-owned consumption ordinal. Built
/// only by collection over the retained drain, in delivery order.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuditedJournalRecord {
    ordinal: ConsumptionOrdinal,
    record: JournalRecord,
}

impl AuditedJournalRecord {
    /// Collection-only constructor: the ingest assigns the ordinal.
    fn collected(ordinal: ConsumptionOrdinal, record: JournalRecord) -> Self {
        Self { ordinal, record }
    }
}

/// What one ingested record did. Every contradiction taints before
/// disposing; nothing silently skips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalDisposition {
    /// A BEGIN reserved one open entry (or recorded a capacity refusal).
    BeginAdmitted,
    /// A capacity refusal was recorded for a later bound or seal refusal.
    BeginRefusedCapacity,
    /// An END matched its open key and staged its terminal.
    EndStaged,
    /// An ABANDON matched its open key and staged its disposition.
    AbandonStaged,
    /// A negative-only invocation arrived as the frozen valid NO_END
    /// signal: the possibly affected image is tainted and its staged
    /// entries disposed without proof. A legal signal, not a
    /// contradiction — but proof for the image ends here.
    NegativeOnlyInvalidated,
    /// An ordinary CALL corroborated an open key's synchronous return.
    ReturnObserved,
    /// An ordinary record carried no journal meaning; its ordinal still
    /// counts toward frontier completeness.
    OrdinaryCounted,
    /// The record contradicted retained journal truth: the affected image
    /// or key is tainted and the entry disposed without proof.
    Contradiction(JournalContradiction),
    /// Ingest after stop, or for a tainted/refused image: refused outright.
    Refused,
}

/// Finite ingest contradiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalContradiction {
    DuplicateBegin,
    TerminalBeforeBegin,
    DuplicateTerminal,
    SequenceRegression,
    NoEndCompleted,
    EndBeginMismatch,
    CallAndEnd,
    AmbiguousReturn,
    FloorExhausted,
    RefusedOverflow,
    /// A BEGIN named a function outside the journaled set (unclassified
    /// or proved irrelevant), or a negative-only invocation promised an
    /// END against the frozen NO_END entry rule: the frozen endpoint
    /// table is contradicted and the image is tainted.
    UnclosedEndpoint,
}

/// Finite seal/audit refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalGap {
    FaultChanged,
    FaultUnreadable,
    FaultSaturated,
    Malformed,
    /// A cumulative reader counter regressed or saturated; the lost
    /// history bound cannot be established from this audit.
    CounterUnprovable,
    /// Resource custody could not retain an original invocation or a
    /// required physical role. This is separate from malformed wire/loss.
    ResourceUnavailable,
    H3Pending,
    H3Loss,
    AdapterInvalidated,
    DomainTainted,
    ImageTainted,
    FrontierRegression,
    BootstrapMismatch,
    /// A required terminal or capacity bound is not yet established within
    /// this frontier: staged inputs are kept for a later seal, nothing is
    /// published, and no proof is voided.
    BoundNotReady,
    ModelRefused,
    DomainEnded,
    ClosureStale,
    Stopped,
    /// The collection's Session drain is not the proof's: history
    /// collected through one Session never seals under another's key.
    /// A wiring refusal, not a loss: nothing is voided.
    DrainMismatch,
    /// The H0 allocator is exhausted: no future history can certify.
    /// The adapter stops permanently.
    H3Exhausted,
    /// The retained reader consumed kernel-discarded reservations
    /// during the collection: lost history voids the seal.
    Discarded,
    /// A required strict cut increment overflowed the cut space:
    /// `u64::MAX` has no successor, so no fence above it can be
    /// derived. The seal refuses explicitly instead of saturating
    /// into a vacuous re-seal; staged inputs are kept.
    CutExhausted,
}

/// The model's bootstrap floor: strictly above the birth, the last
/// sealed frontier, the void fence and every recorded or pending loss
/// bound. The maximum of strict successors is the strict successor of
/// the maximum, so one checked increment derives the whole floor.
fn derive_model_floors(
    birth_cut: u64,
    sealed_through: u64,
    void_fence: u64,
    bounded_upper: Option<u64>,
    pending_bounds: &[u64],
) -> Result<u64, JournalGap> {
    let mut bound = birth_cut.max(sealed_through).max(void_fence);
    if let Some(upper) = bounded_upper {
        bound = bound.max(upper);
    }
    for at in pending_bounds {
        bound = bound.max(*at);
    }
    bound.checked_add(1).ok_or(JournalGap::CutExhausted)
}

// ---------------------------------------------------------------------------
// The adapter: ingest, terminal matching and sealed conversion
// ---------------------------------------------------------------------------

/// Native call identity: the physical-task lifetime ticket plus the
/// per-thread affecting-entry sequence. Never a pid_tgid, handle or cut.
type JournalNativeKey = (u64, u64);

/// One staged open call: its BEGIN facts plus at most one terminal. Model
/// tickets are minted at seal, not at ingest: ingest stages wire truth,
/// the seal converts it after the audit passes.
#[derive(Debug, Clone, Copy)]
struct OpenEntry {
    begin_ordinal: u64,
    image: (u64, u64),
    function: u32,
    begin: ValidatedJournalBegin,
    call_key: Option<CallKey>,
    end: Option<StagedEnd>,
    abandon: Option<StagedAbandon>,
    corroborated_return: Option<u64>,
    converted_ticket: Option<CallToken>,
    converted_for: Option<JournalDomainKey>,
    end_converted: bool,
    /// Resource-only lineage from this exact retained native invocation.
    raw_resource: Option<ledger::ExistingReservation>,
    /// The actual END's H0 allocation survives while that original remains
    /// in H8, including a real refresh-stash handoff into a later quantum.
    collected_origin: Option<joint_driver::CollectedCallOrigin>,
    /// Exact admitted S1Only subject retained before registry staging. The
    /// original END/origin/reservation above remain the only physical owner;
    /// this association permits a later bulk negative, never conversion.
    s1only_subject: Option<JournalDomainKey>,
}

#[derive(Debug, Clone, Copy)]
struct StagedEnd {
    ordinal: u64,
    end: ValidatedJournalEnd,
}

#[derive(Debug, Clone, Copy)]
struct StagedAbandon {
    ordinal: u64,
    abandon: ValidatedJournalAbandon,
}

/// One consumed but unrepresentable BEGIN (reservation full): its cut and
/// identity are retained for a later lost-outcome bound or seal refusal.
/// Never silently dropped below its bound.
#[derive(Debug, Clone, Copy)]
struct RefusedBegin {
    cut: u64,
    image: (u64, u64),
    pid_tgid: u64,
    function: u32,
    slot: u32,
    session: u64,
    mechanism: u64,
    slot_id: u64,
    user_type: u32,
    capture: u32,
    flags: u64,
    entry_ns: u64,
    corroborated_return: Option<u64>,
}

/// Everything one consumed ring record can be to the journal: a validated
/// journal form or an ordinary decoded record (which still consumes one
/// ordinal toward frontier completeness).
#[derive(Clone, Copy)]
pub(crate) enum JournalIngestItem {
    Journal(JournalRecord),
    Ordinary(crate::events::DecodedEventRecord),
}

impl std::fmt::Debug for JournalIngestItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Journal(record) => match record {
                JournalRecord::Begin(_) => "JournalIngestItem::Begin(<private>)",
                JournalRecord::End(_) => "JournalIngestItem::End(<private>)",
                JournalRecord::Abandon(_) => "JournalIngestItem::Abandon(<private>)",
            },
            Self::Ordinary(_) => "JournalIngestItem::Ordinary(<private>)",
        })
    }
}

/// The sealed journal consumer. One adapter serves one Session's retained
/// drain: domain identity is implicit in that ownership, never a supplied
/// integer. Ingest is wire truth only; model input happens at seal, after
/// the audit passes, so an audit failure voids staged proof before any
/// model input exists to corrupt.
pub(crate) struct JournalAdapter {
    limits: JournalLimits,
    consumed_through: u64,
    stream_boundary: Option<crate::events::EventsConsumptionCut>,
    stream_broken: bool,
    open: BTreeMap<JournalNativeKey, OpenEntry>,
    floors: BTreeMap<u64, u64>,
    /// One ordered Session EVENTS/boot-clock namespace. Non-evicted
    /// physical-thread return fences complement native sequence floors:
    /// newly arriving STARTs must follow a proved physical API return.
    /// Existing retained overlapping STARTs are not compared to this.
    /// Both maps survive void, exec, era and native-thread-ticket changes.
    /// The pinned Rust B-tree requested-allocation estimate is 320 bytes
    /// per retained u64 pair plus 224 root/2560 split scratch: at the
    /// policy bound, 5,266,144 bytes. Count enforcement is active; full
    /// H9 shared-byte enforcement remains an explicit separate carry.
    physical_return_floors: BTreeMap<u64, u64>,
    refused: Vec<RefusedBegin>,
    keys: BTreeMap<JournalDomainKey, JournalDomainState>,
    image_keys: BTreeMap<(u64, u64), Vec<JournalDomainKey>>,
    /// Individually retained taints, capped at the sighting bound (the
    /// same image population). Past the cap, `taint_overflow` latches
    /// and every untracked image counts as tainted — the conservative
    /// bounded fallback: no per-image retention, no silent admission.
    tainted_images: BTreeSet<(u64, u64)>,
    taint_overflow: bool,
    sightings: BTreeMap<(u64, u64), ImageSighting>,
    /// Exact physical invocation claims, qualified by native domain,
    /// image, caller/router and era authority. A deque represents
    /// duplicate/colliding inputs only; conversion never selects a
    /// winner by FIFO rank. Counts remain bounded by unsettled work.
    claims: BTreeMap<CallFingerprint, BTreeMap<JournalDomainKey, VecDeque<AdmittedJournalClaim>>>,
    claim_counts: usize,
    last_audit_failure: Option<u64>,
    /// H0 positions below this watermark were voided by an H3-loss
    /// seal: re-presented barriers at or below it wait instead of
    /// voiding twice. Monotone; H0's allocator ascends, so each new
    /// loss lies above it.
    h3_voided_below: u64,
    /// Consumption upper bound of explicitly voided history
    /// (inclusive): births naming a cut below it refuse, so a key
    /// created after a void cannot certify the voided interval.
    /// Monotone; every fence-voiding seal advances it.
    voided_through: u64,
    /// Last sealed checked-fault epoch: the cumulative chain. Each
    /// seal's collection must open at this epoch and the seal-time
    /// re-read must still show the audited one; a move anywhere in
    /// the chain voids and re-baselines.
    last_fault: Option<u64>,
    /// The Session drains this adapter serves, one EVENTS-map identity
    /// per attested native domain, bound exclusively by Session
    /// authority ([`JournalAdapter::bind_session_drain`]) before any
    /// collection. Presentation never pins: a drain whose EVENTS-map
    /// identity is not bound to an attested domain consumes nothing
    /// even when presented first, and a seal under a key whose domain
    /// binds another EVENTS identity refuses. Bounded by the attested
    /// domains (a subset of the key table).
    drain_pins: BTreeMap<u64, u64>,
    invalidated: bool,
    stopped: bool,
    closure_generation: u64,
    /// The one shared reservation owner (N1c): H8 open begins,
    /// model pending calls, staged H9 payloads and prospective key
    /// associations all take tickets from this ledger. H9 borrows
    /// it per call through [`ledger`](Self::ledger_mut).
    ledger: StagingLedger,
    /// Frozen resource-custody Session pair. This binds no semantic drain,
    /// closure, key, birth or H0 authority; those retain their real minters.
    resource_producers: Option<crate::attach::SessionDrainProducers>,
}

impl JournalAdapter {
    #[cfg(test)]
    pub(crate) fn new(limits: JournalLimits) -> Self {
        Self::with_ledger(limits, StagingLedger::new())
    }

    pub(crate) fn with_ledger(limits: JournalLimits, ledger: StagingLedger) -> Self {
        Self {
            limits,
            consumed_through: 0,
            stream_boundary: None,
            stream_broken: false,
            open: BTreeMap::new(),
            floors: BTreeMap::new(),
            physical_return_floors: BTreeMap::new(),
            refused: Vec::new(),
            keys: BTreeMap::new(),
            image_keys: BTreeMap::new(),
            tainted_images: BTreeSet::new(),
            taint_overflow: false,
            sightings: BTreeMap::new(),
            claims: BTreeMap::new(),
            claim_counts: 0,
            last_audit_failure: None,
            h3_voided_below: 0,
            voided_through: 0,
            last_fault: None,
            drain_pins: BTreeMap::new(),
            invalidated: false,
            stopped: false,
            closure_generation: 0,
            ledger,
            resource_producers: None,
        }
    }

    /// The shared reservation ledger (read side).
    pub(crate) fn ledger(&self) -> &StagingLedger {
        &self.ledger
    }

    /// The shared reservation ledger (charge side): H9 staging and
    /// the key-use reducer borrow it per call.
    pub(crate) fn ledger_mut(&mut self) -> &mut StagingLedger {
        &mut self.ledger
    }

    /// Remove actual retained values before refunding their physical role.
    /// The fixed ledger bounds this scan; collecting keys never allocates.
    fn remove_open_where(&mut self, mut remove: impl FnMut(&JournalNativeKey, &OpenEntry) -> bool) {
        let mut keys = [(0, 0); MAX_UNSETTLED_STAGED];
        let mut count = 0;
        for (key, entry) in &self.open {
            if remove(key, entry) {
                keys[count] = *key;
                count += 1;
            }
        }
        for key in &keys[..count] {
            let ordinal = self.open.remove(key).expect("retained key").begin_ordinal;
            self.ledger.release_h8open(ordinal);
        }
    }

    fn bind_resource_producers(
        &mut self,
        producers: &crate::attach::SessionDrainProducers,
    ) -> bool {
        match &self.resource_producers {
            Some(retained) => retained.same_producers(producers),
            None => {
                self.resource_producers = Some(producers.clone());
                true
            }
        }
    }

    /// The current consumption frontier: the highest ordinal consumed, in
    /// any form. The only source of seal frontiers besides older held
    /// values, so a seal can never claim unconsumed history.
    /// Test-only read of the consumed ordinal: H9 scenes mirror the
    /// seal's H3 coverage claim against it. Production passes the
    /// opaque frontier through, never minting from raw cuts.
    #[cfg(test)]
    pub(crate) fn consumed_through_for_test(&self) -> u64 {
        self.consumed_through
    }

    /// Read-only allocation identity check; this never binds a new producer.
    pub(crate) fn retains_producers(
        &self,
        producers: &crate::attach::SessionDrainProducers,
    ) -> bool {
        self.resource_producers
            .as_ref()
            .is_some_and(|held| held.same_producers(producers))
    }

    #[cfg(test)]
    pub(crate) fn retained_starts_for_test(&self) -> Vec<(u64, u64, u64)> {
        self.open
            .iter()
            .map(|(native, entry)| (native.0, native.1, entry.begin_ordinal))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn retained_start_bytes_for_test(
        &self,
        native: (u64, u64),
    ) -> Option<[u8; p11scope_ebpf_common::object_journal::JOURNAL_BEGIN_BYTES]> {
        self.open.get(&native).map(|entry| *entry.begin.bytes())
    }

    /// Read the canonical invocation store and its independent census.
    /// This inspection neither claims nor consumes an original admission.
    #[cfg(test)]
    pub(crate) fn invocation_claims_for_test(&self) -> (usize, Vec<(u64, JournalDomainProof)>) {
        let mut originals = Vec::new();
        for claimants in self.claims.values() {
            for (key, claims) in claimants {
                let proof = JournalDomainProof {
                    key: *key,
                    era: self.keys[key].era,
                };
                originals.extend(claims.iter().map(|claim| (claim.admission, proof)));
            }
        }
        originals.sort_unstable_by_key(|(admission, _)| *admission);
        (self.claim_counts, originals)
    }

    #[cfg(test)]
    pub(crate) fn fault_baseline_for_test(&self) -> Option<u64> {
        self.last_fault
    }

    #[cfg(test)]
    pub(crate) fn open_entry_size_for_test() -> usize {
        size_of::<OpenEntry>()
    }

    #[cfg(test)]
    pub(crate) fn retained_open_charges_for_test(&self) -> Vec<usize> {
        self.open
            .values()
            .map(|entry| {
                self.ledger
                    .h8_open_bytes_for_test(entry.begin_ordinal)
                    .expect("retained actual H8 charge")
            })
            .collect()
    }

    pub(crate) fn consumed_frontier(&self) -> ConsumptionOrdinal {
        ConsumptionOrdinal(self.consumed_through)
    }

    /// Ingest one consumed record in delivery order, assigning it the next
    /// checked ordinal. Birth sightings are recorded before dispatch, so
    /// every consumed observation counts even when dispatch refuses it;
    /// a full sighting table taints the untrackable image and refuses the
    /// record. Ordinary records count toward completeness and may
    /// corroborate an open key's synchronous return; journal records match
    /// terminally against retained wire truth.
    pub(crate) fn ingest_any(&mut self, item: JournalIngestItem) -> JournalDisposition {
        // Direct fixtures/legacy consumers have no cursor-to-ordinal proof.
        // Never permit a later real cut to backfill that missing prefix.
        self.stream_broken = true;
        self.ingest_any_from_raw(item, None, false)
    }

    /// Assign the next original consumed position and record its actual
    /// sightings. Negative raw disposal uses this same accounting without
    /// interpreting a BEGIN/END as admitted H8 input.
    fn note_consumed_item(
        &mut self,
        item: &JournalIngestItem,
        proved_irrelevant: bool,
    ) -> Option<ConsumptionOrdinal> {
        let Some(next) = self.consumed_through.checked_add(1) else {
            self.invalidated = true;
            return None;
        };
        self.consumed_through = next;
        let ordinal = ConsumptionOrdinal(next);
        let mut sighted: [(u64, u64); 2] = [(0, 0); 2];
        let mut sighted_len = 0;
        let mut sight = |image: (u64, u64)| {
            if !sighted[..sighted_len].contains(&image) {
                sighted[sighted_len] = image;
                sighted_len += 1;
            }
        };
        match item {
            JournalIngestItem::Journal(record) => match record {
                JournalRecord::Begin(begin) => sight(Self::image_of_begin(begin)),
                JournalRecord::End(end) => sight(end_image(end)),
                JournalRecord::Abandon(abandon) => {
                    sight((abandon.image_cookie(), abandon.image_exec()));
                }
            },
            JournalIngestItem::Ordinary(decoded) => {
                let event = &decoded.base.event;
                sight((event.image.task_cookie, event.image.exec_id));
                let child = event.child_image;
                if child.task_cookie != 0 || child.exec_id != 0 {
                    sight((child.task_cookie, child.exec_id));
                }
            }
        }
        for image in &sighted[..sighted_len] {
            let affecting = match item {
                JournalIngestItem::Journal(_) => true,
                JournalIngestItem::Ordinary(decoded) => {
                    let event = &decoded.base.event;
                    let child = (event.child_image.task_cookie, event.child_image.exec_id);
                    // A forked child inherits its parent's provider state,
                    // so a present child sighting always counts as
                    // affecting; the acting image counts only when its
                    // function is not proved irrelevant (unclassified is
                    // suspect).
                    (*image == child && child != (0, 0)) || !proved_irrelevant
                }
            };
            if !self.note_sighting(*image, affecting, next) {
                self.taint_image(*image);
                return None;
            }
        }
        Some(ordinal)
    }

    fn ingest_any_from_raw(
        &mut self,
        item: JournalIngestItem,
        resource: Option<ledger::ExistingReservation>,
        proved_irrelevant: bool,
    ) -> JournalDisposition {
        let Some(ordinal) = self.note_consumed_item(&item, proved_irrelevant) else {
            return JournalDisposition::Refused;
        };
        let next = ordinal.0;
        match item {
            JournalIngestItem::Journal(record) => {
                if let JournalRecord::Begin(begin) = record
                    && !self.stopped
                    && !self.invalidated
                {
                    self.ingest_begin(next, begin, resource)
                } else {
                    self.ingest(AuditedJournalRecord::collected(ordinal, record))
                }
            }
            JournalIngestItem::Ordinary(decoded) => self.ingest_ordinary(next, &decoded.base.event),
        }
    }

    /// Record one image observation: first-sighting and first-affecting
    /// ordinals only move earlier-or-equal, never later. A new image past
    /// the sighting bound is untrackable: report false so the caller
    /// taints it and refuses the record. Past taint saturation every
    /// untracked image is untrackable even when the sighting table has
    /// room: a taint that cannot be retained must still refuse.
    fn note_sighting(&mut self, image: (u64, u64), affecting: bool, ordinal: u64) -> bool {
        if let Some(sighting) = self.sightings.get_mut(&image) {
            sighting.first_seen = sighting.first_seen.min(ordinal);
            if affecting {
                sighting.first_affecting = Some(
                    sighting
                        .first_affecting
                        .map_or(ordinal, |at| at.min(ordinal)),
                );
            }
            return true;
        }
        if self.taint_overflow {
            return false;
        }
        if self.sightings.len() >= self.limits.image_sightings {
            return false;
        }
        self.sightings.insert(
            image,
            ImageSighting {
                first_seen: ordinal,
                first_affecting: affecting.then_some(ordinal),
            },
        );
        true
    }

    /// The plan's ingest entry: one audited journal record to its finite
    /// disposition. Wire matching only; no model input.
    pub(crate) fn ingest(&mut self, record: AuditedJournalRecord) -> JournalDisposition {
        if self.stopped || self.invalidated {
            return JournalDisposition::Refused;
        }
        match record.record {
            JournalRecord::Begin(begin) => self.ingest_begin(record.ordinal.0, begin, None),
            JournalRecord::End(end) => self.ingest_end(record.ordinal.0, end),
            JournalRecord::Abandon(abandon) => self.ingest_abandon(record.ordinal.0, abandon),
        }
    }

    fn image_of_begin(begin: &ValidatedJournalBegin) -> (u64, u64) {
        (begin.image_cookie(), begin.image_exec())
    }

    fn ingest_begin(
        &mut self,
        ordinal: u64,
        begin: ValidatedJournalBegin,
        resource: Option<ledger::ExistingReservation>,
    ) -> JournalDisposition {
        let key = (begin.thread(), begin.sequence());
        let image = Self::image_of_begin(&begin);
        if self.is_tainted(image) {
            return JournalDisposition::Refused;
        }
        // The frozen endpoint table is enforced here, before key
        // mechanics: meaning before state. A negative-only invocation is
        // the valid NO_END invalidation signal; anything outside the
        // journaled set, or a negative-only call promising an END,
        // contradicts the table. Tainted records advance no floors.
        let function = begin.descriptor() - 1;
        match endpoint_class(function) {
            Some(EndpointClass::ModeledAffecting) => {}
            Some(EndpointClass::NegativeOnlyAffecting) if begin.no_end() => {
                self.taint_image(image);
                return JournalDisposition::NegativeOnlyInvalidated;
            }
            _ => {
                self.taint_image(image);
                return JournalDisposition::Contradiction(JournalContradiction::UnclosedEndpoint);
            }
        }
        if self.open.contains_key(&key) {
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::DuplicateBegin);
        }
        // Floors track observed sequences even for refused begins: a later
        // begin below an observed sequence is genuinely regressive.
        match self.floors.get(&begin.thread()) {
            Some(floor) if *floor >= begin.sequence() => {
                self.taint_image(image);
                return JournalDisposition::Contradiction(JournalContradiction::SequenceRegression);
            }
            _ => {}
        }
        if !self.floors.contains_key(&begin.thread())
            && self.floors.len() >= self.limits.thread_floors
        {
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::FloorExhausted);
        }
        if !self.physical_return_floors.contains_key(&begin.pid_tgid())
            && self.physical_return_floors.len() >= self.limits.thread_floors
        {
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::FloorExhausted);
        }
        let floor = self
            .physical_return_floors
            .entry(begin.pid_tgid())
            .or_default();
        if begin.pid_tgid() as u32 == 0 || begin.pid_tgid() >> 32 == 0 || begin.entry_ns() < *floor
        {
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::SequenceRegression);
        }
        self.floors.insert(begin.thread(), begin.sequence());
        if self.open.len() >= self.limits.open_calls {
            return self.refuse_begin(ordinal, &begin, image);
        }
        // One shared reservation owner (N1c): the open begin takes
        // its ticket before it lands. A full shared census refuses
        // exactly like a full open table.
        let charged = match &resource {
            Some(reservation) => self.ledger.charge_h8open_from_raw(
                ordinal,
                size_of::<OpenEntry>() as u64,
                reservation,
            ),
            None => self
                .ledger
                .charge_h8open(ordinal, size_of::<OpenEntry>() as u64),
        };
        if charged.is_err() {
            return self.refuse_begin(ordinal, &begin, image);
        }
        self.open.insert(
            key,
            OpenEntry {
                begin_ordinal: ordinal,
                image,
                function: begin.descriptor() - 1,
                begin,
                call_key: None,
                end: None,
                abandon: None,
                corroborated_return: None,
                converted_ticket: None,
                converted_for: None,
                end_converted: false,
                raw_resource: resource,
                collected_origin: None,
                s1only_subject: None,
            },
        );
        JournalDisposition::BeginAdmitted
    }

    fn refuse_begin(
        &mut self,
        ordinal: u64,
        begin: &ValidatedJournalBegin,
        image: (u64, u64),
    ) -> JournalDisposition {
        if self.refused.len() >= self.limits.refused_begins {
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::RefusedOverflow);
        }
        self.refused.push(RefusedBegin {
            cut: ordinal,
            image,
            pid_tgid: begin.pid_tgid(),
            function: begin.descriptor() - 1,
            slot: begin.slot(),
            session: begin.session_word(),
            mechanism: begin.entry_mechanism(),
            slot_id: begin.slot_id(),
            user_type: begin.user_type(),
            capture: begin.capture(),
            flags: begin.call_flags(),
            entry_ns: begin.entry_ns(),
            corroborated_return: None,
        });
        JournalDisposition::BeginRefusedCapacity
    }

    fn ingest_end(&mut self, ordinal: u64, end: ValidatedJournalEnd) -> JournalDisposition {
        let key = (end.thread(), end.sequence());
        let Some(entry) = self.open.get(&key) else {
            self.taint_image(end_image(&end));
            return JournalDisposition::Contradiction(JournalContradiction::TerminalBeforeBegin);
        };
        if self.is_tainted(entry.image) {
            return JournalDisposition::Refused;
        }
        if entry.end.is_some() || entry.abandon.is_some() {
            let image = entry.image;
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::DuplicateTerminal);
        }
        if entry.begin.no_end() {
            let image = entry.image;
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::NoEndCompleted);
        }
        if entry.corroborated_return.is_some() {
            let image = entry.image;
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::CallAndEnd);
        }
        if !end_agrees_with_begin(&entry.begin, &end) {
            let image = entry.image;
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::EndBeginMismatch);
        }
        self.open.get_mut(&key).expect("open entry").end = Some(StagedEnd { ordinal, end });
        JournalDisposition::EndStaged
    }

    fn ingest_abandon(
        &mut self,
        ordinal: u64,
        abandon: ValidatedJournalAbandon,
    ) -> JournalDisposition {
        let key = (abandon.thread(), abandon.sequence());
        let Some(entry) = self.open.get(&key) else {
            // Pre-BEGIN removals carry no staged custody to dispose; the
            // accompanying fault independently invalidates. Without a BEGIN
            // the key is unrepresentable, never silently absorbed.
            self.taint_image((abandon.image_cookie(), abandon.image_exec()));
            return JournalDisposition::Contradiction(JournalContradiction::TerminalBeforeBegin);
        };
        if self.is_tainted(entry.image) {
            return JournalDisposition::Refused;
        }
        if entry.end.is_some() || entry.abandon.is_some() {
            let image = entry.image;
            self.taint_image(image);
            return JournalDisposition::Contradiction(JournalContradiction::DuplicateTerminal);
        }
        self.open.get_mut(&key).expect("open entry").abandon =
            Some(StagedAbandon { ordinal, abandon });
        JournalDisposition::AbandonStaged
    }

    /// One ordinary CALL against open and refused keys: at most one exact
    /// identity match corroborates a synchronous return; zero matches count
    /// toward completeness; ambiguity taints, never guesses. A match on an
    /// END-staged key is the producer's never-both violation in the other
    /// arrival order, so it taints; a match on an ABANDON-staged key
    /// corroborates in either arrival order (the seal only honors reason 9).
    fn ingest_ordinary(
        &mut self,
        ordinal: u64,
        event: &p11scope_ebpf_common::Event,
    ) -> JournalDisposition {
        use p11scope_ebpf_common::event_type;
        if self.stopped || self.invalidated {
            return JournalDisposition::Refused;
        }
        if event.event_type != event_type::CALL || is_pending_rv(event.rv) {
            return JournalDisposition::OrdinaryCounted;
        }
        let mut matches = Vec::new();
        for (key, entry) in &self.open {
            if entry.corroborated_return.is_none()
                && ordinary_matches_begin(event, ordinal, &entry.begin, entry.begin_ordinal)
            {
                matches.push((*key, entry.image, entry.end.is_some()));
            }
        }
        let mut refused_matches = Vec::new();
        for (index, refused) in self.refused.iter().enumerate() {
            if refused.corroborated_return.is_none()
                && ordinary_matches_refused(event, ordinal, refused)
            {
                refused_matches.push(index);
            }
        }
        if matches.iter().any(|(_, _, ended)| *ended) {
            let images: Vec<(u64, u64)> = matches
                .iter()
                .map(|(_, image, _)| *image)
                .chain(
                    refused_matches
                        .iter()
                        .map(|index| self.refused[*index].image),
                )
                .collect();
            for image in images {
                self.taint_image(image);
            }
            return JournalDisposition::Contradiction(JournalContradiction::CallAndEnd);
        }
        if matches.len() + refused_matches.len() > 1 {
            let images: Vec<(u64, u64)> = matches
                .iter()
                .map(|(_, image, _)| *image)
                .chain(
                    refused_matches
                        .iter()
                        .map(|index| self.refused[*index].image),
                )
                .collect();
            for image in images {
                self.taint_image(image);
            }
            return JournalDisposition::Contradiction(JournalContradiction::AmbiguousReturn);
        }
        if let Some((key, _, _)) = matches.first() {
            self.open
                .get_mut(key)
                .expect("matched open entry")
                .corroborated_return = Some(ordinal);
            return JournalDisposition::ReturnObserved;
        }
        if let Some(index) = refused_matches.first() {
            self.refused[*index].corroborated_return = Some(ordinal);
            return JournalDisposition::ReturnObserved;
        }
        JournalDisposition::OrdinaryCounted
    }

    /// Whether one image is refused future proof: individually
    /// retained, or untracked past taint saturation (the conservative
    /// bounded fallback — an image whose taint could not be recorded
    /// is never silently admitted).
    fn is_tainted(&self, image: (u64, u64)) -> bool {
        self.tainted_images.contains(&image)
            || (self.taint_overflow && !self.sightings.contains_key(&image))
    }

    /// Taint one image permanently: attestation for it is refused, its keys'
    /// seals are refused, and its staged entries are disposed without proof.
    /// Retained history stays; only future proof for this image ends.
    /// The retained set is capped at the sighting bound; past it, the
    /// overflow latches, the image's sighting is dropped (future
    /// attestation refuses it as unknown), and its existing keys are
    /// tainted directly so their seals still refuse.
    fn taint_image(&mut self, image: (u64, u64)) {
        if self.is_tainted(image) {
            return;
        }
        self.note_image_taint(image);
        self.remove_open_where(|_, entry| entry.image == image);
        self.refused.retain(|refused| refused.image != image);
    }

    /// Record only the irreversible image evidence. A raw batch marks its
    /// images together, then disposes the existing bounded staging once.
    fn note_image_taint(&mut self, image: (u64, u64)) {
        if !self.tainted_images.contains(&image)
            && self.tainted_images.len() >= self.limits.image_sightings
        {
            self.taint_overflow = true;
            self.sightings.remove(&image);
            if let Some(keys) = self.image_keys.get(&image).cloned() {
                for key in keys {
                    if let Some(state) = self.keys.get_mut(&key) {
                        state.tainted = true;
                    }
                }
            }
        } else {
            self.tainted_images.insert(image);
        }
    }

    /// Negative-only transition for original raw records lacking object
    /// admission. Snapshot retained domains before model loss/key refusal;
    /// never infer completion or a finite provider-effects upper bound.
    fn refuse_disposed_raw(
        &mut self,
        model: &mut ObjectSemantics,
        images: impl Iterator<Item = (u64, u64)>,
        unlocalized: bool,
        gap: JournalGap,
    ) -> SealFailure {
        if !unlocalized {
            for image in images {
                if !self.is_tainted(image) {
                    self.note_image_taint(image);
                }
            }
        }
        // Image taint changes no key identity or era. The original affected
        // domains are retained before any model abandonment/refusal below.
        let scope = if unlocalized {
            self.affected_failure_scope()
        } else {
            let mut domains = Vec::with_capacity(self.keys.len());
            domains.extend(
                self.keys
                    .iter()
                    .filter(|(key, _)| self.is_tainted((key.cookie, key.exec)))
                    .map(|(key, state)| {
                        JournalDomainProof {
                            key: *key,
                            era: state.era,
                        }
                        .domain()
                    }),
            );
            SealFailureScope::AffectedDomains(domains)
        };
        let mut effects = ObjectEffects::default();
        let taints = &self.tainted_images;
        let overflow = self.taint_overflow;
        let sightings = &self.sightings;
        for (key, state) in &mut self.keys {
            let image = (key.cookie, key.exec);
            let affected = unlocalized
                || taints.contains(&image)
                || (overflow && !sightings.contains_key(&image));
            if !affected || state.refused {
                continue;
            }
            if state.model_registered {
                let domain = JournalDomainProof {
                    key: *key,
                    era: state.era,
                }
                .domain();
                effects
                    .effects
                    .extend(model.abandon_domain(domain, &mut self.ledger).effects);
            }
            state.refused = true;
        }
        if unlocalized {
            self.invalidated = true;
            self.void_staged();
        } else {
            // One bounded pass, rather than scanning all retained opens
            // again for every interleaved raw record of an affected image.
            let mut doomed = [(0u64, 0u64); MAX_UNSETTLED_STAGED];
            let mut count = 0;
            for (key, entry) in &self.open {
                if self.is_tainted(entry.image) {
                    doomed[count] = *key;
                    count += 1;
                }
            }
            for key in &doomed[..count] {
                let entry = self.open.remove(key).expect("retained tainted open");
                self.ledger.release_h8open(entry.begin_ordinal);
            }
            let taints = &self.tainted_images;
            let overflow = self.taint_overflow;
            let sightings = &self.sightings;
            self.refused.retain(|entry| {
                !taints.contains(&entry.image)
                    && !(overflow && !sightings.contains_key(&entry.image))
            });
            // The original image loss has irreversibly refused these exact
            // keys. Their proof claims can no longer convert; H9 still owns
            // its separate original rows/roles until negative fanout delivers.
            let count = &mut self.claim_counts;
            self.claims.retain(|fingerprint, claimants| {
                let affected = taints.contains(&fingerprint.image)
                    || (overflow && !sightings.contains_key(&fingerprint.image));
                if affected {
                    *count -= claimants.values().map(VecDeque::len).sum::<usize>();
                }
                !affected
            });
        }
        SealFailure {
            scope,
            gap,
            effects,
            h3_voided: None,
        }
    }

    fn has_s1only_subjects(&self) -> bool {
        self.open
            .values()
            .any(|entry| entry.s1only_subject.is_some())
    }

    #[cfg(test)]
    pub(crate) fn restrict_thread_floors_for_test(&mut self, limit: usize) {
        assert!(self.floors.is_empty() && self.physical_return_floors.is_empty());
        assert!(limit <= self.limits.thread_floors);
        self.limits.thread_floors = limit;
    }

    #[cfg(test)]
    pub(crate) fn proof_refused_for_test(&self, proof: JournalDomainProof) -> bool {
        self.keys
            .get(&proof.key)
            .is_some_and(|state| state.era == proof.era && state.refused)
    }

    /// A disposed/no-admission collection cannot convert an earlier terminal
    /// or release its claim. Real incomplete STARTs may await future END input;
    /// COMPLETE/ABANDON/ordinary-return and marked subjects require their
    /// original ingested or explicit loss consumer instead.
    fn disposed_has_only_future_input(&self, frontier: ConsumptionOrdinal) -> bool {
        !self.has_s1only_subjects()
            && self.claim_counts == 0
            && !self.refused.iter().any(|entry| entry.cut <= frontier.0)
            && self.open.values().all(|entry| {
                entry.begin_ordinal <= frontier.0
                    && entry.raw_resource.as_ref().is_some_and(|resource| {
                        self.ledger.matches_unconverted_original(
                            entry.begin_ordinal,
                            resource,
                            None,
                        )
                    })
                    && entry.converted_ticket.is_none()
                    && entry.call_key.is_none()
                    && !entry.end_converted
                    && entry.end.is_none()
                    && entry.abandon.is_none()
                    && entry.corroborated_return.is_none()
            })
    }

    /// Read every marked physical owner before reserving/taking H3 or
    /// changing the model. A marker never excuses an incomplete, converted,
    /// foreign or colliding original; only its exact own claim may remain.
    fn s1only_subjects_are_owned(&self, frontier: ConsumptionOrdinal) -> bool {
        self.open.values().all(|entry| {
            let Some(key) = entry.s1only_subject else {
                return true;
            };
            let (Some(end), Some(origin), Some(resource)) =
                (entry.end, entry.collected_origin, entry.raw_resource)
            else {
                return false;
            };
            let fingerprint = fingerprint_of_begin(&entry.begin);
            entry.image == (key.cookie, key.exec)
                && origin.position() <= frontier.0
                && end.ordinal <= frontier.0
                && end_agrees_with_begin(&entry.begin, &end.end)
                && fingerprint_matches_event(&fingerprint, &end.end.payload_base().event)
                && entry.call_key.is_none()
                && entry.converted_ticket.is_none()
                && entry.converted_for.is_none()
                && !entry.end_converted
                && entry.abandon.is_none()
                && entry.corroborated_return.is_none()
                && self.s1only_original_claim(entry, key).is_some()
                && self
                    .ledger
                    .matches_unconverted_original(entry.begin_ordinal, &resource, None)
        })
    }

    /// One bulk original negative. A retained exact key has a durable refusal
    /// tombstone; an unbound subject still taints its image conservatively.
    /// Freeze the complete retained domain union before state/model changes.
    /// Claimed sibling rows remain H8-owned for bounded fallback; only the
    /// exact S1Only originals (with at most their own claim) are disposed here.
    fn refuse_s1only_subjects(&mut self, model: &mut ObjectSemantics) -> Option<SealFailure> {
        if !self.has_s1only_subjects() {
            return None;
        }
        // Audit preflight paid for at most keys.len() domains. Sorted unique
        // insertion never needs a subject-sized side table or a new key.
        let mut domains = Vec::with_capacity(self.keys.len());
        let mut image_fallback = false;
        let mut after = None;
        loop {
            let next = match after {
                None => self.open.first_key_value(),
                Some(native) => self
                    .open
                    .range((
                        std::ops::Bound::Excluded(native),
                        std::ops::Bound::Unbounded,
                    ))
                    .next(),
            }
            .map(|(native, entry)| (*native, entry.s1only_subject));
            let Some((native, subject)) = next else {
                break;
            };
            after = Some(native);
            if let Some(key) = subject {
                if let Some(state) = self.keys.get(&key) {
                    let domain = JournalDomainProof {
                        key,
                        era: state.era,
                    }
                    .domain();
                    if let Err(at) = domains.binary_search(&domain) {
                        domains.insert(at, domain);
                    }
                } else {
                    image_fallback = true;
                    self.note_image_taint((key.cookie, key.exec));
                }
            }
        }
        // Independent image/overflow evidence keeps its full existing union,
        // even when every marked subject itself had a retained exact key.
        for (key, state) in &self.keys {
            if self.is_tainted((key.cookie, key.exec)) {
                image_fallback = true;
                let domain = JournalDomainProof {
                    key: *key,
                    era: state.era,
                }
                .domain();
                if let Err(at) = domains.binary_search(&domain) {
                    domains.insert(at, domain);
                }
            }
        }
        assert!(
            domains.len() <= self.keys.len(),
            "original refusal union was prepaid"
        );
        let mut effects = ObjectEffects::default();
        for (key, state) in &mut self.keys {
            let domain = JournalDomainProof {
                key: *key,
                era: state.era,
            }
            .domain();
            if domains.binary_search(&domain).is_err() {
                continue;
            }
            if !state.refused && state.model_registered {
                effects
                    .effects
                    .extend(model.abandon_domain(domain, &mut self.ledger).effects);
            }
            state.refused = true;
        }
        let mut after = None;
        loop {
            let next = match after {
                None => self.open.first_key_value(),
                Some(native) => self
                    .open
                    .range((
                        std::ops::Bound::Excluded(native),
                        std::ops::Bound::Unbounded,
                    ))
                    .next(),
            }
            .map(|(native, entry)| (*native, entry.s1only_subject.is_some()));
            let Some((native, selected)) = next else {
                break;
            };
            after = Some(native);
            if selected {
                let entry = self
                    .open
                    .remove(&native)
                    .expect("preflight original subject");
                let key = entry.s1only_subject.expect("selected original subject");
                if let Some(original) = self
                    .s1only_original_claim(&entry, key)
                    .expect("preflight exact own claim")
                {
                    let claim = self
                        .consume_claim(&fingerprint_of_begin(&entry.begin), key)
                        .expect("retained original own claim");
                    assert_eq!(claim.admission, original.admission);
                    assert_eq!(claim.return_ns, original.return_ns);
                }
                if let Some(state) = self.keys.get_mut(&key) {
                    state.s1only_original_refused = true;
                }
                let ordinal = entry.begin_ordinal;
                self.ledger.release_h8open(ordinal);
            }
        }
        Some(SealFailure {
            scope: SealFailureScope::AffectedDomains(domains),
            gap: if image_fallback {
                JournalGap::ImageTainted
            } else {
                JournalGap::DomainTainted
            },
            effects,
            h3_voided: None,
        })
    }
}

/// Image evidence of an END payload (reconstructed identically for both
/// forms), for taint localization before any key matches.
fn end_image(end: &ValidatedJournalEnd) -> (u64, u64) {
    let base = end.payload_base();
    (base.event.image.task_cookie, base.event.image.exec_id)
}

/// One staged BEGIN's attribution shape: the same overlap the
/// admission side claims, read from wire scalars.
fn fingerprint_of_begin(begin: &ValidatedJournalBegin) -> CallFingerprint {
    CallFingerprint {
        image: (begin.image_cookie(), begin.image_exec()),
        function: begin.descriptor() - 1,
        pid_tgid: begin.pid_tgid(),
        entry_ns: begin.entry_ns(),
        slot: begin.slot(),
        session: begin.session_word(),
        mechanism: begin.entry_mechanism(),
        capture: begin.capture(),
        slot_id: begin.slot_id(),
        flags: begin.call_flags(),
        user_type: begin.user_type(),
    }
}

/// One refused BEGIN's attribution shape.
fn fingerprint_of_refused(refused: &RefusedBegin) -> CallFingerprint {
    CallFingerprint {
        image: refused.image,
        function: refused.function,
        pid_tgid: refused.pid_tgid,
        entry_ns: refused.entry_ns,
        slot: refused.slot,
        session: refused.session,
        mechanism: refused.mechanism,
        capture: refused.capture,
        slot_id: refused.slot_id,
        flags: refused.flags,
        user_type: refused.user_type,
    }
}

/// Whether a return value is still pending (provider-deferred): never a
/// completed synchronous return, never a terminal witness.
fn is_pending_rv(rv: u64) -> bool {
    pkcs11_types::CkRv(rv) == pkcs11_types::CkRv::PENDING
}

/// Whether one ordinary CALL record corroborates one open BEGIN: the
/// exact retained invocation — same image, same process, exact
/// entry-time agreement plus the seven-word call identity — observed
/// strictly after the BEGIN with a completed (non-pending) return
/// value. Entry agreement is exact (`ts - duration`, the return path's
/// own entry reconstruction): a merely later timestamp from another
/// invocation never qualifies.
fn ordinary_matches_begin(
    event: &p11scope_ebpf_common::Event,
    ordinal: u64,
    begin: &ValidatedJournalBegin,
    begin_ordinal: u64,
) -> bool {
    ordinal > begin_ordinal
        && event.ts_ns.checked_sub(event.duration_ns) == Some(begin.entry_ns())
        && event.pid_tgid == begin.pid_tgid()
        && event.image.task_cookie == begin.image_cookie()
        && event.image.exec_id == begin.image_exec()
        && event.slot == begin.slot()
        && event.session == begin.session_word()
        && event.mechanism == begin.entry_mechanism()
        && event.slot_id == begin.slot_id()
        && event.user_type == begin.user_type()
        && event.capture == begin.capture()
        && event.flags == begin.call_flags()
}

/// Whether one ordinary CALL record corroborates one refused BEGIN:
/// the same exact-invocation binding as an open BEGIN.
fn ordinary_matches_refused(
    event: &p11scope_ebpf_common::Event,
    ordinal: u64,
    refused: &RefusedBegin,
) -> bool {
    ordinal > refused.cut
        && event.ts_ns.checked_sub(event.duration_ns) == Some(refused.entry_ns)
        && event.pid_tgid == refused.pid_tgid
        && event.image.task_cookie == refused.image.0
        && event.image.exec_id == refused.image.1
        && event.slot == refused.slot
        && event.session == refused.session
        && event.mechanism == refused.mechanism
        && event.slot_id == refused.slot_id
        && event.user_type == refused.user_type
        && event.capture == refused.capture
        && event.flags == refused.flags
}

// ---------------------------------------------------------------------------
// Production conversion: validated wire to model facts (H9's sealed input)
// ---------------------------------------------------------------------------

fn returned_word_fits_layout(word: u64, layout: u8) -> bool {
    use p11scope_ebpf_common::object_wire::{OBJECT_LAYOUT_ILP32, OBJECT_LAYOUT_LP64};
    match layout {
        OBJECT_LAYOUT_LP64 => true,
        OBJECT_LAYOUT_ILP32 => word <= u64::from(u32::MAX),
        _ => false,
    }
}

/// Match the session/mechanism rewrites made by capture_return_facts.
/// Unreadable entry evidence is never an absent session; capture states are
/// enums, and a captured VALUE (including zero or MECH_NONE's numeric value)
/// stays exact. Other capture bits, ordinary corroboration and ingress are
/// unchanged; asynchronous capture-state rewriting is a separate packet.
fn returned_fields_agree(
    begin: &ValidatedJournalBegin,
    event: &p11scope_ebpf_common::Event,
) -> bool {
    use p11scope_ebpf_common::object_capture::handle_status;
    use p11scope_ebpf_common::{ARG_NONE, MECH_NONE, SESSION_NONE, lifecycle};

    let Some(semantics) = crate::kinds::DESCRIPTORS.get(begin.descriptor() as usize) else {
        return false;
    };
    let absent_session = semantics.session_arg == ARG_NONE
        && begin.session_status() == handle_status::ABSENT
        && begin.session_word() == 0;
    let session_agrees = event.session == begin.session_word()
        || (absent_session
            && (event.session == SESSION_NONE
                || (semantics.lifecycle == lifecycle::OPEN_SESSION
                    && begin.capture() & capture::OUTPUT_MASK == capture::OUTPUT_NON_NULL
                    && matches!(event.rv, 0 | 0x204)
                    && returned_word_fits_layout(event.session, begin.layout()))));
    if !session_agrees {
        return false;
    }

    if event.mechanism == begin.entry_mechanism() && event.capture == begin.capture() {
        return true;
    }
    let before = begin.capture();
    let after = event.capture;
    let entry_state = before & capture::MECHANISM_MASK;
    let return_state = after & capture::MECHANISM_MASK;
    let entry_failed = before & capture::ARG_READ_FAILURE != 0;
    let return_failed = after & capture::ARG_READ_FAILURE != 0;
    if (before ^ after) & !(capture::MECHANISM_MASK | capture::ARG_READ_FAILURE) != 0
        || (entry_failed && !return_failed)
        || semantics.mechanism_arg == ARG_NONE
        || !p11scope_ebpf_common::return_allows_mechanism(event.rv)
    {
        return false;
    }
    if entry_state == capture::MECHANISM_VALUE {
        if event.mechanism != begin.entry_mechanism() {
            return false;
        }
    } else if !matches!(
        entry_state,
        capture::MECHANISM_NONE | capture::MECHANISM_UNREADABLE
    ) || begin.entry_mechanism() != MECH_NONE
    {
        return false;
    }
    match return_state {
        capture::MECHANISM_VALUE => {
            entry_failed == return_failed
                && returned_word_fits_layout(event.mechanism, begin.layout())
        }
        capture::MECHANISM_UNREADABLE => {
            return_failed && event.mechanism == begin.entry_mechanism()
        }
        _ => false,
    }
}

/// Whether one END agrees with the BEGIN's immutable evidence and the
/// producer's finite scalar return rewrites. Entry time is not repeated
/// (the END carries return time), so the existing lower bound remains;
/// ordinary corroboration retains its exact entry-time reconstruction.
fn end_agrees_with_begin(begin: &ValidatedJournalBegin, end: &ValidatedJournalEnd) -> bool {
    let base = end.payload_base();
    let tail = end.payload_tail();
    let event = &base.event;
    if event.image.task_cookie != begin.image_cookie()
        || event.image.exec_id != begin.image_exec()
        || event.pid_tgid != begin.pid_tgid()
        || event.slot != begin.slot()
        || !returned_fields_agree(begin, event)
        || event.slot_id != begin.slot_id()
        || event.flags != begin.call_flags()
        || event.user_type != begin.user_type()
        || event.ts_ns < begin.entry_ns()
    {
        return false;
    }
    if base.continuity.entry_ip != begin.entry_ip() {
        return false;
    }
    if !stamp_agrees(&base.continuity.entry_stamp, &begin.entry_stamp()) {
        return false;
    }
    if end.tail_absent() {
        if tail.iter().any(|byte| *byte != 0) {
            return false;
        }
        // Absent tails ride only the no-row path: the BEGIN descriptor
        // names a known non-object function.
        let function = begin.descriptor() - 1;
        if pkcs11_module::function_name(function as usize).is_none()
            || p11scope_ebpf_common::object_policy::object_descriptor(function).is_some()
        {
            return false;
        }
        return true;
    }
    if tail_u32(&tail, 4) != begin.descriptor() || tail[12] != begin.layout() {
        return false;
    }
    for index in 0..2 {
        if tail_u64(&tail, 16 + 8 * index) != begin.input_word(index)
            || tail[112 + index] != begin.input_status(index)
        {
            return false;
        }
    }
    for pair in 0..2 {
        let kept = begin.requested_pair(pair);
        if tail[128 + 36 * pair..128 + 36 * (pair + 1)] != kept {
            return false;
        }
    }
    true
}

fn stamp_agrees(stamp: &p11scope_ebpf_common::InstanceStamp, bytes: &[u8; 16]) -> bool {
    u32::from_le_bytes(bytes[0..4].try_into().expect("stamp epoch")) == stamp.epoch
        && u32::from_le_bytes(bytes[4..8].try_into().expect("stamp global")) == stamp.global
        && u32::from_le_bytes(bytes[8..12].try_into().expect("stamp fault")) == stamp.fault
        && u16::from_le_bytes(bytes[12..14].try_into().expect("stamp slot"))
            == stamp.file_slot_plus1
        && u16::from_le_bytes(bytes[14..16].try_into().expect("stamp flags")) == stamp.flags
}

fn tail_u32(tail: &[u8; 240], offset: usize) -> u32 {
    u32::from_le_bytes([
        tail[offset],
        tail[offset + 1],
        tail[offset + 2],
        tail[offset + 3],
    ])
}

/// One validated handle word plus its H7 status to a model handle input:
/// absent stays absent, a value carries its nonzero word, and every other
/// finite status (unreadable, invalid, alias, duplicate, unavailable,
/// suppressed, changed) is explicitly unreadable, never a zero handle.
fn handle_input<T>(status: u8, word: u64, make: impl Fn(u64) -> Option<T>) -> HandleInput<T> {
    match status {
        0 => HandleInput::Absent,
        1 => make(word).map_or(HandleInput::Unreadable, HandleInput::Value),
        _ => HandleInput::Unreadable,
    }
}

/// One validated result slot to a model result: absent and never-authorized
/// (protocol-unavailable, suppressed) stay uncaptured; a value carries its
/// nonzero handle; every other finite status is explicitly unreadable.
fn result_slot(status: u8, word: u64) -> ResultSlot {
    match status {
        0 | 7 | 8 => ResultSlot::NotCaptured,
        1 => super::ObjectHandle::new(word).map_or(ResultSlot::Unreadable, ResultSlot::Handle),
        _ => ResultSlot::Unreadable,
    }
}

/// Captured mechanism evidence from a finite capture word plus its
/// mechanism word. The capture bits select the variant; only VALUE reads
/// the word.
fn mechanism_evidence(capture_word: u32, mechanism: u64) -> MechanismEvidence {
    match capture_word & capture::MECHANISM_MASK {
        x if x == capture::MECHANISM_NONE => MechanismEvidence::NotCaptured,
        x if x == capture::MECHANISM_NULL => MechanismEvidence::Null,
        x if x == capture::MECHANISM_UNREADABLE => MechanismEvidence::Unreadable,
        _ => MechanismEvidence::Value(mechanism),
    }
}

/// One validated 36-byte attribute list to model requested facts: absent
/// (all zero) and uninspected lists carry no facts; an inspected list maps
/// each cell within its inspected count.
fn attribute_list(list: &[u8; 36]) -> Option<AttributeList> {
    if list.iter().all(|byte| *byte == 0) {
        return None;
    }
    if list[33] & p11scope_ebpf_common::object_wire::OBJECT_ATTR_LIST_UNINSPECTED != 0 {
        return None;
    }
    let inspected = usize::from(list[32]);
    let mut observations = Vec::new();
    for cell in list.as_chunks::<4>().0.iter().take(inspected.min(8)) {
        observations.push(attribute_cell(
            cell[0],
            cell[1],
            u16::from_le_bytes([cell[2], cell[3]]),
        ));
    }
    Some(AttributeList::new(&observations))
}

/// One validated attribute cell to a model observation. Values re-check
/// full-width membership (scalars) or exact curve identity (EC params);
/// anything unclassifiable is unsupported, never invented. Unknown
/// selectors retain nothing.
fn attribute_cell(kind: u8, status: u8, value: u16) -> AttrObservation {
    use p11scope_ebpf_common::object_policy::classify_attribute_scalar;
    let kind = match kind {
        1 => Some(SafeAttributeKind::Class),
        2 => Some(SafeAttributeKind::KeyType),
        3 => Some(SafeAttributeKind::Token),
        4 => Some(SafeAttributeKind::ValueLen),
        5 => Some(SafeAttributeKind::ModulusBits),
        6 => Some(SafeAttributeKind::EcParams),
        _ => None,
    };
    let (status, value) = match status {
        1 => {
            let value = match kind {
                Some(SafeAttributeKind::EcParams) => match value {
                    1 => Some(FieldValue::Curve(
                        p11scope_ebpf_common::object_policy::SafeCurve::Secp256r1,
                    )),
                    2 => Some(FieldValue::Curve(
                        p11scope_ebpf_common::object_policy::SafeCurve::Secp384r1,
                    )),
                    3 => Some(FieldValue::Curve(
                        p11scope_ebpf_common::object_policy::SafeCurve::Secp521r1,
                    )),
                    _ => None,
                },
                Some(kind) => {
                    classify_attribute_scalar(kind, u64::from(value)).map(FieldValue::Scalar)
                }
                None => None,
            };
            match value {
                Some(value) => (QueryStatus::Established, Some(value)),
                None => (QueryStatus::Unsupported, None),
            }
        }
        2 => (QueryStatus::Unsupported, None),
        3 | 5 => (QueryStatus::Unavailable, None),
        4 => (QueryStatus::SizeOnly, None),
        6..=9 => (QueryStatus::Malformed, None),
        10 => (QueryStatus::Unavailable, None),
        _ => (QueryStatus::NotQueried, None),
    };
    AttrObservation::classified(kind, status, value)
}

/// One staged BEGIN to its sealed origin fact. Scope stays unknown: the
/// wire carries no slot/token-epoch proof, and unknown widens
/// conservatively rather than joining across a token reset.
fn origin_of(
    domain: ObjectDomain,
    begin_ordinal: u64,
    ticket: JournalTicket,
    begin: &ValidatedJournalBegin,
) -> OriginFact {
    OriginFact {
        domain,
        cut: RefCut::sealed(ConsumptionOrdinal(begin_ordinal)),
        key: CallKey::sealed(ticket),
        entry_ns: begin.entry_ns(),
        function: begin.descriptor() - 1,
        session: handle_input(
            begin.session_status(),
            begin.session_word(),
            SessionHandle::new,
        ),
        inputs: [
            handle_input(
                begin.input_status(0),
                begin.input_word(0),
                super::ObjectHandle::new,
            ),
            handle_input(
                begin.input_status(1),
                begin.input_word(1),
                super::ObjectHandle::new,
            ),
        ],
        requested: [
            attribute_list(&begin.requested_pair(0)),
            attribute_list(&begin.requested_pair(1)),
        ],
        entry_mechanism: mechanism_evidence(begin.capture(), begin.entry_mechanism()),
        scope: super::SlotScope::Unknown,
    }
}

/// One staged BEGIN to its H9 correlation fingerprint: the sealed
/// session and mechanism class, mirroring [`origin_of`] exactly.
fn sealed_fingerprint(
    begin: &ValidatedJournalBegin,
) -> (
    super::HandleInput<super::SessionHandle>,
    super::state::MechClass,
) {
    (
        handle_input(
            begin.session_status(),
            begin.session_word(),
            super::SessionHandle::new,
        ),
        super::state::MechClass::of(mechanism_evidence(begin.capture(), begin.entry_mechanism())),
    )
}

/// One staged END to its sealed completion fact. Session outputs are never
/// observed (no session-result protocol exists): session-creating lifecycle
/// calls report their output unreadable, honestly unknown rather than
/// absent; everything else reports no output.
fn completed_of(end_ordinal: u64, function: u32, end: &ValidatedJournalEnd) -> CompletedFact {
    let base = end.payload_base();
    let tail = end.payload_tail();
    let event = &base.event;
    let action = tail[13];
    let results = if end.tail_absent() {
        [ResultSlot::NotCaptured, ResultSlot::NotCaptured]
    } else {
        [
            result_slot(tail[114], tail_u64(&tail, 32)),
            result_slot(tail[115], tail_u64(&tail, 40)),
        ]
    };
    CompletedFact {
        cut: RefCut::sealed(ConsumptionOrdinal(end_ordinal)),
        end_ns: event.ts_ns,
        rv: event.rv,
        return_mechanism: mechanism_evidence(event.capture, event.mechanism),
        results,
        session_out: session_output_of(function),
        found: find_of(action, &tail, end.tail_absent()),
        attributes: attributes_of(action, &tail, end.tail_absent()),
    }
}

fn tail_u64(tail: &[u8; 240], offset: usize) -> u64 {
    u64::from_le_bytes([
        tail[offset],
        tail[offset + 1],
        tail[offset + 2],
        tail[offset + 3],
        tail[offset + 4],
        tail[offset + 5],
        tail[offset + 6],
        tail[offset + 7],
    ])
}

fn session_output_of(function: u32) -> HandleInput<SessionHandle> {
    if Some(function) == crate::kinds::function_id("C_OpenSession") {
        HandleInput::Unreadable
    } else {
        HandleInput::Absent
    }
}

/// The Find section to a model find result: only a validated Find section
/// with all-value cells establishes handles; anything else is explicitly
/// unknown, never a partial guess.
fn find_of(action: u8, tail: &[u8; 240], absent: bool) -> FindResult {
    use p11scope_ebpf_common::object_wire::OBJECT_ACTION_FIND;
    if absent || action != OBJECT_ACTION_FIND || tail[126] == 0 {
        if absent || action != OBJECT_ACTION_FIND {
            return FindResult::NotCaptured;
        }
        return FindResult::Unreadable;
    }
    let len = usize::from(tail[124]);
    let mut handles = Vec::new();
    for index in 0..len {
        if tail[116 + index] != 1 {
            return FindResult::Unreadable;
        }
        let Some(handle) = super::ObjectHandle::new(tail_u64(tail, 48 + 8 * index)) else {
            return FindResult::Unreadable;
        };
        handles.push(handle);
    }
    let mut found = FindResult::handles(&handles);
    if tail[125] & 1 != 0 {
        found = match found {
            FindResult::Handles { handles, .. } => FindResult::Handles {
                handles,
                truncated: true,
            },
            other => other,
        };
    }
    found
}

/// The Get result list to model established facts; only Get populates it.
fn attributes_of(action: u8, tail: &[u8; 240], absent: bool) -> Option<AttributeList> {
    use p11scope_ebpf_common::object_wire::OBJECT_ACTION_GET;
    if absent || action != OBJECT_ACTION_GET {
        return None;
    }
    let mut list = [0u8; 36];
    list.copy_from_slice(&tail[200..236]);
    attribute_list(&list)
}

// ---------------------------------------------------------------------------
// Audit and bootstrap receipts, the sealed prefix and the seal
// ---------------------------------------------------------------------------

/// H3's post-finalizer disposition, minted only by the actual
/// finalizer from its complete disposition state. All positions share
/// H0's one immutable position authority (its checked allocation
/// counter); the seal enforces coverage in that space against the
/// collection's allocation watermark, never against journal ordinals.
/// Private fields: only the finalizer derivation or the test script
/// builds one.
#[derive(Debug, Clone)]
pub(crate) enum H3DispositionEvidence {
    /// Every H0 position at or below the staged maximum is disposed,
    /// except positions at or above the pending floor (route-waiting,
    /// unpublished or lane-stashed). The maximum is monotone over
    /// previous evidence; the floor is always the current one.
    Clean {
        staged_max: u64,
        pending_floor: Option<u64>,
    },
    /// A loss barrier stands at the cut: staged negatives, shed
    /// positions or dropped batches. The seal voids once and forgives
    /// the barrier on re-presentation.
    StagedLoss { barrier: u64 },
    /// The H0 allocator is exhausted: no future position can certify.
    /// Permanent; the seal stops the adapter.
    Exhausted,
}

impl H3DispositionEvidence {
    /// Production derivation from the finalizer's complete disposition
    /// state: staged negatives, staged outcome positions (calls and
    /// invalidations alike), the route-waiting floor, the shed floor,
    /// the unpublished floor, and allocator exhaustion. Called from
    /// the actual `finalize_batch`; the coordinator stores the result
    /// as the seal's H3 evidence. `acked_below` is the seal's H3-loss
    /// acknowledgement: H0 positions below it were voided by a seal.
    #[allow(clippy::too_many_arguments)] // The finalizer's exact disposition facts plus the seal's ack.
    pub(crate) fn from_finalizer_batch(
        negatives: &[crate::inventory_semantics::LaneNegative],
        staged: &[Option<u64>],
        awaiting_floor: Option<u64>,
        shed_floor: Option<u64>,
        unpublished_floor: Option<u64>,
        exhausted: bool,
        previous: &Self,
        acked_below: u64,
    ) -> Self {
        use crate::inventory_semantics::LaneNegative;
        // Exhaustion sticks: an unpositioned outcome (or a dead
        // previous) means the allocator can never certify again.
        if matches!(previous, Self::Exhausted) || exhausted || staged.iter().any(Option::is_none) {
            return Self::Exhausted;
        }
        let mut barrier: Option<u64> = None;
        let mut narrow = |cut: u64| {
            barrier = Some(barrier.map_or(cut, |at: u64| at.min(cut)));
        };
        for negative in negatives {
            match negative {
                LaneNegative::CutBarrier { ordinal } => narrow(*ordinal),
                LaneNegative::CollectionRefused { .. } => narrow(0),
            }
        }
        if let Some(shed) = shed_floor {
            narrow(shed);
        }
        if let Some(barrier) = barrier {
            return Self::StagedLoss { barrier };
        }
        // An unacknowledged loss barrier persists: only the seal's
        // explicit void (positions below `acked_below`) releases the
        // next mint into Clean. A clean batch never overwrites a loss
        // the seal has not consumed.
        if let Self::StagedLoss { barrier } = previous
            && *barrier >= acked_below
        {
            return Self::StagedLoss { barrier: *barrier };
        }
        // The certified maximum is monotone over previous evidence; a
        // voided loss barrier restarts it through the seal's acknowledged
        // interval (those positions were disposed as loss, not success).
        // A quiet next batch need not issue a new position to cover that
        // already disposed interval. The pending floor
        // is the current minimum over route-waiting and unpublished
        // positions.
        let base = match previous {
            Self::Clean { staged_max, .. } => *staged_max,
            Self::StagedLoss { barrier } => (*barrier).max(acked_below.saturating_sub(1)),
            Self::Exhausted => return Self::Exhausted,
        };
        let mut staged_max = base;
        for position in staged.iter().flatten() {
            staged_max = staged_max.max(*position);
        }
        let pending_floor = awaiting_floor.into_iter().chain(unpublished_floor).min();
        Self::Clean {
            staged_max,
            pending_floor,
        }
    }

    /// Genesis evidence: nothing disposed, nothing lost, nothing pending.
    pub(crate) fn genesis() -> Self {
        Self::Clean {
            staged_max: 0,
            pending_floor: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted_clean(staged_max: u64) -> Self {
        Self::Clean {
            staged_max,
            pending_floor: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted_clean_pending(staged_max: u64, pending_floor: Option<u64>) -> Self {
        Self::Clean {
            staged_max,
            pending_floor,
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted_loss(barrier: u64) -> Self {
        Self::StagedLoss { barrier }
    }

    #[cfg(test)]
    pub(crate) fn scripted_exhausted() -> Self {
        Self::Exhausted
    }
}

/// The seal's H3 evidence source: the actual H3 finalizer. The audit
/// constructor takes (consumes) the latest minted disposition through
/// this trait, so the seal never audits caller-supplied H3 evidence.
/// Loss barriers persist across takes until the seal voids them; the
/// joint tick forwards the seal's void report to the finalizer's
/// acknowledgement.
pub(crate) trait H3EvidenceSource {
    fn take_h3_disposition(&mut self) -> H3DispositionEvidence;
}

/// The joint tick's H3 finalizer: the actual finalizer takes (consumes)
/// dispositions and accepts the seal's void acknowledgements through
/// one port, so the acknowledgement flows to the finalizer through
/// production code. Production wires a borrow of the retained Session's
/// finalizer state and producer pair.
pub(crate) trait H3FinalizerPort: H3EvidenceSource {
    fn acknowledge_h3_void(&mut self, acknowledgement: H3VoidAcknowledgement);
}

/// One actual joint seal's void acknowledgement. Its private constructor is
/// used only by JointSealTick after a seal reports a void. The retained native
/// and EVENTS identity must match before its numeric H0 watermark is read.
/// Move-only: it cannot be cloned or synthesized from a supplied scalar.
pub(crate) struct H3VoidAcknowledgement {
    producers: crate::attach::SessionDrainProducers,
    voided_below: u64,
}

impl H3VoidAcknowledgement {
    pub(crate) fn for_producers(
        &self,
        producers: &crate::attach::SessionDrainProducers,
    ) -> Option<u64> {
        self.producers
            .same_producers(producers)
            .then_some(self.voided_below)
    }

    #[cfg(test)]
    pub(crate) fn for_legacy_test(&self) -> u64 {
        self.voided_below
    }
}

impl std::fmt::Debug for H3VoidAcknowledgement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("H3VoidAcknowledgement(<retained>)")
    }
}

/// Production birth-evidence source: the seal pulls one fresh
/// observation per seal through this, never receiving a reusable
/// evidence value. Each take re-runs the birth observation against
/// live native state; a failed take refuses the seal and the next
/// tick takes again. Production wires the Session attach side (live
/// map reads, UNRUN); tests wire single-shot scripted evidence or
/// the real observation.
pub(crate) trait BirthEvidenceSource {
    fn take_birth_evidence(
        &mut self,
    ) -> Result<SessionBirthEvidence, crate::attach::BirthObservationRefusal>;
}

/// Tests-only single-shot birth source: yields its evidence once, then
/// panics — a second take would reuse evidence, the exact failure the
/// take pattern forbids. Tests build one source per seal.
#[cfg(test)]
pub(crate) struct ScriptedBirthSource(Option<SessionBirthEvidence>);

#[cfg(test)]
impl ScriptedBirthSource {
    pub(crate) fn once(evidence: SessionBirthEvidence) -> Self {
        Self(Some(evidence))
    }
}

#[cfg(test)]
impl BirthEvidenceSource for ScriptedBirthSource {
    fn take_birth_evidence(
        &mut self,
    ) -> Result<SessionBirthEvidence, crate::attach::BirthObservationRefusal> {
        Ok(self
            .0
            .take()
            .expect("birth evidence is single-shot: one source per seal"))
    }
}

/// Test-only H3 evidence source: yields one scripted disposition, then
/// genesis (the seal then waits for coverage), mirroring the
/// finalizer's take semantics.
#[cfg(test)]
pub(crate) struct ScriptedH3Source(Option<H3DispositionEvidence>);

#[cfg(test)]
impl ScriptedH3Source {
    pub(crate) fn once(evidence: H3DispositionEvidence) -> Self {
        Self(Some(evidence))
    }
}

#[cfg(test)]
impl H3EvidenceSource for ScriptedH3Source {
    fn take_h3_disposition(&mut self) -> H3DispositionEvidence {
        self.0.take().unwrap_or_else(H3DispositionEvidence::genesis)
    }
}

/// One seal's post-consumption audit: the fault pair bracketing the tick,
/// the drain's malformed delta, H3's disposition and the closure
/// generation the bootstrap must match. Validity is established by
/// [`JournalAuditReceipt::check`]; possession alone proves nothing, so the
/// fields stay private and every constructor funnels through the check.
#[derive(Debug, Clone)]
pub(crate) struct JournalAuditReceipt {
    fault_before: u64,
    fault_after: u64,
    fault_error: Option<FaultReadError>,
    malformed_delta: u64,
    discarded_delta: u64,
    counter_error: bool,
    resource_refused: bool,
    h3: H3DispositionEvidence,
    h0_below: u64,
    closure_generation: u64,
    drain_domain: Option<u64>,
}

/// One collection's audit evidence: per-form counts, the drain's
/// malformed delta, the checked-fault pair bracketing the tick, the
/// Session drain the quantum was collected through (read from the
/// drain itself, never a caller label), and H0's allocation watermark
/// below which every position was minted for this quantum.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JournalCollection {
    pub(crate) ingested: u64,
    pub(crate) ordinary: u64,
    pub(crate) malformed_delta: u64,
    pub(crate) discarded_delta: u64,
    pub(crate) counter_error: bool,
    pub(crate) resource_refused: bool,
    pub(crate) fault_before: u64,
    pub(crate) fault_after: u64,
    pub(crate) fault_error: Option<FaultReadError>,
    pub(crate) drain_domain: u64,
    pub(crate) h0_allocated_below: u64,
}

impl JournalAuditReceipt {
    #[cfg(test)]
    pub(crate) fn h3_for_test(&self) -> &H3DispositionEvidence {
        &self.h3
    }

    #[cfg(test)]
    pub(crate) fn resource_refused_for_test(&self) -> bool {
        self.resource_refused
    }

    /// Production audit from one collection plus the actual H3
    /// finalizer's latest disposition (taken through
    /// [`H3EvidenceSource`], never caller-supplied) and the live
    /// closure generation. The seal's check rules decide; this only
    /// binds the evidence.
    pub(crate) fn collect(
        collection: &JournalCollection,
        source: &mut impl H3EvidenceSource,
        closure_generation: u64,
    ) -> Self {
        Self {
            fault_before: collection.fault_before,
            fault_after: collection.fault_after,
            fault_error: collection.fault_error,
            malformed_delta: collection.malformed_delta,
            discarded_delta: collection.discarded_delta,
            counter_error: collection.counter_error,
            resource_refused: collection.resource_refused,
            h3: source.take_h3_disposition(),
            h0_below: collection.h0_allocated_below,
            closure_generation,
            drain_domain: Some(collection.drain_domain),
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        fault_before: u64,
        fault_after: u64,
        fault_error: Option<FaultReadError>,
        malformed_delta: u64,
        h3: H3DispositionEvidence,
        closure_generation: u64,
    ) -> Self {
        Self::scripted_h0(
            fault_before,
            fault_after,
            fault_error,
            malformed_delta,
            h3,
            closure_generation,
            0,
        )
    }

    /// Scripted audit with an explicit H0 allocation watermark: the H3
    /// rules compare evidence to `h0_below`, never to the frontier. The
    /// plain scripted form watermarks zero, which passes any staged
    /// maximum; use this form to pin H3 strictness.
    #[cfg(test)]
    pub(crate) fn scripted_h0(
        fault_before: u64,
        fault_after: u64,
        fault_error: Option<FaultReadError>,
        malformed_delta: u64,
        h3: H3DispositionEvidence,
        closure_generation: u64,
        h0_below: u64,
    ) -> Self {
        Self {
            fault_before,
            fault_after,
            fault_error,
            malformed_delta,
            discarded_delta: 0,
            counter_error: false,
            resource_refused: false,
            h3,
            h0_below,
            closure_generation,
            drain_domain: None,
        }
    }

    /// The audit rules: an unreadable or changed fault, a break in
    /// the cumulative fault chain, any malformed record, any
    /// reader-consumed discard, a seal-time fault move, undisposed or
    /// lost H3 history below the collection's H0 allocation watermark
    /// (compared in H0's own position space, never against the journal
    /// frontier), or a stale closure each refuse the seal. The caller
    /// voids staged proof on fault/malformed/discard/loss and stops on
    /// exhaustion; pending, forgiven or above-watermark loss, and stale
    /// closures refuse without voiding.
    fn check(
        &self,
        last_fault: Option<u64>,
        h3_voided_below: u64,
        current_closure: u64,
        seal_epoch: &Result<u64, FaultReadError>,
    ) -> Result<(), JournalGap> {
        match self.fault_error {
            Some(FaultReadError::Unreadable) => return Err(JournalGap::FaultUnreadable),
            Some(FaultReadError::Saturated) => return Err(JournalGap::FaultSaturated),
            None => {}
        }
        if self.fault_before != self.fault_after {
            return Err(JournalGap::FaultChanged);
        }
        // Cumulative chain: this collection must open where the last
        // seal closed. A move between collections voids like a move
        // within one.
        if last_fault.is_some_and(|last| self.fault_before != last) {
            return Err(JournalGap::FaultChanged);
        }
        if self.counter_error {
            return Err(JournalGap::CounterUnprovable);
        }
        if self.malformed_delta != 0 {
            return Err(JournalGap::Malformed);
        }
        // Reader-consumed discards are lost history: the seal voids
        // rather than certifying across them.
        if self.discarded_delta != 0 {
            return Err(JournalGap::Discarded);
        }
        // Seal-time native re-read: the cell must still show the
        // audited epoch when the seal runs.
        match seal_epoch {
            Ok(epoch) if *epoch == self.fault_after => {}
            Ok(_) => return Err(JournalGap::FaultChanged),
            Err(FaultReadError::Unreadable) => return Err(JournalGap::FaultUnreadable),
            Err(FaultReadError::Saturated) => return Err(JournalGap::FaultSaturated),
        }
        match &self.h3 {
            H3DispositionEvidence::Exhausted => return Err(JournalGap::H3Exhausted),
            H3DispositionEvidence::StagedLoss { barrier } => {
                // A loss below the watermark voids unless already
                // voided; at or above the watermark it waits for clean
                // evidence without voiding.
                if *barrier < h3_voided_below || *barrier >= self.h0_below {
                    return Err(JournalGap::H3Pending);
                }
                return Err(JournalGap::H3Loss);
            }
            H3DispositionEvidence::Clean {
                staged_max,
                pending_floor,
            } => {
                // Every H0 position below the watermark is disposed:
                // staging reaches it and nothing pends below it.
                if *staged_max < self.h0_below.saturating_sub(1)
                    || pending_floor.is_some_and(|floor| floor < self.h0_below)
                {
                    return Err(JournalGap::H3Pending);
                }
            }
        }
        // Original audit resource refusal voids H8 custody in reject_audit;
        // canonical delivery classifies that same original/audit as loss.
        // Seal-time resource refusal with retained custody may still fall
        // back. Neither may downgrade native/H3 loss or complete pending H3.
        if self.resource_refused {
            return Err(JournalGap::ResourceUnavailable);
        }
        if self.closure_generation != current_closure {
            return Err(JournalGap::ClosureStale);
        }
        Ok(())
    }
}

/// The genuine birth-witness kind behind a bootstrap: a real post-attach
/// exec-marker publication or a complete absence-then-appearance proof,
/// both Session-observed and carried by the birth grant. The kind is
/// grant-determined at [`BootstrapReceipt::attest`], backstopped against
/// retained sightings/audit truth, and re-verified by the seal; tests
/// script the grant to pin the seal's structural rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BirthKind {
    ExecMarker,
    AbsenceAppearance,
}

/// Finite birth-attestation refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BirthRefusal {
    /// The image is tainted: no birth is verifiable for it.
    ImageTainted,
    /// The image was never sighted: a birth with zero observed history
    /// proves nothing.
    ImageUnknown,
    /// The receipt was attested under a different closure generation.
    ClosureStale,
    /// Exec-marker birth with the image sighted at or below the cut: the
    /// image predates its claimed birth.
    NoveltyBroken,
    /// Absence-appearance birth without complete absence: the image is
    /// unseen at the cut, unfenced affecting evidence sits at or below
    /// it, or an audit failure broke the clean chain since the fence.
    AbsenceUnproven,
    /// The Session birth evidence does not authorize this claim: wrong
    /// observed image, zero custody, a tripped admission latch, or a
    /// marker word inconsistent with the claimed kind and exec id.
    /// The seal reports the same refusal when fresh evidence moved
    /// since attestation.
    EvidenceMismatch,
    /// The birth cut is below explicitly voided history: the
    /// claimed-complete interval includes loss, so the birth refuses
    /// even when its key did not exist at the void.
    BelowVoidFence,
}

/// Session-observed native evidence behind a birth claim: the image
/// bound by the same held-custody proof, the `journal_bootstrap`
/// marker word read back with it, the admission-latch failure count,
/// the observed attach generation (the row's `exec_attach_gen` for an
/// exec birth, the negative scan's attach cell for absence), and the
/// held-custody generation. Private fields: production observation
/// mints only through the Session issuance capability; attestation
/// checks the grant's evidence and the seal re-checks FRESH evidence,
/// so native truth that moved between the two (a scope-dirtied
/// marker, a tripped latch, lost custody, a generation that moved
/// past the closure) refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionBirthEvidence {
    image: (u64, u64),
    marker_word: u64,
    admission_failed: u64,
    attach_generation: u64,
    custody: u64,
}

impl SessionBirthEvidence {
    /// Production observation: only Session-owned attach code holds the
    /// native-evidence issuance token. Observation sites call this with words
    /// they read or derived from genuine Session producers. This evidence does
    /// not authorize a grant without the validated H0/absence association.
    #[allow(dead_code)] // No production caller until the joint seal tick lands.
    pub(crate) fn issue(
        _token: &crate::attach::SessionGrantToken,
        image: (u64, u64),
        marker_word: u64,
        admission_failed: u64,
        attach_generation: u64,
        custody: u64,
    ) -> Self {
        Self {
            image,
            marker_word,
            admission_failed,
            attach_generation,
            custody,
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        image: (u64, u64),
        marker_word: u64,
        admission_failed: u64,
        attach_generation: u64,
        custody: u64,
    ) -> Self {
        Self {
            image,
            marker_word,
            admission_failed,
            attach_generation,
            custody,
        }
    }

    /// Observed words, read back by tests pinning that observation
    /// carries the producers' words rather than supplied ones.
    #[cfg(test)]
    pub(crate) fn image(&self) -> (u64, u64) {
        self.image
    }

    #[cfg(test)]
    pub(crate) fn marker_word(&self) -> u64 {
        self.marker_word
    }

    #[cfg(test)]
    pub(crate) fn admission_failed(&self) -> u64 {
        self.admission_failed
    }

    #[cfg(test)]
    pub(crate) fn attach_generation(&self) -> u64 {
        self.attach_generation
    }

    #[cfg(test)]
    pub(crate) fn custody(&self) -> u64 {
        self.custody
    }

    /// Canonical valid evidence for one sealed receipt: the READY
    /// marker naming the proof image's exec id, or the unmarked word
    /// for absence; a clean latch, the receipt's closure generation,
    /// and live custody.
    #[cfg(test)]
    pub(crate) fn scripted_for_receipt(receipt: &BootstrapReceipt) -> Self {
        let proof = receipt.proof();
        Self::scripted_canonical(
            (proof.key.cookie, proof.key.exec),
            receipt.birth(),
            receipt.closure_generation(),
        )
    }

    /// Canonical valid evidence for one image, birth kind and closure
    /// generation: the READY marker naming the image's exec id (real
    /// native encoding), or the unmarked word for absence; a clean
    /// latch, the closure's generation, and live custody.
    #[cfg(test)]
    pub(crate) fn scripted_canonical(
        image: (u64, u64),
        birth: BirthKind,
        closure_generation: u64,
    ) -> Self {
        let marker_word = match birth {
            BirthKind::ExecMarker => p11scope_ebpf_common::journal_marker::ready_word(image.1),
            BirthKind::AbsenceAppearance => 0,
        };
        Self {
            image,
            marker_word,
            admission_failed: 0,
            attach_generation: closure_generation,
            custody: 1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct BirthStreamBinding {
    native: NativeDomainId,
    events: u64,
    cursor: u64,
    ledger: ledger::LedgerGeneration,
}
impl std::fmt::Debug for BirthStreamBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BirthStreamBinding(<private>)")
    }
}

/// Only the owning adapter resolves an actual original cursor boundary.
#[derive(Clone, Debug)]
pub(crate) struct JournalBirthCut {
    binding: BirthStreamBinding,
    ordinal: ConsumptionOrdinal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BirthCutRefusal {
    Foreign,
    Prefix,
    Gap,
    Ledger,
}

impl JournalAdapter {
    pub(crate) fn resolve_birth_cut(
        &mut self,
        cut: &crate::events::EventsConsumptionCut,
        producers: &crate::attach::SessionDrainProducers,
    ) -> Result<JournalBirthCut, BirthCutRefusal> {
        let ledger = self.ledger.generation().ok_or(BirthCutRefusal::Ledger)?;
        if !producers.matches_events(cut.events())
            || !self
                .resource_producers
                .as_ref()
                .is_some_and(|retained| retained.same_producers(producers))
        {
            return Err(BirthCutRefusal::Foreign);
        }
        if self.stream_broken || self.invalidated || self.stopped {
            // OD33/R-50 (v0.5.0): an S1-only lane links no
            // object-journal producer, so no Joint certification
            // depends on this stream. The disposal that broke it
            // already disclosed the loss; refusing every future
            // quantum would strand the run for one discarded
            // reservation. Re-sync the next quantum on a fresh
            // stream instead. Linked lanes keep the fail-closed
            // refusal, and a stopped adapter never re-syncs.
            if !producers.journal_linked() && !self.stopped {
                self.stream_broken = false;
                self.invalidated = false;
                self.stream_boundary = Some(cut.clone());
            } else {
                return Err(BirthCutRefusal::Gap);
            }
        }
        match &self.stream_boundary {
            Some(boundary) if boundary.same_boundary(cut) => {}
            None if self.consumed_through == 0 && cut.is_initial() => {
                self.stream_boundary = Some(cut.clone());
            }
            _ => return Err(BirthCutRefusal::Prefix),
        }
        Ok(JournalBirthCut {
            binding: BirthStreamBinding {
                native: producers.native_domain(),
                events: producers.events_id(),
                cursor: cut.cursor(),
                ledger,
            },
            ordinal: self.consumed_frontier(),
        })
    }

    pub(crate) fn accepts_birth_cut(&self, cut: &JournalBirthCut) -> bool {
        !self.stream_broken
            && !self.invalidated
            && !self.stopped
            && self.ledger.generation() == Some(cut.binding.ledger)
            && cut.ordinal.0 <= self.consumed_through
            && self.stream_boundary.as_ref().is_some_and(|boundary| {
                boundary.cursor() == cut.binding.cursor
                    && boundary.events().id() == cut.binding.events
            })
            && self.resource_producers.as_ref().is_some_and(|producers| {
                producers.native_domain() == cut.binding.native
                    && producers.events_id() == cut.binding.events
            })
    }

    pub(crate) fn quiet_sighting_at(&self, image: ImageIdentity, cut: &JournalBirthCut) -> bool {
        self.accepts_birth_cut(cut)
            && self
                .sightings
                .get(&(image.task_cookie, image.exec_id))
                .is_some_and(|sighting| {
                    sighting.first_seen <= cut.ordinal.0
                        && sighting.first_affecting.is_none_or(|at| at > cut.ordinal.0)
                })
    }
}

impl JournalBirthCut {
    pub(crate) fn same_stream(&self, other: &Self) -> bool {
        self.binding == other.binding
    }
}

/// A Session-owned birth grant: the claimed proof, birth kind, cut and
/// closure generation, plus the Session-observed native evidence the
/// claim was attested under (exec marker publication/readback or
/// held-custody absence/appearance). Production mint requires the
/// original validated H0/absence association, so native freshness and stream
/// inference alone can never birth; the fields stay private, attestation checks
/// the bundled evidence, and the seal re-checks fresh evidence against retained
/// truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionBirthGrant {
    proof: JournalDomainProof,
    birth: BirthKind,
    birth_cut: u64,
    closure_generation: u64,
    evidence: SessionBirthEvidence,
    stream: Option<BirthStreamBinding>,
}

impl SessionBirthGrant {
    /// Production mint consumes the H0 owner's opaque authorization. Its exact
    /// proof, birth kind, stream cut, closure and native evidence were checked
    /// together; callers cannot replace one word or mint from a freshness probe.
    #[allow(dead_code)] // No production caller until the joint seal tick lands.
    pub(crate) fn issue(authorization: crate::semantic_capture::ValidatedH0Birth) -> Self {
        let (proof, birth, birth_cut, closure_generation, evidence) = authorization.into_parts();
        Self {
            proof,
            birth,
            birth_cut: birth_cut.ordinal.0,
            closure_generation,
            evidence,
            stream: Some(birth_cut.binding),
        }
    }

    #[cfg(test)]
    pub(crate) fn issue_for_native_row_test(
        _token: &crate::attach::SessionGrantToken,
        proof: JournalDomainProof,
        birth: BirthKind,
        birth_cut: u64,
        closure_generation: u64,
        evidence: SessionBirthEvidence,
    ) -> Self {
        Self::scripted_with_evidence(proof, birth, birth_cut, closure_generation, evidence)
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        proof: JournalDomainProof,
        birth: BirthKind,
        birth_cut: u64,
        closure_generation: u64,
    ) -> Self {
        let image = (proof.key.cookie, proof.key.exec);
        Self {
            proof,
            birth,
            birth_cut,
            closure_generation,
            evidence: SessionBirthEvidence::scripted_canonical(image, birth, closure_generation),
            stream: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted_with_evidence(
        proof: JournalDomainProof,
        birth: BirthKind,
        birth_cut: u64,
        closure_generation: u64,
        evidence: SessionBirthEvidence,
    ) -> Self {
        Self {
            proof,
            birth,
            birth_cut,
            closure_generation,
            evidence,
            stream: None,
        }
    }
}

/// A Session-owned closure grant: the live endpoint-set generation just
/// installed by successful attachment/readback. Observed from the
/// sealed attachment, never supplied: only a real sealing mints a
/// generation, so a supplied integer cannot advance the closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionClosureGrant {
    generation: u64,
}

impl SessionClosureGrant {
    /// Observe the sealed attachment's generation: the joint tick
    /// installs this per quantum, so the installed closure always
    /// names a real sealed endpoint set.
    pub(crate) fn observe(attachment: &crate::attach::AttachedSemanticSet) -> Self {
        Self {
            generation: attachment.generation(),
        }
    }
}

/// A Session-owned drain↔domain association: the native domain tag
/// from an admission the Session's authority minted, bound to the
/// EVENTS-map identity of the Session's own retained EVENTS domain.
/// Mints only through [`SessionDrainGrant::observe`] from the
/// Session's retained producer pair — there is deliberately no
/// scripted seam, so a bare integer, a presented drain's claim, or a
/// spliced foreign admission can never become binding authority. The
/// joint tick mints this from its retained producers per Session and
/// binds it before collecting; tests traverse the same mint with
/// their retained test producers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionDrainGrant {
    domain_tag: u64,
    events_id: u64,
}

/// Finite Session-drain-mint refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainMintRefusal {
    /// The admission names another native domain than the Session
    /// retaining the EVENTS identity: a spliced foreign pair mints
    /// nothing.
    ForeignAdmission,
}

impl SessionDrainGrant {
    /// Read-only association metadata, not allocation or cursor authority.
    /// Q must separately retain the Session's real producers and cursor cut.
    pub(crate) fn matches_producers(
        &self,
        producers: &crate::attach::SessionDrainProducers,
    ) -> bool {
        self.domain_tag == producers.native_domain().journal_tag()
            && self.events_id == producers.events_id()
    }

    /// Mint the association through the Session retaining both the
    /// native and EVENTS identities: the admission is checked against
    /// THAT Session (its native domain must equal the retained one),
    /// and the EVENTS identity always comes from the retained domain
    /// — never from a presented drain, never from an independently
    /// supplied half. A spliced foreign pair refuses at mint.
    pub(crate) fn observe(
        producers: &crate::attach::SessionDrainProducers,
        admitted: &AdmittedInstanceCall,
    ) -> Result<Self, DrainMintRefusal> {
        let (domain, _image, _router, _caller) = admitted.journal_binding();
        // Common ownership: the admission must name the retained
        // native domain — the Session that retains the EVENTS
        // identity it binds. A spliced foreign admission mints
        // nothing.
        if domain != producers.native_domain() {
            return Err(DrainMintRefusal::ForeignAdmission);
        }
        Ok(Self {
            domain_tag: domain.journal_tag(),
            events_id: producers.events_id(),
        })
    }

    /// The associated native domain tag, from the admission.
    #[cfg(test)]
    pub(crate) fn domain_tag(&self) -> u64 {
        self.domain_tag
    }

    /// The associated EVENTS-map identity, from the retained domain.
    #[cfg(test)]
    pub(crate) fn events_id(&self) -> u64 {
        self.events_id
    }
}

/// One domain's bootstrap: its Session-issued birth grant, verified at
/// attestation and re-verified by the seal, so a chain break between
/// attestation and seal still refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BootstrapReceipt {
    grant: SessionBirthGrant,
}

impl BootstrapReceipt {
    /// Production birth attestation: the Session grant is the birth
    /// authority; the adapter checks its bundled native evidence plus
    /// the live closure generation and its retained sightings/audit
    /// chain as a backstop (an inconsistent grant refuses). The seal
    /// re-verifies with fresh evidence before converting.
    pub(crate) fn attest(
        adapter: &JournalAdapter,
        grant: &SessionBirthGrant,
    ) -> Result<Self, BirthRefusal> {
        if grant.closure_generation != adapter.closure_generation {
            return Err(BirthRefusal::ClosureStale);
        }
        if let Some(stream) = grant.stream
            && (stream.native.journal_tag() != grant.proof.key.domain_tag
                || !adapter.accepts_birth_cut(&JournalBirthCut {
                    binding: stream,
                    ordinal: ConsumptionOrdinal(grant.birth_cut),
                }))
        {
            return Err(BirthRefusal::EvidenceMismatch);
        }
        let fenced_through = adapter
            .keys
            .get(&grant.proof.key)
            .map(|state| state.void_fence)
            .unwrap_or(0)
            .max(adapter.voided_through);
        if grant.birth_cut < fenced_through {
            return Err(BirthRefusal::BelowVoidFence);
        }
        adapter.verify_birth(
            &grant.proof,
            grant.birth,
            grant.birth_cut,
            fenced_through,
            &grant.evidence,
            grant.closure_generation,
        )?;
        Ok(Self { grant: *grant })
    }

    pub(crate) fn proof(&self) -> JournalDomainProof {
        self.grant.proof
    }

    /// The immutable qualified incarnation already proven by this receipt.
    pub(crate) fn domain(&self) -> ObjectDomain {
        self.grant.proof.domain()
    }

    pub(crate) fn birth(&self) -> BirthKind {
        self.grant.birth
    }

    pub(crate) fn birth_cut(&self) -> u64 {
        self.grant.birth_cut
    }

    pub(crate) fn closure_generation(&self) -> u64 {
        self.grant.closure_generation
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        proof: JournalDomainProof,
        birth: BirthKind,
        birth_cut: u64,
        closure_generation: u64,
    ) -> Self {
        Self {
            grant: SessionBirthGrant::scripted(proof, birth, birth_cut, closure_generation),
        }
    }
}

/// One settled call for H9: its model ticket, function and cuts. Read-only
/// output; H9 orders by these cuts but mints nothing from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SealedCall {
    pub(crate) ticket: CallToken,
    pub(crate) key: CallKey,
    pub(crate) function: u32,
    pub(crate) begin_cut: u64,
    pub(crate) end_cut: Option<u64>,
    pub(crate) abandoned: bool,
    /// Correlation fingerprint (H9 exact binding): the sealed
    /// session and mechanism class, mirroring the call's origin
    /// fact. The staged head must match exactly (see
    /// [`SealedCall::matches_head`]).
    pub(crate) session: super::HandleInput<super::SessionHandle>,
    pub(crate) mechanism: super::state::MechClass,
}

impl SealedCall {
    /// Whether this sealed call IS the staged head's call (H9 exact
    /// correlation): FIRST the same admitted invocation — the sealed
    /// key's admission ordinal IS the head's H0 position (C2
    /// identity: conversion mints tickets from queued admissions, so
    /// value-equal shapes from different invocations never match) —
    /// then the same catalog function, the same session, and the same
    /// mechanism capture shape. Value words are never compared (only
    /// the finite class crosses); an unreadable sealed session never
    /// matches; a session-less staged head matches only a
    /// session-less sealed call.
    pub(crate) fn matches_head(
        &self,
        function: u32,
        session: u64,
        mechanism_capture: u32,
        head_position: u64,
    ) -> bool {
        if self.key.admission() != head_position {
            return false;
        }
        if self.function != function {
            return false;
        }
        let session_ok = match self.session {
            super::HandleInput::Value(handle) => handle.0 == session,
            super::HandleInput::Absent => session == p11scope_ebpf_common::SESSION_NONE,
            super::HandleInput::Unreadable => false,
        };
        if !session_ok {
            return false;
        }
        let bits = mechanism_capture & capture::MECHANISM_MASK;
        let class = if bits == capture::MECHANISM_VALUE {
            super::state::MechClass::Value
        } else if bits == capture::MECHANISM_NULL {
            super::state::MechClass::Null
        } else if bits == capture::MECHANISM_UNREADABLE {
            super::state::MechClass::Unreadable
        } else {
            super::state::MechClass::NotCaptured
        };
        self.mechanism == class
    }
}

/// The sealed prefix H9 consumes: the proven domain, frontier, birth
/// and bootstrap cuts, the settled calls and the still-open keys. Built
/// only by a passing seal; the only path to a production
/// [`CompleteInputPrefix`].
#[derive(Debug)]
pub(crate) struct SealedObjectPrefix {
    domain: ObjectDomain,
    frontier: u64,
    birth_cut: u64,
    bootstrap: Option<u64>,
    settled: Vec<SealedCall>,
    // Existing single-call H9 consumes only the current begin-ordered delta.
    // Replay steps may additionally name retained prior conversions appended
    // to this SAME table; they do not widen legacy replay permission.
    settled_len: usize,
    replay_steps: Vec<SealReplayStep>,
    // The original paid conversion locator follows the same table/steps.
    // No consumer can construct an index or substitute its allocation.
    replay_index: Option<seal_replay::ReplayIndex>,
    open: Vec<CallKey>,
}

#[allow(dead_code)] // H9's frozen read interface; H8 seals through it.
impl SealedObjectPrefix {
    /// The proven incarnation this prefix settles.
    pub(crate) fn domain(&self) -> ObjectDomain {
        self.domain
    }

    /// The sealed frontier cut (H9 orders S1 replay at or below it).
    pub(crate) fn frontier_cut(&self) -> u64 {
        self.frontier
    }

    /// The genuine birth cut this prefix was sealed under: proven
    /// history starts above it.
    pub(crate) fn birth_cut(&self) -> u64 {
        self.birth_cut
    }

    /// The model's bootstrap authority for this seal, when the seal
    /// claims any: strictly above the birth, the last sealed frontier,
    /// the void fence and every recorded or pending loss bound. A seal
    /// whose held calls pin below those floors claims nothing (`None`):
    /// it continues under the model's existing floor instead of
    /// presenting a bootstrap the model must refuse. The model input,
    /// not the birth.
    pub(crate) fn bootstrap_cut(&self) -> Option<u64> {
        self.bootstrap
    }

    /// The calls settled by this seal, in begin-cut order.
    pub(crate) fn settled(&self) -> &[SealedCall] {
        &self.settled[..self.settled_len]
    }

    /// The still-open keys at the frontier, for H9's pending alignment.
    pub(crate) fn open_keys(&self) -> &[CallKey] {
        &self.open
    }

    pub(in crate::semantics_objects) fn prefix(&self) -> CompleteInputPrefix {
        CompleteInputPrefix::from_sealed_parts(
            self.domain,
            self.frontier,
            &self.open,
            self.bootstrap,
        )
    }
}

/// A passing seal: the sealed prefix plus the conversion and settlement
/// effects that produced it.
#[derive(Debug)]
pub(crate) struct SealSuccess {
    pub(crate) prefix: SealedObjectPrefix,
    pub(crate) effects: ObjectEffects,
}

/// A refused seal: the finite gap plus any effects the refusal itself
/// applied (abandonment invalidations are reported, never swallowed).
#[derive(Debug)]
pub(crate) struct SealFailure {
    scope: SealFailureScope,
    pub(crate) gap: JournalGap,
    pub(crate) effects: ObjectEffects,
    /// H3-loss acknowledgement: H0 positions below this watermark were
    /// voided by this seal. The joint tick forwards it to the H3
    /// finalizer (`acknowledge_h3_void`); `None` when this seal voided
    /// no H3 loss.
    pub(crate) h3_voided: Option<u64>,
}

/// Identity of an existing adapter refusal, never positive authority.
/// Rare global losses retain at most JournalLimits::domain_keys domains.
#[derive(Debug)]
enum SealFailureScope {
    Unqualified,
    Domain(ObjectDomain),
    AffectedDomains(Vec<ObjectDomain>),
}

impl SealFailure {
    #[cfg(test)]
    pub(crate) fn affects_proof_for_test(&self, proof: &JournalDomainProof) -> bool {
        self.affects_domain(proof.domain())
    }

    pub(crate) fn affects_domain(&self, domain: ObjectDomain) -> bool {
        match &self.scope {
            SealFailureScope::Unqualified => false,
            SealFailureScope::Domain(owned) => *owned == domain,
            SealFailureScope::AffectedDomains(owned) => owned.contains(&domain),
        }
    }
}

/// Finite attestation refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttestationRefusal {
    /// Original physical invocation is already below its irreversible
    /// return fence and no unique unconsumed retained START owns it.
    InvocationStale,
    ImageTainted,
    KeysExhausted,
    Stopped,
    /// Another live key for this image already converted: calls
    /// attributed under sole-key authority cannot be re-examined once
    /// a sibling instance appears.
    ImageSealed,
    /// The per-call claim store is full: conversion must dispose
    /// staged calls (or a void must clear them) before new admissions
    /// claim authority.
    ClaimsExhausted,
}

/// Finite Session-drain-bind refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainBindRefusal {
    /// The admission's native domain attested no key on this adapter:
    /// only attested domains bind drains.
    DomainUnattested,
    /// The domain already binds another EVENTS-map identity: the first
    /// Session binding wins, never a rebind.
    DrainConflict,
}

impl JournalAdapter {
    /// Verify one Session-granted birth claim: its native evidence
    /// first, then the retained sightings/audit backstop. Shared by
    /// production attestation (grant-bundled evidence) and the seal's
    /// re-verification (fresh evidence), so native truth that moved
    /// between the two still refuses. The evidence is the birth
    /// authority; the backstop only refuses grants inconsistent with
    /// retained truth — it never births on its own. `fenced_through`
    /// is the key's void fence: absence requires zero UNFENCED
    /// affecting evidence at or below the cut and a chain unbroken
    /// since the fence. Exec-marker novelty stays strict: a fenced
    /// past is still a past. `closure_generation` is the live closure
    /// the birth is claimed under: the observed attach generation —
    /// the row's `exec_attach_gen` for an exec birth, the negative
    /// scan's attach cell for absence — must equal it (the witness
    /// ran under this closure).
    fn verify_birth(
        &self,
        proof: &JournalDomainProof,
        birth: BirthKind,
        birth_cut: u64,
        fenced_through: u64,
        evidence: &SessionBirthEvidence,
        closure_generation: u64,
    ) -> Result<(), BirthRefusal> {
        let image = (proof.key.cookie, proof.key.exec);
        // Native evidence first: the observed image must be this one,
        // custody must bind a live held proof, the admission latch must
        // be clean, the observed attach generation must be the live
        // closure's, and the marker word must authorize the claimed
        // kind under the real native encoding: READY naming the
        // image's full exec id for an exec birth, or the exactly
        // unmarked word for absence. Dirty, invalid or mismatched
        // states refuse; zero custody binds nothing.
        if evidence.image != image || evidence.custody == 0 || evidence.admission_failed != 0 {
            return Err(BirthRefusal::EvidenceMismatch);
        }
        if evidence.attach_generation != closure_generation {
            return Err(BirthRefusal::EvidenceMismatch);
        }
        let marker_ok = match birth {
            BirthKind::ExecMarker => {
                p11scope_ebpf_common::journal_marker::read_word(evidence.marker_word)
                    == p11scope_ebpf_common::journal_marker::MarkerRead::Ready(image.1)
            }
            BirthKind::AbsenceAppearance => evidence.marker_word == 0,
        };
        if !marker_ok {
            return Err(BirthRefusal::EvidenceMismatch);
        }
        if self.is_tainted(image) {
            return Err(BirthRefusal::ImageTainted);
        }
        let Some(sighting) = self.sightings.get(&image) else {
            return Err(BirthRefusal::ImageUnknown);
        };
        match birth {
            BirthKind::ExecMarker => {
                if sighting.first_seen <= birth_cut {
                    return Err(BirthRefusal::NoveltyBroken);
                }
            }
            BirthKind::AbsenceAppearance => {
                if sighting.first_seen > birth_cut
                    || sighting
                        .first_affecting
                        .is_some_and(|at| at <= birth_cut && at > fenced_through)
                    || self
                        .last_audit_failure
                        .is_some_and(|at| at >= sighting.first_seen && at > fenced_through)
                {
                    return Err(BirthRefusal::AbsenceUnproven);
                }
            }
        }
        Ok(())
    }

    /// Install the closure generation from a Session-owned grant after
    /// an attachment change alters the retained endpoint set. Monotonic:
    /// a regression is refused and the generation stays. Existing
    /// receipts and audits under older generations refuse as stale; only
    /// fresh Session-granted attestation under the live generation
    /// seals. A supplied integer never advances the closure: production
    /// grants mint only through the H0 owner's validated association.
    pub(crate) fn install_closure_grant(&mut self, grant: &SessionClosureGrant) -> bool {
        if grant.generation < self.closure_generation {
            return false;
        }
        self.closure_generation = grant.generation;
        true
    }

    /// Bind one H3-admitted call's incarnation to a journal key without
    /// claiming the invocation before its original START is ingested: exact
    /// native domain, caller, image and router, plus the adapter-tracked
    /// era. Re-attestation after a fault-void returns the live key; a
    /// tainted image or a full key table refuses. A second live key for
    /// an image whose key already converted refuses: sole-key
    /// attributions cannot be re-examined.
    /// Birth and closure are verified on top of this binding by
    /// [`BootstrapReceipt::attest`].
    pub(crate) fn bind_admitted_key(
        &mut self,
        admitted: &AdmittedInstanceCall,
    ) -> Result<JournalDomainProof, AttestationRefusal> {
        if self.stopped || self.invalidated {
            return Err(AttestationRefusal::Stopped);
        }
        let (domain, image, router, caller) = admitted.journal_binding();
        let key = JournalDomainKey {
            domain_tag: domain.journal_tag(),
            caller: caller.0,
            cookie: image.task_cookie,
            exec: image.exec_id,
            router: router.get(),
        };
        if self.is_tainted((key.cookie, key.exec)) {
            return Err(AttestationRefusal::ImageTainted);
        }
        if !self.keys.contains_key(&key)
            && let Some(siblings) = self.image_keys.get(&(key.cookie, key.exec))
            && siblings.iter().any(|sibling| {
                sibling != &key && self.key_is_live(*sibling) && self.keys[sibling].model_registered
            })
        {
            return Err(AttestationRefusal::ImageSealed);
        }
        if !self.keys.contains_key(&key) {
            if self.keys.len() >= self.limits.domain_keys {
                return Err(AttestationRefusal::KeysExhausted);
            }
            self.keys.insert(key, JournalDomainState::default());
            self.image_keys
                .entry((key.cookie, key.exec))
                .or_default()
                .push(key);
        }
        let era = self.keys[&key].era;
        Ok(JournalDomainProof { key, era })
    }

    /// Preserve normal attestation semantics: bind the key, then claim this
    /// actual modeled invocation once its original raw history is ingested.
    pub(crate) fn attest_key(
        &mut self,
        admitted: &AdmittedInstanceCall,
    ) -> Result<JournalDomainProof, AttestationRefusal> {
        let proof = self.bind_admitted_key(admitted)?;
        let key = proof.key;
        if let Some(fingerprint) = admitted.journal_call_fingerprint()
            && endpoint_class(fingerprint.function) == Some(EndpointClass::ModeledAffecting)
        {
            self.claim_fingerprint(
                fingerprint,
                key,
                AdmittedJournalClaim {
                    admission: admitted.h0_ordinal(),
                    return_ns: admitted
                        .journal_return_ns()
                        .expect("fingerprint retained its return"),
                },
            )?;
        }
        let era = self.keys[&key].era;
        Ok(JournalDomainProof { key, era })
    }

    /// Read the actual physical original independently of claim disposition.
    /// No scalar position, resource ID or equal-shaped sibling substitutes.
    fn retained_admission_entry(&self, admitted: &AdmittedInstanceCall) -> Option<&OpenEntry> {
        let (Some(origin), Some(resource), Some(fingerprint)) = (
            admitted.collected_origin(),
            admitted.joint_resource_origin(),
            admitted.journal_call_fingerprint(),
        ) else {
            return None;
        };
        let entry = self.open.get(&resource.invocation())?;
        let end = entry.end?;
        (origin.position() == admitted.h0_ordinal()
            && entry.collected_origin == Some(origin)
            && entry.image == fingerprint.image
            && fingerprint_of_begin(&entry.begin) == fingerprint
            && end_agrees_with_begin(&entry.begin, &end.end)
            && admitted.journal_return_ns() == Some(end.end.payload_base().event.ts_ns)
            && fingerprint_matches_event(&fingerprint, &end.end.payload_base().event)
            && entry.converted_ticket.is_none()
            && entry.converted_for.is_none()
            && entry.call_key.is_none()
            && !entry.end_converted
            && entry.abandon.is_none()
            && entry.corroborated_return.is_none()
            && self
                .resource_producers
                .as_ref()
                .is_some_and(|producers| resource.matches_producers(producers)))
        .then_some(entry)
    }

    /// Continued admission authority still requires an unclaimed original.
    /// Exact own-claim disposal below grants only a negative, never a claim.
    fn matches_retained_admission(&self, admitted: &AdmittedInstanceCall) -> bool {
        let Some(entry) = self.retained_admission_entry(admitted) else {
            return false;
        };
        !self
            .claims
            .get(&fingerprint_of_begin(&entry.begin))
            .is_some_and(|claimants| claimants.values().any(|claims| !claims.is_empty()))
            && self.ledger.matches_unconverted_original(
                entry.begin_ordinal,
                admitted
                    .joint_resource_origin()
                    .expect("checked original")
                    .reservation(),
                None,
            )
    }

    /// An absent claim or exactly this original's one claim. Two same-shaped
    /// physical rows, another key, a repeated claim or another return refuses.
    fn s1only_original_claim(
        &self,
        entry: &OpenEntry,
        key: JournalDomainKey,
    ) -> Option<Option<AdmittedJournalClaim>> {
        let end = entry.end?;
        let origin = entry.collected_origin?;
        if entry.image != (key.cookie, key.exec)
            || self
                .resource_producers
                .as_ref()?
                .native_domain()
                .journal_tag()
                != key.domain_tag
        {
            return None;
        }
        let fingerprint = fingerprint_of_begin(&entry.begin);
        let mut originals = self
            .claims
            .get(&fingerprint)
            .into_iter()
            .flat_map(|claimants| {
                claimants
                    .iter()
                    .flat_map(|(key, claims)| claims.iter().map(move |claim| (key, claim)))
            });
        let Some((claimant, claim)) = originals.next() else {
            return Some(None);
        };
        (originals.next().is_none()
            && *claimant == key
            && claim.admission == origin.position()
            && claim.return_ns == end.end.payload_base().event.ts_ns)
            .then_some(Some(*claim))
    }

    /// One strict READ-ONLY validator for mint and consumption. An unused
    /// or refused bookkeeping token must leave the original unmarked so its
    /// actual registry cursor can retry it without changing custody.
    fn preflight_s1only_subject(
        &self,
        admitted: &AdmittedInstanceCall,
    ) -> Result<JournalDomainKey, joint_driver::RawQuantumRefusal> {
        use joint_driver::RawQuantumRefusal;
        let (native, image, router, caller) = admitted.journal_binding();
        let key = JournalDomainKey {
            domain_tag: native.journal_tag(),
            caller: caller.0,
            cookie: image.task_cookie,
            exec: image.exec_id,
            router: router.get(),
        };
        let entry = self
            .retained_admission_entry(admitted)
            .ok_or(RawQuantumRefusal::Admission)?;
        if self.s1only_original_claim(entry, key).is_none()
            || !self.ledger.matches_unconverted_original(
                entry.begin_ordinal,
                admitted
                    .joint_resource_origin()
                    .expect("checked original")
                    .reservation(),
                None,
            )
        {
            return Err(RawQuantumRefusal::Admission);
        }
        if entry.s1only_subject.is_some() {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        Ok(key)
    }

    /// Commit the marker only after the exact immutable cursor input has
    /// consumed its token, while the adapter is still exclusively borrowed.
    /// No image taint, model transition or membership release occurs here.
    fn retain_s1only_subject(
        &mut self,
        admitted: &AdmittedInstanceCall,
    ) -> Result<(), joint_driver::RawQuantumRefusal> {
        let key = self.preflight_s1only_subject(admitted)?;
        let resource = admitted
            .joint_resource_origin()
            .expect("checked original END");
        let entry = self
            .open
            .get_mut(&resource.invocation())
            .expect("checked physical original");
        entry.s1only_subject = Some(key);
        Ok(())
    }

    /// Always-negative PRESENT state for one constructor-bound decoded
    /// original whose operation has completely left the resource table.
    /// Nothing here proves that ingest refused it, clears held custody, or
    /// permits a seal. The exact immutable admission/RV remains borrowed by
    /// the caller until the same registry stage-cursor original consumes it.
    fn released_tainted_s1_original(
        &self,
        admitted: &AdmittedInstanceCall,
        producers: &crate::attach::SessionDrainProducers,
    ) -> bool {
        let (native, image, _, _) = admitted.journal_binding();
        let (Some(origin), Some(resource), Some(fingerprint), Some(return_ns)) = (
            admitted.collected_origin(),
            admitted.joint_resource_origin(),
            admitted.journal_call_fingerprint(),
            admitted.journal_return_ns(),
        ) else {
            return false;
        };
        if native != producers.native_domain()
            || !resource.matches_producers(producers)
            || origin.position() != admitted.h0_ordinal()
            || fingerprint.image != (image.task_cookie, image.exec_id)
            || fingerprint.pid_tgid as u32 == 0
            || fingerprint.pid_tgid >> 32 == 0
            || fingerprint.entry_ns >= return_ns
            || return_ns != admitted.s1_facts().ts_ns
            || endpoint_class(fingerprint.function) != Some(EndpointClass::ModeledAffecting)
            || !self.is_tainted(fingerprint.image)
            || !self.ledger.original_is_released(resource.reservation())
        {
            return false;
        }
        // An invocation collision, retained/converted original, marked row,
        // refused begin or claim (even an own claim) must stay on the strict
        // retained path. In particular no per-image/global empty-ledger test
        // can replace this original's complete alias/role release above.
        if self.open.contains_key(&resource.invocation())
            || self.open.values().any(|entry| {
                entry.collected_origin == Some(origin)
                    || fingerprint_of_begin(&entry.begin) == fingerprint
            })
            || self
                .refused
                .iter()
                .any(|entry| fingerprint_of_refused(entry) == fingerprint)
            || self.claims.iter().any(|(claimed, claimants)| {
                claimants.iter().any(|(key, claims)| {
                    !claims.is_empty()
                        && (*claimed == fingerprint
                            || (key.domain_tag == native.journal_tag()
                                && claims
                                    .iter()
                                    .any(|claim| claim.admission == admitted.h0_ordinal())))
                })
            })
        {
            return false;
        }
        true
    }

    /// Bind the Session drain serving one attested native domain from
    /// the Session-minted association: the grant's EVENTS-map identity
    /// (minted from the Session's retained EVENTS domain) to its native
    /// domain tag (minted from the Session's admission). No drain
    /// object is read here at all — a presented drain is only ever
    /// CHECKED against the pin at collection, so a foreign drain
    /// presented first refuses instead of becoming authority. The joint
    /// seal tick calls this once per Session from its own producers
    /// before the first collection. The domain must have attested
    /// (pins stay within the key table), and the first binding wins: a
    /// conflicting rebind refuses loudly. Repeating the same grant is
    /// idempotent.
    pub(crate) fn bind_session_drain(
        &mut self,
        grant: &SessionDrainGrant,
    ) -> Result<(), DrainBindRefusal> {
        if !self
            .keys
            .keys()
            .any(|key| key.domain_tag == grant.domain_tag)
        {
            return Err(DrainBindRefusal::DomainUnattested);
        }
        // A single adapter has one ordered EVENTS/clock namespace;
        // native domains may share that drain, never independent drains.
        if self
            .drain_pins
            .values()
            .any(|pinned| *pinned != grant.events_id)
        {
            return Err(DrainBindRefusal::DrainConflict);
        }
        match self.drain_pins.get(&grant.domain_tag) {
            Some(pinned) if *pinned == grant.events_id => Ok(()),
            Some(_) => Err(DrainBindRefusal::DrainConflict),
            None => {
                self.drain_pins.insert(grant.domain_tag, grant.events_id);
                Ok(())
            }
        }
    }

    /// Whether one key can still seal: bound, unrefused, untainted,
    /// unterminated, on an untainted image.
    fn key_is_live(&self, key: JournalDomainKey) -> bool {
        self.keys
            .get(&key)
            .is_some_and(|state| !state.refused && !state.tainted && !state.era_ended)
            && !self.is_tainted((key.cookie, key.exec))
    }

    /// Live keys bound for one image: the attribution set a seal
    /// partitions staged calls over.
    fn live_keys_for_image(&self, image: (u64, u64)) -> Vec<JournalDomainKey> {
        self.image_keys
            .get(&image)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|key| self.key_is_live(*key))
            .collect()
    }

    /// Claim one admitted fingerprint for its key, queueing its H0
    /// admission ordinal (C2 identity). Counts stay within the
    /// staged-call bound; a full store first drops dead keys'
    /// claims, then refuses the attestation.
    fn claim_fingerprint(
        &mut self,
        fingerprint: CallFingerprint,
        key: JournalDomainKey,
        claim: AdmittedJournalClaim,
    ) -> Result<(), AttestationRefusal> {
        let retained = self
            .open
            .values()
            .filter(|entry| {
                entry.converted_ticket.is_none()
                    && fingerprint_of_begin(&entry.begin) == fingerprint
            })
            .count()
            + self
                .refused
                .iter()
                .filter(|entry| fingerprint_of_refused(entry) == fingerprint)
                .count();
        if self
            .physical_return_floors
            .get(&fingerprint.pid_tgid)
            .is_some_and(|floor| fingerprint.entry_ns < *floor)
            && retained != 1
        {
            return Err(AttestationRefusal::InvocationStale);
        }
        if !self
            .physical_return_floors
            .contains_key(&fingerprint.pid_tgid)
            && self.physical_return_floors.len() >= self.limits.thread_floors
        {
            return Err(AttestationRefusal::ClaimsExhausted);
        }
        self.physical_return_floors
            .entry(fingerprint.pid_tgid)
            .or_default();
        if self.claim_counts >= self.limits.open_calls + self.limits.refused_begins {
            self.prune_dead_claims();
            if self.claim_counts >= self.limits.open_calls + self.limits.refused_begins {
                return Err(AttestationRefusal::ClaimsExhausted);
            }
        }
        self.claims
            .entry(fingerprint)
            .or_default()
            .entry(key)
            .or_default()
            .push_back(claim);
        self.claim_counts += 1;
        if self.claims[&fingerprint]
            .values()
            .map(VecDeque::len)
            .sum::<usize>()
            > 1
        {
            // No ordering can select between identical physical inputs.
            // Preserve claims unconsumed and make the ambiguity sticky,
            // including across later pruning and staging voids.
            self.taint_image(fingerprint.image);
        }
        Ok(())
    }

    /// Drop dead keys' claims: their seals refuse anyway, so their
    /// authority is garbage. Solely-dead-claimed staged entries keep
    /// their skip (never convert, never barrier the living).
    fn prune_dead_claims(&mut self) {
        let live: BTreeSet<JournalDomainKey> = self
            .keys
            .keys()
            .copied()
            .filter(|key| self.key_is_live(*key))
            .collect();
        self.claims.retain(|_, claimants| {
            claimants.retain(|key, _| live.contains(key));
            !claimants.is_empty()
        });
        self.claim_counts = self
            .claims
            .values()
            .map(|m| m.values().map(VecDeque::len).sum::<usize>())
            .sum::<usize>();
    }

    /// Peek the exact invocation claim after whole-quantum uniqueness
    /// validation. Conversion mints its ticket from that H0 identity.
    fn peek_claim(
        &self,
        fingerprint: &CallFingerprint,
        key: JournalDomainKey,
    ) -> Option<AdmittedJournalClaim> {
        self.claims
            .get(fingerprint)
            .and_then(|claimants| claimants.get(&key))
            .and_then(|ordinals| ordinals.front().copied())
    }

    /// Consume one queued admission for a converted (or refused)
    /// call, returning its H0 ordinal. Every conversion holds a claim
    /// (attribution requires it, and coverage is checked before
    /// conversion), so the store always has the ordinal; refused
    /// burns discard it. Returns `None` only on invariant break
    /// (callers refuse loudly, never minting from thin air).
    fn consume_claim(
        &mut self,
        fingerprint: &CallFingerprint,
        key: JournalDomainKey,
    ) -> Option<AdmittedJournalClaim> {
        let mut vacated = false;
        let mut popped = None;
        if let Some(claimants) = self.claims.get_mut(fingerprint) {
            if let Some(ordinals) = claimants.get_mut(&key) {
                popped = ordinals.pop_front();
                if let Some(claim) = popped {
                    self.claim_counts -= 1;
                    let floor = self
                        .physical_return_floors
                        .get_mut(&fingerprint.pid_tgid)
                        .expect("physical namespace reserved before claim consumption");
                    *floor = (*floor).max(claim.return_ns);
                }
                if ordinals.is_empty() {
                    claimants.remove(&key);
                }
            }
            vacated = claimants.is_empty();
        }
        if vacated {
            self.claims.remove(fingerprint);
        }
        popped
    }

    /// Read one selected physical original. Counts are useful only after
    /// every matching original has passed this exact key/START/END/H9 check.
    #[allow(clippy::too_many_arguments)]
    fn completed_fallback_original(
        &self,
        entry: &OpenEntry,
        audit: &JournalAuditReceipt,
        key: JournalDomainKey,
        frontier: ConsumptionOrdinal,
        staged_max: u64,
        target: &crate::discovery::caller_registry::instance_input::JointFeedTarget,
        registry: &crate::discovery::caller_registry::CallerRegistry,
    ) -> Result<Option<u64>, joint_driver::RawQuantumRefusal> {
        use joint_driver::RawQuantumRefusal;
        let fingerprint = fingerprint_of_begin(&entry.begin);
        let Some(claimants) = self.claims.get(&fingerprint) else {
            return Ok(None);
        };
        let Some(mine) = claimants.get(&key).filter(|claims| !claims.is_empty()) else {
            return Ok(None);
        };
        let Some(end) = entry.end else {
            return Err(RawQuantumRefusal::DispositionMismatch);
        };
        if mine.len() != 1
            || claimants
                .values()
                .filter(|claims| !claims.is_empty())
                .count()
                != 1
            || entry.begin_ordinal > frontier.0
            || end.ordinal > frontier.0
            || entry.image != (key.cookie, key.exec)
            || entry.converted_ticket.is_some()
            || entry.converted_for.is_some()
            || entry.call_key.is_some()
            || entry.end_converted
            || entry.abandon.is_some()
            || entry.corroborated_return.is_some()
            || entry.raw_resource.is_none()
            || entry.s1only_subject.is_some()
        {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        let claim = mine.front().expect("one original admission");
        let event = end.end.payload_base().event;
        let staged = registry
            .joint_staged_resource(target, claim.admission)
            .ok_or(RawQuantumRefusal::DispositionMismatch)?;
        if claim.admission > staged_max
            || claim.admission >= audit.h0_below
            || entry
                .collected_origin
                .is_none_or(|origin| origin.position() != claim.admission)
            || !end_agrees_with_begin(&entry.begin, &end.end)
            || !fingerprint_matches_event(&fingerprint, &event)
            || event.ts_ns != claim.return_ns
            || !self
                .physical_return_floors
                .contains_key(&fingerprint.pid_tgid)
            || !self.ledger.matches_completed_staging(
                entry.begin_ordinal,
                key.domain_tag,
                claim.admission,
                staged,
            )
        {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        Ok(Some(claim.admission))
    }

    /// Validate the original suffix once, in bounded work, before any fallback
    /// effect or S1 replay. The same frame/cursor then commits only one exact
    /// completed H8 owner after each actual H9 disposition. No callback,
    /// exported disposal token, copied fact queue or whole-suffix retry scan.
    #[allow(clippy::too_many_arguments)]
    fn deliver_completed_fallback(
        &mut self,
        input: joint_audit::AuditedDomainInput<'_>,
        batch: &mut joint_audit::FailureBatchDelivery<'_>,
        target: &crate::discovery::caller_registry::instance_input::JointFeedTarget,
        registry: &mut crate::discovery::caller_registry::CallerRegistry,
        model: &ObjectSemantics,
        remaining: &mut usize,
    ) -> Result<crate::semantics_key_use::FailureBatchProgress, joint_driver::RawQuantumRefusal>
    {
        use crate::semantics_key_use::{FailureBatchProgress, SealFailureDisposition};
        use joint_driver::RawQuantumRefusal;
        batch.audited().validate_input(self, &input)?;
        let (audit, bootstrap, frontier) = input.into_parts();
        let proof = bootstrap.proof();
        let key = proof.key;
        let H3DispositionEvidence::Clean {
            staged_max,
            pending_floor: None,
        } = &audit.h3
        else {
            return Err(RawQuantumRefusal::DispositionMismatch);
        };
        if !std::ptr::eq(bootstrap, target.bootstrap())
            || key.caller != target.caller().0
            || self
                .keys
                .get(&key)
                .is_none_or(|state| state.era != proof.era)
            || self
                .resource_producers
                .as_ref()
                .is_none_or(|own| own.native_domain().journal_tag() != key.domain_tag)
            || batch.audited().disposition() != SealFailureDisposition::Fallback
        {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        if let Some(total) = batch.cursor.suffix {
            if registry.joint_staged_count(target) != total.checked_sub(batch.cursor.consumed) {
                return Err(RawQuantumRefusal::DispositionMismatch);
            }
        } else {
            loop {
                if *remaining == 0 {
                    return Ok(FailureBatchProgress::Yielded);
                }
                let next = match batch.cursor.after {
                    None => self.open.first_key_value(),
                    Some(native) => self
                        .open
                        .range((
                            std::ops::Bound::Excluded(native),
                            std::ops::Bound::Unbounded,
                        ))
                        .next(),
                };
                *remaining -= 1;
                let Some((native, entry)) = next else {
                    let expected = registry
                        .joint_staged_count(target)
                        .ok_or(RawQuantumRefusal::Admission)?;
                    if batch.cursor.verified != expected {
                        return Err(RawQuantumRefusal::DispositionMismatch);
                    }
                    batch.cursor.suffix = Some(expected);
                    break;
                };
                if self
                    .completed_fallback_original(
                        entry,
                        audit,
                        key,
                        frontier,
                        *staged_max,
                        target,
                        registry,
                    )?
                    .is_some()
                {
                    batch.cursor.verified = batch
                        .cursor
                        .verified
                        .checked_add(1)
                        .ok_or(RawQuantumRefusal::Capacity)?;
                }
                batch.cursor.after = Some(*native);
            }
        }
        let before = registry
            .joint_staged_count(target)
            .ok_or(RawQuantumRefusal::Admission)?;
        let head = registry.joint_staged_head_original(target);
        let original = match head {
            Some((admission, Some(native))) => {
                let entry = self
                    .open
                    .get(&native)
                    .ok_or(RawQuantumRefusal::DispositionMismatch)?;
                if self.completed_fallback_original(
                    entry,
                    audit,
                    key,
                    frontier,
                    *staged_max,
                    target,
                    registry,
                )? != Some(admission)
                {
                    return Err(RawQuantumRefusal::DispositionMismatch);
                }
                Some((native, admission))
            }
            Some((_, None)) => return Err(RawQuantumRefusal::DispositionMismatch),
            None if before == 0 => None,
            None => return Err(RawQuantumRefusal::DispositionMismatch),
        };
        let outcome =
            registry.deliver_joint_failure(target.id(), batch, model, &mut self.ledger, remaining);
        let after = registry
            .joint_staged_count(target)
            .ok_or(RawQuantumRefusal::Admission)?;
        if after != before {
            assert_eq!(
                before.checked_sub(1),
                Some(after),
                "one bounded original disposition"
            );
            let (native, admission) = original.expect("preflight exact consumed head");
            let (ordinal, fingerprint) = {
                let entry = self
                    .open
                    .remove(&native)
                    .expect("exclusively retained original");
                (entry.begin_ordinal, fingerprint_of_begin(&entry.begin))
            };
            let claim = self
                .consume_claim(&fingerprint, key)
                .expect("preflight original claim");
            assert_eq!(claim.admission, admission);
            self.ledger.release_h8open(ordinal);
            batch.cursor.consumed += 1;
        }
        Ok(outcome)
    }

    /// Attribute one staged fingerprint under a sealing key. Every
    /// staged call converts only under its key's admission claim —
    /// including under a sole live key, which does not prove a sole
    /// provider instance. A sole live claim converts here, a sibling's
    /// claim (or solely dead claims) skips, and no claim — or a live
    /// collision — waits.
    fn attribute_call(
        &self,
        key: JournalDomainKey,
        fingerprint: &CallFingerprint,
        live: &[JournalDomainKey],
    ) -> CallAttribution {
        let mut mine = false;
        let mut sibling = false;
        let mut dead = false;
        if let Some(claimants) = self.claims.get(fingerprint) {
            for (claimant, ordinals) in claimants {
                if ordinals.is_empty() {
                    continue;
                }
                if *claimant == key {
                    mine = true;
                } else if live.contains(claimant) {
                    sibling = true;
                } else {
                    dead = true;
                }
            }
        }
        match (mine, sibling, dead) {
            (true, false, _) => CallAttribution::Mine,
            (false, true, _) | (false, false, true) => CallAttribution::Sibling,
            _ => CallAttribution::Unclaimed,
        }
    }

    /// The plan's seal entry: audit (with a seal-time native fault
    /// re-read), re-verify the birth with fresh Session evidence,
    /// derive the model's fence, then convert staged history at or below
    /// the frontier, then settle. Validation precedes every model
    /// mutation; a model surprise fails closed with the key tainted.
    /// Staged inputs below a refused-but-recoverable seal are kept for
    /// a later seal; fault, malformed and H3 loss fence the void
    /// explicitly and drop staged proof.
    #[cfg(test)]
    pub(crate) fn seal(
        &mut self,
        model: &mut ObjectSemantics,
        audit: &JournalAuditReceipt,
        bootstrap: &BootstrapReceipt,
        frontier: ConsumptionOrdinal,
        births: &mut impl BirthEvidenceSource,
        fault: &impl FaultEpoch,
    ) -> Result<SealSuccess, SealFailure> {
        let requested = self.retained_failure_domain(bootstrap);
        self.seal_inner(model, audit, bootstrap, frontier, births, fault)
            .map_err(|mut failure| {
                if matches!(failure.scope, SealFailureScope::Unqualified)
                    && failure.gap != JournalGap::DrainMismatch
                    && let Some(domain) = requested
                {
                    failure.scope = SealFailureScope::Domain(domain);
                }
                failure
            })
    }

    fn check_collection_owner(&self, audit: &JournalAuditReceipt) -> Result<(), SealFailure> {
        // A foreign/unbound EVENTS stream proves no loss of this adapter.
        // Check before global audit mutation, independently of the requested
        // bootstrap; an actual owned audit can still void owned domains when
        // that requested bootstrap is missing or otherwise invalid.
        if audit
            .drain_domain
            .is_some_and(|drained| !self.drain_pins.values().any(|pinned| *pinned == drained))
        {
            return Err(self.failure(JournalGap::DrainMismatch));
        }
        if self.stopped {
            return Err(self.global_failure(JournalGap::Stopped));
        }
        if self.invalidated {
            return Err(self.global_failure(JournalGap::AdapterInvalidated));
        }
        Ok(())
    }

    /// Adjudicate one owned collection even when no domain is eligible to
    /// seal. Preserve the original affected scope/effects before voiding.
    pub(super) fn audit_collected(
        &mut self,
        model: &mut ObjectSemantics,
        audit: &JournalAuditReceipt,
        fault: &impl FaultEpoch,
    ) -> Result<(), SealFailure> {
        self.check_collection_owner(audit)?;
        let seal_epoch = fault.fault_epoch();
        if let Err(gap) = audit.check(
            self.last_fault,
            self.h3_voided_below,
            self.closure_generation,
            &seal_epoch,
        ) {
            return Err(self.reject_audit(model, audit, gap, seal_epoch));
        }
        // The audit passed: pin the cumulative baseline. Past the first
        // seal this is a no-op (the chain rule already equated them).
        self.last_fault = Some(audit.fault_after);
        Ok(())
    }

    fn reject_audit(
        &mut self,
        model: &mut ObjectSemantics,
        audit: &JournalAuditReceipt,
        gap: JournalGap,
        seal_epoch: Result<u64, FaultReadError>,
    ) -> SealFailure {
        // Any audit failure breaks absence-appearance chains: the clean
        // coverage the witness requires is gone from this ordinal on.
        // Voids fence the loss explicitly before dropping staged
        // truth, so later proof resumes above a fenced interval
        // instead of silently skipping it; the fencing effects are
        // reported with the refusal.
        let scope = match gap {
            JournalGap::H3Pending | JournalGap::ClosureStale => SealFailureScope::Unqualified,
            _ => self.affected_failure_scope(),
        };
        self.last_audit_failure = Some(self.consumed_through);
        let mut effects = ObjectEffects::default();
        let mut h3_voided = None;
        match gap {
            JournalGap::FaultSaturated => {
                self.stopped = true;
            }
            JournalGap::H3Exhausted => {
                // The H0 allocator is dead: no future history can
                // certify, so the adapter stops (invalidating tracked
                // keys) instead of waiting forever.
                effects = self.stop(model);
            }
            JournalGap::FaultChanged
            | JournalGap::FaultUnreadable
            | JournalGap::Malformed
            | JournalGap::CounterUnprovable
            | JournalGap::ResourceUnavailable
            | JournalGap::Discarded
            | JournalGap::H3Loss => {
                // Irreversible refusals first: staged unbounded
                // abandonments refuse their incarnations permanently
                // BEFORE staged custody is dropped, so a void can
                // never erase them into a recoverable fence.
                effects = self.preserve_abandonment_refusals(model);
                effects
                    .effects
                    .extend(self.fence_void(model, self.consumed_through).effects);
                self.void_staged();
                // The voided consumption interval binds future keys too:
                // births naming a cut below it refuse even when their key
                // did not exist at the void.
                self.voided_through = self.voided_through.max(self.consumed_through);
                if gap == JournalGap::H3Loss {
                    // Forgive the voided H0 interval: re-presented
                    // barriers at or below it wait for clean
                    // evidence instead of voiding twice. The void
                    // report acknowledges the consumed barrier to
                    // the finalizer through the joint tick.
                    self.h3_voided_below = self.h3_voided_below.max(audit.h0_below);
                    h3_voided = Some(self.h3_voided_below);
                }
                if gap == JournalGap::FaultChanged {
                    // Re-baseline the cumulative chain on the
                    // freshest observed epoch: the audited close or
                    // the seal-time re-read, whichever is newer.
                    let freshest = audit
                        .fault_after
                        .max(seal_epoch.unwrap_or(audit.fault_after));
                    self.last_fault = Some(freshest);
                }
            }
            JournalGap::H3Pending | JournalGap::ClosureStale => {}
            _ => {}
        }
        SealFailure {
            gap,
            effects,
            h3_voided,
            scope,
        }
    }

    #[cfg(test)]
    fn seal_inner(
        &mut self,
        model: &mut ObjectSemantics,
        audit: &JournalAuditReceipt,
        bootstrap: &BootstrapReceipt,
        frontier: ConsumptionOrdinal,
        births: &mut impl BirthEvidenceSource,
        fault: &impl FaultEpoch,
    ) -> Result<SealSuccess, SealFailure> {
        self.check_collection_owner(audit)?;
        let frontier = frontier.0;
        if frontier > self.consumed_through {
            return Err(self.failure(JournalGap::FrontierRegression));
        }
        self.audit_collected(model, audit, fault)?;
        self.seal_domain_inner(
            model,
            audit,
            bootstrap,
            ConsumptionOrdinal(frontier),
            births,
            None,
        )
    }

    /// Per-domain conversion under the frame's already adjudicated collection.
    /// The opaque input can only be minted by that frame. A fresh fault read
    /// may add a later broad loss; it never takes or re-audits H3/counters.
    fn seal_in_audit(
        &mut self,
        model: &mut ObjectSemantics,
        input: joint_audit::AuditedDomainInput<'_>,
        births: &mut impl BirthEvidenceSource,
        fault: &impl FaultEpoch,
        replay: ReplayPreparation,
    ) -> Result<SealSuccess, SealFailure> {
        let (audit, bootstrap, frontier) = input.into_parts();
        let requested = self.retained_failure_domain(bootstrap);
        let outcome = (|| {
            self.check_collection_owner(audit)?;
            if frontier.0 > self.consumed_through {
                return Err(self.failure(JournalGap::FrontierRegression));
            }
            let reading = fault.fault_epoch();
            let gap = match reading {
                Err(FaultReadError::Saturated) => Some(JournalGap::FaultSaturated),
                Err(FaultReadError::Unreadable) => Some(JournalGap::FaultUnreadable),
                Ok(epoch) if epoch > u64::from(u32::MAX) => Some(JournalGap::FaultSaturated),
                Ok(epoch) if epoch != audit.fault_after => Some(JournalGap::FaultChanged),
                Ok(_) => None,
            };
            if let Some(gap) = gap {
                return Err(self.reject_audit(model, audit, gap, reading));
            }
            self.seal_domain_inner(model, audit, bootstrap, frontier, births, Some(replay))
        })();
        outcome.map_err(|mut failure| {
            if matches!(failure.scope, SealFailureScope::Unqualified)
                && failure.gap != JournalGap::DrainMismatch
                && let Some(domain) = requested
            {
                failure.scope = SealFailureScope::Domain(domain);
            }
            failure
        })
    }

    fn seal_domain_inner(
        &mut self,
        model: &mut ObjectSemantics,
        audit: &JournalAuditReceipt,
        bootstrap: &BootstrapReceipt,
        frontier: ConsumptionOrdinal,
        births: &mut impl BirthEvidenceSource,
        replay: Option<ReplayPreparation>,
    ) -> Result<SealSuccess, SealFailure> {
        let frontier = frontier.0;
        let key = bootstrap.proof().key;
        let Some(state) = self.keys.get(&key) else {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        };
        if state.refused || state.tainted {
            return Err(self.failure(JournalGap::DomainTainted));
        }
        if self.is_tainted((key.cookie, key.exec)) {
            return Err(self.failure(JournalGap::ImageTainted));
        }
        // The collection's drain must be the EVENTS-map identity the
        // Session bound to this proof's native domain: one Session's
        // history never seals under another's key. The binding comes
        // from Session authority before any collection, never from
        // presentation or a caller label. Scripted (test-only) audits
        // carry no drain and skip this binding.
        if let Some(drained) = audit.drain_domain
            && self.drain_pins.get(&key.domain_tag) != Some(&drained)
        {
            return Err(self.failure(JournalGap::DrainMismatch));
        }
        if state.era_ended {
            return Err(self.failure(JournalGap::DomainEnded));
        }
        // Era discipline: the proof carries the live era, or the next era
        // once the live one ended (handled below after the ended check can
        // observe it). Anything else is a mismatched bootstrap.
        if bootstrap.proof().era != state.era {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        // The receipt's own generation must be live: a birth verified
        // under a replaced endpoint set proves nothing under this one.
        if bootstrap.closure_generation() != self.closure_generation {
            return Err(self.failure(JournalGap::ClosureStale));
        }
        if let Some(stream) = bootstrap.grant.stream
            && !self.accepts_birth_cut(&JournalBirthCut {
                binding: stream,
                ordinal: ConsumptionOrdinal(bootstrap.birth_cut()),
            })
        {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        // Pull one fresh birth observation: the seal never receives a
        // reusable evidence value. A failed take refuses (the next tick
        // takes again), exactly like moved native evidence.
        let Ok(fresh) = births.take_birth_evidence() else {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        };
        // Re-verify the birth with fresh Session evidence against
        // current retained truth: moved native evidence or a chain break
        // between attestation and seal still refuses. The fence is the
        // same global-aware fence attestation used, so the two agree.
        let fenced_through = state.void_fence.max(self.voided_through);
        if let Err(refusal) = self.verify_birth(
            &bootstrap.proof(),
            bootstrap.birth(),
            bootstrap.birth_cut(),
            fenced_through,
            &fresh,
            self.closure_generation,
        ) {
            // The receipt generation was checked above, so only taint
            // keeps its own gap here.
            let gap = match refusal {
                BirthRefusal::ImageTainted => JournalGap::ImageTainted,
                _ => JournalGap::BootstrapMismatch,
            };
            return Err(self.failure(gap));
        }
        // The birth cut pins per key-era at first seal: a later seal for
        // the same era must carry the same cut. Rebirth above kept staged
        // history is refused — void first.
        if let Some(pinned) = state.bootstraps.get(&bootstrap.proof().era)
            && *pinned != bootstrap.birth_cut()
        {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        // The birth covers all retained staged history for the key:
        // conversion proves staged begins, so a cut at or above any of
        // them would certify history the birth excludes. A sibling
        // key's staging belongs to its own birth.
        let image = (key.cookie, key.exec);
        let live = self.live_keys_for_image(image);
        if !self.birth_covers_staged(key, &live, image, bootstrap.birth_cut()) {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        if frontier < state.sealed_through {
            return Err(self.failure(JournalGap::FrontierRegression));
        }
        if bootstrap.birth_cut() > frontier {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        // Resumption below the void fence refuses: a fresh birth names
        // the fence it resumes at. At the fence is sound (the fenced
        // interval is explicitly lost, and conversion covers strictly
        // above the cut). The fence covers keys created after the void
        // as well as the keys the void fenced directly.
        if bootstrap.birth_cut() < fenced_through {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        // Unclaimed staged history barriers every seal past it: an
        // entry no bound key can account for is never silently
        // excluded. Only an explicit void drops it.
        if self.has_unbound_staging(frontier) {
            return Err(self.failure(JournalGap::BoundNotReady));
        }
        // With sibling keys, every staged entry for this image needs
        // its attribution: this key's entries convert, a sibling's
        // wait for their own seal, and unclaimed shapes (or live
        // collisions) hold the seal until admission authority names
        // them.
        if !self.attribution_ready(key, &live, frontier) {
            return Err(self.failure(JournalGap::BoundNotReady));
        }
        // A fresh birth (no pinned cut for this era) must ground its
        // authority in new staged history: naming the void fence with
        // an advanced frontier but no convertible begin above the cut
        // certifies nothing, so the seal waits instead of succeeding
        // vacantly. Structural mismatches above keep priority: only a
        // well-formed but history-less resumption waits.
        if !state.bootstraps.contains_key(&bootstrap.proof().era)
            && !self.has_staged_history(key, &live, bootstrap.birth_cut(), frontier)
        {
            return Err(self.failure(JournalGap::BoundNotReady));
        }
        // The model's bootstrap authority is derived, not supplied:
        // strictly above the birth, the last sealed frontier, the void
        // fence and every recorded or pending loss bound. Held calls
        // pinning below those floors make the seal a continuation: it
        // claims no new bootstrap (the model keeps its floor and held
        // calls still apply under it) instead of presenting a fence the
        // model must refuse. Only floors past the frontier wait for more
        // history — a repeated seal at an unchanged frontier never
        // succeeds vacuously. Staged inputs are kept for a later seal.
        // Pending loss bounds: this key's staged bounded abandonments
        // and refused begins with their corroborating returns in the
        // frontier. Calls this seal removes never apply, so they leave
        // the held pin alone. A sibling key's bounds belong to its own
        // fence.
        let mut pending_bounds = Vec::new();
        for entry in self.open.values() {
            if self.abandons_here(key, &live, entry)
                && entry.begin_ordinal <= frontier
                && let Some(staged) = entry.abandon
                && staged.ordinal <= frontier
                && staged.abandon.reason() == JOURNAL_REASON_SYNC_RETURN_RESULT_LOST
                && let Some(at) = entry.corroborated_return
                && at <= frontier
            {
                pending_bounds.push(at);
            }
        }
        for refused in &self.refused {
            if self.refused_converts_here(key, &live, refused)
                && refused.cut <= frontier
                && let Some(at) = refused.corroborated_return
                && at <= frontier
            {
                pending_bounds.push(at);
            }
        }
        let floors = derive_model_floors(
            bootstrap.birth_cut(),
            state.sealed_through,
            state.void_fence,
            state.bounded_upper,
            &pending_bounds,
        )
        .map_err(|gap| self.failure(gap))?;
        // Held pin: the earliest staged begin this seal keeps. Bounded
        // losses removed below contribute their bound instead of their
        // begin; everything else convertible here may still apply. A
        // sibling key's held calls pin its own fence, never this one. A
        // pin below the floors continues without claiming; at or above
        // them the seal claims the floors as new authority.
        let held = self
            .open
            .values()
            .filter(|entry| {
                (self.converts_here(key, &live, entry) || entry.converted_for == Some(key))
                    && !(entry.abandon.is_some_and(|staged| {
                        staged.ordinal <= frontier
                            && staged.abandon.reason() == JOURNAL_REASON_SYNC_RETURN_RESULT_LOST
                            && entry.corroborated_return.is_some_and(|at| at <= frontier)
                    }))
            })
            .map(|entry| entry.begin_ordinal)
            .min();
        if floors > frontier {
            return Err(self.failure(JournalGap::BoundNotReady));
        }
        let fence = match held {
            Some(pinned) if pinned < floors => None,
            _ => Some(floors),
        };
        self.seal_validated(model, key, bootstrap, frontier, fence, audit, replay)
    }

    /// Preserve staged unbounded abandonments across a void: each
    /// one refuses its incarnation permanently (model invalidation
    /// reported) before staged custody is dropped. A sole live key
    /// takes its image's abandonments; with siblings, live claimants
    /// of the abandoned call's fingerprint refuse; an abandonment no
    /// live key can account for taints its image (unknown continuing
    /// effects), as does a keyless one. Either way the void fence
    /// never becomes replacement birth authority over continuing
    /// provider effects.
    fn preserve_abandonment_refusals(&mut self, model: &mut ObjectSemantics) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        let mut doomed: BTreeSet<JournalDomainKey> = BTreeSet::new();
        let mut taint: BTreeSet<(u64, u64)> = BTreeSet::new();
        for entry in self.open.values() {
            if !entry.abandon.is_some_and(|staged| {
                abandon_disposition(staged.abandon.reason())
                    == Some(AbandonDisposition::UnboundedInvalidation)
            }) {
                continue;
            }
            let live = self.live_keys_for_image(entry.image);
            match live.as_slice() {
                [sole] => {
                    doomed.insert(*sole);
                }
                [] if !self.image_keys.contains_key(&entry.image) => {
                    taint.insert(entry.image);
                }
                [] => {}
                _ => {
                    let fingerprint = fingerprint_of_begin(&entry.begin);
                    let claimants: Vec<JournalDomainKey> = self
                        .claims
                        .get(&fingerprint)
                        .map(|m| {
                            m.iter()
                                .filter(|(key, ordinals)| {
                                    !ordinals.is_empty() && live.contains(key)
                                })
                                .map(|(key, _)| *key)
                                .collect()
                        })
                        .unwrap_or_default();
                    if claimants.is_empty() {
                        taint.insert(entry.image);
                    } else {
                        doomed.extend(claimants);
                    }
                }
            }
        }
        for image in taint {
            self.taint_image(image);
        }
        for key in doomed {
            if self.is_tainted((key.cookie, key.exec)) {
                continue;
            }
            let (era, registered) = self
                .keys
                .get(&key)
                .map(|state| (state.era, state.model_registered))
                .expect("doomed key");
            if registered {
                let domain = ObjectDomain::sealed(&JournalDomainProof { key, era });
                let refused = model.abandon_domain(domain, &mut self.ledger);
                effects.effects.extend(refused.effects);
            }
            self.keys.get_mut(&key).expect("doomed key").refused = true;
        }
        effects
    }

    /// Fence one void explicitly: every key's fence rises to the voided
    /// interval's upper cut, and every model-held domain records the
    /// interval as lost. Unregistered keys fence adapter-side only —
    /// their domains hold no model history to fence, and their future
    /// births still resume at or above the fence.
    fn fence_void(&mut self, model: &mut ObjectSemantics, upper: u64) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        let live: Vec<(JournalDomainKey, u64, bool)> = self
            .keys
            .iter()
            .map(|(key, state)| (*key, state.era, state.model_registered))
            .collect();
        for (key, era, registered) in live {
            let state = self.keys.get_mut(&key).expect("fenced key");
            state.void_fence = state.void_fence.max(upper);
            if !registered {
                continue;
            }
            let domain = ObjectDomain::sealed(&JournalDomainProof { key, era });
            let lost = model.outcome_lost(
                super::LostOutcome::Voided(domain, RefCut::sealed(ConsumptionOrdinal(upper))),
                &mut self.ledger,
            );
            effects.effects.extend(lost.effects);
        }
        effects
    }

    /// Whether staged wire truth no bound key can account for sits at
    /// or below a frontier: an open begin or refused begin whose image
    /// was never attested. Such entries barrier every seal past them.
    fn has_unbound_staging(&self, frontier: u64) -> bool {
        self.open.values().any(|entry| {
            entry.converted_ticket.is_none()
                && entry.begin_ordinal <= frontier
                && !self.image_keys.contains_key(&entry.image)
        }) || self
            .refused
            .iter()
            .any(|refused| refused.cut <= frontier && !self.image_keys.contains_key(&refused.image))
    }

    /// Whether every staged entry for one image at or below a frontier
    /// is attributed under a sealing key: this key's entries, a
    /// sibling's (left for their own seal), or solely dead claims. An
    /// unclaimed shape or a live collision holds the seal; multiset
    /// claim counts must cover this key's staged entries — including
    /// under a sole live key.
    fn attribution_ready(
        &self,
        key: JournalDomainKey,
        live: &[JournalDomainKey],
        frontier: u64,
    ) -> bool {
        let image = (key.cookie, key.exec);
        let mut needs: BTreeMap<CallFingerprint, u64> = BTreeMap::new();
        for entry in self.open.values() {
            if entry.image != image
                || entry.converted_ticket.is_some()
                || entry.begin_ordinal > frontier
            {
                continue;
            }
            match self.attribute_call(key, &fingerprint_of_begin(&entry.begin), live) {
                CallAttribution::Mine => {
                    *needs.entry(fingerprint_of_begin(&entry.begin)).or_default() += 1;
                }
                CallAttribution::Sibling => {}
                CallAttribution::Unclaimed => return false,
            }
        }
        for refused in &self.refused {
            if refused.image != image || refused.cut > frontier {
                continue;
            }
            match self.attribute_call(key, &fingerprint_of_refused(refused), live) {
                CallAttribution::Mine => {
                    *needs.entry(fingerprint_of_refused(refused)).or_default() += 1;
                }
                CallAttribution::Sibling => {}
                CallAttribution::Unclaimed => return false,
            }
        }
        needs.into_iter().all(|(fingerprint, need)| {
            self.claims
                .get(&fingerprint)
                .and_then(|claimants| claimants.get(&key))
                .map(|ordinals| ordinals.len() as u64)
                .unwrap_or(0)
                >= need
        })
    }

    fn awaits_future_terminal(
        &self,
        bootstrap: &BootstrapReceipt,
        frontier: ConsumptionOrdinal,
    ) -> bool {
        if self.has_unbound_staging(frontier.0) {
            return false;
        }
        let key = bootstrap.proof().key;
        let live = self.live_keys_for_image((key.cookie, key.exec));
        if self
            .refused
            .iter()
            .any(|entry| entry.image == (key.cookie, key.exec) && entry.cut <= frontier.0)
        {
            return false;
        }
        let mut waiting = false;
        let mut needed = BTreeMap::<CallFingerprint, usize>::new();
        for entry in self.open.values().filter(|entry| {
            entry.image == (key.cookie, key.exec)
                && entry.begin_ordinal <= frontier.0
                && entry.converted_ticket.is_none()
        }) {
            let fingerprint = fingerprint_of_begin(&entry.begin);
            match self.attribute_call(key, &fingerprint, &live) {
                CallAttribution::Sibling => {}
                CallAttribution::Mine => {
                    *needed.entry(fingerprint).or_default() += 1;
                }
                CallAttribution::Unclaimed => {
                    let any_claim = self.claims.get(&fingerprint).is_some_and(|claimants| {
                        claimants.values().any(|claims| !claims.is_empty())
                    });
                    if any_claim
                        || entry.end.is_some()
                        || entry.abandon.is_some()
                        || entry.corroborated_return.is_some()
                    {
                        return false;
                    }
                    waiting = true;
                }
            }
        }
        waiting
            && needed.into_iter().all(|(fingerprint, count)| {
                self.claims
                    .get(&fingerprint)
                    .and_then(|claimants| claimants.get(&key))
                    .is_some_and(|claims| claims.len() >= count)
            })
    }

    /// Whether one staged open entry converts under a sealing key: its
    /// image's, unconverted, and attributed here.
    fn converts_here(
        &self,
        key: JournalDomainKey,
        live: &[JournalDomainKey],
        entry: &OpenEntry,
    ) -> bool {
        entry.image == (key.cookie, key.exec)
            && entry.converted_ticket.is_none()
            && self.attribute_call(key, &fingerprint_of_begin(&entry.begin), live)
                == CallAttribution::Mine
    }

    /// Whether one staged refused begin converts under a sealing key.
    fn refused_converts_here(
        &self,
        key: JournalDomainKey,
        live: &[JournalDomainKey],
        refused: &RefusedBegin,
    ) -> bool {
        refused.image == (key.cookie, key.exec)
            && self.attribute_call(key, &fingerprint_of_refused(refused), live)
                == CallAttribution::Mine
    }

    /// Whether one staged open entry's abandonment disposes under a
    /// sealing key: converting here, or already converted for it. An
    /// abandonment staged on an already-converted call refuses and
    /// disposes exactly like one on a converting call — conversion
    /// never outruns abandonment authority.
    fn abandons_here(
        &self,
        key: JournalDomainKey,
        live: &[JournalDomainKey],
        entry: &OpenEntry,
    ) -> bool {
        self.converts_here(key, live, entry) || entry.converted_for == Some(key)
    }

    /// Whether a birth cut covers all retained staged history for one
    /// key: every convertible-or-converted begin and refused cut sits
    /// strictly above it. A sibling key's staging belongs to its own
    /// birth, and other images are irrelevant to this one.
    fn birth_covers_staged(
        &self,
        key: JournalDomainKey,
        live: &[JournalDomainKey],
        image: (u64, u64),
        birth_cut: u64,
    ) -> bool {
        self.open.values().all(|entry| {
            entry.image != image
                || entry.begin_ordinal > birth_cut
                || !(self.converts_here(key, live, entry) || entry.converted_for == Some(key))
        }) && self.refused.iter().all(|refused| {
            refused.image != image
                || refused.cut > birth_cut
                || !self.refused_converts_here(key, live, refused)
        })
    }

    /// Whether convertible wire truth for one key sits strictly above a
    /// cut at or below a frontier: an open begin or a refused begin
    /// this seal would cover. A fresh birth needs one; an advanced
    /// frontier alone certifies nothing.
    fn has_staged_history(
        &self,
        key: JournalDomainKey,
        live: &[JournalDomainKey],
        birth_cut: u64,
        frontier: u64,
    ) -> bool {
        self.open.values().any(|entry| {
            self.converts_here(key, live, entry)
                && entry.begin_ordinal > birth_cut
                && entry.begin_ordinal <= frontier
        }) || self.refused.iter().any(|refused| {
            self.refused_converts_here(key, live, refused)
                && refused.cut > birth_cut
                && refused.cut <= frontier
        })
    }

    /// Drop all staged wire truth and void every bootstrap after a fault,
    /// malformed record or H3 loss: proof ends, history is retained in the
    /// model, and only a fresh attestation resumes seals. Sightings
    /// survive: consumed history is fact even when its staged
    /// interpretation is void. The void fence (recorded by
    /// [`Self::fence_void`] before this runs) makes the voided interval
    /// explicitly lost, so later proof resumes at or above the fence
    /// instead of silently skipping it.
    fn void_staged(&mut self) {
        self.open.clear();
        self.ledger.release_all_h8open();
        self.refused.clear();
        self.claims.clear();
        self.claim_counts = 0;
        for state in self.keys.values_mut() {
            state.bootstraps.clear();
        }
    }

    fn retained_failure_domain(&self, bootstrap: &BootstrapReceipt) -> Option<ObjectDomain> {
        let proof = bootstrap.proof();
        self.keys
            .get(&proof.key)
            .filter(|state| state.era == proof.era)
            .map(|state| {
                JournalDomainProof {
                    key: proof.key,
                    era: state.era,
                }
                .domain()
            })
    }

    fn affected_failure_scope(&self) -> SealFailureScope {
        // Count bounded by the existing domain-key policy (4096). The
        // requested allocation is capacity * size_of::<ObjectDomain>();
        // the failure releases it on drop. H9's byte envelope remains a
        // separate enforcement carry; a None byte limit is not enforcement.
        let mut domains = Vec::with_capacity(self.keys.len());
        domains.extend(self.keys.iter().map(|(key, state)| {
            JournalDomainProof {
                key: *key,
                era: state.era,
            }
            .domain()
        }));
        SealFailureScope::AffectedDomains(domains)
    }

    fn global_failure(&self, gap: JournalGap) -> SealFailure {
        SealFailure {
            scope: self.affected_failure_scope(),
            ..self.failure(gap)
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted_failure(
        &self,
        gap: JournalGap,
        bootstrap: &BootstrapReceipt,
        effects: ObjectEffects,
    ) -> SealFailure {
        SealFailure {
            scope: self
                .retained_failure_domain(bootstrap)
                .map_or(SealFailureScope::Unqualified, SealFailureScope::Domain),
            effects,
            ..self.failure(gap)
        }
    }

    fn failure(&self, gap: JournalGap) -> SealFailure {
        SealFailure {
            gap,
            effects: ObjectEffects::default(),
            h3_voided: None,
            scope: SealFailureScope::Unqualified,
        }
    }

    /// Conversion and settlement after every structural rule passed. The
    /// only remaining failures are model surprises, which fail closed.
    #[allow(clippy::too_many_arguments)] // One validated domain keeps its original audit and prepaid replay storage.
    fn seal_validated(
        &mut self,
        model: &mut ObjectSemantics,
        key: JournalDomainKey,
        bootstrap: &BootstrapReceipt,
        frontier: u64,
        model_fence: Option<u64>,
        audit: &JournalAuditReceipt,
        replay: Option<ReplayPreparation>,
    ) -> Result<SealSuccess, SealFailure> {
        let image = (key.cookie, key.exec);
        let live = self.live_keys_for_image(image);
        // Unbounded abandonment of this key's calls staged at or below
        // the frontier refuses this key permanently: invalidate its
        // proof (reported), mark it, dispose its staged entries, and
        // refuse the seal. Already-converted calls count: their
        // abandonments refuse and dispose here, never prune silently.
        // A sibling's abandonment belongs to its own seal; unclaimed
        // shapes barriered before conversion.
        let unbounded = self.open.values().any(|entry| {
            self.abandons_here(key, &live, entry)
                && entry.begin_ordinal <= frontier
                && entry.abandon.is_some_and(|staged| {
                    staged.ordinal <= frontier
                        && abandon_disposition(staged.abandon.reason())
                            == Some(AbandonDisposition::UnboundedInvalidation)
                })
        });
        if unbounded {
            let domain = ObjectDomain::sealed(&bootstrap.proof());
            let effects = model.abandon_domain(domain, &mut self.ledger);
            self.keys.get_mut(&key).expect("sealed key").refused = true;
            let drop: BTreeSet<JournalNativeKey> = self
                .open
                .iter()
                .filter(|(_, entry)| {
                    entry.image == image
                        && (self.converts_here(key, &live, entry)
                            || entry.converted_for == Some(key))
                })
                .map(|(native, _)| *native)
                .collect();
            self.remove_open_where(|native, _| drop.contains(native));
            let mut kept = Vec::with_capacity(self.refused.len());
            for refused in self.refused.iter() {
                if !self.refused_converts_here(key, &live, refused) {
                    kept.push(*refused);
                }
            }
            self.refused = kept;
            return Err(SealFailure {
                gap: JournalGap::DomainTainted,
                effects,
                h3_voided: None,
                scope: SealFailureScope::Unqualified,
            });
        }
        // This key's bounded abandonments need their corroborating
        // returns within the frontier; otherwise the bound is not ready
        // and the seal waits. Already-converted calls wait here too,
        // instead of tainting as a model surprise below.
        let unready = self.open.values().any(|entry| {
            self.abandons_here(key, &live, entry)
                && entry.begin_ordinal <= frontier
                && entry.abandon.is_some_and(|staged| {
                    staged.ordinal <= frontier
                        && staged.abandon.reason() == JOURNAL_REASON_SYNC_RETURN_RESULT_LOST
                        && entry.corroborated_return.is_none_or(|at| at > frontier)
                })
        });
        if unready {
            return Err(self.failure(JournalGap::BoundNotReady));
        }
        // Every refused begin of this key at or below the frontier needs
        // its bound within the frontier; otherwise the seal waits.
        let refused_unready = self.refused.iter().any(|refused| {
            self.refused_converts_here(key, &live, refused)
                && refused.cut <= frontier
                && refused.corroborated_return.is_none_or(|at| at > frontier)
        });
        if refused_unready {
            return Err(self.failure(JournalGap::BoundNotReady));
        }
        self.validate_invocation_claims(key, &live, frontier, audit)?;
        self.convert_and_settle(model, key, bootstrap, frontier, model_fence, replay)
    }

    fn validate_invocation_claims(
        &mut self,
        key: JournalDomainKey,
        live: &[JournalDomainKey],
        frontier: u64,
        audit: &JournalAuditReceipt,
    ) -> Result<(), SealFailure> {
        let mut candidates: BTreeMap<
            CallFingerprint,
            (usize, Option<p11scope_ebpf_common::Event>),
        > = BTreeMap::new();
        for entry in self.open.values() {
            if entry.begin_ordinal <= frontier && self.converts_here(key, live, entry) {
                let value = candidates
                    .entry(fingerprint_of_begin(&entry.begin))
                    .or_default();
                value.0 += 1;
                value.1 = entry
                    .end
                    .filter(|end| end.ordinal <= frontier)
                    .map(|end| end.end.payload_base().event);
            }
        }
        for entry in &self.refused {
            if entry.cut <= frontier && self.refused_converts_here(key, live, entry) {
                candidates
                    .entry(fingerprint_of_refused(entry))
                    .or_default()
                    .0 += 1;
            }
        }
        for (fingerprint, (_, end)) in candidates {
            let count = self
                .open
                .values()
                .filter(|entry| fingerprint_of_begin(&entry.begin) == fingerprint)
                .count()
                + self
                    .refused
                    .iter()
                    .filter(|entry| fingerprint_of_refused(entry) == fingerprint)
                    .count();
            let claims = &self.claims[&fingerprint][&key];
            if count != 1 || claims.len() != 1 {
                // Do not let pruning/void turn this ambiguity into a later
                // singleton winner. Taint preserves every claim unconsumed.
                self.taint_image(fingerprint.image);
                return Err(self.failure(JournalGap::ImageTainted));
            }
            let claim = claims.front().expect("one exact claim");
            // Only the loss-audited ordered prefix may make this
            // physical return irreversible. Zero H0 watermarks exist
            // solely in the explicitly scripted algorithm audit factory.
            let covered = match audit.h3 {
                H3DispositionEvidence::Clean {
                    staged_max,
                    pending_floor,
                } => {
                    staged_max >= claim.admission
                        && pending_floor.is_none_or(|floor| floor > claim.admission)
                        && (audit.h0_below == 0 || claim.admission < audit.h0_below)
                }
                _ => false,
            };
            if !covered {
                return Err(self.failure(JournalGap::H3Pending));
            }
            if let Some(end) = end
                && (end.duration_ns == 0
                    || end.ts_ns.checked_sub(end.duration_ns) != Some(fingerprint.entry_ns)
                    || end.ts_ns != claim.return_ns)
            {
                return Err(self.failure(JournalGap::H3Pending));
            }
        }
        Ok(())
    }

    /// Register, convert (refused, begins, terminals, abandonments),
    /// settle, prune. Infallible by construction; a model surprise taints
    /// the key and fails the seal closed.
    fn convert_and_settle(
        &mut self,
        model: &mut ObjectSemantics,
        key: JournalDomainKey,
        bootstrap: &BootstrapReceipt,
        frontier: u64,
        model_fence: Option<u64>,
        mut replay: Option<ReplayPreparation>,
    ) -> Result<SealSuccess, SealFailure> {
        let image = (key.cookie, key.exec);
        let live = self.live_keys_for_image(image);
        let domain = ObjectDomain::sealed(&bootstrap.proof());
        let mut effects = ObjectEffects::default();
        if model.register_domain(domain).is_err() {
            self.keys.get_mut(&key).expect("sealed key").tainted = true;
            return Err(SealFailure {
                gap: JournalGap::ModelRefused,
                effects,
                h3_voided: None,
                scope: SealFailureScope::Unqualified,
            });
        }
        self.keys
            .get_mut(&key)
            .expect("sealed key")
            .model_registered = true;
        // This key's refused begins first: the model records each cut
        // exactly like its own capacity refusal, then a single
        // lost-outcome bound clears them once every refused begin is
        // corroborated. Conversion consumes one claim count per
        // refused begin; a sibling's refusals stay staged.
        let mut refused_cuts: Vec<u64> = self
            .refused
            .iter()
            .filter(|refused| {
                refused.cut <= frontier && self.refused_converts_here(key, &live, refused)
            })
            .map(|refused| refused.cut)
            .collect();
        refused_cuts.sort_unstable();
        for cut in &refused_cuts {
            let start = effects.effects.len();
            let refused_effects = model.note_refused_begin(
                domain,
                RefCut::sealed(ConsumptionOrdinal(*cut)),
                &mut self.ledger,
            );
            effects.effects.extend(refused_effects.effects);
            if let Some(replay) = &mut replay {
                replay.conversion(*cut, start..effects.effects.len());
            }
        }
        if !refused_cuts.is_empty() {
            let upper = self
                .refused
                .iter()
                .filter(|refused| {
                    refused.cut <= frontier && self.refused_converts_here(key, &live, refused)
                })
                .filter_map(|refused| refused.corroborated_return)
                .max();
            match upper {
                Some(upper) => {
                    let start = effects.effects.len();
                    let lost = model.outcome_lost(
                        super::LostOutcome::Refused(
                            domain,
                            RefCut::sealed(ConsumptionOrdinal(upper)),
                        ),
                        &mut self.ledger,
                    );
                    effects.effects.extend(lost.effects);
                    if let Some(replay) = &mut replay {
                        replay.conversion(upper, start..effects.effects.len());
                    }
                    // The model fences this upper too; the adapter keeps
                    // the running maximum so the bootstrap rule stays
                    // sufficient on its own evidence.
                    let retained = self.keys.get_mut(&key).expect("sealed key");
                    retained.bounded_upper =
                        Some(retained.bounded_upper.map_or(upper, |kept| kept.max(upper)));
                }
                None => {
                    self.keys.get_mut(&key).expect("sealed key").tainted = true;
                    return Err(SealFailure {
                        gap: JournalGap::ModelRefused,
                        effects,
                        h3_voided: None,
                        scope: SealFailureScope::Unqualified,
                    });
                }
            }
            let mut consumed = Vec::new();
            let mut kept = Vec::with_capacity(self.refused.len());
            for refused in self.refused.iter() {
                if refused.cut <= frontier && self.refused_converts_here(key, &live, refused) {
                    consumed.push(fingerprint_of_refused(refused));
                } else {
                    kept.push(*refused);
                }
            }
            self.refused = kept;
            for fingerprint in &consumed {
                self.consume_claim(fingerprint, key);
            }
        }
        // This key's begins in cut order, then their terminals. A
        // sibling's begins stay staged for their own seal.
        let mut begins: Vec<(JournalNativeKey, u64)> = self
            .open
            .iter()
            .filter(|(_, entry)| {
                entry.begin_ordinal <= frontier && self.converts_here(key, &live, entry)
            })
            .map(|(key, entry)| (*key, entry.begin_ordinal))
            .collect();
        begins.sort_by_key(|(_, ordinal)| *ordinal);
        let mut settled = replay
            .as_mut()
            .map_or_else(Vec::new, ReplayPreparation::take_calls);
        for (native, _) in begins {
            let entry = *self.open.get(&native).expect("staged begin");
            // The exact physical invocation has one qualified H0
            // claim. Whole-quantum validation preceded any refusal
            // burn/model mutation; no FIFO/rank inference assigns it.
            // A missing claim is an invariant refusal, never a ticket
            // minted from another invocation.
            let fingerprint = fingerprint_of_begin(&entry.begin);
            let Some(claim) = self.peek_claim(&fingerprint, key) else {
                self.keys.get_mut(&key).expect("sealed key").tainted = true;
                return Err(SealFailure {
                    gap: JournalGap::ModelRefused,
                    effects,
                    h3_voided: None,
                    scope: SealFailureScope::Unqualified,
                });
            };
            let ticket = JournalTicket(claim.admission);
            let origin = origin_of(domain, entry.begin_ordinal, ticket, &entry.begin);
            let function = entry.function;
            let call_key = CallKey::sealed(ticket);
            // C2 already established attribution above. The pending model
            // copy adds its own physical charge to this exact retained H8
            // operation. Keep the OpenEntry's charge until actual removal.
            let Some(resource) = self.ledger.h8_reservation(entry.begin_ordinal) else {
                return Err(SealFailure {
                    gap: JournalGap::ResourceUnavailable,
                    effects,
                    h3_voided: None,
                    scope: SealFailureScope::Unqualified,
                });
            };
            let start = effects.effects.len();
            let (admitted, begin_effects) =
                model.begin_with_resource(origin, &mut self.ledger, &resource);
            effects.effects.extend(begin_effects.effects);
            if let Some(replay) = &mut replay {
                replay.conversion(entry.begin_ordinal, start..effects.effects.len());
            }
            match admitted {
                Ok(token) => {
                    let popped = self.consume_claim(&fingerprint, key);
                    debug_assert_eq!(popped, Some(claim));
                    let (session, mechanism) = sealed_fingerprint(&entry.begin);
                    let entry = self.open.get_mut(&native).expect("staged begin");
                    entry.converted_ticket = Some(token);
                    entry.converted_for = Some(key);
                    entry.call_key = Some(call_key);
                    settled.push(SealedCall {
                        ticket: token,
                        key: call_key,
                        function,
                        begin_cut: entry.begin_ordinal,
                        end_cut: None,
                        abandoned: false,
                        session,
                        mechanism,
                    });
                }
                Err(_) => {
                    self.keys.get_mut(&key).expect("sealed key").tainted = true;
                    // The unconverted OpenEntry still owns its original
                    // role/charge; refusal never erased or recreated it.
                    return Err(SealFailure {
                        gap: JournalGap::ModelRefused,
                        effects,
                        h3_voided: None,
                        scope: SealFailureScope::Unqualified,
                    });
                }
            }
        }
        // Populate the same current delta before terminal actions, while
        // every converted original still exists. Newly converted BEGINs are
        // already begin-ordered; search only that unchanged prefix, then append
        // older fresh terminals once. This avoids a scan per terminal.
        let converted_begins = settled.len();
        for entry in self
            .open
            .values()
            .filter(|entry| entry.converted_for == Some(key))
        {
            let end = entry
                .end
                .filter(|staged| staged.ordinal <= frontier && !entry.end_converted);
            let abandoned = entry.abandon.is_some_and(|staged| {
                staged.ordinal <= frontier
                    && staged.abandon.reason() == JOURNAL_REASON_SYNC_RETURN_RESULT_LOST
            });
            if end.is_none() && !abandoned {
                continue;
            }
            if let Ok(index) = settled[..converted_begins]
                .binary_search_by_key(&entry.begin_ordinal, |summary| summary.begin_cut)
            {
                settled[index].end_cut = end.map(|staged| staged.ordinal);
                settled[index].abandoned = abandoned;
            } else {
                let (session, mechanism) = sealed_fingerprint(&entry.begin);
                settled.push(SealedCall {
                    ticket: entry.converted_ticket.expect("converted original"),
                    key: entry.call_key.expect("converted original key"),
                    function: entry.function,
                    begin_cut: entry.begin_ordinal,
                    end_cut: end.map(|staged| staged.ordinal),
                    abandoned,
                    session,
                    mechanism,
                });
            }
        }
        // Terminal deltas append after this seal's conversions; restore
        // the begin-cut order the prefix promises H9.
        settled.sort_unstable_by_key(|summary| summary.begin_cut);
        let settled_len = settled.len();
        if let Some(replay) = &mut replay {
            let retained = self
                .open
                .values()
                .filter(|entry| entry.converted_for == Some(key))
                .map(|entry| {
                    let (session, mechanism) = sealed_fingerprint(&entry.begin);
                    SealedCall {
                        ticket: entry.converted_ticket.expect("converted original"),
                        key: entry.call_key.expect("converted original key"),
                        function: entry.function,
                        begin_cut: entry.begin_ordinal,
                        end_cut: entry
                            .end
                            .filter(|staged| staged.ordinal <= frontier)
                            .map(|staged| staged.ordinal),
                        abandoned: entry
                            .abandon
                            .is_some_and(|staged| staged.ordinal <= frontier),
                        session,
                        mechanism,
                    }
                });
            if !replay.freeze_calls(&mut settled, retained) {
                return Err(SealFailure {
                    effects,
                    ..self.failure(JournalGap::ModelRefused)
                });
            }
        }
        // Table metadata is now stable. Only the actual actions below and
        // actual settlement can mint End/BoundedLoss step permissions.
        // Terminals for this key's converted begins: ends complete,
        // bounded abandonments dispose through the lost-outcome bound.
        // A sibling's converted terminals belong to its own seal.
        let mut terminals: Vec<(JournalNativeKey, u64)> = Vec::new();
        for (native, entry) in &self.open {
            if entry.converted_for != Some(key) {
                continue;
            }
            if let Some(staged) = entry.end
                && staged.ordinal <= frontier
            {
                terminals.push((*native, staged.ordinal));
            }
            if let Some(staged) = entry.abandon
                && staged.ordinal <= frontier
            {
                terminals.push((*native, staged.ordinal));
            }
        }
        terminals.sort_by_key(|(_, ordinal)| *ordinal);
        for (native, _) in terminals {
            let entry = *self.open.get(&native).expect("staged terminal");
            let token = entry.converted_ticket.expect("converted begin");
            if let Some(staged) = entry.end
                && staged.ordinal <= frontier
                && !entry.end_converted
            {
                let completed = completed_of(staged.ordinal, entry.function, &staged.end);
                let start = effects.effects.len();
                let applied = model.complete(token, completed, &mut self.ledger);
                effects.effects.extend(applied.effects);
                if let Some(replay) = &mut replay {
                    replay.conversion(staged.ordinal, start..effects.effects.len());
                }
                self.open
                    .get_mut(&native)
                    .expect("staged terminal")
                    .end_converted = true;
            }
            if let Some(staged) = entry.abandon
                && staged.ordinal <= frontier
                && staged.abandon.reason() == JOURNAL_REASON_SYNC_RETURN_RESULT_LOST
            {
                let Some(at) = entry.corroborated_return else {
                    self.keys.get_mut(&key).expect("sealed key").tainted = true;
                    return Err(SealFailure {
                        gap: JournalGap::ModelRefused,
                        effects,
                        h3_voided: None,
                        scope: SealFailureScope::Unqualified,
                    });
                };
                let start = effects.effects.len();
                let lost = model.outcome_lost(
                    super::LostOutcome::Ticket(token, RefCut::sealed(ConsumptionOrdinal(at))),
                    &mut self.ledger,
                );
                effects.effects.extend(lost.effects);
                if let Some(replay) = &mut replay {
                    replay.bounded_loss(
                        entry.call_key.expect("converted loss subject"),
                        token,
                        at,
                        start..effects.effects.len(),
                    );
                }
                let retained = self.keys.get_mut(&key).expect("sealed key");
                retained.bounded_upper =
                    Some(retained.bounded_upper.map_or(at, |kept| kept.max(at)));
            }
        }
        // Settle the covered history under this bootstrap. The open
        // list is cumulative over this key's converted entries,
        // mirroring the model's rule exactly: converted calls with no
        // terminal at or below the frontier. A per-seal list would omit
        // calls held across seals and contradict the settlement; a
        // sibling's opens belong to its own prefix.
        let open: Vec<CallKey> = self
            .open
            .values()
            .filter(|entry| {
                entry.converted_for == Some(key)
                    && entry.end.is_none_or(|staged| staged.ordinal > frontier)
                    && entry.abandon.is_none_or(|staged| staged.ordinal > frontier)
            })
            .map(|entry| entry.call_key.expect("converted open has a key"))
            .collect();
        let mut prefix = SealedObjectPrefix {
            domain,
            frontier,
            birth_cut: bootstrap.birth_cut(),
            bootstrap: model_fence,
            settled,
            settled_len,
            replay_steps: Vec::new(),
            replay_index: None,
            open,
        };
        let offset = effects.effects.len();
        let applied = match &mut replay {
            Some(replay) => model.settle_recorded(
                CompleteInputPrefix::sealed(&prefix),
                &mut self.ledger,
                &mut |transition, span| replay.settlement(transition, span, offset),
            ),
            None => model.settle(CompleteInputPrefix::sealed(&prefix), &mut self.ledger),
        };
        let ended = applied.effects.iter().any(|effect| {
            matches!(
                effect,
                ObjectEffect::Gap {
                    reason: ObjectGap::DomainEnded
                }
            )
        });
        // A seal whose required authority the model rejected is refused,
        // never succeeded-with-rejection: no frontier advance, no pin,
        // no pruning. The key is not tainted — staged inputs stay for a
        // later seal once authority clears (new history can raise the
        // floors past a moved model floor).
        let rejected = applied.effects.iter().any(|effect| {
            matches!(
                effect,
                ObjectEffect::Gap {
                    reason: ObjectGap::BootstrapRefused | ObjectGap::PrefixContradiction
                }
            )
        });
        effects.effects.extend(applied.effects);
        if ended {
            self.keys.get_mut(&key).expect("sealed key").era_ended = true;
            return Err(SealFailure {
                gap: JournalGap::DomainEnded,
                effects,
                h3_voided: None,
                scope: SealFailureScope::Unqualified,
            });
        }
        if rejected {
            return Err(SealFailure {
                gap: JournalGap::ModelRefused,
                effects,
                h3_voided: None,
                scope: SealFailureScope::Unqualified,
            });
        }
        if let Some(replay) = replay {
            let Some((steps, index)) = replay.finish(effects.effects.len()) else {
                return Err(SealFailure {
                    effects,
                    ..self.failure(JournalGap::ModelRefused)
                });
            };
            prefix.replay_steps = steps;
            prefix.replay_index = Some(index);
        }
        debug_assert!(prefix.settled_len <= prefix.settled.len());
        self.keys.get_mut(&key).expect("sealed key").sealed_through = frontier;
        self.keys
            .get_mut(&key)
            .expect("sealed key")
            .bootstraps
            .insert(bootstrap.proof().era, bootstrap.birth_cut());
        self.prune_settled(key, frontier);
        Ok(SealSuccess { prefix, effects })
    }

    /// Drop this key's staged entries the settlement applied:
    /// completed ends at or below the watermark (the model's own rule,
    /// mirrored on identical staged data), bounded abandonments the
    /// lost-outcome bound removed, and converted begins the model
    /// pruned. A sibling key's staging is never pruned here; staged
    /// inputs above the watermark stay for the next seal.
    fn prune_settled(&mut self, key: JournalDomainKey, frontier: u64) {
        let earliest_open = self
            .open
            .values()
            .filter(|entry| {
                entry.converted_for == Some(key)
                    && entry.end.is_none_or(|staged| staged.ordinal > frontier)
                    && entry.abandon.is_none()
            })
            .map(|entry| entry.begin_ordinal)
            .min();
        let watermark = match earliest_open {
            Some(0) => None,
            Some(begin) => Some(frontier.min(begin - 1)),
            None => Some(frontier),
        };
        let Some(watermark) = watermark else {
            return;
        };
        self.remove_open_where(|_, entry| {
            if entry.converted_for != Some(key) {
                return false;
            }
            entry
                .abandon
                .is_some_and(|staged| staged.ordinal <= frontier)
                || entry.end.is_some_and(|staged| staged.ordinal <= watermark)
        });
    }

    /// Collect one quantum over the Session's retained drain: every
    /// consumed record, journal or ordinary, takes the next checked
    /// ordinal in delivery order through the one dispatch poll, with the
    /// checked fault read before and after and the drain's malformed
    /// and discard deltas. The collection's drain domain is read from
    /// the drain itself and CHECKED against the Session binding (an
    /// unbound drain consumes nothing, even presented first; the seal
    /// refuses foreign-drain audits per key), and H0's post-quantum
    /// allocation watermark rides along for H3 coverage. Collection
    /// stages wire truth only; the seal audits this evidence before
    /// any model input. Collection never pins: only
    /// [`JournalAdapter::bind_session_drain`] establishes bindings.
    ///
    /// DISCARD observability: the patched Aya reader counts consumed
    /// kernel-discarded reservations (see the ring-reader patch: both
    /// `next` and `next_before` funnel discards through the counting
    /// consume), and this collection audits the per-collection delta.
    /// A spanned discard voids the seal directly; the fault invariant
    /// (every discarded journal reservation raises the checked fault
    /// before discard; native contract, activation-gated) stays as
    /// defense in depth behind it.
    pub(crate) fn collect_from_drain<S: crate::events::RecordSource>(
        &mut self,
        drain: &mut crate::events::EventDrain<S>,
        descriptors: &[p11scope_ebpf_common::object_wire::ObjectDescriptorWire;
             MAX_DESCRIPTORS as usize],
        quantum: Option<usize>,
        fault: &impl FaultEpoch,
        h0_allocated_below: u64,
    ) -> JournalCollection {
        // Session-bound authority: the drain's EVENTS-map identity
        // must be bound to an attested domain before this collection;
        // an unbound drain consumes nothing (its audit refuses at
        // seal), even when presented first. Collection checks the
        // binding but never establishes it. No caller label names the
        // domain.
        let drain_domain = drain.domain_id();
        if !self
            .drain_pins
            .values()
            .any(|pinned| *pinned == drain_domain)
        {
            // A refused collect still reports its fault read honestly:
            // an unreadable cell voids at seal like any other tick.
            let (fault_before, fault_error) = match fault.fault_epoch() {
                Ok(epoch) => (epoch, None),
                Err(error) => (0, Some(error)),
            };
            return JournalCollection {
                ingested: 0,
                ordinary: 0,
                malformed_delta: 0,
                discarded_delta: 0,
                counter_error: false,
                resource_refused: false,
                fault_before,
                fault_after: fault_before,
                fault_error,
                drain_domain,
                h0_allocated_below,
            };
        }
        let fault_before = match fault.fault_epoch() {
            Ok(epoch) => epoch,
            Err(error) => {
                return JournalCollection {
                    ingested: 0,
                    ordinary: 0,
                    malformed_delta: 0,
                    discarded_delta: 0,
                    counter_error: false,
                    resource_refused: false,
                    fault_before: 0,
                    fault_after: 0,
                    fault_error: Some(error),
                    drain_domain,
                    h0_allocated_below,
                };
            }
        };
        let malformed_before = drain.malformed();
        let discarded_before = drain.discarded();
        // One ordered staging vec shared by both consumers: delivery
        // order is ordinal order across forms.
        let staged = std::cell::RefCell::new(Vec::new());
        drain.poll_dispatched_records(
            quantum,
            descriptors,
            |decoded| {
                staged
                    .borrow_mut()
                    .push(JournalIngestItem::Ordinary(decoded));
                std::ops::ControlFlow::Continue(())
            },
            |record| {
                staged.borrow_mut().push(JournalIngestItem::Journal(record));
                std::ops::ControlFlow::Continue(())
            },
        );
        let mut ingested = 0;
        let mut ordinary = 0;
        for item in staged.take() {
            match item {
                JournalIngestItem::Journal(_) => ingested += 1,
                JournalIngestItem::Ordinary(_) => ordinary += 1,
            }
            self.ingest_any(item);
        }
        let (fault_after, fault_error) = match fault.fault_epoch() {
            Ok(epoch) => (epoch, None),
            Err(error) => (fault_before, Some(error)),
        };
        // The production joint tick passes H0's post-quantum allocation
        // counter (never zero: the counter starts at one). A zero
        // watermark is the test-only joint-quantum fiction: H0 minted
        // exactly the consumed records, in order.
        let h0_allocated_below = if h0_allocated_below == 0 {
            self.consumed_through + 1
        } else {
            h0_allocated_below
        };
        JournalCollection {
            ingested,
            ordinary,
            malformed_delta: drain.malformed().saturating_sub(malformed_before),
            discarded_delta: drain.discarded().saturating_sub(discarded_before),
            counter_error: false,
            resource_refused: false,
            fault_before,
            fault_after,
            fault_error,
            drain_domain,
            h0_allocated_below,
        }
    }

    /// Stop: refuse all future ingest, seals and attestations; invalidate
    /// every key with tracked (converted-but-unsettled) calls and refuse
    /// those incarnations permanently. Quiet keys keep their sealed
    /// history but seal nothing further. Late provider effects after stop
    /// meet a refused incarnation, never a rebootstrap.
    pub(crate) fn stop(&mut self, model: &mut ObjectSemantics) -> ObjectEffects {
        self.stopped = true;
        let mut effects = ObjectEffects::default();
        let keys: Vec<JournalDomainKey> = self.keys.keys().copied().collect();
        for key in keys {
            let live = self.live_keys_for_image((key.cookie, key.exec));
            let tracked = self
                .open
                .values()
                .any(|entry| entry.converted_for == Some(key))
                || self
                    .refused
                    .iter()
                    .any(|refused| self.refused_converts_here(key, &live, refused));
            if !tracked {
                continue;
            }
            let era = self.keys[&key].era;
            let domain = ObjectDomain::sealed(&JournalDomainProof { key, era });
            let applied = model.abandon_domain(domain, &mut self.ledger);
            effects.effects.extend(applied.effects);
            self.keys.get_mut(&key).expect("stopped key").refused = true;
        }
        self.open.clear();
        self.ledger.release_all_h8open();
        self.refused.clear();
        effects
    }
}

/// Legacy single-domain algorithm driver. It remains only under cfg(test)
/// for existing wire/model controls. Production collection, audit, all-domain
/// delivery and delayed acknowledgement require the owned joint audit frame.
#[cfg(test)]
#[allow(dead_code)] // Legacy algorithm driver; production requires the owned audit frame.
pub(crate) struct JointSealTick<'a, S, F, H> {
    adapter: &'a mut JournalAdapter,
    model: &'a mut ObjectSemantics,
    drain: &'a mut crate::events::EventDrain<S>,
    descriptors:
        &'a [p11scope_ebpf_common::object_wire::ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
    fault: &'a F,
    finalizer: &'a mut H,
    attachment: &'a crate::attach::AttachedSemanticSet,
    producers: &'a crate::attach::SessionDrainProducers,
}

#[cfg(test)]
#[allow(dead_code)] // As above.
impl<'a, S, F, H> JointSealTick<'a, S, F, H>
where
    S: crate::events::RecordSource,
    F: FaultEpoch,
    H: H3FinalizerPort,
{
    /// Wire one Session's journal quantum: its adapter, model, retained
    /// drain, frozen descriptors, fault cell, H3 finalizer, sealed
    /// attachment (the closure generation's observed source) and
    /// retained drain producers (the grant's observed source).
    #[allow(clippy::too_many_arguments)] // Every quantum producer is injected, none supplied.
    pub(crate) fn wire(
        adapter: &'a mut JournalAdapter,
        model: &'a mut ObjectSemantics,
        drain: &'a mut crate::events::EventDrain<S>,
        descriptors: &'a [p11scope_ebpf_common::object_wire::ObjectDescriptorWire;
                MAX_DESCRIPTORS as usize],
        fault: &'a F,
        finalizer: &'a mut H,
        attachment: &'a crate::attach::AttachedSemanticSet,
        producers: &'a crate::attach::SessionDrainProducers,
    ) -> Self {
        Self {
            adapter,
            model,
            drain,
            descriptors,
            fault,
            finalizer,
            attachment,
            producers,
        }
    }

    /// One joint quantum: install the observed closure, mint and bind
    /// the Session drain grant, collect, take, audit, seal (pulling
    /// one fresh birth observation), then forward the seal's void
    /// report (if any) to the finalizer before returning. The closure
    /// generation is observed from the sealed attachment for both the
    /// install and the audit — never supplied. `admitted` is the
    /// Session loop's H3-admitted call for this quantum: the grant
    /// mints from the retained producers plus this admission, so a
    /// foreign admission refuses the quantum before anything is
    /// collected. `h0_allocated_below` is H0's post-quantum allocation
    /// counter (production; tests pass the joint-quantum fiction 0).
    pub(crate) fn tick(
        &mut self,
        quantum: Option<usize>,
        h0_allocated_below: u64,
        bootstrap: &BootstrapReceipt,
        admitted: &AdmittedInstanceCall,
        births: &mut impl BirthEvidenceSource,
    ) -> Result<SealSuccess, SealFailure> {
        let observed = self.attachment.generation();
        let _ = self
            .adapter
            .install_closure_grant(&SessionClosureGrant::observe(self.attachment));
        // The joint-tick mint: the grant mints from the Session's
        // retained producers plus this quantum's admission, and binds
        // before the first collection. A foreign admission, an
        // unattested domain, or a conflicting rebind refuses the
        // quantum here — one Session's history never collects, let
        // alone seals, under another's key.
        let grant = match SessionDrainGrant::observe(self.producers, admitted) {
            Ok(grant) => grant,
            Err(_) => return Err(self.adapter.failure(JournalGap::DrainMismatch)),
        };
        if self.adapter.bind_session_drain(&grant).is_err() {
            return Err(self.adapter.failure(JournalGap::DrainMismatch));
        }
        let collection = self.adapter.collect_from_drain(
            self.drain,
            self.descriptors,
            quantum,
            self.fault,
            h0_allocated_below,
        );
        self.seal_collection(collection, observed, bootstrap, births)
    }

    /// Seal the SAME previously collected quantum after genuine H0/H3
    /// disposition. This path never polls EVENTS, accepts no scalar H0
    /// watermark and leaves a pending/foreign quantum owned by the caller.
    pub(crate) fn tick_collected(
        &mut self,
        retained: &mut Option<joint_driver::RawJointQuantum>,
        bootstrap: &BootstrapReceipt,
        admitted: &AdmittedInstanceCall,
        births: &mut impl BirthEvidenceSource,
    ) -> Result<SealSuccess, SealFailure> {
        let Some(raw) = retained.as_ref() else {
            return Err(self.adapter.failure(JournalGap::BoundNotReady));
        };
        if let Err(refusal) = raw.ready_for_ingest(self.adapter, self.producers) {
            let gap = if refusal == joint_driver::RawQuantumRefusal::H0Undelivered {
                JournalGap::H3Pending
            } else {
                JournalGap::DrainMismatch
            };
            return Err(self.adapter.failure(gap));
        }
        let grant = SessionDrainGrant::observe(self.producers, admitted)
            .map_err(|_| self.adapter.failure(JournalGap::DrainMismatch))?;
        self.adapter
            .bind_session_drain(&grant)
            .map_err(|_| self.adapter.failure(JournalGap::DrainMismatch))?;
        let observed = self.attachment.generation();
        let _ = self
            .adapter
            .install_closure_grant(&SessionClosureGrant::observe(self.attachment));
        let raw = retained.take().expect("checked retained quantum");
        let collection = match raw.ingest(self.adapter, self.producers, &grant) {
            Ok(collection) => collection,
            Err((raw, _)) => {
                *retained = Some(raw);
                return Err(self.adapter.failure(JournalGap::DrainMismatch));
            }
        };
        self.seal_collection(collection.into_collection(), observed, bootstrap, births)
    }

    fn seal_collection(
        &mut self,
        collection: JournalCollection,
        observed: u64,
        bootstrap: &BootstrapReceipt,
        births: &mut impl BirthEvidenceSource,
    ) -> Result<SealSuccess, SealFailure> {
        let audit = JournalAuditReceipt::collect(&collection, self.finalizer, observed);
        let frontier = self.adapter.consumed_frontier();
        let outcome = self
            .adapter
            .seal(self.model, &audit, bootstrap, frontier, births, self.fault);
        if let Err(failure) = &outcome
            && let Some(voided) = failure.h3_voided
        {
            self.finalizer.acknowledge_h3_void(H3VoidAcknowledgement {
                producers: self.producers.clone(),
                voided_below: voided,
            });
        }
        outcome
    }
}

/// Test-only authority drivers, shared with H9's production-minter
/// tests (`key_operation_tests`): real admissions, real wire records,
/// real attest/ingest/seal. Only the marked support items are
/// reachable; `#[test]` fns stay private. No production impact: the
/// module vanishes outside `cfg(test)`.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::ModuleKey;
    use crate::discovery::caller_registry::instance_input::{
        AdmittedInstanceCall, CallEvidence, CallStanding, InstanceReason, admit_call_from_evidence,
    };
    use crate::discovery::instances::{
        CallFacts, EntryIp, EpochReading, InstanceId, InstanceRouter, MapRange, Route,
        RouterLimits, StableObservation,
    };
    use crate::inventory_semantics::AttestedSubset;
    use crate::semantic_capture::{Endpoint, RoutedCall};
    use p11scope_ebpf_common::instance::STAMP_VALID;
    use p11scope_ebpf_common::object_journal::decode_journal_record;
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_LAYOUT_LP64, publish_object_descriptors,
        verify_object_descriptors,
    };
    use p11scope_ebpf_common::{Event, ImageIdentity, InstanceStamp, MAX_DESCRIPTORS};

    pub(crate) const COOKIE: u64 = 71;
    pub(crate) const EXEC: u64 = 0;
    const PID_TGID: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    pub(crate) const SESSION: u64 = 0x5050_5050_5050_5050;
    pub(crate) const SLOT_ID: u64 = 0x6060_6060_6060_6060;
    pub(crate) const FLAGS: u64 = 0x7070_7070_7070_7070;
    pub(crate) const ENTRY_NS: u64 = 0x3030_3030_3030_3030;
    const ENTRY_IP: u64 = 0x4040_4040_4040_4040;

    fn resource_audit(h3: H3DispositionEvidence) -> JournalAuditReceipt {
        JournalAuditReceipt {
            fault_before: 7,
            fault_after: 7,
            fault_error: None,
            malformed_delta: 0,
            discarded_delta: 0,
            counter_error: false,
            resource_refused: true,
            h3,
            h0_below: 8,
            closure_generation: 1,
            drain_domain: None,
        }
    }

    #[test]
    fn object_journal_resource_audit_never_masks_actual_loss_or_exhaustion() {
        use crate::semantics_key_use::{SealFailureDisposition, disposition_of};
        let clean = || H3DispositionEvidence::Clean {
            staged_max: 7,
            pending_floor: None,
        };
        for resource_refused in [false, true] {
            for (h3, seal_epoch, expected) in [
                (clean(), Ok(8), JournalGap::FaultChanged),
                (
                    clean(),
                    Err(FaultReadError::Unreadable),
                    JournalGap::FaultUnreadable,
                ),
                (
                    clean(),
                    Err(FaultReadError::Saturated),
                    JournalGap::FaultSaturated,
                ),
                (
                    H3DispositionEvidence::StagedLoss { barrier: 7 },
                    Ok(7),
                    JournalGap::H3Loss,
                ),
                (
                    H3DispositionEvidence::Exhausted,
                    Ok(7),
                    JournalGap::H3Exhausted,
                ),
            ] {
                let mut audit = resource_audit(h3);
                audit.resource_refused = resource_refused;
                assert_eq!(audit.check(None, 0, 1, &seal_epoch), Err(expected));
                assert_eq!(
                    disposition_of(expected),
                    SealFailureDisposition::HistoryLoss
                );
            }
            for expected in [
                JournalGap::Malformed,
                JournalGap::Discarded,
                JournalGap::CounterUnprovable,
            ] {
                let mut audit = resource_audit(clean());
                audit.resource_refused = resource_refused;
                match expected {
                    JournalGap::Malformed => audit.malformed_delta = 1,
                    JournalGap::Discarded => audit.discarded_delta = 1,
                    JournalGap::CounterUnprovable => audit.counter_error = true,
                    _ => unreachable!(),
                }
                assert_eq!(audit.check(None, 0, 1, &Ok(7)), Err(expected));
                assert_eq!(
                    disposition_of(expected),
                    SealFailureDisposition::HistoryLoss
                );
            }
        }
    }

    #[test]
    fn object_journal_resource_audit_fallback_requires_complete_h3() {
        use crate::semantics_key_use::{SealFailureDisposition, disposition_of};
        let clean = resource_audit(H3DispositionEvidence::Clean {
            staged_max: 7,
            pending_floor: None,
        });
        let reason = clean.check(None, 0, 1, &Ok(7)).unwrap_err();
        assert_eq!(reason, JournalGap::ResourceUnavailable);
        assert_eq!(disposition_of(reason), SealFailureDisposition::Fallback);
        for h3 in [
            H3DispositionEvidence::Clean {
                staged_max: 6,
                pending_floor: None,
            },
            H3DispositionEvidence::Clean {
                staged_max: 7,
                pending_floor: Some(7),
            },
        ] {
            let pending = resource_audit(h3);
            let reason = pending.check(None, 0, 1, &Ok(7)).unwrap_err();
            assert_eq!(reason, JournalGap::H3Pending);
            assert_eq!(disposition_of(reason), SealFailureDisposition::Retry);
        }
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn function_id(name: &str) -> u32 {
        crate::kinds::function_id(name).expect("catalog function")
    }

    /// Minimal valid BEGIN for any catalog function: VALUE session, absent
    /// inputs, valid entry stamp, zero requested lists.
    pub(crate) fn begin_bytes(thread: u64, sequence: u64, function: u32, flags: u8) -> [u8; 224] {
        begin_bytes_image(thread, sequence, function, flags, (COOKIE, EXEC))
    }

    /// Shaped BEGIN: the minimal record with explicit fingerprint
    /// fields (session word, entry mechanism, capture vocabulary)
    /// plus an optional input-0 word for key-use calls, for
    /// admissions whose S1 shape varies. Shared with H9 tests.
    #[allow(clippy::too_many_arguments)] // Fixture shaper: every record word explicit, no hidden defaults.
    pub(crate) fn begin_bytes_shaped(
        thread: u64,
        sequence: u64,
        function: u32,
        flags: u8,
        image: (u64, u64),
        session: u64,
        mechanism: u64,
        capture: u32,
        input0: Option<(u64, u8)>,
        input1: Option<(u64, u8)>,
        call_flags: u64,
    ) -> [u8; 224] {
        let mut bytes = begin_bytes_image(thread, sequence, function, flags, image);
        put_u64(&mut bytes, 80, session);
        put_u64(&mut bytes, 112, mechanism);
        put_u32(&mut bytes, 120, capture);
        put_u64(&mut bytes, 208, call_flags);
        if let Some((word, status)) = input0 {
            put_u64(&mut bytes, 88, word);
            bytes[126] = status;
        }
        if let Some((word, status)) = input1 {
            put_u64(&mut bytes, 96, word);
            bytes[127] = status;
        }
        bytes
    }

    fn begin_bytes_image(
        thread: u64,
        sequence: u64,
        function: u32,
        flags: u8,
        image: (u64, u64),
    ) -> [u8; 224] {
        use p11scope_ebpf_common::object_journal::*;
        let mut bytes = [0u8; JOURNAL_BEGIN_BYTES];
        put_u16(&mut bytes, 0, JOURNAL_VERSION);
        put_u16(&mut bytes, 2, JOURNAL_BEGIN_BYTES as u16);
        bytes[4] = JOURNAL_KIND_BEGIN;
        bytes[5] = flags;
        put_u64(&mut bytes, 8, thread);
        put_u64(&mut bytes, 16, sequence);
        put_u64(&mut bytes, 24, invocation_pid(thread));
        put_u64(&mut bytes, 32, image.0);
        put_u64(&mut bytes, 40, image.1);
        put_u64(&mut bytes, 48, invocation_entry_ns(thread, sequence));
        put_u64(&mut bytes, 56, ENTRY_IP);
        put_u32(&mut bytes, 64, 7);
        put_u32(&mut bytes, 68, 8);
        put_u32(&mut bytes, 72, 9);
        put_u16(&mut bytes, 76, 3);
        put_u16(&mut bytes, 78, STAMP_VALID);
        put_u64(&mut bytes, 80, SESSION);
        put_u32(&mut bytes, 104, fixture_slot(function).unwrap_or(11));
        put_u32(&mut bytes, 108, function + 1);
        bytes[124] = OBJECT_LAYOUT_LP64;
        bytes[125] = 1;
        put_u64(&mut bytes, 200, SLOT_ID);
        put_u64(&mut bytes, 208, FLAGS);
        put_u32(&mut bytes, 216, 1);
        bytes
    }

    fn invocation_pid(thread: u64) -> u64 {
        PID_TGID + thread
    }

    fn invocation_entry_ns(thread: u64, sequence: u64) -> u64 {
        ENTRY_NS + thread * 1_000_000 + sequence * 1_000
    }

    fn fixture_slot(function: u32) -> Option<u32> {
        // Plan slots follow the original table traversal, not file-offset
        // order. Reconstruct the fixture's input recipe before admission;
        // admit_original_event independently checks the actual attested slot.
        let surfaces = [
            pkcs11_module::Surface::LegacyFunctionList {
                version: cryptoki_sys::CK_VERSION {
                    major: 2,
                    minor: 40,
                },
            },
            pkcs11_module::Surface::StandardInterface {
                version: cryptoki_sys::CK_VERSION { major: 3, minor: 0 },
            },
        ];
        let mut functions = Vec::new();
        for surface in surfaces {
            if let pkcs11_module::TableSet::Walk(spans) = pkcs11_module::tables_for(surface) {
                for name in spans
                    .iter()
                    .flat_map(|span| span.fields())
                    .map(|field| field.name)
                {
                    if ADMITTABLE_FUNCTIONS.contains(&name) && !functions.contains(&name) {
                        functions.push(name);
                    }
                }
            }
        }
        functions
            .iter()
            .position(|name| function_id(name) == function)
            .map(|slot| slot as u32)
    }

    /// Minimal valid 608-byte completed payload matching `begin`: same
    /// image, session, slot, mechanism, capture, slot identity, flags,
    /// user type, entry address/stamp and requested lists.
    fn payload_for(begin: &[u8; 224], rv: u64, ts_ns: u64) -> [u8; 608] {
        use p11scope_ebpf_common::event_type;
        let mut payload = [0u8; 608];
        // Existing algorithm cases specify the return offset relative
        // to ENTRY_NS; the paired wire input retains this BEGIN's own
        // START time, so the original Event reconstructs it exactly.
        let entry_ns = u64::from_le_bytes(begin[48..56].try_into().unwrap());
        let duration = ts_ns.checked_sub(ENTRY_NS).expect("fixture return offset");
        put_u64(&mut payload, 0, entry_ns + duration);
        put_u64(&mut payload, 8, duration);
        payload[16..24].copy_from_slice(&begin[24..32]);
        put_u64(&mut payload, 24, 0x3333_3333_3333_3333);
        payload[32..40].copy_from_slice(&begin[80..88]);
        payload[40..48].copy_from_slice(&begin[200..208]);
        payload[48..56].copy_from_slice(&begin[112..120]);
        payload[56..64].copy_from_slice(&begin[208..216]);
        put_u64(&mut payload, 64, rv);
        payload[104..108].copy_from_slice(&begin[104..108]);
        payload[112..116].copy_from_slice(&begin[216..220]);
        payload[280..284].copy_from_slice(&begin[120..124]);
        put_u32(&mut payload, 284, event_type::CALL);
        payload[288..304].copy_from_slice(&begin[32..48]);
        put_u64(&mut payload, 320, 1);
        payload[328..336].copy_from_slice(&begin[56..64]);
        payload[336..352].copy_from_slice(&begin[64..80]);
        payload[352..368].copy_from_slice(&begin[64..80]);
        payload
    }

    /// Minimal valid H7 tail for the BEGIN's function: the BEGIN's own
    /// input words/statuses (they must agree), a VALUE result word for
    /// creations, absent-zero lists.
    fn tail_for(begin: &[u8; 224], action: u8) -> [u8; 240] {
        use p11scope_ebpf_common::object_wire::{OBJECT_CALL_BYTES, OBJECT_CALL_VERSION};
        let mut tail = [0u8; 240];
        put_u16(&mut tail, 0, OBJECT_CALL_VERSION);
        put_u16(&mut tail, 2, OBJECT_CALL_BYTES);
        tail[4..8].copy_from_slice(&begin[108..112]);
        tail[12] = OBJECT_LAYOUT_LP64;
        tail[13] = action;
        tail[16..32].copy_from_slice(&begin[88..104]);
        tail[112] = begin[126];
        tail[113] = begin[127];
        if action == OBJECT_ACTION_CREATE {
            put_u64(&mut tail, 32, 0x9090_9090_9090_9090);
            tail[114] = 1;
        }
        tail[128..200].copy_from_slice(&begin[128..200]);
        tail
    }

    /// END with an explicit CREATE result word (distinct keys for
    /// multi-key histories). Shared with H9 tests.
    pub(crate) fn end_bytes_result(
        begin: &[u8; 224],
        action: u8,
        rv: u64,
        ts_ns: u64,
        result: u64,
    ) -> [u8; 632] {
        let mut end = end_bytes(begin, action, rv, ts_ns);
        // Tail result word: record[392 + 32 .. 392 + 40].
        put_u64(&mut end, 424, result);
        end
    }

    /// GET END with explicit attribute cells (kind, status, value):
    /// requested-only (unavailable status) or establishing (status 1
    /// with a classifying scalar). Shared with H9 tests.
    pub(crate) fn end_bytes_getattr(
        begin: &[u8; 224],
        rv: u64,
        ts_ns: u64,
        cells: &[(u8, u8, u16)],
    ) -> [u8; 632] {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_GET;
        let mut end = end_bytes(begin, OBJECT_ACTION_GET, rv, ts_ns);
        // Attribute list: tail[200..236] = record[592..628]; eight
        // 4-byte cells, inspected count at +32, flags at +33.
        assert!(cells.len() <= 8, "at most eight attribute cells");
        for (index, (kind, status, value)) in cells.iter().enumerate() {
            let base = 592 + index * 4;
            end[base] = *kind;
            end[base + 1] = *status;
            end[base + 2..base + 4].copy_from_slice(&value.to_le_bytes());
        }
        end[624] = cells.len() as u8;
        end[625] = 1;
        end
    }

    pub(crate) fn end_bytes(begin: &[u8; 224], action: u8, rv: u64, ts_ns: u64) -> [u8; 632] {
        use p11scope_ebpf_common::object_journal::*;
        let thread = u64::from_le_bytes(begin[8..16].try_into().unwrap());
        let sequence = u64::from_le_bytes(begin[16..24].try_into().unwrap());
        let mut bytes = [0u8; JOURNAL_END_FULL_BYTES];
        put_u16(&mut bytes, 0, JOURNAL_VERSION);
        put_u16(&mut bytes, 2, JOURNAL_END_FULL_BYTES as u16);
        bytes[4] = JOURNAL_KIND_END;
        put_u64(&mut bytes, 8, thread);
        put_u64(&mut bytes, 16, sequence);
        let mut payload = payload_for(begin, rv, ts_ns);
        payload[368..].copy_from_slice(&tail_for(begin, action));
        bytes[24..].copy_from_slice(&payload);
        bytes
    }

    /// Minimal valid absent-tail END for a no-row (neutral/lifecycle)
    /// BEGIN: the absent bit set with 240 zero tail bytes.
    pub(crate) fn end_bytes_absent(begin: &[u8; 224], rv: u64, ts_ns: u64) -> [u8; 632] {
        use p11scope_ebpf_common::object_journal::*;
        let mut bytes = end_bytes(begin, OBJECT_ACTION_CREATE, rv, ts_ns);
        bytes[5] = JOURNAL_END_TAIL_ABSENT;
        bytes[24 + 368..].fill(0);
        bytes
    }

    /// Producer field audit for P0a (no journal producer is activated):
    ///
    /// - START image, slot/slot-id, flags and user type survive fill_call_event
    ///   exactly; the BEGIN also retains the entry IP/stamp and H7 inputs.
    /// - START's entry time becomes BEGIN.entry_ns; END has return time and
    ///   the duration measured from that original entry.
    /// - H7 absent session is 0/status 0; S1's absent word is SESSION_NONE.
    ///   OpenSession alone can replace that word after a successful out-read.
    /// - Safe entry retains MECH_NONE and its pointer. capture_return_facts
    ///   can set VALUE or UNREADABLE; the optional unsafe entry can already
    ///   hold either state. Mechanism bits are an enum, not a monotonic mask.
    /// - Return preserves output/async-session bits. Only mechanism state,
    ///   ARG_READ_FAILURE and ASYNC_VALUE_UNREADABLE can change there.
    ///
    /// The S1 bytes below come from the actual shared return constructor,
    /// not payload_for's equality-by-copy fixture. H7 tails still use the
    /// existing validated fixture; this is not a live BEGIN producer proof.
    fn producer_agreement_pair(
        name: &str,
        rewrite: impl FnOnce(
            &mut p11scope_ebpf_common::CallStart,
            &mut p11scope_ebpf_common::object_flow::ReturnEventFacts,
        ),
    ) -> ([u8; 224], [u8; 632]) {
        use p11scope_ebpf_common::object_capture::handle_status;
        use p11scope_ebpf_common::object_flow::{ReturnEventFacts, fill_call_event};
        use p11scope_ebpf_common::{ARG_NONE, CallStart, EventRecord, MECH_NONE, SESSION_NONE};
        assert!(matches!(
            name,
            "C_SignInit"
                | "C_OpenSession"
                | "C_Finalize"
                | "C_CloseAllSessions"
                | "C_CreateObject"
                | "C_GetSessionInfo"
        ));
        let function = function_id(name);
        let semantics = crate::kinds::DESCRIPTORS[function as usize + 1];
        let rows = publish_object_descriptors();
        let mut begin = begin_bytes(1, 1, function, 0);
        // The generic BEGIN helper leaves inputs absent. Actual H7 entry
        // capture gives every descriptor-present nonzero handle VALUE;
        // the END tail must carry that same entry observation.
        for (index, argument) in rows[function as usize + 1].input_args.iter().enumerate() {
            if *argument != ARG_NONE {
                put_u64(&mut begin, 88 + 8 * index, SESSION + index as u64);
                begin[126 + index] = handle_status::VALUE;
            }
        }
        let entry_ns = u64::from_le_bytes(begin[48..56].try_into().unwrap());
        let mut start = CallStart {
            ts_ns: entry_ns,
            session: if semantics.session_arg == ARG_NONE {
                SESSION_NONE
            } else {
                SESSION
            },
            slot_id: if semantics.slot_arg == ARG_NONE {
                0
            } else {
                SLOT_ID
            },
            mechanism: MECH_NONE,
            mechanism_ptr: if semantics.mechanism_arg == ARG_NONE {
                0
            } else {
                0x1000
            },
            flags: if semantics.flags_arg == ARG_NONE {
                0
            } else {
                4
            },
            user_type: p11scope_ebpf_common::USER_TYPE_NONE,
            target_function: function,
            image: ImageIdentity {
                task_cookie: COOKIE,
                exec_id: EXEC,
            },
            ..Default::default()
        };
        if semantics.output_arg != ARG_NONE {
            start.capture |= capture::OUTPUT_NON_NULL;
            if semantics.lifecycle == p11scope_ebpf_common::lifecycle::OPEN_SESSION {
                start.out_ptr = 0x2000;
            }
        }
        let mut facts = ReturnEventFacts {
            ts_ns: entry_ns + 100,
            duration_ns: 100,
            rv: 0,
            mechanism: if start.mechanism_ptr == 0 {
                MECH_NONE
            } else {
                1
            },
            session: if start.out_ptr == 0 {
                start.session
            } else {
                0x9090
            },
            async_value: 0,
            capture_flags: if start.mechanism_ptr == 0 {
                start.capture
            } else {
                (start.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_VALUE
            },
            pid_tgid: invocation_pid(1),
            cgroup_id: 1,
            root_affiliation: 0,
        };
        rewrite(&mut start, &mut facts);
        put_u64(
            &mut begin,
            80,
            if start.session == SESSION_NONE {
                0
            } else {
                start.session
            },
        );
        begin[125] = u8::from(start.session != SESSION_NONE);
        put_u64(&mut begin, 112, start.mechanism);
        put_u32(&mut begin, 120, start.capture);
        put_u64(&mut begin, 200, start.slot_id);
        put_u64(&mut begin, 208, start.flags);
        put_u32(&mut begin, 216, start.user_type);

        let mut base = EventRecord::default();
        // SAFETY: exclusively owned, aligned Event; the production helper
        // fills every byte of this padding-free wire value.
        unsafe {
            fill_call_event(
                &mut base.event,
                &start,
                u32::from_le_bytes(begin[104..108].try_into().unwrap()),
                &facts,
            )
        };
        base.continuity.entry_ip = ENTRY_IP;
        base.continuity.entry_stamp = InstanceStamp {
            epoch: 7,
            global: 8,
            fault: 9,
            file_slot_plus1: 3,
            flags: STAMP_VALID,
        };
        base.continuity.return_stamp = base.continuity.entry_stamp;
        let action = rows[function as usize + 1].action;
        let mut end = if action == 0 {
            end_bytes_absent(&begin, facts.rv, ENTRY_NS + 100)
        } else {
            end_bytes(&begin, action, facts.rv, ENTRY_NS + 100)
        };
        // SAFETY: EventRecord is the initialized, padding-free 368-byte
        // kernel wire value, with the same layout pinned by common tests.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&base as *const EventRecord).cast::<u8>(),
                std::mem::size_of::<EventRecord>(),
            )
        };
        end[24..24 + bytes.len()].copy_from_slice(bytes);
        (begin, end)
    }

    fn producer_pair_agrees(begin: &[u8; 224], end: &[u8; 632]) -> bool {
        let rows = publish_object_descriptors();
        let JournalRecord::Begin(begin) =
            decode_journal_record(begin, &rows).expect("valid producer BEGIN")
        else {
            panic!("BEGIN shape")
        };
        let JournalRecord::End(end) =
            decode_journal_record(end, &rows).expect("valid producer END")
        else {
            panic!("END shape")
        };
        end_agrees_with_begin(&begin, &end)
    }

    #[test]
    fn object_journal_agreement_accepts_producer_return_rewrites() {
        for name in [
            "C_SignInit",
            "C_OpenSession",
            "C_Finalize",
            "C_CloseAllSessions",
        ] {
            let (begin, end) = producer_agreement_pair(name, |_, _| {});
            assert!(
                producer_pair_agrees(&begin, &end),
                "legitimate return rewrite: {name}"
            );
        }
    }

    #[test]
    fn object_journal_agreement_accepts_producer_unsafe_mechanism_transitions() {
        for entry_readable in [true, false] {
            let (begin, end) = producer_agreement_pair("C_SignInit", |start, facts| {
                if entry_readable {
                    start.mechanism = 1;
                    start.capture =
                        (start.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_VALUE;
                    facts.mechanism = 1;
                    facts.capture_flags = (facts.capture_flags & !capture::MECHANISM_MASK)
                        | capture::MECHANISM_UNREADABLE
                        | capture::ARG_READ_FAILURE;
                } else {
                    start.capture = (start.capture & !capture::MECHANISM_MASK)
                        | capture::MECHANISM_UNREADABLE
                        | capture::ARG_READ_FAILURE;
                    facts.capture_flags |= capture::ARG_READ_FAILURE;
                }
            });
            assert!(
                producer_pair_agrees(&begin, &end),
                "entry readable={entry_readable}"
            );
        }
    }

    #[test]
    fn object_journal_agreement_accepts_safe_unreadable_mechanism_return() {
        let (begin, end) = producer_agreement_pair("C_SignInit", |_, facts| {
            facts.mechanism = p11scope_ebpf_common::MECH_NONE;
            facts.capture_flags = (facts.capture_flags & !capture::MECHANISM_MASK)
                | capture::MECHANISM_UNREADABLE
                | capture::ARG_READ_FAILURE;
        });
        assert!(producer_pair_agrees(&begin, &end));
    }

    #[test]
    fn object_journal_agreement_accepts_producer_open_session_outcomes() {
        use p11scope_ebpf_common::SESSION_NONE;
        for outcome in [
            "pending-out-read",
            "failed-rv",
            "null-out",
            "entry-unreadable-out",
            "return-unreadable-word",
        ] {
            let (begin, end) =
                producer_agreement_pair("C_OpenSession", |start, facts| match outcome {
                    "pending-out-read" => facts.rv = 0x204,
                    "failed-rv" => {
                        facts.rv = 5;
                        facts.session = SESSION_NONE;
                    }
                    "null-out" | "entry-unreadable-out" => {
                        start.out_ptr = 0;
                        start.capture = if outcome == "null-out" {
                            capture::OUTPUT_NULL
                        } else {
                            capture::OUTPUT_UNREADABLE | capture::ARG_READ_FAILURE
                        };
                        facts.capture_flags = start.capture;
                        facts.session = SESSION_NONE;
                    }
                    "return-unreadable-word" => facts.session = SESSION_NONE,
                    _ => unreachable!(),
                });
            assert!(
                producer_pair_agrees(&begin, &end),
                "legitimate OpenSession outcome: {outcome}"
            );
        }
    }

    #[test]
    fn object_journal_agreement_keeps_producer_identity_exact() {
        for name in ["C_CreateObject", "C_GetSessionInfo"] {
            let (begin, end) = producer_agreement_pair(name, |_, _| {});
            assert!(
                producer_pair_agrees(&begin, &end),
                "unchanged producer call agrees: {name}"
            );
            for offset in [16, 32, 40, 56, 104, 112, 288, 296, 328, 336] {
                let mut changed = end;
                changed[24 + offset] ^= 1;
                assert!(
                    !producer_pair_agrees(&begin, &changed),
                    "immutable {name} field at {offset}"
                );
            }
        }
    }

    #[test]
    fn object_journal_producer_ordinary_matching_keeps_entry_and_session_exact() {
        use p11scope_ebpf_common::SESSION_NONE;
        let (begin, end) = producer_agreement_pair("C_GetSessionInfo", |_, _| {});
        for session in [0, SESSION_NONE] {
            let mut changed = end;
            put_u64(&mut changed, 24 + 32, session);
            assert!(
                !producer_pair_agrees(&begin, &changed),
                "GetSessionInfo is not sessionless: {session}"
            );
        }
        let rows = publish_object_descriptors();
        let JournalRecord::Begin(begin) = decode_journal_record(&begin, &rows).unwrap() else {
            panic!("BEGIN")
        };
        let JournalRecord::End(end) = decode_journal_record(&end, &rows).unwrap() else {
            panic!("END")
        };
        let event = end.payload_base().event;
        assert!(ordinary_matches_begin(&event, 2, &begin, 1));
        let mut wrong_entry = event;
        wrong_entry.duration_ns += 1;
        assert!(
            !ordinary_matches_begin(&wrong_entry, 2, &begin, 1),
            "a later return with another entry is not corroboration"
        );
        for session in [0, SESSION_NONE, event.session ^ 1] {
            let mut changed = event;
            changed.session = session;
            assert!(
                !ordinary_matches_begin(&changed, 2, &begin, 1),
                "session argument 0 remains exact: {session}"
            );
        }
    }

    #[test]
    fn object_journal_agreement_refuses_unrelated_return_capture_changes() {
        let (begin, end) = producer_agreement_pair("C_CreateObject", |_, facts| {
            facts.capture_flags |= capture::ARG_READ_FAILURE;
        });
        assert!(
            !producer_pair_agrees(&begin, &end),
            "no mechanism-read failure on CreateObject"
        );
        for added in [capture::OUTPUT_NON_NULL, capture::ASYNC_SESSION] {
            let (begin, end) = producer_agreement_pair("C_SignInit", |_, facts| {
                facts.capture_flags |= added;
            });
            assert!(
                !producer_pair_agrees(&begin, &end),
                "entry-only capture bit {added}"
            );
        }
        let (begin, end) = producer_agreement_pair("C_SignInit", |start, facts| {
            start.mechanism = 0;
            start.capture = (start.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_VALUE;
            facts.mechanism = 1;
        });
        assert!(
            !producer_pair_agrees(&begin, &end),
            "mechanism zero is a captured value, not NONE"
        );
    }

    #[test]
    fn object_journal_agreement_refuses_unwritten_open_session_results() {
        let (begin, end) = producer_agreement_pair("C_OpenSession", |_, facts| {
            facts.rv = 5;
        });
        assert!(
            !producer_pair_agrees(&begin, &end),
            "failed return cannot rewrite session"
        );
        let (begin, end) = producer_agreement_pair("C_OpenSession", |start, facts| {
            start.out_ptr = 0;
            start.capture = capture::OUTPUT_NULL;
            facts.capture_flags = start.capture;
        });
        assert!(
            !producer_pair_agrees(&begin, &end),
            "NULL out-pointer cannot supply a new handle"
        );
    }

    #[test]
    fn object_journal_return_rewrites_follow_native_rv_and_output_gates() {
        for rv in [0, 0x204, 5, 0x150] {
            let (begin, end) = producer_agreement_pair("C_SignInit", |_, facts| facts.rv = rv);
            assert_eq!(producer_pair_agrees(&begin, &end), matches!(rv, 0 | 0x204));
            let (begin, end) = producer_agreement_pair("C_OpenSession", |_, facts| facts.rv = rv);
            assert_eq!(producer_pair_agrees(&begin, &end), matches!(rv, 0 | 0x204));
        }
        for output in [
            capture::OUTPUT_NONE,
            capture::OUTPUT_NULL,
            capture::OUTPUT_UNREADABLE,
        ] {
            let (begin, end) = producer_agreement_pair("C_OpenSession", |start, facts| {
                start.out_ptr = 0;
                start.capture = output;
                facts.capture_flags = output;
            });
            assert!(!producer_pair_agrees(&begin, &end));
        }
        for status in [
            p11scope_ebpf_common::object_capture::handle_status::UNREADABLE,
            p11scope_ebpf_common::object_capture::handle_status::INVALID_SPAN,
        ] {
            let (mut begin, end) = producer_agreement_pair("C_Finalize", |_, _| {});
            begin[125] = status;
            assert!(!producer_pair_agrees(&begin, &end), "unknown is not absent");
        }
        let (mut begin, end) = producer_agreement_pair("C_GetSessionInfo", |start, facts| {
            start.session = 0;
            facts.session = 0;
        });
        begin[125] = p11scope_ebpf_common::object_capture::handle_status::INVALID_ZERO;
        assert!(
            producer_pair_agrees(&begin, &end),
            "argument zero stays zero"
        );
    }

    #[test]
    fn object_journal_return_rewrites_keep_captured_zero_and_sentinel_exact() {
        for captured in [0, 1, u64::MAX] {
            for unreadable in [false, true] {
                let (begin, end) = producer_agreement_pair("C_SignInit", |start, facts| {
                    start.mechanism = captured;
                    start.capture = capture::MECHANISM_VALUE;
                    facts.mechanism = captured;
                    facts.capture_flags = if unreadable {
                        capture::MECHANISM_UNREADABLE | capture::ARG_READ_FAILURE
                    } else {
                        capture::MECHANISM_VALUE
                    };
                });
                assert!(producer_pair_agrees(&begin, &end));
            }
            let (begin, end) = producer_agreement_pair("C_SignInit", |start, facts| {
                start.mechanism = captured;
                start.capture = capture::MECHANISM_VALUE;
                facts.mechanism = captured ^ 1;
            });
            assert!(
                !producer_pair_agrees(&begin, &end),
                "captured VALUE={captured}"
            );
        }
    }

    #[test]
    fn object_journal_return_rewrites_refuse_unproduced_capture_transitions() {
        for poison in [
            "cleared-entry-failure",
            "new-success-failure",
            "unreadable-without-failure",
            "null-to-value",
            "unreadable-changed-word",
            "uncaptured-nonsentinel",
            "async-return-bit",
            "unknown-bit",
        ] {
            let (begin, end) = producer_agreement_pair("C_SignInit", |start, facts| match poison {
                "cleared-entry-failure" => {
                    start.capture = capture::MECHANISM_UNREADABLE | capture::ARG_READ_FAILURE;
                    facts.capture_flags = capture::MECHANISM_VALUE;
                }
                "new-success-failure" => facts.capture_flags |= capture::ARG_READ_FAILURE,
                "unreadable-without-failure" => {
                    facts.mechanism = start.mechanism;
                    facts.capture_flags = capture::MECHANISM_UNREADABLE;
                }
                "null-to-value" => start.capture = capture::MECHANISM_NULL,
                "unreadable-changed-word" => {
                    facts.capture_flags = capture::MECHANISM_UNREADABLE | capture::ARG_READ_FAILURE;
                }
                "uncaptured-nonsentinel" => start.mechanism = 0,
                "async-return-bit" => facts.capture_flags |= capture::ASYNC_VALUE_UNREADABLE,
                "unknown-bit" => facts.capture_flags |= 0x80,
                _ => unreachable!(),
            });
            assert!(!producer_pair_agrees(&begin, &end), "{poison}");
        }
        let (begin, end) = producer_agreement_pair("C_GetSessionInfo", |_, facts| {
            facts.mechanism = 1;
            facts.capture_flags = capture::MECHANISM_VALUE;
        });
        assert!(!producer_pair_agrees(&begin, &end), "no mechanism argument");
    }

    #[test]
    fn object_journal_return_rewrites_bound_new_ilp32_words() {
        use p11scope_ebpf_common::object_wire::OBJECT_LAYOUT_ILP32;
        // Structural word-width coverage, not live ILP32 Joint admission.
        for returned in [0, u64::from(u32::MAX), u64::from(u32::MAX) + 1] {
            let (mut begin, end) = producer_agreement_pair("C_OpenSession", |start, facts| {
                start.slot_id = 7;
                facts.session = returned;
            });
            begin[124] = OBJECT_LAYOUT_ILP32;
            assert_eq!(
                producer_pair_agrees(&begin, &end),
                returned <= u64::from(u32::MAX)
            );

            let (mut begin, mut end) = producer_agreement_pair("C_SignInit", |start, facts| {
                start.session = 42;
                facts.session = 42;
                facts.mechanism = returned;
            });
            // Use native-width H7 entry facts as well as the real S1
            // constructor. The mechanism is the only varying return word.
            begin[124] = OBJECT_LAYOUT_ILP32;
            put_u64(&mut begin, 56, 0x4000);
            put_u64(&mut begin, 88, 7);
            put_u64(&mut end, 24 + 328, 0x4000);
            put_u64(&mut end, 24 + 368 + 16, 7);
            end[24 + 368 + 12] = OBJECT_LAYOUT_ILP32;
            assert_eq!(
                producer_pair_agrees(&begin, &end),
                returned <= u64::from(u32::MAX)
            );
            if returned <= u64::from(u32::MAX) {
                end[24 + 368 + 12] = OBJECT_LAYOUT_LP64;
                assert!(!producer_pair_agrees(&begin, &end), "layout is immutable");
            }
        }
    }

    #[test]
    fn object_journal_return_rewrites_preserve_exact_tail_evidence() {
        let (begin, end) = producer_agreement_pair("C_SignInit", |_, _| {});
        assert!(producer_pair_agrees(&begin, &end));
        let mut changed_input = end;
        changed_input[24 + 368 + 16] ^= 1;
        assert!(!producer_pair_agrees(&begin, &changed_input));
        let mut changed_status = end;
        put_u64(&mut changed_status, 24 + 368 + 16, 0);
        changed_status[24 + 368 + 112] =
            p11scope_ebpf_common::object_capture::handle_status::UNREADABLE;
        assert!(!producer_pair_agrees(&begin, &changed_status));
        let mut changed_descriptor = end;
        put_u32(
            &mut changed_descriptor,
            24 + 368 + 4,
            function_id("C_VerifyInit") + 1,
        );
        assert!(!producer_pair_agrees(&begin, &changed_descriptor));

        let (begin, mut end) = producer_agreement_pair("C_CreateObject", |_, _| {});
        end[24 + 368 + 128 + 33] = p11scope_ebpf_common::object_wire::OBJECT_ATTR_LIST_UNINSPECTED;
        assert!(
            !producer_pair_agrees(&begin, &end),
            "requested lists are immutable"
        );
    }

    pub(crate) fn abandon_bytes(
        thread: u64,
        sequence: u64,
        reason: u32,
        image: (u64, u64),
    ) -> [u8; 64] {
        use p11scope_ebpf_common::object_journal::*;
        let mut bytes = [0u8; JOURNAL_ABANDON_BYTES];
        put_u16(&mut bytes, 0, JOURNAL_VERSION);
        put_u16(&mut bytes, 2, JOURNAL_ABANDON_BYTES as u16);
        bytes[4] = JOURNAL_KIND_ABANDON;
        put_u64(&mut bytes, 8, thread);
        put_u64(&mut bytes, 16, sequence);
        put_u64(&mut bytes, 24, invocation_pid(thread));
        put_u64(&mut bytes, 32, image.0);
        put_u64(&mut bytes, 40, image.1);
        put_u32(&mut bytes, 48, 11);
        put_u32(&mut bytes, 52, reason);
        put_u64(&mut bytes, 56, invocation_entry_ns(thread, sequence));
        bytes
    }

    /// One ordinary CALL corroborating `begin`: the same seven-word call
    /// identity read from the BEGIN, returned after entry, completed
    /// (non-pending) rv. Shared with H9 tests.
    pub(crate) fn ordinary_for(begin: &[u8; 224], rv: u64) -> Event {
        let entry_ns = u64::from_le_bytes(begin[48..56].try_into().unwrap());
        Event {
            ts_ns: entry_ns + 100,
            duration_ns: 100,
            pid_tgid: u64::from_le_bytes(begin[24..32].try_into().unwrap()),
            session: u64::from_le_bytes(begin[80..88].try_into().unwrap()),
            slot_id: u64::from_le_bytes(begin[200..208].try_into().unwrap()),
            mechanism: u64::from_le_bytes(begin[112..120].try_into().unwrap()),
            flags: u64::from_le_bytes(begin[208..216].try_into().unwrap()),
            rv,
            slot: u32::from_le_bytes(begin[104..108].try_into().unwrap()),
            user_type: u32::from_le_bytes(begin[216..220].try_into().unwrap()),
            capture: u32::from_le_bytes(begin[120..124].try_into().unwrap()),
            event_type: p11scope_ebpf_common::event_type::CALL,
            image: ImageIdentity {
                task_cookie: u64::from_le_bytes(begin[32..40].try_into().unwrap()),
                exec_id: u64::from_le_bytes(begin[40..48].try_into().unwrap()),
            },
            root_affiliation: 0,
            ..Default::default()
        }
    }

    /// The H3 attestation fixture: a real pinned provider manifest, a real
    /// prepared subset, a real routed instance id and real admission. The
    /// journal key binding traverses actual Session/admission authority;
    /// only the ring bytes and fault cell are scripted.
    /// Functions the attestation fixture resolves in its provider
    /// manifest: every modeled function journal tests stage needs an
    /// admittable plan slot, since each staged call converts only
    /// under its own H3 admission claim.
    const ADMITTABLE_FUNCTIONS: [&str; 16] = [
        "C_CreateObject",
        "C_GetAttributeValue",
        "C_SignInit",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_SignMessage",
        "C_DestroyObject",
        // H9 S1-matrix extensions, appended so the T3 indices above
        // (and their legacy offsets) never shift.
        "C_SignUpdate",
        "C_SignFinal",
        "C_OpenSession",
        "C_CloseSession",
        "C_SessionCancel",
        "C_MessageSignInit",
        "C_MessageSignFinal",
        // H9 key-role extension (dual-reference direct call).
        "C_WrapKey",
    ];

    /// v3-only functions, resolved on the 3.0 interface surface
    /// (they ride no legacy table) at `start + 64 + stride`, clear of
    /// the legacy `start + index` band.
    const V3_ONLY_FUNCTIONS: [&str; 4] = [
        "C_SignMessage",
        "C_MessageSignInit",
        "C_MessageSignFinal",
        "C_SessionCancel",
    ];

    /// Genuine-bind identity answers: the cookie queries the bind
    /// proof makes against the Detailed domain.
    #[derive(Default)]
    struct BindIdentity {
        answers:
            std::collections::HashMap<(u32, NativeDomainId), crate::attach::capture::CookieQuery>,
    }

    impl crate::discovery::native_binding::NativeIdentity<crate::process::PidPin> for BindIdentity {
        fn owner_image(
            &mut self,
            _pid: u32,
        ) -> Option<crate::discovery::native_binding::BoundImage> {
            None
        }

        fn query_cookie(
            &mut self,
            domain: NativeDomainId,
            pin: &crate::process::PidPin,
        ) -> crate::attach::capture::CookieQuery {
            self.answers
                .get(&(pin.pid(), domain))
                .cloned()
                .unwrap_or(crate::attach::capture::CookieQuery::NoCookie)
        }
    }

    std::thread_local! {
        static BIND_SIGHT_NS: std::cell::Cell<u64> = const { std::cell::Cell::new(1_005) };
    }

    fn bind_sight_clock() -> Option<u64> {
        BIND_SIGHT_NS.with(|clock| Some(clock.get()))
    }

    /// One genuine bind through the coordinator's real proof: admit the
    /// pid, map the module completely, answer the identity query, prove
    /// the image to the domain, duplicate the live pin and run the bind
    /// proof. Returns the bound caller; the binding reads back from the
    /// coordinator. Mirrors the custody-chain scene's proven shape.
    #[allow(clippy::too_many_arguments)]
    fn genuine_bind(
        coordinator: &mut crate::discovery::engine::inventory_coordinator::InventoryCoordinator<
            crate::discovery::caller_registry::OsProcessSource,
        >,
        identity: &mut BindIdentity,
        pid: u32,
        module: &crate::discovery::caller_registry::ModuleKey,
        domain: NativeDomainId,
        image: ImageIdentity,
    ) -> crate::discovery::caller_registry::CallerId {
        use crate::attach::capture::{
            CaptureHealth, CapturePhase, CookieQuery, DiscoveryBatch, DomainCookie, ScopeCustody,
            WitnessBatch, WitnessRow,
        };
        use crate::discovery::caller_registry::{AdmissionState, ImageAuthority, ModuleInfo};
        use crate::discovery::engine::inventory_coordinator::NativeBatch;
        use crate::discovery::inventory_attach_set::{AttachObjectId, EndpointId};
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let info = ModuleInfo {
            path: "/task3/provider.so".into(),
            key: module.clone(),
            double_loaded: false,
            build_id: None,
            identity_source: Some("task3".into()),
            admission: AdmissionState::Admitted,
            admission_class: Some("exact".into()),
            admission_endpoints: Some(1),
            admission_reasons: Vec::new(),
        };
        coordinator
            .registry_mut()
            .note_mapping(caller, pid, info, 60);
        coordinator.commit_batch(false).unwrap();
        identity.answers.insert(
            (pid, domain),
            CookieQuery::Cookie(DomainCookie::scripted(domain, image.task_cookie)),
        );
        let witness = |domain: NativeDomainId, rows: Vec<WitnessRow>, at_ns: u64| WitnessBatch {
            domain,
            phase: CapturePhase::Active,
            rows,
            integrity: Vec::new(),
            integrity_total: 0,
            visited: 0,
            sweep_completed: true,
            sweeps_completed: 1,
            row_bound_reached: false,
            deadline_reached: false,
            read_failures: Vec::new(),
            unrecorded_rows: 0,
            sweep_gaps: false,
            counts: Vec::new(),
            refresh_sweep_completed: true,
            refresh_sweep_gaps: false,
            refresh_deadline_reached: false,
            refresh_sweeps_completed: 1,
            seen_rows: 0,
            pair_limit: 65_536,
            health: CaptureHealth {
                discovery_counters: Some([0; 5]),
                ..CaptureHealth::default()
            },
            health_regression: None,
            health_unproven: None,
            health_baseline_ns: 0,
            health_read_ns: at_ns,
            rows_anchor_ns: at_ns + 1,
            rows_read_ns: at_ns + 1,
            counts_read_ns: at_ns + 1,
            changed_objects: Vec::new(),
            custody: ScopeCustody::System,
            custody_proven_ns: None,
            lifecycle_proven_ns: u64::MAX,
            lifecycle_loss: None,
            unsettled: false,
        };
        let rows = vec![WitnessRow::scripted(
            domain,
            image.task_cookie,
            image.exec_id,
            AttachObjectId::scripted(0),
            EndpointId(0),
            pid,
            100,
        )];
        coordinator.stage_native(
            NativeBatch::Witness(Box::new(witness(domain, rows, 1_000))),
            identity,
            1_002,
        );
        coordinator.stage_native(
            NativeBatch::Lifecycle(DiscoveryBatch::scripted(domain, Vec::new(), 1_010)),
            identity,
            1_011,
        );
        coordinator.stage_native(
            NativeBatch::Witness(Box::new(witness(domain, Vec::new(), 1_020))),
            identity,
            1_022,
        );
        coordinator.commit_batch(false).unwrap();
        let pin = std::sync::Arc::new(
            coordinator
                .adapter()
                .live_pin(pid)
                .and_then(|(_, pin)| pin.try_clone().ok())
                .unwrap(),
        );
        coordinator
            .bind_semantic_caller_with_pin(caller, module.clone(), domain, image, identity, pin)
            .unwrap_or_else(|refusal| {
                panic!("genuine_bind pid={pid} domain={domain:?} image={image:?}: {refusal:?}")
            });
        caller
    }

    pub(crate) struct AttestationFixture {
        _dir: tempfile::TempDir,
        subset: Option<AttestedSubset>,
        coordinator: crate::discovery::engine::inventory_coordinator::InventoryCoordinator<
            crate::discovery::caller_registry::OsProcessSource,
        >,
        identity: BindIdentity,
        primary: crate::discovery::caller_registry::CallerId,
        domain: NativeDomainId,
        image: ImageIdentity,
        router: InstanceId,
        functions: BTreeMap<String, (u32, Endpoint)>,
        next_token: u64,
        attachment: crate::attach::AttachedSemanticSet,
        /// The fixture's bound incarnation: a live sleeper the
        /// primary binding pins. Owned so custody tests can reap
        /// the exact pin the binding holds (drop reaps).
        child: std::process::Child,
    }

    impl Drop for AttestationFixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl AttestationFixture {
        pub(crate) fn new(image: ImageIdentity) -> Self {
            Self::with_quiet_function(image, false)
        }

        pub(crate) fn new_with_quiet_function(image: ImageIdentity) -> Self {
            Self::with_quiet_function(image, true)
        }

        fn with_quiet_function(image: ImageIdentity, quiet: bool) -> Self {
            use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
            use p11scope_manifest::manifest::*;
            let admitted_functions: Vec<_> = ADMITTABLE_FUNCTIONS
                .into_iter()
                .chain(quiet.then_some("C_GetSessionInfo"))
                .collect();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("provider.so");
            std::fs::copy("/bin/true", &path).unwrap();
            let file = open_object(&path).unwrap();
            let inspected = inspect_file(&file).unwrap();
            let mapping = mapping_file_key(&file).unwrap();
            let start = inspected
                .executable_ranges
                .iter()
                .find(|(a, b)| b - a > 64 + admitted_functions.len() as u64)
                .unwrap()
                .0;
            let functions: Vec<FunctionRecord> =
                match pkcs11_module::tables_for(pkcs11_module::Surface::LegacyFunctionList {
                    version: cryptoki_sys::CK_VERSION {
                        major: 2,
                        minor: 40,
                    },
                }) {
                    pkcs11_module::TableSet::Walk(spans) => spans
                        .iter()
                        .flat_map(|span| span.fields())
                        .map(|field| {
                            let resolution = admitted_functions
                                .iter()
                                .position(|name| *name == field.name)
                                .map(|index| Resolution::Resolved {
                                    object: 0,
                                    file_offset: start + index as u64,
                                })
                                .unwrap_or(Resolution::NullPointer);
                            FunctionRecord {
                                name: field.name.into(),
                                resolution,
                            }
                        })
                        .collect(),
                    _ => panic!("2.40 is a full standard table"),
                };
            // The v3-only functions ride no legacy table: resolve
            // each on a v3 interface surface (canonical V3_0 walk
            // order) at `start + 64 + stride`, clear of the legacy
            // `start + index` band.
            let message_functions: Vec<FunctionRecord> =
                match pkcs11_module::tables_for(pkcs11_module::Surface::StandardInterface {
                    version: cryptoki_sys::CK_VERSION { major: 3, minor: 0 },
                }) {
                    pkcs11_module::TableSet::Walk(spans) => spans
                        .iter()
                        .flat_map(|span| span.fields())
                        .map(|field| {
                            let resolution = V3_ONLY_FUNCTIONS
                                .iter()
                                .position(|name| *name == field.name)
                                .map(|stride| Resolution::Resolved {
                                    object: 0,
                                    file_offset: start + 64 + stride as u64,
                                })
                                .unwrap_or(Resolution::NullPointer);
                            FunctionRecord {
                                name: field.name.into(),
                                resolution,
                            }
                        })
                        .collect(),
                    _ => panic!("3.0 is a full standard table"),
                };
            let path = path.to_str().unwrap().to_string();
            let manifest = Manifest {
                schema: p11scope_manifest::manifest::SCHEMA.into(),
                module_path: path.clone(),
                objects: vec![ObjectRecord {
                    id: 0,
                    path: path.clone(),
                    identity: inspected.identity.clone(),
                }],
                provenance_objects: vec![ProvenanceObject {
                    path,
                    device_major: mapping.device_major,
                    device_minor: mapping.device_minor,
                    inode: mapping.inode,
                    identity: inspected.identity,
                }],
                interface_list: Acquisition::Ok,
                surfaces: vec![
                    SurfaceRecord {
                        source: SurfaceSource::LegacyFunctionList,
                        acquisition: Acquisition::Ok,
                        version: Some(Version {
                            major: 2,
                            minor: 40,
                        }),
                        walk: WalkOutcome::Full,
                        functions,
                    },
                    SurfaceRecord {
                        source: SurfaceSource::Interface {
                            index: 0,
                            raw_name_hex: Some("504b4353203131".into()),
                            name_lossy: Some("PKCS 11".into()),
                            name_error: None,
                            flags: 0,
                            classification: InterfaceClassification::ExactStandard,
                        },
                        acquisition: Acquisition::Ok,
                        version: Some(Version { major: 3, minor: 0 }),
                        walk: WalkOutcome::Full,
                        functions: message_functions,
                    },
                ],
                vendor_interfaces: Vec::new(),
                alias_groups: Vec::new(),
                selection_evidence: Default::default(),
            };
            let problems = crate::manifest_input::validate_structure(&manifest);
            assert!(problems.is_empty(), "fixture manifest: {problems:?}");
            let pinning =
                crate::discovery::identity::pin_manifest_objects_deferred(&manifest).unwrap();
            assert!(pinning.stale.is_empty());
            let pins = pinning.pins;
            let operator = dir.path().join("operator-input.json");
            std::fs::write(&operator, serde_json::to_vec(&manifest).unwrap()).unwrap();
            let engine =
                crate::discovery::engine::inventory_coordinator::semantics::engine_for_test(
                    Vec::new(),
                    Vec::new(),
                    pins.clone(),
                );
            let prepared =
                crate::discovery::engine::inventory_coordinator::semantics::prepare_attested_subset(
                    &engine,
                    std::slice::from_ref(&operator),
                );
            let subset = prepared.subset.expect("nonempty validated operator subset");
            let mut functions = BTreeMap::new();
            for name in admitted_functions {
                let slot = subset
                    .plan()
                    .slots
                    .iter()
                    .find(|slot| slot.names.len() == 1 && slot.names[0] == name)
                    .unwrap_or_else(|| {
                        let names: Vec<_> = subset
                            .plan()
                            .slots
                            .iter()
                            .map(|slot| slot.names.clone())
                            .collect();
                        panic!("{name} slot; have {names:?}")
                    });
                functions.insert(
                    name.to_string(),
                    (
                        slot.index,
                        Endpoint {
                            object: slot.object,
                            file_slot: 0,
                            offset: slot.file_offset,
                        },
                    ),
                );
            }
            let pin = pins.pinned().next().unwrap();
            let module = ModuleKey::physical(
                pin.key.device.major,
                pin.key.device.minor,
                pin.key.inode,
                Some(pin.sha256.to_owned()),
                pin.path,
            );
            let domain = NativeDomainId::mint();
            // The bound incarnation is an owned sleeper, not the test
            // process: custody tests reap the exact pin the primary
            // binding holds, and the drop above reaps every spawn.
            let child = std::process::Command::new("/bin/sleep")
                .arg("120")
                .spawn()
                .unwrap();
            let pid = child.id();
            // The happy-path binding traverses the coordinator's real
            // bind proof (live incarnation, original pin, established
            // mapping, bracketed sightings) — never scripted. The
            // extend receipt activates roots exactly as in production
            // scenes; the bind below proves this domain's image.
            let mut coordinator =
                crate::discovery::engine::inventory_coordinator::InventoryCoordinator::new(
                    crate::attach::Scope::Pid(pid),
                    crate::discovery::hooks::HookRegistry::builtin(),
                    Vec::new(),
                    crate::discovery::caller_registry::OsProcessSource,
                    crate::discovery::caller_registry::RegistryLimits::default_limits(),
                )
                .unwrap();
            coordinator.note_extend_receipt(&crate::attach::capture::ExtendReceipt {
                activated_roots: true,
                exec_coverage: Some(crate::attach::capture::ExecCoverage::scripted(domain, 0)),
                ..crate::attach::capture::ExtendReceipt::default()
            });
            coordinator.set_semantic_binding_clock(bind_sight_clock);
            let mut identity = BindIdentity::default();
            let primary =
                genuine_bind(&mut coordinator, &mut identity, pid, &module, domain, image);
            let router = Self::route(domain, image);
            // Seal this fixture's attachment from its attested subset,
            // then re-attest a working subset for admissions from the
            // same authority: both envelopes are genuinely attested, so
            // admits and the sealed attachment share one domain without
            // ordering constraints.
            let attachment = crate::attach::seal_test_attachment(subset, domain, &pins);
            let prepared =
                crate::discovery::engine::inventory_coordinator::semantics::prepare_attested_subset(
                    &engine,
                    &[operator],
                );
            let subset = prepared.subset.expect("re-attested working subset");
            Self {
                _dir: dir,
                subset: Some(subset),
                coordinator,
                identity,
                primary,
                domain,
                image,
                router,
                functions,
                next_token: 0,
                attachment,
                child,
            }
        }

        /// The fixture's minted native domain: the Session-side
        /// native identity its admissions name.
        pub(crate) fn domain(&self) -> NativeDomainId {
            self.domain
        }

        pub(crate) fn provider_path(&self) -> std::path::PathBuf {
            self._dir.path().join("provider.so")
        }

        pub(crate) fn endpoint_for(&self, name: &str) -> (u32, Endpoint) {
            self.functions[name]
        }

        pub(crate) fn admit_collected(&mut self, call: RoutedCall) -> AdmittedInstanceCall {
            self.admit_collected_for(call, None)
        }

        /// Admit against an existing genuinely bound caller, never a caller
        /// number supplied as proof. Used by the two-image raw-loss fixture.
        pub(crate) fn admit_collected_for(
            &mut self,
            call: RoutedCall,
            caller: Option<crate::discovery::caller_registry::CallerId>,
        ) -> AdmittedInstanceCall {
            self.next_token = self
                .next_token
                .max(call.position().expect("actual H0 position"));
            let evidence = CallEvidence::from_routed(call).expect("actual H0 joined call");
            admit_call_from_evidence(
                evidence,
                self.binding_for_collected(caller),
                self.subset.as_ref().expect("subset held"),
                CallStanding::Historical(InstanceReason::SemanticLoss),
                None,
            )
            .expect("actual collected call admits")
        }

        pub(crate) fn binding_for_collected(
            &self,
            caller: Option<crate::discovery::caller_registry::CallerId>,
        ) -> &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding
        {
            self.binding_for(caller.unwrap_or(self.primary))
        }

        pub(crate) fn bind_collected_image(
            &mut self,
            pid: u32,
            image: ImageIdentity,
        ) -> crate::discovery::caller_registry::CallerId {
            self.bind_extra(pid, self.domain, image)
        }

        /// The happy-path binding, genuinely bound: read back from the
        /// coordinator's stored proof.
        pub(crate) fn binding(
            &self,
        ) -> &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding
        {
            self.binding_for(self.primary)
        }

        /// Read back one genuinely bound caller.
        fn binding_for(
            &self,
            caller: crate::discovery::caller_registry::CallerId,
        ) -> &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding
        {
            self.coordinator
                .semantic_bindings()
                .get(caller)
                .expect("caller genuinely bound")
        }

        /// Genuinely bind one more caller through the same proof (for
        /// refusal crosses): any pid/domain/image, same module. The
        /// cross's domain/exec gets the same extend receipt the
        /// fixture's own domain got at construction, so the bind
        /// proof evaluates the cross's real naming.
        fn bind_extra(
            &mut self,
            pid: u32,
            domain: NativeDomainId,
            image: ImageIdentity,
        ) -> crate::discovery::caller_registry::CallerId {
            self.coordinator
                .note_extend_receipt(&crate::attach::capture::ExtendReceipt {
                    activated_roots: true,
                    exec_coverage: Some(crate::attach::capture::ExecCoverage::scripted(
                        domain,
                        image.exec_id,
                    )),
                    ..crate::attach::capture::ExtendReceipt::default()
                });
            let module = self.binding().reference_single_provider_module().clone();
            genuine_bind(
                &mut self.coordinator,
                &mut self.identity,
                pid,
                &module,
                domain,
                image,
            )
        }

        fn route(domain: NativeDomainId, image: ImageIdentity) -> InstanceId {
            let mut router = InstanceRouter::new(domain, RouterLimits::default());
            router.observe_legacy(StableObservation {
                file_slot: 0,
                reading: EpochReading {
                    cookie: image.task_cookie,
                    local: 1,
                    global: 0,
                    fault: 0,
                    record_flags: 0,
                    sticky: 0,
                },
                ranges: vec![MapRange::new(0x7000_0000, 0x7000_3000, 0, true)],
                fence: 0,
            });
            let stamp = InstanceStamp {
                epoch: 1,
                file_slot_plus1: 1,
                flags: STAMP_VALID,
                ..InstanceStamp::default()
            };
            match router.route(CallFacts {
                token: 1,
                domain,
                image,
                entry: stamp,
                ret: stamp,
                ip: EntryIp::new(0x7000_1000),
                attached_offset: Some(0x1000),
            }) {
                Route::Joined(id) => id,
                other => panic!("fixture must route a real instance: {other:?}"),
            }
        }

        /// One real admission: routed evidence through the real
        /// descriptor/binding proofs, historical standing (no coverage
        /// needed for key binding).
        fn admit(&mut self) -> AdmittedInstanceCall {
            self.admit_session(SESSION)
        }

        /// One real admission for a chosen session word.
        fn admit_session(&mut self, session: u64) -> AdmittedInstanceCall {
            self.admit_session_function(session, "C_CreateObject")
        }

        /// One real admission for a chosen function: routed evidence
        /// against that function's plan slot, through the real
        /// descriptor/binding proofs.
        pub(crate) fn admit_function(&mut self, name: &str) -> AdmittedInstanceCall {
            self.admit_session_function(SESSION, name)
        }

        /// One real admission for a chosen session word and function.
        pub(crate) fn admit_session_function(
            &mut self,
            session: u64,
            name: &str,
        ) -> AdmittedInstanceCall {
            self.admit_shaped(session, name, 0, 0, Event::default().capture, FLAGS)
        }

        /// One real admission with explicit S1 evidence shape: return
        /// code, entry mechanism, capture vocabulary and call flags
        /// ride the routed event into the proved facts. Shared with H9
        /// tests, whose S1-varied streams need failed/query/Init-shaped
        /// admissions.
        pub(crate) fn admit_shaped(
            &mut self,
            session: u64,
            name: &str,
            rv: u64,
            mechanism: u64,
            capture: u32,
            call_flags: u64,
        ) -> AdmittedInstanceCall {
            let slot = self.functions[name].0;
            self.admit_original_event(
                name,
                Event {
                    slot,
                    session,
                    slot_id: SLOT_ID,
                    flags: call_flags,
                    user_type: 1,
                    rv,
                    mechanism,
                    capture,
                    ts_ns: 100 + self.next_token + 1,
                    image: self.image,
                    ..Default::default()
                },
            )
        }

        /// The original Event is complete before routed admission. No
        /// admitted authority or private identity is rewritten afterward.
        pub(crate) fn admit_original_event(
            &mut self,
            name: &str,
            event: Event,
        ) -> AdmittedInstanceCall {
            let (slot, endpoint) = self.functions[name];
            assert_eq!(
                event.slot, slot,
                "native slot belongs to the attested function"
            );
            assert!(
                event.image == self.image,
                "original Event belongs to this image"
            );
            self.next_token += 1;
            let token = self.next_token;
            let stamp = InstanceStamp {
                epoch: 1,
                file_slot_plus1: 1,
                flags: STAMP_VALID,
                ..InstanceStamp::default()
            };
            let routed = RoutedCall::scripted(
                self.domain,
                crate::events::DecodedEventRecord {
                    joint_resource: None,
                    base: crate::semantic_capture::event_record_with_routing(event, stamp, 0x2200),
                    object: None,
                },
                Route::Joined(self.router),
                Some(endpoint),
                Some(token),
            );
            let evidence =
                CallEvidence::from_routed(routed).expect("joined call converts to evidence");
            admit_call_from_evidence(
                evidence,
                self.binding(),
                self.subset.as_ref().expect("subset held"),
                CallStanding::Historical(InstanceReason::SemanticLoss),
                None,
            )
            .expect("scripted evidence admits")
        }

        pub(crate) fn h0_allocated_below(&self) -> u64 {
            self.next_token + 1
        }

        /// Move the attested subset out (for a semantic lane): the
        /// fixture keeps its binding/router for further admissions.
        fn take_subset(&mut self) -> AttestedSubset {
            self.subset.take().expect("subset held")
        }

        /// This fixture's sealed attachment: sealed from its attested
        /// subset at construction (a working subset was re-attested
        /// for admissions), so admits and sealing share one domain
        /// without ordering constraints.
        pub(crate) fn attachment(&self) -> &crate::attach::AttachedSemanticSet {
            &self.attachment
        }
    }

    fn original_for_validated_begin(begin: &ValidatedJournalBegin) -> Event {
        Event {
            ts_ns: begin.entry_ns() + 100,
            duration_ns: 100,
            pid_tgid: begin.pid_tgid(),
            session: begin.session_word(),
            slot_id: begin.slot_id(),
            mechanism: begin.entry_mechanism(),
            flags: begin.call_flags(),
            slot: begin.slot(),
            user_type: begin.user_type(),
            capture: begin.capture(),
            image: ImageIdentity {
                task_cookie: begin.image_cookie(),
                exec_id: begin.image_exec(),
            },
            ..Event::default()
        }
    }

    /// One full journal scene: adapter, model, frozen table and H3
    /// attestation for one image.
    struct Scene {
        adapter: JournalAdapter,
        model: ObjectSemantics,
        descriptors:
            [p11scope_ebpf_common::object_wire::ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
        fixture: AttestationFixture,
        /// The Session's retained EVENTS domain (fd-backed in
        /// production): the drain-side producer behind every drain
        /// grant this scene mints. One Session retains one domain.
        retained_events: crate::events::EventsDomain,
        pending_claims: VecDeque<(String, u64)>,
        paired_admissions: BTreeMap<u64, u64>,
    }

    impl Scene {
        fn new(image: ImageIdentity) -> Self {
            Self::new_with_limits(image, JournalLimits::policy())
        }

        fn new_with_limits(image: ImageIdentity, limits: JournalLimits) -> Self {
            let descriptors = publish_object_descriptors();
            assert!(verify_object_descriptors(&descriptors));
            let mut scene = Self {
                adapter: JournalAdapter::new(limits),
                model: ObjectSemantics::new(),
                descriptors,
                fixture: AttestationFixture::new(image),
                retained_events: crate::events::EventsDomain::test_standin(7),
                pending_claims: VecDeque::new(),
                paired_admissions: BTreeMap::new(),
            };
            // The Session sealed before journal work: the adapter
            // starts under the observed closure.
            scene.install_observed_closure();
            scene
        }

        fn attest(&mut self) -> JournalDomainProof {
            self.attest_session_function(SESSION, "C_CreateObject")
        }

        /// This scene's sealed attachment: the closure generation's
        /// observed source for installs, grants and audits.
        fn attachment(&self) -> &crate::attach::AttachedSemanticSet {
            self.fixture.attachment()
        }

        /// The observed closure generation all scene seals run under.
        fn closure_generation(&self) -> u64 {
            self.attachment().generation()
        }

        /// Install the observed closure grant: every seal helper runs
        /// under the sealed attachment's generation, never a supplied
        /// integer. Best-effort (a newer installed generation stays:
        /// stale-closure tests rely on the refusal that follows).
        fn install_observed_closure(&mut self) {
            let grant = SessionClosureGrant::observe(self.attachment());
            let _ = self.adapter.install_closure_grant(&grant);
        }

        /// Attest `n` admissions for one key: every staged call needs
        /// its H3 admission claim, and counts accumulate per
        /// fingerprint. Each admission carries a distinct H0 token.
        fn attest_calls(&mut self, n: usize) -> JournalDomainProof {
            assert!(n > 0, "attest at least one call");
            let mut proof = self.attest();
            for _ in 1..n {
                proof = self.attest();
            }
            proof
        }

        /// Attest one admission for a chosen function: the staged
        /// call's H3-routed return for that function's fingerprint.
        fn attest_function(&mut self, name: &str) -> JournalDomainProof {
            self.attest_session_function(SESSION, name)
        }

        /// Attest `n` admissions for a chosen function.
        fn attest_function_n(&mut self, name: &str, n: usize) -> JournalDomainProof {
            assert!(n > 0, "attest at least one call");
            let mut proof = self.attest_function(name);
            for _ in 1..n {
                proof = self.attest_function(name);
            }
            proof
        }

        /// Attest one admission for a chosen session word and function.
        fn attest_session_function(&mut self, session: u64, name: &str) -> JournalDomainProof {
            // Bind the key separately from the paired physical invocation.
            // Zero-duration binding grants no journal call claim.
            let admitted = self.fixture.admit_session_function(session, name);
            let proof = self.adapter.attest_key(&admitted).expect("key attests");
            self.pending_claims.push_back((name.into(), session));
            proof
        }

        /// Build paired original inputs before normal routed admission.
        /// H8 algorithm fixtures deliberately substitute the I/O here;
        /// this is not the N1a production-ingress acceptance driver.
        fn prepare_claims(&mut self) {
            let image = (self.fixture.image.task_cookie, self.fixture.image.exec_id);
            if self.adapter.is_tainted(image) {
                return;
            }
            let mut inputs: Vec<(u64, u32, Event)> = self
                .adapter
                .open
                .values()
                .filter(|entry| entry.image == image && entry.converted_ticket.is_none())
                .map(|entry| {
                    let event = entry
                        .end
                        .map(|end| end.end.payload_base().event)
                        .unwrap_or_else(|| original_for_validated_begin(&entry.begin));
                    (entry.begin_ordinal, entry.function, event)
                })
                .collect();
            inputs.extend(
                self.adapter
                    .refused
                    .iter()
                    .filter(|entry| entry.image == image)
                    .map(|entry| {
                        (
                            entry.cut,
                            entry.function,
                            Event {
                                ts_ns: entry.entry_ns + 100,
                                duration_ns: 100,
                                pid_tgid: entry.pid_tgid,
                                session: entry.session,
                                slot_id: entry.slot_id,
                                mechanism: entry.mechanism,
                                flags: entry.flags,
                                slot: entry.slot,
                                user_type: entry.user_type,
                                capture: entry.capture,
                                image: ImageIdentity {
                                    task_cookie: image.0,
                                    exec_id: image.1,
                                },
                                ..Event::default()
                            },
                        )
                    }),
            );
            self.admit_paired_inputs(inputs);
        }

        fn admit_paired_inputs(&mut self, mut inputs: Vec<(u64, u32, Event)>) {
            inputs.sort_by_key(|input| input.0);
            for (cut, function, event) in inputs {
                if self.paired_admissions.contains_key(&cut) {
                    continue;
                }
                let Some(index) = self.pending_claims.iter().position(|(name, session)| {
                    function_id(name) == function && *session == event.session
                }) else {
                    continue;
                };
                let (name, _) = self
                    .pending_claims
                    .remove(index)
                    .expect("selected fixture input");
                let admitted = self.fixture.admit_original_event(&name, event);
                self.adapter
                    .attest_key(&admitted)
                    .expect("paired input admits");
                self.paired_admissions.insert(cut, admitted.h0_ordinal());
            }
        }

        /// Explicit scripted wire inputs are paired before routed H0
        /// admission and collection. This is an algorithm/drain fixture,
        /// not the outstanding N1a production single-cursor driver.
        fn prepare_record_claims(&mut self, records: &[Vec<u8>]) {
            let decoded: Vec<_> = records
                .iter()
                .enumerate()
                .filter_map(|(index, bytes)| {
                    decode_journal_record(bytes, &self.descriptors)
                        .map(|record| (self.adapter.consumed_through + index as u64 + 1, record))
                })
                .collect();
            let inputs = decoded
                .iter()
                .filter_map(|(cut, record)| {
                    let JournalRecord::Begin(begin) = record else {
                        return None;
                    };
                    if (begin.image_cookie(), begin.image_exec())
                        != (self.fixture.image.task_cookie, self.fixture.image.exec_id)
                    {
                        return None;
                    }
                    let event = decoded
                        .iter()
                        .find_map(|(_, record)| {
                            let JournalRecord::End(end) = record else {
                                return None;
                            };
                            (end.thread() == begin.thread() && end.sequence() == begin.sequence())
                                .then(|| end.payload_base().event)
                        })
                        .unwrap_or_else(|| original_for_validated_begin(begin));
                    Some((*cut, begin.descriptor() - 1, event))
                })
                .collect();
            self.admit_paired_inputs(inputs);
        }

        fn admit_other_end(
            &mut self,
            other: &mut AttestationFixture,
            name: &str,
            end: &[u8],
        ) -> JournalDomainProof {
            let JournalRecord::End(end) = decode_journal_record(end, &self.descriptors).unwrap()
            else {
                panic!("paired END")
            };
            // These algorithm fixtures model one H0 allocator across
            // two admitted callers. Advance the input allocator before
            // normal admission; no admitted identity is rewritten.
            other.next_token = other.next_token.max(self.fixture.next_token);
            let admitted = other.admit_original_event(name, end.payload_base().event);
            self.fixture.next_token = other.next_token;
            self.adapter
                .attest_key(&admitted)
                .expect("paired sibling return attests")
        }

        /// This scene's retained drain producers: its fixture's
        /// minted native domain plus its retained test EVENTS domain.
        fn producers(&self) -> crate::attach::SessionDrainProducers {
            crate::attach::SessionDrainProducers::test_pair(
                self.fixture.domain(),
                self.retained_events.clone(),
            )
        }

        /// Mint the Session's drain↔domain association from its own
        /// retained producer pair plus an admission. The joint tick
        /// calls the same mint in production.
        fn mint_drain_grant(&mut self) -> SessionDrainGrant {
            let admitted = self.fixture.admit();
            SessionDrainGrant::observe(&self.producers(), &admitted)
                .expect("the scene's own admission mints")
        }

        /// Session authority binds this scene's retained drain to the
        /// attested native domain, before any collection: the joint
        /// tick's bind step. The domain must have attested first.
        fn bind_session_drain(&mut self) {
            let grant = self.mint_drain_grant();
            self.adapter
                .bind_session_drain(&grant)
                .expect("session drain binds");
        }

        fn ingest(&mut self, bytes: &[u8]) -> JournalDisposition {
            use p11scope_ebpf_common::object_journal::decode_journal_record;
            let record =
                decode_journal_record(bytes, &self.descriptors).expect("test bytes decode");
            self.adapter.ingest_any(JournalIngestItem::Journal(record))
        }

        fn ingest_ordinary(&mut self, event: Event) -> JournalDisposition {
            let decoded = crate::events::DecodedEventRecord {
                joint_resource: None,
                base: crate::semantic_capture::event_record_with_routing(
                    event,
                    InstanceStamp::default(),
                    0,
                ),
                object: None,
            };
            self.adapter
                .ingest_any(JournalIngestItem::Ordinary(decoded))
        }

        /// Lower-level ordinal/chain algorithm input only. The actual H0
        /// admission/cut acceptance is exercised by the retained-birth rig.
        fn ingest_algorithm_quiet(&mut self, event: Event) -> JournalDisposition {
            let decoded = crate::events::DecodedEventRecord {
                joint_resource: None,
                base: crate::semantic_capture::event_record_with_routing(
                    event,
                    InstanceStamp::default(),
                    0,
                ),
                object: None,
            };
            self.adapter
                .ingest_any_from_raw(JournalIngestItem::Ordinary(decoded), None, true)
        }

        fn audit(&mut self) -> JournalAuditReceipt {
            self.prepare_claims();
            JournalAuditReceipt::scripted(
                7,
                7,
                None,
                0,
                H3DispositionEvidence::scripted_clean(self.fixture.next_token),
                self.closure_generation(),
            )
        }

        fn seal(&mut self, bootstrap: &BootstrapReceipt) -> Result<SealSuccess, SealFailure> {
            self.install_observed_closure();
            let frontier = self.adapter.consumed_frontier();
            let audit = self.audit();
            let fresh = SessionBirthEvidence::scripted_for_receipt(bootstrap);
            self.seal_explicit(&audit, bootstrap, frontier, fresh)
        }

        /// One seal under an explicit fault epoch: for post-void
        /// resumptions, whose cumulative baseline advanced past the
        /// default steady epoch.
        fn seal_at(
            &mut self,
            bootstrap: &BootstrapReceipt,
            epoch: u64,
        ) -> Result<SealSuccess, SealFailure> {
            self.install_observed_closure();
            self.prepare_claims();
            let frontier = self.adapter.consumed_frontier();
            let audit = JournalAuditReceipt::scripted(
                epoch,
                epoch,
                None,
                0,
                H3DispositionEvidence::scripted_clean(self.fixture.next_token),
                self.closure_generation(),
            );
            let fresh = SessionBirthEvidence::scripted_for_receipt(bootstrap);
            self.seal_explicit(&audit, bootstrap, frontier, fresh)
        }

        /// One seal against an explicit audit: the seal-time native
        /// cell reads the audited epoch (a steady collection), so only
        /// the audit's own evidence decides. Tests pinning seal-time
        /// moves call the adapter directly with their own cell.
        fn seal_explicit(
            &mut self,
            audit: &JournalAuditReceipt,
            bootstrap: &BootstrapReceipt,
            frontier: ConsumptionOrdinal,
            fresh: SessionBirthEvidence,
        ) -> Result<SealSuccess, SealFailure> {
            self.install_observed_closure();
            self.prepare_claims();
            let cell = ScriptedFaultCell::steady(audit.fault_after);
            let mut births = ScriptedBirthSource::once(fresh);
            self.adapter.seal(
                &mut self.model,
                audit,
                bootstrap,
                frontier,
                &mut births,
                &cell,
            )
        }

        fn bootstrap(&self, proof: JournalDomainProof, birth_cut: u64) -> BootstrapReceipt {
            BootstrapReceipt::scripted(
                proof,
                BirthKind::ExecMarker,
                birth_cut,
                self.closure_generation(),
            )
        }

        /// One production collection over scripted ring bytes: the real
        /// dispatch poll, real decode, real malformed accounting and the
        /// scripted fault cell. Binds the scene drain first (the joint
        /// tick's bind step; idempotent across collections). The drain
        /// runs over this scene's own retained EVENTS identity.
        fn collect_records(
            &mut self,
            records: Vec<Vec<u8>>,
            fault: &impl FaultEpoch,
        ) -> JournalCollection {
            self.bind_session_drain();
            self.prepare_record_claims(&records);
            let bound = records.len();
            let mut drain = crate::events::EventDrain::over_test_domain(
                crate::events::ScriptedRecords::records(records, bound),
                self.retained_events.id(),
            );
            self.adapter.collect_from_drain(
                &mut drain,
                &self.descriptors,
                Some(bound),
                fault,
                self.fixture.h0_allocated_below(),
            )
        }

        /// One seal from a real collection: H3 disposition covers the
        /// consumed frontier, closure observed from the attachment.
        fn seal_collected(
            &mut self,
            bootstrap: &BootstrapReceipt,
            collection: &JournalCollection,
        ) -> Result<SealSuccess, SealFailure> {
            let h3 = H3DispositionEvidence::scripted_clean(self.fixture.next_token);
            let mut source = ScriptedH3Source::once(h3);
            let audit =
                JournalAuditReceipt::collect(collection, &mut source, self.closure_generation());
            let frontier = self.adapter.consumed_frontier();
            let fresh = SessionBirthEvidence::scripted_for_receipt(bootstrap);
            self.seal_explicit(&audit, bootstrap, frontier, fresh)
        }

        /// One bounded dispatch drain to a stop: the real proven-Q poll
        /// with both consumers ingesting in delivery order.
        fn drain_bounded_to<S: crate::events::BoundedRecordSource>(
            &mut self,
            drain: &mut crate::events::EventDrain<S>,
            stop: usize,
        ) -> anyhow::Result<(bool, bool)> {
            let staged = std::cell::RefCell::new(Vec::new());
            let outcome = crate::events::poll_dispatched_records_to_position(
                drain,
                stop,
                None,
                &self.descriptors,
                |decoded| {
                    staged
                        .borrow_mut()
                        .push(JournalIngestItem::Ordinary(decoded));
                    std::ops::ControlFlow::Continue(())
                },
                |record| {
                    staged.borrow_mut().push(JournalIngestItem::Journal(record));
                    std::ops::ControlFlow::Continue(())
                },
            )?;
            for item in staged.take() {
                self.adapter.ingest_any(item);
            }
            Ok(outcome)
        }
    }

    /// The scripted equivalent of the session's mmapable fault cell:
    /// steady, sequenced (for mid-tick changes) or failing reads, with
    /// the production saturation rule mirrored exactly.
    struct ScriptedFaultCell {
        values: Vec<u64>,
        at: std::cell::Cell<usize>,
        fail: bool,
    }

    impl ScriptedFaultCell {
        fn steady(epoch: u64) -> Self {
            Self {
                values: vec![epoch],
                at: std::cell::Cell::new(0),
                fail: false,
            }
        }

        fn sequence(values: Vec<u64>) -> Self {
            Self {
                values,
                at: std::cell::Cell::new(0),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                values: vec![0],
                at: std::cell::Cell::new(0),
                fail: true,
            }
        }
    }

    impl FaultEpoch for ScriptedFaultCell {
        fn fault_epoch(&self) -> Result<u64, FaultReadError> {
            if self.fail {
                return Err(FaultReadError::Unreadable);
            }
            let index = self.at.get().min(self.values.len() - 1);
            self.at.set(self.at.get() + 1);
            let epoch = self.values[index];
            if epoch > u64::from(u32::MAX) {
                return Err(FaultReadError::Saturated);
            }
            Ok(epoch)
        }
    }

    /// A scripted ring that goes BUSY on schedule through the real reader
    /// seams: `busy_after` injects one live-path stall (the poll ends with
    /// the cursor held, like Aya's BUSY skip) after that many records,
    /// and `pending_before` injects that many bounded-path Pending
    /// outcomes before items flow.
    struct BusyScript {
        queue: std::collections::VecDeque<Vec<u8>>,
        taken: usize,
        busy_after: Option<usize>,
        busy_done: bool,
        pending_before: usize,
        discarded: u64,
        /// (taken count, bump): when `taken` reaches the count mid-poll
        /// the reader reports the bump as freshly consumed discards,
        /// modelling the Aya reader's counting consume.
        discard_bump: Option<(usize, u64)>,
        discard_bumped: bool,
    }

    impl BusyScript {
        fn new(records: Vec<Vec<u8>>) -> Self {
            Self {
                queue: records.into(),
                taken: 0,
                busy_after: None,
                busy_done: false,
                pending_before: 0,
                discarded: 0,
                discard_bump: None,
                discard_bumped: false,
            }
        }
    }

    impl crate::events::RecordSource for BusyScript {
        fn next_record(&mut self) -> Option<impl std::ops::Deref<Target = [u8]> + '_> {
            if !self.busy_done && self.busy_after == Some(self.taken) {
                self.busy_done = true;
                return None;
            }
            let item = self.queue.pop_front()?;
            self.taken += 1;
            if !self.discard_bumped
                && let Some((at, bump)) = self.discard_bump
                && at == self.taken
            {
                self.discard_bumped = true;
                self.discarded += bump;
            }
            Some(item)
        }

        fn discarded(&self) -> u64 {
            self.discarded
        }
    }

    impl crate::events::BoundedRecordSource for BusyScript {
        fn positions(&self) -> aya::maps::ring_buf::RingBufPositions {
            aya::maps::ring_buf::RingBufPositions {
                consumer: self.taken * 8,
                producer: (self.taken + self.queue.len()) * 8,
                capacity: 4096,
            }
        }

        fn consumer(&self) -> usize {
            self.taken * 8
        }

        fn bounded_record(
            &mut self,
            stop: usize,
        ) -> anyhow::Result<crate::events::BoundedRecord<impl std::ops::Deref<Target = [u8]> + '_>>
        {
            if self.pending_before > 0 {
                self.pending_before -= 1;
                return Ok(crate::events::BoundedRecord::Pending);
            }
            if self.taken * 8 == stop {
                return Ok(crate::events::BoundedRecord::Reached);
            }
            match self.queue.pop_front() {
                Some(item) => {
                    self.taken += 1;
                    Ok(crate::events::BoundedRecord::Item(item))
                }
                None => Ok(crate::events::BoundedRecord::Pending),
            }
        }
    }

    fn image_default() -> ImageIdentity {
        ImageIdentity {
            task_cookie: COOKIE,
            exec_id: EXEC,
        }
    }

    #[test]
    fn object_journal_neutral_vocabulary_is_finite() {
        // Exactly the 41 frozen names, distinct and in plan order.
        assert_eq!(NEUTRAL_S1_FUNCTIONS.len(), 41);
        let mut sorted = NEUTRAL_S1_FUNCTIONS;
        sorted.sort_unstable();
        for pair in sorted.windows(2) {
            assert_ne!(pair[0], pair[1], "neutral names are distinct");
        }
        assert_eq!(NEUTRAL_S1_FUNCTIONS[0], "C_DigestInit");
        assert_eq!(NEUTRAL_S1_FUNCTIONS[40], "C_VerifySignatureFinal");

        for name in NEUTRAL_S1_FUNCTIONS {
            // Exact accepted catalog/descriptor agreement for every name.
            let id = crate::kinds::function_id(name)
                .unwrap_or_else(|| panic!("{name} resolves in the catalog"));
            assert!(
                crate::kinds::descriptor(name).is_some(),
                "{name} has an accepted capture descriptor"
            );
            // No object row: object descriptors retain precedence, so no
            // neutral name may collide with the object policy.
            assert!(
                crate::kinds::object_descriptor(name).is_none(),
                "{name} carries no object descriptor"
            );
            assert!(is_neutral_function(id), "{name} classifies neutral");
        }

        // Prefix-similar and neighboring functions are not neutral by
        // analogy: key-bearing Inits (object), DigestKey (object), Find
        // lifecycle, token init, wrap and message-Init neighbors.
        for name in [
            "C_SignInit",
            "C_SignRecoverInit",
            "C_VerifyInit",
            "C_VerifyRecoverInit",
            "C_EncryptInit",
            "C_DecryptInit",
            "C_MessageSignInit",
            "C_MessageVerifyInit",
            "C_VerifySignatureInit",
            "C_DigestKey",
            "C_FindObjectsInit",
            "C_FindObjects",
            "C_InitToken",
            "C_WrapKey",
            "C_UnwrapKey",
            "C_DeriveKey",
            "C_OpenSession",
            "C_CloseSession",
            "C_Login",
            "C_GetInfo",
            "C_GetFunctionList",
            "C_GenerateRandom",
            "C_SeedRandom",
        ] {
            let id = crate::kinds::function_id(name)
                .unwrap_or_else(|| panic!("{name} resolves in the catalog"));
            assert!(!is_neutral_function(id), "{name} is not neutral");
        }
        // Unknown ordinals are not neutral.
        assert!(!is_neutral_function(u32::MAX));
        assert!(!is_neutral_function(10_000));

        // Object precedence is structural: every object-policy function
        // classifies through the object arm first (checked again by the
        // model's classifier test), so neutral membership can never shadow
        // a key-bearing call.
        for name in [
            "C_CreateObject",
            "C_DestroyObject",
            "C_GetAttributeValue",
            "C_SetAttributeValue",
            "C_SignInit",
            "C_DigestKey",
        ] {
            let id = crate::kinds::function_id(name).expect("catalog");
            assert!(
                p11scope_ebpf_common::object_policy::object_descriptor(id).is_some(),
                "{name} keeps its object row"
            );
            assert!(!is_neutral_function(id));
        }
    }

    #[test]
    fn object_journal_abandon_reason_matrix_is_finite() {
        use p11scope_ebpf_common::object_journal::{
            JOURNAL_REASON_ABI_REFUSED, JOURNAL_REASON_ENTRY_COLLISION, JOURNAL_REASON_EXEC_EXIT,
            JOURNAL_REASON_IDENTITY_REFUSED, JOURNAL_REASON_INSERT_FAILED,
            JOURNAL_REASON_PARTIAL_TRANSACTION, JOURNAL_REASON_SCOPE_LOST,
            JOURNAL_REASON_STOP_CLEANUP, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
        };
        // Eight unbounded reasons, one bounded-witness candidate, in frozen
        // code order; every code has a finite wire label.
        let unbounded = [
            (JOURNAL_REASON_ENTRY_COLLISION, 1u32),
            (JOURNAL_REASON_INSERT_FAILED, 2),
            (JOURNAL_REASON_SCOPE_LOST, 3),
            (JOURNAL_REASON_ABI_REFUSED, 4),
            (JOURNAL_REASON_IDENTITY_REFUSED, 5),
            (JOURNAL_REASON_EXEC_EXIT, 6),
            (JOURNAL_REASON_STOP_CLEANUP, 7),
            (JOURNAL_REASON_PARTIAL_TRANSACTION, 8),
        ];
        for (code, expected) in unbounded {
            assert_eq!(code, expected);
            assert_eq!(
                abandon_disposition(code),
                Some(AbandonDisposition::UnboundedInvalidation)
            );
            assert!(
                p11scope_ebpf_common::object_journal::reason_name(code).is_some(),
                "reason {code} has a finite label"
            );
        }
        assert_eq!(JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, 9);
        assert_eq!(
            abandon_disposition(JOURNAL_REASON_SYNC_RETURN_RESULT_LOST),
            Some(AbandonDisposition::BoundedWitnessCandidate)
        );
        // Unknown codes have neither disposition nor label.
        for code in [0u32, 10, 99, u32::MAX] {
            assert_eq!(abandon_disposition(code), None);
            assert_eq!(
                p11scope_ebpf_common::object_journal::reason_name(code),
                None
            );
        }
    }

    const RV_FAILED: u64 = 0x07;

    fn rv_pending() -> u64 {
        pkcs11_types::CkRv::PENDING.0
    }

    fn has_effect(effects: &ObjectEffects, want: &str) -> bool {
        effects.effects.iter().any(|effect| match effect {
            ObjectEffect::Created { .. } => want == "created",
            ObjectEffect::Referenced { .. } => want == "referenced",
            ObjectEffect::FirstObserved { .. } => want == "first-observed",
            ObjectEffect::Destroyed { .. } => want == "destroyed",
            ObjectEffect::Retired { .. } => want == "retired",
            ObjectEffect::Unresolved { .. } => want == "unresolved",
            ObjectEffect::Gap { .. } => want == "gap",
            _ => false,
        })
    }

    #[test]
    fn object_journal_start_terminal_matrix() {
        use p11scope_ebpf_common::object_journal::JOURNAL_BEGIN_NO_END;
        use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_CREATE, OBJECT_ACTION_DESTROY};

        // Healthy creation through real admission, decode, ingest and seal.
        {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
            let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
            assert_eq!(scene.ingest(&end), JournalDisposition::EndStaged);
            let bootstrap = scene.bootstrap(proof, 0);
            let success = scene.seal(&bootstrap).expect("healthy seal passes");
            assert_eq!(success.prefix.settled().len(), 1);
            assert!(success.prefix.open_keys().is_empty());
            assert!(has_effect(&success.effects, "created"));
            assert_eq!(scene.model.project().objects.len(), 1);
        }

        // Creation then destruction of the minted handle settles both.
        {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            scene.attest_function("C_DestroyObject");
            let create = function_id("C_CreateObject");
            let destroy = function_id("C_DestroyObject");
            let begin = begin_bytes(1, 1, create, 0);
            scene.ingest(&begin);
            scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
            let mut kill = begin_bytes(1, 2, destroy, 0);
            put_u64(&mut kill, 88, 0x9090_9090_9090_9090);
            kill[126] = 1;
            scene.ingest(&kill);
            scene.ingest(&end_bytes(&kill, OBJECT_ACTION_DESTROY, 0, ENTRY_NS + 60));
            let bootstrap = scene.bootstrap(proof, 0);
            let success = scene.seal(&bootstrap).expect("create+destroy seal passes");
            assert!(has_effect(&success.effects, "created"));
            assert!(has_effect(&success.effects, "destroyed"));
            let objects = &scene.model.project().objects;
            assert_eq!(objects.len(), 1);
            assert_eq!(
                objects[0].lifetime,
                crate::semantics_objects::Lifetime::Destroyed
            );
        }

        // A neutral call seals through the absent-tail path with no
        // object effect: ordering only.
        {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest_function("C_Sign");
            let sign = function_id("C_Sign");
            let begin = begin_bytes(1, 1, sign, 0);
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
            assert_eq!(
                scene.ingest(&end_bytes_absent(&begin, 0, ENTRY_NS + 50)),
                JournalDisposition::EndStaged
            );
            let bootstrap = scene.bootstrap(proof, 0);
            let success = scene.seal(&bootstrap).expect("neutral seal passes");
            assert_eq!(success.prefix.settled().len(), 1);
            assert!(success.prefix.open_keys().is_empty());
            assert!(!has_effect(&success.effects, "created"));
            assert!(!has_effect(&success.effects, "referenced"));
            assert!(!has_effect(&success.effects, "destroyed"));
            assert!(scene.model.project().objects.is_empty());
        }

        // Failed and pending terminals settle without creating objects.
        for rv in [RV_FAILED, rv_pending()] {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            scene.ingest(&begin);
            scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, rv, ENTRY_NS + 50));
            let bootstrap = scene.bootstrap(proof, 0);
            let success = scene.seal(&bootstrap).expect("error seal passes");
            assert!(!has_effect(&success.effects, "created"));
            assert!(scene.model.project().objects.is_empty());
        }

        // Terminal before BEGIN invalidates; re-ingest never double-admits.
        {
            let mut scene = Scene::new(image_default());
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
            assert_eq!(
                scene.ingest(&end),
                JournalDisposition::Contradiction(JournalContradiction::TerminalBeforeBegin)
            );
            // The image is tainted: attestation refuses and ingest refuses.
            let admitted = scene.fixture.admit();
            assert_eq!(
                scene.adapter.attest_key(&admitted),
                Err(AttestationRefusal::ImageTainted)
            );
            assert_eq!(scene.ingest(&begin), JournalDisposition::Refused);
        }

        // Duplicate BEGIN, duplicate END and NO_END completion contradict.
        {
            let mut scene = Scene::new(image_default());
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
            assert_eq!(
                scene.ingest(&begin),
                JournalDisposition::Contradiction(JournalContradiction::DuplicateBegin)
            );
        }
        {
            let mut scene = Scene::new(image_default());
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            scene.ingest(&begin);
            let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
            assert_eq!(scene.ingest(&end), JournalDisposition::EndStaged);
            assert_eq!(
                scene.ingest(&end),
                JournalDisposition::Contradiction(JournalContradiction::DuplicateTerminal)
            );
        }
        {
            let mut scene = Scene::new(image_default());
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, JOURNAL_BEGIN_NO_END);
            scene.ingest(&begin);
            let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
            assert_eq!(
                scene.ingest(&end),
                JournalDisposition::Contradiction(JournalContradiction::NoEndCompleted)
            );
        }

        // Sequence regression contradicts, including across a sealed
        // frontier: floors never reset.
        {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            let create = function_id("C_CreateObject");
            let first = begin_bytes(1, 5, create, 0);
            scene.ingest(&first);
            let bootstrap = scene.bootstrap(proof, 0);
            scene.seal(&bootstrap).expect("first seal passes");
            let regressed = begin_bytes(1, 3, create, 0);
            assert_eq!(
                scene.ingest(&regressed),
                JournalDisposition::Contradiction(JournalContradiction::SequenceRegression)
            );
        }
    }

    #[test]
    fn object_journal_abandon_unbounded_invalidates_scope() {
        use p11scope_ebpf_common::object_journal::{
            JOURNAL_REASON_ENTRY_COLLISION, JOURNAL_REASON_EXEC_EXIT,
            JOURNAL_REASON_IDENTITY_REFUSED,
        };
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // A nested same-slot call abandons the outer START; the outer
        // provider frame resumes and another thread uses a colliding
        // handle. No terminal, rescan or rebootstrap recovers the
        // incarnation's object proof.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(2);
        let create = function_id("C_CreateObject");
        let outer = begin_bytes(1, 1, create, 0);
        let inner = begin_bytes(1, 2, create, 0);
        assert_eq!(scene.ingest(&outer), JournalDisposition::BeginAdmitted);
        assert_eq!(scene.ingest(&inner), JournalDisposition::BeginAdmitted);
        let abandon = abandon_bytes(1, 1, JOURNAL_REASON_ENTRY_COLLISION, (COOKIE, EXEC));
        assert_eq!(scene.ingest(&abandon), JournalDisposition::AbandonStaged);
        let bootstrap = scene.bootstrap(proof, 0);
        let failure = scene
            .seal(&bootstrap)
            .expect_err("unbounded abandon refuses the seal");
        assert_eq!(failure.gap, JournalGap::DomainTainted);
        // The refusal reports its invalidation; nothing is swallowed.
        assert!(has_effect(&failure.effects, "gap"));
        assert!(scene.model.project().objects.is_empty());

        // No rebootstrap while the image is still clean: a fresh birth
        // cut still meets the refused key.
        let readmitted = scene.fixture.admit();
        let reproof = scene.adapter.attest_key(&readmitted).expect("key rebinds");
        let rebootstrap = scene.bootstrap(reproof, scene.adapter.consumed_through);
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let retry = scene
            .seal_explicit(
                &audit,
                &rebootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&rebootstrap),
            )
            .expect_err("refused key never reseals");
        assert_eq!(retry.gap, JournalGap::DomainTainted);
        // The outer provider frame resumes with a late END: terminal
        // before BEGIN on disposed custody, never a completion.
        let late = end_bytes(&outer, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 90);
        assert_eq!(
            scene.ingest(&late),
            JournalDisposition::Contradiction(JournalContradiction::TerminalBeforeBegin)
        );
        // The image is now tainted too: re-attestation refuses, and another
        // thread's colliding handle use meets refused custody.
        let readmitted = scene.fixture.admit();
        assert_eq!(
            scene.adapter.attest_key(&readmitted),
            Err(AttestationRefusal::ImageTainted)
        );
        let colliding = begin_bytes(2, 1, create, 0);
        assert_eq!(scene.ingest(&colliding), JournalDisposition::Refused);
        assert!(scene.model.project().objects.is_empty());
        assert!(scene.model.project().gap(super::ObjectGap::Loss) >= 1);

        // Every other unbounded reason refuses identically.
        for reason in [
            JOURNAL_REASON_ENTRY_COLLISION,
            2,
            3,
            4,
            JOURNAL_REASON_IDENTITY_REFUSED,
            JOURNAL_REASON_EXEC_EXIT,
            7,
            8,
        ] {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            let begin = begin_bytes(1, 1, create, 0);
            scene.ingest(&begin);
            scene.ingest(&abandon_bytes(1, 1, reason, (COOKIE, EXEC)));
            let bootstrap = scene.bootstrap(proof, 0);
            let failure = scene
                .seal(&bootstrap)
                .expect_err("unbounded reason refuses the seal");
            assert_eq!(failure.gap, JournalGap::DomainTainted, "reason {reason}");
            assert!(scene.model.project().objects.is_empty());
        }

        // Stop with a held call invalidates and refuses; the provider's
        // late terminal meets a stopped adapter, never a rebootstrap.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let held = begin_bytes(1, 1, create, 0);
        scene.ingest(&held);
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene.seal(&bootstrap).expect("open call seals listed");
        assert_eq!(success.prefix.open_keys().len(), 1);
        let stopped = scene.adapter.stop(&mut scene.model);
        assert!(
            has_effect(&stopped, "gap") || scene.model.project().gap(super::ObjectGap::Loss) >= 1
        );
        let late = end_bytes(&held, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 90);
        assert_eq!(scene.ingest(&late), JournalDisposition::Refused);
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let retry = scene
            .seal_explicit(
                &audit,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("stopped adapter never seals");
        assert_eq!(retry.gap, JournalGap::Stopped);
        let readmitted = scene.fixture.admit();
        assert_eq!(
            scene.adapter.attest_key(&readmitted),
            Err(AttestationRefusal::Stopped)
        );
        assert!(scene.model.project().objects.is_empty());

        // An unrelated proved scope stays useful on the same adapter.
        let mut scene = Scene::new(image_default());
        let proof_a = scene.attest();
        let other_image = ImageIdentity {
            task_cookie: COOKIE + 1,
            exec_id: EXEC,
        };
        let mut other = AttestationFixture::new(other_image);
        let proof_b = scene
            .adapter
            .attest_key(&other.admit())
            .expect("second key attests");
        let doomed = begin_bytes(1, 1, create, 0);
        scene.ingest(&doomed);
        scene.ingest(&abandon_bytes(
            1,
            1,
            JOURNAL_REASON_ENTRY_COLLISION,
            (COOKIE, EXEC),
        ));
        let bootstrap_a = scene.bootstrap(proof_a, 0);
        assert_eq!(
            scene.seal(&bootstrap_a).expect_err("A refuses").gap,
            JournalGap::DomainTainted
        );
        let healthy = begin_bytes_image(2, 1, create, 0, (COOKIE + 1, EXEC));
        scene.admit_other_end(
            &mut other,
            "C_CreateObject",
            &end_bytes(&healthy, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50),
        );
        assert_eq!(scene.ingest(&healthy), JournalDisposition::BeginAdmitted);
        scene.ingest(&end_bytes(&healthy, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap_b = scene.bootstrap(proof_b, 1);
        let success = scene.seal(&bootstrap_b).expect("B seals");
        assert!(has_effect(&success.effects, "created"));

        // Unknown scope (fault change) voids every staged scope at once
        // and fences the loss explicitly; resumption names the fence and
        // proves new history above it, never below it and never vacuous.
        let audit = JournalAuditReceipt::scripted(
            7,
            8,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            scene.closure_generation(),
        );
        let frontier = scene.adapter.consumed_frontier();
        let failure = scene
            .seal_explicit(
                &audit,
                &bootstrap_b,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap_b),
            )
            .expect_err("fault change refuses");
        assert_eq!(failure.gap, JournalGap::FaultChanged);
        // The void is explicit: proved views retire and the loss counter
        // records the fenced interval.
        assert!(has_effect(&failure.effects, "retired"));
        assert!(scene.model.project().gap(super::ObjectGap::OutcomeLost) >= 1);
        let reproof = scene
            .adapter
            .attest_key(&other.admit())
            .expect("B re-attests");
        let fence = scene.adapter.consumed_through;
        assert_eq!(fence, 4);
        // Below the fence refuses; at the fence with no new history waits.
        for (cut, gap) in [
            (fence - 1, JournalGap::BootstrapMismatch),
            (fence, JournalGap::BoundNotReady),
        ] {
            let rebootstrap = BootstrapReceipt::scripted(
                reproof,
                BirthKind::AbsenceAppearance,
                cut,
                scene.closure_generation(),
            );
            // The void advanced the cumulative baseline to 8: the
            // resumption seals under the fresh epoch.
            let outcome = scene.seal_at(&rebootstrap, 8);
            assert_eq!(outcome.expect_err("fence gates resumption").gap, gap);
        }
        // New history above the fence seals under the fresh birth.
        let create = function_id("C_CreateObject");
        let healthy = begin_bytes_image(3, 1, create, 0, (COOKIE + 1, EXEC));
        scene.admit_other_end(
            &mut other,
            "C_CreateObject",
            &end_bytes(&healthy, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 70),
        );
        scene.ingest(&healthy);
        scene.ingest(&end_bytes(&healthy, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 70));
        let rebootstrap = BootstrapReceipt::scripted(
            reproof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let success = scene
            .seal_at(&rebootstrap, 8)
            .expect("fresh attestation resumes above the fence");
        assert_eq!(success.prefix.birth_cut(), fence);
        assert_eq!(success.prefix.bootstrap_cut(), Some(fence + 1));
        assert!(has_effect(&success.effects, "created"));
    }

    #[test]
    fn object_journal_abandon_bounded_lost_outcome() {
        use p11scope_ebpf_common::object_journal::JOURNAL_REASON_SYNC_RETURN_RESULT_LOST;
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // Observed synchronous return at 5, ABANDON-9 at 7: the bound is
        // the return cut, never the disposal ordinal. An earlier seal
        // covers through 2; the derived fence lands strictly above the
        // pending bound at 6, which the model accepts.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(3);
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        scene.ingest(&first);
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 40));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("first seal covers through 2");
        let begin = begin_bytes(1, 2, create, 0);
        assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
        let mut pad = ordinary_for(&begin, 0);
        pad.slot = 99;
        scene.ingest_ordinary(pad);
        assert_eq!(
            scene.ingest_ordinary(ordinary_for(&begin, 0)),
            JournalDisposition::ReturnObserved
        );
        scene.ingest_ordinary(pad);
        assert_eq!(
            scene.ingest(&abandon_bytes(
                1,
                2,
                JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
                (COOKIE, EXEC)
            )),
            JournalDisposition::AbandonStaged
        );
        assert_eq!(scene.adapter.consumed_through, 7);
        // The birth stays below staged history; the seal derives the
        // model's fence strictly above the pending return cut. The bound
        // is the return cut 5, never the disposal ordinal 7: a mutant
        // deriving from disposal would fence 8, and a mutant skipping
        // the pending bound would fence 3 and leave the model refusing
        // its floor.
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene.seal(&bootstrap).expect("bounded loss seals");
        assert_eq!(success.prefix.birth_cut(), 0);
        assert_eq!(success.prefix.bootstrap_cut(), Some(6));
        assert!(
            !success.effects.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::Gap {
                    reason: super::ObjectGap::BootstrapRefused
                }
            )),
            "derived fence clears the model floor"
        );
        assert!(success.prefix.settled()[0].abandoned);
        // The lost call creates no object result and no reference.
        assert!(!has_effect(&success.effects, "created"));
        assert!(!has_effect(&success.effects, "referenced"));
        assert!(!has_effect(&success.effects, "first-observed"));
        // A later seal keeps valid history flowing under the same pinned
        // birth: the next healthy creation settles, fenced above both
        // the recorded bound and the last sealed frontier.
        let healthy = begin_bytes(1, 3, create, 0);
        scene.ingest(&healthy);
        scene.ingest(&end_bytes(
            &healthy,
            OBJECT_ACTION_CREATE,
            0,
            ENTRY_NS + 120,
        ));
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene.seal(&bootstrap).expect("later seal passes");
        assert_eq!(success.prefix.birth_cut(), 0);
        assert_eq!(success.prefix.bootstrap_cut(), Some(8));
        assert!(has_effect(&success.effects, "created"));

        // Without corroboration the bound is not ready: the seal waits
        // with staged inputs kept, and a pending return never corroborates.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        assert_eq!(
            scene.ingest_ordinary(ordinary_for(&begin, rv_pending())),
            JournalDisposition::OrdinaryCounted
        );
        scene.ingest(&abandon_bytes(
            1,
            1,
            JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
            (COOKIE, EXEC),
        ));
        let bootstrap = scene.bootstrap(proof, 0);
        let failure = scene
            .seal(&bootstrap)
            .expect_err("uncorroborated bound waits");
        assert_eq!(failure.gap, JournalGap::BoundNotReady);
        // The corroborating return in the other arrival order completes it.
        assert_eq!(
            scene.ingest_ordinary(ordinary_for(&begin, 0)),
            JournalDisposition::ReturnObserved
        );
        let mut pad = ordinary_for(&begin, 0);
        pad.slot = 99;
        scene.ingest_ordinary(pad);
        scene.ingest_ordinary(pad);
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene.seal(&bootstrap).expect("late corroboration seals");
        assert_eq!(success.prefix.birth_cut(), 0);
        assert_eq!(success.prefix.bootstrap_cut(), Some(5));
    }

    #[test]
    fn object_journal_continuity_precedes_result_reads() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // Every repeated entry fact must agree exactly, or the END is a
        // contradiction: no completion is staged and no result is read.
        type Mutate = Box<dyn Fn(&mut [u8; 632])>;
        let mutations: Vec<(&str, Mutate)> = vec![
            ("image-cookie", Box::new(|end| end[24 + 288] ^= 0xFF)),
            ("image-exec", Box::new(|end| end[24 + 296] ^= 0xFF)),
            ("pid", Box::new(|end| end[24 + 16] ^= 0xFF)),
            ("session", Box::new(|end| end[24 + 32] ^= 0xFF)),
            ("slot", Box::new(|end| end[24 + 104] ^= 0xFF)),
            ("mechanism", Box::new(|end| end[24 + 48] ^= 0xFF)),
            ("capture", Box::new(|end| end[24 + 280] ^= 0x01)),
            ("slot-id", Box::new(|end| end[24 + 40] ^= 0xFF)),
            ("flags", Box::new(|end| end[24 + 56] ^= 0xFF)),
            ("user-type", Box::new(|end| end[24 + 112] ^= 0xFF)),
            ("entry-ip", Box::new(|end| end[24 + 328] ^= 0xFF)),
            ("entry-stamp", Box::new(|end| end[24 + 336] ^= 0xFF)),
            (
                "requested",
                Box::new(|end| {
                    end[24 + 368 + 128] = 1;
                    end[24 + 368 + 160] = 1;
                    end[24 + 368 + 161] = 1;
                }),
            ),
            (
                "return-before-entry",
                Box::new(|end| {
                    end[24..32].copy_from_slice(&(ENTRY_NS - 1).to_le_bytes());
                    end[32..40].copy_from_slice(&0u64.to_le_bytes());
                }),
            ),
        ];
        for (name, mutate) in mutations {
            let mut scene = Scene::new(image_default());
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            scene.ingest(&begin);
            let mut end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
            mutate(&mut end);
            assert_eq!(
                scene.ingest(&end),
                JournalDisposition::Contradiction(JournalContradiction::EndBeginMismatch),
                "{name} mismatch contradicts"
            );
        }

        // Input words and statuses disagree on a Destroy: both sides
        // decode (finite VALUE/UNREADABLE positions) but never complete.
        {
            use p11scope_ebpf_common::object_wire::OBJECT_ACTION_DESTROY;
            let mut scene = Scene::new(image_default());
            let destroy = function_id("C_DestroyObject");
            let mut begin = begin_bytes(1, 1, destroy, 0);
            put_u64(&mut begin, 88, 0x1111_1111_1111_1111);
            begin[126] = 1;
            scene.ingest(&begin);
            let mut end = end_bytes(&begin, OBJECT_ACTION_DESTROY, 0, ENTRY_NS + 50);
            end[24 + 368 + 16] ^= 0xFF;
            assert_eq!(
                scene.ingest(&end),
                JournalDisposition::Contradiction(JournalContradiction::EndBeginMismatch),
                "input word mismatch contradicts"
            );
        }
        {
            use p11scope_ebpf_common::object_wire::OBJECT_ACTION_DESTROY;
            let mut scene = Scene::new(image_default());
            let destroy = function_id("C_DestroyObject");
            let mut begin = begin_bytes(1, 1, destroy, 0);
            put_u64(&mut begin, 88, 0x1111_1111_1111_1111);
            begin[126] = 1;
            scene.ingest(&begin);
            let mut end = end_bytes(&begin, OBJECT_ACTION_DESTROY, 0, ENTRY_NS + 50);
            end[24 + 368 + 112] = 3;
            end[24 + 368 + 16..24 + 368 + 24].fill(0);
            assert_eq!(
                scene.ingest(&end),
                JournalDisposition::Contradiction(JournalContradiction::EndBeginMismatch),
                "input status mismatch contradicts"
            );
        }

        // A valid END for another descriptor decodes but never completes
        // this BEGIN: descriptor agreement is exact.
        {
            let mut scene = Scene::new(image_default());
            let sign = function_id("C_Sign");
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, sign, 0);
            scene.ingest(&begin);
            let foreign = begin_bytes(1, 1, create, 0);
            let end = end_bytes(&foreign, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
            // Same constants, so only the descriptor disagrees.
            assert_eq!(
                scene.ingest(&end),
                JournalDisposition::Contradiction(JournalContradiction::EndBeginMismatch)
            );
        }

        // The exact positive twin stages and settles.
        {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            scene.ingest(&begin);
            scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
            let bootstrap = scene.bootstrap(proof, 0);
            let success = scene.seal(&bootstrap).expect("exact agreement seals");
            assert!(has_effect(&success.effects, "created"));
        }
    }

    #[test]
    fn object_journal_busy_before_end() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // A live-path BUSY stall ends the quantum with the cursor held:
        // the frontier covers exactly the consumed prefix, and the rest
        // flows on the next collection.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        scene.bind_session_drain();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        scene.prepare_record_claims(&[begin.to_vec(), end.to_vec()]);
        let mut script = BusyScript::new(vec![begin.to_vec(), end.to_vec()]);
        script.busy_after = Some(1);
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let fault = ScriptedFaultCell::steady(7);
        let first = scene.adapter.collect_from_drain(
            &mut drain,
            &scene.descriptors,
            None,
            &fault,
            scene.fixture.h0_allocated_below(),
        );
        assert_eq!((first.ingested, first.ordinary), (1, 0));
        assert_eq!(scene.adapter.consumed_through, 1);
        let bootstrap = scene.bootstrap(proof, 0);
        let held = scene
            .seal_collected(&bootstrap, &first)
            .expect("prefix frontier seals");
        assert_eq!(held.prefix.open_keys().len(), 1);
        let second = scene.adapter.collect_from_drain(
            &mut drain,
            &scene.descriptors,
            None,
            &fault,
            scene.fixture.h0_allocated_below(),
        );
        assert_eq!((second.ingested, second.ordinary), (1, 0));
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene
            .seal_collected(&bootstrap, &second)
            .expect("completed frontier seals");
        assert!(has_effect(&success.effects, "created"));

        // A stall before the first record consumes nothing at all.
        // (Bound, so the zero-consumption proves the BUSY stall, not an
        // unbound-drain refusal.)
        let mut scene = Scene::new(image_default());
        scene.attest();
        scene.bind_session_drain();
        let mut script = BusyScript::new(vec![begin.to_vec()]);
        script.busy_after = Some(0);
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let first =
            scene
                .adapter
                .collect_from_drain(&mut drain, &scene.descriptors, None, &fault, 0);
        assert_eq!((first.ingested, first.ordinary), (0, 0));
        assert_eq!(scene.adapter.consumed_through, 0);

        // The bounded path: Pending at the stop holds the frontier with
        // nothing consumed; Pending below the stop is the ungated-writer
        // error, also consuming nothing.
        let mut scene = Scene::new(image_default());
        let mut script = BusyScript::new(vec![begin.to_vec(), end.to_vec()]);
        script.pending_before = 1;
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let outcome = scene
            .drain_bounded_to(&mut drain, 0)
            .expect("pending at the stop is legal");
        assert_eq!(outcome, (false, false));
        assert_eq!(scene.adapter.consumed_through, 0);
        let outcome = scene
            .drain_bounded_to(&mut drain, 16)
            .expect("bounded drain consumes to the stop");
        assert_eq!(outcome, (false, false));
        assert_eq!(scene.adapter.consumed_through, 2);

        let mut scene = Scene::new(image_default());
        let mut script = BusyScript::new(vec![begin.to_vec()]);
        script.pending_before = 1;
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let outcome = scene.drain_bounded_to(&mut drain, 8);
        assert!(outcome.is_err(), "busy below the stop errors");
        assert_eq!(scene.adapter.consumed_through, 0);
    }

    #[test]
    fn object_journal_frontier_requires_complete_disposition() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // A delayed seal proves exactly what prompt sealing proves.
        let build = |delayed: bool| {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest_calls(2);
            let create = function_id("C_CreateObject");
            let first = begin_bytes(1, 1, create, 0);
            scene.ingest(&first);
            scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 40));
            let held = scene.adapter.consumed_frontier();
            let second = begin_bytes(1, 2, create, 0);
            scene.ingest(&second);
            scene.ingest(&end_bytes(&second, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
            let bootstrap = scene.bootstrap(proof, 0);
            if !delayed {
                let frontier = held;
                let audit = scene.audit();
                scene
                    .seal_explicit(
                        &audit,
                        &bootstrap,
                        frontier,
                        SessionBirthEvidence::scripted_for_receipt(&bootstrap),
                    )
                    .expect("prompt first seal passes");
            }
            let frontier = scene.adapter.consumed_frontier();
            let audit = scene.audit();
            scene
                .seal_explicit(
                    &audit,
                    &bootstrap,
                    frontier,
                    SessionBirthEvidence::scripted_for_receipt(&bootstrap),
                )
                .expect("final seal passes");
            // Proved relationships only: the prompt run's second seal
            // reuses the covered bootstrap and counts one expected
            // BootstrapRefused gap the delayed run never takes.
            let projection = scene.model.project();
            format!(
                "{:?}{:?}{:?}",
                projection.objects, projection.sessions, projection.usage
            )
        };
        assert_eq!(build(false), build(true));

        // A frontier below the sealed-through cut regresses.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(2);
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        scene.ingest(&first);
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 40));
        let held = scene.adapter.consumed_frontier();
        let second = begin_bytes(1, 2, create, 0);
        scene.ingest(&second);
        scene.ingest(&end_bytes(&second, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("first seal passes");
        let audit = scene.audit();
        let failure = scene
            .seal_explicit(
                &audit,
                &bootstrap,
                held,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("regressed frontier refuses");
        assert_eq!(failure.gap, JournalGap::FrontierRegression);

        // Undisposed H3 history refuses without voiding: the same staged
        // inputs seal once disposition covers them.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let short = JournalAuditReceipt::scripted_h0(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(frontier.cut() - 1),
            scene.closure_generation(),
            frontier.cut() + 1,
        );
        let failure = scene
            .seal_explicit(
                &short,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("undisposed H3 refuses");
        assert_eq!(failure.gap, JournalGap::H3Pending);
        let audit = scene.audit();
        let success = scene
            .seal_explicit(
                &audit,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect("covered disposition seals the kept inputs");
        assert_eq!(success.prefix.settled().len(), 1);

        // A staged H3 loss voids and fences: resumption names the
        // fence and proves new history above it.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let loss = JournalAuditReceipt::scripted_h0(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_loss(2),
            scene.closure_generation(),
            3,
        );
        let failure = scene
            .seal_explicit(
                &loss,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("H3 loss refuses");
        assert_eq!(failure.gap, JournalGap::H3Loss);
        // Vacuous resumption at the fence waits for new history.
        let fence = scene.adapter.consumed_through;
        assert_eq!(fence, 2);
        let resume = BootstrapReceipt::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let audit = scene.audit();
        let waiting = scene
            .seal_explicit(
                &audit,
                &resume,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&resume),
            )
            .expect_err("empty resumption waits");
        assert_eq!(waiting.gap, JournalGap::BoundNotReady);
        // New history above the fence seals under the fresh birth. The
        // void cleared admission claims: re-attest for the new history.
        scene.attest();
        let again = begin_bytes(1, 2, create, 0);
        scene.ingest(&again);
        scene.ingest(&end_bytes(&again, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let success = scene
            .seal(&resume)
            .expect("resumption seals above the fence");
        assert_eq!(success.prefix.birth_cut(), fence);
        assert_eq!(success.prefix.bootstrap_cut(), Some(fence + 1));
        assert_eq!(success.prefix.settled().len(), 1);
        assert!(has_effect(&success.effects, "created"));
    }

    #[test]
    fn object_journal_retained_cursor_discard_audit() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // One malformed record in a real collection refuses the seal and
        // voids the tick's staged inputs.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        let fault = ScriptedFaultCell::steady(7);
        let collection =
            scene.collect_records(vec![begin.to_vec(), vec![0u8; 100], end.to_vec()], &fault);
        assert_eq!(collection.malformed_delta, 1);
        assert_eq!((collection.ingested, collection.ordinary), (2, 0));
        let bootstrap = scene.bootstrap(proof, 0);
        let failure = scene
            .seal_collected(&bootstrap, &collection)
            .expect_err("malformed tick refuses");
        assert_eq!(failure.gap, JournalGap::Malformed);
        // Resumption names the void fence: vacuous at the fence waits,
        // and new history above it seals under the fresh birth.
        let fence = scene.adapter.consumed_through;
        assert_eq!(fence, 2);
        let resume = BootstrapReceipt::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let clean = JournalCollection {
            malformed_delta: 0,
            ..collection
        };
        let waiting = scene
            .seal_collected(&resume, &clean)
            .expect_err("empty resumption waits");
        assert_eq!(waiting.gap, JournalGap::BoundNotReady);
        // The void cleared admission claims: re-attest for the new history.
        scene.attest();
        let again = begin_bytes(1, 2, create, 0);
        let collection = scene.collect_records(
            vec![
                again.to_vec(),
                end_bytes(&again, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60).to_vec(),
            ],
            &fault,
        );
        assert_eq!(collection.malformed_delta, 0);
        let success = scene
            .seal_collected(&resume, &collection)
            .expect("resumption seals above the fence");
        assert_eq!(success.prefix.birth_cut(), fence);
        assert_eq!(success.prefix.bootstrap_cut(), Some(fence + 1));
        assert_eq!(success.prefix.settled().len(), 1);

        // A fault change across the tick refuses and voids, through the
        // same collection evidence.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        let fault = ScriptedFaultCell::sequence(vec![7, 8]);
        let collection = scene.collect_records(vec![begin.to_vec()], &fault);
        assert_eq!((collection.fault_before, collection.fault_after), (7, 8));
        let bootstrap = scene.bootstrap(proof, 0);
        let failure = scene
            .seal_collected(&bootstrap, &collection)
            .expect_err("changed fault refuses");
        assert_eq!(failure.gap, JournalGap::FaultChanged);

        // An unreadable fault stages nothing and refuses; a saturated
        // fault stops the adapter permanently.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        let fault = ScriptedFaultCell::failing();
        let collection = scene.collect_records(vec![begin.to_vec()], &fault);
        assert_eq!((collection.ingested, collection.ordinary), (0, 0));
        let bootstrap = scene.bootstrap(proof, 0);
        let failure = scene
            .seal_collected(&bootstrap, &collection)
            .expect_err("unreadable fault refuses");
        assert_eq!(failure.gap, JournalGap::FaultUnreadable);
        let fault = ScriptedFaultCell::sequence(vec![u64::MAX]);
        let collection = scene.collect_records(vec![begin.to_vec()], &fault);
        let failure = scene
            .seal_collected(&bootstrap, &collection)
            .expect_err("saturated fault refuses");
        assert_eq!(failure.gap, JournalGap::FaultSaturated);
        let readmitted = scene.fixture.admit();
        assert_eq!(
            scene.adapter.attest_key(&readmitted),
            Err(AttestationRefusal::Stopped)
        );

        // A clean mixed collection counts every form and seals.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        let mut pad = ordinary_for(&begin, 0);
        pad.slot = 99;
        let fault = ScriptedFaultCell::steady(7);
        let collection = scene.collect_records(
            vec![
                begin.to_vec(),
                crate::events::event_bytes(&pad),
                end.to_vec(),
            ],
            &fault,
        );
        assert_eq!((collection.ingested, collection.ordinary), (2, 1));
        assert_eq!(collection.malformed_delta, 0);
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene
            .seal_collected(&bootstrap, &collection)
            .expect("clean mixed tick seals");
        assert!(has_effect(&success.effects, "created"));
    }

    #[test]
    fn object_journal_pending_and_floor_capacity() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // The 1,025th open call at the 1,024 policy bound records its
        // refusal; a corroborated synchronous return bounds it and the
        // seal clears the refusal without a bootstrap refusal.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(1_025);
        let create = function_id("C_CreateObject");
        for sequence in 1..=1_024u64 {
            let begin = begin_bytes(1, sequence, create, 0);
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
        }
        let refused = begin_bytes(1, 1_025, create, 0);
        assert_eq!(
            scene.ingest(&refused),
            JournalDisposition::BeginRefusedCapacity
        );
        let bootstrap = scene.bootstrap(proof, 0);
        let failure = scene.seal(&bootstrap).expect_err("unbounded refusal waits");
        assert_eq!(failure.gap, JournalGap::BoundNotReady);
        assert_eq!(
            scene.ingest_ordinary(ordinary_for(&refused, 0)),
            JournalDisposition::ReturnObserved
        );
        let mut pad = ordinary_for(&refused, 0);
        pad.slot = 99;
        scene.ingest_ordinary(pad);
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene.seal(&bootstrap).expect("bounded refusal seals");
        // The held opens pin below the floors, so the seal continues
        // without claiming new authority; the 1,026 bound lives in the
        // model's floor, and the staged refusal is disposed.
        assert_eq!(success.prefix.birth_cut(), 0);
        assert_eq!(success.prefix.bootstrap_cut(), None);
        assert_eq!(success.prefix.open_keys().len(), 1_024);
        assert!(scene.adapter.refused.is_empty());

        // Small injected bounds refuse overflow exactly: two opens, two
        // refusals, then the third refusal overflows and taints.
        let mut scene = Scene::new_with_limits(
            image_default(),
            JournalLimits {
                open_calls: 2,
                thread_floors: 8,
                refused_begins: 2,
                domain_keys: 4,
                image_sightings: 8,
            },
        );
        for sequence in 1..=2u64 {
            let begin = begin_bytes(1, sequence, create, 0);
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
        }
        for sequence in 3..=4u64 {
            let begin = begin_bytes(1, sequence, create, 0);
            assert_eq!(
                scene.ingest(&begin),
                JournalDisposition::BeginRefusedCapacity
            );
        }
        let begin = begin_bytes(1, 5, create, 0);
        assert_eq!(
            scene.ingest(&begin),
            JournalDisposition::Contradiction(JournalContradiction::RefusedOverflow)
        );
        let admitted = scene.fixture.admit();
        assert_eq!(
            scene.adapter.attest_key(&admitted),
            Err(AttestationRefusal::ImageTainted)
        );

        // The 16,449th thread at the 16,448 policy floor bound refuses
        // with the image tainted; seals are refused before any model
        // input for the overflow. Batches seal and prune so only floors
        // accumulate.
        let mut scene = Scene::new(image_default());
        // H3 admits each call before its batch seals; conversions
        // consume as they go (one in-flight admission stays ahead).
        let proof = scene.attest();
        let bootstrap = scene.bootstrap(proof, 0);
        for batch in 0..64u64 {
            for thread in 1..=256u64 {
                scene.attest();
                let ticket = batch * 256 + thread;
                let begin = begin_bytes(ticket, 1, create, 0);
                assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
                scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
            }
            scene.seal(&bootstrap).expect("batch seal prunes");
        }
        for thread in 16_384 + 1..=16_448u64 {
            scene.attest();
            let begin = begin_bytes(thread, 1, create, 0);
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
            scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        }
        scene.seal(&bootstrap).expect("final batch seals");
        let begin = begin_bytes(16_449, 1, create, 0);
        assert_eq!(
            scene.ingest(&begin),
            JournalDisposition::Contradiction(JournalContradiction::FloorExhausted)
        );
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let failure = scene
            .seal_explicit(
                &audit,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("tainted image never seals");
        assert_eq!(failure.gap, JournalGap::ImageTainted);

        // The domain-key table refuses past its injected bound.
        let mut scene = Scene::new_with_limits(
            image_default(),
            JournalLimits {
                open_calls: 8,
                thread_floors: 8,
                refused_begins: 8,
                domain_keys: 1,
                image_sightings: 8,
            },
        );
        scene.attest();
        let mut other = AttestationFixture::new(ImageIdentity {
            task_cookie: COOKIE + 1,
            exec_id: EXEC,
        });
        assert_eq!(
            scene.adapter.attest_key(&other.admit()),
            Err(AttestationRefusal::KeysExhausted)
        );
    }

    #[test]
    fn object_journal_neutral_s1_calls_close_prefix() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // A neutral call holds the settlement watermark exactly like an
        // object call: the completed creation below it applies only once
        // the neutral call closes, and the neutral call itself contributes
        // no object effect.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        scene.attest_function("C_Sign");
        let create = function_id("C_CreateObject");
        let sign = function_id("C_Sign");
        let neutral = begin_bytes(1, 1, sign, 0);
        scene.ingest(&neutral);
        let begin = begin_bytes(1, 2, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        let held = scene.seal(&bootstrap).expect("neutral-open prefix seals");
        assert_eq!(held.prefix.settled().len(), 2);
        assert_eq!(held.prefix.open_keys().len(), 1);
        assert!(!has_effect(&held.effects, "created"));
        assert!(scene.model.project().objects.is_empty());
        scene.ingest(&end_bytes_absent(&neutral, 0, ENTRY_NS + 60));
        let success = scene.seal(&bootstrap).expect("closed prefix seals");
        assert!(has_effect(&success.effects, "created"));
        // Each terminal converts once: the held creation completes
        // without a duplicate-completion gap on the second seal.
        assert!(
            !success.effects.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::Gap {
                    reason: super::ObjectGap::DuplicateCompletion
                }
            )),
            "no duplicate completion"
        );
        assert!(success.prefix.open_keys().is_empty());
        assert_eq!(scene.model.project().objects.len(), 1);
    }

    #[test]
    fn object_journal_sequence_scope_frontier() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // A delayed first route retains its original BEGIN cut.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(2);
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        let mut pad = ordinary_for(&begin, 0);
        pad.slot = 99;
        scene.ingest_ordinary(pad);
        scene.ingest_ordinary(pad);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        assert_eq!(scene.adapter.consumed_through, 4);
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene.seal(&bootstrap).expect("delayed seal passes");
        assert_eq!(success.prefix.settled()[0].begin_cut, 1);

        // One pending lease: re-sealing the same frontier waits for new
        // history instead of settling nothing, and a converted call never
        // re-mints on a later seal.
        let second = scene.seal(&bootstrap).expect_err("repeat seal waits");
        assert_eq!(second.gap, JournalGap::BoundNotReady);
        let next = begin_bytes(1, 2, create, 0);
        scene.ingest(&next);
        scene.ingest(&end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 70));
        let third = scene.seal(&bootstrap).expect("later seal passes");
        assert_eq!(third.prefix.settled().len(), 1);
        assert_eq!(third.prefix.settled()[0].begin_cut, 5);

        // Settlement releases the lease: after a pruning seal the same
        // small table admits new calls instead of refusing capacity.
        let mut scene = Scene::new_with_limits(
            image_default(),
            JournalLimits {
                open_calls: 2,
                thread_floors: 8,
                refused_begins: 8,
                domain_keys: 4,
                image_sightings: 8,
            },
        );
        let proof = scene.attest_calls(2);
        for sequence in 1..=2u64 {
            let begin = begin_bytes(1, sequence, create, 0);
            scene.ingest(&begin);
            scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        }
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("pruning seal passes");
        for sequence in 3..=4u64 {
            let begin = begin_bytes(1, sequence, create, 0);
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
        }
    }

    /// Frozen closure census: every catalog ordinal pins its class.
    /// Any H2 acceptance change, catalog renumbering, or classification
    /// edit breaks this test and requires an explicit amendment — never
    /// a silent default.
    #[test]
    fn object_journal_closure_census_is_frozen() {
        // Explicit lists are well-formed: distinct, inventoried, not
        // modeled, disjoint, and classified as labeled.
        for list in [
            NEGATIVE_ONLY_FUNCTIONS.as_slice(),
            PROVED_IRRELEVANT_FUNCTIONS.as_slice(),
        ] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), list.len(), "duplicate in {list:?}");
            for name in list {
                assert!(
                    crate::kinds::descriptor(name).is_some(),
                    "{name} not in inventory"
                );
            }
        }
        for name in NEGATIVE_ONLY_FUNCTIONS {
            assert!(
                !PROVED_IRRELEVANT_FUNCTIONS.contains(&name),
                "{name} in both lists"
            );
        }
        // (ordinal, name, class) for every non-modeled function.
        let pinned: [(u32, &str, EndpointClass); 28] = [
            (0, "C_Initialize", EndpointClass::NegativeOnlyAffecting),
            (2, "C_GetInfo", EndpointClass::ProvedIrrelevant),
            (3, "C_GetFunctionList", EndpointClass::ProvedIrrelevant),
            (4, "C_GetSlotList", EndpointClass::ProvedIrrelevant),
            (5, "C_GetSlotInfo", EndpointClass::ProvedIrrelevant),
            (6, "C_GetTokenInfo", EndpointClass::ProvedIrrelevant),
            (7, "C_GetMechanismList", EndpointClass::ProvedIrrelevant),
            (8, "C_GetMechanismInfo", EndpointClass::ProvedIrrelevant),
            (9, "C_InitToken", EndpointClass::NegativeOnlyAffecting),
            (10, "C_InitPIN", EndpointClass::ProvedIrrelevant),
            (11, "C_SetPIN", EndpointClass::ProvedIrrelevant),
            (15, "C_GetSessionInfo", EndpointClass::ProvedIrrelevant),
            (16, "C_GetOperationState", EndpointClass::ProvedIrrelevant),
            (63, "C_SeedRandom", EndpointClass::ProvedIrrelevant),
            (64, "C_GenerateRandom", EndpointClass::ProvedIrrelevant),
            (65, "C_GetFunctionStatus", EndpointClass::ProvedIrrelevant),
            (66, "C_CancelFunction", EndpointClass::ProvedIrrelevant),
            (67, "C_WaitForSlotEvent", EndpointClass::ProvedIrrelevant),
            (68, "C_GetInterfaceList", EndpointClass::ProvedIrrelevant),
            (69, "C_GetInterface", EndpointClass::ProvedIrrelevant),
            (92, "C_EncapsulateKey", EndpointClass::NegativeOnlyAffecting),
            (93, "C_DecapsulateKey", EndpointClass::NegativeOnlyAffecting),
            (
                98,
                "C_GetSessionValidationFlags",
                EndpointClass::ProvedIrrelevant,
            ),
            (99, "C_AsyncComplete", EndpointClass::NegativeOnlyAffecting),
            (100, "C_AsyncGetID", EndpointClass::NegativeOnlyAffecting),
            (101, "C_AsyncJoin", EndpointClass::NegativeOnlyAffecting),
            (
                102,
                "C_WrapKeyAuthenticated",
                EndpointClass::NegativeOnlyAffecting,
            ),
            (
                103,
                "C_UnwrapKeyAuthenticated",
                EndpointClass::NegativeOnlyAffecting,
            ),
        ];
        for (ordinal, name, class) in pinned {
            assert_eq!(
                pkcs11_module::function_name(ordinal as usize),
                Some(name),
                "catalog renumbered at {ordinal}"
            );
            assert!(
                !crate::semantics_objects::state::is_modeled_function(ordinal),
                "{name} became modeled"
            );
            assert_eq!(endpoint_class(ordinal), Some(class), "{name}");
        }
        // Everything else named is modeled; the census totals pin the
        // split so no function hides in the default arm.
        let mut modeled = 0u32;
        for ordinal in 0..104u32 {
            if pinned.iter().any(|entry| entry.0 == ordinal) {
                continue;
            }
            assert_eq!(
                endpoint_class(ordinal),
                Some(EndpointClass::ModeledAffecting),
                "ordinal {ordinal} left the modeled set"
            );
            modeled += 1;
        }
        assert_eq!(modeled, 76, "modeled census moved");
        // Catalog gap sentinel: ordinal 104 is unnamed today. Filling it
        // must amend this census; until then it is refused, and so is
        // everything beyond the descriptor table.
        assert_eq!(pkcs11_module::function_name(104), None);
        assert_eq!(endpoint_class(104), None);
        assert_eq!(endpoint_class(105), None);
        assert_eq!(endpoint_class(106), None);
        assert_eq!(endpoint_class(u32::MAX), None);
    }

    #[test]
    fn object_journal_negative_only_invocation_invalidates() {
        use p11scope_ebpf_common::object_journal::JOURNAL_BEGIN_NO_END;
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // A linked negative-only endpoint permits the pre-invocation
        // positive twin: healthy history seals before it is ever invoked.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("pre-invocation twin seals");
        // Its actual invocation arrives as the frozen valid NO_END signal
        // and invalidates the possibly affected incarnation before any
        // user effect can be proven: staged entries are disposed,
        // attestation refuses, and no later seal proves.
        let init = function_id("C_Initialize");
        let invoked = begin_bytes(1, 2, init, JOURNAL_BEGIN_NO_END);
        assert_eq!(
            scene.ingest(&invoked),
            JournalDisposition::NegativeOnlyInvalidated
        );
        assert!(scene.adapter.open.is_empty());
        let readmitted = scene.fixture.admit();
        assert_eq!(
            scene.adapter.attest_key(&readmitted),
            Err(AttestationRefusal::ImageTainted)
        );
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let refused = scene
            .seal_explicit(
                &audit,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("invoked incarnation never seals");
        assert_eq!(refused.gap, JournalGap::ImageTainted);
        // Sealed history stays: the pre-invocation creation is retained.
        assert_eq!(scene.model.project().objects.len(), 1);

        // A negative-only invocation promising an END violates the frozen
        // NO_END entry rule: contradiction, not a signal.
        let mut scene = Scene::new(image_default());
        scene.attest();
        let encap = function_id("C_EncapsulateKey");
        assert_eq!(
            scene.ingest(&begin_bytes(1, 1, encap, 0)),
            JournalDisposition::Contradiction(JournalContradiction::UnclosedEndpoint)
        );
        let readmitted = scene.fixture.admit();
        assert_eq!(
            scene.adapter.attest_key(&readmitted),
            Err(AttestationRefusal::ImageTainted)
        );
    }

    #[test]
    fn object_journal_irrelevant_begin_contradicts_table() {
        // The producer never journals proved-irrelevant functions: a BEGIN
        // naming one contradicts the frozen table and taints the image
        // before any key state advances.
        let mut scene = Scene::new(image_default());
        scene.attest();
        let info = function_id("C_GetInfo");
        assert_eq!(
            scene.ingest(&begin_bytes(1, 1, info, 0)),
            JournalDisposition::Contradiction(JournalContradiction::UnclosedEndpoint)
        );
        assert!(scene.adapter.open.is_empty());
        assert!(!scene.adapter.floors.contains_key(&1));
        let readmitted = scene.fixture.admit();
        assert_eq!(
            scene.adapter.attest_key(&readmitted),
            Err(AttestationRefusal::ImageTainted)
        );
    }

    #[test]
    fn object_journal_neutral_operation_history() {
        use p11scope_ebpf_common::object_wire::{
            OBJECT_ACTION_ACCESS, OBJECT_ACTION_CREATE, OBJECT_ACTION_DESTROY, OBJECT_ACTION_GET,
        };

        // Nonempty create/Get/Sign/Verify and message histories ingest
        // through the frozen endpoint table and seal healthy: settled
        // calls keep S1 payload order with no invented references, and
        // only the creation establishes an object.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        for name in [
            "C_GetAttributeValue",
            "C_SignInit",
            "C_Sign",
            "C_VerifyInit",
            "C_Verify",
            "C_SignMessage",
            "C_DestroyObject",
        ] {
            scene.attest_function(name);
        }
        let create = function_id("C_CreateObject");
        let getattr = function_id("C_GetAttributeValue");
        let sign_init = function_id("C_SignInit");
        let sign = function_id("C_Sign");
        let verify_init = function_id("C_VerifyInit");
        let verify = function_id("C_Verify");
        let sign_message = function_id("C_SignMessage");
        let destroy = function_id("C_DestroyObject");
        // (function, tail action): row calls carry their action, rowless
        // neutrals ride the absent-tail path.
        let history = [
            (create, Some(OBJECT_ACTION_CREATE)),
            (getattr, Some(OBJECT_ACTION_GET)),
            (sign_init, Some(OBJECT_ACTION_ACCESS)),
            (sign, None),
            (verify_init, Some(OBJECT_ACTION_ACCESS)),
            (verify, None),
            (sign_message, None),
            (destroy, Some(OBJECT_ACTION_DESTROY)),
        ];
        let mut sequence = 0u64;
        let mut begin_cuts = Vec::new();
        for (function, action) in history {
            sequence += 1;
            let mut begin = begin_bytes(1, sequence, function, 0);
            // Row calls with input positions carry a non-absent input
            // status. Every input names the created handle, so the whole
            // history grounds on one proven key.
            if function == getattr
                || function == sign_init
                || function == verify_init
                || function == destroy
            {
                put_u64(&mut begin, 88, 0x9090_9090_9090_9090);
                begin[126] = 1;
            }
            scene.ingest(&begin);
            begin_cuts.push(scene.adapter.consumed_through);
            let end = match action {
                Some(action) => end_bytes(&begin, action, 0, ENTRY_NS + 50),
                None => end_bytes_absent(&begin, 0, ENTRY_NS + 50),
            };
            assert_eq!(scene.ingest(&end), JournalDisposition::EndStaged);
        }
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene.seal(&bootstrap).expect("neutral history seals");
        let settled = success.prefix.settled();
        assert_eq!(settled.len(), history.len());
        assert!(success.prefix.open_keys().is_empty());
        for (summary, ((function, _), cut)) in
            settled.iter().zip(history.iter().zip(begin_cuts.iter()))
        {
            assert_eq!(summary.function, *function);
            assert_eq!(summary.begin_cut, *cut);
            assert!(!summary.abandoned);
        }
        let mut tickets: Vec<_> = settled.iter().map(|summary| summary.ticket).collect();
        tickets.sort();
        tickets.dedup();
        assert_eq!(tickets.len(), history.len(), "one ticket per call");
        let objects = &scene.model.project().objects;
        assert_eq!(objects.len(), 1);
        assert_eq!(
            objects[0].lifetime,
            crate::semantics_objects::Lifetime::Destroyed
        );
    }

    #[test]
    fn object_journal_exec_marker_birth_requires_novel_image() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // A birth BEGIN as the image's first observed record attests as
        // an exec-marker birth through the production constructor and
        // seals.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        let birth = BootstrapReceipt::attest(
            &scene.adapter,
            &SessionBirthGrant::scripted(
                proof,
                BirthKind::ExecMarker,
                0,
                scene.closure_generation(),
            ),
        )
        .expect("novel image births");
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        scene.seal(&birth).expect("exec birth seals");

        // An image observed before its first affecting call is novel at
        // cut zero but not at cut one; the same cut one births as absence
        // and seals the later affecting call.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        let mut seen = ordinary_for(&begin, 0);
        seen.slot = 99;
        scene.ingest_algorithm_quiet(seen);
        scene.ingest(&begin);
        BootstrapReceipt::attest(
            &scene.adapter,
            &SessionBirthGrant::scripted(
                proof,
                BirthKind::ExecMarker,
                0,
                scene.closure_generation(),
            ),
        )
        .expect("novel at cut zero");
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    proof,
                    BirthKind::ExecMarker,
                    1,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::NoveltyBroken)
        );
        let absence = BootstrapReceipt::attest(
            &scene.adapter,
            &SessionBirthGrant::scripted(
                proof,
                BirthKind::AbsenceAppearance,
                1,
                scene.closure_generation(),
            ),
        )
        .expect("observed quiet life births as absence");
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let success = scene.seal(&absence).expect("absence birth seals");
        assert_eq!(success.prefix.settled().len(), 1);
        assert!(success.prefix.open_keys().is_empty());

        // An affecting ordinary before the cut breaks both kinds: the
        // image was already affecting provider state when observed.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let sign = function_id("C_Sign");
        let begin = begin_bytes(1, 1, create, 0);
        let mut affecting = ordinary_for(&begin, 0);
        affecting.slot = 99;
        affecting.target_function = sign;
        scene.ingest_ordinary(affecting);
        scene.ingest(&begin);
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    proof,
                    BirthKind::ExecMarker,
                    1,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::NoveltyBroken)
        );
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    proof,
                    BirthKind::AbsenceAppearance,
                    1,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::AbsenceUnproven)
        );

        // An unclassified ordinary function is suspect, never quiet.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        let mut unknown = ordinary_for(&begin, 0);
        unknown.slot = 99;
        unknown.target_function = 104;
        scene.ingest_ordinary(unknown);
        scene.ingest(&begin);
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    proof,
                    BirthKind::AbsenceAppearance,
                    1,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::AbsenceUnproven)
        );

        // A birth with zero observed history proves nothing: attestation
        // refuses, and the seal maps it to a bootstrap mismatch.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    proof,
                    BirthKind::ExecMarker,
                    0,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::ImageUnknown)
        );
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let refused = scene
            .seal_explicit(
                &audit,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("unknown image never seals");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);
    }

    #[test]
    fn object_journal_absence_birth_requires_clean_chain() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // An audit failure between first sighting and birth breaks the
        // clean chain the witness requires, even though the failure kept
        // staged inputs.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        let mut seen = ordinary_for(&begin, 0);
        seen.slot = 99;
        scene.ingest_algorithm_quiet(seen);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let pending = JournalAuditReceipt::scripted_h0(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through - 1),
            scene.closure_generation(),
            scene.adapter.consumed_through + 1,
        );
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let failure = scene
            .seal_explicit(
                &pending,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("undisposed H3 refuses");
        assert_eq!(failure.gap, JournalGap::H3Pending);
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    proof,
                    BirthKind::AbsenceAppearance,
                    1,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::AbsenceUnproven)
        );

        // A forked child observed only through an inherited terminal can
        // never birth: the orphan END taints the child image while the
        // parent stays useful.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let parent = begin_bytes(1, 1, create, 0);
        scene.ingest(&parent);
        let child_begin = begin_bytes_image(9, 1, create, 0, (COOKIE + 7, EXEC));
        let orphan = end_bytes(&child_begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        assert_eq!(
            scene.ingest(&orphan),
            JournalDisposition::Contradiction(JournalContradiction::TerminalBeforeBegin)
        );
        let child_image = ImageIdentity {
            task_cookie: COOKIE + 7,
            exec_id: EXEC,
        };
        let mut child_fixture = AttestationFixture::new(child_image);
        assert_eq!(
            scene.adapter.attest_key(&child_fixture.admit()),
            Err(AttestationRefusal::ImageTainted)
        );
        let bootstrap = scene.bootstrap(proof, 0);
        scene
            .seal(&bootstrap)
            .expect("parent seals despite the fork");

        // A fork record sighting the child marks inheritance as
        // affecting: the child can neither exec-birth above the fork nor
        // claim absence, while the parent's own quiet sighting births.
        let mut scene = Scene::new(image_default());
        let parent_proof = scene.attest();
        let child_image = ImageIdentity {
            task_cookie: COOKIE + 9,
            exec_id: EXEC,
        };
        let mut child_fixture = AttestationFixture::new(child_image);
        let child_proof = scene
            .adapter
            .attest_key(&child_fixture.admit())
            .expect("child key attests");
        let begin = begin_bytes(1, 1, create, 0);
        let mut fork = ordinary_for(&begin, 0);
        fork.slot = 99;
        fork.child_image = child_image;
        scene.ingest_algorithm_quiet(fork);
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    child_proof,
                    BirthKind::ExecMarker,
                    1,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::NoveltyBroken)
        );
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    child_proof,
                    BirthKind::AbsenceAppearance,
                    1,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::AbsenceUnproven)
        );
        scene.ingest(&begin);
        BootstrapReceipt::attest(
            &scene.adapter,
            &SessionBirthGrant::scripted(
                parent_proof,
                BirthKind::AbsenceAppearance,
                1,
                scene.closure_generation(),
            ),
        )
        .expect("parent quiet life births");
    }

    #[test]
    fn object_journal_birth_cut_covers_and_pins_history() {
        // Direct: the cover rule over staged begins, ignoring staged
        // history for other images and vacuous when nothing is staged.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let image = (COOKIE, EXEC);
        let live = scene.adapter.live_keys_for_image(image);
        assert!(
            scene
                .adapter
                .birth_covers_staged(proof.key, &live, image, 0)
        );
        scene.ingest(&begin_bytes(1, 1, create, 0));
        scene.prepare_claims();
        assert!(
            scene
                .adapter
                .birth_covers_staged(proof.key, &live, image, 0)
        );
        assert!(
            !scene
                .adapter
                .birth_covers_staged(proof.key, &live, image, 1)
        );
        assert!(
            scene
                .adapter
                .birth_covers_staged(proof.key, &live, (COOKIE + 1, EXEC), 1)
        );

        // Pinning: the birth pins per key-era at first seal. Another
        // image's record lands first, so the scene image is first
        // sighted at 2 and both cuts 0 and 1 verify as exec-novel; the
        // moved birth still refuses on the pin alone.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(2);
        let anchor = begin_bytes(1, 1, create, 0);
        let mut foreign = ordinary_for(&anchor, 0);
        foreign.slot = 99;
        foreign.image = ImageIdentity {
            task_cookie: COOKIE + 3,
            exec_id: EXEC,
        };
        foreign.target_function = function_id("C_GetInfo");
        scene.ingest_ordinary(foreign);
        scene.ingest(&begin_bytes(1, 1, create, 0));
        let first = scene.bootstrap(proof, 0);
        scene.seal(&first).expect("first seal pins the birth");
        let moved = scene.bootstrap(proof, 1);
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let refused = scene
            .seal_explicit(
                &audit,
                &moved,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&moved),
            )
            .expect_err("moved birth refuses");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);
        // A repeat at the unchanged frontier waits instead of
        // succeeding vacuously; new history resumes progress under the
        // same pinned birth.
        let repeat = scene.seal(&first).expect_err("repeat waits");
        assert_eq!(repeat.gap, JournalGap::BoundNotReady);
        scene.ingest(&begin_bytes(1, 2, create, 0));
        scene.seal(&first).expect("pinned birth re-seals");
    }

    #[test]
    fn object_journal_closure_generation_binds_seal() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // Healthy history seals under the observed sealing generation.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(2);
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        scene
            .seal(&bootstrap)
            .expect("observed-closure seal passes");
        // A later sealing advances the closure: both envelopes are
        // genuinely sealed, so the newer generation is strictly
        // greater. Advancing retires old audits and old receipts alike.
        let aux = AttestationFixture::new(image_default());
        let advanced = aux.attachment().generation();
        assert!(
            advanced > scene.closure_generation(),
            "later sealings mint strictly greater generations"
        );
        assert!(
            scene
                .adapter
                .install_closure_grant(&SessionClosureGrant::observe(aux.attachment()))
        );
        let frontier = scene.adapter.consumed_frontier();
        let stale_audit = scene.audit();
        let refused = scene
            .seal_explicit(
                &stale_audit,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("stale audit refuses");
        assert_eq!(refused.gap, JournalGap::ClosureStale);
        let fresh_audit = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            advanced,
        );
        let refused = scene
            .seal_explicit(
                &fresh_audit,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("stale receipt refuses");
        assert_eq!(refused.gap, JournalGap::ClosureStale);
        // Fresh production attestation under the live generation seals
        // new history.
        let next = begin_bytes(1, 2, create, 0);
        scene.ingest(&next);
        scene.ingest(&end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let birth = BootstrapReceipt::attest(
            &scene.adapter,
            &SessionBirthGrant::scripted(proof, BirthKind::ExecMarker, 0, advanced),
        )
        .expect("live generation attests");
        let frontier = scene.adapter.consumed_frontier();
        let fresh_audit = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            advanced,
        );
        let success = scene
            .seal_explicit(
                &fresh_audit,
                &birth,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&birth),
            )
            .expect("live generation seals");
        assert_eq!(success.prefix.settled().len(), 1);
        // Regressions refuse; repeats are idempotent; stale attestation
        // refuses at the constructor.
        assert!(
            !scene
                .adapter
                .install_closure_grant(&SessionClosureGrant::observe(scene.attachment()))
        );
        assert!(
            scene
                .adapter
                .install_closure_grant(&SessionClosureGrant::observe(aux.attachment()))
        );
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    proof,
                    BirthKind::ExecMarker,
                    0,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::ClosureStale)
        );
    }

    #[test]
    fn object_journal_stop_provider_continues() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // One creation seals, one call stays held, then stop invalidates
        // the tracked incarnation and reports it.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(2);
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let held = begin_bytes(1, 2, create, 0);
        scene.ingest(&held);
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("pre-stop seal passes");
        scene.adapter.stop(&mut scene.model);
        assert!(scene.model.project().gap(super::ObjectGap::Loss) >= 1);
        // The provider's late terminal meets a stopped adapter: refused
        // as unjournaled, never terminal proof and never a
        // contradiction. Stop Q is no terminal bound.
        let late = end_bytes(&held, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 90);
        let consumed = scene.adapter.consumed_through;
        assert_eq!(scene.ingest(&late), JournalDisposition::Refused);
        assert_eq!(scene.adapter.consumed_through, consumed + 1);
        assert_eq!(scene.ingest(&held), JournalDisposition::Refused);
        // Seals and attestations refuse; sealed history stays.
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let refused = scene
            .seal_explicit(
                &audit,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("stopped adapter never seals");
        assert_eq!(refused.gap, JournalGap::Stopped);
        let readmitted = scene.fixture.admit();
        assert_eq!(
            scene.adapter.attest_key(&readmitted),
            Err(AttestationRefusal::Stopped)
        );
        assert_eq!(scene.model.project().objects.len(), 1);
        // Stop is idempotent and quiet the second time.
        let again = scene.adapter.stop(&mut scene.model);
        assert!(again.effects.is_empty());
    }

    #[test]
    fn object_journal_image_sighting_capacity() {
        // Two sightings fit; the third image is untrackable: its record
        // is refused and the image tainted, while tracked images stay
        // useful.
        let mut scene = Scene::new_with_limits(
            image_default(),
            JournalLimits {
                open_calls: 8,
                thread_floors: 8,
                refused_begins: 8,
                domain_keys: 8,
                image_sightings: 2,
            },
        );
        let create = function_id("C_CreateObject");
        let getinfo = function_id("C_GetInfo");
        let anchor = begin_bytes(1, 1, create, 0);
        let mut first = ordinary_for(&anchor, 0);
        first.slot = 99;
        first.target_function = getinfo;
        assert_eq!(
            scene.ingest_ordinary(first),
            JournalDisposition::OrdinaryCounted
        );
        let image_b = ImageIdentity {
            task_cookie: COOKIE + 11,
            exec_id: EXEC,
        };
        let mut second = ordinary_for(&anchor, 0);
        second.slot = 99;
        second.image = image_b;
        second.target_function = getinfo;
        assert_eq!(
            scene.ingest_ordinary(second),
            JournalDisposition::OrdinaryCounted
        );
        let image_c = ImageIdentity {
            task_cookie: COOKIE + 12,
            exec_id: EXEC,
        };
        let mut third = ordinary_for(&anchor, 0);
        third.slot = 99;
        third.image = image_c;
        third.target_function = getinfo;
        assert_eq!(scene.ingest_ordinary(third), JournalDisposition::Refused);
        let mut other = AttestationFixture::new(image_c);
        assert_eq!(
            scene.adapter.attest_key(&other.admit()),
            Err(AttestationRefusal::ImageTainted)
        );
        // A journal record for a fourth image refuses the same way,
        // before any dispatch.
        let fourth = begin_bytes_image(5, 1, create, 0, (COOKIE + 13, EXEC));
        assert_eq!(scene.ingest(&fourth), JournalDisposition::Refused);
        // Tracked images still attest and seal.
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(
            &begin,
            p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE,
            0,
            ENTRY_NS + 50,
        ));
        let bootstrap = scene.bootstrap(proof, 0);
        scene
            .seal(&bootstrap)
            .expect("tracked image seals under a full table");
    }

    #[test]
    fn object_journal_void_fence_is_monotonic() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // An unregistered key fences adapter-side only: the void reports
        // no model effects, and births below the fence refuse.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let malformed = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            1,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            scene.closure_generation(),
        );
        let failure = scene
            .seal_explicit(
                &malformed,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("malformed tick refuses");
        assert_eq!(failure.gap, JournalGap::Malformed);
        assert!(failure.effects.effects.is_empty());
        let fence = scene.adapter.consumed_through;
        assert_eq!(fence, 2);
        let below = BootstrapReceipt::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            fence - 1,
            scene.closure_generation(),
        );
        let audit = scene.audit();
        let refused = scene
            .seal_explicit(
                &audit,
                &below,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&below),
            )
            .expect_err("birth below the fence refuses");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);

        // A second void raises the fence; resumption names the latest
        // one, and floors survive the void.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("first seal registers");
        let malformed = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            1,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            scene.closure_generation(),
        );
        let frontier = scene.adapter.consumed_frontier();
        let failure = scene
            .seal_explicit(
                &malformed,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("first void refuses");
        assert_eq!(failure.gap, JournalGap::Malformed);
        assert!(has_effect(&failure.effects, "retired"));
        scene.ingest(&begin_bytes(1, 2, create, 0));
        let malformed = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            1,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            scene.closure_generation(),
        );
        let frontier = scene.adapter.consumed_frontier();
        assert_eq!(scene.adapter.consumed_through, 3);
        let failure = scene
            .seal_explicit(
                &malformed,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("second void refuses");
        assert_eq!(failure.gap, JournalGap::Malformed);
        let below = BootstrapReceipt::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            2,
            scene.closure_generation(),
        );
        let audit = scene.audit();
        let refused = scene
            .seal_explicit(
                &audit,
                &below,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&below),
            )
            .expect_err("birth below the latest fence refuses");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);
        let fresh = begin_bytes(1, 9, create, 0);
        scene.ingest(&fresh);
        scene.ingest(&end_bytes(&fresh, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 70));
        // The voids cleared admission claims: re-attest for the new history.
        scene.attest();
        let resume = BootstrapReceipt::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            3,
            scene.closure_generation(),
        );
        let success = scene.seal(&resume).expect("resumption names the fence");
        assert_eq!(success.prefix.birth_cut(), 3);
        assert_eq!(success.prefix.bootstrap_cut(), Some(4));
        assert_eq!(success.prefix.settled().len(), 1);
    }

    #[test]
    fn object_journal_birth_after_h3_void_respects_fence() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // An H3 loss voids the registered key. A later birth for a key
        // that did not exist at the void, naming a cut below the void,
        // must refuse: its claimed-complete interval includes the loss.
        // Absence resumption exactly at the fence stays sound.
        let mut scene = Scene::new(image_default());
        let y_proof = scene.attest();
        let create = function_id("C_CreateObject");
        let y_begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&y_begin);
        scene.ingest(&end_bytes(&y_begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        // Shed call for X: observed (ordinal 3) while X's key is
        // unregistered, then lost to the H3 void below.
        let x_image = ImageIdentity {
            task_cookie: COOKIE + 1,
            exec_id: EXEC,
        };
        let shed_begin = begin_bytes_image(9, 9, create, 0, (x_image.task_cookie, x_image.exec_id));
        scene.ingest_ordinary(ordinary_for(&shed_begin, 0));
        assert_eq!(scene.adapter.consumed_through, 3);
        let y_bootstrap = scene.bootstrap(y_proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let loss = JournalAuditReceipt::scripted_h0(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_loss(2),
            scene.closure_generation(),
            6,
        );
        let failure = scene
            .seal_explicit(
                &loss,
                &y_bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&y_bootstrap),
            )
            .expect_err("H3 loss voids");
        assert_eq!(failure.gap, JournalGap::H3Loss);
        assert_eq!(failure.h3_voided, Some(6));
        // New history for X above the void: ordinals 4-5.
        let x_begin = begin_bytes_image(2, 1, create, 0, (x_image.task_cookie, x_image.exec_id));
        scene.ingest(&x_begin);
        let x_end = end_bytes(&x_begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60);
        assert_eq!(scene.ingest(&x_end), JournalDisposition::EndStaged);
        // X's key is bound only after the void.
        let mut x_fixture = AttestationFixture::new(x_image);
        let x_proof = scene.admit_other_end(&mut x_fixture, "C_CreateObject", &x_end);
        // An exec-marker birth below the fence refuses at attestation.
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    x_proof,
                    BirthKind::ExecMarker,
                    0,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::BelowVoidFence)
        );
        // The seal refuses the same cut even when attestation is bypassed.
        let scripted = BootstrapReceipt::scripted(
            x_proof,
            BirthKind::ExecMarker,
            0,
            scene.closure_generation(),
        );
        let audit = scene.audit();
        let frontier = scene.adapter.consumed_frontier();
        let refused = scene
            .seal_explicit(
                &audit,
                &scripted,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&scripted),
            )
            .expect_err("seal below the fence refuses");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);
        // Absence below the fence refuses as well.
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    x_proof,
                    BirthKind::AbsenceAppearance,
                    0,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::BelowVoidFence)
        );
        // Absence exactly at the fence resumes and seals the new history.
        let resume = BootstrapReceipt::attest(
            &scene.adapter,
            &SessionBirthGrant::scripted(
                x_proof,
                BirthKind::AbsenceAppearance,
                3,
                scene.closure_generation(),
            ),
        )
        .expect("absence at the fence attests");
        let success = scene.seal(&resume).expect("absence at the fence seals");
        assert_eq!(success.prefix.settled().len(), 1);
    }

    #[test]
    fn object_journal_fork_child_birth_after_parent_h3_void_respects_fence() {
        use crate::semantics_objects::{Birth, FieldState, KeyLabel, Lifetime, ViewOrigin};
        use p11scope_ebpf_common::event_type;
        use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_ACCESS, OBJECT_ACTION_CREATE};

        // The parent seals a create plus an RSA-2048 label read, then the
        // lane voids on H3 loss. Child C is forked before the void, child
        // A at the void ordinal, child B after it (all fork-without-exec:
        // fresh cookie, parent exec id). No child birth may name a cut
        // below the void, and no child publish may carry the voided
        // parent label: inherited session and object words join as
        // first-observed unknowns in the child's own domain.
        const INHERITED_KEY: u64 = 0x9090_9090_9090_9090;
        let mut scene = Scene::new(image_default());
        let create = function_id("C_CreateObject");
        let getattr = function_id("C_GetAttributeValue");
        let sign_init = function_id("C_SignInit");
        let init_capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
        let query_capture = capture::MECHANISM_NONE | capture::OUTPUT_NULL;

        // Ordinals 1-2: the parent creates the object the children inherit.
        let p_begin = begin_bytes(1, 1, create, 0);
        let p_end = end_bytes(&p_begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        scene.ingest(&p_begin);
        scene.ingest(&p_end);
        // Ordinal 3: fork record sighting pre-void child C.
        let child_c = ImageIdentity {
            task_cookie: COOKIE + 7,
            exec_id: EXEC,
        };
        let mut fork_c = ordinary_for(&p_begin, 0);
        fork_c.event_type = event_type::FORK;
        fork_c.child_image = child_c;
        assert_eq!(
            scene.ingest_ordinary(fork_c),
            JournalDisposition::OrdinaryCounted
        );
        // Ordinals 4-5: the parent establishes RSA-2048 on the object.
        let p_get = begin_bytes_shaped(
            1,
            2,
            getattr,
            0,
            (COOKIE, EXEC),
            SESSION,
            0,
            query_capture,
            Some((INHERITED_KEY, 1)),
            None,
            FLAGS,
        );
        let p_get_end = end_bytes_getattr(
            &p_get,
            0,
            ENTRY_NS + 55,
            &[(1, 1, 3), (2, 1, 0), (5, 1, 2048)],
        );
        scene.ingest(&p_get);
        assert_eq!(scene.ingest(&p_get_end), JournalDisposition::EndStaged);
        // Admit and seal the parent history before the void.
        let JournalRecord::End(create_return) =
            decode_journal_record(&p_end, &scene.descriptors).unwrap()
        else {
            panic!("END")
        };
        let admitted_create = scene
            .fixture
            .admit_original_event("C_CreateObject", create_return.payload_base().event);
        let parent_proof = scene.adapter.attest_key(&admitted_create).unwrap();
        let JournalRecord::End(get_return) =
            decode_journal_record(&p_get_end, &scene.descriptors).unwrap()
        else {
            panic!("END")
        };
        let admitted_get = scene
            .fixture
            .admit_original_event("C_GetAttributeValue", get_return.payload_base().event);
        scene.adapter.attest_key(&admitted_get).unwrap();
        let parent_seal = scene
            .seal(&scene.bootstrap(parent_proof, 0))
            .expect("parent seals before the void");
        assert_eq!(parent_seal.prefix.settled().len(), 2);
        let parent_view = parent_seal
            .effects
            .effects
            .iter()
            .find_map(|effect| match effect {
                ObjectEffect::Created { object, .. } => Some(*object),
                _ => None,
            })
            .expect("parent create effect");
        {
            let projection = scene.model.project();
            let view = projection.object(parent_view).expect("parent view");
            assert_eq!(view.label, Some(KeyLabel::Rsa { modulus_bits: 2048 }));
            assert_eq!(view.lifetime, Lifetime::Live);
        }
        // Ordinal 6: fork record sighting child A at the void ordinal.
        let child_a = ImageIdentity {
            task_cookie: COOKIE + 9,
            exec_id: EXEC,
        };
        let mut fork_a = ordinary_for(&p_begin, 0);
        fork_a.event_type = event_type::FORK;
        fork_a.child_image = child_a;
        assert_eq!(
            scene.ingest_ordinary(fork_a),
            JournalDisposition::OrdinaryCounted
        );
        assert_eq!(scene.adapter.consumed_through, 6);
        // H3 loss voids at 6 with the parent key present.
        let void_bootstrap = scene.bootstrap(parent_proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let loss = JournalAuditReceipt::scripted_h0(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_loss(2),
            scene.closure_generation(),
            6,
        );
        let failure = scene
            .seal_explicit(
                &loss,
                &void_bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&void_bootstrap),
            )
            .expect_err("H3 loss voids");
        assert_eq!(failure.gap, JournalGap::H3Loss);
        assert_eq!(failure.h3_voided, Some(6));
        // The voided parent label stays in the model, retired: the
        // children's unknowns below prove non-inheritance, not absence.
        {
            let projection = scene.model.project();
            let view = projection.object(parent_view).expect("voided parent view");
            assert_eq!(view.lifetime, Lifetime::Retired(ObjectGap::OutcomeLost));
            assert_eq!(view.label, Some(KeyLabel::Rsa { modulus_bits: 2048 }));
        }
        // Ordinal 7: fork record sighting post-void child B.
        let child_b = ImageIdentity {
            task_cookie: COOKIE + 11,
            exec_id: EXEC,
        };
        let mut fork_b = ordinary_for(&p_begin, 0);
        fork_b.event_type = event_type::FORK;
        fork_b.child_image = child_b;
        assert_eq!(
            scene.ingest_ordinary(fork_b),
            JournalDisposition::OrdinaryCounted
        );
        // Each child signs once with the inherited session and key words.
        let sign_call = |thread: u64, image: ImageIdentity, ts: u64| {
            let begin = begin_bytes_shaped(
                thread,
                1,
                sign_init,
                0,
                (image.task_cookie, image.exec_id),
                SESSION,
                1,
                init_capture,
                Some((INHERITED_KEY, 1)),
                None,
                FLAGS,
            );
            let end = end_bytes(&begin, OBJECT_ACTION_ACCESS, 0, ts);
            (begin, end)
        };
        let (a_begin, a_end) = sign_call(2, child_a, ENTRY_NS + 60);
        scene.ingest(&a_begin);
        assert_eq!(scene.ingest(&a_end), JournalDisposition::EndStaged);
        let (b_begin, b_end) = sign_call(3, child_b, ENTRY_NS + 70);
        scene.ingest(&b_begin);
        assert_eq!(scene.ingest(&b_end), JournalDisposition::EndStaged);
        let (c_begin, c_end) = sign_call(4, child_c, ENTRY_NS + 80);
        scene.ingest(&c_begin);
        assert_eq!(scene.ingest(&c_end), JournalDisposition::EndStaged);
        // All three child keys bind only after the void.
        let mut fa = AttestationFixture::new(child_a);
        let a_proof = scene.admit_other_end(&mut fa, "C_SignInit", &a_end);
        let mut fb = AttestationFixture::new(child_b);
        let b_proof = scene.admit_other_end(&mut fb, "C_SignInit", &b_end);
        let mut fc = AttestationFixture::new(child_c);
        let c_proof = scene.admit_other_end(&mut fc, "C_SignInit", &c_end);
        let attest = |scene: &Scene, proof: JournalDomainProof, birth: BirthKind, cut: u64| {
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(proof, birth, cut, scene.closure_generation()),
            )
        };
        // Below the fence every child birth refuses, both kinds, at the
        // cut and at the boundary just under it.
        for (proof, who) in [(a_proof, "A"), (b_proof, "B"), (c_proof, "C")] {
            for birth in [BirthKind::ExecMarker, BirthKind::AbsenceAppearance] {
                assert_eq!(
                    attest(&scene, proof, birth, 0),
                    Err(BirthRefusal::BelowVoidFence),
                    "{who} cut 0 {birth:?}"
                );
                assert_eq!(
                    attest(&scene, proof, birth, 5),
                    Err(BirthRefusal::BelowVoidFence),
                    "{who} cut 5 {birth:?}"
                );
            }
        }
        // At the fence the kind rules still apply on top of it.
        assert_eq!(
            attest(&scene, a_proof, BirthKind::ExecMarker, 6),
            Err(BirthRefusal::NoveltyBroken),
            "A sighted at its cut"
        );
        assert_eq!(
            attest(&scene, b_proof, BirthKind::AbsenceAppearance, 6),
            Err(BirthRefusal::AbsenceUnproven),
            "B unseen at its cut"
        );
        assert_eq!(
            attest(&scene, b_proof, BirthKind::AbsenceAppearance, 7),
            Err(BirthRefusal::AbsenceUnproven),
            "B fork inheritance is affecting"
        );
        assert_eq!(
            attest(&scene, c_proof, BirthKind::ExecMarker, 6),
            Err(BirthRefusal::NoveltyBroken),
            "C fenced past is still a past"
        );
        // Scripted receipts bypassing attestation still refuse at seal.
        let audit = scene.audit();
        let frontier = scene.adapter.consumed_frontier();
        for (proof, birth, who) in [
            (a_proof, BirthKind::ExecMarker, "A exec"),
            (b_proof, BirthKind::ExecMarker, "B exec"),
            (a_proof, BirthKind::AbsenceAppearance, "A absence"),
            (b_proof, BirthKind::AbsenceAppearance, "B absence"),
        ] {
            let scripted = BootstrapReceipt::scripted(proof, birth, 0, scene.closure_generation());
            let refused = scene
                .seal_explicit(
                    &audit,
                    &scripted,
                    frontier,
                    SessionBirthEvidence::scripted_for_receipt(&scripted),
                )
                .expect_err("seal below the fence refuses");
            assert_eq!(refused.gap, JournalGap::BootstrapMismatch, "{who}");
        }
        // C's absence cut 5 passes birth verification (a pre-void fork is
        // fenced history) but the seal refuses it below the fence.
        let scripted = BootstrapReceipt::scripted(
            c_proof,
            BirthKind::AbsenceAppearance,
            5,
            scene.closure_generation(),
        );
        let refused = scene
            .seal_explicit(
                &audit,
                &scripted,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&scripted),
            )
            .expect_err("seal below the fence refuses");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);
        // Sound resumptions at the fence attest and seal one settled call
        // each, strictly above the void.
        let a_receipt = attest(&scene, a_proof, BirthKind::AbsenceAppearance, 6)
            .expect("A absence at the fence attests");
        let b_receipt =
            attest(&scene, b_proof, BirthKind::ExecMarker, 6).expect("B exec at the fence attests");
        let c_receipt = attest(&scene, c_proof, BirthKind::AbsenceAppearance, 6)
            .expect("C absence at the fence attests");
        let a_seal = scene.seal(&a_receipt).expect("A seals");
        let b_seal = scene.seal(&b_receipt).expect("B seals");
        let c_seal = scene.seal(&c_receipt).expect("C seals");
        for (seal, begin_cut, who) in [(&a_seal, 8, "A"), (&b_seal, 10, "B"), (&c_seal, 12, "C")] {
            assert_eq!(seal.prefix.settled().len(), 1, "{who}");
            assert_eq!(seal.prefix.settled()[0].begin_cut, begin_cut, "{who}");
            assert_eq!(seal.prefix.settled()[0].function, sign_init, "{who}");
            assert_eq!(seal.prefix.birth_cut(), 6, "{who}");
            assert_eq!(seal.prefix.bootstrap_cut(), Some(7), "{who}");
        }
        // Each child joins the inherited words as a fresh session and a
        // fresh view: the published key use carries no inherited label.
        let mut child_views = Vec::new();
        for (seal, who) in [(&a_seal, "A"), (&b_seal, "B"), (&c_seal, "C")] {
            assert!(
                seal.effects
                    .effects
                    .iter()
                    .any(|effect| matches!(effect, ObjectEffect::SessionFirstObserved { .. })),
                "{who} fresh session"
            );
            let first = seal
                .effects
                .effects
                .iter()
                .find_map(|effect| match effect {
                    ObjectEffect::FirstObserved { object, .. } => Some(*object),
                    _ => None,
                })
                .expect("fresh child view");
            assert_ne!(first, parent_view, "{who} view is not the parent view");
            let joined = seal
                .effects
                .effects
                .iter()
                .find_map(|effect| match effect {
                    ObjectEffect::Referenced {
                        object,
                        key_use,
                        label,
                        metadata,
                        ..
                    } if *object == first => Some((*key_use, *label, *metadata)),
                    _ => None,
                })
                .expect("child key use");
            assert!(joined.0, "{who} key use");
            assert_eq!(joined.1, None, "{who} no inherited label");
            assert_eq!(
                joined.2.established_count(),
                0,
                "{who} no inherited metadata"
            );
            assert_eq!(joined.2.requested_count(), 0, "{who} nothing requested");
            child_views.push((first, who));
        }
        assert_ne!(child_views[0].0, child_views[1].0);
        assert_ne!(child_views[0].0, child_views[2].0);
        assert_ne!(child_views[1].0, child_views[2].0);
        {
            let projection = scene.model.project();
            for (id, who) in &child_views {
                let view = projection.object(*id).expect("child view");
                assert_eq!(view.origin, ViewOrigin::FirstObserved, "{who}");
                assert_eq!(view.birth, Birth::Unknown, "{who}");
                assert_eq!(view.label, None, "{who}");
                for kind in [
                    SafeAttributeKind::Class,
                    SafeAttributeKind::KeyType,
                    SafeAttributeKind::Token,
                    SafeAttributeKind::ValueLen,
                    SafeAttributeKind::ModulusBits,
                    SafeAttributeKind::EcParams,
                ] {
                    assert_eq!(
                        view.established.field(kind),
                        FieldState::Unknown,
                        "{who} {kind:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn object_journal_fork_exec_child_birth_after_parent_h3_void_respects_fence() {
        use p11scope_ebpf_common::event_type;
        use p11scope_ebpf_common::object_wire::{OBJECT_ACTION_ACCESS, OBJECT_ACTION_CREATE};

        // Fork plus exec: the fork record names the pre-exec image while
        // the child's calls arrive under the post-exec image, which has
        // no fork sighting of its own. Below-fence births refuse; exec
        // birth at the fence resumes without the voided parent history.
        // The post-exec image uses a distinct cookie: the attestation
        // fixture's legacy observation hard-codes exec 0, and every
        // journal/model key uses the exact (cookie, exec) pair, so a
        // distinct pair exercises the identical paths.
        const INHERITED_KEY: u64 = 0x9090_9090_9090_9090;
        let mut scene = Scene::new(image_default());
        let y_proof = scene.attest();
        let create = function_id("C_CreateObject");
        let sign_init = function_id("C_SignInit");
        let p_begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&p_begin);
        scene.ingest(&end_bytes(&p_begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        // Ordinal 3: fork record naming the pre-exec child image.
        let pre_exec = ImageIdentity {
            task_cookie: COOKIE + 13,
            exec_id: EXEC,
        };
        let post_exec = ImageIdentity {
            task_cookie: COOKIE + 14,
            exec_id: EXEC,
        };
        let mut fork = ordinary_for(&p_begin, 0);
        fork.event_type = event_type::FORK;
        fork.child_image = pre_exec;
        assert_eq!(
            scene.ingest_ordinary(fork),
            JournalDisposition::OrdinaryCounted
        );
        assert_eq!(scene.adapter.consumed_through, 3);
        let y_bootstrap = scene.bootstrap(y_proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let loss = JournalAuditReceipt::scripted_h0(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_loss(2),
            scene.closure_generation(),
            6,
        );
        let failure = scene
            .seal_explicit(
                &loss,
                &y_bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&y_bootstrap),
            )
            .expect_err("H3 loss voids");
        assert_eq!(failure.gap, JournalGap::H3Loss);
        // Ordinals 4-5: the post-exec child signs with inherited words.
        let begin = begin_bytes_shaped(
            2,
            1,
            sign_init,
            0,
            (post_exec.task_cookie, post_exec.exec_id),
            SESSION,
            1,
            capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
            Some((INHERITED_KEY, 1)),
            None,
            FLAGS,
        );
        let end = end_bytes(&begin, OBJECT_ACTION_ACCESS, 0, ENTRY_NS + 60);
        scene.ingest(&begin);
        assert_eq!(scene.ingest(&end), JournalDisposition::EndStaged);
        let mut fixture = AttestationFixture::new(post_exec);
        let proof = scene.admit_other_end(&mut fixture, "C_SignInit", &end);
        let attest = |scene: &Scene, birth: BirthKind, cut: u64| {
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(proof, birth, cut, scene.closure_generation()),
            )
        };
        assert_eq!(
            attest(&scene, BirthKind::ExecMarker, 0),
            Err(BirthRefusal::BelowVoidFence)
        );
        assert_eq!(
            attest(&scene, BirthKind::AbsenceAppearance, 0),
            Err(BirthRefusal::BelowVoidFence)
        );
        assert_eq!(
            attest(&scene, BirthKind::AbsenceAppearance, 3),
            Err(BirthRefusal::AbsenceUnproven),
            "post-exec image unseen at the fence"
        );
        // A scripted receipt bypassing attestation still refuses at seal.
        let scripted =
            BootstrapReceipt::scripted(proof, BirthKind::ExecMarker, 0, scene.closure_generation());
        let audit = scene.audit();
        let frontier = scene.adapter.consumed_frontier();
        let refused = scene
            .seal_explicit(
                &audit,
                &scripted,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&scripted),
            )
            .expect_err("seal below the fence refuses");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);
        // Exec birth at the fence resumes and seals without inheritance.
        let receipt = attest(&scene, BirthKind::ExecMarker, 3).expect("exec at the fence attests");
        let success = scene.seal(&receipt).expect("exec at the fence seals");
        assert_eq!(success.prefix.settled().len(), 1);
        assert_eq!(success.prefix.settled()[0].begin_cut, 4);
        assert_eq!(success.prefix.birth_cut(), 3);
        assert!(
            success
                .effects
                .effects
                .iter()
                .any(|effect| matches!(effect, ObjectEffect::FirstObserved { .. }))
        );
        let joined = success
            .effects
            .effects
            .iter()
            .find_map(|effect| match effect {
                ObjectEffect::Referenced {
                    label, metadata, ..
                } => Some((*label, *metadata)),
                _ => None,
            })
            .expect("child key use");
        assert_eq!(joined.0, None);
        assert_eq!(joined.1.established_count(), 0);
    }

    #[test]
    fn object_journal_bootstrap_requires_birth_and_closure() {
        use p11scope_ebpf_common::object_journal::JOURNAL_BEGIN_NO_END;
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // G10 gate: genuine image-bound post-attachment birth plus the
        // closed endpoint set permits bootstrap through production
        // attestation; pre-attachment birth, a foreign domain, an
        // unsupported affecting endpoint and a stale closure refuse.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let birth = BootstrapReceipt::attest(
            &scene.adapter,
            &SessionBirthGrant::scripted(
                proof,
                BirthKind::ExecMarker,
                0,
                scene.closure_generation(),
            ),
        )
        .expect("genuine birth attests");
        let success = scene.seal(&birth).expect("genuine birth seals");
        assert_eq!(success.prefix.settled().len(), 1);
        assert_eq!(success.prefix.birth_cut(), 0);

        // Pre-attachment birth: an END with no BEGIN proves pre-attach
        // provider history and taints the image before any key binds.
        let mut scene = Scene::new(image_default());
        scene.attest();
        let ghost = begin_bytes(1, 1, create, 0);
        let orphan = end_bytes(&ghost, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        assert_eq!(
            scene.ingest(&orphan),
            JournalDisposition::Contradiction(JournalContradiction::TerminalBeforeBegin)
        );
        let readmitted = scene.fixture.admit();
        assert_eq!(
            scene.adapter.attest_key(&readmitted),
            Err(AttestationRefusal::ImageTainted)
        );

        // Foreign domain: a proof minted on another adapter names no key
        // here, so the seal cannot bind it.
        let mut scene = Scene::new(image_default());
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let mut foreign = Scene::new(image_default());
        let foreign_proof = foreign.attest();
        let receipt = BootstrapReceipt::scripted(
            foreign_proof,
            BirthKind::ExecMarker,
            0,
            scene.closure_generation(),
        );
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let refused = scene
            .seal_explicit(
                &audit,
                &receipt,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&receipt),
            )
            .expect_err("foreign proof never binds");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);

        // Unsupported affecting endpoint: its invocation taints, and
        // birth attestation refuses the image.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let encap = function_id("C_EncapsulateKey");
        assert_eq!(
            scene.ingest(&begin_bytes(1, 1, encap, JOURNAL_BEGIN_NO_END)),
            JournalDisposition::NegativeOnlyInvalidated
        );
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                &SessionBirthGrant::scripted(
                    proof,
                    BirthKind::ExecMarker,
                    0,
                    scene.closure_generation()
                )
            ),
            Err(BirthRefusal::ImageTainted)
        );

        // Stale closure: advancing the generation retires the receipt.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let birth = BootstrapReceipt::attest(
            &scene.adapter,
            &SessionBirthGrant::scripted(
                proof,
                BirthKind::ExecMarker,
                0,
                scene.closure_generation(),
            ),
        )
        .expect("birth attests");
        let aux = AttestationFixture::new(image_default());
        assert!(
            scene
                .adapter
                .install_closure_grant(&SessionClosureGrant::observe(aux.attachment()))
        );
        let frontier = scene.adapter.consumed_frontier();
        let audit = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            1,
        );
        let refused = scene
            .seal_explicit(
                &audit,
                &birth,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&birth),
            )
            .expect_err("stale closure refuses");
        assert_eq!(refused.gap, JournalGap::ClosureStale);
    }

    #[test]
    fn object_journal_policy_capacity_bounds() {
        // At policy scale: 16,448 thread floors fill across sealing
        // batches and the 16,449th taints its image (floors never
        // recycle); then 1,024 opens fill the table on one live thread
        // and the 1,025th is refused for capacity, never dropped.
        let mut scene = Scene::new(image_default());
        // H3 admits each call before its batch seals; conversions
        // consume as they go (one in-flight admission stays ahead).
        let proof = scene.attest_function("C_Sign");
        let sign = function_id("C_Sign");
        let bootstrap = scene.bootstrap(proof, 0);
        for thread in 1..=16_448u64 {
            scene.attest_function("C_Sign");
            let begin = begin_bytes(thread, 1, sign, 0);
            scene.ingest(&begin);
            scene.ingest(&end_bytes_absent(&begin, 0, ENTRY_NS + 50));
            if thread % 512 == 0 || thread == 16_448 {
                scene.seal(&bootstrap).expect("batch seal passes");
            }
        }
        assert_eq!(scene.adapter.floors.len(), 16_448);
        assert_eq!(scene.adapter.sightings.len(), 1);
        assert!(scene.adapter.open.is_empty());
        // The 16,449th thread arrives on another image so the exhaustion
        // taint does not touch the scene image under test.
        let overflow = begin_bytes_image(16_449, 1, sign, 0, (COOKIE + 21, EXEC));
        assert_eq!(
            scene.ingest(&overflow),
            JournalDisposition::Contradiction(JournalContradiction::FloorExhausted)
        );
        // New threads refuse now, but the live thread still admits up to
        // the open bound.
        let create = function_id("C_CreateObject");
        for sequence in 2..=1_025u64 {
            let begin = begin_bytes(1, sequence, create, 0);
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
        }
        assert_eq!(scene.adapter.open.len(), 1_024);
        assert_eq!(
            scene.ingest(&begin_bytes(1, 1_026, create, 0)),
            JournalDisposition::BeginRefusedCapacity
        );
        assert_eq!(scene.adapter.refused.len(), 1);
        assert_eq!(scene.adapter.floors.len(), 16_448);
    }

    #[test]
    fn object_journal_taint_set_is_bounded() {
        // I5: the taint set is capped at the sighting bound. A hundred
        // untrackable newcomers past a cap of four must not retain a
        // hundred taints; their records refuse and the retention stays
        // flat.
        let create = function_id("C_CreateObject");
        let mut scene = Scene::new_with_limits(
            image_default(),
            JournalLimits {
                open_calls: 8,
                thread_floors: 512,
                refused_begins: 8,
                domain_keys: 4,
                image_sightings: 4,
            },
        );
        let first = begin_bytes(1, 1, create, 0);
        assert_eq!(scene.ingest(&first), JournalDisposition::BeginAdmitted);
        // Three newcomers still fit the sighting table (each on its own
        // thread); the remaining 97 are untrackable and refuse.
        for (i, cookie) in (1000..1100u64).enumerate() {
            let begin = begin_bytes_image(cookie, 1, create, 0, (cookie, EXEC));
            if i < 3 {
                assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
            } else {
                assert_eq!(scene.ingest(&begin), JournalDisposition::Refused);
            }
        }
        assert!(
            scene.adapter.tainted_images.len() <= 4,
            "taint set capped, got {}",
            scene.adapter.tainted_images.len()
        );
        // The overflow latches; unrecorded newcomers still count as
        // tainted and refuse, while tracked images keep working.
        assert!(scene.adapter.taint_overflow);
        assert!(scene.adapter.is_tainted((1050, EXEC)));
        assert!(!scene.adapter.is_tainted((COOKIE, EXEC)));
        assert!(!scene.adapter.is_tainted((1000, EXEC)));
        let again = begin_bytes_image(1050, 2, create, 0, (1050, EXEC));
        assert_eq!(scene.ingest(&again), JournalDisposition::Refused);
        let tracked = begin_bytes_image(1000, 2, create, 0, (1000, EXEC));
        assert_eq!(scene.ingest(&tracked), JournalDisposition::BeginAdmitted);
    }

    #[test]
    fn object_journal_bounded_uppers_keep_max_only() {
        // I5: only the maximum bounded-loss upper is retained. Two
        // bounded losses across two seals must not grow a per-loss
        // vector; the fence needs the max alone.
        use p11scope_ebpf_common::object_journal::JOURNAL_REASON_SYNC_RETURN_RESULT_LOST;
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(3);
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        scene.ingest(&first);
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 40));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("first seal covers through 2");
        for sequence in [2u64, 3] {
            let begin = begin_bytes(1, sequence, create, 0);
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
            assert_eq!(
                scene.ingest_ordinary(ordinary_for(&begin, 0)),
                JournalDisposition::ReturnObserved
            );
            assert_eq!(
                scene.ingest(&abandon_bytes(
                    1,
                    sequence,
                    JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
                    (COOKIE, EXEC)
                )),
                JournalDisposition::AbandonStaged
            );
            let bootstrap = scene.bootstrap(proof, 0);
            scene.seal(&bootstrap).expect("bounded loss seals");
        }
        let state = scene.adapter.keys.get(&proof.key).expect("sealed key");
        // Return cuts 4 then 7: the retained max is 7, never a vector.
        assert_eq!(state.bounded_upper, Some(7));
    }

    #[test]
    fn object_journal_refused_begin_propagates_invalidation_effects() {
        // I4: a capacity refusal retires live views; those retirement
        // effects must reach the seal's effects, never a dropped local.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new_with_limits(
            image_default(),
            JournalLimits {
                open_calls: 2,
                thread_floors: 8,
                refused_begins: 2,
                domain_keys: 4,
                image_sightings: 8,
            },
        );
        let proof = scene.attest_calls(2);
        scene.attest_session_function(0x1111_1111_1111_1111, "C_CreateObject");
        scene.attest_session_function(0x2222_2222_2222_2222, "C_CreateObject");
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        scene.ingest(&first);
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 40));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("creation seals");
        assert_eq!(scene.model.project().objects.len(), 1);
        // Fill the open table, then one capacity refusal with a
        // corroborating return. The open begins carry distinct session
        // words so the return witnesses only the refused begin.
        let mut second = begin_bytes(1, 2, create, 0);
        put_u64(&mut second, 80, 0x1111_1111_1111_1111);
        let mut third = begin_bytes(1, 3, create, 0);
        put_u64(&mut third, 80, 0x2222_2222_2222_2222);
        assert_eq!(scene.ingest(&second), JournalDisposition::BeginAdmitted);
        assert_eq!(scene.ingest(&third), JournalDisposition::BeginAdmitted);
        let fourth = begin_bytes(1, 4, create, 0);
        assert_eq!(
            scene.ingest(&fourth),
            JournalDisposition::BeginRefusedCapacity
        );
        assert_eq!(
            scene.ingest_ordinary(ordinary_for(&fourth, 0)),
            JournalDisposition::ReturnObserved
        );
        // The frontier must cover the bound's authority before the seal
        // claims it.
        let mut pad = ordinary_for(&fourth, 0);
        pad.slot = 99;
        scene.ingest_ordinary(pad);
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene
            .seal(&bootstrap)
            .expect("refusal seals with its bound");
        assert!(
            success.effects.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::Retired {
                    reason: super::ObjectGap::PendingCapacity,
                    ..
                }
            )),
            "retirement reaches seal effects: {:?}",
            success.effects.effects
        );
    }

    #[test]
    fn object_journal_long_open_call_spans_seals() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // One neutral call held open across fifty seals while fifty
        // creations complete: the watermark holds the span, every seal
        // lists the held call, and the late terminal settles it without
        // disturbing settled history. The held call is neutral (a slow
        // operation), since a held creation would genuinely collide with
        // everything inside its span.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(50);
        scene.attest_function("C_Sign");
        let create = function_id("C_CreateObject");
        let sign = function_id("C_Sign");
        let held = begin_bytes(1, 1, sign, 0);
        scene.ingest(&held);
        let bootstrap = scene.bootstrap(proof, 0);
        let mut settled_total = 0;
        for sequence in 2..=51u64 {
            let begin = begin_bytes(1, sequence, create, 0);
            scene.ingest(&begin);
            // Distinct result handles: fifty-one creates minting one
            // handle would be genuinely contradictory aliasing.
            let mut end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
            put_u64(&mut end, 24 + 368 + 32, 0x9000_0000_0000_0000 + sequence);
            scene.ingest(&end);
            let sealed = scene.seal(&bootstrap).expect("span seal passes");
            // The open list is cumulative: every seal lists the held call
            // while newly settling exactly its own pair.
            assert_eq!(sealed.prefix.open_keys().len(), 1);
            settled_total += sealed.prefix.settled().len();
        }
        assert_eq!(settled_total, 51);
        // The watermark held everything: nothing applied yet.
        assert!(scene.model.project().objects.is_empty());
        scene.ingest(&end_bytes_absent(&held, 0, ENTRY_NS + 90));
        let closed = scene.seal(&bootstrap).expect("closing seal passes");
        assert!(closed.prefix.open_keys().is_empty());
        assert_eq!(scene.model.project().objects.len(), 50);
    }

    #[test]
    fn object_journal_settle_bootstrap_rejection_fails_the_seal() {
        // I1: a seal whose required bootstrap authority the model
        // rejects fails (ModelRefused) instead of succeeding with the
        // rejection riding along: no frontier advance, no pruning,
        // staged inputs kept for a later seal.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(2);
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        scene.ingest(&first);
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 40));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("first seal passes");
        assert!(scene.adapter.open.is_empty());
        // A model-side refusal the adapter mirror never drove: an
        // unbound refused begin fences the model's authority.
        let domain = super::ObjectDomain::sealed(&proof);
        let _ = scene.model.note_refused_begin(
            domain,
            super::RefCut::reference(99),
            scene.adapter.ledger_mut(),
        );
        let next = begin_bytes(1, 2, create, 0);
        scene.ingest(&next);
        scene.ingest(&end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let failure = scene
            .seal(&bootstrap)
            .expect_err("rejected authority fails the seal");
        assert_eq!(failure.gap, JournalGap::ModelRefused);
        // Nothing advanced, nothing pruned, nothing tainted: the key
        // can seal again once authority clears.
        let state = scene.adapter.keys.get(&proof.key).expect("sealed key");
        assert_eq!(state.sealed_through, 2);
        assert!(!state.refused && !state.tainted);
        assert!(!scene.adapter.open.is_empty());
    }

    #[test]
    fn object_journal_settle_prefix_contradiction_fails_the_seal() {
        // I1: a seal whose open alignment the model contradicts fails
        // (ModelRefused) — including a continuation seal, which claims
        // no new bootstrap but still requires the model's agreement on
        // the listed opens.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_function_n("C_Sign", 2);
        let sign = function_id("C_Sign");
        scene.ingest(&begin_bytes(1, 1, sign, 0));
        let bootstrap = scene.bootstrap(proof, 0);
        let held = scene.seal(&bootstrap).expect("open call seals held");
        let ticket = held.prefix.settled()[0].ticket;
        // The model's custody diverges behind the adapter's back: the
        // ticket the adapter still lists as open is gone.
        let _ = scene.model.outcome_lost(
            crate::semantics_objects::LostOutcome::Ticket(ticket, super::RefCut::reference(999)),
            scene.adapter.ledger_mut(),
        );
        scene.ingest(&begin_bytes(1, 2, sign, 0));
        let failure = scene
            .seal(&bootstrap)
            .expect_err("contradicted alignment fails the seal");
        assert_eq!(failure.gap, JournalGap::ModelRefused);
        let state = scene.adapter.keys.get(&proof.key).expect("sealed key");
        assert_eq!(state.sealed_through, 1);
        assert!(!state.refused && !state.tainted);
    }

    #[test]
    fn object_journal_fence_is_strictly_above_birth() {
        // I1: the derived fence strictly increments the birth. Absence
        // births at cut 5 with history above; the seal claims 6, never 5.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let template = begin_bytes(1, 1, create, 0);
        for _ in 1..=5u64 {
            let mut seen = ordinary_for(&template, 0);
            seen.slot = 99;
            scene.ingest_algorithm_quiet(seen);
        }
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let evidence = SessionBirthEvidence::scripted(
            (COOKIE, EXEC),
            p11scope_ebpf_common::journal_marker::MARKER_UNPUBLISHED,
            0,
            scene.closure_generation(),
            1,
        );
        let grant = SessionBirthGrant::scripted_with_evidence(
            proof,
            BirthKind::AbsenceAppearance,
            5,
            scene.closure_generation(),
            evidence,
        );
        let birth = BootstrapReceipt::attest(&scene.adapter, &grant).expect("absence attests at 5");
        let success = scene.seal(&birth).expect("birth seals");
        assert_eq!(success.prefix.birth_cut(), 5);
        assert_eq!(success.prefix.bootstrap_cut(), Some(6));
    }

    #[test]
    fn object_journal_model_floors_refuse_cut_exhaustion() {
        // Carryover 7: the derived floor is strictly above every
        // authority bound, and cut-space exhaustion refuses explicitly
        // instead of saturating (an unchanged MAX frontier must never
        // pass again). The seal's floor inputs never exceed the
        // consumed frontier, so exhaustion is unreachable end to end;
        // this pins the real derivation helper the seal calls.
        assert_eq!(derive_model_floors(5, 3, 0, None, &[]), Ok(6));
        assert_eq!(derive_model_floors(5, 9, 7, Some(4), &[6]), Ok(10));
        assert_eq!(
            derive_model_floors(5, 9, 7, Some(u64::MAX), &[]),
            Err(JournalGap::CutExhausted)
        );
        assert_eq!(
            derive_model_floors(u64::MAX, 0, 0, None, &[]),
            Err(JournalGap::CutExhausted)
        );
        assert_eq!(
            derive_model_floors(0, 0, 0, None, &[u64::MAX]),
            Err(JournalGap::CutExhausted)
        );
    }

    #[test]
    fn object_journal_held_below_floors_continues_without_claim() {
        // I1: held calls pinning below the floors make the seal a
        // continuation: no new bootstrap is claimed (None), the model
        // keeps its floor, and no doomed fence draws a refusal.
        let mut scene = Scene::new_with_limits(
            image_default(),
            JournalLimits {
                open_calls: 2,
                thread_floors: 8,
                refused_begins: 2,
                domain_keys: 4,
                image_sightings: 8,
            },
        );
        let proof = scene.attest();
        scene.attest_session_function(0x1111_1111_1111_1111, "C_CreateObject");
        scene.attest_session_function(0x2222_2222_2222_2222, "C_CreateObject");
        let create = function_id("C_CreateObject");
        let mut first = begin_bytes(1, 1, create, 0);
        put_u64(&mut first, 80, 0x1111_1111_1111_1111);
        let mut second = begin_bytes(1, 2, create, 0);
        put_u64(&mut second, 80, 0x2222_2222_2222_2222);
        scene.ingest(&first);
        scene.ingest(&second);
        let third = begin_bytes(1, 3, create, 0);
        assert_eq!(
            scene.ingest(&third),
            JournalDisposition::BeginRefusedCapacity
        );
        assert_eq!(
            scene.ingest_ordinary(ordinary_for(&third, 0)),
            JournalDisposition::ReturnObserved
        );
        let mut pad = ordinary_for(&third, 0);
        pad.slot = 99;
        scene.ingest_ordinary(pad);
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene.seal(&bootstrap).expect("continuation seals");
        assert_eq!(success.prefix.bootstrap_cut(), None);
        assert!(
            !success.effects.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::Gap {
                    reason: super::ObjectGap::BootstrapRefused
                }
            )),
            "no doomed fence, no refusal: {:?}",
            success.effects.effects
        );
        assert!(scene.adapter.refused.is_empty());
    }

    #[test]
    fn object_journal_late_terminal_emits_delta() {
        // I2: a terminal arriving after its BEGIN's first seal appears in
        // the closing prefix as an explicit terminal delta — H9's
        // delivery contract, not just the model result.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_function("C_Sign");
        // The held call is neutral (a slow operation), mirroring the
        // long-open test: a held creation would genuinely collide.
        let sign = function_id("C_Sign");
        let begin = begin_bytes(1, 1, sign, 0);
        scene.ingest(&begin);
        let bootstrap = scene.bootstrap(proof, 0);
        let held = scene.seal(&bootstrap).expect("open call seals held");
        assert_eq!(held.prefix.settled().len(), 1);
        let ticket = held.prefix.settled()[0].ticket;
        assert_eq!(held.prefix.settled()[0].end_cut, None);
        assert_eq!(
            scene.ingest(&end_bytes_absent(&begin, 0, ENTRY_NS + 90)),
            JournalDisposition::EndStaged
        );
        let closed = scene.seal(&bootstrap).expect("closing seal passes");
        assert!(closed.prefix.open_keys().is_empty());
        let delta = closed
            .prefix
            .settled()
            .iter()
            .find(|summary| summary.ticket == ticket)
            .expect("closing prefix carries the terminal delta");
        assert_eq!(delta.begin_cut, 1);
        assert_eq!(delta.end_cut, Some(scene.adapter.consumed_through));
        assert!(!delta.abandoned);
    }

    #[test]
    fn object_journal_production_birth_requires_session_evidence() {
        // C1: the production constructor takes a Session-owned birth
        // grant; there is no grantless stream-inference path (it does not
        // compile). A grant consistent with retained truth attests and
        // seals; inconsistent or stale grants refuse at the backstop.
        // Production grants mint only through the Session issuance
        // capability, which has no issuance site until the H8-D native
        // witnesses wire — so production attestation fails closed.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        scene.ingest(&begin_bytes(1, 1, create, 0));
        scene.install_observed_closure();
        let grant = SessionBirthGrant::scripted(
            proof,
            BirthKind::ExecMarker,
            0,
            scene.closure_generation(),
        );
        let birth =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("consistent grant attests");
        scene.seal(&birth).expect("granted birth seals");
        // The image was sighted at 1, so an exec claim at cut 1 refuses
        // even with a grant in hand: the grant is checked, not trusted.
        let inconsistent = SessionBirthGrant::scripted(
            proof,
            BirthKind::ExecMarker,
            1,
            scene.closure_generation(),
        );
        assert_eq!(
            BootstrapReceipt::attest(&scene.adapter, &inconsistent),
            Err(BirthRefusal::NoveltyBroken)
        );
        // A grant under a non-live generation refuses at the constructor.
        let aux = AttestationFixture::new(image_default());
        let stale = SessionBirthGrant::scripted(
            proof,
            BirthKind::ExecMarker,
            0,
            aux.attachment().generation(),
        );
        assert_eq!(
            BootstrapReceipt::attest(&scene.adapter, &stale),
            Err(BirthRefusal::ClosureStale)
        );
    }

    #[test]
    fn object_journal_closure_reattest_requires_fresh_session_evidence() {
        // C1: installing a new closure retires the old grant.
        // Re-attesting with the old grant refuses; only a fresh grant
        // under the live generation (fresh Session attachment evidence)
        // attests.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        scene.ingest(&begin_bytes(1, 1, create, 0));
        scene.install_observed_closure();
        let old_grant = SessionBirthGrant::scripted(
            proof,
            BirthKind::ExecMarker,
            0,
            scene.closure_generation(),
        );
        BootstrapReceipt::attest(&scene.adapter, &old_grant).expect("observed grant attests");
        let aux = AttestationFixture::new(image_default());
        assert!(
            scene
                .adapter
                .install_closure_grant(&SessionClosureGrant::observe(aux.attachment()))
        );
        assert_eq!(
            BootstrapReceipt::attest(&scene.adapter, &old_grant),
            Err(BirthRefusal::ClosureStale)
        );
        let fresh = SessionBirthGrant::scripted(
            proof,
            BirthKind::ExecMarker,
            0,
            aux.attachment().generation(),
        );
        BootstrapReceipt::attest(&scene.adapter, &fresh).expect("fresh grant attests");
    }

    #[test]
    fn object_journal_birth_grant_evidence_is_checked() {
        // C1: the grant's Session-observed native evidence is CHECKED at
        // attestation, not just carried. Each corruption below refuses
        // with EvidenceMismatch; canonical evidence attests. Marker
        // words use the real native encoding (low two bits state).
        use p11scope_ebpf_common::journal_marker::{MARKER_DIRTY, MARKER_UNPUBLISHED, ready_word};
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        // Ordinal 1 observes the image without affecting it (proved
        // irrelevant), so absence can birth at cut 1; the BEGIN at 2
        // keeps exec novel only at cut 0.
        let mut seen = ordinary_for(&begin, 0);
        seen.slot = 99;
        scene.ingest_algorithm_quiet(seen);
        scene.ingest(&begin);
        let image = (COOKIE, EXEC);
        let ready = ready_word(EXEC);
        let closure = scene.closure_generation();
        let bad_exec = [
            // Wrong observed image.
            SessionBirthEvidence::scripted((COOKIE + 1, EXEC), ready, 0, closure, 1),
            // Zero custody binds nothing.
            SessionBirthEvidence::scripted(image, ready, 0, closure, 0),
            // A tripped admission latch withholds birth.
            SessionBirthEvidence::scripted(image, ready, 1, closure, 1),
            // Unpublished is not an exec publication.
            SessionBirthEvidence::scripted(image, MARKER_UNPUBLISHED, 0, closure, 1),
            // A scope-dirtied marker is not an exec publication.
            SessionBirthEvidence::scripted(image, MARKER_DIRTY, 0, closure, 1),
            // An invalid marker word refuses.
            SessionBirthEvidence::scripted(image, ready | 1, 0, closure, 1),
            // The marker names another exec id.
            SessionBirthEvidence::scripted(image, ready_word(EXEC + 1), 0, closure, 1),
            // The exec did not happen under this closure.
            SessionBirthEvidence::scripted(image, ready, 0, closure.wrapping_add(1), 1),
        ];
        for evidence in bad_exec {
            let grant = SessionBirthGrant::scripted_with_evidence(
                proof,
                BirthKind::ExecMarker,
                0,
                scene.closure_generation(),
                evidence,
            );
            assert_eq!(
                BootstrapReceipt::attest(&scene.adapter, &grant),
                Err(BirthRefusal::EvidenceMismatch)
            );
        }
        // Absence requires the unmarked word: READY, dirty and
        // invalid words all refuse as absence evidence.
        for word in [ready, MARKER_DIRTY, ready | 1] {
            let evidence = SessionBirthEvidence::scripted(image, word, 0, closure, 1);
            let grant = SessionBirthGrant::scripted_with_evidence(
                proof,
                BirthKind::AbsenceAppearance,
                1,
                scene.closure_generation(),
                evidence,
            );
            assert_eq!(
                BootstrapReceipt::attest(&scene.adapter, &grant),
                Err(BirthRefusal::EvidenceMismatch)
            );
        }
        // Canonical evidence attests both kinds.
        for birth in [BirthKind::ExecMarker, BirthKind::AbsenceAppearance] {
            let cut = u64::from(birth == BirthKind::AbsenceAppearance);
            let grant = SessionBirthGrant::scripted(proof, birth, cut, scene.closure_generation());
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("canonical evidence attests");
        }
    }

    /// C1 genuine-producer rig: the birth-row publisher fixture runs
    /// the REAL marker leaves over real rows and dumps native bytes.
    /// Only the argv parameters are injected; every dumped byte comes
    /// from the production publication/dirty/admission
    /// implementation. See
    /// `tests/fixtures/object-journal/birth_row_publisher.c`.
    /// Exposed `pub(crate)` so H9 Joint tests can bootstrap from the
    /// same genuine-producer chain as T3 founding (see
    /// `object_journal_session_exec_birth_observes_genuine_producers`).
    pub(crate) struct NativePublisher {
        _dir: tempfile::TempDir,
        binary: std::path::PathBuf,
    }

    impl NativePublisher {
        pub(crate) fn build() -> Self {
            let dir = tempfile::tempdir().expect("publisher directory");
            let binary = dir.path().join("birth-row-publisher");
            let output = std::process::Command::new("clang-18")
                .args([
                    "-O2",
                    "-g",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    "crates/ebpf/native",
                    "tests/fixtures/object-journal/birth_row_publisher.c",
                    "-o",
                ])
                .arg(&binary)
                .output()
                .expect("execute clang-18");
            assert!(
                output.status.success(),
                "publisher compile: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Self { _dir: dir, binary }
        }

        /// Run the publisher and parse the ROW/CTL hex dumps into the
        /// native structs (little-endian u64 cells, matching the C
        /// layouts byte for byte). Returns the row, the control row,
        /// and the native win count.
        pub(crate) fn publish(
            &self,
            args: &[&str],
        ) -> (
            p11scope_ebpf_common::InstanceRecord,
            p11scope_ebpf_common::JournalAdmissionControl,
            u64,
        ) {
            let output = std::process::Command::new(&self.binary)
                .args(args)
                .output()
                .expect("execute publisher");
            assert!(
                output.status.success(),
                "publisher [{}]: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).expect("publisher utf8");
            let mut row = None;
            let mut control = None;
            let mut wins = None;
            for line in stdout.lines() {
                if let Some(hex) = line.strip_prefix("ROW ") {
                    row = Some(parse_published_row(hex));
                } else if let Some(hex) = line.strip_prefix("CTL ") {
                    control = Some(parse_published_control(hex));
                } else if let Some(count) = line.strip_prefix("WINS ") {
                    wins = Some(count.parse::<u64>().expect("wins integer"));
                }
            }
            (
                row.expect("ROW dump"),
                control.expect("CTL dump"),
                wins.expect("WINS dump"),
            )
        }

        /// Run the publisher with the `exec_attach_gen` word stamped:
        /// the argv-settled exec stamp the generation comparison pins.
        /// Short argv pads with zeros through `nopub` so the stamp
        /// always lands in the sixth slot.
        pub(crate) fn publish_stamped(
            &self,
            args: &[&str],
            stamp: u64,
        ) -> (
            p11scope_ebpf_common::InstanceRecord,
            p11scope_ebpf_common::JournalAdmissionControl,
            u64,
        ) {
            let stamp_arg = stamp.to_string();
            let mut full: Vec<&str> = args.to_vec();
            while full.len() < 5 {
                full.push("0");
            }
            full.push(&stamp_arg);
            self.publish(&full)
        }
    }

    /// Parse one publisher hex dump (bytes in memory order) into
    /// little-endian u64 cells.
    fn parse_hex_cells(hex: &str, cells: usize, what: &str) -> Vec<u64> {
        assert_eq!(hex.len(), cells * 16, "{what} hex length");
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex byte"))
            .collect();
        bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect()
    }

    /// 8 slot_plus1 + 8 epoch + flags + exec_attach_gen + marker.
    fn parse_published_row(hex: &str) -> p11scope_ebpf_common::InstanceRecord {
        let cells = parse_hex_cells(hex, 19, "ROW");
        p11scope_ebpf_common::InstanceRecord {
            slot_plus1: cells[0..8].try_into().expect("slots"),
            epoch: cells[8..16].try_into().expect("epochs"),
            flags: cells[16],
            exec_attach_gen: cells[17],
            journal_bootstrap: cells[18],
        }
    }

    fn parse_published_control(hex: &str) -> p11scope_ebpf_common::JournalAdmissionControl {
        let cells = parse_hex_cells(hex, 2, "CTL");
        p11scope_ebpf_common::JournalAdmissionControl {
            spent: cells[0],
            failed: cells[1],
        }
    }

    /// Birth-row reader over one publisher dump: the rows a real
    /// native publication left behind.
    pub(crate) struct NativeBirthRows {
        pub(crate) row: p11scope_ebpf_common::InstanceRecord,
        pub(crate) control: p11scope_ebpf_common::JournalAdmissionControl,
    }

    impl crate::attach::BirthRowReader for NativeBirthRows {
        fn read_marker_row(
            &mut self,
        ) -> Result<p11scope_ebpf_common::InstanceRecord, crate::attach::BirthRowError> {
            Ok(self.row)
        }

        fn read_admission_control(
            &mut self,
        ) -> Result<p11scope_ebpf_common::JournalAdmissionControl, crate::attach::BirthRowError>
        {
            Ok(self.control)
        }
    }

    /// Failure-injecting reader: a missing side reads back unreadable
    /// (map error, short buffer). Only the ERROR is injected; a
    /// present side carries real published bytes.
    struct FaultyRows {
        row: Option<p11scope_ebpf_common::InstanceRecord>,
        control: Option<p11scope_ebpf_common::JournalAdmissionControl>,
    }

    impl crate::attach::BirthRowReader for FaultyRows {
        fn read_marker_row(
            &mut self,
        ) -> Result<p11scope_ebpf_common::InstanceRecord, crate::attach::BirthRowError> {
            self.row.ok_or(crate::attach::BirthRowError::Unreadable)
        }

        fn read_admission_control(
            &mut self,
        ) -> Result<p11scope_ebpf_common::JournalAdmissionControl, crate::attach::BirthRowError>
        {
            self.control.ok_or(crate::attach::BirthRowError::Unreadable)
        }
    }

    /// One watched-file load through the PRODUCTION scan protocol.
    /// The I/O values enter through `acquire_test_scan` (the same
    /// seam every router test uses: no userspace-runnable producer
    /// exists for BPF map scans — the live path is `scan_image`,
    /// UNRUN here), and the proof still passes all of `scan_with`'s
    /// checks before the real router joins it.
    const SCAN_FILE: u32 = 3;
    const SCAN_BASE: u64 = 0x8000_0000;

    fn scan_ranges_full() -> Vec<crate::discovery::instances::MapRange> {
        use crate::discovery::instances::MapRange;
        vec![
            MapRange::new(SCAN_BASE, SCAN_BASE + 0x1000, 0, false),
            MapRange::new(SCAN_BASE + 0x1000, SCAN_BASE + 0x2000, 0x1000, true),
            MapRange::new(SCAN_BASE + 0x2000, SCAN_BASE + 0x3000, 0x2000, false),
        ]
    }

    fn absence_maps_entry(
        start: u64,
        end: u64,
        major: u64,
        minor: u64,
        inode: u64,
    ) -> p11scope_manifest::maps::MapEntry {
        p11scope_manifest::maps::MapEntry {
            start,
            end,
            file_offset: 0,
            permissions: *b"r-xp",
            device: p11scope_manifest::maps::Device { major, minor },
            inode,
            raw_path: None,
        }
    }

    /// A complete process enumeration with no watched-provider
    /// mapping: exe/libc/stack-style entries under unrelated
    /// identities.
    fn absence_entries_free() -> Vec<p11scope_manifest::maps::MapEntry> {
        vec![
            absence_maps_entry(0x400000, 0x401000, 8, 2, 1001),
            absence_maps_entry(0x7f00_0000, 0x7f00_1000, 8, 2, 2002),
            absence_maps_entry(0x7fff_0000, 0x7fff_1000, 0, 0, 0),
        ]
    }

    /// The mremap shape: the SAME file-backed watched mapping moved
    /// to disjoint addresses. Identity decides, never addresses: this
    /// enumeration is not provider-free.
    fn absence_entries_mremapped() -> Vec<p11scope_manifest::maps::MapEntry> {
        let mut entries = absence_entries_free();
        entries.push(absence_maps_entry(
            SCAN_BASE + 0x50000,
            SCAN_BASE + 0x51000,
            8,
            1,
            999,
        ));
        entries
    }

    fn absence_watched_keys() -> Vec<p11scope_manifest::maps::ObjectKey> {
        vec![p11scope_manifest::maps::ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 999,
        }]
    }

    fn absence_watched_identity() -> crate::discovery::instances::MappedFileIdentity {
        crate::discovery::instances::MappedFileIdentity {
            dev: 0x801,
            ino: 999,
        }
    }

    /// One sealed negative witness through the PRODUCTION absence
    /// protocol: the enumeration, attach cell and confirmation enter
    /// through `acquire_test_absence` (the same seam shape every
    /// scan test uses), and the witness still passes all of
    /// `prove_absence_with`'s checks. Confirmation matches the
    /// watched identity (a moved mapping confirms; a provider-free
    /// enumeration consults no candidate at all).
    fn absence_proof(
        domain: NativeDomainId,
        cookie: u64,
        file_slot: u32,
        local: u64,
        attach: u64,
        entries: Vec<p11scope_manifest::maps::MapEntry>,
        fence: u64,
    ) -> crate::attach::image_query::ImageAbsenceProof {
        crate::attach::image_query::acquire_test_absence(
            domain,
            ImageIdentity {
                task_cookie: cookie,
                exec_id: EXEC,
            },
            file_slot,
            crate::attach::image_query::CompleteEpochs {
                local,
                global: 0,
                fault: 0,
                sticky: 0,
                record_flags: 0,
            },
            entries,
            attach,
            absence_watched_keys(),
            absence_watched_identity(),
            |_, _| Ok(absence_watched_identity()),
            fence,
        )
        .expect("provider-free enumeration seals")
    }

    fn scan_proof(
        domain: NativeDomainId,
        cookie: u64,
        file_slot: u32,
        local: u64,
        ranges: Vec<crate::discovery::instances::MapRange>,
        fence: u64,
    ) -> crate::attach::image_query::ImageScanProof {
        scan_proof_at_fault(domain, cookie, file_slot, local, ranges, fence, 0)
    }

    fn scan_proof_at_fault(
        domain: NativeDomainId,
        cookie: u64,
        file_slot: u32,
        local: u64,
        ranges: Vec<crate::discovery::instances::MapRange>,
        fence: u64,
        fault: u64,
    ) -> crate::attach::image_query::ImageScanProof {
        crate::attach::image_query::acquire_test_scan(
            domain,
            ImageIdentity {
                task_cookie: cookie,
                exec_id: EXEC,
            },
            file_slot,
            crate::attach::image_query::CompleteEpochs {
                local,
                global: 0,
                fault,
                sticky: 0,
                record_flags: 0,
            },
            ranges,
            fence,
        )
        .expect("stable scan seals")
    }

    fn scan_router(domain: NativeDomainId) -> crate::discovery::instances::InstanceRouter {
        crate::discovery::instances::InstanceRouter::new(
            domain,
            crate::discovery::instances::RouterLimits::default(),
        )
    }

    #[test]
    fn object_journal_session_bindings_are_genuine() {
        // C1: no scripted() binding constructors anywhere in this
        // module — happy-path bindings traverse the coordinator's real
        // bind proof, and refusal crosses are genuine bindings paired
        // against foreign admissions (never fabricated namings).
        let source = std::fs::read_to_string("src/semantics_objects/journal.rs")
            .expect("read journal module");
        // The needle is assembled so this probe does not trip on its
        // own mention of the constructor it forbids.
        let needle = ["SemanticCallerBinding", "scripted"].join("::");
        assert!(
            !source.contains(&needle),
            "scripted bindings remain in journal.rs"
        );
    }

    #[test]
    fn unjournaled_normalization_precedes_adapter_sightings_and_key_accounting() {
        use p11scope_ebpf_common::object_journal::{JOURNAL_END_UNJOURNALED, pack_compact_end};
        // Composed decoder/adapter coverage only: no producer, live Session,
        // kernel Q attestation or semantic object-tail authority is activated.
        for absent in [false, true] {
            let begin = begin_bytes(
                1,
                1,
                function_id(if absent { "C_Sign" } else { "C_CreateObject" }),
                0,
            );
            let full = if absent {
                end_bytes_absent(&begin, 0, ENTRY_NS + 100)
            } else {
                end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 100)
            };
            for compact in [false, true] {
                let mut wire = if compact {
                    pack_compact_end(1, 1, full[5], &full[24..])
                        .unwrap()
                        .to_vec()
                } else {
                    full.to_vec()
                };
                wire[5] |= JOURNAL_END_UNJOURNALED;
                wire[8..24].fill(0);
                for bounded in [false, true] {
                    let mut scene = Scene::new(image_default());
                    let _proof = scene.attest();
                    scene.bind_session_drain();
                    let keys_before = scene.adapter.keys.len();
                    assert!(scene.adapter.sightings.is_empty());
                    if bounded {
                        let mut drain = crate::events::EventDrain::over_test_domain(
                            BusyScript::new(vec![wire.clone()]),
                            scene.retained_events.id(),
                        );
                        assert_eq!(
                            scene.drain_bounded_to(&mut drain, 8).unwrap(),
                            (false, false)
                        );
                        assert_eq!(drain.malformed(), 0);
                        assert_eq!(
                            crate::events::BoundedRecordSource::consumer(drain.source()),
                            8
                        );
                    } else {
                        let mut drain = crate::events::EventDrain::over_test_domain(
                            crate::events::ScriptedRecords::records([wire.clone()], 1),
                            scene.retained_events.id(),
                        );
                        let collection = scene.adapter.collect_from_drain(
                            &mut drain,
                            &scene.descriptors,
                            Some(1),
                            &ScriptedFaultCell::steady(0),
                            scene.fixture.h0_allocated_below(),
                        );
                        assert_eq!((collection.ingested, collection.ordinary), (0, 1));
                        assert_eq!(collection.malformed_delta, 0);
                        assert_eq!(collection.discarded_delta, 0);
                    }
                    assert_eq!(scene.adapter.consumed_through, 1);
                    let sighting = scene.adapter.sightings.get(&(COOKIE, EXEC)).unwrap();
                    assert_eq!(sighting.first_seen, 1);
                    assert_eq!(sighting.first_affecting, Some(1));
                    assert_eq!(scene.adapter.sightings.len(), 1);
                    assert_eq!(scene.adapter.keys.len(), keys_before);
                    assert!(scene.adapter.open.is_empty());
                    assert!(scene.adapter.floors.is_empty());
                    assert!(scene.adapter.physical_return_floors.is_empty());
                    assert!(scene.adapter.refused.is_empty());
                    assert!(!scene.adapter.is_tainted((COOKIE, EXEC)));
                }
            }
        }
    }

    #[test]
    fn joint_ordinary_async_target_cannot_make_a_quiet_sighting() {
        // target_function names an async target argument, not this
        // physical endpoint. Trusting it could hide affecting history
        // underneath an absence birth cut before any H3 admission.
        let mut scene = Scene::new(image_default());
        let begin = begin_bytes(1, 1, function_id("C_Sign"), 0);
        let mut event = ordinary_for(&begin, 0);
        event.target_function = function_id("C_GetInfo");
        scene.ingest_ordinary(event);
        let sighting = scene.adapter.sightings.get(&(COOKIE, EXEC)).unwrap();
        assert_eq!(sighting.first_seen, 1);
        assert_eq!(
            sighting.first_affecting,
            Some(1),
            "unadmitted ordinary input cannot be narrowed by an async target argument",
        );
    }

    #[test]
    fn joint_key_binding_precedes_ingest_without_claiming_original_start() {
        let mut scene = Scene::new(image_default());
        let begin = begin_bytes(1, 1, function_id("C_CreateObject"), 0);
        let end = end_bytes(
            &begin,
            p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE,
            0,
            ENTRY_NS + 100,
        );
        let JournalRecord::End(end) = decode_journal_record(&end, &scene.descriptors).unwrap()
        else {
            panic!("END");
        };
        let admitted = scene
            .fixture
            .admit_original_event("C_CreateObject", end.payload_base().event);
        let proof = scene.adapter.bind_admitted_key(&admitted).unwrap();
        assert_eq!(
            scene.adapter.claim_counts, 0,
            "binding grants no invocation claim"
        );
        assert!(scene.adapter.open.is_empty());
        scene.ingest(&begin);
        assert_eq!(scene.adapter.attest_key(&admitted).unwrap(), proof);
        assert_eq!(
            scene.adapter.claim_counts, 1,
            "normal attestation claims after the original START"
        );
    }

    #[test]
    fn object_journal_session_exec_birth_observes_genuine_producers() {
        // C1: Session-owned exec-marker birth end to end with zero
        // scripted birth constructors. Observation pulls the genuine
        // producers (a natively published READY marker naming the
        // admitted exec, a real admission control row, live held
        // custody, the sealed successful attachment, the admitted
        // image); the issued grant attests; a FRESH publisher run at
        // seal re-observes and converts.
        use crate::attach::observe_exec_birth;
        use p11scope_ebpf_common::journal_marker::ready_word;
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let paired_begin = begin_bytes(1, 1, function_id("C_CreateObject"), 0);
        let paired_end = end_bytes(&paired_begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        let JournalRecord::End(paired_end) =
            decode_journal_record(&paired_end, &scene.descriptors).unwrap()
        else {
            panic!("paired END")
        };
        let admitted = scene
            .fixture
            .admit_original_event("C_CreateObject", paired_end.payload_base().event);
        let proof = scene.adapter.attest_key(&admitted).expect("key attests");
        let (row, control, wins) =
            publisher.publish_stamped(&["0", "1"], scene.closure_generation());
        assert_eq!(wins, 1, "one real admission wins");
        let mut rows = NativeBirthRows { row, control };
        let (token, evidence) = observe_exec_birth(
            &mut rows,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        )
        .expect("genuine producers observe");
        assert_eq!(evidence.image(), (COOKIE, EXEC));
        assert_eq!(evidence.marker_word(), ready_word(EXEC));
        assert_eq!(evidence.admission_failed(), 0);
        assert_eq!(evidence.attach_generation(), scene.closure_generation());
        assert_eq!(
            evidence.custody(),
            scene.fixture.binding().pin().start_time().unwrap()
        );
        let grant = SessionBirthGrant::issue_for_native_row_test(
            &token,
            proof,
            BirthKind::ExecMarker,
            0,
            scene.closure_generation(),
            evidence,
        );
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        let birth =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("observed grant attests");
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        // Fresh native bytes at seal: a second publisher run, pulled
        // through a new reader — never the first run's words.
        let (fresh_row, fresh_control, _) =
            publisher.publish_stamped(&["0", "1"], scene.closure_generation());
        let mut fresh_rows = NativeBirthRows {
            row: fresh_row,
            control: fresh_control,
        };
        let (_, fresh) = observe_exec_birth(
            &mut fresh_rows,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        )
        .expect("fresh words re-observe");
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        scene
            .seal_explicit(&audit, &birth, frontier, fresh)
            .expect("observed birth seals");
    }

    #[test]
    fn object_journal_session_exec_birth_checks_generation() {
        // C1a(a): the exec witness requires READY plus matching
        // image/generation: the observed row's exec_attach_gen must
        // equal the sealed closure's minted generation, and the
        // evidence carries the observed word. Sweep native generations
        // under the fixed sealed closure: every non-equal value
        // refuses, only the equal one observes.
        use crate::attach::{BirthObservationRefusal, observe_exec_birth};

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        scene.adapter.attest_key(&admitted).expect("key attests");
        let closure = scene.closure_generation();
        let mut sweep = vec![0u64, 1, 99, closure, closure.wrapping_add(1)];
        sweep.sort_unstable();
        sweep.dedup();
        assert!(sweep.len() >= 2, "the sweep brackets the closure");
        for native_gen in sweep {
            let (row, control, _) = publisher.publish_stamped(&["0", "1"], native_gen);
            assert_eq!(
                row.exec_attach_gen, native_gen,
                "the publisher stamps the swept word"
            );
            let mut rows = NativeBirthRows { row, control };
            let outcome = observe_exec_birth(
                &mut rows,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted,
            );
            if native_gen == closure {
                let (_, evidence) = outcome.expect("the equal generation observes");
                assert_eq!(evidence.attach_generation(), closure);
            } else {
                assert_eq!(
                    outcome,
                    Err(BirthObservationRefusal::GenerationMismatch),
                    "native gen {native_gen} under closure {closure} refuses"
                );
            }
        }
    }

    #[test]
    fn object_journal_session_birth_observation_refuses_per_producer() {
        // C1: every genuine producer gates observation with its own
        // finite refusal; nothing mints on any failure. Every row
        // below is natively published (only the publisher argv varies);
        // only the row-read ERRORS are injected.
        use crate::attach::{BirthObservationRefusal, observe_exec_birth};
        use p11scope_ebpf_common::journal_marker::MARKER_ADMIT_CAP;

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        scene.adapter.attest_key(&admitted).expect("key attests");
        // Marker readback: unpublished, dirty and foreign-exec native
        // words are not this birth's publication. (The admitted exec
        // is 0, so exec 1 is foreign.)
        for args in [
            &["0", "0", "0", "0", "1"][..],
            &["0", "0", "1"][..],
            &["1"][..],
        ] {
            let (row, control, _) = publisher.publish(args);
            let mut rows = NativeBirthRows { row, control };
            assert_eq!(
                observe_exec_birth(
                    &mut rows,
                    scene.fixture.binding(),
                    scene.fixture.attachment(),
                    &admitted
                ),
                Err(BirthObservationRefusal::MarkerNotReady),
                "publisher [{:?}]",
                args
            );
        }
        // Admission control, all natively produced: an admit/exec
        // mismatch trips the failed latch; 2^24 real admits spend
        // the cap exactly (failed still clear); 2^24 - 1 admits observe.
        let (ready_row, _, _) = publisher.publish(&["0", "1"]);
        let (_, latched, latched_wins) = publisher.publish(&["0", "1", "0", "1"]);
        assert_eq!(latched_wins, 0, "mismatch admits nothing");
        assert_eq!(latched.failed, 1, "mismatch trips the latch natively");
        let mut rows = NativeBirthRows {
            row: ready_row,
            control: latched,
        };
        assert_eq!(
            observe_exec_birth(
                &mut rows,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted
            ),
            Err(BirthObservationRefusal::LatchTripped)
        );
        let (ready_row, spent, spent_wins) = publisher.publish(&["0", "16777216"]);
        assert_eq!(spent_wins, MARKER_ADMIT_CAP);
        assert_eq!((spent.spent, spent.failed), (MARKER_ADMIT_CAP, 0));
        let mut rows = NativeBirthRows {
            row: ready_row,
            control: spent,
        };
        assert_eq!(
            observe_exec_birth(
                &mut rows,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted
            ),
            Err(BirthObservationRefusal::SpentExhausted)
        );
        let (ready_row, nearly, nearly_wins) =
            publisher.publish_stamped(&["0", "16777215"], scene.closure_generation());
        assert_eq!(nearly_wins, MARKER_ADMIT_CAP - 1);
        let mut rows = NativeBirthRows {
            row: ready_row,
            control: nearly,
        };
        observe_exec_birth(
            &mut rows,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        )
        .expect("below-cap control observes");
        // Attachment: a seal under another domain is not this
        // admission's successful attachment.
        let foreign_scene = Scene::new(image_default());
        let (ready_row, control, _) = publisher.publish(&["0", "1"]);
        let mut rows = NativeBirthRows {
            row: ready_row,
            control,
        };
        assert_eq!(
            observe_exec_birth(
                &mut rows,
                scene.fixture.binding(),
                foreign_scene.fixture.attachment(),
                &admitted
            ),
            Err(BirthObservationRefusal::AttachmentMismatch)
        );
        // Binding: the held pin must be bound to the admitted
        // domain/image/caller — any other naming refuses. Each cross
        // is genuinely bound under its own name and live pid, then
        // crossed against the admitted call. One image has one
        // holder, so a genuine cross always differs in caller too;
        // each cross below differs in caller plus the named
        // dimension (image, domain, image again).
        let (domain, image, _, _) = admitted.journal_binding();
        let mut crossed_children = Vec::new();
        let mut crossed = Vec::new();
        for (cross_domain, cross_image) in [
            (
                domain,
                ImageIdentity {
                    task_cookie: image.task_cookie,
                    exec_id: image.exec_id + 1,
                },
            ),
            (NativeDomainId::mint(), image),
            (
                domain,
                ImageIdentity {
                    task_cookie: image.task_cookie,
                    exec_id: image.exec_id + 2,
                },
            ),
        ] {
            let child = std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .unwrap();
            crossed.push(
                scene
                    .fixture
                    .bind_extra(child.id(), cross_domain, cross_image),
            );
            crossed_children.push(child);
        }
        for misnamed in crossed {
            let (ready_row, control, _) = publisher.publish(&["0", "1"]);
            let mut rows = NativeBirthRows {
                row: ready_row,
                control,
            };
            assert_eq!(
                observe_exec_birth(
                    &mut rows,
                    scene.fixture.binding_for(misnamed),
                    scene.fixture.attachment(),
                    &admitted
                ),
                Err(BirthObservationRefusal::BindingMismatch)
            );
        }
        for mut child in crossed_children {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        // Row reads: an unreadable marker or control row refuses (the
        // present side of each pair is real published bytes).
        let (ready_row, control, _) = publisher.publish(&["0", "1"]);
        let mut rows = FaultyRows {
            row: None,
            control: Some(control),
        };
        assert_eq!(
            observe_exec_birth(
                &mut rows,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted
            ),
            Err(BirthObservationRefusal::RowUnreadable)
        );
        let mut rows = FaultyRows {
            row: Some(ready_row),
            control: None,
        };
        assert_eq!(
            observe_exec_birth(
                &mut rows,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted
            ),
            Err(BirthObservationRefusal::RowUnreadable)
        );
        // Custody, last: reaping the fixture's own incarnation kills
        // the exact pin the primary binding holds. The binding still
        // names the admitted triple, so custody — not naming — refuses.
        scene.fixture.child.kill().unwrap();
        scene.fixture.child.wait().unwrap();
        let (ready_row, control, _) = publisher.publish(&["0", "1"]);
        let mut rows = NativeBirthRows {
            row: ready_row,
            control,
        };
        assert_eq!(
            observe_exec_birth(
                &mut rows,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted
            ),
            Err(BirthObservationRefusal::CustodyLost)
        );
    }

    #[test]
    fn object_journal_session_exec_birth_recheck_withdraws_after_latch_or_cap() {
        // M6: an accepted birth is withdrawn at the next take: the
        // production recheck path re-runs the observation against
        // current native rows, so a latch tripped (or the cap spent)
        // after the first take refuses the second. Every row below
        // is natively published; only the take count advances.
        use crate::attach::{BirthObservationRefusal, ExecBirthSource};
        use crate::semantics_objects::journal::BirthEvidenceSource;

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        scene.adapter.attest_key(&admitted).expect("key attests");
        let (ready_row, control, _) =
            publisher.publish_stamped(&["0", "1"], scene.closure_generation());
        let mut first = ExecBirthSource::over(
            NativeBirthRows {
                row: ready_row,
                control,
            },
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        );
        first.take_birth_evidence().expect("below-cap birth takes");
        // The latch trips natively after the take (an admit/exec
        // mismatch); the same process re-taken refuses.
        let (_, latched, latched_wins) = publisher.publish(&["0", "1", "0", "1"]);
        assert_eq!(latched_wins, 0, "mismatch admits nothing");
        assert_eq!(latched.failed, 1, "mismatch trips the latch natively");
        let mut retake = ExecBirthSource::over(
            NativeBirthRows {
                row: ready_row,
                control: latched,
            },
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        );
        assert_eq!(
            retake.take_birth_evidence(),
            Err(BirthObservationRefusal::LatchTripped)
        );
        // Spending the cap natively after the take refuses the same way.
        let (_, spent, _) = publisher.publish(&["0", "16777216"]);
        let mut capped = ExecBirthSource::over(
            NativeBirthRows {
                row: ready_row,
                control: spent,
            },
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        );
        assert_eq!(
            capped.take_birth_evidence(),
            Err(BirthObservationRefusal::SpentExhausted)
        );
    }

    #[test]
    fn object_journal_session_absence_birth_seals_on_quiet_history() {
        // Same native-positive selector now exercises actual collected H0,
        // the earlier genuine absence/cut and one retained witness.
        crate::semantic_capture::assert_actual_absence_birth_fixture();
    }

    #[test]
    fn object_journal_session_absence_birth_refuses_per_producer() {
        // C1: every absence producer gates observation with its own
        // finite refusal; nothing mints on any failure. Rows are
        // natively published; the negative and the appearance pass
        // the production protocols; the router is real.
        use crate::attach::{BirthObservationRefusal, observe_absence_birth};

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        scene.adapter.attest_key(&admitted).expect("key attests");
        let (domain, _, _, _) = admitted.journal_binding();
        let full = scan_ranges_full();
        let closure = scene.closure_generation();
        // Marker: only the unmarked native word observes; a READY
        // publication or a DIRTY poisoning refuses.
        for args in [&["0", "1"][..], &["0", "0", "1"][..]] {
            let (row, control, _) = publisher.publish(args);
            let mut rows = NativeBirthRows { row, control };
            let mut router = scan_router(domain);
            assert_eq!(
                observe_absence_birth(
                    &mut rows,
                    absence_proof(
                        domain,
                        COOKIE,
                        SCAN_FILE,
                        0,
                        closure,
                        absence_entries_free(),
                        0
                    ),
                    scan_proof(domain, COOKIE, SCAN_FILE, 1, full.clone(), 0),
                    &mut router,
                    scene.fixture.binding(),
                    scene.fixture.attachment(),
                    &admitted,
                ),
                Err(BirthObservationRefusal::MarkerPublished),
                "publisher [{:?}]",
                args
            );
        }
        // Witness continuity: a negative of another process, or an
        // appearance of another process, domain, or file, is not this
        // birth's witness pair — whichever side drifts.
        let (row, control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
        for (negative_cookie, appearance_cookie) in [(COOKIE + 1, COOKIE + 1), (COOKIE, COOKIE + 1)]
        {
            let mut rows = NativeBirthRows { row, control };
            let mut router = scan_router(domain);
            assert_eq!(
                observe_absence_birth(
                    &mut rows,
                    absence_proof(
                        domain,
                        negative_cookie,
                        SCAN_FILE,
                        0,
                        closure,
                        absence_entries_free(),
                        0
                    ),
                    scan_proof(domain, appearance_cookie, SCAN_FILE, 1, full.clone(), 0),
                    &mut router,
                    scene.fixture.binding(),
                    scene.fixture.attachment(),
                    &admitted,
                ),
                Err(BirthObservationRefusal::AppearanceForeign),
                "negative {negative_cookie} appearance {appearance_cookie}"
            );
        }
        let mut rows = NativeBirthRows { row, control };
        let mut router = scan_router(domain);
        assert_eq!(
            observe_absence_birth(
                &mut rows,
                absence_proof(
                    domain,
                    COOKIE,
                    SCAN_FILE,
                    0,
                    closure,
                    absence_entries_free(),
                    0
                ),
                scan_proof(domain, COOKIE, SCAN_FILE + 1, 1, full.clone(), 0),
                &mut router,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted,
            ),
            Err(BirthObservationRefusal::AppearanceForeign)
        );
        let mut rows = NativeBirthRows { row, control };
        let mut router = scan_router(domain);
        assert_eq!(
            observe_absence_birth(
                &mut rows,
                absence_proof(
                    domain,
                    COOKIE,
                    SCAN_FILE,
                    0,
                    closure,
                    absence_entries_free(),
                    0
                ),
                scan_proof(
                    NativeDomainId::mint(),
                    COOKIE,
                    SCAN_FILE,
                    1,
                    full.clone(),
                    0
                ),
                &mut router,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted,
            ),
            Err(BirthObservationRefusal::AppearanceForeign)
        );
        // Generation: a negative that ran under another closure is
        // not this birth's witness.
        let mut rows = NativeBirthRows { row, control };
        let mut router = scan_router(domain);
        assert_eq!(
            observe_absence_birth(
                &mut rows,
                absence_proof(
                    domain,
                    COOKIE,
                    SCAN_FILE,
                    0,
                    closure.wrapping_add(1),
                    absence_entries_free(),
                    0
                ),
                scan_proof(domain, COOKIE, SCAN_FILE, 1, full.clone(), 0),
                &mut router,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted,
            ),
            Err(BirthObservationRefusal::GenerationMismatch)
        );
        // Advancement: unchanged counters past the negative are a
        // re-presentation, not an appearance.
        let mut rows = NativeBirthRows { row, control };
        let mut router = scan_router(domain);
        assert_eq!(
            observe_absence_birth(
                &mut rows,
                absence_proof(
                    domain,
                    COOKIE,
                    SCAN_FILE,
                    0,
                    closure,
                    absence_entries_free(),
                    0
                ),
                scan_proof(domain, COOKIE, SCAN_FILE, 0, full.clone(), 0),
                &mut router,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted,
            ),
            Err(BirthObservationRefusal::AppearanceNotAdvanced)
        );
        // New appearance: epochs the router already holds are not an
        // appearance (birth once, then re-present the same pair).
        let mut router = scan_router(domain);
        let mut rows = NativeBirthRows { row, control };
        observe_absence_birth(
            &mut rows,
            absence_proof(
                domain,
                COOKIE,
                SCAN_FILE,
                0,
                closure,
                absence_entries_free(),
                0,
            ),
            scan_proof(domain, COOKIE, SCAN_FILE, 1, full.clone(), 0),
            &mut router,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        )
        .expect("first presentation births");
        let mut rows = NativeBirthRows { row, control };
        assert_eq!(
            observe_absence_birth(
                &mut rows,
                absence_proof(
                    domain,
                    COOKIE,
                    SCAN_FILE,
                    0,
                    closure,
                    absence_entries_free(),
                    0
                ),
                scan_proof(domain, COOKIE, SCAN_FILE, 1, full.clone(), 0),
                &mut router,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted,
            ),
            Err(BirthObservationRefusal::AppearanceRejected)
        );
    }

    #[test]
    fn object_journal_session_absence_witness_refuses_moved_mapping() {
        // C1a(b): the disjoint-replacement reading is dead. A scan
        // that CONTAINS the watched mapping — the mremap shape (the
        // same file-backed mapping moved to disjoint addresses) —
        // cannot witness absence: the negative seal refuses with
        // Present, so the absence gate is unfirable and the positive
        // stays withheld. Identity decides, never addresses.
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        let (domain, _, _, _) = admitted.journal_binding();
        assert!(matches!(
            crate::attach::image_query::acquire_test_absence(
                domain,
                ImageIdentity {
                    task_cookie: COOKIE,
                    exec_id: EXEC,
                },
                SCAN_FILE,
                crate::attach::image_query::CompleteEpochs {
                    local: 0,
                    global: 0,
                    fault: 0,
                    sticky: 0,
                    record_flags: 0,
                },
                absence_entries_mremapped(),
                scene.closure_generation(),
                absence_watched_keys(),
                absence_watched_identity(),
                |_, _| Ok(absence_watched_identity()),
                0,
            ),
            Err(crate::attach::image_query::ImageQueryRefusal::Present)
        ));
    }

    #[test]
    fn object_journal_session_absence_withholds_positive_until_negative_commits() {
        // C1b: the positive stays withheld until the negative commits.
        // A refused negative leaves the router clean — the same
        // appearance still births once a committed negative precedes
        // it. (If the refused attempt had joined the appearance, the
        // retry would see AppearanceRejected instead of birthing.)
        use crate::attach::{BirthObservationRefusal, observe_absence_birth};

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        scene.adapter.attest_key(&admitted).expect("key attests");
        let (domain, _, _, _) = admitted.journal_binding();
        let full = scan_ranges_full();
        let closure = scene.closure_generation();
        let (row, control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
        let mut router = scan_router(domain);
        let mut rows = NativeBirthRows { row, control };
        assert_eq!(
            observe_absence_birth(
                &mut rows,
                absence_proof(
                    domain,
                    COOKIE,
                    SCAN_FILE,
                    0,
                    closure.wrapping_add(1),
                    absence_entries_free(),
                    0
                ),
                scan_proof(domain, COOKIE, SCAN_FILE, 1, full.clone(), 0),
                &mut router,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted,
            ),
            Err(BirthObservationRefusal::GenerationMismatch)
        );
        let mut rows = NativeBirthRows { row, control };
        observe_absence_birth(
            &mut rows,
            absence_proof(
                domain,
                COOKIE,
                SCAN_FILE,
                0,
                closure,
                absence_entries_free(),
                0,
            ),
            scan_proof(domain, COOKIE, SCAN_FILE, 1, full.clone(), 0),
            &mut router,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        )
        .expect("the withheld appearance births once the negative commits");
    }

    #[test]
    fn object_journal_session_absence_birth_refuses_stale_fence_pair() {
        // N15: a negative witness sealed under an old publication
        // fence cannot birth against a router that has advanced past
        // it, even beside a fresh appearance — the pair must be
        // current and consistent before the positive publishes, with
        // zero router joins on refusal. A fresh pair at the new fence
        // still births (no over-refusal).
        use crate::attach::{BirthObservationRefusal, observe_absence_birth};

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        scene.adapter.attest_key(&admitted).expect("key attests");
        let (domain, _, _, _) = admitted.journal_binding();
        let full = scan_ranges_full();
        let closure = scene.closure_generation();
        let (row, control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
        // The reviewer probe shape: a stale-fence negative (fence 0)
        // beside a fresh appearance the advanced router would join as
        // New (fence 1, fault 1). Pre-fix this births; post-fix it
        // refuses before the positive publishes.
        let mut router = scan_router(domain);
        router.audit(1, 0, 0);
        assert_eq!(router.fence(), 1, "the gap advanced the fence");
        let mut rows = NativeBirthRows { row, control };
        assert_eq!(
            observe_absence_birth(
                &mut rows,
                absence_proof(
                    domain,
                    COOKIE,
                    SCAN_FILE,
                    0,
                    closure,
                    absence_entries_free(),
                    0
                ),
                scan_proof_at_fault(domain, COOKIE, SCAN_FILE, 1, full.clone(), 1, 1),
                &mut router,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted,
            ),
            Err(BirthObservationRefusal::NegativeFenceMismatch)
        );
        assert_eq!(
            router.counters().observations,
            0,
            "the refused pair joins nothing"
        );
        assert_eq!(router.instances_minted(), 0);
        // An internally consistent but stale pair (both fences 0)
        // refuses the same way: the negative is not current.
        let mut rows = NativeBirthRows { row, control };
        assert_eq!(
            observe_absence_birth(
                &mut rows,
                absence_proof(
                    domain,
                    COOKIE,
                    SCAN_FILE,
                    0,
                    closure,
                    absence_entries_free(),
                    0
                ),
                scan_proof(domain, COOKIE, SCAN_FILE, 1, full.clone(), 0),
                &mut router,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted,
            ),
            Err(BirthObservationRefusal::NegativeFenceMismatch)
        );
        assert_eq!(
            router.counters().observations,
            0,
            "the refused pair joins nothing"
        );
        // Control: a fresh pair at the new fence still births.
        let mut fresh_router = scan_router(domain);
        fresh_router.audit(1, 0, 0);
        let mut rows = NativeBirthRows { row, control };
        observe_absence_birth(
            &mut rows,
            absence_proof(
                domain,
                COOKIE,
                SCAN_FILE,
                0,
                closure,
                absence_entries_free(),
                1,
            ),
            scan_proof_at_fault(domain, COOKIE, SCAN_FILE, 1, full.clone(), 1, 1),
            &mut fresh_router,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        )
        .expect("a current consistent pair births");
        assert_eq!(fresh_router.counters().observations, 1);
    }

    #[test]
    fn object_journal_session_stale_negative_discards_on_gap_take() {
        // N15: the production take path discards an outstanding stale
        // negative on its gap: wiring the sealed pair, then taking
        // against the advanced router, refuses — and the refusal
        // consumes the single-shot pair, so no later take can recover
        // bootstrap through it. A fresh pair takes cleanly.
        use crate::attach::{AbsenceBirthSource, BirthObservationRefusal};
        use crate::semantics_objects::journal::BirthEvidenceSource;

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        scene.adapter.attest_key(&admitted).expect("key attests");
        let (domain, _, _, _) = admitted.journal_binding();
        let full = scan_ranges_full();
        let closure = scene.closure_generation();
        let (row, control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
        let mut router = scan_router(domain);
        router.audit(1, 0, 0);
        let mut source = AbsenceBirthSource::over(
            NativeBirthRows { row, control },
            absence_proof(
                domain,
                COOKIE,
                SCAN_FILE,
                0,
                closure,
                absence_entries_free(),
                0,
            ),
            scan_proof_at_fault(domain, COOKIE, SCAN_FILE, 1, full.clone(), 1, 1),
            &mut router,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        );
        assert_eq!(
            source.take_birth_evidence(),
            Err(BirthObservationRefusal::NegativeFenceMismatch)
        );
        assert_eq!(
            source.take_birth_evidence(),
            Err(BirthObservationRefusal::AppearanceRejected),
            "the refused take consumed the single-shot pair"
        );
        let mut fresh_router = scan_router(domain);
        fresh_router.audit(1, 0, 0);
        let mut fresh = AbsenceBirthSource::over(
            NativeBirthRows { row, control },
            absence_proof(
                domain,
                COOKIE,
                SCAN_FILE,
                0,
                closure,
                absence_entries_free(),
                1,
            ),
            scan_proof_at_fault(domain, COOKIE, SCAN_FILE, 1, full, 1, 1),
            &mut fresh_router,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        );
        fresh
            .take_birth_evidence()
            .expect("a current consistent pair takes");
    }

    #[test]
    fn object_journal_session_birth_grant_binds_observed_words() {
        // C1: the grant binds the observed evidence, and the seal
        // re-checks fresh words: native truth that moved between
        // observation and seal (a scope-dirtied marker) refuses the
        // seal even though the grant attested. Fresh observation
        // itself refuses the natively dirtied row; the seal must
        // refuse the dirtied words however they arrive.
        use crate::attach::{BirthObservationRefusal, observe_exec_birth};
        use p11scope_ebpf_common::journal_marker::MARKER_DIRTY;
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        let proof = scene.adapter.attest_key(&admitted).expect("key attests");
        let (row, control, _) = publisher.publish_stamped(&["0", "1"], scene.closure_generation());
        let mut rows = NativeBirthRows { row, control };
        let (token, evidence) = observe_exec_birth(
            &mut rows,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        )
        .expect("genuine producers observe");
        let grant = SessionBirthGrant::issue_for_native_row_test(
            &token,
            proof,
            BirthKind::ExecMarker,
            0,
            scene.closure_generation(),
            evidence,
        );
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        let birth =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("observed grant attests");
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        // Native truth moved: a fresh run dirties the marker through
        // the real dirty() leaf (no admits: an admit after dirty
        // would trip the latch natively); fresh observation refuses it.
        let (dirty_row, dirty_control, _) = publisher.publish(&["0", "0", "1"]);
        assert_eq!(dirty_row.journal_bootstrap, MARKER_DIRTY);
        let mut dirty_rows = NativeBirthRows {
            row: dirty_row,
            control: dirty_control,
        };
        assert_eq!(
            observe_exec_birth(
                &mut dirty_rows,
                scene.fixture.binding(),
                scene.fixture.attachment(),
                &admitted
            ),
            Err(BirthObservationRefusal::MarkerNotReady)
        );
        let moved = SessionBirthEvidence::scripted(
            (COOKIE, EXEC),
            MARKER_DIRTY,
            0,
            scene.closure_generation(),
            scene.fixture.binding().pin().start_time().unwrap(),
        );
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let failure = scene
            .seal_explicit(&audit, &birth, frontier, moved)
            .expect_err("dirtied marker refuses the seal");
        assert_eq!(failure.gap, JournalGap::BootstrapMismatch);
    }

    #[test]
    fn object_journal_void_preserves_unbounded_abandonment() {
        // C2: BEGIN -> collision ABANDON -> fault audit. The void must
        // preserve the staged unbounded abandonment as a permanent
        // incarnation refusal: rebirth at the void fence (even via
        // absence, which the fence would otherwise permit) never
        // recovers, and new calls never produce positive effects while
        // the abandoned provider frame remains capable.
        use p11scope_ebpf_common::object_journal::JOURNAL_REASON_ENTRY_COLLISION;
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let outer = begin_bytes(1, 1, create, 0);
        scene.ingest(&outer);
        let abandon = abandon_bytes(1, 1, JOURNAL_REASON_ENTRY_COLLISION, (COOKIE, EXEC));
        assert_eq!(scene.ingest(&abandon), JournalDisposition::AbandonStaged);
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let faulted = JournalAuditReceipt::scripted(
            7,
            8,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            scene.closure_generation(),
        );
        let failure = scene
            .seal_explicit(
                &faulted,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("fault audit voids");
        assert_eq!(failure.gap, JournalGap::FaultChanged);
        // The void fence would otherwise permit an absence rebirth; the
        // preserved abandonment refuses the incarnation instead.
        let fence = scene.adapter.consumed_through;
        let readmitted = scene.fixture.admit();
        let reproof = scene.adapter.attest_key(&readmitted).expect("key rebinds");
        assert_eq!(reproof, proof);
        let next = begin_bytes(1, 2, create, 0);
        scene.ingest(&next);
        scene.ingest(&end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let grant = SessionBirthGrant::scripted(
            reproof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let rebirth =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("fence absence attests");
        let retry = scene
            .seal_at(&rebirth, 8)
            .expect_err("abandoned incarnation never recovers");
        assert_eq!(retry.gap, JournalGap::DomainTainted);
        assert!(scene.model.project().objects.is_empty());
    }

    #[test]
    fn object_journal_unbounded_abandonment_releases_model_calls() {
        // I3: unbounded abandonment disposes model call storage (the
        // shared pending budget is refunded) while the incarnation
        // refusal sticks: proof for the abandoned frame never recovers.
        use p11scope_ebpf_common::object_journal::JOURNAL_REASON_ENTRY_COLLISION;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest_function_n("C_Sign", 2);
        let sign = function_id("C_Sign");
        // One call converts (model holds its ticket); a second, never
        // converted, is then abandoned unboundedly.
        scene.ingest(&begin_bytes(1, 1, sign, 0));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("open converts");
        assert_eq!(scene.model.project().usage.pending_calls, 1);
        scene.ingest(&begin_bytes(1, 2, sign, 0));
        let abandon = abandon_bytes(1, 2, JOURNAL_REASON_ENTRY_COLLISION, (COOKIE, EXEC));
        assert_eq!(scene.ingest(&abandon), JournalDisposition::AbandonStaged);
        let failure = scene
            .seal(&bootstrap)
            .expect_err("unbounded abandonment refuses");
        assert_eq!(failure.gap, JournalGap::DomainTainted);
        // Storage released, refusal retained.
        assert_eq!(scene.model.project().usage.pending_calls, 0);
        assert!(
            scene
                .adapter
                .keys
                .get(&proof.key)
                .expect("sealed key")
                .refused
        );
        let retry = scene
            .seal(&bootstrap)
            .expect_err("incarnation never recovers");
        assert_eq!(retry.gap, JournalGap::DomainTainted);
    }

    #[test]
    fn object_journal_converted_abandonment_refuses_and_disposes() {
        // Carryover 9 + N2: an unbounded abandonment staged on an
        // already-CONVERTED call refuses permanently and disposes its
        // model storage exactly like one on a converting call —
        // conversion never outruns abandonment authority, and settle
        // never succeeds across it.
        use p11scope_ebpf_common::object_journal::JOURNAL_REASON_ENTRY_COLLISION;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest_function("C_Sign");
        let sign = function_id("C_Sign");
        scene.ingest(&begin_bytes(1, 1, sign, 0));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("open converts");
        assert_eq!(scene.model.project().usage.pending_calls, 1);
        let abandon = abandon_bytes(1, 1, JOURNAL_REASON_ENTRY_COLLISION, (COOKIE, EXEC));
        assert_eq!(scene.ingest(&abandon), JournalDisposition::AbandonStaged);
        let failure = scene
            .seal(&bootstrap)
            .expect_err("converted abandonment refuses");
        assert_eq!(failure.gap, JournalGap::DomainTainted);
        assert_eq!(scene.model.project().usage.pending_calls, 0);
        assert!(
            scene
                .adapter
                .keys
                .get(&proof.key)
                .expect("sealed key")
                .refused
        );
    }

    #[test]
    fn object_journal_converted_bounded_abandonment_waits_for_its_bound() {
        // Carryover 9 + N2: a converted call's bounded abandonment
        // without its corroborating return in the frontier waits
        // (BoundNotReady) instead of tainting as a model surprise;
        // the corroborated twin then seals with the bounded loss.
        use p11scope_ebpf_common::object_journal::JOURNAL_REASON_SYNC_RETURN_RESULT_LOST;

        for corroborated in [false, true] {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            scene.ingest(&begin);
            let bootstrap = scene.bootstrap(proof, 0);
            scene.seal(&bootstrap).expect("open converts");
            let abandon =
                abandon_bytes(1, 1, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, (COOKIE, EXEC));
            assert_eq!(scene.ingest(&abandon), JournalDisposition::AbandonStaged);
            if corroborated {
                scene.ingest_ordinary(ordinary_for(&begin, 0));
                // The fence sits strictly above the corroborated bound,
                // so the frontier must cover it: one pad record.
                let mut pad = ordinary_for(&begin, 0);
                pad.slot = 99;
                scene.ingest_ordinary(pad);
            }
            if corroborated {
                let success = scene.seal(&bootstrap).expect("corroborated bound seals");
                assert!(success.prefix.settled().iter().any(|call| call.abandoned));
            } else {
                let failure = scene
                    .seal(&bootstrap)
                    .expect_err("uncorroborated converted bound waits");
                assert_eq!(failure.gap, JournalGap::BoundNotReady);
                assert!(
                    !scene
                        .adapter
                        .keys
                        .get(&proof.key)
                        .expect("sealed key")
                        .tainted
                );
            }
        }
    }

    #[test]
    fn object_journal_conversion_capacity_refusal_propagates_effects() {
        // Carryover 10: a capacity refusal on the production conversion
        // path (model.begin inside the seal) publishes its invalidation
        // effects to the seal failure before anything further — admit()
        // must not drop them.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        // Shrink ONLY the model: the journal stages every begin, the
        // model holds two pending calls.
        scene.model = ObjectSemantics::with_limits(crate::semantics_objects::ObjectLimits {
            pending_calls: 2,
            ..crate::semantics_objects::ObjectLimits::policy()
        });
        let proof = scene.attest_calls(4);
        let create = function_id("C_CreateObject");
        // One creation settles first: its live view is what the later
        // refusal retires.
        let first = begin_bytes(1, 1, create, 0);
        scene.ingest(&first);
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 40));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("creation seals");
        assert_eq!(scene.model.project().usage.pending_calls, 0);
        // Three opens convert into two model slots: the third begin
        // refuses capacity on the conversion path.
        scene.ingest(&begin_bytes(1, 2, create, 0));
        scene.ingest(&begin_bytes(1, 3, create, 0));
        scene.ingest(&begin_bytes(1, 4, create, 0));
        let bootstrap = scene.bootstrap(proof, 0);
        let failure = scene
            .seal(&bootstrap)
            .expect_err("model capacity refuses the seal");
        assert_eq!(failure.gap, JournalGap::ModelRefused);
        assert!(
            failure.effects.effects.iter().any(|effect| matches!(
                effect,
                ObjectEffect::Retired {
                    reason: super::ObjectGap::PendingCapacity,
                    ..
                }
            )),
            "conversion refusal reaches seal effects: {:?}",
            failure.effects.effects
        );
    }

    #[test]
    fn object_journal_empty_resumption_waits_for_history() {
        // C2: a fault voids benign staged history; one unrelated
        // ordinary record then advances the frontier. Naming the void
        // fence with no new staged history certifies nothing, so the
        // resumption waits (BoundNotReady) instead of succeeding; new
        // staged history above the fence recovers.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let faulted = JournalAuditReceipt::scripted(
            7,
            8,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            scene.closure_generation(),
        );
        scene
            .seal_explicit(
                &faulted,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("fault audit voids");
        let fence = scene.adapter.consumed_through;
        let mut pad = ordinary_for(&begin, 0);
        pad.slot = 99;
        scene.ingest_ordinary(pad);
        let grant = SessionBirthGrant::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let resume =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("fence absence attests");
        let waiting = scene
            .seal_at(&resume, 8)
            .expect_err("empty resumption waits for history");
        assert_eq!(waiting.gap, JournalGap::BoundNotReady);
        // Genuinely new staged history above the fence recovers. The
        // void cleared admission claims: re-attest for the new history.
        scene.attest();
        let next = begin_bytes(1, 2, create, 0);
        scene.ingest(&next);
        scene.ingest(&end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let recovered = scene.seal_at(&resume, 8).expect("new history recovers");
        assert_eq!(recovered.prefix.settled().len(), 1);
    }

    #[test]
    fn object_journal_return_witness_binds_exact_invocation() {
        // C3: an ordinary CALL corroborates a staged BEGIN only for the
        // exact retained invocation: same image, same process, exact
        // entry-time agreement plus the scalar call identity. A foreign
        // process/image or a different entry instant never becomes the
        // bounded-loss upper cut.
        let mut scene = Scene::new(image_default());
        scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        let mut foreign_image = ordinary_for(&begin, 0);
        foreign_image.image.task_cookie += 1;
        assert_eq!(
            scene.ingest_ordinary(foreign_image),
            JournalDisposition::OrdinaryCounted
        );
        let mut foreign_process = ordinary_for(&begin, 0);
        foreign_process.pid_tgid ^= 0xFFFF_FFFF_0000_0000;
        assert_eq!(
            scene.ingest_ordinary(foreign_process),
            JournalDisposition::OrdinaryCounted
        );
        // Same return instant, different entry instant: not this call.
        let mut foreign_entry = ordinary_for(&begin, 0);
        foreign_entry.duration_ns = 50;
        assert_eq!(
            scene.ingest_ordinary(foreign_entry),
            JournalDisposition::OrdinaryCounted
        );
        assert_eq!(
            scene.ingest_ordinary(ordinary_for(&begin, 0)),
            JournalDisposition::ReturnObserved
        );

        // The same binding guards refused begins, end to end: a foreign
        // return leaves the bound unready instead of minting a
        // LostOutcome upper cut from another invocation.
        let mut scene = Scene::new_with_limits(
            image_default(),
            JournalLimits {
                open_calls: 1,
                thread_floors: 8,
                refused_begins: 8,
                domain_keys: 4,
                image_sightings: 8,
            },
        );
        let proof = scene.attest();
        scene.attest_session_function(0x1111_1111_1111_1111, "C_CreateObject");
        let mut first = begin_bytes(1, 1, create, 0);
        put_u64(&mut first, 80, 0x1111_1111_1111_1111);
        scene.ingest(&first);
        let second = begin_bytes(1, 2, create, 0);
        assert_eq!(
            scene.ingest(&second),
            JournalDisposition::BeginRefusedCapacity
        );
        let mut foreign = ordinary_for(&second, 0);
        foreign.image.exec_id ^= 0x0F0F_0F0F_0F0F_0F0F;
        assert_eq!(
            scene.ingest_ordinary(foreign),
            JournalDisposition::OrdinaryCounted
        );
        let bootstrap = scene.bootstrap(proof, 0);
        let unready = scene
            .seal(&bootstrap)
            .expect_err("foreign witness leaves the bound unready");
        assert_eq!(unready.gap, JournalGap::BoundNotReady);
        assert_eq!(
            scene.ingest_ordinary(ordinary_for(&second, 0)),
            JournalDisposition::ReturnObserved
        );
        // The frontier must cover the bound's authority before the seal
        // claims it.
        let mut pad = ordinary_for(&second, 0);
        pad.slot = 99;
        scene.ingest_ordinary(pad);
        let bound = scene.seal(&bootstrap).expect("exact witness bounds");
        assert_eq!(bound.prefix.settled().len(), 1);
    }

    /// A refused invocation burns only its own exact admission. Keep
    /// the retained call open so its H8 receipt names that admission
    /// even when the refused call's bound moves the bootstrap floor.
    fn retained_and_refused_claim_identity(refused_first: bool) {
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(2);
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        let mut second = begin_bytes(2, 1, create, 0);
        put_u64(&mut second, 48, ENTRY_NS + 1_000);
        scene.adapter.limits.open_calls = usize::from(!refused_first);
        scene.ingest(&first);
        scene.adapter.limits.open_calls = usize::from(refused_first);
        scene.ingest(&second);
        let refused = if refused_first { &first } else { &second };
        assert_eq!(
            scene.ingest_ordinary(ordinary_for(refused, 0)),
            JournalDisposition::ReturnObserved
        );
        let mut pad = ordinary_for(refused, 0);
        pad.slot = 99;
        scene.ingest_ordinary(pad);
        let bootstrap = scene.bootstrap(proof, 0);
        scene.prepare_claims();
        let expected = scene.paired_admissions[&if refused_first { 2 } else { 1 }];
        let seal = scene
            .seal(&bootstrap)
            .expect("bounded refusal with one retained open seals");
        assert_eq!(seal.prefix.settled().len(), 1);
        assert_eq!(
            seal.prefix.settled()[0].key.admission(),
            expected,
            "the refused call cannot burn the retained invocation's H0 admission"
        );
        assert_eq!(seal.prefix.open_keys().len(), 1);
    }

    #[test]
    fn object_journal_c2_retained_then_refused_claim_identity() {
        retained_and_refused_claim_identity(false);
    }

    #[test]
    fn object_journal_c2_refused_then_retained_claim_identity() {
        retained_and_refused_claim_identity(true);
    }

    #[test]
    fn object_journal_c2_ambiguous_overlap_reversed_returns_keeps_claims() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_calls(2);
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        let mut second = begin_bytes(2, 1, create, 0);
        second[24..32].copy_from_slice(&first[24..32]);
        second[48..56].copy_from_slice(&first[48..56]);
        scene.ingest(&first);
        scene.ingest(&second);
        scene.ingest(&end_bytes(&second, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        scene.prepare_claims();
        let claims = scene.adapter.claims.clone();
        let count = scene.adapter.claim_counts;
        let bootstrap = scene.bootstrap(proof, 0);
        let outcome = scene.seal(&bootstrap);
        assert_eq!(
            scene.adapter.claims, claims,
            "ambiguous conversion must consume no invocation's claim"
        );
        assert_eq!(scene.adapter.claim_counts, count);
        assert_eq!(
            outcome
                .expect_err("identical physical tuple needs explicit correlation refusal")
                .gap,
            JournalGap::ImageTainted
        );
        assert!(scene.model.project().objects.is_empty());
        let retry = scene
            .seal(&bootstrap)
            .expect_err("ambiguity remains unresolved");
        assert_eq!(retry.gap, JournalGap::ImageTainted);
        assert_eq!(scene.adapter.claims, claims);
    }

    #[test]
    fn object_journal_c2_consumed_identity_stays_stale_after_1025_calls() {
        let mut scene = Scene::new(image_default());
        let function = function_id("C_SignUpdate");
        let begin = begin_bytes(1, 1, function, 0);
        let end = end_bytes_absent(&begin, 0, ENTRY_NS + 50);
        let JournalRecord::End(native) = decode_journal_record(&end, &scene.descriptors).unwrap()
        else {
            panic!("END")
        };
        let first = scene
            .fixture
            .admit_original_event("C_SignUpdate", native.payload_base().event);
        let proof = scene.adapter.attest_key(&first).unwrap();
        scene.ingest(&begin);
        scene.ingest(&end);
        let bootstrap = scene.bootstrap(proof, 0);
        let delayed = scene.seal(&bootstrap).unwrap();
        assert_eq!(
            delayed.prefix.settled()[0].key.admission(),
            first.h0_ordinal()
        );
        assert_eq!(
            scene.adapter.attest_key(&first),
            Err(AttestationRefusal::InvocationStale)
        );
        for sequence in 2..=1_026 {
            scene.attest_function("C_SignUpdate");
            let begin = begin_bytes(1, sequence, function, 0);
            scene.ingest(&begin);
            scene.ingest(&end_bytes_absent(&begin, 0, ENTRY_NS + 50));
            scene.seal(&bootstrap).unwrap();
        }
        assert_eq!(
            scene.adapter.attest_key(&first),
            Err(AttestationRefusal::InvocationStale)
        );
        assert_eq!(scene.adapter.claim_counts, 0);
        assert_eq!(scene.adapter.physical_return_floors.len(), 1);
        assert_eq!(
            delayed.prefix.settled()[0].key.admission(),
            first.h0_ordinal(),
            "late seal retains its actual original H0 identity"
        );
    }

    #[test]
    fn object_journal_c2_new_native_ticket_cannot_recycle_old_physical_entry() {
        for new_ticket in [false, true] {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest_function("C_SignUpdate");
            let function = function_id("C_SignUpdate");
            let first = begin_bytes(1, 1, function, 0);
            scene.ingest(&first);
            scene.ingest(&end_bytes_absent(&first, 0, ENTRY_NS + 50));
            scene.seal(&scene.bootstrap(proof, 0)).unwrap();
            let floor = scene.adapter.physical_return_floors[&invocation_pid(1)];
            scene.adapter.void_staged(); // Bounded direct-guard reset test.
            let mut replay = begin_bytes_image(
                if new_ticket { 2 } else { 1 },
                if new_ticket { 1 } else { 2 },
                function,
                0,
                (COOKIE, EXEC + 1),
            );
            replay[24..32].copy_from_slice(&first[24..32]);
            replay[48..56].copy_from_slice(&first[48..56]);
            assert_eq!(
                scene.ingest(&replay),
                JournalDisposition::Contradiction(JournalContradiction::SequenceRegression)
            );
            assert_eq!(
                scene.adapter.physical_return_floors[&invocation_pid(1)],
                floor,
                "void/exec/native ticket never reset the physical fence"
            );
            assert_eq!(scene.adapter.claim_counts, 0);
        }
    }

    #[test]
    fn object_journal_c2_namespace_capacity_spares_tracked_namespace() {
        let mut scene = Scene::new_with_limits(
            image_default(),
            JournalLimits {
                thread_floors: 1,
                ..JournalLimits::policy()
            },
        );
        let proof = scene.attest_function("C_SignUpdate");
        let function = function_id("C_SignUpdate");
        let first = begin_bytes(1, 1, function, 0);
        scene.ingest(&first);
        scene.ingest(&end_bytes_absent(&first, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).unwrap();
        let mut refused = begin_bytes_image(1, 2, function, 0, (COOKIE + 1, EXEC));
        put_u64(&mut refused, 24, invocation_pid(2));
        assert_eq!(
            scene.ingest(&refused),
            JournalDisposition::Contradiction(JournalContradiction::FloorExhausted)
        );
        assert_eq!(
            scene.adapter.claim_counts, 0,
            "capacity burns no unrelated claim"
        );
        scene.attest_function("C_SignUpdate");
        let healthy = begin_bytes(1, 2, function, 0);
        scene.ingest(&healthy);
        scene.ingest(&end_bytes_absent(&healthy, 0, ENTRY_NS + 50));
        assert_eq!(scene.seal(&bootstrap).unwrap().prefix.settled().len(), 1);
        assert_eq!(scene.adapter.physical_return_floors.len(), 1);
    }

    #[test]
    fn object_journal_c2_unique_unconsumed_start_exception_is_bounded_guard_only() {
        let mut scene = Scene::new(image_default());
        let begin = begin_bytes(1, 1, function_id("C_SignUpdate"), 0);
        let JournalRecord::Begin(native) =
            decode_journal_record(&begin, &scene.descriptors).unwrap()
        else {
            panic!("BEGIN")
        };
        scene.ingest(&begin);
        // Deliberately inject only the later fence for this guard-unit
        // test: normal full-image attribution currently holds unclaimed
        // outer STARTs, so this is not end-to-end ingress evidence.
        scene
            .adapter
            .physical_return_floors
            .insert(native.pid_tgid(), native.entry_ns() + 10_000);
        let event = original_for_validated_begin(&native);
        let admitted = scene.fixture.admit_original_event("C_SignUpdate", event);
        scene
            .adapter
            .attest_key(&admitted)
            .expect("unique retained unconsumed START owns its delayed original return");
        let mut foreign = event;
        foreign.ts_ns -= 1;
        let wrong = scene.fixture.admit_original_event("C_SignUpdate", foreign);
        assert_eq!(
            scene.adapter.attest_key(&wrong),
            Err(AttestationRefusal::InvocationStale)
        );
        assert_eq!(scene.adapter.claim_counts, 1);
    }

    #[test]
    fn object_journal_c2_equal_next_entry_and_previous_return_is_healthy() {
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_function("C_SignUpdate");
        let function = function_id("C_SignUpdate");
        let first = begin_bytes(1, 1, function, 0);
        scene.ingest(&first);
        scene.ingest(&end_bytes_absent(&first, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).unwrap();
        let previous_return = scene.adapter.physical_return_floors[&invocation_pid(1)];
        scene.attest_function("C_SignUpdate");
        let mut next = begin_bytes(1, 2, function, 0);
        put_u64(&mut next, 48, previous_return);
        assert_eq!(scene.ingest(&next), JournalDisposition::BeginAdmitted);
        scene.ingest(&end_bytes_absent(&next, 0, ENTRY_NS + 50));
        assert_eq!(scene.seal(&bootstrap).unwrap().prefix.settled().len(), 1);
        assert_eq!(
            scene.adapter.physical_return_floors[&invocation_pid(1)],
            previous_return + 50
        );
    }

    #[test]
    fn object_journal_c2_foreign_begin_identity_never_burns_original_claim() {
        for changed in 0..4 {
            let mut scene = Scene::new(image_default());
            let function = function_id("C_SignUpdate");
            let begin = begin_bytes(1, 1, function, 0);
            let end = end_bytes_absent(&begin, 0, ENTRY_NS + 50);
            let JournalRecord::End(native) =
                decode_journal_record(&end, &scene.descriptors).unwrap()
            else {
                panic!("END")
            };
            let admitted = scene
                .fixture
                .admit_original_event("C_SignUpdate", native.payload_base().event);
            let proof = scene.adapter.attest_key(&admitted).unwrap();
            let mut foreign = begin;
            match changed {
                0 => put_u64(&mut foreign, 24, invocation_pid(2)),
                1 => put_u64(&mut foreign, 48, invocation_entry_ns(1, 1) + 1),
                2 => put_u32(&mut foreign, 104, fixture_slot(function).unwrap() + 1),
                _ => put_u64(&mut foreign, 32, COOKIE + 1),
            }
            scene.ingest(&foreign);
            scene.ingest(&end_bytes_absent(&foreign, 0, ENTRY_NS + 50));
            let claims = scene.adapter.claims.clone();
            scene
                .seal(&scene.bootstrap(proof, 0))
                .expect_err("different physical identity is not the admitted original");
            assert_eq!(scene.adapter.claims, claims);
            assert_eq!(scene.adapter.claim_counts, 1);
        }
    }

    #[test]
    fn object_journal_c2_adapter_refuses_independent_drain_namespace() {
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        scene.adapter.attest_key(&admitted).unwrap();
        let grant = SessionDrainGrant::observe(&scene.producers(), &admitted).unwrap();
        scene.adapter.bind_session_drain(&grant).unwrap();
        let mut other = Scene::new(image_default());
        other.retained_events = crate::events::EventsDomain::test_standin(8);
        let foreign = other.fixture.admit();
        scene.adapter.attest_key(&foreign).unwrap();
        let grant = SessionDrainGrant::observe(&other.producers(), &foreign).unwrap();
        assert_eq!(
            scene.adapter.bind_session_drain(&grant),
            Err(DrainBindRefusal::DrainConflict)
        );
        let same_cursor = crate::attach::SessionDrainProducers::test_pair(
            other.fixture.domain(),
            scene.retained_events.clone(),
        );
        let grant = SessionDrainGrant::observe(&same_cursor, &foreign).unwrap();
        scene
            .adapter
            .bind_session_drain(&grant)
            .expect("native domains can share the same retained Session cursor");
    }

    /// Direct era/request guard: production currently has no era-revival
    /// path, so this deliberately scripts the mismatched request only.
    #[test]
    fn object_journal_c2_failure_scope_preserves_full_era() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, function_id("C_CreateObject"), 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let receipt = scene.bootstrap(proof, 0);
        let next_era = BootstrapReceipt::scripted(
            JournalDomainProof {
                era: proof.era + 1,
                ..proof
            },
            BirthKind::ExecMarker,
            0,
            scene.closure_generation(),
        );
        let old_failure = scene.adapter.scripted_failure(
            JournalGap::ClosureStale,
            &receipt,
            ObjectEffects::default(),
        );
        assert!(old_failure.affects_domain(receipt.domain()));
        assert!(!old_failure.affects_domain(next_era.domain()));
        let audit = scene.audit();
        let frontier = scene.adapter.consumed_frontier();
        let failure = scene
            .seal_explicit(
                &audit,
                &next_era,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&next_era),
            )
            .expect_err("unknown requested era is inert");
        assert_eq!(failure.gap, JournalGap::BootstrapMismatch);
        assert!(!failure.affects_domain(receipt.domain()));
        assert!(!failure.affects_domain(next_era.domain()));
        assert!(
            old_failure.affects_domain(receipt.domain()),
            "scope is an immutable snapshot"
        );
        scene
            .seal(&receipt)
            .expect("the actual current era remains healthy");
        let global = scene.adapter.global_failure(JournalGap::Stopped);
        let SealFailureScope::AffectedDomains(domains) = global.scope else {
            panic!("global snapshot")
        };
        assert_eq!(domains.len(), 1);
        assert_eq!(std::mem::size_of::<ObjectDomain>(), 40);
        assert!(domains.capacity() <= scene.adapter.limits.domain_keys);
        eprintln!(
            "C2 scoped-loss storage: {} domains, {} requested bytes; maximum {} bytes",
            domains.len(),
            domains.capacity() * std::mem::size_of::<ObjectDomain>(),
            JournalLimits::policy().domain_keys * std::mem::size_of::<ObjectDomain>()
        );
    }

    #[test]
    fn object_journal_c2_same_shape_reversed_returns_keep_actual_h0_identity() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_ACCESS;
        let mut scene = Scene::new(image_default());
        let function = function_id("C_SignInit");
        let capture = capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL;
        let first = begin_bytes_shaped(
            1,
            1,
            function,
            0,
            (COOKIE, EXEC),
            SESSION,
            1,
            capture,
            Some((7, 1)),
            None,
            FLAGS,
        );
        let mut second = begin_bytes_shaped(
            2,
            1,
            function,
            0,
            (COOKIE, EXEC),
            SESSION,
            1,
            capture,
            Some((7, 1)),
            None,
            FLAGS,
        );
        put_u64(&mut second, 48, invocation_entry_ns(1, 1) + 10);
        let first_end = end_bytes(&first, OBJECT_ACTION_ACCESS, 0, ENTRY_NS + 60);
        let second_end = end_bytes(&second, OBJECT_ACTION_ACCESS, 0, ENTRY_NS + 20);
        // H0 admits in physical return order, opposite native BEGIN order.
        let JournalRecord::End(second_return) =
            decode_journal_record(&second_end, &scene.descriptors).unwrap()
        else {
            panic!("END")
        };
        let admitted_second = scene
            .fixture
            .admit_original_event("C_SignInit", second_return.payload_base().event);
        let proof = scene.adapter.attest_key(&admitted_second).unwrap();
        let JournalRecord::End(first_return) =
            decode_journal_record(&first_end, &scene.descriptors).unwrap()
        else {
            panic!("END")
        };
        let admitted_first = scene
            .fixture
            .admit_original_event("C_SignInit", first_return.payload_base().event);
        scene.adapter.attest_key(&admitted_first).unwrap();
        scene.ingest(&first);
        scene.ingest(&second);
        scene.ingest(&second_end);
        scene.ingest(&first_end);
        let seal = scene
            .seal(&scene.bootstrap(proof, 0))
            .expect("distinct physical identities need no rank inference");
        assert_eq!(seal.prefix.settled().len(), 2);
        assert_eq!(
            seal.prefix.settled()[0].key.admission(),
            admitted_first.h0_ordinal()
        );
        assert_eq!(
            seal.prefix.settled()[1].key.admission(),
            admitted_second.h0_ordinal()
        );
        let mut s1 = crate::semantics_edge::EdgeSemantics::default();
        s1.observe(admitted_second.s1_facts());
        s1.observe(admitted_first.s1_facts());
        assert_eq!(
            (s1.calls(), s1.started(), s1.cancelled(), s1.unknown()),
            (2, 2, 1, 0)
        );
        assert_eq!(
            s1.completed(),
            0,
            "identity binding invents no S1 completion"
        );
    }

    #[test]
    fn object_journal_c2_original_interval_refusals_preserve_s1() {
        use crate::semantics_edge::EdgeSemantics;
        let mut scene = Scene::new(image_default());
        let function = function_id("C_SignUpdate");
        let begin = begin_bytes(1, 1, function, 0);
        let JournalRecord::Begin(native) =
            decode_journal_record(&begin, &scene.descriptors).unwrap()
        else {
            panic!("BEGIN")
        };
        let valid = original_for_validated_begin(&native);
        for invalid in 0..4 {
            let mut event = valid;
            match invalid {
                0 => event.duration_ns = 0,
                1 => {
                    event.ts_ns = 10;
                    event.duration_ns = 11;
                }
                2 => event.pid_tgid &= 0xffff_ffff_0000_0000,
                _ => event.pid_tgid &= 0xffff_ffff,
            }
            let admitted = scene.fixture.admit_original_event("C_SignUpdate", event);
            assert!(admitted.journal_call_fingerprint().is_none());
            scene.adapter.attest_key(&admitted).unwrap();
            assert_eq!(scene.adapter.claim_counts, 0);
            let mut edge = EdgeSemantics::default();
            edge.observe(admitted.s1_facts());
            assert_eq!(
                edge.calls(),
                1,
                "refusing Joint identity preserves definite S1 input"
            );
        }
    }

    #[test]
    fn object_journal_c2_native_end_interval_mismatch_keeps_claim() {
        let mut scene = Scene::new(image_default());
        let begin = begin_bytes(1, 1, function_id("C_SignUpdate"), 0);
        let end = end_bytes_absent(&begin, 0, ENTRY_NS + 50);
        let JournalRecord::End(native) = decode_journal_record(&end, &scene.descriptors).unwrap()
        else {
            panic!("END")
        };
        let admitted = scene
            .fixture
            .admit_original_event("C_SignUpdate", native.payload_base().event);
        let proof = scene.adapter.attest_key(&admitted).unwrap();
        scene.ingest(&begin);
        scene.ingest(&end_bytes_absent(&begin, 0, ENTRY_NS + 60));
        let claims = scene.adapter.claims.clone();
        let failure = scene
            .seal(&scene.bootstrap(proof, 0))
            .expect_err("a different original END interval is not this admission");
        assert_eq!(failure.gap, JournalGap::H3Pending);
        assert_eq!(scene.adapter.claims, claims);
    }

    #[test]
    fn object_journal_c2_missing_end_pending_physical_return_is_not_completion() {
        let mut scene = Scene::new(image_default());
        let begin = begin_bytes(1, 1, function_id("C_SignInit"), 0);
        let JournalRecord::Begin(native) =
            decode_journal_record(&begin, &scene.descriptors).unwrap()
        else {
            panic!("BEGIN")
        };
        let mut event = original_for_validated_begin(&native);
        event.rv = pkcs11_types::CkRv::PENDING.0;
        let admitted = scene.fixture.admit_original_event("C_SignInit", event);
        let proof = scene.adapter.attest_key(&admitted).unwrap();
        scene.ingest(&begin);
        let seal = scene
            .seal(&scene.bootstrap(proof, 0))
            .expect("original physical return identifies this open native invocation");
        assert_eq!(seal.prefix.settled().len(), 1);
        assert_eq!(
            seal.prefix.settled()[0].key.admission(),
            admitted.h0_ordinal()
        );
        assert!(seal.prefix.settled()[0].end_cut.is_none());
        assert_eq!(
            scene.adapter.physical_return_floors[&native.pid_tgid()],
            event.ts_ns
        );
        let mut edge = crate::semantics_edge::EdgeSemantics::default();
        edge.observe(admitted.s1_facts());
        assert_eq!(
            edge.completed(),
            0,
            "physical return is never semantic completion"
        );
    }

    #[test]
    fn object_journal_c2_guard_stays_bounded_through_100k_calls() {
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_function("C_SignUpdate");
        let bootstrap = scene.bootstrap(proof, 0);
        let function = function_id("C_SignUpdate");
        for sequence in 1..=100_000 {
            if sequence != 1 {
                scene.attest_function("C_SignUpdate");
            }
            let begin = begin_bytes(1, sequence, function, 0);
            let cut = scene.adapter.consumed_through + 1;
            assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
            scene.ingest(&end_bytes_absent(&begin, 0, ENTRY_NS + 50));
            let seal = scene
                .seal(&bootstrap)
                .expect("healthy namespace never hits a lifetime call cap");
            assert_eq!(seal.prefix.settled().len(), 1);
            assert_eq!(
                seal.prefix.settled()[0].key.admission(),
                scene.paired_admissions[&cut]
            );
            assert_eq!(scene.adapter.floors.len(), 1);
            assert_eq!(scene.adapter.physical_return_floors.len(), 1);
            assert_eq!(scene.adapter.claim_counts, 0);
            assert!(scene.adapter.open.is_empty());
            assert!(scene.adapter.refused.is_empty());
        }
    }

    #[test]
    fn object_journal_c2_retained_outer_survives_inner_return_fence() {
        let mut scene = Scene::new(image_default());
        let proof = scene.attest_function("C_SignUpdate");
        let bootstrap = scene.bootstrap(proof, 0);
        let function = function_id("C_SignUpdate");
        let outer = begin_bytes(1, 1, function, 0);
        scene.ingest(&outer);
        // Original physical API return is admitted even though the
        // native END is delayed. This is algorithm-level late delivery.
        scene
            .seal(&bootstrap)
            .expect("outer START converts from its original return");
        for sequence in 2..=100 {
            scene.attest_function("C_SignUpdate");
            let begin = begin_bytes(1, sequence, function, 0);
            scene.ingest(&begin);
            scene.ingest(&end_bytes_absent(&begin, 0, ENTRY_NS + 50));
            scene
                .seal(&bootstrap)
                .expect("bounded inner wave advances the physical floor");
        }
        let floor = scene.adapter.physical_return_floors[&invocation_pid(1)];
        assert!(floor > invocation_entry_ns(1, 1) + 100);
        // END retains the exact original physical interval, rather than
        // replacing it with delivery time after the inner calls.
        scene.ingest(&end_bytes_absent(&outer, 0, ENTRY_NS + 100));
        scene
            .seal(&bootstrap)
            .expect("retained outer completes below the advanced floor");
        assert!(scene.adapter.open.is_empty());
        assert_eq!(
            scene.adapter.physical_return_floors[&invocation_pid(1)],
            floor
        );
        assert_eq!(scene.adapter.physical_return_floors.len(), 1);
    }

    #[test]
    fn object_journal_conversion_attributes_per_call_authority() {
        // C4: two provider instances share one image. Each key converts
        // only the calls its own admission authority names; a seal never
        // attributes a sibling instance's calls to whichever key seals
        // first.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        const OTHER_SESSION: u64 = 0x2222_2222_2222_2222;
        let mut scene = Scene::new(image_default());
        let proof_a = scene.attest();
        let mut other = AttestationFixture::new(image_default());
        let proof_b = scene
            .adapter
            .attest_key(&other.admit_session(OTHER_SESSION))
            .expect("second key attests");
        assert_ne!(proof_a, proof_b);
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        scene.ingest(&first);
        let mut second = begin_bytes(2, 1, create, 0);
        put_u64(&mut second, 80, OTHER_SESSION);
        scene.admit_other_end(
            &mut other,
            "C_CreateObject",
            &end_bytes(&second, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60),
        );
        scene.ingest(&second);
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        scene.ingest(&end_bytes(&second, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let bootstrap_a = scene.bootstrap(proof_a, 0);
        let sealed_a = scene.seal(&bootstrap_a).expect("first key seals");
        assert_eq!(sealed_a.prefix.settled().len(), 1);
        assert_eq!(sealed_a.prefix.settled()[0].begin_cut, 1);
        let bootstrap_b = scene.bootstrap(proof_b, 0);
        let sealed_b = scene.seal(&bootstrap_b).expect("second key seals its call");
        assert_eq!(sealed_b.prefix.settled().len(), 1);
        assert_eq!(sealed_b.prefix.settled()[0].begin_cut, 2);
    }

    #[test]
    fn object_journal_unknown_staged_entries_barrier_every_domain() {
        // C4: a staged BEGIN for an image no key was attested for is not
        // silently excluded: it barriers every seal past it, and only a
        // void (which drops it explicitly) recovers the domain.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        let strange = begin_bytes_image(2, 1, create, 0, (COOKIE + 9, EXEC));
        scene.ingest(&strange);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        let blocked = scene
            .seal(&bootstrap)
            .expect_err("unknown staged entries barrier");
        assert_eq!(blocked.gap, JournalGap::BoundNotReady);
        // A void drops the unknown history explicitly; the domain then
        // resumes above the fence with genuinely new history.
        let frontier = scene.adapter.consumed_frontier();
        let faulted = JournalAuditReceipt::scripted(
            7,
            8,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            scene.closure_generation(),
        );
        scene
            .seal_explicit(
                &faulted,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("fault audit voids");
        let fence = scene.adapter.consumed_through;
        // The void cleared admission claims: re-attest for the new history.
        scene.attest();
        let next = begin_bytes(1, 2, create, 0);
        scene.ingest(&next);
        scene.ingest(&end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let grant = SessionBirthGrant::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let resume =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("fence absence attests");
        scene.seal_at(&resume, 8).expect("post-void history seals");
    }

    #[test]
    fn object_journal_unadmitted_shape_barriers_multi_key_seal() {
        // C4: with two live keys on one image, a staged call no admission
        // authority names barriers the seal; it is neither converted nor
        // silently skipped.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        const OTHER_SESSION: u64 = 0x2222_2222_2222_2222;
        const STRAY_SESSION: u64 = 0x3333_3333_3333_3333;
        let mut scene = Scene::new(image_default());
        let proof_a = scene.attest();
        let mut other = AttestationFixture::new(image_default());
        scene
            .adapter
            .attest_key(&other.admit_session(OTHER_SESSION))
            .expect("second key attests");
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        scene.ingest(&first);
        let mut stray = begin_bytes(2, 1, create, 0);
        put_u64(&mut stray, 80, STRAY_SESSION);
        scene.ingest(&stray);
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        scene.ingest(&end_bytes(&stray, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let bootstrap_a = scene.bootstrap(proof_a, 0);
        let blocked = scene
            .seal(&bootstrap_a)
            .expect_err("unadmitted shape barriers");
        assert_eq!(blocked.gap, JournalGap::BoundNotReady);
    }

    #[test]
    fn object_journal_late_attestation_after_conversion_refuses() {
        // C4: a second key for an image whose live key already converted
        // refuses attestation: calls converted under sole-key authority
        // cannot be re-examined once a sibling instance appears.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("sole key seals");
        let mut other = AttestationFixture::new(image_default());
        assert_eq!(
            scene.adapter.attest_key(&other.admit()),
            Err(AttestationRefusal::ImageSealed)
        );
    }

    #[test]
    fn object_journal_sole_key_requires_admission_claim() {
        // Carryover 4: a sole KNOWN key does not prove a sole provider
        // instance. Staged calls convert only under an admission claim
        // — even with no sibling keys. An unclaimed staged call waits;
        // its H3 admission then lets the seal convert it.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        scene.ingest(&begin_bytes(1, 1, create, 0));
        scene.ingest(&begin_bytes(1, 2, create, 0));
        let bootstrap = scene.bootstrap(proof, 0);
        let blocked = scene
            .seal(&bootstrap)
            .expect_err("unclaimed staged call waits");
        assert_eq!(blocked.gap, JournalGap::BoundNotReady);
        scene.attest();
        let success = scene.seal(&bootstrap).expect("claimed calls seal");
        assert_eq!(success.prefix.settled().len(), 2);
    }

    #[test]
    fn object_journal_collection_binds_drain_session() {
        // C2: the drain↔domain association mints from the SESSION's own
        // producers (its retained EVENTS domain plus an admission its
        // authority minted) — a presented drain is checked, never
        // trusted. A foreign drain presented FIRST, with no setup at
        // all, refuses and consumes nothing (no association covers
        // it); the Session-minted grant then binds; the bound Session
        // drain collects and seals; a foreign drain presented after
        // still refuses. Binding an unattested domain, or rebinding a
        // bound one to a rotated identity, refuses loudly.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let fault = ScriptedFaultCell::steady(7);
        let bootstrap = scene.bootstrap(proof, 0);
        // FOREIGN FIRST with no setup at all: EVENTS 9 presented before
        // any grant mints refuses and consumes nothing.
        let foreign = begin_bytes(1, 2, create, 0);
        let mut drain = crate::events::EventDrain::over_test_domain(
            crate::events::ScriptedRecords::records(vec![foreign.to_vec()], 1),
            9,
        );
        let refused =
            scene
                .adapter
                .collect_from_drain(&mut drain, &scene.descriptors, None, &fault, 0);
        assert_eq!((refused.ingested, refused.ordinary), (0, 0));
        assert_eq!(refused.drain_domain, 9);
        assert_eq!(scene.adapter.consumed_through, 0);
        // Its audit refuses the seal without voiding staged proof.
        let mut source = ScriptedH3Source::once(H3DispositionEvidence::scripted_clean(0));
        let audit = JournalAuditReceipt::collect(&refused, &mut source, scene.closure_generation());
        let frontier = scene.adapter.consumed_frontier();
        let fresh = SessionBirthEvidence::scripted_for_receipt(&bootstrap);
        let failure = scene
            .seal_explicit(&audit, &bootstrap, frontier, fresh)
            .expect_err("first-presented foreign drain refuses");
        assert_eq!(failure.gap, JournalGap::DrainMismatch);
        assert!(
            !failure.affects_domain(bootstrap.domain()),
            "foreign drain refusal has no loss authority"
        );
        // Session authority mints the association from its retained
        // EVENTS domain (7) plus the admission: the grant carries the
        // producers' identities, and binding it is idempotent.
        let grant = scene.mint_drain_grant();
        assert_eq!(grant.domain_tag(), proof.key.domain_tag);
        assert_eq!(grant.events_id(), 7);
        scene.bind_session_drain();
        scene.bind_session_drain();
        // THE SESSION DRAIN collects and seals.
        let begin = begin_bytes(1, 1, create, 0);
        let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        let collection = scene.collect_records(vec![begin.to_vec(), end.to_vec()], &fault);
        assert_eq!(collection.drain_domain, 7);
        scene
            .seal_collected(&bootstrap, &collection)
            .expect("own drain seals");
        // FOREIGN AFTER: still refuses and consumes nothing.
        let mut drain = crate::events::EventDrain::over_test_domain(
            crate::events::ScriptedRecords::records(vec![foreign.to_vec()], 1),
            9,
        );
        let refused =
            scene
                .adapter
                .collect_from_drain(&mut drain, &scene.descriptors, None, &fault, 0);
        assert_eq!((refused.ingested, refused.ordinary), (0, 0));
        assert_eq!(scene.adapter.consumed_through, 2);
        // Bind discipline: an unattested domain binds nothing, and a
        // bound domain never rebinds to a rotated EVENTS identity
        // (another Session incarnation's retained domain).
        let mut stranger = Scene::new(image_default());
        let grant = stranger.mint_drain_grant();
        assert_eq!(
            stranger.adapter.bind_session_drain(&grant),
            Err(DrainBindRefusal::DomainUnattested)
        );
        stranger.attest();
        stranger.bind_session_drain();
        let rotated_producers = crate::attach::SessionDrainProducers::test_pair(
            stranger.fixture.domain(),
            crate::events::EventsDomain::test_standin(13),
        );
        let rotated = SessionDrainGrant::observe(&rotated_producers, &stranger.fixture.admit())
            .expect("the stranger's own admission mints");
        assert_eq!(
            stranger.adapter.bind_session_drain(&rotated),
            Err(DrainBindRefusal::DrainConflict)
        );
    }

    #[test]
    fn object_journal_drain_grant_refuses_spliced_foreign_pair() {
        // C2: the grant mints through the Session retaining BOTH the
        // native and EVENTS identities: one Session's producers paired
        // with another Session's admission refuse at mint — BEFORE any
        // valid binding exists, with no assumed-correct setup on the
        // foreign-first path. Each Session's own pair still mints.
        let mut scene_a = Scene::new(image_default());
        let mut scene_b = Scene::new(image_default());
        scene_b.retained_events = crate::events::EventsDomain::test_standin(11);
        let proof_a = scene_a.attest();
        let proof_b = scene_b.attest();
        assert_ne!(
            proof_a.key.domain_tag, proof_b.key.domain_tag,
            "scenes own distinct native domains"
        );
        let admitted_a = scene_a.fixture.admit();
        let admitted_b = scene_b.fixture.admit();
        let producers_a = scene_a.producers();
        let producers_b = scene_b.producers();
        assert_eq!(producers_a.events_id(), 7);
        assert_eq!(producers_b.events_id(), 11);
        // SPLICED FOREIGN FIRST in both directions: neither adapter
        // holds a binding yet, and the mint still refuses.
        assert_eq!(
            SessionDrainGrant::observe(&producers_b, &admitted_a),
            Err(DrainMintRefusal::ForeignAdmission)
        );
        assert_eq!(
            SessionDrainGrant::observe(&producers_a, &admitted_b),
            Err(DrainMintRefusal::ForeignAdmission)
        );
        // Each Session's own pair mints and binds.
        scene_a.bind_session_drain();
        scene_b.bind_session_drain();
    }

    #[test]
    fn object_journal_h3_disposition_requires_complete_disposition() {
        // C5: H3 disposition is minted from the finalizer's complete
        // state, never a maximum token. Staged positions certify only
        // their batch's maximum; route-waiting, unpublished and shed
        // positions ride along explicitly; negatives and exhaustion
        // dispose as loss; and the seal enforces coverage in H0's own
        // position space.
        use crate::inventory_semantics::LaneNegative;

        let genesis = H3DispositionEvidence::genesis();
        // A later joined outcome while earlier routing pends: the
        // batch maximum is 2 but position 1 is undisposed. The
        // evidence carries both facts; it never claims 2 disposed.
        let evidence = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(2)],
            Some(1),
            None,
            None,
            false,
            &genesis,
            0,
        );
        assert!(matches!(
            evidence,
            H3DispositionEvidence::Clean {
                staged_max: 2,
                pending_floor: Some(1),
            }
        ));
        // The maximum is monotone over previous evidence; the pending
        // floor is always the current one.
        let next = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(1), Some(3)],
            None,
            None,
            None,
            false,
            &evidence,
            0,
        );
        assert!(matches!(
            next,
            H3DispositionEvidence::Clean {
                staged_max: 3,
                pending_floor: None,
            }
        ));
        // Shed positions never certify: the minimum shed is a loss
        // barrier, even above the staged maximum.
        let shed = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(4)],
            None,
            Some(9),
            None,
            false,
            &genesis,
            0,
        );
        assert!(matches!(
            shed,
            H3DispositionEvidence::StagedLoss { barrier: 9 }
        ));
        // An unpositioned staged outcome means the H0 allocator is
        // exhausted: permanent, not a waitable gap.
        let dead = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(4), None],
            None,
            None,
            None,
            false,
            &genesis,
            0,
        );
        assert!(matches!(dead, H3DispositionEvidence::Exhausted));
        // Staged negatives are loss barriers; a refused collection
        // disposes nothing.
        for (negatives, barrier) in [
            (vec![LaneNegative::CutBarrier { ordinal: 5 }], 5),
            (
                vec![
                    LaneNegative::CutBarrier { ordinal: 5 },
                    LaneNegative::CutBarrier { ordinal: 3 },
                ],
                3,
            ),
        ] {
            let loss = H3DispositionEvidence::from_finalizer_batch(
                &negatives,
                &[Some(9)],
                None,
                None,
                None,
                false,
                &genesis,
                0,
            );
            assert!(
                matches!(loss, H3DispositionEvidence::StagedLoss { barrier: b } if b == barrier)
            );
        }
        // Exhaustion sticks: later batches cannot revive the allocator.
        let after = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(10)],
            None,
            None,
            None,
            false,
            &dead,
            0,
        );
        assert!(matches!(after, H3DispositionEvidence::Exhausted));
        // An unacknowledged loss barrier persists across a clean
        // batch: only the seal's explicit void releases the next mint
        // into Clean, restarting the certified maximum above the voided
        // barrier.
        let unacked = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(10)],
            None,
            None,
            None,
            false,
            &shed,
            0,
        );
        assert!(matches!(
            unacked,
            H3DispositionEvidence::StagedLoss { barrier: 9 }
        ));
        let recovered = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(10)],
            None,
            None,
            None,
            false,
            &shed,
            10,
        );
        assert!(matches!(
            recovered,
            H3DispositionEvidence::Clean {
                staged_max: 10,
                pending_floor: None,
            }
        ));
    }

    #[test]
    fn object_journal_h3_acknowledged_loss_covers_a_quiet_voided_interval() {
        let loss = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(7), Some(9)],
            None,
            Some(7),
            None,
            false,
            &H3DispositionEvidence::genesis(),
            0,
        );
        assert!(matches!(
            loss,
            H3DispositionEvidence::StagedLoss { barrier: 7 }
        ));

        // The actual seal's exclusive acknowledgement disposes the whole
        // interval below12. No fresh outcome is needed to dispose it again.
        let recovered = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[],
            None,
            None,
            None,
            false,
            &loss,
            12,
        );
        assert!(
            matches!(
                recovered,
                H3DispositionEvidence::Clean {
                    staged_max: 11,
                    pending_floor: None
                }
            ),
            "an acknowledged quiet interval must not await new calls: {recovered:?}"
        );
    }

    #[test]
    fn object_journal_h3_void_recovery_retains_pending_floors_and_new_loss() {
        let loss = H3DispositionEvidence::StagedLoss { barrier: 7 };
        let pending = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[],
            Some(8),
            None,
            Some(10),
            false,
            &loss,
            12,
        );
        assert!(
            matches!(
                pending,
                H3DispositionEvidence::Clean {
                    staged_max: 11,
                    pending_floor: Some(8)
                }
            ),
            "a void acknowledgement cannot erase retained work: {pending:?}"
        );

        let unacknowledged = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[],
            None,
            None,
            None,
            false,
            &loss,
            7,
        );
        assert!(matches!(
            unacknowledged,
            H3DispositionEvidence::StagedLoss { barrier: 7 }
        ));

        let new_loss = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(13)],
            None,
            Some(13),
            None,
            false,
            &loss,
            12,
        );
        assert!(matches!(
            new_loss,
            H3DispositionEvidence::StagedLoss { barrier: 13 }
        ));
        let exhausted = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[],
            None,
            None,
            None,
            true,
            &loss,
            12,
        );
        assert!(matches!(exhausted, H3DispositionEvidence::Exhausted));
    }

    #[test]
    fn object_journal_h3_loss_acknowledgement_gates_clean_transition() {
        // N1: loss at position 1, then a clean batch through 2. Without
        // the seal's acknowledgement the barrier persists (never a
        // silent Clean); the acknowledged twin transitions.
        let genesis = H3DispositionEvidence::genesis();
        let loss = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(1)],
            None,
            Some(1),
            None,
            false,
            &genesis,
            0,
        );
        assert!(matches!(
            loss,
            H3DispositionEvidence::StagedLoss { barrier: 1 }
        ));
        let unacked = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(2)],
            None,
            None,
            None,
            false,
            &loss,
            0,
        );
        assert!(
            matches!(unacked, H3DispositionEvidence::StagedLoss { barrier: 1 }),
            "unacknowledged loss persists: {unacked:?}"
        );
        let acked = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[Some(2)],
            None,
            None,
            None,
            false,
            &loss,
            2,
        );
        assert!(matches!(
            acked,
            H3DispositionEvidence::Clean {
                staged_max: 2,
                pending_floor: None,
            }
        ));
    }

    #[test]
    fn object_journal_seal_acknowledges_h3_loss_through_finalizer() {
        // C3 (+carryover 5 + N1): the PRODUCTION joint tick drives the
        // wired path through the ACTUAL H3 finalizer. The finalizer
        // mints a loss; the tick takes it (never caller-supplied),
        // audits, seals, voids and forwards the voided watermark to the
        // finalizer through production code — the test never touches
        // collect/audit/seal/acknowledge. The next mint releases into
        // Clean so genuinely new history seals. A tick with no fresh
        // batch waits on genesis evidence.
        use crate::attach::{BackendSelection, Scope};
        use crate::discovery::caller_registry::{OsProcessSource, RegistryLimits};
        use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;
        use crate::discovery::hooks::HookRegistry;
        use crate::inventory_semantics::{AttestedSemanticLane, SemanticBatch};
        use crate::semantic_capture::{Invalidation, InvalidationScope, TickOutcome, TickReport};
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let pid = std::process::id();
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        // The lane runs on its own attested subset; the scene keeps
        // its fixture for admission claims across the void.
        let mut lane_fixture = AttestationFixture::new(image_default());
        let mut lane = AttestedSemanticLane::start(
            lane_fixture.take_subset(),
            &Scope::Pid(pid),
            BackendSelection::Auto,
        )
        .expect("shell lane starts");
        let detailed = lane.domain();
        let commit = |coordinator: &mut InventoryCoordinator<OsProcessSource>,
                      lane: &mut AttestedSemanticLane,
                      report: TickReport| {
            let batch = SemanticBatch::from_tick_report(detailed, report, Vec::new(), 130).unwrap();
            coordinator.stage_semantic_batch(batch);
            coordinator
                .commit_batch_with_semantics(false, Some(lane))
                .unwrap();
        };
        let invalidation = |position: u64| {
            TickOutcome::Invalidation(Invalidation::scripted(
                detailed,
                InvalidationScope::CoverageFailed,
                Some(position),
            ))
        };
        let create = function_id("C_CreateObject");
        let fault = ScriptedFaultCell::steady(7);
        // The Session drain holds both quanta; the tick consumes two
        // records per quantum through the real dispatch poll. The tick
        // performs the first bind itself (no manual pre-bind).
        let producers = scene.producers();
        let first = begin_bytes(1, 1, create, 0);
        let next = begin_bytes(1, 2, create, 0);
        let mut drain = crate::events::EventDrain::over_test_domain(
            crate::events::ScriptedRecords::records(
                vec![
                    first.to_vec(),
                    end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50).to_vec(),
                    next.to_vec(),
                    end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60).to_vec(),
                ],
                4,
            ),
            7,
        );
        // Quantum 1: journal history plus a finalizer loss barrier below
        // the collection watermark. The tick takes the loss, voids,
        // reports the voided watermark and forwards it to the finalizer.
        commit(
            &mut coordinator,
            &mut lane,
            TickReport::scripted_with_disposition(
                vec![invalidation(2)],
                Vec::new(),
                None,
                Some(1),
                false,
            ),
        );
        let bootstrap = scene.bootstrap(proof, 0);
        let mut births =
            ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(&bootstrap));
        let admitted = scene.fixture.admit();
        let failure = {
            let mut tick = JointSealTick::wire(
                &mut scene.adapter,
                &mut scene.model,
                &mut drain,
                &scene.descriptors,
                &fault,
                &mut coordinator,
                scene.fixture.attachment(),
                &producers,
            );
            tick.tick(Some(2), 0, &bootstrap, &admitted, &mut births)
                .expect_err("taken loss voids")
        };
        assert_eq!(failure.gap, JournalGap::H3Loss);
        assert_eq!(failure.h3_voided, Some(3));
        // A real void already disposed every position below3. With no
        // further calls, an empty finalizer batch must cover that exact
        // acknowledged prefix instead of waiting for a new position.
        commit(
            &mut coordinator,
            &mut lane,
            TickReport::scripted_with_disposition(Vec::new(), Vec::new(), None, None, false),
        );
        let quiet = coordinator.take_h3_disposition();
        assert!(
            matches!(
                quiet,
                H3DispositionEvidence::Clean {
                    staged_max: 2,
                    pending_floor: None
                }
            ),
            "the actual seal acknowledgement must release quiet coverage: {quiet:?}"
        );
        // Quantum 2: a clean finalizer batch releases into Clean past
        // the acknowledged barrier, and genuinely new journal history
        // seals above the void fence. The void cleared admission
        // claims: re-attest for the new history. No manual
        // acknowledgement anywhere: the tick forwarded quantum 1's
        // report through production code.
        let paired_end = end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60);
        let JournalRecord::End(paired_end) =
            decode_journal_record(&paired_end, &scene.descriptors).unwrap()
        else {
            panic!("paired END")
        };
        let admitted_return = scene
            .fixture
            .admit_original_event("C_CreateObject", paired_end.payload_base().event);
        scene
            .adapter
            .attest_key(&admitted_return)
            .expect("new exact return attests after void");
        commit(
            &mut coordinator,
            &mut lane,
            TickReport::scripted_with_disposition(
                vec![invalidation(4)],
                Vec::new(),
                None,
                None,
                false,
            ),
        );
        let fence = scene.adapter.consumed_through;
        let grant = SessionBirthGrant::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let resume =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("fence absence attests");
        let mut births =
            ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(&resume));
        let admitted = scene.fixture.admit();
        let recovered = {
            let mut tick = JointSealTick::wire(
                &mut scene.adapter,
                &mut scene.model,
                &mut drain,
                &scene.descriptors,
                &fault,
                &mut coordinator,
                scene.fixture.attachment(),
                &producers,
            );
            tick.tick(Some(2), 0, &resume, &admitted, &mut births)
                .expect("acknowledged history seals")
        };
        assert_eq!(recovered.prefix.settled().len(), 1);
        // No fresh batch minted: the take yields genesis and the tick
        // waits for coverage instead of certifying across a gap.
        let mut births =
            ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(&resume));
        let admitted = scene.fixture.admit();
        let failure = {
            let mut tick = JointSealTick::wire(
                &mut scene.adapter,
                &mut scene.model,
                &mut drain,
                &scene.descriptors,
                &fault,
                &mut coordinator,
                scene.fixture.attachment(),
                &producers,
            );
            tick.tick(Some(2), 0, &resume, &admitted, &mut births)
                .expect_err("stale evidence waits")
        };
        assert_eq!(failure.gap, JournalGap::H3Pending);
    }

    #[test]
    fn object_journal_h3_acknowledgement_checks_retained_session() {
        use crate::discovery::caller_registry::{OsProcessSource, RegistryLimits};
        use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;

        struct HeldAcknowledgement(Option<H3VoidAcknowledgement>);
        impl H3EvidenceSource for HeldAcknowledgement {
            fn take_h3_disposition(&mut self) -> H3DispositionEvidence {
                H3DispositionEvidence::scripted_loss(1)
            }
        }
        impl H3FinalizerPort for HeldAcknowledgement {
            fn acknowledge_h3_void(&mut self, acknowledgement: H3VoidAcknowledgement) {
                assert!(self.0.replace(acknowledgement).is_none());
            }
        }

        for mismatch in 0..4 {
            // Native I/O is substituted by the existing algorithm scene. The
            // actual JointSealTick alone mints each move-only acknowledgement.
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            let producers = scene.producers();
            let begin = begin_bytes(1, 1, function_id("C_CreateObject"), 0);
            let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
            let mut drain = crate::events::EventDrain::over_test_domain(
                crate::events::ScriptedRecords::records([begin.to_vec(), end.to_vec()], 2),
                7,
            );
            let fault = ScriptedFaultCell::steady(7);
            let bootstrap = scene.bootstrap(proof, 0);
            let mut births =
                ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(&bootstrap));
            let admitted = scene.fixture.admit();
            let mut held = HeldAcknowledgement(None);
            let failure = JointSealTick::wire(
                &mut scene.adapter,
                &mut scene.model,
                &mut drain,
                &scene.descriptors,
                &fault,
                &mut held,
                scene.fixture.attachment(),
                &producers,
            )
            .tick(Some(2), 0, &bootstrap, &admitted, &mut births)
            .expect_err("real seal loss mints a void acknowledgement");
            assert_eq!(failure.gap, JournalGap::H3Loss);
            let voided = failure.h3_voided.unwrap();
            let target = match mismatch {
                0 => producers.clone(),
                1 => crate::attach::SessionDrainProducers::test_pair(
                    NativeDomainId::mint(),
                    scene.retained_events.clone(),
                ),
                2 => crate::attach::SessionDrainProducers::test_pair(
                    producers.native_domain(),
                    crate::events::EventsDomain::test_standin(8),
                ),
                _ => crate::attach::SessionDrainProducers::test_pair(
                    producers.native_domain(),
                    crate::events::EventsDomain::test_standin(producers.events_id()),
                ),
            };
            let mut coordinator = InventoryCoordinator::new(
                crate::attach::Scope::Pid(std::process::id()),
                crate::discovery::hooks::HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::default_limits(),
            )
            .unwrap();
            coordinator
                .session_h3_finalizer(&target)
                .unwrap()
                .acknowledge_h3_void(held.0.take().unwrap());
            assert_eq!(
                coordinator.reference_h3_acknowledged_below(),
                if mismatch == 0 { voided } else { 0 },
                "only the exact retained native/EVENTS pair may mutate its H0 namespace"
            );
        }
    }

    /// The owner's disjoint split wires the staged seal tick: the
    /// adapter/model pair from `parts()` is exactly what `wire` takes.
    /// Construction alone compiles here; the tick itself stays gated
    /// (no `tick`/`tick_collected` call). The read/write model borrows
    /// share that same model identity.
    #[test]
    fn joint_capture_owner_parts_wire_the_seal_tick_without_ticking() {
        use super::joint_driver::JointCaptureOwner;
        use crate::semantics_edge::resources::SemanticResourcePool;

        struct WiredOnlyFinalizer;
        impl H3EvidenceSource for WiredOnlyFinalizer {
            fn take_h3_disposition(&mut self) -> H3DispositionEvidence {
                H3DispositionEvidence::genesis()
            }
        }
        impl H3FinalizerPort for WiredOnlyFinalizer {
            fn acknowledge_h3_void(&mut self, _acknowledgement: H3VoidAcknowledgement) {
                unreachable!("wired but never ticked");
            }
        }

        let scene = Scene::new(image_default());
        let producers = scene.producers();
        let mut drain = crate::events::EventDrain::over_test_domain(
            crate::events::ScriptedRecords::records([], 0),
            7,
        );
        let fault = ScriptedFaultCell::steady(7);
        let mut finalizer = WiredOnlyFinalizer;
        let pool = SemanticResourcePool::default();
        let mut owner = JointCaptureOwner::new(JournalLimits::policy(), pool.reserver());
        {
            let (adapter, model) = owner.parts();
            let _tick = JointSealTick::wire(
                adapter,
                model,
                &mut drain,
                &scene.descriptors,
                &fault,
                &mut finalizer,
                scene.fixture.attachment(),
                &producers,
            );
        }
        assert_eq!(
            owner.ledger().census(),
            0,
            "wiring borrows without charging or ticking"
        );
        let model_via_parts = {
            let (_, model) = owner.parts();
            std::ptr::from_ref(&*model)
        };
        assert_eq!(
            model_via_parts,
            std::ptr::from_ref(owner.model()),
            "parts() and model() borrow the capture's one model"
        );
        let model_mut_via_parts = {
            let (_, model) = owner.parts();
            std::ptr::from_mut(&mut *model)
        };
        assert_eq!(
            model_mut_via_parts,
            std::ptr::from_mut(owner.model_mut()),
            "parts() and model_mut() lend the capture's one model"
        );
    }

    #[test]
    fn object_journal_joint_tick_forwards_void_report() {
        // C3: the production tick forwards the seal's void report to
        // the finalizer exactly once, and only on a voiding seal. A
        // recording fake finalizer takes scripted evidence and records
        // every acknowledgement.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        struct RecordingFinalizer {
            next: H3DispositionEvidence,
            acked: Vec<H3VoidAcknowledgement>,
        }

        impl H3EvidenceSource for RecordingFinalizer {
            fn take_h3_disposition(&mut self) -> H3DispositionEvidence {
                std::mem::replace(&mut self.next, H3DispositionEvidence::genesis())
            }
        }

        impl H3FinalizerPort for RecordingFinalizer {
            fn acknowledge_h3_void(&mut self, acknowledgement: H3VoidAcknowledgement) {
                self.acked.push(acknowledgement);
            }
        }

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        // The tick performs the first bind itself (no manual pre-bind).
        let producers = scene.producers();
        let create = function_id("C_CreateObject");
        let fault = ScriptedFaultCell::steady(7);
        let first = begin_bytes(1, 1, create, 0);
        let next = begin_bytes(1, 2, create, 0);
        let mut drain = crate::events::EventDrain::over_test_domain(
            crate::events::ScriptedRecords::records(
                vec![
                    first.to_vec(),
                    end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50).to_vec(),
                    next.to_vec(),
                    end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60).to_vec(),
                ],
                4,
            ),
            7,
        );
        // A voiding seal forwards its report exactly once.
        let mut finalizer = RecordingFinalizer {
            next: H3DispositionEvidence::scripted_loss(1),
            acked: Vec::new(),
        };
        let bootstrap = scene.bootstrap(proof, 0);
        let mut births =
            ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(&bootstrap));
        let admitted = scene.fixture.admit();
        let failure = {
            let mut tick = JointSealTick::wire(
                &mut scene.adapter,
                &mut scene.model,
                &mut drain,
                &scene.descriptors,
                &fault,
                &mut finalizer,
                scene.fixture.attachment(),
                &producers,
            );
            tick.tick(Some(2), 0, &bootstrap, &admitted, &mut births)
                .expect_err("taken loss voids")
        };
        assert_eq!(failure.gap, JournalGap::H3Loss);
        assert_eq!(finalizer.acked.len(), 1);
        let acknowledgement = finalizer.acked.pop().unwrap();
        let voided = failure.h3_voided.expect("void report");
        assert_eq!(acknowledgement.for_producers(&producers), Some(voided));
        // A clean seal acknowledges nothing. The clean evidence covers
        // the post-quantum watermark (fence + 2 records).
        let fence = scene.adapter.consumed_through;
        let mut finalizer = RecordingFinalizer {
            next: H3DispositionEvidence::scripted_clean(fence + 2),
            acked: Vec::new(),
        };
        let paired_end = end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60);
        let JournalRecord::End(paired_end) =
            decode_journal_record(&paired_end, &scene.descriptors).unwrap()
        else {
            panic!("paired END")
        };
        let admitted_return = scene
            .fixture
            .admit_original_event("C_CreateObject", paired_end.payload_base().event);
        scene
            .adapter
            .attest_key(&admitted_return)
            .expect("new physical return attests");
        let grant = SessionBirthGrant::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let resume =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("fence absence attests");
        let mut births =
            ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(&resume));
        let admitted = scene.fixture.admit();
        let mut tick = JointSealTick::wire(
            &mut scene.adapter,
            &mut scene.model,
            &mut drain,
            &scene.descriptors,
            &fault,
            &mut finalizer,
            scene.fixture.attachment(),
            &producers,
        );
        tick.tick(Some(2), 0, &resume, &admitted, &mut births)
            .expect("clean history seals");
        assert!(finalizer.acked.is_empty(), "clean seals ack nothing");
    }

    #[test]
    fn object_journal_joint_tick_refuses_foreign_admission() {
        // C2: the joint tick mints from its retained producers plus
        // the quantum's admission, so a foreign admission refuses the
        // quantum with DrainMismatch before anything is collected —
        // one Session's history never collects under another's key.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let producers = scene.producers();
        let mut stranger = Scene::new(image_default());
        stranger.attest();
        let foreign = stranger.fixture.admit();
        let create = function_id("C_CreateObject");
        let fault = ScriptedFaultCell::steady(7);
        let first = begin_bytes(1, 1, create, 0);
        let mut drain = crate::events::EventDrain::over_test_domain(
            crate::events::ScriptedRecords::records(
                vec![
                    first.to_vec(),
                    end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50).to_vec(),
                ],
                2,
            ),
            7,
        );
        let bootstrap = scene.bootstrap(proof, 0);
        let mut births =
            ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(&bootstrap));
        struct RefusingFinalizer;
        impl H3EvidenceSource for RefusingFinalizer {
            fn take_h3_disposition(&mut self) -> H3DispositionEvidence {
                H3DispositionEvidence::genesis()
            }
        }
        impl H3FinalizerPort for RefusingFinalizer {
            fn acknowledge_h3_void(&mut self, _acknowledgement: H3VoidAcknowledgement) {
                unreachable!("the foreign quantum refuses before any void report");
            }
        }
        let mut finalizer = RefusingFinalizer;
        let mut tick = JointSealTick::wire(
            &mut scene.adapter,
            &mut scene.model,
            &mut drain,
            &scene.descriptors,
            &fault,
            &mut finalizer,
            scene.fixture.attachment(),
            &producers,
        );
        let failure = tick
            .tick(Some(2), 0, &bootstrap, &foreign, &mut births)
            .expect_err("foreign admission refuses the quantum");
        assert_eq!(failure.gap, JournalGap::DrainMismatch);
        assert_eq!(scene.adapter.consumed_through, 0, "nothing collected");
    }

    #[test]
    fn object_journal_seal_enforces_h3_quantum_coverage() {
        // C5: the seal enforces H3 coverage in H0's position space
        // against the collection's allocation watermark — never by
        // comparing H0 tokens to journal ordinals. Short staging or
        // pending below the watermark waits; a loss below it voids
        // once and forgives on re-presentation; exhaustion stops.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        fn scene_with_history() -> (Scene, BootstrapReceipt) {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            scene.ingest(&begin);
            scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
            let bootstrap = scene.bootstrap(proof, 0);
            (scene, bootstrap)
        }
        fn audit(scene: &Scene, h3: H3DispositionEvidence, h0_below: u64) -> JournalAuditReceipt {
            JournalAuditReceipt::scripted_h0(
                7,
                7,
                None,
                0,
                h3,
                scene.closure_generation(),
                h0_below,
            )
        }
        // Staged short of the watermark waits.
        let (mut scene, bootstrap) = scene_with_history();
        let frontier = scene.adapter.consumed_frontier();
        let short = audit(&scene, H3DispositionEvidence::scripted_clean(4), 6);
        let failure = scene
            .seal_explicit(
                &short,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("short staging waits");
        assert_eq!(failure.gap, JournalGap::H3Pending);
        // Pending below the watermark waits even at full staging.
        let pending = audit(
            &scene,
            H3DispositionEvidence::scripted_clean_pending(9, Some(5)),
            6,
        );
        let failure = scene
            .seal_explicit(
                &pending,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("pending below the watermark waits");
        assert_eq!(failure.gap, JournalGap::H3Pending);
        // Full coverage seals.
        let covered = audit(
            &scene,
            H3DispositionEvidence::scripted_clean_pending(9, Some(6)),
            6,
        );
        scene
            .seal_explicit(
                &covered,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect("covered quantum seals");
        // A loss below the watermark voids once...
        let (mut scene, bootstrap) = scene_with_history();
        let frontier = scene.adapter.consumed_frontier();
        let loss = audit(&scene, H3DispositionEvidence::scripted_loss(2), 6);
        let failure = scene
            .seal_explicit(
                &loss,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("loss below the watermark voids");
        assert_eq!(failure.gap, JournalGap::H3Loss);
        // ...is forgiven on re-presentation (the seal waits for clean
        // evidence instead of voiding twice)...
        let failure = scene
            .seal_explicit(
                &loss,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("forgiven loss waits");
        assert_eq!(failure.gap, JournalGap::H3Pending);
        // ...while a loss above the watermark waits without voiding.
        let above = audit(&scene, H3DispositionEvidence::scripted_loss(9), 6);
        let failure = scene
            .seal_explicit(
                &above,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("loss above the watermark waits");
        assert_eq!(failure.gap, JournalGap::H3Pending);
        // Exhaustion stops the adapter permanently.
        let (mut scene, bootstrap) = scene_with_history();
        let frontier = scene.adapter.consumed_frontier();
        let dead = audit(&scene, H3DispositionEvidence::scripted_exhausted(), 6);
        let failure = scene
            .seal_explicit(
                &dead,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("exhaustion stops");
        assert_eq!(failure.gap, JournalGap::H3Exhausted);
        let stopped = scene.seal(&bootstrap).expect_err("stopped adapter refuses");
        assert_eq!(stopped.gap, JournalGap::Stopped);
    }

    #[test]
    fn object_journal_fault_continuity_chains_across_collections() {
        // C6: the checked fault chains cumulatively, not just within one
        // collection. A fault that moves between collections (7,7 then
        // 8,8) voids; the baseline catches up and later seals pass.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let first = begin_bytes(1, 1, create, 0);
        scene.ingest(&first);
        scene.ingest(&end_bytes(&first, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("first seal passes");
        assert_eq!(scene.adapter.last_fault, Some(7));
        let second = begin_bytes(1, 2, create, 0);
        scene.ingest(&second);
        scene.ingest(&end_bytes(&second, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let frontier = scene.adapter.consumed_frontier();
        let moved = JournalAuditReceipt::scripted(
            8,
            8,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            scene.closure_generation(),
        );
        let failure = scene
            .seal_explicit(
                &moved,
                &bootstrap,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&bootstrap),
            )
            .expect_err("inter-collection fault move voids");
        assert_eq!(failure.gap, JournalGap::FaultChanged);
        assert_eq!(scene.adapter.last_fault, Some(8));
        // The baseline caught up: new history above the fence seals
        // under the fresh epoch. The void cleared admission claims:
        // re-attest for the new history.
        let fence = scene.adapter.consumed_through;
        scene.attest();
        let third = begin_bytes(1, 3, create, 0);
        scene.ingest(&third);
        scene.ingest(&end_bytes(&third, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 70));
        let grant = SessionBirthGrant::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let resume =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("fence absence attests");
        let frontier = scene.adapter.consumed_frontier();
        let fresh = JournalAuditReceipt::scripted(
            8,
            8,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            scene.closure_generation(),
        );
        let recovered = scene
            .seal_explicit(
                &fresh,
                &resume,
                frontier,
                SessionBirthEvidence::scripted_for_receipt(&resume),
            )
            .expect("post-void history seals");
        assert_eq!(recovered.prefix.settled().len(), 1);
    }

    #[test]
    fn object_journal_seal_rereads_fault_at_seal_time() {
        // C6: the seal re-reads the native fault cell at seal time. A
        // clean collection pair that moved before the seal voids; the
        // fresh reading becomes the new baseline.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let moved = ScriptedFaultCell::steady(8);
        let failure = scene
            .adapter
            .seal(
                &mut scene.model,
                &audit,
                &bootstrap,
                frontier,
                &mut ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(
                    &bootstrap,
                )),
                &moved,
            )
            .expect_err("seal-time fault move voids");
        assert_eq!(failure.gap, JournalGap::FaultChanged);
        assert_eq!(scene.adapter.last_fault, Some(8));
        // The fresh baseline holds: the old epoch no longer chains.
        let stale = scene
            .adapter
            .seal(
                &mut scene.model,
                &audit,
                &bootstrap,
                frontier,
                &mut ScriptedBirthSource::once(SessionBirthEvidence::scripted_for_receipt(
                    &bootstrap,
                )),
                &ScriptedFaultCell::steady(7),
            )
            .expect_err("stale epoch refuses");
        assert_eq!(stale.gap, JournalGap::FaultChanged);
    }

    #[test]
    fn object_journal_reader_discards_void_the_seal() {
        // C6: the retained reader surfaces consumed discards, and a
        // collection spanning one voids the seal (lost history is never
        // silently skipped). A clean re-collection seals new history
        // above the fence.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        scene.bind_session_drain();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        let mut script = BusyScript::new(vec![begin.to_vec(), end.to_vec()]);
        script.discard_bump = Some((1, 1));
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let fault = ScriptedFaultCell::steady(7);
        let collection =
            scene
                .adapter
                .collect_from_drain(&mut drain, &scene.descriptors, None, &fault, 0);
        assert_eq!(collection.discarded_delta, 1);
        let bootstrap = scene.bootstrap(proof, 0);
        let failure = scene
            .seal_collected(&bootstrap, &collection)
            .expect_err("spanned discards void");
        assert_eq!(failure.gap, JournalGap::Discarded);
        // A clean re-collection seals genuinely new history above the
        // fence. The void cleared admission claims: re-attest.
        let fence = scene.adapter.consumed_through;
        scene.attest();
        let next = begin_bytes(1, 2, create, 0);
        let next_end = end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60);
        scene.prepare_record_claims(&[next.to_vec(), next_end.to_vec()]);
        let script = BusyScript::new(vec![next.to_vec(), next_end.to_vec()]);
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let collection = scene.adapter.collect_from_drain(
            &mut drain,
            &scene.descriptors,
            None,
            &fault,
            scene.fixture.h0_allocated_below(),
        );
        assert_eq!(collection.discarded_delta, 0);
        let grant = SessionBirthGrant::scripted(
            proof,
            BirthKind::AbsenceAppearance,
            fence,
            scene.closure_generation(),
        );
        let resume =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("fence absence attests");
        let recovered = scene
            .seal_collected(&resume, &collection)
            .expect("clean history seals");
        assert_eq!(recovered.prefix.settled().len(), 1);
    }

    #[test]
    fn object_journal_failed_birth_take_refuses_without_void() {
        // C1: the seal pulls one fresh birth observation per seal; a
        // failed take refuses without voiding (the next tick takes
        // again), exactly like unverified native evidence.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        struct FailingBirthSource;

        impl BirthEvidenceSource for FailingBirthSource {
            fn take_birth_evidence(
                &mut self,
            ) -> Result<SessionBirthEvidence, crate::attach::BirthObservationRefusal> {
                Err(crate::attach::BirthObservationRefusal::CustodyLost)
            }
        }

        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let cell = ScriptedFaultCell::steady(audit.fault_after);
        let mut failing = FailingBirthSource;
        let failure = scene
            .adapter
            .seal(
                &mut scene.model,
                &audit,
                &bootstrap,
                frontier,
                &mut failing,
                &cell,
            )
            .expect_err("failed take refuses");
        assert_eq!(failure.gap, JournalGap::BootstrapMismatch);
        assert_eq!(failure.h3_voided, None);
        // Nothing voided: a fresh take seals the same staged history.
        let success = scene.seal(&bootstrap).expect("fresh take seals");
        assert_eq!(success.prefix.settled().len(), 1);
    }

    #[test]
    fn object_journal_seal_rechecks_fresh_birth_evidence() {
        // C1: the seal re-verifies FRESH Session birth evidence, not just
        // the attest-time grant. Native truth that moved between
        // attestation and seal (dirtied marker, tripped latch, lost
        // custody, rebound image, generation moved past the closure)
        // refuses the seal even though the grant attested.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        fn sealed_scene() -> (Scene, BootstrapReceipt) {
            let mut scene = Scene::new(image_default());
            let proof = scene.attest();
            let create = function_id("C_CreateObject");
            let begin = begin_bytes(1, 1, create, 0);
            scene.ingest(&begin);
            scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
            let grant = SessionBirthGrant::scripted(
                proof,
                BirthKind::ExecMarker,
                0,
                scene.closure_generation(),
            );
            let birth = BootstrapReceipt::attest(&scene.adapter, &grant).expect("grant attests");
            (scene, birth)
        }
        use p11scope_ebpf_common::journal_marker::{MARKER_DIRTY, MARKER_UNPUBLISHED, ready_word};
        let image = (COOKIE, EXEC);
        let ready = ready_word(EXEC);
        // Fresh evidence matching the grant seals.
        let (mut scene, birth) = sealed_scene();
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let fresh = SessionBirthEvidence::scripted(image, ready, 0, scene.closure_generation(), 1);
        scene
            .seal_explicit(&audit, &birth, frontier, fresh)
            .expect("fresh evidence seals");
        // Each post-attestation corruption refuses the seal (each
        // scene seals under its own closure, so the fresh words are
        // built against that scene's generation).
        for corrupt in 0..6 {
            let (mut scene, birth) = sealed_scene();
            let closure = scene.closure_generation();
            let fresh = match corrupt {
                0 => SessionBirthEvidence::scripted(image, MARKER_DIRTY, 0, closure, 1),
                1 => SessionBirthEvidence::scripted(image, ready, 1, closure, 1),
                2 => SessionBirthEvidence::scripted(image, ready, 0, closure, 0),
                3 => SessionBirthEvidence::scripted((COOKIE + 1, EXEC), ready, 0, closure, 1),
                4 => SessionBirthEvidence::scripted(image, MARKER_UNPUBLISHED, 0, closure, 1),
                _ => SessionBirthEvidence::scripted(image, ready, 0, closure.wrapping_add(1), 1),
            };
            let frontier = scene.adapter.consumed_frontier();
            let audit = scene.audit();
            let failure = scene
                .seal_explicit(&audit, &birth, frontier, fresh)
                .expect_err("moved native truth refuses the seal");
            assert_eq!(failure.gap, JournalGap::BootstrapMismatch);
        }
    }
}
