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

use std::collections::{BTreeMap, BTreeSet};

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
/// the image both sides bind). Return-time facts (rv, timestamps) are
/// excluded: a BEGIN is entry truth. Two same-image instances whose
/// calls share a fingerprint are indistinguishable on the wire, so a
/// fingerprint claimed by two live keys attributes to neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CallFingerprint {
    pub(crate) image: (u64, u64),
    pub(crate) function: u32,
    pub(crate) session: u64,
    pub(crate) mechanism: u64,
    pub(crate) capture: u32,
    pub(crate) slot_id: u64,
    pub(crate) flags: u64,
    pub(crate) user_type: u32,
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
    mint: u64,
    open: BTreeMap<JournalNativeKey, OpenEntry>,
    floors: BTreeMap<u64, u64>,
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
    /// Per-call admission authority: each admitted modeled call's
    /// fingerprint, claimed by its key with a multiset count. Conversion
    /// consumes one count per staged call; total counts stay within the
    /// staged-call bound (a void clears the store with the staging).
    claims: BTreeMap<CallFingerprint, BTreeMap<JournalDomainKey, u64>>,
    claim_counts: usize,
    last_audit_failure: Option<u64>,
    /// H0 positions below this watermark were voided by an H3-loss
    /// seal: re-presented barriers at or below it wait instead of
    /// voiding twice. Monotone; H0's allocator ascends, so each new
    /// loss lies above it.
    h3_voided_below: u64,
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
}

impl JournalAdapter {
    pub(crate) fn new(limits: JournalLimits) -> Self {
        Self {
            limits,
            consumed_through: 0,
            mint: 0,
            open: BTreeMap::new(),
            floors: BTreeMap::new(),
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
            last_fault: None,
            drain_pins: BTreeMap::new(),
            invalidated: false,
            stopped: false,
            closure_generation: 0,
        }
    }

    /// The current consumption frontier: the highest ordinal consumed, in
    /// any form. The only source of seal frontiers besides older held
    /// values, so a seal can never claim unconsumed history.
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
        let Some(next) = self.consumed_through.checked_add(1) else {
            self.invalidated = true;
            return JournalDisposition::Refused;
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
        match &item {
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
            let affecting = match &item {
                JournalIngestItem::Journal(_) => true,
                JournalIngestItem::Ordinary(decoded) => {
                    let event = &decoded.base.event;
                    let child = (event.child_image.task_cookie, event.child_image.exec_id);
                    // A forked child inherits its parent's provider state,
                    // so a present child sighting always counts as
                    // affecting; the acting image counts only when its
                    // function is not proved irrelevant (unclassified is
                    // suspect).
                    (*image == child && child != (0, 0))
                        || !matches!(
                            endpoint_class(event.target_function),
                            Some(EndpointClass::ProvedIrrelevant)
                        )
                }
            };
            if !self.note_sighting(*image, affecting, next) {
                self.taint_image(*image);
                return JournalDisposition::Refused;
            }
        }
        match item {
            JournalIngestItem::Journal(record) => {
                self.ingest(AuditedJournalRecord::collected(ordinal, record))
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
            JournalRecord::Begin(begin) => self.ingest_begin(record.ordinal.0, begin),
            JournalRecord::End(end) => self.ingest_end(record.ordinal.0, end),
            JournalRecord::Abandon(abandon) => self.ingest_abandon(record.ordinal.0, abandon),
        }
    }

    fn image_of_begin(begin: &ValidatedJournalBegin) -> (u64, u64) {
        (begin.image_cookie(), begin.image_exec())
    }

    fn ingest_begin(&mut self, ordinal: u64, begin: ValidatedJournalBegin) -> JournalDisposition {
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
        self.floors.insert(begin.thread(), begin.sequence());
        if self.open.len() >= self.limits.open_calls {
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
        self.open.retain(|_, entry| entry.image != image);
        self.refused.retain(|refused| refused.image != image);
    }

    /// Mint one checked nonrecycled ticket, failing closed on exhaustion.
    fn mint_ticket(&mut self) -> Option<JournalTicket> {
        let next = self.mint.checked_add(1)?;
        self.mint = next;
        Some(JournalTicket(next))
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

/// Whether one END's repeated entry evidence agrees exactly with its BEGIN:
/// image, key, descriptor, session, inputs, slot, mechanism, capture,
/// layout, entry address/stamp, requested lists, slot identity, flags and
/// user type. Entry time is not repeated (the END carries return time, not
/// entry time), so it is not compared; the model still rejects a return
/// older than its entry as malformed.
fn end_agrees_with_begin(begin: &ValidatedJournalBegin, end: &ValidatedJournalEnd) -> bool {
    let base = end.payload_base();
    let tail = end.payload_tail();
    let event = &base.event;
    if event.image.task_cookie != begin.image_cookie()
        || event.image.exec_id != begin.image_exec()
        || event.pid_tgid != begin.pid_tgid()
        || event.session != begin.session_word()
        || event.slot != begin.slot()
        || event.mechanism != begin.entry_mechanism()
        || event.capture != begin.capture()
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
        // voided loss barrier restarts it above itself (positions at or
        // below the barrier were disposed as loss). The pending floor
        // is the current minimum over route-waiting and unpublished
        // positions.
        let base = match previous {
            Self::Clean { staged_max, .. } => *staged_max,
            Self::StagedLoss { barrier } => *barrier,
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
/// production code. Production wires the live coordinator; tests wire
/// the real coordinator over a scripted lane.
pub(crate) trait H3FinalizerPort: H3EvidenceSource {
    fn acknowledge_h3_void(&mut self, voided_below: u64);
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
    pub(crate) fault_before: u64,
    pub(crate) fault_after: u64,
    pub(crate) fault_error: Option<FaultReadError>,
    pub(crate) drain_domain: u64,
    pub(crate) h0_allocated_below: u64,
}

impl JournalAuditReceipt {
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
    /// issuance token, and only the birth observation sites
    /// (`observe_exec_birth` / `observe_absence_birth`) call this, with
    /// words they read or derived from genuine Session producers. The
    /// joint seal tick that observes in production is later Task 3 work.
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

/// A Session-owned birth grant: the claimed proof, birth kind, cut and
/// closure generation, plus the Session-observed native evidence the
/// claim was attested under (exec marker publication/readback or
/// held-custody absence/appearance). Production mint requires the
/// Session issuance capability, so stream inference alone can never
/// birth; the fields stay private, attestation checks the bundled
/// evidence, and the seal re-checks fresh evidence against retained
/// truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionBirthGrant {
    proof: JournalDomainProof,
    birth: BirthKind,
    birth_cut: u64,
    closure_generation: u64,
    evidence: SessionBirthEvidence,
}

impl SessionBirthGrant {
    /// Production mint: only Session-owned attach code holds the
    /// issuance token, minted solely by the birth observation sites.
    /// The joint seal tick that issues in production is later Task 3
    /// work; until it lands the observation/issue path is exercised by
    /// tests.
    #[allow(dead_code)] // No production caller until the joint seal tick lands.
    pub(crate) fn issue(
        _token: &crate::attach::SessionGrantToken,
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
        }
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
        let fenced_through = adapter
            .keys
            .get(&grant.proof.key)
            .map(|state| state.void_fence)
            .unwrap_or(0);
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
}

/// The sealed prefix H9 consumes: the proven domain, frontier, birth
/// and bootstrap cuts, the settled calls and the still-open keys. Built
/// only by a passing seal; the only path to a production
/// [`CompleteInputPrefix`].
#[derive(Debug, Clone)]
pub(crate) struct SealedObjectPrefix {
    domain: ObjectDomain,
    frontier: u64,
    birth_cut: u64,
    bootstrap: Option<u64>,
    settled: Vec<SealedCall>,
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
        &self.settled
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
    pub(crate) gap: JournalGap,
    pub(crate) effects: ObjectEffects,
    /// H3-loss acknowledgement: H0 positions below this watermark were
    /// voided by this seal. The joint tick forwards it to the H3
    /// finalizer (`acknowledge_h3_void`); `None` when this seal voided
    /// no H3 loss.
    pub(crate) h3_voided: Option<u64>,
}

/// Finite attestation refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttestationRefusal {
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
    /// grants mint only through the Session issuance capability.
    pub(crate) fn install_closure_grant(&mut self, grant: &SessionClosureGrant) -> bool {
        if grant.generation < self.closure_generation {
            return false;
        }
        self.closure_generation = grant.generation;
        true
    }

    /// Bind one H3-admitted call's incarnation to a journal key: the exact
    /// native domain, caller, image and router, plus the adapter-tracked
    /// era. Re-attestation after a fault-void returns the live key; a
    /// tainted image or a full key table refuses. A second live key for
    /// an image whose key already converted refuses: sole-key
    /// attributions cannot be re-examined. An admitted modeled call
    /// also claims its fingerprint for per-call conversion authority.
    /// Birth and closure are verified on top of this binding by
    /// [`BootstrapReceipt::attest`].
    pub(crate) fn attest_key(
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
        if let Some(fingerprint) = admitted.journal_call_fingerprint()
            && endpoint_class(fingerprint.function) == Some(EndpointClass::ModeledAffecting)
        {
            self.claim_fingerprint(fingerprint, key)?;
        }
        let era = self.keys[&key].era;
        Ok(JournalDomainProof { key, era })
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

    /// Claim one admitted fingerprint for its key. Counts stay within
    /// the staged-call bound; a full store first drops dead keys'
    /// claims, then refuses the attestation.
    fn claim_fingerprint(
        &mut self,
        fingerprint: CallFingerprint,
        key: JournalDomainKey,
    ) -> Result<(), AttestationRefusal> {
        if self.claim_counts >= self.limits.open_calls + self.limits.refused_begins {
            self.prune_dead_claims();
            if self.claim_counts >= self.limits.open_calls + self.limits.refused_begins {
                return Err(AttestationRefusal::ClaimsExhausted);
            }
        }
        *self
            .claims
            .entry(fingerprint)
            .or_default()
            .entry(key)
            .or_default() += 1;
        self.claim_counts += 1;
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
            .map(|m| m.values().sum::<u64>())
            .sum::<u64>() as usize;
    }

    /// Consume one claim count for a converted call. Every conversion
    /// holds a claim (attribution requires it, and coverage is checked
    /// before conversion), so the store always has the count.
    fn consume_claim(&mut self, fingerprint: &CallFingerprint, key: JournalDomainKey) {
        let mut vacated = false;
        if let Some(claimants) = self.claims.get_mut(fingerprint) {
            if let Some(count) = claimants.get_mut(&key)
                && *count > 0
            {
                *count -= 1;
                self.claim_counts -= 1;
                if *count == 0 {
                    claimants.remove(&key);
                }
            }
            vacated = claimants.is_empty();
        }
        if vacated {
            self.claims.remove(fingerprint);
        }
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
            for (claimant, count) in claimants {
                if *count == 0 {
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
    pub(crate) fn seal(
        &mut self,
        model: &mut ObjectSemantics,
        audit: &JournalAuditReceipt,
        bootstrap: &BootstrapReceipt,
        frontier: ConsumptionOrdinal,
        births: &mut impl BirthEvidenceSource,
        fault: &impl FaultEpoch,
    ) -> Result<SealSuccess, SealFailure> {
        let frontier = frontier.0;
        if self.stopped {
            return Err(self.failure(JournalGap::Stopped));
        }
        if self.invalidated {
            return Err(self.failure(JournalGap::AdapterInvalidated));
        }
        if frontier > self.consumed_through {
            return Err(self.failure(JournalGap::FrontierRegression));
        }
        let seal_epoch = fault.fault_epoch();
        if let Err(gap) = audit.check(
            self.last_fault,
            self.h3_voided_below,
            self.closure_generation,
            &seal_epoch,
        ) {
            // Any audit failure breaks absence-appearance chains: the clean
            // coverage the witness requires is gone from this ordinal on.
            // Voids fence the loss explicitly before dropping staged
            // truth, so later proof resumes above a fenced interval
            // instead of silently skipping it; the fencing effects are
            // reported with the refusal.
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
            return Err(SealFailure {
                gap,
                effects,
                h3_voided,
            });
        }
        // The audit passed: pin the cumulative baseline. Past the first
        // seal this is a no-op (the chain rule already equated them).
        self.last_fault = Some(audit.fault_after);
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
        // Pull one fresh birth observation: the seal never receives a
        // reusable evidence value. A failed take refuses (the next tick
        // takes again), exactly like moved native evidence.
        let Ok(fresh) = births.take_birth_evidence() else {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        };
        // Re-verify the birth with fresh Session evidence against
        // current retained truth: moved native evidence or a chain break
        // between attestation and seal still refuses.
        if let Err(refusal) = self.verify_birth(
            &bootstrap.proof(),
            bootstrap.birth(),
            bootstrap.birth_cut(),
            state.void_fence,
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
        // above the cut).
        if bootstrap.birth_cut() < state.void_fence {
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
        self.seal_validated(model, key, bootstrap, frontier, fence)
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
                                .filter(|(key, count)| **count > 0 && live.contains(key))
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
                let refused = model.abandon_domain(domain);
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
            let lost = model.outcome_lost(super::LostOutcome::Voided(
                domain,
                RefCut::sealed(ConsumptionOrdinal(upper)),
            ));
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
                .copied()
                .unwrap_or(0)
                >= need
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
        self.refused.clear();
        self.claims.clear();
        self.claim_counts = 0;
        for state in self.keys.values_mut() {
            state.bootstraps.clear();
        }
    }

    fn failure(&self, gap: JournalGap) -> SealFailure {
        SealFailure {
            gap,
            effects: ObjectEffects::default(),
            h3_voided: None,
        }
    }

    /// Conversion and settlement after every structural rule passed. The
    /// only remaining failures are model surprises, which fail closed.
    fn seal_validated(
        &mut self,
        model: &mut ObjectSemantics,
        key: JournalDomainKey,
        bootstrap: &BootstrapReceipt,
        frontier: u64,
        model_fence: Option<u64>,
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
            let effects = model.abandon_domain(domain);
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
            self.open.retain(|native, _| !drop.contains(native));
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
        self.convert_and_settle(model, key, bootstrap, frontier, model_fence)
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
            let refused_effects =
                model.note_refused_begin(domain, RefCut::sealed(ConsumptionOrdinal(*cut)));
            effects.effects.extend(refused_effects.effects);
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
                    let lost = model.outcome_lost(super::LostOutcome::Refused(
                        domain,
                        RefCut::sealed(ConsumptionOrdinal(upper)),
                    ));
                    effects.effects.extend(lost.effects);
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
        let mut settled = Vec::new();
        for (native, _) in begins {
            let Some(ticket) = self.mint_ticket() else {
                self.keys.get_mut(&key).expect("sealed key").tainted = true;
                return Err(SealFailure {
                    gap: JournalGap::ModelRefused,
                    effects,
                    h3_voided: None,
                });
            };
            let entry = *self.open.get(&native).expect("staged begin");
            let origin = origin_of(domain, entry.begin_ordinal, ticket, &entry.begin);
            let function = entry.function;
            let call_key = CallKey::sealed(ticket);
            let (admitted, begin_effects) = model.begin_with_effects(origin);
            effects.effects.extend(begin_effects.effects);
            match admitted {
                Ok(token) => {
                    let fingerprint = fingerprint_of_begin(&entry.begin);
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
                    });
                    self.consume_claim(&fingerprint, key);
                }
                Err(_) => {
                    self.keys.get_mut(&key).expect("sealed key").tainted = true;
                    return Err(SealFailure {
                        gap: JournalGap::ModelRefused,
                        effects,
                        h3_voided: None,
                    });
                }
            }
        }
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
                let applied = model.complete(token, completed);
                effects.effects.extend(applied.effects);
                self.open
                    .get_mut(&native)
                    .expect("staged terminal")
                    .end_converted = true;
                if let Some(summary) = settled.iter_mut().find(|summary| summary.ticket == token) {
                    summary.end_cut = Some(staged.ordinal);
                } else {
                    // The BEGIN converted under an earlier seal: emit an
                    // explicit terminal delta so H9 sees the close.
                    settled.push(SealedCall {
                        ticket: token,
                        key: entry.call_key.expect("converted terminal has a key"),
                        function: entry.function,
                        begin_cut: entry.begin_ordinal,
                        end_cut: Some(staged.ordinal),
                        abandoned: false,
                    });
                }
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
                    });
                };
                let lost = model.outcome_lost(super::LostOutcome::Ticket(
                    token,
                    RefCut::sealed(ConsumptionOrdinal(at)),
                ));
                effects.effects.extend(lost.effects);
                let retained = self.keys.get_mut(&key).expect("sealed key");
                retained.bounded_upper =
                    Some(retained.bounded_upper.map_or(at, |kept| kept.max(at)));
                if let Some(summary) = settled.iter_mut().find(|summary| summary.ticket == token) {
                    summary.abandoned = true;
                } else {
                    // The BEGIN converted under an earlier seal: emit an
                    // explicit terminal delta so H9 sees the bound.
                    settled.push(SealedCall {
                        ticket: token,
                        key: entry.call_key.expect("converted terminal has a key"),
                        function: entry.function,
                        begin_cut: entry.begin_ordinal,
                        end_cut: None,
                        abandoned: true,
                    });
                }
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
        // Terminal deltas append after this seal's conversions; restore
        // the begin-cut order the prefix promises H9.
        settled.sort_by_key(|summary| summary.begin_cut);
        let prefix = SealedObjectPrefix {
            domain,
            frontier,
            birth_cut: bootstrap.birth_cut(),
            bootstrap: model_fence,
            settled: settled.clone(),
            open,
        };
        let applied = model.settle(CompleteInputPrefix::sealed(&prefix));
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
            });
        }
        if rejected {
            return Err(SealFailure {
                gap: JournalGap::ModelRefused,
                effects,
                h3_voided: None,
            });
        }
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
        self.open.retain(|_, entry| {
            if entry.converted_for != Some(key) {
                return true;
            }
            if entry
                .abandon
                .is_some_and(|staged| staged.ordinal <= frontier)
            {
                return false;
            }
            if let Some(staged) = entry.end
                && staged.ordinal <= watermark
            {
                return false;
            }
            true
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
            let applied = model.abandon_domain(domain);
            effects.effects.extend(applied.effects);
            self.keys.get_mut(&key).expect("stopped key").refused = true;
        }
        self.open.clear();
        self.refused.clear();
        effects
    }
}

/// The production joint seal tick (H8): Session-owned orchestration of
/// one journal quantum. Each tick collects through the Session drain,
/// takes the H3 disposition from the actual finalizer, audits, seals,
/// and forwards the seal's void report back to the finalizer — the
/// acknowledgement flows through this production path, never through
/// test orchestration. All I/O is injected: production wires the live
/// drain, fault cell and finalizer (privileged execution stays UNRUN);
/// tests wire scripted ones. Construct once per Session; tick per
/// quantum.
#[allow(dead_code)] // No Session-loop caller until live activation; tests drive it.
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
        let audit = JournalAuditReceipt::collect(&collection, self.finalizer, observed);
        let frontier = self.adapter.consumed_frontier();
        let outcome = self
            .adapter
            .seal(self.model, &audit, bootstrap, frontier, births, self.fault);
        if let Err(failure) = &outcome
            && let Some(voided) = failure.h3_voided
        {
            self.finalizer.acknowledge_h3_void(voided);
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
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
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_LAYOUT_LP64, publish_object_descriptors,
        verify_object_descriptors,
    };
    use p11scope_ebpf_common::{Event, ImageIdentity, InstanceStamp, MAX_DESCRIPTORS};

    const COOKIE: u64 = 71;
    const EXEC: u64 = 0;
    const PID_TGID: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    const SESSION: u64 = 0x5050_5050_5050_5050;
    const SLOT_ID: u64 = 0x6060_6060_6060_6060;
    const FLAGS: u64 = 0x7070_7070_7070_7070;
    const ENTRY_NS: u64 = 0x3030_3030_3030_3030;
    const ENTRY_IP: u64 = 0x4040_4040_4040_4040;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn function_id(name: &str) -> u32 {
        crate::kinds::function_id(name).expect("catalog function")
    }

    /// Minimal valid BEGIN for any catalog function: VALUE session, absent
    /// inputs, valid entry stamp, zero requested lists.
    fn begin_bytes(thread: u64, sequence: u64, function: u32, flags: u8) -> [u8; 224] {
        begin_bytes_image(thread, sequence, function, flags, (COOKIE, EXEC))
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
        put_u64(&mut bytes, 24, PID_TGID);
        put_u64(&mut bytes, 32, image.0);
        put_u64(&mut bytes, 40, image.1);
        put_u64(&mut bytes, 48, ENTRY_NS);
        put_u64(&mut bytes, 56, ENTRY_IP);
        put_u32(&mut bytes, 64, 7);
        put_u32(&mut bytes, 68, 8);
        put_u32(&mut bytes, 72, 9);
        put_u16(&mut bytes, 76, 3);
        put_u16(&mut bytes, 78, STAMP_VALID);
        put_u64(&mut bytes, 80, SESSION);
        put_u32(&mut bytes, 104, 11);
        put_u32(&mut bytes, 108, function + 1);
        bytes[124] = OBJECT_LAYOUT_LP64;
        bytes[125] = 1;
        put_u64(&mut bytes, 200, SLOT_ID);
        put_u64(&mut bytes, 208, FLAGS);
        put_u32(&mut bytes, 216, 1);
        bytes
    }

    /// Minimal valid 608-byte completed payload matching `begin`: same
    /// image, session, slot, mechanism, capture, slot identity, flags,
    /// user type, entry address/stamp and requested lists.
    fn payload_for(begin: &[u8; 224], rv: u64, ts_ns: u64) -> [u8; 608] {
        use p11scope_ebpf_common::event_type;
        let mut payload = [0u8; 608];
        put_u64(&mut payload, 0, ts_ns);
        put_u64(&mut payload, 8, ts_ns.saturating_sub(ENTRY_NS));
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

    fn end_bytes(begin: &[u8; 224], action: u8, rv: u64, ts_ns: u64) -> [u8; 632] {
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
    fn end_bytes_absent(begin: &[u8; 224], rv: u64, ts_ns: u64) -> [u8; 632] {
        use p11scope_ebpf_common::object_journal::*;
        let mut bytes = end_bytes(begin, OBJECT_ACTION_CREATE, rv, ts_ns);
        bytes[5] = JOURNAL_END_TAIL_ABSENT;
        bytes[24 + 368..].fill(0);
        bytes
    }

    fn abandon_bytes(thread: u64, sequence: u64, reason: u32, image: (u64, u64)) -> [u8; 64] {
        use p11scope_ebpf_common::object_journal::*;
        let mut bytes = [0u8; JOURNAL_ABANDON_BYTES];
        put_u16(&mut bytes, 0, JOURNAL_VERSION);
        put_u16(&mut bytes, 2, JOURNAL_ABANDON_BYTES as u16);
        bytes[4] = JOURNAL_KIND_ABANDON;
        put_u64(&mut bytes, 8, thread);
        put_u64(&mut bytes, 16, sequence);
        put_u64(&mut bytes, 24, PID_TGID);
        put_u64(&mut bytes, 32, image.0);
        put_u64(&mut bytes, 40, image.1);
        put_u32(&mut bytes, 48, 11);
        put_u32(&mut bytes, 52, reason);
        put_u64(&mut bytes, 56, ENTRY_NS);
        bytes
    }

    /// One ordinary CALL corroborating `begin`: the same seven-word call
    /// identity read from the BEGIN, returned after entry, completed
    /// (non-pending) rv.
    fn ordinary_for(begin: &[u8; 224], rv: u64) -> Event {
        let entry_ns = u64::from_le_bytes(begin[48..56].try_into().unwrap());
        Event {
            ts_ns: entry_ns + 100,
            duration_ns: 100,
            pid_tgid: PID_TGID,
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
    const ADMITTABLE_FUNCTIONS: [&str; 8] = [
        "C_CreateObject",
        "C_GetAttributeValue",
        "C_SignInit",
        "C_Sign",
        "C_VerifyInit",
        "C_Verify",
        "C_SignMessage",
        "C_DestroyObject",
    ];

    /// Genuine-bind identity answers: the cookie queries the bind
    /// proof makes against the Detailed domain.
    #[derive(Default)]
    struct BindIdentity {
        answers:
            std::collections::HashMap<(u32, NativeDomainId), crate::attach::capture::CookieQuery>,
    }

    impl crate::discovery::native_binding::NativeIdentity<crate::process::PidPin> for BindIdentity {
        fn owner_image(&mut self, _pid: u32) -> Option<ImageIdentity> {
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

    struct AttestationFixture {
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
        fn new(image: ImageIdentity) -> Self {
            use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
            use p11scope_manifest::manifest::*;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("provider.so");
            std::fs::copy("/bin/true", &path).unwrap();
            let file = open_object(&path).unwrap();
            let inspected = inspect_file(&file).unwrap();
            let mapping = mapping_file_key(&file).unwrap();
            let start = inspected
                .executable_ranges
                .iter()
                .find(|(a, b)| b - a > ADMITTABLE_FUNCTIONS.len() as u64)
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
                            let resolution = ADMITTABLE_FUNCTIONS
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
            // The v3 message functions ride no legacy table: resolve
            // the one the neutral history stages on a v3 interface
            // surface (canonical V3_0 walk order).
            let message_functions: Vec<FunctionRecord> =
                match pkcs11_module::tables_for(pkcs11_module::Surface::StandardInterface {
                    version: cryptoki_sys::CK_VERSION { major: 3, minor: 0 },
                }) {
                    pkcs11_module::TableSet::Walk(spans) => spans
                        .iter()
                        .flat_map(|span| span.fields())
                        .map(|field| {
                            let resolution = if field.name == "C_SignMessage" {
                                Resolution::Resolved {
                                    object: 0,
                                    file_offset: start + 8,
                                }
                            } else {
                                Resolution::NullPointer
                            };
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
            for name in ADMITTABLE_FUNCTIONS {
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
        fn domain(&self) -> NativeDomainId {
            self.domain
        }

        /// The happy-path binding, genuinely bound: read back from the
        /// coordinator's stored proof.
        fn binding(
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
            let module = self.binding().module().clone();
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
        fn admit_function(&mut self, name: &str) -> AdmittedInstanceCall {
            self.admit_session_function(SESSION, name)
        }

        /// One real admission for a chosen session word and function.
        fn admit_session_function(&mut self, session: u64, name: &str) -> AdmittedInstanceCall {
            let (slot, endpoint) = self.functions[name];
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
                    base: crate::semantic_capture::event_record_with_routing(
                        Event {
                            slot,
                            session,
                            slot_id: SLOT_ID,
                            flags: FLAGS,
                            user_type: 1,
                            rv: 0,
                            ts_ns: 100 + token,
                            image: self.image,
                            ..Default::default()
                        },
                        stamp,
                        0x2200,
                    ),
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

        /// Move the attested subset out (for a semantic lane): the
        /// fixture keeps its binding/router for further admissions.
        fn take_subset(&mut self) -> AttestedSubset {
            self.subset.take().expect("subset held")
        }

        /// This fixture's sealed attachment: sealed from its attested
        /// subset at construction (a working subset was re-attested
        /// for admissions), so admits and sealing share one domain
        /// without ordering constraints.
        fn attachment(&self) -> &crate::attach::AttachedSemanticSet {
            &self.attachment
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
            };
            // The Session sealed before journal work: the adapter
            // starts under the observed closure.
            scene.install_observed_closure();
            scene
        }

        fn attest(&mut self) -> JournalDomainProof {
            let admitted = self.fixture.admit();
            self.adapter.attest_key(&admitted).expect("key attests")
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
            let admitted = self.fixture.admit_function(name);
            self.adapter.attest_key(&admitted).expect("key attests")
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
            let admitted = self.fixture.admit_session_function(session, name);
            self.adapter.attest_key(&admitted).expect("key attests")
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

        fn audit(&self) -> JournalAuditReceipt {
            JournalAuditReceipt::scripted(
                7,
                7,
                None,
                0,
                H3DispositionEvidence::scripted_clean(self.adapter.consumed_through),
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
            let frontier = self.adapter.consumed_frontier();
            let audit = JournalAuditReceipt::scripted(
                epoch,
                epoch,
                None,
                0,
                H3DispositionEvidence::scripted_clean(self.adapter.consumed_through),
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
            let bound = records.len();
            let mut drain = crate::events::EventDrain::over_test_domain(
                crate::events::ScriptedRecords::records(records, bound),
                self.retained_events.id(),
            );
            self.bind_session_drain();
            self.adapter
                .collect_from_drain(&mut drain, &self.descriptors, Some(bound), fault, 0)
        }

        /// One seal from a real collection: H3 disposition covers the
        /// consumed frontier, closure observed from the attachment.
        fn seal_collected(
            &mut self,
            bootstrap: &BootstrapReceipt,
            collection: &JournalCollection,
        ) -> Result<SealSuccess, SealFailure> {
            let h3 = H3DispositionEvidence::scripted_clean(self.adapter.consumed_through);
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
        let mut script = BusyScript::new(vec![begin.to_vec(), end.to_vec()]);
        script.busy_after = Some(1);
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let fault = ScriptedFaultCell::steady(7);
        let first =
            scene
                .adapter
                .collect_from_drain(&mut drain, &scene.descriptors, None, &fault, 0);
        assert_eq!((first.ingested, first.ordinary), (1, 0));
        assert_eq!(scene.adapter.consumed_through, 1);
        let bootstrap = scene.bootstrap(proof, 0);
        let held = scene
            .seal_collected(&bootstrap, &first)
            .expect("prefix frontier seals");
        assert_eq!(held.prefix.open_keys().len(), 1);
        let second =
            scene
                .adapter
                .collect_from_drain(&mut drain, &scene.descriptors, None, &fault, 0);
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
        let mut refused = begin_bytes(1, 1_025, create, 0);
        put_u32(&mut refused, 104, 77);
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
        let getinfo = function_id("C_GetInfo");
        let begin = begin_bytes(1, 1, create, 0);
        let mut seen = ordinary_for(&begin, 0);
        seen.slot = 99;
        seen.target_function = getinfo;
        scene.ingest_ordinary(seen);
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
        let getinfo = function_id("C_GetInfo");
        let begin = begin_bytes(1, 1, create, 0);
        let mut seen = ordinary_for(&begin, 0);
        seen.slot = 99;
        seen.target_function = getinfo;
        scene.ingest_ordinary(seen);
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
        fork.target_function = getinfo;
        fork.child_image = child_image;
        scene.ingest_ordinary(fork);
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
        let _ = scene
            .model
            .note_refused_begin(domain, super::RefCut::reference(99));
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
        let _ = scene
            .model
            .outcome_lost(crate::semantics_objects::LostOutcome::Ticket(
                ticket,
                super::RefCut::reference(999),
            ));
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
        let getinfo = function_id("C_GetInfo");
        let template = begin_bytes(1, 1, create, 0);
        for _ in 1..=5u64 {
            let mut seen = ordinary_for(&template, 0);
            seen.slot = 99;
            seen.target_function = getinfo;
            scene.ingest_ordinary(seen);
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
        let getinfo = function_id("C_GetInfo");
        let begin = begin_bytes(1, 1, create, 0);
        // Ordinal 1 observes the image without affecting it (proved
        // irrelevant), so absence can birth at cut 1; the BEGIN at 2
        // keeps exec novel only at cut 0.
        let mut seen = ordinary_for(&begin, 0);
        seen.slot = 99;
        seen.target_function = getinfo;
        scene.ingest_ordinary(seen);
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
    struct NativePublisher {
        _dir: tempfile::TempDir,
        binary: std::path::PathBuf,
    }

    impl NativePublisher {
        fn build() -> Self {
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
        fn publish(
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
        fn publish_stamped(
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
    struct NativeBirthRows {
        row: p11scope_ebpf_common::InstanceRecord,
        control: p11scope_ebpf_common::JournalAdmissionControl,
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
            permissions: [b'r', b'-', b'x', b'p'],
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
                fault: 0,
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
        let admitted = scene.fixture.admit();
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
        let grant = SessionBirthGrant::issue(
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
        // mismatch trips the failed latch; 16384 real admits spend
        // the cap exactly (failed still clear); 16383 admits observe.
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
        let (ready_row, spent, spent_wins) = publisher.publish(&["0", "16384"]);
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
            publisher.publish_stamped(&["0", "16383"], scene.closure_generation());
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
    fn object_journal_session_absence_birth_seals_on_quiet_history() {
        // C1: absence observation over a natively unmarked row issues;
        // the grant attests an absence birth over quiet history and
        // seals on fresh re-observation (fresh native bytes, a fresh
        // negative, a fresh appearance, a fresh router — never the
        // first pass's words). The witness is a committed
        // provider-free interval after the closure, followed by a
        // full mapping at advanced epochs — never disjoint positives.
        use crate::attach::observe_absence_birth;
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        let publisher = NativePublisher::build();
        let mut scene = Scene::new(image_default());
        let admitted = scene.fixture.admit();
        let proof = scene.adapter.attest_key(&admitted).expect("key attests");
        let (domain, _, _, _) = admitted.journal_binding();
        let full = scan_ranges_full();
        let mut router = scan_router(domain);
        let (row, control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
        let mut rows = NativeBirthRows { row, control };
        let closure = scene.closure_generation();
        let (token, evidence) = observe_absence_birth(
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
        .expect("unmarked row observes");
        assert_eq!(evidence.marker_word(), 0);
        assert_eq!(evidence.image(), (COOKIE, EXEC));
        assert_eq!(evidence.attach_generation(), closure);
        assert_eq!(
            evidence.custody(),
            scene.fixture.binding().pin().start_time().unwrap()
        );
        let grant = SessionBirthGrant::issue(
            &token,
            proof,
            BirthKind::AbsenceAppearance,
            1,
            scene.closure_generation(),
            evidence,
        );
        let create = function_id("C_CreateObject");
        let getinfo = function_id("C_GetInfo");
        let template = begin_bytes(1, 1, create, 0);
        let mut seen = ordinary_for(&template, 0);
        seen.slot = 99;
        seen.target_function = getinfo;
        scene.ingest_ordinary(seen);
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        let birth =
            BootstrapReceipt::attest(&scene.adapter, &grant).expect("quiet life attests absence");
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let (fresh_row, fresh_control, _) = publisher.publish(&["0", "0", "0", "0", "1"]);
        let mut fresh_rows = NativeBirthRows {
            row: fresh_row,
            control: fresh_control,
        };
        let mut fresh_router = scan_router(domain);
        let (_, fresh) = observe_absence_birth(
            &mut fresh_rows,
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
            &mut fresh_router,
            scene.fixture.binding(),
            scene.fixture.attachment(),
            &admitted,
        )
        .expect("fresh words re-observe");
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        scene
            .seal_explicit(&audit, &birth, frontier, fresh)
            .expect("observed absence seals");
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
        let grant = SessionBirthGrant::issue(
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
        // Quantum 2: a clean finalizer batch releases into Clean past
        // the acknowledged barrier, and genuinely new journal history
        // seals above the void fence. The void cleared admission
        // claims: re-attest for the new history. No manual
        // acknowledgement anywhere: the tick forwarded quantum 1's
        // report through production code.
        scene.attest();
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
    fn object_journal_joint_tick_forwards_void_report() {
        // C3: the production tick forwards the seal's void report to
        // the finalizer exactly once, and only on a voiding seal. A
        // recording fake finalizer takes scripted evidence and records
        // every acknowledgement.
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        struct RecordingFinalizer {
            next: H3DispositionEvidence,
            acked: Vec<u64>,
        }

        impl H3EvidenceSource for RecordingFinalizer {
            fn take_h3_disposition(&mut self) -> H3DispositionEvidence {
                std::mem::replace(&mut self.next, H3DispositionEvidence::genesis())
            }
        }

        impl H3FinalizerPort for RecordingFinalizer {
            fn acknowledge_h3_void(&mut self, voided_below: u64) {
                self.acked.push(voided_below);
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
        assert_eq!(
            finalizer.acked,
            vec![failure.h3_voided.expect("void report")]
        );
        // A clean seal acknowledges nothing. The clean evidence covers
        // the post-quantum watermark (fence + 2 records).
        let fence = scene.adapter.consumed_through;
        let mut finalizer = RecordingFinalizer {
            next: H3DispositionEvidence::scripted_clean(fence + 2),
            acked: Vec::new(),
        };
        scene.attest();
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
            fn acknowledge_h3_void(&mut self, _voided_below: u64) {
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
        let script = BusyScript::new(vec![next.to_vec(), next_end.to_vec()]);
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let collection =
            scene
                .adapter
                .collect_from_drain(&mut drain, &scene.descriptors, None, &fault, 0);
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
