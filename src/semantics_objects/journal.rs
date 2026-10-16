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
    AffectedScope, AttrObservation, AttributeList, CallKey, CallToken, CompleteInputPrefix,
    CompletedFact, FieldValue, FindResult, HandleInput, MechanismEvidence, ObjectDomain,
    ObjectEffect, ObjectEffects, ObjectGap, ObjectSemantics, OriginFact, QueryStatus, RefCut,
    ResultSlot, SessionHandle,
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
    bounded_uppers: Vec<u64>,
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
    tainted_images: BTreeSet<(u64, u64)>,
    sightings: BTreeMap<(u64, u64), ImageSighting>,
    last_audit_failure: Option<u64>,
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
            sightings: BTreeMap::new(),
            last_audit_failure: None,
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
    /// taints it and refuses the record.
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
        if self.tainted_images.contains(&image) {
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
        if self.tainted_images.contains(&entry.image) {
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
        if self.tainted_images.contains(&entry.image) {
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

    /// Taint one image permanently: attestation for it is refused, its keys'
    /// seals are refused, and its staged entries are disposed without proof.
    /// Retained history stays; only future proof for this image ends.
    fn taint_image(&mut self, image: (u64, u64)) {
        self.tainted_images.insert(image);
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

/// Whether a return value is still pending (provider-deferred): never a
/// completed synchronous return, never a terminal witness.
fn is_pending_rv(rv: u64) -> bool {
    pkcs11_types::CkRv(rv) == pkcs11_types::CkRv::PENDING
}

/// Whether one ordinary CALL record corroborates one open BEGIN: same
/// seven-word call identity, strictly after the BEGIN, returned at or after
/// entry, with a completed (non-pending) return value.
fn ordinary_matches_begin(
    event: &p11scope_ebpf_common::Event,
    ordinal: u64,
    begin: &ValidatedJournalBegin,
    begin_ordinal: u64,
) -> bool {
    ordinal > begin_ordinal
        && event.ts_ns >= begin.entry_ns()
        && event.slot == begin.slot()
        && event.session == begin.session_word()
        && event.mechanism == begin.entry_mechanism()
        && event.slot_id == begin.slot_id()
        && event.user_type == begin.user_type()
        && event.capture == begin.capture()
        && event.flags == begin.call_flags()
}

/// Whether one ordinary CALL record corroborates one refused BEGIN.
fn ordinary_matches_refused(
    event: &p11scope_ebpf_common::Event,
    ordinal: u64,
    refused: &RefusedBegin,
) -> bool {
    ordinal > refused.cut
        && event.ts_ns >= refused.entry_ns
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

/// H3's post-finalizer disposition for one seal frontier, derived from the
/// finalizer's own staged batch state: either every collected outcome
/// through a cut is disposed with no staged loss, or a loss barrier stands
/// in scope. Private fields: only finalizer-typed evidence or the test
/// script builds one.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Activation-gated: the finalizer derives this per batch.
pub(crate) enum H3DispositionEvidence {
    Clean { disposed_through: u64 },
    StagedLoss { barrier: u64 },
}

#[allow(dead_code)] // Activation-gated: called from `finalize_batch`.
impl H3DispositionEvidence {
    /// Production derivation from the finalizer's staged batch: any staged
    /// negative in scope is a loss barrier (a refused collection disposes
    /// nothing, so it barriers at zero); otherwise disposition extends
    /// through the greatest staged token. Activation-gated: called from
    /// `finalize_batch` once the producer wires; until then the audit
    /// rules below are exercised with scripted evidence.
    pub(crate) fn from_finalizer_batch(
        negatives: &[crate::inventory_semantics::LaneNegative],
        staged: &[crate::discovery::caller_registry::instance_input::CallEvidence],
        previous: &Self,
    ) -> Self {
        use crate::inventory_semantics::LaneNegative;
        let mut barrier: Option<u64> = None;
        for negative in negatives {
            let cut = match negative {
                LaneNegative::CutBarrier { ordinal } => *ordinal,
                LaneNegative::CollectionRefused { .. } => 0,
            };
            barrier = Some(barrier.map_or(cut, |at: u64| at.min(cut)));
        }
        if let Some(barrier) = barrier {
            return Self::StagedLoss { barrier };
        }
        let previous_through = match previous {
            Self::Clean { disposed_through } => *disposed_through,
            Self::StagedLoss { .. } => 0,
        };
        let mut through = previous_through;
        for evidence in staged {
            through = through.max(evidence.token());
        }
        Self::Clean {
            disposed_through: through,
        }
    }

    /// Genesis evidence: nothing disposed, nothing lost.
    pub(crate) fn genesis() -> Self {
        Self::Clean {
            disposed_through: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted_clean(disposed_through: u64) -> Self {
        Self::Clean { disposed_through }
    }

    #[cfg(test)]
    pub(crate) fn scripted_loss(barrier: u64) -> Self {
        Self::StagedLoss { barrier }
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
    h3: H3DispositionEvidence,
    closure_generation: u64,
}

/// One collection's audit evidence: per-form counts, the drain's
/// malformed delta and the checked-fault pair bracketing the tick.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JournalCollection {
    pub(crate) ingested: u64,
    pub(crate) ordinary: u64,
    pub(crate) malformed_delta: u64,
    pub(crate) fault_before: u64,
    pub(crate) fault_after: u64,
    pub(crate) fault_error: Option<FaultReadError>,
}

impl JournalAuditReceipt {
    /// Production audit from one collection plus H3's disposition and the
    /// live closure generation. The seal's check rules decide; this only
    /// binds the evidence.
    pub(crate) fn collect(
        collection: &JournalCollection,
        h3: H3DispositionEvidence,
        closure_generation: u64,
    ) -> Self {
        Self {
            fault_before: collection.fault_before,
            fault_after: collection.fault_after,
            fault_error: collection.fault_error,
            malformed_delta: collection.malformed_delta,
            h3,
            closure_generation,
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
        Self {
            fault_before,
            fault_after,
            fault_error,
            malformed_delta,
            h3,
            closure_generation,
        }
    }

    /// The audit rules: an unreadable or changed fault, any malformed
    /// record, any H3 loss in scope, undisposed H3 history below the
    /// frontier, or a stale closure each refuse the seal. The caller
    /// voids staged proof on fault/malformed/loss; pending and stale
    /// closures refuse without voiding.
    fn check(&self, frontier: u64, current_closure: u64) -> Result<(), JournalGap> {
        match self.fault_error {
            Some(FaultReadError::Unreadable) => return Err(JournalGap::FaultUnreadable),
            Some(FaultReadError::Saturated) => return Err(JournalGap::FaultSaturated),
            None => {}
        }
        if self.fault_before != self.fault_after {
            return Err(JournalGap::FaultChanged);
        }
        if self.malformed_delta != 0 {
            return Err(JournalGap::Malformed);
        }
        match &self.h3 {
            H3DispositionEvidence::StagedLoss { .. } => return Err(JournalGap::H3Loss),
            H3DispositionEvidence::Clean { disposed_through } => {
                if *disposed_through < frontier {
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
/// exec-marker publication (the image's entire observed life is above the
/// cut) or a complete absence-then-appearance proof (the image lived
/// observably at or below the cut with zero unfenced affecting evidence
/// and a clean audit chain unbroken since the void fence, then its first
/// unfenced affecting record appeared). The kind is stream-determined by
/// [`BootstrapReceipt::attest`] and re-verified by the seal; tests script
/// the receipt to pin the seal's structural rules.
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
}

/// One domain's bootstrap: its sealed proof, the verified birth kind and
/// cut, and the closure generation it was attested under. Production
/// attestation verifies genuine birth plus closure; the seal re-verifies
/// both, so a chain break between attestation and seal still refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BootstrapReceipt {
    proof: JournalDomainProof,
    birth: BirthKind,
    birth_cut: u64,
    closure_generation: u64,
}

impl BootstrapReceipt {
    /// Production birth attestation: verify the claimed kind against the
    /// adapter's retained sightings and audit chain, under the live
    /// closure generation. The seal re-verifies before converting.
    pub(crate) fn attest(
        adapter: &JournalAdapter,
        proof: JournalDomainProof,
        birth: BirthKind,
        birth_cut: u64,
        closure_generation: u64,
    ) -> Result<Self, BirthRefusal> {
        if closure_generation != adapter.closure_generation {
            return Err(BirthRefusal::ClosureStale);
        }
        let fenced_through = adapter
            .keys
            .get(&proof.key)
            .map(|state| state.void_fence)
            .unwrap_or(0);
        adapter.verify_birth(&proof, birth, birth_cut, fenced_through)?;
        Ok(Self {
            proof,
            birth,
            birth_cut,
            closure_generation,
        })
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        proof: JournalDomainProof,
        birth: BirthKind,
        birth_cut: u64,
        closure_generation: u64,
    ) -> Self {
        Self {
            proof,
            birth,
            birth_cut,
            closure_generation,
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
    bootstrap: u64,
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

    /// The model's bootstrap fence derived for this seal: strictly above
    /// the birth, the last sealed frontier, the void fence and every
    /// recorded or pending loss bound, capped at the earliest held begin
    /// so its application still qualifies. When held calls keep the fence
    /// below the model's floors the model keeps a benign stale floor and
    /// held calls still apply; the loss bounds live in the model's floor
    /// either way. The model input, not the birth.
    pub(crate) fn bootstrap_cut(&self) -> u64 {
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
}

/// Finite attestation refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttestationRefusal {
    ImageTainted,
    KeysExhausted,
    Stopped,
}

impl JournalAdapter {
    /// Verify one birth claim against retained sightings and the audit
    /// chain. Shared by production attestation and the seal's
    /// re-verification, so a chain break between the two still refuses.
    /// `fenced_through` is the key's void fence: absence requires zero
    /// UNFENCED affecting evidence at or below the cut and a chain
    /// unbroken since the fence. Exec-marker novelty stays strict: a
    /// fenced past is still a past.
    fn verify_birth(
        &self,
        proof: &JournalDomainProof,
        birth: BirthKind,
        birth_cut: u64,
        fenced_through: u64,
    ) -> Result<(), BirthRefusal> {
        let image = (proof.key.cookie, proof.key.exec);
        if self.tainted_images.contains(&image) {
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

    /// Advance the closure generation after an attachment change alters
    /// the retained endpoint set. Monotonic: a regression is refused and
    /// the generation stays. Existing receipts and audits under older
    /// generations refuse as stale; only fresh attestation under the live
    /// generation seals. Production caller: the attach path that changes
    /// the retained set (wired when the producer activates); until then
    /// the generation stays zero and the seal's stale rule is exercised
    /// through this advancer.
    pub(crate) fn advance_closure_generation(&mut self, generation: u64) -> bool {
        if generation < self.closure_generation {
            return false;
        }
        self.closure_generation = generation;
        true
    }

    /// Bind one H3-admitted call's incarnation to a journal key: the exact
    /// native domain, caller, image and router, plus the adapter-tracked
    /// era. Re-attestation after a fault-void returns the live key; a
    /// tainted image or a full key table refuses. Birth and closure are
    /// verified on top of this binding by [`BootstrapReceipt::attest`].
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
        if self.tainted_images.contains(&(key.cookie, key.exec)) {
            return Err(AttestationRefusal::ImageTainted);
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

    /// The plan's seal entry: audit, verify the birth, derive the
    /// model's fence, then convert staged history at or below the
    /// frontier, then settle. Validation precedes every model mutation; a
    /// model surprise fails closed with the key tainted. Staged inputs
    /// below a refused-but-recoverable seal are kept for a later seal;
    /// fault, malformed and H3 loss fence the void explicitly and drop
    /// staged proof.
    pub(crate) fn seal(
        &mut self,
        model: &mut ObjectSemantics,
        audit: &JournalAuditReceipt,
        bootstrap: &BootstrapReceipt,
        frontier: ConsumptionOrdinal,
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
        if let Err(gap) = audit.check(frontier, self.closure_generation) {
            // Any audit failure breaks absence-appearance chains: the clean
            // coverage the witness requires is gone from this ordinal on.
            // Voids fence the loss explicitly before dropping staged
            // truth, so later proof resumes above a fenced interval
            // instead of silently skipping it; the fencing effects are
            // reported with the refusal.
            self.last_audit_failure = Some(self.consumed_through);
            let mut effects = ObjectEffects::default();
            match gap {
                JournalGap::FaultSaturated => {
                    self.stopped = true;
                }
                JournalGap::FaultChanged
                | JournalGap::FaultUnreadable
                | JournalGap::Malformed
                | JournalGap::H3Loss => {
                    effects = self.fence_void(model, self.consumed_through);
                    self.void_staged();
                }
                JournalGap::H3Pending | JournalGap::ClosureStale => {}
                _ => {}
            }
            return Err(SealFailure { gap, effects });
        }
        let key = bootstrap.proof.key;
        let Some(state) = self.keys.get(&key) else {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        };
        if state.refused || state.tainted {
            return Err(self.failure(JournalGap::DomainTainted));
        }
        if self.tainted_images.contains(&(key.cookie, key.exec)) {
            return Err(self.failure(JournalGap::ImageTainted));
        }
        if state.era_ended {
            return Err(self.failure(JournalGap::DomainEnded));
        }
        // Era discipline: the proof carries the live era, or the next era
        // once the live one ended (handled below after the ended check can
        // observe it). Anything else is a mismatched bootstrap.
        if bootstrap.proof.era != state.era {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        // The receipt's own generation must be live: a birth verified
        // under a replaced endpoint set proves nothing under this one.
        if bootstrap.closure_generation != self.closure_generation {
            return Err(self.failure(JournalGap::ClosureStale));
        }
        // Re-verify the birth against current retained truth: a chain
        // break between attestation and seal still refuses.
        if let Err(refusal) = self.verify_birth(
            &bootstrap.proof,
            bootstrap.birth,
            bootstrap.birth_cut,
            state.void_fence,
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
        if let Some(pinned) = state.bootstraps.get(&bootstrap.proof.era)
            && *pinned != bootstrap.birth_cut
        {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        // The birth covers all retained staged history for the image:
        // conversion proves staged begins, so a cut at or above any of
        // them would certify history the birth excludes.
        let image = (key.cookie, key.exec);
        if !self.birth_covers_staged(image, bootstrap.birth_cut) {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        if frontier < state.sealed_through {
            return Err(self.failure(JournalGap::FrontierRegression));
        }
        if bootstrap.birth_cut > frontier {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        // Resumption below the void fence refuses: a fresh birth names
        // the fence it resumes at. At the fence is sound (the fenced
        // interval is explicitly lost, and conversion covers strictly
        // above the cut).
        if bootstrap.birth_cut < state.void_fence {
            return Err(self.failure(JournalGap::BootstrapMismatch));
        }
        // The model's bootstrap fence is derived, not supplied: strictly
        // above the birth, the last sealed frontier, the void fence and
        // every recorded or pending loss bound — but never above a held
        // begin, whose application the floor would otherwise disqualify.
        // The model refuses anything lower (a benign stale floor under
        // which held calls still apply); only a fence past the frontier
        // waits for more history. Staged inputs are kept for a later seal.
        let mut fence = bootstrap
            .birth_cut
            .max(state.sealed_through.saturating_add(1));
        fence = fence.max(state.void_fence.saturating_add(1));
        for upper in &state.bounded_uppers {
            fence = fence.max(upper.saturating_add(1));
        }
        // Pending loss bounds: staged bounded abandonments and refused
        // begins with their corroborating returns in the frontier. Calls
        // this seal removes never apply, so they leave the held cap alone.
        for entry in self.open.values() {
            if entry.image == image
                && entry.begin_ordinal <= frontier
                && let Some(staged) = entry.abandon
                && staged.ordinal <= frontier
                && staged.abandon.reason() == JOURNAL_REASON_SYNC_RETURN_RESULT_LOST
                && let Some(at) = entry.corroborated_return
                && at <= frontier
            {
                fence = fence.max(at.saturating_add(1));
            }
        }
        for refused in &self.refused {
            if refused.image == image
                && refused.cut <= frontier
                && let Some(at) = refused.corroborated_return
                && at <= frontier
            {
                fence = fence.max(at.saturating_add(1));
            }
        }
        // Held cap: the earliest staged begin this seal keeps. Bounded
        // losses removed below contribute their bound instead of their
        // begin; everything else staged may still apply.
        let held = self
            .open
            .values()
            .filter(|entry| {
                entry.image == image
                    && !(entry.abandon.is_some_and(|staged| {
                        staged.ordinal <= frontier
                            && staged.abandon.reason() == JOURNAL_REASON_SYNC_RETURN_RESULT_LOST
                            && entry.corroborated_return.is_some_and(|at| at <= frontier)
                    }))
            })
            .map(|entry| entry.begin_ordinal)
            .min();
        if let Some(held) = held {
            fence = fence.min(held);
        }
        if fence > frontier {
            return Err(self.failure(JournalGap::BoundNotReady));
        }
        self.seal_validated(model, key, bootstrap, frontier, fence)
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

    /// Whether a birth cut covers all retained staged history for one
    /// image: every staged begin and refused cut sits strictly above it.
    /// Staged history for other images is irrelevant to this birth.
    fn birth_covers_staged(&self, image: (u64, u64), birth_cut: u64) -> bool {
        self.open
            .values()
            .all(|entry| entry.image != image || entry.begin_ordinal > birth_cut)
            && self
                .refused
                .iter()
                .all(|refused| refused.image != image || refused.cut > birth_cut)
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
        for state in self.keys.values_mut() {
            state.bootstraps.clear();
        }
    }

    fn failure(&self, gap: JournalGap) -> SealFailure {
        SealFailure {
            gap,
            effects: ObjectEffects::default(),
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
        model_fence: u64,
    ) -> Result<SealSuccess, SealFailure> {
        let image = (key.cookie, key.exec);
        // Unbounded abandonment staged at or below the frontier refuses
        // this key permanently: invalidate its proof (reported), mark it,
        // dispose its staged entries, and refuse the seal.
        let unbounded = self.open.values().any(|entry| {
            entry.image == image
                && entry.begin_ordinal <= frontier
                && entry.abandon.is_some_and(|staged| {
                    staged.ordinal <= frontier
                        && abandon_disposition(staged.abandon.reason())
                            == Some(AbandonDisposition::UnboundedInvalidation)
                })
        });
        if unbounded {
            let domain = ObjectDomain::sealed(&bootstrap.proof);
            let effects = model.invalidate(AffectedScope::Domain(domain), ObjectGap::Loss);
            self.keys.get_mut(&key).expect("sealed key").refused = true;
            self.open.retain(|_, entry| entry.image != image);
            self.refused.retain(|refused| refused.image != image);
            return Err(SealFailure {
                gap: JournalGap::DomainTainted,
                effects,
            });
        }
        // Bounded abandonment needs its corroborating return within the
        // frontier; otherwise the bound is not ready and the seal waits.
        let unready = self.open.values().any(|entry| {
            entry.image == image
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
        // Every refused begin at or below the frontier needs its bound
        // within the frontier; otherwise the seal waits.
        let refused_unready = self.refused.iter().any(|refused| {
            refused.image == image
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
        model_fence: u64,
    ) -> Result<SealSuccess, SealFailure> {
        let image = (key.cookie, key.exec);
        let domain = ObjectDomain::sealed(&bootstrap.proof);
        let mut effects = ObjectEffects::default();
        if model.register_domain(domain).is_err() {
            self.keys.get_mut(&key).expect("sealed key").tainted = true;
            return Err(SealFailure {
                gap: JournalGap::ModelRefused,
                effects,
            });
        }
        self.keys
            .get_mut(&key)
            .expect("sealed key")
            .model_registered = true;
        // Refused begins first: the model records each cut exactly like
        // its own capacity refusal, then a single lost-outcome bound
        // clears them once every refused begin is corroborated.
        let mut refused_cuts: Vec<u64> = self
            .refused
            .iter()
            .filter(|refused| refused.image == image && refused.cut <= frontier)
            .map(|refused| refused.cut)
            .collect();
        refused_cuts.sort_unstable();
        for cut in &refused_cuts {
            model.note_refused_begin(domain, RefCut::sealed(ConsumptionOrdinal(*cut)));
        }
        if !refused_cuts.is_empty() {
            let upper = self
                .refused
                .iter()
                .filter(|refused| refused.image == image && refused.cut <= frontier)
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
                    // its own copy so the bootstrap rule stays sufficient
                    // on its own evidence.
                    self.keys
                        .get_mut(&key)
                        .expect("sealed key")
                        .bounded_uppers
                        .push(upper);
                }
                None => {
                    self.keys.get_mut(&key).expect("sealed key").tainted = true;
                    return Err(SealFailure {
                        gap: JournalGap::ModelRefused,
                        effects,
                    });
                }
            }
            self.refused
                .retain(|refused| !(refused.image == image && refused.cut <= frontier));
        }
        // Begins in cut order, then their terminals.
        let mut begins: Vec<(JournalNativeKey, u64)> = self
            .open
            .iter()
            .filter(|(_, entry)| {
                entry.image == image
                    && entry.begin_ordinal <= frontier
                    && entry.converted_ticket.is_none()
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
                });
            };
            let entry = *self.open.get(&native).expect("staged begin");
            let origin = origin_of(domain, entry.begin_ordinal, ticket, &entry.begin);
            let function = entry.function;
            let call_key = CallKey::sealed(ticket);
            match model.begin(origin) {
                Ok(token) => {
                    let entry = self.open.get_mut(&native).expect("staged begin");
                    entry.converted_ticket = Some(token);
                    entry.call_key = Some(call_key);
                    settled.push(SealedCall {
                        ticket: token,
                        key: call_key,
                        function,
                        begin_cut: entry.begin_ordinal,
                        end_cut: None,
                        abandoned: false,
                    });
                }
                Err(_) => {
                    self.keys.get_mut(&key).expect("sealed key").tainted = true;
                    return Err(SealFailure {
                        gap: JournalGap::ModelRefused,
                        effects,
                    });
                }
            }
        }
        // Terminals for converted begins: ends complete, bounded
        // abandonments dispose through the lost-outcome bound.
        let mut terminals: Vec<(JournalNativeKey, u64)> = Vec::new();
        for (native, entry) in &self.open {
            if entry.image != image || entry.converted_ticket.is_none() {
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
                    });
                };
                let lost = model.outcome_lost(super::LostOutcome::Ticket(
                    token,
                    RefCut::sealed(ConsumptionOrdinal(at)),
                ));
                effects.effects.extend(lost.effects);
                self.keys
                    .get_mut(&key)
                    .expect("sealed key")
                    .bounded_uppers
                    .push(at);
                if let Some(summary) = settled.iter_mut().find(|summary| summary.ticket == token) {
                    summary.abandoned = true;
                }
            }
        }
        // Settle the covered history under this bootstrap. The open
        // list is cumulative over retained staged entries, mirroring the
        // model's rule exactly: converted calls with no terminal at or
        // below the frontier. A per-seal list would omit calls held
        // across seals and contradict the settlement.
        let open: Vec<CallKey> = self
            .open
            .values()
            .filter(|entry| {
                entry.image == image
                    && entry.converted_ticket.is_some()
                    && entry.end.is_none_or(|staged| staged.ordinal > frontier)
                    && entry.abandon.is_none_or(|staged| staged.ordinal > frontier)
            })
            .map(|entry| entry.call_key.expect("converted open has a key"))
            .collect();
        let prefix = SealedObjectPrefix {
            domain,
            frontier,
            birth_cut: bootstrap.birth_cut,
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
        effects.effects.extend(applied.effects);
        if ended {
            self.keys.get_mut(&key).expect("sealed key").era_ended = true;
            return Err(SealFailure {
                gap: JournalGap::DomainEnded,
                effects,
            });
        }
        self.keys.get_mut(&key).expect("sealed key").sealed_through = frontier;
        self.keys
            .get_mut(&key)
            .expect("sealed key")
            .bootstraps
            .insert(bootstrap.proof.era, bootstrap.birth_cut);
        self.prune_settled(key, frontier);
        Ok(SealSuccess { prefix, effects })
    }

    /// Drop staged entries the settlement applied: completed ends at or
    /// below the watermark (the model's own rule, mirrored on identical
    /// staged data), bounded abandonments the lost-outcome bound removed,
    /// and converted begins the model pruned. Staged inputs above the
    /// watermark stay for the next seal.
    fn prune_settled(&mut self, key: JournalDomainKey, frontier: u64) {
        let image = (key.cookie, key.exec);
        let earliest_open = self
            .open
            .values()
            .filter(|entry| {
                entry.image == image
                    && entry.converted_ticket.is_some()
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
            if entry.image != image {
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
    /// delta. Collection stages wire truth only; the seal audits this
    /// evidence before any model input.
    ///
    /// DISCARD observability: the patched Aya reader consumes
    /// kernel-discarded reservations internally (see the ring-reader
    /// patch: both `next` and `next_before` skip discarded records
    /// without surfacing them), so per-reservation discard counts are
    /// unavailable by construction. The selected mechanism is the fault
    /// invariant instead: every discarded journal reservation raises the
    /// checked fault before discard (native contract, activation-gated),
    /// and every candidate seal audits the fault pair after consumption.
    /// A changed fault therefore refuses the seal whether the cause was
    /// a discard or any other native fault.
    pub(crate) fn collect_from_drain<S: crate::events::RecordSource>(
        &mut self,
        drain: &mut crate::events::EventDrain<S>,
        descriptors: &[p11scope_ebpf_common::object_wire::ObjectDescriptorWire;
             MAX_DESCRIPTORS as usize],
        quantum: Option<usize>,
        fault: &impl FaultEpoch,
    ) -> JournalCollection {
        let fault_before = match fault.fault_epoch() {
            Ok(epoch) => epoch,
            Err(error) => {
                return JournalCollection {
                    ingested: 0,
                    ordinary: 0,
                    malformed_delta: 0,
                    fault_before: 0,
                    fault_after: 0,
                    fault_error: Some(error),
                };
            }
        };
        let malformed_before = drain.malformed();
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
        JournalCollection {
            ingested,
            ordinary,
            malformed_delta: drain.malformed().saturating_sub(malformed_before),
            fault_before,
            fault_after,
            fault_error,
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
        let live: Vec<JournalDomainKey> = self.keys.keys().copied().collect();
        for key in live {
            let tracked = self.open.values().any(|entry| {
                entry.image == (key.cookie, key.exec) && entry.converted_ticket.is_some()
            }) || self
                .refused
                .iter()
                .any(|refused| refused.image == (key.cookie, key.exec));
            if !tracked {
                continue;
            }
            let era = self.keys[&key].era;
            let domain = ObjectDomain::sealed(&JournalDomainProof { key, era });
            let applied = model.invalidate(AffectedScope::Domain(domain), ObjectGap::Loss);
            effects.effects.extend(applied.effects);
            self.keys.get_mut(&key).expect("stopped key").refused = true;
        }
        self.open.clear();
        self.refused.clear();
        effects
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::instance_input::{
        AdmittedInstanceCall, CallEvidence, CallStanding, InstanceReason, admit_call_from_evidence,
    };
    use crate::discovery::caller_registry::{CallerId, ModuleKey};
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
    struct AttestationFixture {
        _dir: tempfile::TempDir,
        subset: AttestedSubset,
        binding: crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
        domain: NativeDomainId,
        image: ImageIdentity,
        router: InstanceId,
        slot: u32,
        endpoint: Endpoint,
        next_token: u64,
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
                .find(|(a, b)| b - a > 2)
                .unwrap()
                .0;
            let functions =
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
                            let resolution = match field.name {
                                "C_CreateObject" => Resolution::Resolved {
                                    object: 0,
                                    file_offset: start,
                                },
                                _ => Resolution::NullPointer,
                            };
                            FunctionRecord {
                                name: field.name.into(),
                                resolution,
                            }
                        })
                        .collect(),
                    _ => panic!("2.40 is a full standard table"),
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
                interface_list: Acquisition::Absent,
                surfaces: vec![SurfaceRecord {
                    source: SurfaceSource::LegacyFunctionList,
                    acquisition: Acquisition::Ok,
                    version: Some(Version {
                        major: 2,
                        minor: 40,
                    }),
                    walk: WalkOutcome::Full,
                    functions,
                }],
                vendor_interfaces: Vec::new(),
                alias_groups: Vec::new(),
                selection_evidence: Default::default(),
            };
            assert!(crate::manifest_input::validate_structure(&manifest).is_empty());
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
                    &[operator],
                );
            let subset = prepared.subset.expect("nonempty validated operator subset");
            let slot = subset
                .plan()
                .slots
                .iter()
                .find(|slot| slot.names.len() == 1 && slot.names[0] == "C_CreateObject")
                .expect("create slot");
            let endpoint = Endpoint {
                object: slot.object,
                file_slot: 0,
                offset: slot.file_offset,
            };
            let slot = slot.index;
            let pin = pins.pinned().next().unwrap();
            let module = ModuleKey::physical(
                pin.key.device.major,
                pin.key.device.minor,
                pin.key.inode,
                Some(pin.sha256.to_owned()),
                pin.path,
            );
            let domain = NativeDomainId::mint();
            let pid = std::process::id();
            let caller = CallerId(1);
            let binding =
                crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding::scripted(
                    caller,
                    module,
                    domain,
                    image,
                    std::sync::Arc::new(crate::process::PidPin::test_proc_only(pid)),
                );
            let router = Self::route(domain, image);
            Self {
                _dir: dir,
                subset,
                binding,
                domain,
                image,
                router,
                slot,
                endpoint,
                next_token: 0,
            }
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

        /// One real routed evidence: scripted routed call through the
        /// production move-only conversion, with its real H0 token.
        fn evidence(&mut self) -> CallEvidence {
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
                            slot: self.slot,
                            session: SESSION,
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
                Some(self.endpoint),
                Some(token),
            );
            CallEvidence::from_routed(routed).expect("joined call converts to evidence")
        }

        /// One real admission: routed evidence through the real
        /// descriptor/binding proofs, historical standing (no coverage
        /// needed for key binding).
        fn admit(&mut self) -> AdmittedInstanceCall {
            let evidence = self.evidence();
            admit_call_from_evidence(
                evidence,
                &self.binding,
                &self.subset,
                CallStanding::Historical(InstanceReason::SemanticLoss),
                None,
            )
            .expect("scripted evidence admits")
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
    }

    impl Scene {
        fn new(image: ImageIdentity) -> Self {
            Self::new_with_limits(image, JournalLimits::policy())
        }

        fn new_with_limits(image: ImageIdentity, limits: JournalLimits) -> Self {
            let descriptors = publish_object_descriptors();
            assert!(verify_object_descriptors(&descriptors));
            Self {
                adapter: JournalAdapter::new(limits),
                model: ObjectSemantics::new(),
                descriptors,
                fixture: AttestationFixture::new(image),
            }
        }

        fn attest(&mut self) -> JournalDomainProof {
            let admitted = self.fixture.admit();
            self.adapter.attest_key(&admitted).expect("key attests")
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
                0,
            )
        }

        fn seal(&mut self, bootstrap: &BootstrapReceipt) -> Result<SealSuccess, SealFailure> {
            let frontier = self.adapter.consumed_frontier();
            let audit = self.audit();
            self.adapter
                .seal(&mut self.model, &audit, bootstrap, frontier)
        }

        fn bootstrap(&self, proof: JournalDomainProof, birth_cut: u64) -> BootstrapReceipt {
            BootstrapReceipt::scripted(proof, BirthKind::ExecMarker, birth_cut, 0)
        }

        /// One production collection over scripted ring bytes: the real
        /// dispatch poll, real decode, real malformed accounting and the
        /// scripted fault cell.
        fn collect_records(
            &mut self,
            records: Vec<Vec<u8>>,
            fault: &impl FaultEpoch,
        ) -> JournalCollection {
            let bound = records.len();
            let mut drain = crate::events::EventDrain::over_test_domain(
                crate::events::ScriptedRecords::records(records, bound),
                7,
            );
            self.adapter
                .collect_from_drain(&mut drain, &self.descriptors, Some(bound), fault)
        }

        /// One seal from a real collection: H3 disposition covers the
        /// consumed frontier, closure generation zero.
        fn seal_collected(
            &mut self,
            bootstrap: &BootstrapReceipt,
            collection: &JournalCollection,
        ) -> Result<SealSuccess, SealFailure> {
            let h3 = H3DispositionEvidence::scripted_clean(self.adapter.consumed_through);
            let audit = JournalAuditReceipt::collect(collection, h3, 0);
            let frontier = self.adapter.consumed_frontier();
            self.adapter
                .seal(&mut self.model, &audit, bootstrap, frontier)
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
    }

    impl BusyScript {
        fn new(records: Vec<Vec<u8>>) -> Self {
            Self {
                queue: records.into(),
                taken: 0,
                busy_after: None,
                busy_done: false,
                pending_before: 0,
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
            Some(item)
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
            let proof = scene.attest();
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
        let proof = scene.attest();
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
            .adapter
            .seal(&mut scene.model, &audit, &rebootstrap, frontier)
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
            .adapter
            .seal(&mut scene.model, &audit, &bootstrap, frontier)
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
            0,
        );
        let frontier = scene.adapter.consumed_frontier();
        let failure = scene
            .adapter
            .seal(&mut scene.model, &audit, &bootstrap_b, frontier)
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
            let rebootstrap =
                BootstrapReceipt::scripted(reproof, BirthKind::AbsenceAppearance, cut, 0);
            let frontier = scene.adapter.consumed_frontier();
            let audit = scene.audit();
            let outcome = scene
                .adapter
                .seal(&mut scene.model, &audit, &rebootstrap, frontier);
            assert_eq!(outcome.expect_err("fence gates resumption").gap, gap);
        }
        // New history above the fence seals under the fresh birth.
        let create = function_id("C_CreateObject");
        let healthy = begin_bytes_image(3, 1, create, 0, (COOKIE + 1, EXEC));
        scene.ingest(&healthy);
        scene.ingest(&end_bytes(&healthy, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 70));
        let rebootstrap =
            BootstrapReceipt::scripted(reproof, BirthKind::AbsenceAppearance, fence, 0);
        let success = scene
            .seal(&rebootstrap)
            .expect("fresh attestation resumes above the fence");
        assert_eq!(success.prefix.birth_cut(), fence);
        assert_eq!(success.prefix.bootstrap_cut(), fence + 1);
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
        let proof = scene.attest();
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
        assert_eq!(success.prefix.bootstrap_cut(), 6);
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
        assert_eq!(success.prefix.bootstrap_cut(), 8);
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
        assert_eq!(success.prefix.bootstrap_cut(), 5);
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
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        let end = end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50);
        let mut script = BusyScript::new(vec![begin.to_vec(), end.to_vec()]);
        script.busy_after = Some(1);
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let fault = ScriptedFaultCell::steady(7);
        let first = scene
            .adapter
            .collect_from_drain(&mut drain, &scene.descriptors, None, &fault);
        assert_eq!((first.ingested, first.ordinary), (1, 0));
        assert_eq!(scene.adapter.consumed_through, 1);
        let bootstrap = scene.bootstrap(proof, 0);
        let held = scene
            .seal_collected(&bootstrap, &first)
            .expect("prefix frontier seals");
        assert_eq!(held.prefix.open_keys().len(), 1);
        let second = scene
            .adapter
            .collect_from_drain(&mut drain, &scene.descriptors, None, &fault);
        assert_eq!((second.ingested, second.ordinary), (1, 0));
        let bootstrap = scene.bootstrap(proof, 0);
        let success = scene
            .seal_collected(&bootstrap, &second)
            .expect("completed frontier seals");
        assert!(has_effect(&success.effects, "created"));

        // A stall before the first record consumes nothing at all.
        let mut scene = Scene::new(image_default());
        let mut script = BusyScript::new(vec![begin.to_vec()]);
        script.busy_after = Some(0);
        let mut drain = crate::events::EventDrain::over_test_domain(script, 7);
        let first = scene
            .adapter
            .collect_from_drain(&mut drain, &scene.descriptors, None, &fault);
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
            let proof = scene.attest();
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
                    .adapter
                    .seal(&mut scene.model, &audit, &bootstrap, frontier)
                    .expect("prompt first seal passes");
            }
            let frontier = scene.adapter.consumed_frontier();
            let audit = scene.audit();
            scene
                .adapter
                .seal(&mut scene.model, &audit, &bootstrap, frontier)
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
        let proof = scene.attest();
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
            .adapter
            .seal(&mut scene.model, &audit, &bootstrap, held)
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
        let short = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(frontier.cut() - 1),
            0,
        );
        let failure = scene
            .adapter
            .seal(&mut scene.model, &short, &bootstrap, frontier)
            .expect_err("undisposed H3 refuses");
        assert_eq!(failure.gap, JournalGap::H3Pending);
        let audit = scene.audit();
        let success = scene
            .adapter
            .seal(&mut scene.model, &audit, &bootstrap, frontier)
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
        let loss = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_loss(2),
            0,
        );
        let failure = scene
            .adapter
            .seal(&mut scene.model, &loss, &bootstrap, frontier)
            .expect_err("H3 loss refuses");
        assert_eq!(failure.gap, JournalGap::H3Loss);
        // Vacuous resumption at the fence waits for new history.
        let fence = scene.adapter.consumed_through;
        assert_eq!(fence, 2);
        let resume = BootstrapReceipt::scripted(proof, BirthKind::AbsenceAppearance, fence, 0);
        let audit = scene.audit();
        let waiting = scene
            .adapter
            .seal(&mut scene.model, &audit, &resume, frontier)
            .expect_err("empty resumption waits");
        assert_eq!(waiting.gap, JournalGap::BoundNotReady);
        // New history above the fence seals under the fresh birth.
        let again = begin_bytes(1, 2, create, 0);
        scene.ingest(&again);
        scene.ingest(&end_bytes(&again, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let success = scene
            .seal(&resume)
            .expect("resumption seals above the fence");
        assert_eq!(success.prefix.birth_cut(), fence);
        assert_eq!(success.prefix.bootstrap_cut(), fence + 1);
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
        let resume = BootstrapReceipt::scripted(proof, BirthKind::AbsenceAppearance, fence, 0);
        let clean = JournalCollection {
            malformed_delta: 0,
            ..collection
        };
        let waiting = scene
            .seal_collected(&resume, &clean)
            .expect_err("empty resumption waits");
        assert_eq!(waiting.gap, JournalGap::BoundNotReady);
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
        assert_eq!(success.prefix.bootstrap_cut(), fence + 1);
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
        let begin = begin_bytes(1, 1, create, 0);
        let fault = ScriptedFaultCell::failing();
        let collection = scene.collect_records(vec![begin.to_vec()], &fault);
        assert_eq!((collection.ingested, collection.ordinary), (0, 0));
        let proof = scene.attest();
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
        let proof = scene.attest();
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
        // The held opens cap the derived fence at 1 so their later
        // application still qualifies; the 1,026 bound lives in the
        // model's floor, and the staged refusal is disposed.
        assert_eq!(success.prefix.birth_cut(), 0);
        assert_eq!(success.prefix.bootstrap_cut(), 1);
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
        let proof = scene.attest();
        let bootstrap = scene.bootstrap(proof, 0);
        for batch in 0..64u64 {
            for thread in 1..=256u64 {
                let ticket = batch * 256 + thread;
                let begin = begin_bytes(ticket, 1, create, 0);
                assert_eq!(scene.ingest(&begin), JournalDisposition::BeginAdmitted);
                scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
            }
            scene.seal(&bootstrap).expect("batch seal prunes");
        }
        for thread in 16_384 + 1..=16_448u64 {
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
            .adapter
            .seal(&mut scene.model, &audit, &bootstrap, frontier)
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
        let proof = scene.attest();
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
        let proof = scene.attest();
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

    #[test]
    fn object_journal_h3_disposition_evidence() {
        use crate::inventory_semantics::{LaneCollectionRefusal, LaneNegative};

        let mut scene = Scene::new(image_default());
        let genesis = H3DispositionEvidence::genesis();

        // No negatives: disposition extends through the greatest staged
        // token, monotonically over the previous evidence.
        let clean = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[scene.fixture.evidence(), scene.fixture.evidence()],
            &genesis,
        );
        assert!(matches!(
            clean,
            H3DispositionEvidence::Clean {
                disposed_through: 2
            }
        ));
        let chained =
            H3DispositionEvidence::from_finalizer_batch(&[], &[scene.fixture.evidence()], &clean);
        assert!(matches!(
            chained,
            H3DispositionEvidence::Clean {
                disposed_through: 3
            }
        ));
        let older =
            H3DispositionEvidence::from_finalizer_batch(&[], &[scene.fixture.evidence()], &chained);
        assert!(matches!(
            older,
            H3DispositionEvidence::Clean {
                disposed_through: 4
            }
        ));
        // Disposition never regresses below the previous evidence.
        let held = H3DispositionEvidence::from_finalizer_batch(
            &[],
            &[scene.fixture.evidence()],
            &H3DispositionEvidence::scripted_clean(10),
        );
        assert!(matches!(
            held,
            H3DispositionEvidence::Clean {
                disposed_through: 10
            }
        ));

        // Any staged negative is a loss barrier: the narrowest cut wins,
        // and a refused collection disposes nothing.
        let barrier = H3DispositionEvidence::from_finalizer_batch(
            &[
                LaneNegative::CutBarrier { ordinal: 5 },
                LaneNegative::CutBarrier { ordinal: 3 },
            ],
            &[scene.fixture.evidence()],
            &genesis,
        );
        assert!(matches!(
            barrier,
            H3DispositionEvidence::StagedLoss { barrier: 3 }
        ));
        for refusal in [
            LaneCollectionRefusal::Backpressure,
            LaneCollectionRefusal::CollectionFailed,
        ] {
            let refused = H3DispositionEvidence::from_finalizer_batch(
                &[LaneNegative::CollectionRefused { reason: refusal }],
                &[scene.fixture.evidence()],
                &genesis,
            );
            assert!(matches!(
                refused,
                H3DispositionEvidence::StagedLoss { barrier: 0 }
            ));
        }

        // A clean batch after a loss batch recovers disposition from its
        // own staged tokens.
        let recovered =
            H3DispositionEvidence::from_finalizer_batch(&[], &[scene.fixture.evidence()], &barrier);
        assert!(matches!(
            recovered,
            H3DispositionEvidence::Clean {
                disposed_through: 9
            }
        ));
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
            .adapter
            .seal(&mut scene.model, &audit, &bootstrap, frontier)
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
        let birth = BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 0, 0)
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
        BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 0, 0)
            .expect("novel at cut zero");
        assert_eq!(
            BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 1, 0),
            Err(BirthRefusal::NoveltyBroken)
        );
        let absence =
            BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::AbsenceAppearance, 1, 0)
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
            BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 1, 0),
            Err(BirthRefusal::NoveltyBroken)
        );
        assert_eq!(
            BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::AbsenceAppearance, 1, 0),
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
            BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::AbsenceAppearance, 1, 0),
            Err(BirthRefusal::AbsenceUnproven)
        );

        // A birth with zero observed history proves nothing: attestation
        // refuses, and the seal maps it to a bootstrap mismatch.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        assert_eq!(
            BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 0, 0),
            Err(BirthRefusal::ImageUnknown)
        );
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let refused = scene
            .adapter
            .seal(&mut scene.model, &audit, &bootstrap, frontier)
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
        let pending = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through - 1),
            0,
        );
        let bootstrap = scene.bootstrap(proof, 0);
        let frontier = scene.adapter.consumed_frontier();
        let failure = scene
            .adapter
            .seal(&mut scene.model, &pending, &bootstrap, frontier)
            .expect_err("undisposed H3 refuses");
        assert_eq!(failure.gap, JournalGap::H3Pending);
        assert_eq!(
            BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::AbsenceAppearance, 1, 0),
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
            BootstrapReceipt::attest(&scene.adapter, child_proof, BirthKind::ExecMarker, 1, 0),
            Err(BirthRefusal::NoveltyBroken)
        );
        assert_eq!(
            BootstrapReceipt::attest(
                &scene.adapter,
                child_proof,
                BirthKind::AbsenceAppearance,
                1,
                0
            ),
            Err(BirthRefusal::AbsenceUnproven)
        );
        scene.ingest(&begin);
        BootstrapReceipt::attest(
            &scene.adapter,
            parent_proof,
            BirthKind::AbsenceAppearance,
            1,
            0,
        )
        .expect("parent quiet life births");
    }

    #[test]
    fn object_journal_birth_cut_covers_and_pins_history() {
        // Direct: the cover rule over staged begins, ignoring staged
        // history for other images and vacuous when nothing is staged.
        let mut scene = Scene::new(image_default());
        scene.attest();
        let create = function_id("C_CreateObject");
        let image = (COOKIE, EXEC);
        assert!(scene.adapter.birth_covers_staged(image, 0));
        scene.ingest(&begin_bytes(1, 1, create, 0));
        assert!(scene.adapter.birth_covers_staged(image, 0));
        assert!(!scene.adapter.birth_covers_staged(image, 1));
        assert!(scene.adapter.birth_covers_staged((COOKIE + 1, EXEC), 1));

        // Pinning: the birth pins per key-era at first seal. Another
        // image's record lands first, so the scene image is first
        // sighted at 2 and both cuts 0 and 1 verify as exec-novel; the
        // moved birth still refuses on the pin alone.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
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
            .adapter
            .seal(&mut scene.model, &audit, &moved, frontier)
            .expect_err("moved birth refuses");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);
        scene.seal(&first).expect("pinned birth re-seals");
    }

    #[test]
    fn object_journal_closure_generation_binds_seal() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // Healthy history seals under generation zero.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let create = function_id("C_CreateObject");
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let bootstrap = scene.bootstrap(proof, 0);
        scene.seal(&bootstrap).expect("gen-zero seal passes");
        // Advancing the closure retires old audits and old receipts alike.
        assert!(scene.adapter.advance_closure_generation(1));
        let frontier = scene.adapter.consumed_frontier();
        let stale_audit = scene.audit();
        let refused = scene
            .adapter
            .seal(&mut scene.model, &stale_audit, &bootstrap, frontier)
            .expect_err("stale audit refuses");
        assert_eq!(refused.gap, JournalGap::ClosureStale);
        let fresh_audit = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            1,
        );
        let refused = scene
            .adapter
            .seal(&mut scene.model, &fresh_audit, &bootstrap, frontier)
            .expect_err("stale receipt refuses");
        assert_eq!(refused.gap, JournalGap::ClosureStale);
        // Fresh production attestation under the live generation seals
        // new history.
        let next = begin_bytes(1, 2, create, 0);
        scene.ingest(&next);
        scene.ingest(&end_bytes(&next, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 60));
        let birth = BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 0, 1)
            .expect("live generation attests");
        let frontier = scene.adapter.consumed_frontier();
        let fresh_audit = JournalAuditReceipt::scripted(
            7,
            7,
            None,
            0,
            H3DispositionEvidence::scripted_clean(scene.adapter.consumed_through),
            1,
        );
        let success = scene
            .adapter
            .seal(&mut scene.model, &fresh_audit, &birth, frontier)
            .expect("live generation seals");
        assert_eq!(success.prefix.settled().len(), 1);
        // Regressions refuse; repeats are idempotent; stale attestation
        // refuses at the constructor.
        assert!(!scene.adapter.advance_closure_generation(0));
        assert!(scene.adapter.advance_closure_generation(1));
        assert_eq!(
            BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 0, 0),
            Err(BirthRefusal::ClosureStale)
        );
    }

    #[test]
    fn object_journal_stop_provider_continues() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // One creation seals, one call stays held, then stop invalidates
        // the tracked incarnation and reports it.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
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
            .adapter
            .seal(&mut scene.model, &audit, &bootstrap, frontier)
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
            0,
        );
        let failure = scene
            .adapter
            .seal(&mut scene.model, &malformed, &bootstrap, frontier)
            .expect_err("malformed tick refuses");
        assert_eq!(failure.gap, JournalGap::Malformed);
        assert!(failure.effects.effects.is_empty());
        let fence = scene.adapter.consumed_through;
        assert_eq!(fence, 2);
        let below = BootstrapReceipt::scripted(proof, BirthKind::AbsenceAppearance, fence - 1, 0);
        let audit = scene.audit();
        let refused = scene
            .adapter
            .seal(&mut scene.model, &audit, &below, frontier)
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
            0,
        );
        let frontier = scene.adapter.consumed_frontier();
        let failure = scene
            .adapter
            .seal(&mut scene.model, &malformed, &bootstrap, frontier)
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
            0,
        );
        let frontier = scene.adapter.consumed_frontier();
        assert_eq!(scene.adapter.consumed_through, 3);
        let failure = scene
            .adapter
            .seal(&mut scene.model, &malformed, &bootstrap, frontier)
            .expect_err("second void refuses");
        assert_eq!(failure.gap, JournalGap::Malformed);
        let below = BootstrapReceipt::scripted(proof, BirthKind::AbsenceAppearance, 2, 0);
        let audit = scene.audit();
        let refused = scene
            .adapter
            .seal(&mut scene.model, &audit, &below, frontier)
            .expect_err("birth below the latest fence refuses");
        assert_eq!(refused.gap, JournalGap::BootstrapMismatch);
        let fresh = begin_bytes(1, 9, create, 0);
        scene.ingest(&fresh);
        scene.ingest(&end_bytes(&fresh, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 70));
        let resume = BootstrapReceipt::scripted(proof, BirthKind::AbsenceAppearance, 3, 0);
        let success = scene.seal(&resume).expect("resumption names the fence");
        assert_eq!(success.prefix.birth_cut(), 3);
        assert_eq!(success.prefix.bootstrap_cut(), 4);
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
        let birth = BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 0, 0)
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
        let receipt = BootstrapReceipt::scripted(foreign_proof, BirthKind::ExecMarker, 0, 0);
        let frontier = scene.adapter.consumed_frontier();
        let audit = scene.audit();
        let refused = scene
            .adapter
            .seal(&mut scene.model, &audit, &receipt, frontier)
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
            BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 0, 0),
            Err(BirthRefusal::ImageTainted)
        );

        // Stale closure: advancing the generation retires the receipt.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
        let begin = begin_bytes(1, 1, create, 0);
        scene.ingest(&begin);
        scene.ingest(&end_bytes(&begin, OBJECT_ACTION_CREATE, 0, ENTRY_NS + 50));
        let birth = BootstrapReceipt::attest(&scene.adapter, proof, BirthKind::ExecMarker, 0, 0)
            .expect("birth attests");
        assert!(scene.adapter.advance_closure_generation(1));
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
            .adapter
            .seal(&mut scene.model, &audit, &birth, frontier)
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
        let proof = scene.attest();
        let sign = function_id("C_Sign");
        let bootstrap = scene.bootstrap(proof, 0);
        for thread in 1..=16_448u64 {
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
    fn object_journal_long_open_call_spans_seals() {
        use p11scope_ebpf_common::object_wire::OBJECT_ACTION_CREATE;

        // One neutral call held open across fifty seals while fifty
        // creations complete: the watermark holds the span, every seal
        // lists the held call, and the late terminal settles it without
        // disturbing settled history. The held call is neutral (a slow
        // operation), since a held creation would genuinely collide with
        // everything inside its span.
        let mut scene = Scene::new(image_default());
        let proof = scene.attest();
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
}
