//! SPDX-License-Identifier: GPL-3.0-or-later
//! Capture-owned registries and settlement for the pure object model.
//!
//! Settlement replays each domain's admitted history in reference-cut order
//! up to a watermark: the prefix frontier, held back before the earliest
//! still-open call so every overlap is judged with known outcomes. Begin
//! events snapshot the session/input bindings at their original cut
//! (settled, deferred to first observation, or unproven); completion events
//! apply effects once. Rejected result candidates leave a per-binding
//! tombstone so a dependent is never re-attached to a replacement or
//! silently first-observed. Records are never evicted: retired views,
//! sessions and tombstones consume the stated budgets, and refusal is
//! explicit. Pending calls are pruned only after their completion is applied
//! and no unapplied call can overlap them.

use super::{
    AffectedScope, AttributeList, Attribution, Birth, CallKey, CallToken, CompleteInputPrefix,
    CompletedFact, CreationFamily, FieldState, FieldValue, FindResult, HandleInput, KeyLabel,
    Lifetime, LostOutcome, METADATA_FIELDS, MechanismEvidence, MetadataView, ObjectDomain,
    ObjectEffect, ObjectEffects, ObjectGap, ObjectHandle, ObjectId, ObjectLimits, ObjectProjection,
    ObjectView, OriginFact, QueryStatus, ResultSlot, SessionEnd, SessionHandle, SessionIncarnation,
    SessionOrigin, SessionState, SessionView, SlotScope, StateEstimate, StateUsage, ViewOrigin,
    field_index,
};
use p11scope_ebpf_common::object_policy::{
    DeriveResultProtocol, ObjectAction, SafeAttributeKind, authorized_result_pointer_args,
    derive_result_protocol, object_descriptor,
};
use p11scope_ebpf_common::{ARG_NONE, lifecycle, semantic_flags, transition};
use pkcs11_types::CkRv;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem::size_of;

type InstanceKey = (u64, u64, u64, u64);

/// Test observations of the real settlement loop, never replay authority.
#[cfg(test)]
pub(crate) struct SettlementStepForTest {
    pub(crate) cut: u64,
    pub(crate) terminal: bool,
    pub(crate) call: CallToken,
    pub(crate) effects: std::ops::Range<usize>,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct SettlementTraceForTest {
    pub(crate) steps: Vec<SettlementStepForTest>,
    pub(crate) effects: Vec<ObjectEffect>,
    pub(crate) settlements: usize,
}

#[cfg(test)]
thread_local! {
    static SETTLEMENT_TRACE: std::cell::RefCell<Option<(ObjectDomain, SettlementTraceForTest)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn trace_settlement_for_test<R>(
    domain: ObjectDomain,
    run: impl FnOnce() -> R,
) -> (R, SettlementTraceForTest) {
    struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            SETTLEMENT_TRACE.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    SETTLEMENT_TRACE.with(|slot| {
        let mut slot = slot.borrow_mut();
        assert!(
            slot.is_none(),
            "a settlement observer cannot replace another scope"
        );
        *slot = Some((domain, SettlementTraceForTest::default()));
    });
    // Thread-local and exact-domain filtering isolate parallel fixtures. The
    // guard clears the observer on panic as well as normal return.
    let scope = Scope;
    let result = run();
    let trace = SETTLEMENT_TRACE.with(|slot| slot.borrow_mut().take().unwrap().1);
    drop(scope);
    (result, trace)
}

#[cfg(test)]
fn observe_settlement_step(
    domain: ObjectDomain,
    cut: u64,
    terminal: bool,
    call: CallToken,
    effects: std::ops::Range<usize>,
) {
    SETTLEMENT_TRACE.with(|slot| {
        if let Some((selected, trace)) = slot.borrow_mut().as_mut()
            && *selected == domain
        {
            trace.steps.push(SettlementStepForTest {
                cut,
                terminal,
                call,
                effects,
            });
        }
    });
}

#[cfg(test)]
fn observe_settlement_effects(domain: ObjectDomain, effects: &ObjectEffects) {
    SETTLEMENT_TRACE.with(|slot| {
        if let Some((selected, trace)) = slot.borrow_mut().as_mut()
            && *selected == domain
        {
            trace.settlements += 1;
            trace.effects.extend_from_slice(&effects.effects);
        }
    });
}

/// The finite call vocabulary the model accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallKind {
    Object(ObjectAction),
    Lifecycle(u8),
    /// Effect-neutral S1 operation: participates in ordering, overlap, loss
    /// and replay, but applies no object, session-lifecycle or metadata
    /// effect. See the frozen vocabulary in the journal child.
    Neutral,
}

/// Terminal outcome classes. Never one overloaded "failure".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    /// GetAttributeValue's partial-result return codes.
    Partial,
    Pending,
    /// Ordinary ordered failure: no effect, no new epoch.
    Failed,
    InvalidHandle,
    SessionInvalid,
    /// Potentially partial or unlocalized effect.
    Ambiguous,
}

impl Outcome {
    fn success_like(self) -> bool {
        matches!(self, Self::Ok | Self::Partial)
    }

    /// Could this call have changed object/session state?
    fn may_affect(self) -> bool {
        matches!(
            self,
            Self::Ok | Self::Partial | Self::Pending | Self::Ambiguous
        )
    }
}

fn classify(rv: u64, kind: CallKind, malformed: bool) -> Outcome {
    if malformed {
        return Outcome::Ambiguous;
    }
    let rv = CkRv(rv);
    if rv == CkRv::OK {
        return Outcome::Ok;
    }
    if rv == CkRv::PENDING {
        return Outcome::Pending;
    }
    if kind == CallKind::Object(ObjectAction::GetAttributes)
        && (rv == CkRv::ATTRIBUTE_SENSITIVE
            || rv == CkRv::ATTRIBUTE_TYPE_INVALID
            || rv == CkRv::BUFFER_TOO_SMALL)
    {
        return Outcome::Partial;
    }
    if rv == CkRv::OBJECT_HANDLE_INVALID
        || rv == CkRv::KEY_HANDLE_INVALID
        || rv == CkRv::WRAPPING_KEY_HANDLE_INVALID
        || rv == CkRv::UNWRAPPING_KEY_HANDLE_INVALID
    {
        return Outcome::InvalidHandle;
    }
    if rv == CkRv::SESSION_CLOSED || rv == CkRv::SESSION_HANDLE_INVALID {
        return Outcome::SessionInvalid;
    }
    if rv == CkRv::GENERAL_ERROR
        || rv == CkRv::DEVICE_ERROR
        || rv == CkRv::DEVICE_MEMORY
        || rv == CkRv::DEVICE_REMOVED
        || rv == CkRv::TOKEN_NOT_PRESENT
        || rv == CkRv::CRYPTOKI_NOT_INITIALIZED
    {
        return Outcome::Ambiguous;
    }
    Outcome::Failed
}

/// Whether the model accepts a canonical function ordinal at all
/// (object, lifecycle or neutral): the journal's modeled-affecting test.
pub(super) fn is_modeled_function(function: u32) -> bool {
    call_kind(function).is_some()
}

fn call_kind(function: u32) -> Option<CallKind> {
    if let Some(descriptor) = object_descriptor(function) {
        return Some(CallKind::Object(descriptor.action));
    }
    if super::journal::is_neutral_function(function) {
        return Some(CallKind::Neutral);
    }
    let name = pkcs11_module::function_name(function as usize)?;
    let slot = crate::kinds::descriptor(name)?;
    match slot.lifecycle {
        lifecycle::OPEN_SESSION
        | lifecycle::CLOSE_SESSION
        | lifecycle::CLOSE_ALL_SESSIONS
        | lifecycle::FINALIZE
        | lifecycle::LOGIN
        | lifecycle::LOGOUT
        | lifecycle::FIND_INIT
        | lifecycle::FIND_FINAL
        | lifecycle::SESSION_CANCEL => Some(CallKind::Lifecycle(slot.lifecycle)),
        _ => None,
    }
}

fn creation_family(action: ObjectAction) -> Option<CreationFamily> {
    match action {
        ObjectAction::Create => Some(CreationFamily::Create),
        ObjectAction::Copy => Some(CreationFamily::Copy),
        ObjectAction::Generate => Some(CreationFamily::Generate),
        ObjectAction::GeneratePair => Some(CreationFamily::GeneratePair),
        ObjectAction::Derive => Some(CreationFamily::Derive),
        ObjectAction::Unwrap => Some(CreationFamily::Unwrap),
        _ => None,
    }
}

/// An origin at the call's own entry cut, recorded by the begin replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OriginState {
    Absent,
    /// Bound to a settled view at the original cut.
    Settled(ObjectId),
    /// No binding at the cut: a covered success may first-observe.
    Deferred,
    /// Missing/contradicted evidence: the join stays unknown.
    Unproven(ObjectGap),
}

/// No Debug: snapshots carry a domain proof generation.
#[derive(Clone, Copy)]
struct Snapshot {
    qualified: bool,
    /// The domain proof generation at the begin replay; a later proof void
    /// makes the snapshot unusable even if a new bootstrap follows.
    generation: u64,
    session: Option<SessionIncarnation>,
    inputs: [OriginState; 2],
}

const EMPTY_SNAPSHOT: Snapshot = Snapshot {
    qualified: false,
    generation: 0,
    session: None,
    inputs: [OriginState::Absent; 2],
};

/// Mechanism evidence class without the raw word. Shared
/// crate-internally for the seal's H9 correlation fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MechClass {
    NotCaptured,
    Null,
    Unreadable,
    Value,
}

impl MechClass {
    pub(crate) fn of(evidence: MechanismEvidence) -> Self {
        match evidence {
            MechanismEvidence::NotCaptured => Self::NotCaptured,
            MechanismEvidence::Null => Self::Null,
            MechanismEvidence::Unreadable => Self::Unreadable,
            MechanismEvidence::Value(_) => Self::Value,
        }
    }
}

/// Null-mechanism cancellation from both entry and return evidence. A
/// cancel needs a null on one side and no contrary evidence on the other;
/// null against a value (or unreadable) is inconsistent and joins nothing.
fn null_mechanism_gap(entry: MechClass, ret: MechanismEvidence) -> Option<ObjectGap> {
    let ret = MechClass::of(ret);
    if entry != MechClass::Null && ret != MechClass::Null {
        return None;
    }
    let quiet = |m: MechClass| matches!(m, MechClass::Null | MechClass::NotCaptured);
    if quiet(entry) && quiet(ret) {
        Some(ObjectGap::NullMechanismCancel)
    } else {
        Some(ObjectGap::InconsistentMechanism)
    }
}

/// No Debug: completions carry raw reference cuts.
#[derive(Clone)]
struct Completion {
    cut: u64,
    end_ns: u64,
    rv: u64,
    return_mechanism: MechanismEvidence,
    results: [ResultSlot; 2],
    session_out: HandleInput<SessionHandle>,
    found: FindResult,
    attributes: Option<AttributeList>,
    malformed: bool,
}

/// No Debug: pending calls carry raw reference cuts.
#[derive(Clone)]
struct PendingCall {
    domain: ObjectDomain,
    key: CallKey,
    begin: u64,
    entry_ns: u64,
    function: u32,
    kind: CallKind,
    session: HandleInput<SessionHandle>,
    inputs: [HandleInput<ObjectHandle>; 2],
    requested: [Option<AttributeList>; 2],
    /// Only the finite entry protocol is retained, never the raw word.
    derive_protocol: DeriveResultProtocol,
    entry_mechanism: MechClass,
    scope: SlotScope,
    completion: Option<Completion>,
    fenced: bool,
    begin_applied: bool,
    end_applied: bool,
    snapshot: Snapshot,
}

impl PendingCall {
    fn outcome(&self) -> Option<Outcome> {
        self.completion
            .as_ref()
            .map(|c| classify(c.rv, self.kind, c.malformed))
    }

    fn end_cut(&self) -> Option<u64> {
        self.completion.as_ref().map(|c| c.cut)
    }

    fn session_handle(&self) -> Option<SessionHandle> {
        match self.session {
            HandleInput::Value(h) => Some(h),
            _ => None,
        }
    }

    fn action(&self) -> Option<ObjectAction> {
        match self.kind {
            CallKind::Object(action) => Some(action),
            CallKind::Lifecycle(_) | CallKind::Neutral => None,
        }
    }

    fn is_creation(&self) -> bool {
        self.action().and_then(creation_family).is_some()
    }

    /// Accepted result handles, or `None` when any authorized output is
    /// unknown (unreadable, pending, ambiguous, protocol unavailable).
    fn known_outputs(&self) -> Option<Vec<ObjectHandle>> {
        let completion = self.completion.as_ref()?;
        if classify(completion.rv, self.kind, completion.malformed) != Outcome::Ok {
            return None;
        }
        let slots = self.authorized_slots(completion)?;
        let mut out = Vec::new();
        for (index, authorized) in slots.iter().enumerate() {
            if !authorized {
                continue;
            }
            match completion.results[index] {
                ResultSlot::Handle(h) => out.push(h),
                _ => return None,
            }
        }
        Some(out)
    }

    /// Which result slots the policy authorizes for this exact call; `None`
    /// when the Derive protocol guard fails.
    fn authorized_slots(&self, completion: &Completion) -> Option<[bool; 2]> {
        let entry_mechanism = match self.derive_protocol {
            DeriveResultProtocol::ScalarHandle(_) => match completion.return_mechanism {
                MechanismEvidence::Value(value)
                    if derive_result_protocol(value) == self.derive_protocol =>
                {
                    Some(value)
                }
                _ => None,
            },
            DeriveResultProtocol::Unavailable => None,
        };
        let args = authorized_result_pointer_args(self.function, entry_mechanism);
        if self.action() == Some(ObjectAction::Derive) && args == [ARG_NONE; 2] {
            return None;
        }
        Some([args[0] != ARG_NONE, args[1] != ARG_NONE])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Binding {
    View(ObjectId),
    /// A rejected/uncertain result candidate: joins through this handle in
    /// this session stay unknown until a later boundary or accepted output.
    Tombstone,
}

#[derive(Debug, Clone)]
struct SessionRecord {
    domain: ObjectDomain,
    handle: SessionHandle,
    origin: SessionOrigin,
    scope: SlotScope,
    state: SessionState,
    /// Retained view records whose session this is (pruning guard).
    views: usize,
}

#[derive(Debug, Clone)]
struct ViewRecord {
    domain: ObjectDomain,
    session: SessionIncarnation,
    handle: ObjectHandle,
    origin: ViewOrigin,
    creator: Option<SessionIncarnation>,
    birth: Birth,
    lifetime: Lifetime,
    attribution: Attribution,
    references: u64,
    key_uses: u64,
    /// Inline retention from key history (N6): set when a key use
    /// references this record, never cleared — retained key rows
    /// name this object for the capture, so pruning must keep it
    /// and capacity pressure must refuse the newcomer instead.
    key_retained: bool,
    requested: [FieldState; METADATA_FIELDS],
    established: [FieldState; METADATA_FIELDS],
    queries: [QueryStatus; METADATA_FIELDS],
}

impl ViewRecord {
    fn token_true(&self) -> bool {
        self.established[field_index(SafeAttributeKind::Token)]
            == FieldState::Value(FieldValue::Scalar(1))
    }

    fn token_false(&self) -> bool {
        self.established[field_index(SafeAttributeKind::Token)]
            == FieldState::Value(FieldValue::Scalar(0))
    }

    fn created(&self) -> bool {
        matches!(self.origin, ViewOrigin::Created(_)) && self.attribution == Attribution::Valid
    }

    fn label(&self) -> Option<KeyLabel> {
        let field = |kind| self.established[field_index(kind)];
        let scalar = |kind| match field(kind) {
            FieldState::Value(FieldValue::Scalar(v)) => Some(v),
            _ => None,
        };
        if matches!(field(SafeAttributeKind::Class), FieldState::Conflict(_)) {
            return None;
        }
        let key_type = scalar(SafeAttributeKind::KeyType)?;
        // An established class incompatible with the key type withholds
        // the combined label: AES and generic_secret need secret_key;
        // RSA and EC need public_key or private_key. Unknown and
        // invalidated classes are not established and do not block.
        if let Some(class) = scalar(SafeAttributeKind::Class) {
            let compatible = match key_type {
                0x1f | 0x10 => class == 4,
                0x00 | 0x03 => class == 2 || class == 3,
                _ => true,
            };
            if !compatible {
                return None;
            }
        }
        match key_type {
            0x1f => {
                scalar(SafeAttributeKind::ValueLen).map(|value_len| KeyLabel::Aes { value_len })
            }
            0x00 => scalar(SafeAttributeKind::ModulusBits)
                .map(|modulus_bits| KeyLabel::Rsa { modulus_bits }),
            0x03 => match field(SafeAttributeKind::EcParams) {
                FieldState::Value(FieldValue::Curve(curve)) => Some(KeyLabel::Ec { curve }),
                _ => None,
            },
            _ => None,
        }
    }
}

/// No Debug: domain state carries raw reference cuts.
#[derive(Default)]
struct DomainState {
    /// Calls with begin cut >= this are qualified.
    bootstrap: Option<u64>,
    /// Watermark: every event at or below has been applied.
    applied: Option<u64>,
    /// Highest prefix frontier accepted (completeness claimed through it).
    covered: Option<u64>,
    /// A new bootstrap must lie strictly above this cut.
    fence_floor: Option<u64>,
    ended: Option<ObjectGap>,
    /// Proof generation: every void increments it, so snapshots taken
    /// under an earlier proof can never publish.
    generation: u64,
    /// Highest cut of a begin refused for capacity: that call may still be
    /// running, so no bootstrap is accepted until a lost-outcome fact
    /// bounds it.
    refused_in_flight: Option<u64>,
    /// Prune candidates with the domain position at which they ended:
    /// retired views, ended sessions and cleared tombstone charges.
    retired_views: Vec<(ObjectId, u64)>,
    ended_sessions: Vec<(SessionIncarnation, u64)>,
    cleared_tombstones: Vec<u64>,
    live_sessions: BTreeMap<SessionHandle, SessionIncarnation>,
    bindings: BTreeMap<(SessionIncarnation, ObjectHandle), Binding>,
    keys: BTreeMap<CallKey, CallToken>,
    cuts: BTreeSet<u64>,
}

// Compile-time guard: records that carry raw reference cuts must never
// implement Debug (a derive would make this path ambiguous and fail to
// build).
const _: fn() = || {
    trait AmbiguousIfDebug<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
    struct IsDebug;
    impl<T: ?Sized + std::fmt::Debug> AmbiguousIfDebug<IsDebug> for T {}
    let _ = <PendingCall as AmbiguousIfDebug<_>>::check;
    let _ = <Completion as AmbiguousIfDebug<_>>::check;
    let _ = <DomainState as AmbiguousIfDebug<_>>::check;
    let _ = <Snapshot as AmbiguousIfDebug<_>>::check;
};

#[derive(Debug, Default, Clone, Copy)]
struct InstanceUsage {
    live_sessions: usize,
    views: usize,
}

/// One frozen async input (6.07b deferred mint): the origin-END join
/// verdict for one input ordinal. Frozen values never change except
/// `lost`, which death paths set; a lost input yields no receipt at
/// completion. Raw handle words are never retained: only resolved ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferredInput {
    Absent,
    Unproven(ObjectGap),
    Frozen {
        object: ObjectId,
        key_use: bool,
        metadata: super::KeyMetadataFlags,
        label: Option<super::KeyLabel>,
        attribution_valid: bool,
        lost: bool,
    },
}

/// A minted deferred origin (6.07b): the frozen receipt vector of one
/// PENDING origin END, retained model-side until the completion
/// quantum redeems it or a death path disposes it. S1 records carry
/// only the origin ticket (the deferred key); the snapshot lives
/// once, here. No raw handle, async value, or replacement view is
/// ever consulted at completion time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeferredOrigin {
    /// Origin ticket (F1): the cross-side deferred key.
    ticket: CallToken,
    /// Origin H0 position (F1): the origin key's admission ordinal.
    /// First production reader lands with the Q2 seal path.
    #[cfg_attr(not(test), allow(dead_code))]
    position: u64,
    /// Origin catalog function (F1).
    /// First production reader lands with the Q2 seal path.
    #[cfg_attr(not(test), allow(dead_code))]
    function: u32,
    /// Origin domain (F2).
    domain: ObjectDomain,
    /// Snapshot proof generation (F2).
    generation: u64,
    /// Acting session incarnation (F3): `None` (with no frozen
    /// inputs) when resolution was not Live at the origin END.
    session: Option<SessionIncarnation>,
    /// Frozen inputs (F4–F6).
    inputs: [DeferredInput; 2],
    /// Mint order for oldest-first eviction.
    sequence: u64,
}

/// A detached deferred origin (6.07b): the GetID-minted custody form,
/// mirroring S1 `AsyncId`. `holder` is the current owning session
/// incarnation (`None` floats — joinable, a live state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DetachedDeferred {
    origin: DeferredOrigin,
    holder: Option<SessionIncarnation>,
}

/// Shared-budget charge for one deferred origin (6.07b §§2.2/3.8):
/// the larger (detached) table form, held for the record's whole
/// lifetime. The constant stays stable across detach, so the charge
/// moves with the record keyed by origin ticket — no recharge, no
/// release — until consumption, eviction or disposal releases it.
const DEFERRED_ORIGIN_CHARGE: u64 = size_of::<DetachedDeferred>() as u64;

/// Why a deferred custody move was refused (6.07b). Refusals keep the
/// first origin intact and count ambiguity; they never overwrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeferredRefusal {
    /// No live record for the named key.
    NoRecord,
    /// The detached key already names a live origin: first wins.
    Occupied,
    /// The origin session's slot scope is Unknown: no exact detached
    /// key exists (U-4: refuse to detach).
    UnknownSlot,
}

/// Debug prints cardinalities and finite gap counts only: no handle, domain
/// word, cut or epoch.
pub(super) struct ModelState {
    limits: ObjectLimits,
    next_object: u64,
    next_session: u64,
    next_token: u64,
    domains: BTreeMap<ObjectDomain, DomainState>,
    instances: BTreeMap<InstanceKey, InstanceUsage>,
    sessions: BTreeMap<SessionIncarnation, SessionRecord>,
    objects: BTreeMap<ObjectId, ViewRecord>,
    pending: BTreeMap<CallToken, PendingCall>,
    /// Live deferred origins by (origin session, target function):
    /// PENDING origins awaiting GetID or direct completion (6.07b).
    deferred_pending: BTreeMap<(SessionIncarnation, u32), DeferredOrigin>,
    /// Detached deferred origins by (domain, target, value word):
    /// GetID-minted custody awaiting Join or completion (6.07b).
    deferred_detached: BTreeMap<(ObjectDomain, u32, u64), DetachedDeferred>,
    /// Mint order for oldest-first deferred eviction.
    deferred_sequence: u64,
    /// Origin tickets whose deferred records were consumed or
    /// disposed on a path without ledger access (redeem, session
    /// death): their shared-budget charges release at the next
    /// deferred mint (before its charge) and at every prune, so the
    /// queue never spans settles and a remint observes freed budget.
    deferred_releases: Vec<u64>,
    /// Live tombstone bindings (usage reporting).
    tombstones: usize,
    /// Tombstone charges still held: a cleared tombstone's charge is
    /// refunded only by pruning, once no fence can still need it.
    tombstone_charges: usize,
    pruned_objects: u64,
    pruned_sessions: u64,
    refunded_tombstones: u64,
    pruned_domains: u64,
    /// Bounded memory of the most recently pruned domain identities (at
    /// most `limits.instances`), so late facts for them are refused with a
    /// distinct reason. Older pruned identities are refused as unknown.
    recently_pruned: VecDeque<ObjectDomain>,
    recently_pruned_set: BTreeSet<ObjectDomain>,
    gaps: BTreeMap<ObjectGap, u64>,
}

fn max_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// Borrowed positions from the actual settlement loop, before its calls are
/// pruned. The journal records indexes/ranges, never a second set of facts.
#[derive(Clone, Copy)]
pub(super) enum SettlementTransition {
    Prelude,
    Begin {
        key: CallKey,
        token: CallToken,
        cut: u64,
    },
    End {
        key: CallKey,
        token: CallToken,
        cut: u64,
    },
    Tail,
}

impl ModelState {
    pub(super) fn new(limits: ObjectLimits) -> Self {
        Self {
            limits,
            next_object: 0,
            next_session: 0,
            next_token: 0,
            domains: BTreeMap::new(),
            instances: BTreeMap::new(),
            sessions: BTreeMap::new(),
            objects: BTreeMap::new(),
            pending: BTreeMap::new(),
            deferred_pending: BTreeMap::new(),
            deferred_detached: BTreeMap::new(),
            deferred_sequence: 0,
            deferred_releases: Vec::new(),
            tombstones: 0,
            tombstone_charges: 0,
            pruned_objects: 0,
            pruned_sessions: 0,
            refunded_tombstones: 0,
            pruned_domains: 0,
            recently_pruned: VecDeque::new(),
            recently_pruned_set: BTreeSet::new(),
            gaps: BTreeMap::new(),
        }
    }

    fn gap(&mut self, reason: ObjectGap) {
        let count = self.gaps.entry(reason).or_insert(0);
        *count = count.saturating_add(1);
    }

    fn gap_effect(&mut self, effects: &mut ObjectEffects, reason: ObjectGap) {
        self.gap(reason);
        effects.push(ObjectEffect::Gap { reason });
    }

    fn unresolved(&mut self, effects: &mut ObjectEffects, call: CallToken, reason: ObjectGap) {
        self.gap(reason);
        effects.push(ObjectEffect::Unresolved { call, reason });
    }

    /// Explicitly register a domain record (counted against the instance
    /// budget). Idempotent while held. Under the cap, ended domains with no
    /// remaining claims are pruned first. A recently pruned identity is
    /// refused (`DomainPruned`).
    pub(super) fn register_domain(&mut self, domain: ObjectDomain) -> Result<(), ObjectGap> {
        if self.domains.contains_key(&domain) {
            return Ok(());
        }
        if self.recently_pruned_set.contains(&domain) {
            self.gap(ObjectGap::DomainPruned);
            return Err(ObjectGap::DomainPruned);
        }
        if self.domains.len() >= self.limits.instances {
            self.prune_domains();
        }
        if self.domains.len() >= self.limits.instances {
            self.gap(ObjectGap::InstanceCapacity);
            return Err(ObjectGap::InstanceCapacity);
        }
        self.domains.insert(domain, DomainState::default());
        self.instances.entry(domain.instance_key()).or_default();
        Ok(())
    }

    /// Facts only ever name a held domain: never an implicit creation.
    fn held(&self, domain: ObjectDomain) -> Result<(), ObjectGap> {
        if self.domains.contains_key(&domain) {
            Ok(())
        } else if self.recently_pruned_set.contains(&domain) {
            Err(ObjectGap::DomainPruned)
        } else {
            Err(ObjectGap::UnknownDomain)
        }
    }

    /// Remove ended domains that hold no ticket, live view or live session,
    /// after pruning their records. Runs only from registration under the
    /// cap, never inside a replay.
    fn prune_domains(&mut self) {
        let ended: Vec<ObjectDomain> = self
            .domains
            .iter()
            .filter(|(_, state)| state.ended.is_some() && state.keys.is_empty())
            .map(|(domain, _)| *domain)
            .collect();
        for domain in ended {
            self.prune_records(domain);
            let state = &self.domains[&domain];
            let empty = state.retired_views.is_empty()
                && state.ended_sessions.is_empty()
                && state.cleared_tombstones.is_empty()
                && state.live_sessions.is_empty()
                && state.bindings.is_empty();
            if !empty {
                continue;
            }
            self.domains.remove(&domain);
            self.pruned_domains = self.pruned_domains.saturating_add(1);
            if self.recently_pruned.len() >= self.limits.instances
                && let Some(oldest) = self.recently_pruned.pop_front()
            {
                self.recently_pruned_set.remove(&oldest);
            }
            if self.limits.instances > 0 {
                self.recently_pruned.push_back(domain);
                self.recently_pruned_set.insert(domain);
            }
        }
        let held: BTreeSet<InstanceKey> = self.domains.keys().map(|d| d.instance_key()).collect();
        self.instances.retain(|key, _| held.contains(key));
    }

    // -----------------------------------------------------------------------
    // begin / complete
    // -----------------------------------------------------------------------

    pub(super) fn begin(
        &mut self,
        origin: OriginFact,
        ledger: &mut super::journal::StagingLedger,
    ) -> Result<CallToken, ObjectGap> {
        // Reference/tests entry: production conversion uses
        // `begin_with_effects` so refusal invalidations publish.
        self.begin_with_effects(origin, ledger).0
    }

    /// Admission with its refusal effects: capacity and contradiction
    /// invalidations ride alongside the token, so the production
    /// conversion path publishes them before further publication
    /// instead of dropping them in a local.
    pub(super) fn begin_with_effects(
        &mut self,
        origin: OriginFact,
        ledger: &mut super::journal::StagingLedger,
    ) -> (Result<CallToken, ObjectGap>, ObjectEffects) {
        self.begin_with_resource(origin, ledger, None)
    }

    pub(super) fn begin_with_resource(
        &mut self,
        origin: OriginFact,
        ledger: &mut super::journal::StagingLedger,
        resource: Option<&super::journal::ExistingReservation>,
    ) -> (Result<CallToken, ObjectGap>, ObjectEffects) {
        let (domain, cut) = (origin.domain, origin.cut.0);
        let (result, mut effects) = self.admit_with_effects(origin, ledger, resource);
        match result {
            Err(reason @ (ObjectGap::ClosedFrontier | ObjectGap::MalformedFact)) => {
                // Unrepresentable history: a begin the model can no longer
                // order. Proof ends and the fence floor rises above it.
                // It is still a real call that may be running: like a
                // capacity refusal, it blocks bootstrap until bounded.
                self.contradict(domain, reason, Some(cut), &mut effects, ledger);
                if let Some(state) = self.domains.get_mut(&domain) {
                    state.refused_in_flight = max_opt(state.refused_in_flight, Some(cut));
                }
            }
            Err(reason) => self.gap(reason),
            Ok(_) => {}
        }
        (result, effects)
    }

    /// Admission with its capacity-refusal effects: a refused begin is
    /// unrepresented history that may still be running, and its
    /// invalidation effects are observable, never local.
    fn admit_with_effects(
        &mut self,
        origin: OriginFact,
        ledger: &mut super::journal::StagingLedger,
        resource: Option<&super::journal::ExistingReservation>,
    ) -> (Result<CallToken, ObjectGap>, ObjectEffects) {
        let domain = origin.domain;
        let refused = |reason: ObjectGap| (Err(reason), ObjectEffects::default());
        if let Err(reason) = self.held(domain) {
            return refused(reason);
        }
        if self.domains[&domain].ended.is_some() {
            return refused(ObjectGap::DomainEnded);
        }
        let Some(kind) = call_kind(origin.function) else {
            return refused(ObjectGap::UnsupportedFunction);
        };
        let cut = origin.cut.0;
        let state = &self.domains[&domain];
        if let Some(token) = state.keys.get(&origin.key) {
            // An exact re-delivery of an admitted begin is a no-op; the same
            // key at another cut is malformed.
            return refused(if self.pending[token].begin == cut {
                ObjectGap::DuplicateCall
            } else {
                ObjectGap::MalformedFact
            });
        }
        if state.covered.is_some_and(|covered| cut <= covered) {
            return refused(ObjectGap::ClosedFrontier);
        }
        if state.cuts.contains(&cut) {
            return refused(ObjectGap::MalformedFact);
        }
        if self.pending.len() >= self.limits.pending_calls {
            let effects = self.refuse_unrepresented(domain, cut, ledger);
            return (Err(ObjectGap::PendingCapacity), effects);
        }
        let Some(next) = self
            .next_token
            .checked_add(1)
            .filter(|next| *next <= self.limits.max_call_token)
        else {
            let effects = self.refuse_unrepresented(domain, cut, ledger);
            return (Err(ObjectGap::IdExhausted), effects);
        };
        // One shared reservation owner (N1c): the model pending
        // call takes its ticket before the token is consumed, so a
        // refusal burns no token. A full shared census refuses
        // exactly like a full pending table.
        let charged = match resource {
            Some(resource) => {
                ledger.charge_model_from_open(next, size_of::<PendingCall>() as u64, resource)
            }
            None => ledger.charge_model(next, size_of::<PendingCall>() as u64),
        };
        if charged.is_err() {
            let effects = self.refuse_unrepresented(domain, cut, ledger);
            return (Err(ObjectGap::PendingCapacity), effects);
        }
        self.next_token = next;
        let token = CallToken(next);
        let derive_protocol = match origin.entry_mechanism {
            MechanismEvidence::Value(value) => derive_result_protocol(value),
            _ => DeriveResultProtocol::Unavailable,
        };
        let call = PendingCall {
            domain,
            key: origin.key,
            begin: cut,
            entry_ns: origin.entry_ns,
            function: origin.function,
            kind,
            session: origin.session,
            inputs: origin.inputs,
            requested: origin.requested,
            derive_protocol,
            entry_mechanism: MechClass::of(origin.entry_mechanism),
            scope: origin.scope,
            completion: None,
            fenced: false,
            begin_applied: false,
            end_applied: false,
            snapshot: EMPTY_SNAPSHOT,
        };
        let state = self.domains.get_mut(&domain).expect("registered domain");
        state.keys.insert(origin.key, token);
        state.cuts.insert(cut);
        self.pending.insert(token, call);
        (Ok(token), ObjectEffects::default())
    }

    /// The journal adapter's consumed-but-unrepresentable begin: recorded
    /// exactly like a model capacity refusal. The domain must be held;
    /// an unheld domain counts its gap instead of recording. Returns the
    /// void's invalidation effects (retired views and sessions) so the
    /// caller publishes them; they are observable, never local.
    pub(super) fn note_refused(
        &mut self,
        domain: ObjectDomain,
        cut: u64,
        ledger: &mut super::journal::StagingLedger,
    ) -> ObjectEffects {
        if self.held(domain).is_err() {
            self.gap(ObjectGap::UnknownDomain);
            return ObjectEffects::default();
        }
        let effects = self.refuse_unrepresented(domain, cut, ledger);
        self.gap(ObjectGap::PendingCapacity);
        effects
    }

    /// A refused call is unrepresented history that may still be running:
    /// proof in its domain ends, and no bootstrap is accepted until a
    /// lost-outcome fact bounds it. Existing tickets stay as fences.
    /// Returns the void's invalidation effects for publication.
    fn refuse_unrepresented(
        &mut self,
        domain: ObjectDomain,
        cut: u64,
        ledger: &mut super::journal::StagingLedger,
    ) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        self.void_bootstrap(domain, ObjectGap::PendingCapacity, &mut effects, ledger);
        if let Some(state) = self.domains.get_mut(&domain) {
            state.fence_floor = max_opt(state.fence_floor, Some(cut));
            state.refused_in_flight = max_opt(state.refused_in_flight, Some(cut));
        }
        effects
    }

    pub(super) fn complete(
        &mut self,
        token: CallToken,
        result: CompletedFact,
        ledger: &mut super::journal::StagingLedger,
    ) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        let Some(call) = self.pending.get(&token) else {
            self.gap_effect(&mut effects, ObjectGap::StaleToken);
            return effects;
        };
        let domain = call.domain;
        let cut = result.cut.0;
        if call.fenced {
            self.gap_effect(&mut effects, ObjectGap::FencedCompletion);
            if let Some(state) = self.domains.get_mut(&domain) {
                state.fence_floor = max_opt(state.fence_floor, Some(cut));
            }
            self.remove_call(token, ledger);
            return effects;
        }
        if call.completion.is_some() {
            self.gap_effect(&mut effects, ObjectGap::DuplicateCompletion);
            return effects;
        }
        let state = &self.domains[&domain];
        let contradicts = state.covered.is_some_and(|covered| cut <= covered);
        let malformed_cut = cut <= call.begin || state.cuts.contains(&cut);
        if contradicts || malformed_cut {
            let reason = if contradicts {
                ObjectGap::PrefixContradiction
            } else {
                ObjectGap::MalformedFact
            };
            self.remove_call(token, ledger);
            self.contradict(domain, reason, Some(cut), &mut effects, ledger);
            return effects;
        }
        let malformed = result.end_ns < call.entry_ns;
        let call = self.pending.get_mut(&token).expect("pending call");
        call.completion = Some(Completion {
            cut,
            end_ns: result.end_ns,
            rv: result.rv,
            return_mechanism: result.return_mechanism,
            results: result.results,
            session_out: result.session_out,
            found: result.found,
            attributes: result.attributes,
            malformed,
        });
        self.domains
            .get_mut(&domain)
            .expect("registered domain")
            .cuts
            .insert(cut);
        if malformed {
            self.gap(ObjectGap::MalformedFact);
        }
        effects
    }

    fn remove_call(&mut self, token: CallToken, ledger: &mut super::journal::StagingLedger) {
        if let Some(call) = self.pending.remove(&token) {
            // The pending ticket returns with its record (N1c). Tokens
            // never recycle, so a removed ticket is never recharged.
            ledger.release_model(token.0);
            if let Some(state) = self.domains.get_mut(&call.domain) {
                state.keys.remove(&call.key);
                state.cuts.remove(&call.begin);
                if let Some(end) = call.end_cut() {
                    state.cuts.remove(&end);
                }
            }
        }
    }

    fn domain_calls(&self, domain: ObjectDomain) -> Vec<CallToken> {
        self.domains
            .get(&domain)
            .map(|state| state.keys.values().copied().collect())
            .unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // settle
    // -----------------------------------------------------------------------

    pub(super) fn settle(
        &mut self,
        prefix: CompleteInputPrefix,
        ledger: &mut super::journal::StagingLedger,
    ) -> ObjectEffects {
        self.settle_recorded(prefix, ledger, &mut |_, _| {})
    }

    pub(super) fn settle_recorded(
        &mut self,
        prefix: CompleteInputPrefix,
        ledger: &mut super::journal::StagingLedger,
        record: &mut impl FnMut(SettlementTransition, std::ops::Range<usize>),
    ) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        let domain = prefix.domain;
        if let Err(reason) = self.held(domain) {
            self.gap_effect(&mut effects, reason);
            return effects;
        }
        if self.domains[&domain].ended.is_some() {
            self.gap_effect(&mut effects, ObjectGap::DomainEnded);
            return effects;
        }
        let frontier = prefix.frontier.0;
        if self.domains[&domain]
            .covered
            .is_some_and(|covered| frontier < covered)
        {
            self.gap_effect(&mut effects, ObjectGap::StalePrefix);
            return effects;
        }
        if !self.prefix_consistent(domain, frontier, &prefix.open) {
            self.contradict(
                domain,
                ObjectGap::PrefixContradiction,
                None,
                &mut effects,
                ledger,
            );
            // Surface the rejection to the seal: contradict counted it;
            // the effect (pushed, not counted twice) lets the caller
            // refuse a seal whose required alignment was rejected
            // instead of succeeding with the contradiction inside.
            effects.push(ObjectEffect::Gap {
                reason: ObjectGap::PrefixContradiction,
            });
            return effects;
        }
        if let Some(bootstrap) = prefix.bootstrap {
            self.accept_bootstrap(domain, bootstrap.0, frontier, &mut effects);
        }
        let state = self.domains.get_mut(&domain).expect("registered domain");
        state.covered = max_opt(state.covered, Some(frontier));

        // Watermark: hold back before the earliest unfenced call that is
        // still open at this frontier.
        let tokens = self.domain_calls(domain);
        let earliest_open = tokens
            .iter()
            .map(|t| &self.pending[t])
            .filter(|c| !c.fenced && c.end_cut().is_none_or(|end| end > frontier))
            .map(|c| c.begin)
            .min();
        let watermark = match earliest_open {
            Some(0) => None,
            Some(begin) => Some(frontier.min(begin - 1)),
            None => Some(frontier),
        };
        record(SettlementTransition::Prelude, 0..effects.effects.len());
        let applied = self.domains[&domain].applied;
        if let Some(watermark) = watermark {
            let mut events: Vec<(u64, bool, CallToken)> = Vec::new();
            for token in &tokens {
                let call = &self.pending[token];
                if call.fenced {
                    continue;
                }
                let after = |cut: u64| applied.is_none_or(|a| cut > a) && cut <= watermark;
                if !call.begin_applied && after(call.begin) {
                    events.push((call.begin, false, *token));
                }
                if let Some(end) = call.end_cut()
                    && !call.end_applied
                    && after(end)
                {
                    events.push((end, true, *token));
                }
            }
            events.sort();
            for (_cut, is_end, token) in events {
                // A contradiction inside this replay fences or releases the
                // remaining calls: their events no longer apply.
                if self.pending.get(&token).is_none_or(|c| c.fenced) {
                    continue;
                }
                let key = self.pending[&token].key;
                let replay_start = effects.effects.len();
                #[cfg(test)]
                let effect_start = effects.effects.len();
                if is_end {
                    self.apply_end(token, &mut effects, ledger);
                } else {
                    self.apply_begin(token);
                }
                #[cfg(test)]
                observe_settlement_step(
                    domain,
                    _cut,
                    is_end,
                    token,
                    effect_start..effects.effects.len(),
                );
                record(
                    if is_end {
                        SettlementTransition::End {
                            key,
                            token,
                            cut: _cut,
                        }
                    } else {
                        SettlementTransition::Begin {
                            key,
                            token,
                            cut: _cut,
                        }
                    },
                    replay_start..effects.effects.len(),
                );
                if self.domains[&domain].ended.is_some() {
                    break;
                }
            }
            let state = self.domains.get_mut(&domain).expect("registered domain");
            state.applied = max_opt(state.applied, Some(watermark));
        }
        let tail_start = effects.effects.len();
        self.prune(domain, ledger);
        record(
            SettlementTransition::Tail,
            tail_start..effects.effects.len(),
        );
        #[cfg(test)]
        observe_settlement_effects(domain, &effects);
        effects
    }

    fn prefix_consistent(&self, domain: ObjectDomain, frontier: u64, open: &[CallKey]) -> bool {
        if open.len() > self.limits.pending_calls {
            return false;
        }
        let state = &self.domains[&domain];
        let listed: BTreeSet<CallKey> = open.iter().copied().collect();
        for key in &listed {
            let Some(token) = state.keys.get(key) else {
                return false;
            };
            let call = &self.pending[token];
            if call.begin > frontier || call.end_cut().is_some_and(|end| end <= frontier) {
                return false;
            }
        }
        for token in state.keys.values() {
            let call = &self.pending[token];
            if call.fenced || call.begin > frontier {
                continue;
            }
            let open_here = call.end_cut().is_none_or(|end| end > frontier);
            if open_here && !listed.contains(&call.key) {
                return false;
            }
        }
        true
    }

    fn accept_bootstrap(
        &mut self,
        domain: ObjectDomain,
        bootstrap: u64,
        frontier: u64,
        effects: &mut ObjectEffects,
    ) {
        let state = &self.domains[&domain];
        let unresolved_fence = state
            .keys
            .values()
            .any(|t| self.pending[t].fenced && self.pending[t].completion.is_none());
        let above = |floor: Option<u64>| floor.is_none_or(|f| bootstrap > f);
        let ok = bootstrap <= frontier
            && above(state.covered)
            && above(state.applied)
            && above(state.fence_floor)
            && state.refused_in_flight.is_none()
            && !unresolved_fence;
        if ok {
            self.domains.get_mut(&domain).expect("domain").bootstrap = Some(bootstrap);
        } else {
            self.gap_effect(effects, ObjectGap::BootstrapRefused);
        }
    }

    fn prune(&mut self, domain: ObjectDomain, ledger: &mut super::journal::StagingLedger) {
        let tokens = self.domain_calls(domain);
        let min_unapplied = tokens
            .iter()
            .map(|t| &self.pending[t])
            .filter(|c| !c.fenced && !c.end_applied)
            .map(|c| c.begin)
            .min();
        let doomed: Vec<CallToken> = tokens
            .into_iter()
            .filter(|t| {
                let c = &self.pending[t];
                let resolved_fence = c.fenced
                    && c.completion.is_some()
                    && c.end_cut()
                        .is_some_and(|end| self.domains[&domain].covered.is_some_and(|f| end <= f));
                let settled = !c.fenced
                    && c.end_applied
                    && c.end_cut()
                        .is_some_and(|end| min_unapplied.is_none_or(|m| end < m));
                resolved_fence || settled
            })
            .collect();
        for token in doomed {
            self.remove_call(token, ledger);
        }
        // Consumed or disposed deferred records release here, so
        // their charges never pin budget past their settle.
        self.flush_deferred_releases(ledger);
    }

    // -----------------------------------------------------------------------
    // replay
    // -----------------------------------------------------------------------

    fn session_scope(&self, session: Option<SessionIncarnation>) -> SlotScope {
        session
            .and_then(|s| self.sessions.get(&s))
            .map_or(SlotScope::Unknown, |r| r.scope)
    }

    fn apply_begin(&mut self, token: CallToken) {
        let call = &self.pending[&token];
        let state = &self.domains[&call.domain];
        let qualified = state.bootstrap.is_some_and(|b| call.begin >= b);
        let mut snapshot = Snapshot {
            qualified,
            generation: state.generation,
            ..EMPTY_SNAPSHOT
        };
        if qualified {
            snapshot.session = call
                .session_handle()
                .and_then(|h| state.live_sessions.get(&h).copied());
            for (index, input) in call.inputs.iter().enumerate() {
                snapshot.inputs[index] = match input {
                    HandleInput::Absent => OriginState::Absent,
                    HandleInput::Unreadable => OriginState::Unproven(ObjectGap::UnprovenInput),
                    HandleInput::Value(h) => match snapshot.session {
                        Some(s) => match state.bindings.get(&(s, *h)) {
                            Some(Binding::View(id)) => OriginState::Settled(*id),
                            Some(Binding::Tombstone) => {
                                OriginState::Unproven(ObjectGap::DependencyBroken)
                            }
                            None => OriginState::Deferred,
                        },
                        None => OriginState::Deferred,
                    },
                };
            }
        }
        let call = self.pending.get_mut(&token).expect("pending call");
        call.snapshot = snapshot;
        call.begin_applied = true;
    }

    fn apply_end(
        &mut self,
        token: CallToken,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) {
        let call = {
            let call = self.pending.get_mut(&token).expect("pending call");
            call.end_applied = true;
            call.clone()
        };
        let completion = call.completion.clone().expect("applied completion");
        let outcome = classify(completion.rv, call.kind, completion.malformed);
        let rv = CkRv(completion.rv);

        // The module was finalized by a call this capture never saw. Like
        // the removal escalations below, this only retires, ends or
        // contradicts, so it applies even to an unqualified end.
        if !completion.malformed && rv == CkRv::CRYPTOKI_NOT_INITIALIZED {
            self.contradict(
                call.domain,
                ObjectGap::UnseenFinalize,
                None,
                effects,
                ledger,
            );
            return;
        }
        let scope = self.call_scope(&call);

        // A proof void after this call's begin replay rejects its snapshot,
        // even when a newer bootstrap is in force.
        if !call.snapshot.qualified
            || call.snapshot.generation != self.domains[&call.domain].generation
        {
            self.gap_effect(effects, ObjectGap::BootstrapUnproven);
        } else if !self.apply_qualified_end(token, &call, &completion, outcome, effects, ledger) {
            return;
        }

        // Removal/corruption returns reach beyond the call itself.
        if completion.malformed
            || call.kind == CallKind::Lifecycle(lifecycle::FINALIZE)
            || self.domains[&call.domain].ended.is_some()
        {
            return;
        }
        if rv == CkRv::DEVICE_REMOVED || rv == CkRv::TOKEN_NOT_PRESENT || rv == CkRv::DEVICE_ERROR {
            self.end_scope_sessions(call.domain, scope, ObjectGap::DeviceLoss, effects);
        } else if rv == CkRv::GENERAL_ERROR {
            self.retire_scope(call.domain, scope, ObjectGap::AmbiguousOutcome, effects);
        }
    }

    /// Joins and actions of a qualified end. Returns false when the call
    /// was a null-mechanism cancel (no further escalation applies).
    fn apply_qualified_end(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        completion: &Completion,
        outcome: Outcome,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) -> bool {
        // Init null-mechanism cancellation precedes object association.
        if outcome == Outcome::Ok
            && is_null_cancel_init(call.function)
            && let Some(reason) =
                null_mechanism_gap(call.entry_mechanism, completion.return_mechanism)
        {
            if reason == ObjectGap::NullMechanismCancel {
                self.gap(reason);
            } else {
                self.unresolved(effects, token, reason);
            }
            return false;
        }
        self.apply_action(token, call, outcome, effects, ledger);
        true
    }

    /// The slot scope a call may have acted on: its entry session's scope,
    /// its own slot argument for session-less calls, otherwise unknown.
    fn call_scope(&self, call: &PendingCall) -> SlotScope {
        let session = call.snapshot.session.or_else(|| {
            call.session_handle()
                .and_then(|h| self.domains[&call.domain].live_sessions.get(&h).copied())
        });
        match (session, call.session) {
            (Some(s), _) => self.session_scope(Some(s)),
            (None, HandleInput::Absent) => call.scope,
            (None, _) => SlotScope::Unknown,
        }
    }

    fn apply_action(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        outcome: Outcome,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) {
        let (interference, metadata_interference) = self.interference(token);

        let session = match self.resolve_session(token, call, outcome, effects) {
            SessionRes::Live(s) => Some(s),
            SessionRes::NoSession => None,
            SessionRes::Unknown(scope) => {
                // The acting session is unknown: a boundary that may have
                // taken effect widens over every compatible view.
                if outcome.may_affect() {
                    self.widen_unknown_session(call, scope, effects);
                }
                // 6.07b F3: an Unknown-session PENDING origin mints the
                // effect with no frozen inputs (no record is stored:
                // no incarnation key exists). Permanently unknown.
                if outcome == Outcome::Pending && matches!(call.kind, CallKind::Object(_)) {
                    self.mint_deferred(token, call, None, interference, effects, ledger);
                }
                return;
            }
        };

        if outcome == Outcome::SessionInvalid
            && let Some(s) = session
            && call.kind != CallKind::Lifecycle(lifecycle::CLOSE_SESSION)
        {
            self.close_session(s, Some(ObjectGap::SessionContradiction), None, effects);
            return;
        }

        // 6.07b: a PENDING object END freezes its origin BEFORE the
        // action arm runs (destroy-PENDING retires its target below;
        // joins evaluate pre-mutation, like the Ok path).
        if outcome == Outcome::Pending && matches!(call.kind, CallKind::Object(_)) {
            // F3: only a snapshot-proven Live session freezes inputs —
            // a FirstObserved incarnation never qualifies (a session
            // bound after entry never joins retroactively).
            let live = session.filter(|s| {
                call.snapshot.session == Some(*s)
                    && self
                        .sessions
                        .get(s)
                        .is_some_and(|record| record.state == SessionState::Live)
            });
            self.mint_deferred(token, call, live, interference, effects, ledger);
        }

        match call.kind {
            CallKind::Object(action) => {
                if let Some(family) = creation_family(action) {
                    self.apply_creation(
                        token,
                        call,
                        family,
                        outcome,
                        session,
                        interference,
                        effects,
                    );
                } else {
                    match action {
                        ObjectAction::Destroy => {
                            self.apply_destroy(token, call, outcome, session, interference, effects)
                        }
                        ObjectAction::Find => {
                            self.apply_find(token, call, outcome, session, interference, effects)
                        }
                        ObjectAction::GetAttributes => self.apply_access(
                            token,
                            call,
                            outcome,
                            session,
                            interference,
                            Some(metadata_interference),
                            effects,
                        ),
                        ObjectAction::SetAttributes => self.apply_set_attributes(
                            token,
                            call,
                            outcome,
                            session,
                            interference,
                            effects,
                        ),
                        _ => self.apply_access(
                            token,
                            call,
                            outcome,
                            session,
                            interference,
                            None,
                            effects,
                        ),
                    }
                }
            }
            CallKind::Lifecycle(action) => match action {
                lifecycle::OPEN_SESSION => self.apply_open(token, call, outcome, effects),
                lifecycle::CLOSE_SESSION => {
                    self.apply_close(token, call, outcome, session, interference, effects)
                }
                lifecycle::CLOSE_ALL_SESSIONS => {
                    self.apply_close_all(token, call, outcome, effects)
                }
                lifecycle::LOGOUT => self.apply_logout(call, outcome, session, effects),
                lifecycle::FINALIZE => self.apply_finalize(call, outcome, effects, ledger),
                _ => {}
            },
            // Neutral terminals apply no object effect: ordering, overlap
            // and loss participation only. Session resolution above still
            // runs, so an invalid acting session stays conservative.
            CallKind::Neutral => {}
        }
    }

    /// Boundary effects of a call whose acting session is not known.
    fn widen_unknown_session(
        &mut self,
        call: &PendingCall,
        scope: SlotScope,
        effects: &mut ObjectEffects,
    ) {
        match call.kind {
            CallKind::Object(ObjectAction::Destroy) => self.retire_aliases(
                call.domain,
                None,
                scope,
                None,
                ObjectGap::DestroyAlias,
                effects,
            ),
            CallKind::Object(ObjectAction::SetAttributes) => {
                for id in self.live_views(call.domain) {
                    if self
                        .session_scope(Some(self.objects[&id].session))
                        .compatible(scope)
                    {
                        self.invalidate_metadata(id, ObjectGap::MetadataUncertain, effects);
                    }
                }
            }
            CallKind::Lifecycle(lifecycle::CLOSE_SESSION) => self.close_other_views(
                call.domain,
                None,
                scope,
                false,
                ObjectGap::CloseUncertain,
                effects,
            ),
            CallKind::Lifecycle(lifecycle::LOGOUT) => {
                self.retire_scope(call.domain, scope, ObjectGap::LogoutUncertain, effects)
            }
            _ => {}
        }
    }

    fn resolve_session(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        outcome: Outcome,
        effects: &mut ObjectEffects,
    ) -> SessionRes {
        if let Some(s) = call.snapshot.session {
            if self.sessions[&s].state == SessionState::Live {
                return SessionRes::Live(s);
            }
            if outcome.success_like() {
                self.unresolved(effects, token, ObjectGap::StaleOrigin);
            }
            return SessionRes::Unknown(self.sessions[&s].scope);
        }
        match call.session {
            HandleInput::Absent => SessionRes::NoSession,
            HandleInput::Unreadable => {
                if outcome.success_like() {
                    self.unresolved(effects, token, ObjectGap::UnprovenSession);
                }
                SessionRes::Unknown(SlotScope::Unknown)
            }
            HandleInput::Value(h) => {
                if !outcome.success_like() {
                    return SessionRes::Unknown(SlotScope::Unknown);
                }
                if self.domains[&call.domain].live_sessions.contains_key(&h) {
                    // Bound after this call's entry: no retroactive join.
                    self.unresolved(effects, token, ObjectGap::StaleOrigin);
                    return SessionRes::Unknown(SlotScope::Unknown);
                }
                match self.alloc_session(
                    call.domain,
                    h,
                    SessionOrigin::FirstObserved,
                    SlotScope::Unknown,
                ) {
                    Ok(s) => {
                        effects.push(ObjectEffect::SessionFirstObserved {
                            call: token,
                            session: s,
                        });
                        SessionRes::Live(s)
                    }
                    Err(reason) => {
                        self.unresolved(effects, token, reason);
                        SessionRes::Unknown(SlotScope::Unknown)
                    }
                }
            }
        }
    }

    /// Overlapping calls (with known outcomes, guaranteed by the watermark)
    /// that may alter what this call's joins rely on. Neutral calls take
    /// no part as either side: they apply no joins to protect, and they
    /// apply no object effect that could alter another call's joins.
    /// Their overlap participation is cut ordering (the watermark), which
    /// the settlement path already enforces.
    fn interference(&self, token: CallToken) -> (Option<ObjectGap>, bool) {
        let x = &self.pending[&token];
        if x.kind == CallKind::Neutral {
            return (None, false);
        }
        let Some(x_end) = x.end_cut() else {
            return (None, false);
        };
        let x_scope = self.session_scope(x.snapshot.session);
        let x_views: Vec<&ViewRecord> = x
            .snapshot
            .inputs
            .iter()
            .filter_map(|o| match o {
                OriginState::Settled(id) => self.objects.get(id),
                _ => None,
            })
            .collect();
        let x_deferred = x
            .snapshot
            .inputs
            .iter()
            .any(|o| matches!(o, OriginState::Deferred));
        let x_action = x.action();
        let joins_objects = x_action.is_some_and(|a| a != ObjectAction::Destroy);
        let x_outputs = if x.is_creation() {
            x.known_outputs()
        } else {
            None
        };
        let mut metadata = false;
        for token_y in self.domain_calls(x.domain) {
            if token_y == token {
                continue;
            }
            let y = &self.pending[&token_y];
            if y.fenced || y.begin >= x_end || y.end_cut().is_some_and(|end| end <= x.begin) {
                continue;
            }
            if y.kind == CallKind::Neutral {
                continue;
            }
            if let (Some(a), Some(b)) = (x.session_handle(), y.session_handle())
                && a == b
            {
                return (Some(ObjectGap::SameSessionOverlap), metadata);
            }
            if !joins_objects {
                continue;
            }
            let y_outcome = y.outcome();
            if y_outcome.is_some_and(|o| !o.may_affect()) {
                continue;
            }
            let y_scope = match y.kind {
                CallKind::Lifecycle(lifecycle::CLOSE_ALL_SESSIONS) => y.scope,
                _ => self.session_scope(y.snapshot.session),
            };
            let compatible = x_scope.compatible(y_scope);
            let y_ok = y_outcome == Some(Outcome::Ok);
            match y.kind {
                CallKind::Lifecycle(lifecycle::FINALIZE) => {
                    return (Some(ObjectGap::OverlapUncertain), metadata);
                }
                CallKind::Lifecycle(lifecycle::CLOSE_ALL_SESSIONS | lifecycle::LOGOUT)
                    if compatible =>
                {
                    return (Some(ObjectGap::OverlapUncertain), metadata);
                }
                CallKind::Lifecycle(lifecycle::CLOSE_SESSION) if compatible => {
                    let exempt = y_ok
                        && x_action != Some(ObjectAction::Find)
                        && !x_deferred
                        && x_views
                            .iter()
                            .all(|v| v.token_true() || v.creator == Some(v.session));
                    if !exempt {
                        return (Some(ObjectGap::OverlapUncertain), metadata);
                    }
                }
                CallKind::Object(ObjectAction::Destroy) if compatible => {
                    let target = match y.snapshot.inputs[0] {
                        OriginState::Settled(id) => self.objects.get(&id).filter(|t| t.created()),
                        _ => None,
                    };
                    let exempt = y_ok
                        && x_action != Some(ObjectAction::Find)
                        && !x_deferred
                        && target.is_some()
                        && x_views.iter().all(|v| v.created());
                    if !exempt {
                        return (Some(ObjectGap::OverlapUncertain), metadata);
                    }
                }
                CallKind::Object(ObjectAction::SetAttributes)
                    if compatible && x_action == Some(ObjectAction::GetAttributes) =>
                {
                    metadata = true;
                }
                CallKind::Object(action)
                    if compatible && creation_family(action).is_some() && x.is_creation() =>
                {
                    match (y.known_outputs(), &x_outputs) {
                        (Some(y_out), Some(x_out)) => {
                            if y_out.iter().any(|h| x_out.contains(h)) {
                                return (Some(ObjectGap::OutputCollision), metadata);
                            }
                        }
                        (None, _) => return (Some(ObjectGap::OutputCollision), metadata),
                        (Some(_), None) => {}
                    }
                }
                _ => {}
            }
        }
        (None, metadata)
    }

    // -----------------------------------------------------------------------
    // allocation and bindings
    // -----------------------------------------------------------------------

    fn alloc_session(
        &mut self,
        domain: ObjectDomain,
        handle: SessionHandle,
        origin: SessionOrigin,
        scope: SlotScope,
    ) -> Result<SessionIncarnation, ObjectGap> {
        if self.sessions.len() >= self.limits.session_records {
            self.prune_all();
        }
        let usage = self.instances.entry(domain.instance_key()).or_default();
        if usage.live_sessions >= self.limits.live_sessions_per_instance
            || self.sessions.len() >= self.limits.session_records
        {
            return Err(ObjectGap::SessionCapacity);
        }
        let Some(next) = self
            .next_session
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_session_id)
        else {
            return Err(ObjectGap::IdExhausted);
        };
        self.next_session = next;
        let id = SessionIncarnation(next);
        usage.live_sessions += 1;
        self.sessions.insert(
            id,
            SessionRecord {
                domain,
                handle,
                origin,
                scope,
                state: SessionState::Live,
                views: 0,
            },
        );
        self.domains
            .get_mut(&domain)
            .expect("domain")
            .live_sessions
            .insert(handle, id);
        Ok(id)
    }

    /// Capacity check that first reclaims prunable records under pressure.
    fn ensure_view_capacity(&mut self, domain: ObjectDomain) -> Result<(), ObjectGap> {
        if self.view_capacity(domain).is_err() {
            self.prune_all();
        }
        self.view_capacity(domain)
    }

    fn view_capacity(&self, domain: ObjectDomain) -> Result<(), ObjectGap> {
        let usage = self
            .instances
            .get(&domain.instance_key())
            .copied()
            .unwrap_or_default();
        if usage.views >= self.limits.views_per_instance
            || self.objects.len() + self.tombstone_charges >= self.limits.object_records
        {
            return Err(ObjectGap::ObjectCapacity);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn alloc_view(
        &mut self,
        domain: ObjectDomain,
        session: SessionIncarnation,
        handle: ObjectHandle,
        origin: ViewOrigin,
        birth: Birth,
        requested: [FieldState; METADATA_FIELDS],
        lifetime: Lifetime,
    ) -> Result<ObjectId, ObjectGap> {
        self.ensure_view_capacity(domain)?;
        let Some(next) = self
            .next_object
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_object_id)
        else {
            return Err(ObjectGap::IdExhausted);
        };
        self.next_object = next;
        let id = ObjectId(next);
        let creator = matches!(origin, ViewOrigin::Created(_)).then_some(session);
        self.objects.insert(
            id,
            ViewRecord {
                domain,
                session,
                handle,
                origin,
                creator,
                birth,
                lifetime,
                attribution: Attribution::Valid,
                references: 0,
                key_uses: 0,
                key_retained: false,
                requested,
                established: [FieldState::Unknown; METADATA_FIELDS],
                queries: [QueryStatus::NotQueried; METADATA_FIELDS],
            },
        );
        self.instances
            .entry(domain.instance_key())
            .or_default()
            .views += 1;
        if let Some(record) = self.sessions.get_mut(&session) {
            record.views += 1;
        }
        if lifetime == Lifetime::Live {
            self.set_binding(domain, session, handle, Some(Binding::View(id)));
        } else {
            self.mark_retired(id, domain);
        }
        Ok(id)
    }

    /// Replace one binding. Clearing a tombstone never refunds its charge
    /// directly: the charge is queued and refunded only by pruning.
    fn set_binding(
        &mut self,
        domain: ObjectDomain,
        session: SessionIncarnation,
        handle: ObjectHandle,
        binding: Option<Binding>,
    ) {
        let state = self.domains.get_mut(&domain).expect("domain");
        let old = match binding {
            Some(b) => state.bindings.insert((session, handle), b),
            None => state.bindings.remove(&(session, handle)),
        };
        if old == Some(Binding::Tombstone) {
            self.tombstones -= 1;
            let at = self.position(domain);
            self.domains
                .get_mut(&domain)
                .expect("domain")
                .cleared_tombstones
                .push(at);
        }
        if binding == Some(Binding::Tombstone) {
            self.tombstones += 1;
            self.tombstone_charges += 1;
            self.instances
                .entry(domain.instance_key())
                .or_default()
                .views += 1;
        }
    }

    /// Fence a rejected result candidate. A tombstone consumes view budget
    /// while live; once cleared, its charge is refunded only by pruning
    /// after its clearing has settled. When it cannot be stored, joins
    /// through that handle in this session could no longer be refused, so
    /// the session itself ends uncertain (`ObjectCapacity`); an ended
    /// session produces no dependents, so refunds elsewhere cannot erase a
    /// needed fence.
    fn tombstone(
        &mut self,
        domain: ObjectDomain,
        session: SessionIncarnation,
        handle: ObjectHandle,
        effects: &mut ObjectEffects,
    ) {
        if self
            .sessions
            .get(&session)
            .is_none_or(|r| r.state != SessionState::Live)
        {
            return;
        }
        if let Some(Binding::View(id)) = self.domains[&domain]
            .bindings
            .get(&(session, handle))
            .copied()
        {
            self.end_view(id, Lifetime::Retired(ObjectGap::OutputCollision), effects);
        }
        if self.ensure_view_capacity(domain).is_ok() {
            self.set_binding(domain, session, handle, Some(Binding::Tombstone));
        } else {
            self.set_binding(domain, session, handle, None);
            self.end_session_uncertain(session, ObjectGap::ObjectCapacity, effects);
        }
    }

    /// Retire a live session's own views and end it uncertain.
    fn end_session_uncertain(
        &mut self,
        s: SessionIncarnation,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
    ) {
        let Some(record) = self.sessions.get(&s) else {
            return;
        };
        if record.state != SessionState::Live {
            return;
        }
        let domain = record.domain;
        for (_, binding) in self.session_bindings(domain, s) {
            if let Binding::View(id) = binding {
                self.end_view(id, Lifetime::Retired(reason), effects);
            }
        }
        self.end_session(s, SessionEnd::Uncertain(reason), effects);
    }

    /// End every live session whose scope is compatible with `scope`;
    /// returns their handles.
    fn end_scope_sessions(
        &mut self,
        domain: ObjectDomain,
        scope: SlotScope,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
    ) -> Vec<SessionHandle> {
        let live: Vec<SessionIncarnation> = self.domains[&domain]
            .live_sessions
            .values()
            .copied()
            .collect();
        let mut handles = Vec::new();
        for s in live {
            let record = &self.sessions[&s];
            if !record.scope.compatible(scope) {
                continue;
            }
            handles.push(record.handle);
            self.end_session_uncertain(s, reason, effects);
        }
        handles
    }

    /// Retire every live view whose session scope is compatible with
    /// `scope`; sessions stay live.
    fn retire_scope(
        &mut self,
        domain: ObjectDomain,
        scope: SlotScope,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
    ) {
        for id in self.live_views(domain) {
            if self
                .session_scope(Some(self.objects[&id].session))
                .compatible(scope)
            {
                self.end_view(id, Lifetime::Retired(reason), effects);
            }
        }
    }

    /// The highest cut this domain has seen: a record ended now ended at or
    /// before it.
    fn position(&self, domain: ObjectDomain) -> u64 {
        let state = &self.domains[&domain];
        let last = state.cuts.iter().next_back().copied();
        max_opt(max_opt(state.applied, state.covered), last).unwrap_or(0)
    }

    fn mark_retired(&mut self, id: ObjectId, domain: ObjectDomain) {
        let at = self.position(domain);
        self.domains
            .get_mut(&domain)
            .expect("domain")
            .retired_views
            .push((id, at));
    }

    fn prune_all(&mut self) {
        let domains: Vec<ObjectDomain> = self.domains.keys().copied().collect();
        for domain in domains {
            self.prune_records(domain);
        }
    }

    /// Bounded pruning (spec: "prune only after affected tickets
    /// settle/invalidate and the closed frontier excludes re-entry"). A
    /// retired view, ended session or cleared tombstone charge is removed and
    /// refunded only when replay has passed the position at which it ended,
    /// no unsettled ticket began at or before that position, no pending
    /// origin snapshot references it, and no key-history retention holds
    /// it. Live views, live sessions and live tombstones are never
    /// pruned. Every record of an ended domain is eligible. Pruning runs
    /// lazily, only under capacity pressure, so the projection keeps
    /// retired history until a budget needs the room. IDs are never reused.
    fn prune_records(&mut self, domain: ObjectDomain) {
        let Some(state) = self.domains.get(&domain) else {
            return;
        };
        let ended = state.ended.is_some();
        let applied = state.applied;
        let mut blocker: Option<u64> = None;
        let mut views_ref: BTreeSet<ObjectId> = BTreeSet::new();
        let mut sessions_ref: BTreeSet<SessionIncarnation> = BTreeSet::new();
        for token in state.keys.values() {
            let call = &self.pending[token];
            if call.fenced {
                continue;
            }
            if !call.end_applied {
                blocker = Some(blocker.map_or(call.begin, |b| b.min(call.begin)));
            }
            if let Some(s) = call.snapshot.session {
                sessions_ref.insert(s);
            }
            for origin in call.snapshot.inputs {
                if let OriginState::Settled(id) = origin {
                    views_ref.insert(id);
                }
            }
        }
        let eligible =
            |at: u64| ended || (applied.is_some_and(|a| at <= a) && blocker.is_none_or(|b| at < b));
        let key = domain.instance_key();
        let state = self.domains.get_mut(&domain).expect("domain");
        let views = std::mem::take(&mut state.retired_views);
        let tombs = std::mem::take(&mut state.cleared_tombstones);
        let sessions = std::mem::take(&mut state.ended_sessions);

        let mut keep_views = Vec::new();
        for (id, at) in views {
            // A key-history retention holds the referent inline:
            // capacity pressure keeps the pinned original and the
            // newcomer refuses visibly (ObjectCapacity), never the
            // reverse.
            let key_retained = self.objects.get(&id).is_some_and(|view| view.key_retained);
            if !eligible(at) || views_ref.contains(&id) || key_retained {
                keep_views.push((id, at));
                continue;
            }
            if let Some(view) = self.objects.remove(&id) {
                if let Some(usage) = self.instances.get_mut(&key) {
                    usage.views = usage.views.saturating_sub(1);
                }
                if let Some(record) = self.sessions.get_mut(&view.session) {
                    record.views = record.views.saturating_sub(1);
                }
                self.pruned_objects = self.pruned_objects.saturating_add(1);
            }
        }
        let mut keep_tombs = Vec::new();
        for at in tombs {
            if !eligible(at) {
                keep_tombs.push(at);
                continue;
            }
            self.tombstone_charges = self.tombstone_charges.saturating_sub(1);
            if let Some(usage) = self.instances.get_mut(&key) {
                usage.views = usage.views.saturating_sub(1);
            }
            self.refunded_tombstones = self.refunded_tombstones.saturating_add(1);
        }
        let mut keep_sessions = Vec::new();
        for (s, at) in sessions {
            let Some(record) = self.sessions.get(&s) else {
                continue;
            };
            let removable = eligible(at)
                && !sessions_ref.contains(&s)
                && record.views == 0
                && record.state != SessionState::Live;
            if removable {
                self.sessions.remove(&s);
                self.pruned_sessions = self.pruned_sessions.saturating_add(1);
            } else {
                keep_sessions.push((s, at));
            }
        }
        let state = self.domains.get_mut(&domain).expect("domain");
        state.retired_views = keep_views;
        state.cleared_tombstones = keep_tombs;
        state.ended_sessions = keep_sessions;
    }

    /// End one live view's binding with a finite lifetime state.
    fn end_view(&mut self, id: ObjectId, lifetime: Lifetime, effects: &mut ObjectEffects) {
        let Some(view) = self.objects.get_mut(&id) else {
            return;
        };
        if view.lifetime != Lifetime::Live {
            return;
        }
        view.lifetime = lifetime;
        let (domain, session, handle) = (view.domain, view.session, view.handle);
        self.mark_retired(id, domain);
        self.mark_deferred_lost(id);
        effects.push(match lifetime {
            Lifetime::Retired(reason) => ObjectEffect::Retired { object: id, reason },
            Lifetime::AccessEnded(reason) => ObjectEffect::AccessEnded { object: id, reason },
            Lifetime::Destroyed | Lifetime::Live => ObjectEffect::AccessEnded {
                object: id,
                reason: ObjectGap::SessionClosed,
            },
        });
        if self.domains[&domain].bindings.get(&(session, handle)) == Some(&Binding::View(id)) {
            self.set_binding(domain, session, handle, None);
        }
    }

    fn destroy_view(&mut self, call: CallToken, id: ObjectId, effects: &mut ObjectEffects) {
        let Some(view) = self.objects.get_mut(&id) else {
            return;
        };
        if view.lifetime != Lifetime::Live {
            return;
        }
        view.lifetime = Lifetime::Destroyed;
        let (domain, session, handle) = (view.domain, view.session, view.handle);
        self.mark_retired(id, domain);
        self.mark_deferred_lost(id);
        effects.push(ObjectEffect::Destroyed { call, object: id });
        if self.domains[&domain].bindings.get(&(session, handle)) == Some(&Binding::View(id)) {
            self.set_binding(domain, session, handle, None);
        }
    }

    fn live_views(&self, domain: ObjectDomain) -> Vec<ObjectId> {
        self.domains[&domain]
            .bindings
            .values()
            .filter_map(|b| match b {
                Binding::View(id) => Some(*id),
                Binding::Tombstone => None,
            })
            .collect()
    }

    fn session_bindings(
        &self,
        domain: ObjectDomain,
        session: SessionIncarnation,
    ) -> Vec<(ObjectHandle, Binding)> {
        let low = (session, ObjectHandle(0));
        let high = (session, ObjectHandle(u64::MAX));
        self.domains[&domain]
            .bindings
            .range(low..=high)
            .map(|((_, h), b)| (*h, *b))
            .collect()
    }

    fn end_session(&mut self, s: SessionIncarnation, end: SessionEnd, effects: &mut ObjectEffects) {
        let Some(record) = self.sessions.get_mut(&s) else {
            return;
        };
        if record.state != SessionState::Live {
            return;
        }
        record.state = match end {
            SessionEnd::Closed => SessionState::Closed,
            SessionEnd::Uncertain(reason) => SessionState::Ended(reason),
        };
        let (domain, handle) = (record.domain, record.handle);
        self.dispose_session_deferred(s);
        let at = self.position(domain);
        self.domains
            .get_mut(&domain)
            .expect("domain")
            .ended_sessions
            .push((s, at));
        effects.push(ObjectEffect::SessionEnded { session: s, end });
        // Remaining bindings (tombstones) end with the session.
        for (h, binding) in self.session_bindings(domain, s) {
            if let Binding::View(id) = binding {
                self.end_view(id, Lifetime::Retired(ObjectGap::SessionClosed), effects);
            }
            self.set_binding(domain, s, h, None);
        }
        let state = self.domains.get_mut(&domain).expect("domain");
        if state.live_sessions.get(&handle) == Some(&s) {
            state.live_sessions.remove(&handle);
        }
        if let Some(usage) = self.instances.get_mut(&domain.instance_key()) {
            usage.live_sessions -= 1;
        }
    }

    /// Mint one deferred origin at a PENDING object END (6.07b
    /// §2.1–§2.2): the origin ticket, H0 position and catalog function
    /// (F1), domain and proof generation (F2), acting session
    /// incarnation or `None` (F3), and per-input frozen verdicts
    /// (F4–F6). Emits `DeferredMinted` on every mint (even with zero
    /// frozen inputs); a duplicate key mints nothing and resolves
    /// `AmbiguousOutcome` instead (first wins).
    fn mint_deferred(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        session: Option<SessionIncarnation>,
        interference: Option<ObjectGap>,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) {
        // F4 key-use rule, per arm exactly as the Ok path: creation
        // freezes a use only for derive/unwrap; access freezes a use
        // for Access/OperationImport except GetObjectSize; destroy,
        // find and attributes never freeze a key use.
        let key_use = match call.kind {
            CallKind::Object(action) => match creation_family(action) {
                Some(CreationFamily::Derive | CreationFamily::Unwrap) => true,
                Some(_) => false,
                None => {
                    matches!(action, ObjectAction::Access | ObjectAction::OperationImport)
                        && !is_function(call.function, "C_GetObjectSize")
                }
            },
            _ => false,
        };
        let mut inputs = [DeferredInput::Absent; 2];
        if let Some(s) = session {
            for (index, slot) in inputs.iter_mut().enumerate() {
                *slot = match call.snapshot.inputs[index] {
                    OriginState::Absent => DeferredInput::Absent,
                    OriginState::Unproven(reason) => DeferredInput::Unproven(reason),
                    OriginState::Settled(id) => match call.inputs[index] {
                        HandleInput::Value(handle)
                            if self.domains[&call.domain].bindings.get(&(s, handle))
                                == Some(&Binding::View(id)) =>
                        {
                            match self.objects.get(&id) {
                                Some(view) => DeferredInput::Frozen {
                                    object: id,
                                    key_use,
                                    metadata: Self::metadata_flags_of(view),
                                    label: view.label(),
                                    attribution_valid: view.attribution
                                        == super::Attribution::Valid,
                                    lost: false,
                                },
                                // The binding names a view the model no
                                // longer holds: nothing to freeze.
                                None => DeferredInput::Unproven(ObjectGap::StaleOrigin),
                            }
                        }
                        _ => DeferredInput::Unproven(ObjectGap::StaleOrigin),
                    },
                    // F6: the deferred mint NEVER first-observes — no
                    // `alloc_view` here, however the Ok path reads.
                    OriginState::Deferred => {
                        DeferredInput::Unproven(ObjectGap::PendingResultUnavailable)
                    }
                };
            }
            // F5: the mint runs the interference verdict the Pending
            // arm skips; any gap voids every non-absent input.
            if let Some(gap) = interference {
                for slot in inputs.iter_mut() {
                    if !matches!(slot, DeferredInput::Absent) {
                        *slot = DeferredInput::Unproven(gap);
                    }
                }
            }
        }
        let Some(s) = session else {
            // F3: no incarnation key exists, so no record is stored.
            // Unknown stays unknown, explicitly.
            effects.push(ObjectEffect::DeferredMinted { call: token });
            return;
        };
        if self.deferred_pending.contains_key(&(s, call.function)) {
            // First wins: the live record stands; this origin joins
            // nothing and mints no effect of its own.
            self.unresolved(effects, token, ObjectGap::AmbiguousOutcome);
            return;
        }
        // Charge-before-insert (§§2.2/3.8): previously consumed or
        // disposed records release first, so a remint observes freed
        // budget; an exhausted budget refuses with counted evidence —
        // no record, no sequence advance, no growth.
        self.flush_deferred_releases(ledger);
        if ledger
            .charge_deferred(token.0, DEFERRED_ORIGIN_CHARGE)
            .is_err()
        {
            self.unresolved(effects, token, ObjectGap::PendingCapacity);
            return;
        }
        self.deferred_sequence = self.deferred_sequence.wrapping_add(1);
        let sequence = self.deferred_sequence;
        self.evict_deferred_if_needed(call.domain, ledger);
        self.deferred_pending.insert(
            (s, call.function),
            DeferredOrigin {
                ticket: token,
                position: call.key.admission(),
                function: call.function,
                domain: call.domain,
                generation: call.snapshot.generation,
                session: Some(s),
                inputs,
                sequence,
            },
        );
        effects.push(ObjectEffect::DeferredMinted { call: token });
    }

    /// Oldest-first deferred eviction past the per-domain combined
    /// bound (6.07b §2.2/§3.8): the model's scope for the shared S1
    /// `MAX_EDGE_PENDING` bound is the domain, whose custody never
    /// crosses to another domain. The S1 twin ends the matching
    /// originating machine Unknown; the model side disposes with
    /// capacity evidence.
    fn evict_deferred_if_needed(
        &mut self,
        domain: ObjectDomain,
        ledger: &mut super::journal::StagingLedger,
    ) {
        let bound = crate::semantics_edge::MAX_EDGE_PENDING;
        let held = self
            .deferred_pending
            .values()
            .filter(|record| record.domain == domain)
            .count()
            + self
                .deferred_detached
                .keys()
                .filter(|(held, _, _)| *held == domain)
                .count();
        if held < bound {
            return;
        }
        let oldest_pending = self
            .deferred_pending
            .iter()
            .filter(|(_, record)| record.domain == domain)
            .min_by_key(|(_, record)| record.sequence)
            .map(|(key, record)| (*key, record.sequence));
        let oldest_detached = self
            .deferred_detached
            .iter()
            .filter(|(key, _)| key.0 == domain)
            .min_by_key(|(_, detached)| detached.origin.sequence)
            .map(|(key, detached)| (*key, detached.origin.sequence));
        match (oldest_pending, oldest_detached) {
            (Some((key, pending_seq)), Some((detached_key, detached_seq))) => {
                if pending_seq <= detached_seq {
                    if let Some(record) = self.deferred_pending.remove(&key) {
                        ledger.release_deferred(record.ticket.0);
                    }
                } else if let Some(detached) = self.deferred_detached.remove(&detached_key) {
                    ledger.release_deferred(detached.origin.ticket.0);
                }
            }
            (Some((key, _)), None) => {
                if let Some(record) = self.deferred_pending.remove(&key) {
                    ledger.release_deferred(record.ticket.0);
                }
            }
            (None, Some((key, _))) => {
                if let Some(detached) = self.deferred_detached.remove(&key) {
                    ledger.release_deferred(detached.origin.ticket.0);
                }
            }
            (None, None) => return,
        }
        self.gap(ObjectGap::PendingCapacity);
    }

    /// Release the shared-budget charges of deferred records
    /// consumed or disposed without ledger access. Idempotent and
    /// exact: tickets never recycle, so each queued ticket names a
    /// charge this ledger still holds or a no-op.
    fn flush_deferred_releases(&mut self, ledger: &mut super::journal::StagingLedger) {
        for ticket in self.deferred_releases.drain(..) {
            ledger.release_deferred(ticket);
        }
    }

    /// 6.07b D1: a frozen input naming a dead view can never redeem a
    /// receipt. The record survives (its other input may be live);
    /// completion skips lost inputs. Death never re-resolves through
    /// current bindings.
    fn mark_deferred_lost(&mut self, id: ObjectId) {
        for record in self.deferred_pending.values_mut() {
            for input in record.inputs.iter_mut() {
                Self::lose_deferred_input(input, id);
            }
        }
        for detached in self.deferred_detached.values_mut() {
            for input in detached.origin.inputs.iter_mut() {
                Self::lose_deferred_input(input, id);
            }
        }
    }

    fn lose_deferred_input(input: &mut DeferredInput, id: ObjectId) {
        if let DeferredInput::Frozen { object, lost, .. } = input
            && *object == id
        {
            *lost = true;
        }
    }

    /// 6.07b D2: the acting session's death ends its deferred
    /// authority on both tables (a completion can never prove a dead
    /// origin live again); a dead non-origin holder merely floats the
    /// id it held (joinable). Session close, close-all, logout-widen
    /// retirement, finalize, exec/device loss and proof void all
    /// funnel through `end_session`, so one hook covers them.
    fn dispose_session_deferred(&mut self, s: SessionIncarnation) {
        // Disposal has no ledger access: queue each removed record's
        // ticket so its charge releases at the next mint or prune.
        let dead_pending: Vec<((SessionIncarnation, u32), u64)> = self
            .deferred_pending
            .iter()
            .filter(|((session, _), _)| *session == s)
            .map(|(key, record)| (*key, record.ticket.0))
            .collect();
        for (key, ticket) in dead_pending {
            self.deferred_pending.remove(&key);
            self.deferred_releases.push(ticket);
        }
        let dead_detached: Vec<((ObjectDomain, u32, u64), u64)> = self
            .deferred_detached
            .iter()
            .filter(|(_, detached)| detached.origin.session == Some(s))
            .map(|(key, detached)| (*key, detached.origin.ticket.0))
            .collect();
        for (key, ticket) in dead_detached {
            self.deferred_detached.remove(&key);
            self.deferred_releases.push(ticket);
        }
        for detached in self.deferred_detached.values_mut() {
            if detached.holder == Some(s) {
                detached.holder = None;
            }
        }
    }

    /// Resolve one input at completion against its begin-cut origin.
    fn join_input(
        &mut self,
        call: &PendingCall,
        token: CallToken,
        index: usize,
        session: SessionIncarnation,
        effects: &mut ObjectEffects,
    ) -> Result<Option<ObjectId>, ObjectGap> {
        let HandleInput::Value(handle) = call.inputs[index] else {
            return match call.inputs[index] {
                HandleInput::Unreadable => Err(ObjectGap::UnprovenInput),
                _ => Ok(None),
            };
        };
        let current = self.domains[&call.domain]
            .bindings
            .get(&(session, handle))
            .copied();
        match call.snapshot.inputs[index] {
            OriginState::Absent => Ok(None),
            OriginState::Unproven(reason) => Err(reason),
            OriginState::Settled(id) => {
                if current == Some(Binding::View(id)) {
                    Ok(Some(id))
                } else {
                    Err(ObjectGap::StaleOrigin)
                }
            }
            OriginState::Deferred => match current {
                Some(Binding::Tombstone) => Err(ObjectGap::DependencyBroken),
                Some(Binding::View(_)) => Err(ObjectGap::StaleOrigin),
                None => {
                    let id = self.alloc_view(
                        call.domain,
                        session,
                        handle,
                        ViewOrigin::FirstObserved,
                        Birth::Unknown,
                        [FieldState::Unknown; METADATA_FIELDS],
                        Lifetime::Live,
                    )?;
                    effects.push(ObjectEffect::FirstObserved {
                        call: token,
                        object: id,
                        session,
                    });
                    Ok(Some(id))
                }
            },
        }
    }

    fn reference(
        &mut self,
        token: CallToken,
        id: ObjectId,
        key_use: bool,
        input: Option<u8>,
        effects: &mut ObjectEffects,
    ) {
        // The metadata snapshot freezes here, at the qualified join:
        // whatever the view learns later (even before H9 assembles
        // the receipt) cannot rewrite this observation.
        let Some(view) = self.objects.get(&id) else {
            return;
        };
        let metadata = Self::metadata_flags_of(view);
        let label = view.label();
        let attribution_valid = view.attribution == super::Attribution::Valid;
        if let Some(view) = self.objects.get_mut(&id) {
            view.references = view.references.saturating_add(1);
            if key_use {
                view.key_uses = view.key_uses.saturating_add(1);
                view.key_retained = true;
            }
            effects.push(ObjectEffect::Referenced {
                call: token,
                object: id,
                key_use,
                input,
                metadata,
                label,
                attribution_valid,
            });
        }
    }

    /// An invalid-handle return ends access only for the argument it
    /// names. When the argument cannot be identified, every settled input's
    /// continuity becomes uncertain instead.
    fn end_input_access(&mut self, call: &PendingCall, effects: &mut ObjectEffects) {
        let rv = call.completion.as_ref().map(|c| CkRv(c.rv));
        let present: Vec<usize> = (0..call.inputs.len())
            .filter(|i| call.inputs[*i] != HandleInput::Absent)
            .collect();
        let named = if is_function(call.function, "C_WrapKey") {
            if rv == Some(CkRv::WRAPPING_KEY_HANDLE_INVALID) {
                Some(0)
            } else if rv == Some(CkRv::KEY_HANDLE_INVALID) {
                Some(1)
            } else {
                None
            }
        } else if is_function(call.function, "C_UnwrapKey")
            && rv == Some(CkRv::UNWRAPPING_KEY_HANDLE_INVALID)
        {
            Some(0)
        } else if present.len() == 1 {
            Some(present[0])
        } else {
            None
        };
        match named {
            Some(index) => {
                if let OriginState::Settled(id) = call.snapshot.inputs[index] {
                    self.end_view(id, Lifetime::AccessEnded(ObjectGap::InvalidHandle), effects);
                }
            }
            None => {
                for origin in call.snapshot.inputs {
                    if let OriginState::Settled(id) = origin {
                        self.end_view(id, Lifetime::Retired(ObjectGap::InvalidHandle), effects);
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // object actions
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn apply_creation(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        family: CreationFamily,
        outcome: Outcome,
        session: Option<SessionIncarnation>,
        interference: Option<ObjectGap>,
        effects: &mut ObjectEffects,
    ) {
        match outcome {
            Outcome::Failed | Outcome::SessionInvalid => return,
            Outcome::InvalidHandle => {
                self.end_input_access(call, effects);
                return;
            }
            Outcome::Pending => {
                self.unresolved(effects, token, ObjectGap::PendingResultUnavailable);
                return;
            }
            Outcome::Ambiguous => {
                self.unresolved(effects, token, ObjectGap::AmbiguousOutcome);
                return;
            }
            Outcome::Ok | Outcome::Partial => {}
        }
        let Some(session) = session else {
            self.unresolved(effects, token, ObjectGap::UnprovenSession);
            return;
        };
        let completion = call.completion.as_ref().expect("completion");
        if let Some(reason) = interference {
            self.unresolved(effects, token, reason);
            if let Some(outputs) = call.known_outputs() {
                for handle in outputs {
                    self.tombstone(call.domain, session, handle, effects);
                }
            }
            return;
        }
        // Inputs: copy source is a reference; derive base/unwrapping key a use.
        if call.inputs[0] != HandleInput::Absent {
            let key_use = matches!(family, CreationFamily::Derive | CreationFamily::Unwrap);
            match self.join_input(call, token, 0, session, effects) {
                Ok(Some(id)) => self.reference(token, id, key_use, Some(0), effects),
                Ok(None) => {}
                Err(reason) => self.unresolved(effects, token, reason),
            }
        }
        let Some(authorized) = call.authorized_slots(completion) else {
            self.gap(ObjectGap::ResultProtocolUnavailable);
            effects.push(ObjectEffect::Gap {
                reason: ObjectGap::ResultProtocolUnavailable,
            });
            return;
        };
        let mut candidates: Vec<(u8, ObjectHandle)> = Vec::new();
        for (slot, ok) in authorized.iter().enumerate() {
            if !ok {
                continue;
            }
            match completion.results[slot] {
                ResultSlot::Handle(h) => candidates.push((slot as u8, h)),
                _ => self.gap_effect(effects, ObjectGap::OutputUnreadable),
            }
        }
        if candidates.len() == 2 && candidates[0].1 == candidates[1].1 {
            self.unresolved(effects, token, ObjectGap::PairDuplicate);
            self.tombstone(call.domain, session, candidates[0].1, effects);
            return;
        }
        for (slot, handle) in candidates {
            if let Some(Binding::View(old)) = self.domains[&call.domain]
                .bindings
                .get(&(session, handle))
                .copied()
            {
                self.end_view(old, Lifetime::Retired(ObjectGap::HandleReuse), effects);
            }
            let template = if family == CreationFamily::GeneratePair {
                slot as usize
            } else {
                0
            };
            let requested = requested_fields(call.requested[template].as_ref());
            let birth = Birth::Observed {
                start_ns: call.entry_ns,
                end_ns: completion.end_ns,
            };
            match self.alloc_view(
                call.domain,
                session,
                handle,
                ViewOrigin::Created(family),
                birth,
                requested,
                Lifetime::Live,
            ) {
                Ok(id) => effects.push(ObjectEffect::Created {
                    call: token,
                    slot,
                    object: id,
                    session,
                }),
                Err(reason) => {
                    self.set_binding(call.domain, session, handle, None);
                    self.unresolved(effects, token, reason);
                }
            }
        }
    }

    fn apply_destroy(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        outcome: Outcome,
        session: Option<SessionIncarnation>,
        interference: Option<ObjectGap>,
        effects: &mut ObjectEffects,
    ) {
        let Some(session) = session else {
            if outcome.may_affect() {
                // Unknown session: every compatible view may be affected.
                self.retire_aliases(
                    call.domain,
                    None,
                    SlotScope::Unknown,
                    None,
                    ObjectGap::DestroyAlias,
                    effects,
                );
            }
            return;
        };
        let target = call.snapshot.inputs[0];
        let handle = match call.inputs[0] {
            HandleInput::Value(h) => Some(h),
            _ => None,
        };
        let scope = self.session_scope(Some(session));
        let current_target = match target {
            OriginState::Settled(id)
                if handle.is_some_and(|h| {
                    self.domains[&call.domain].bindings.get(&(session, h))
                        == Some(&Binding::View(id))
                }) =>
            {
                Some(id)
            }
            _ => None,
        };
        match outcome {
            Outcome::Failed | Outcome::SessionInvalid => {}
            Outcome::InvalidHandle => {
                if let Some(id) = current_target {
                    self.end_view(id, Lifetime::AccessEnded(ObjectGap::InvalidHandle), effects);
                } else if let Some(h) = handle
                    && self.domains[&call.domain].bindings.get(&(session, h))
                        == Some(&Binding::Tombstone)
                {
                    self.set_binding(call.domain, session, h, None);
                }
            }
            Outcome::Pending | Outcome::Ambiguous => {
                if let Some(id) = current_target {
                    self.end_view(id, Lifetime::Retired(ObjectGap::AmbiguousOutcome), effects);
                }
                self.retire_aliases(
                    call.domain,
                    Some(session),
                    scope,
                    None,
                    ObjectGap::DestroyAlias,
                    effects,
                );
                self.unresolved(effects, token, ObjectGap::AmbiguousOutcome);
            }
            Outcome::Ok | Outcome::Partial => {
                if let Some(reason) = interference {
                    if let Some(id) = current_target {
                        self.end_view(id, Lifetime::Retired(reason), effects);
                    }
                    self.retire_aliases(
                        call.domain,
                        Some(session),
                        scope,
                        None,
                        ObjectGap::DestroyAlias,
                        effects,
                    );
                    self.unresolved(effects, token, reason);
                    return;
                }
                let mut target_id = current_target;
                if let Some(id) = current_target {
                    self.destroy_view(token, id, effects);
                } else if let Some(h) = handle {
                    match (
                        target,
                        self.domains[&call.domain]
                            .bindings
                            .get(&(session, h))
                            .copied(),
                    ) {
                        (OriginState::Deferred, None) => {
                            // First observed at its destruction; birth unknown.
                            match self.alloc_view(
                                call.domain,
                                session,
                                h,
                                ViewOrigin::FirstObserved,
                                Birth::Unknown,
                                [FieldState::Unknown; METADATA_FIELDS],
                                Lifetime::Destroyed,
                            ) {
                                Ok(id) => {
                                    effects.push(ObjectEffect::FirstObserved {
                                        call: token,
                                        object: id,
                                        session,
                                    });
                                    effects.push(ObjectEffect::Destroyed {
                                        call: token,
                                        object: id,
                                    });
                                    target_id = Some(id);
                                }
                                Err(reason) => self.unresolved(effects, token, reason),
                            }
                        }
                        (_, Some(Binding::Tombstone)) => {
                            self.set_binding(call.domain, session, h, None);
                            self.unresolved(effects, token, ObjectGap::DependencyBroken);
                        }
                        (_, current) => {
                            if let Some(Binding::View(id)) = current {
                                self.end_view(
                                    id,
                                    Lifetime::Retired(ObjectGap::StaleOrigin),
                                    effects,
                                );
                            }
                            self.unresolved(effects, token, ObjectGap::StaleOrigin);
                        }
                    }
                } else {
                    self.unresolved(effects, token, ObjectGap::UnprovenInput);
                }
                self.retire_aliases(
                    call.domain,
                    Some(session),
                    scope,
                    target_id,
                    ObjectGap::DestroyAlias,
                    effects,
                );
            }
        }
    }

    /// Retire views in other sessions of the exact domain whose scope is
    /// compatible, unless both they and the proven target are distinct
    /// continuous creations.
    fn retire_aliases(
        &mut self,
        domain: ObjectDomain,
        session: Option<SessionIncarnation>,
        scope: SlotScope,
        target: Option<ObjectId>,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
    ) {
        let target_created = target
            .and_then(|t| self.objects.get(&t))
            .is_some_and(ViewRecord::created);
        for id in self.live_views(domain) {
            let view = &self.objects[&id];
            if Some(view.session) == session {
                continue;
            }
            if !self.session_scope(Some(view.session)).compatible(scope) {
                continue;
            }
            if target_created && view.created() && Some(id) != target {
                continue;
            }
            self.end_view(id, Lifetime::Retired(reason), effects);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_access(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        outcome: Outcome,
        session: Option<SessionIncarnation>,
        interference: Option<ObjectGap>,
        metadata_interference: Option<bool>,
        effects: &mut ObjectEffects,
    ) {
        match outcome {
            Outcome::Failed | Outcome::SessionInvalid => return,
            Outcome::InvalidHandle => {
                self.end_input_access(call, effects);
                return;
            }
            Outcome::Pending => {
                self.unresolved(effects, token, ObjectGap::PendingResultUnavailable);
                return;
            }
            Outcome::Ambiguous => {
                self.unresolved(effects, token, ObjectGap::AmbiguousOutcome);
                return;
            }
            Outcome::Ok | Outcome::Partial => {}
        }
        let Some(session) = session else {
            self.unresolved(effects, token, ObjectGap::UnprovenSession);
            return;
        };
        if let Some(reason) = interference {
            self.unresolved(effects, token, reason);
            return;
        }
        let key_use = matches!(
            call.action(),
            Some(ObjectAction::Access | ObjectAction::OperationImport)
        ) && !is_function(call.function, "C_GetObjectSize");
        for index in 0..call.inputs.len() {
            match self.join_input(call, token, index, session, effects) {
                Ok(Some(id)) => {
                    let input = u8::try_from(index).ok();
                    self.reference(token, id, key_use, input, effects);
                    if let Some(metadata_uncertain) = metadata_interference {
                        if metadata_uncertain {
                            self.unresolved(effects, token, ObjectGap::MetadataUncertain);
                        } else if let Some(list) =
                            call.completion.as_ref().and_then(|c| c.attributes)
                        {
                            self.establish(token, id, &list, effects);
                        }
                    }
                }
                Ok(None) => {}
                Err(reason) => self.unresolved(effects, token, reason),
            }
        }
    }

    fn establish(
        &mut self,
        token: CallToken,
        id: ObjectId,
        list: &AttributeList,
        effects: &mut ObjectEffects,
    ) {
        let Some(view) = self.objects.get_mut(&id) else {
            return;
        };
        let mut established = false;
        for observation in list.observations() {
            let Some(kind) = observation.kind else {
                continue;
            };
            let index = field_index(kind);
            view.queries[index] = observation.status;
            let Some(value) = observation.value else {
                continue;
            };
            view.established[index] = match view.established[index] {
                FieldState::Unknown | FieldState::Invalidated(_) => {
                    established = true;
                    FieldState::Value(value)
                }
                FieldState::Value(old) if old == value => FieldState::Value(old),
                // Conflict, never last-writer-wins: the earlier value stays
                // as history.
                FieldState::Value(old) => {
                    effects.push(ObjectEffect::MetadataConflict {
                        call: token,
                        object: id,
                        field: kind,
                    });
                    FieldState::Conflict(Some(old))
                }
                FieldState::Conflict(earlier) => {
                    effects.push(ObjectEffect::MetadataConflict {
                        call: token,
                        object: id,
                        field: kind,
                    });
                    FieldState::Conflict(earlier)
                }
            };
        }
        if established {
            effects.push(ObjectEffect::MetadataEstablished {
                call: token,
                object: id,
            });
        }
    }

    fn invalidate_metadata(
        &mut self,
        id: ObjectId,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
    ) {
        let Some(view) = self.objects.get_mut(&id) else {
            return;
        };
        let mut changed = false;
        for field in view.established.iter_mut() {
            *field = match *field {
                FieldState::Value(v) => {
                    changed = true;
                    FieldState::Invalidated(Some(v))
                }
                FieldState::Conflict(earlier) => {
                    changed = true;
                    FieldState::Invalidated(earlier)
                }
                other => other,
            };
        }
        if changed {
            effects.push(ObjectEffect::MetadataInvalidated { object: id, reason });
        }
    }

    fn apply_set_attributes(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        outcome: Outcome,
        session: Option<SessionIncarnation>,
        interference: Option<ObjectGap>,
        effects: &mut ObjectEffects,
    ) {
        if !outcome.may_affect() {
            if outcome == Outcome::InvalidHandle {
                self.end_input_access(call, effects);
            }
            return;
        }
        let Some(session) = session else {
            self.widen_unknown_session(call, SlotScope::Unknown, effects);
            return;
        };
        let target = match call.snapshot.inputs[0] {
            OriginState::Settled(id) => Some(id),
            _ => None,
        };
        if let Some(id) = target {
            self.invalidate_metadata(id, ObjectGap::MetadataUncertain, effects);
        }
        // A mutation through this view may reach possibly aliasing views.
        let scope = self.session_scope(Some(session));
        let target_created = target
            .and_then(|t| self.objects.get(&t))
            .is_some_and(ViewRecord::created);
        for id in self.live_views(call.domain) {
            let view = &self.objects[&id];
            if view.session == session || !self.session_scope(Some(view.session)).compatible(scope)
            {
                continue;
            }
            if target_created && view.created() {
                continue;
            }
            self.invalidate_metadata(id, ObjectGap::MetadataUncertain, effects);
        }
        if outcome == Outcome::Ok && interference.is_none() {
            if let Ok(Some(id)) = self.join_input(call, token, 0, session, effects) {
                self.reference(token, id, false, Some(0), effects);
            }
        } else if let Some(reason) = interference {
            self.unresolved(effects, token, reason);
        }
    }

    fn apply_find(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        outcome: Outcome,
        session: Option<SessionIncarnation>,
        interference: Option<ObjectGap>,
        effects: &mut ObjectEffects,
    ) {
        if !outcome.success_like() {
            return;
        }
        let Some(session) = session else {
            return;
        };
        if let Some(reason) = interference {
            self.unresolved(effects, token, reason);
            return;
        }
        let FindResult::Handles { handles, truncated } =
            call.completion.as_ref().expect("completion").found
        else {
            return;
        };
        if truncated {
            self.gap_effect(effects, ObjectGap::OutputUnreadable);
        }
        let mut seen: Vec<ObjectHandle> = Vec::new();
        for handle in handles.into_iter().flatten() {
            if seen.contains(&handle) {
                self.unresolved(effects, token, ObjectGap::OutputCollision);
                continue;
            }
            seen.push(handle);
            match self.domains[&call.domain]
                .bindings
                .get(&(session, handle))
                .copied()
            {
                Some(Binding::View(id)) => self.reference(token, id, false, None, effects),
                Some(Binding::Tombstone) => {
                    self.unresolved(effects, token, ObjectGap::DependencyBroken)
                }
                None => match self.alloc_view(
                    call.domain,
                    session,
                    handle,
                    ViewOrigin::FirstObserved,
                    Birth::Unknown,
                    [FieldState::Unknown; METADATA_FIELDS],
                    Lifetime::Live,
                ) {
                    Ok(id) => {
                        effects.push(ObjectEffect::FirstObserved {
                            call: token,
                            object: id,
                            session,
                        });
                        self.reference(token, id, false, None, effects);
                    }
                    Err(reason) => self.unresolved(effects, token, reason),
                },
            }
        }
    }

    // -----------------------------------------------------------------------
    // lifecycle
    // -----------------------------------------------------------------------

    fn apply_open(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        outcome: Outcome,
        effects: &mut ObjectEffects,
    ) {
        if outcome != Outcome::Ok {
            if outcome.may_affect() {
                self.unresolved(effects, token, ObjectGap::AmbiguousOutcome);
            }
            return;
        }
        let completion = call.completion.as_ref().expect("completion");
        let HandleInput::Value(handle) = completion.session_out else {
            self.unresolved(effects, token, ObjectGap::OutputUnreadable);
            return;
        };
        if let Some(old) = self.domains[&call.domain]
            .live_sessions
            .get(&handle)
            .copied()
        {
            self.close_session(old, Some(ObjectGap::HandleReuse), None, effects);
        }
        match self.alloc_session(call.domain, handle, SessionOrigin::Opened, call.scope) {
            Ok(session) => effects.push(ObjectEffect::SessionOpened {
                call: token,
                session,
            }),
            Err(reason) => self.unresolved(effects, token, reason),
        }
    }

    /// End `s` and apply the close-scope rule to compatible views. Only a
    /// definite close (`uncertain == None`, with its call) proves destruction.
    fn close_session(
        &mut self,
        s: SessionIncarnation,
        uncertain: Option<ObjectGap>,
        call: Option<CallToken>,
        effects: &mut ObjectEffects,
    ) {
        let Some(record) = self.sessions.get(&s) else {
            return;
        };
        if record.state != SessionState::Live {
            return;
        }
        let (domain, scope) = (record.domain, record.scope);
        self.end_own_views(s, uncertain, call, effects);
        let end = match uncertain {
            None => SessionEnd::Closed,
            Some(reason) => SessionEnd::Uncertain(reason),
        };
        self.end_session(s, end, effects);
        self.close_other_views(
            domain,
            Some(s),
            scope,
            uncertain.is_none(),
            ObjectGap::CloseUncertain,
            effects,
        );
    }

    /// The closing session's own views: creator plus established
    /// token=false proves session-object destruction; otherwise access ends
    /// (or continuity is uncertain for an uncertain close).
    fn end_own_views(
        &mut self,
        s: SessionIncarnation,
        uncertain: Option<ObjectGap>,
        call: Option<CallToken>,
        effects: &mut ObjectEffects,
    ) {
        let domain = self.sessions[&s].domain;
        for (_, binding) in self.session_bindings(domain, s) {
            let Binding::View(id) = binding else {
                continue;
            };
            let view = &self.objects[&id];
            match (uncertain, call) {
                (None, Some(call)) if view.creator == Some(s) && view.token_false() => {
                    self.destroy_view(call, id, effects);
                }
                (None, _) => {
                    self.end_view(id, Lifetime::AccessEnded(ObjectGap::SessionClosed), effects)
                }
                (Some(reason), _) => self.end_view(id, Lifetime::Retired(reason), effects),
            }
        }
    }

    /// Other sessions' possibly affected views: retire uncertain unless this
    /// definite close leaves them exempt (established token=true, or created
    /// in their own session).
    fn close_other_views(
        &mut self,
        domain: ObjectDomain,
        closed: Option<SessionIncarnation>,
        scope: SlotScope,
        definite: bool,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
    ) {
        for id in self.live_views(domain) {
            let view = &self.objects[&id];
            if Some(view.session) == closed {
                continue;
            }
            if !self.session_scope(Some(view.session)).compatible(scope) {
                continue;
            }
            let exempt = definite && (view.token_true() || view.creator == Some(view.session));
            if !exempt {
                self.end_view(id, Lifetime::Retired(reason), effects);
            }
        }
    }

    fn apply_close(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        outcome: Outcome,
        session: Option<SessionIncarnation>,
        interference: Option<ObjectGap>,
        effects: &mut ObjectEffects,
    ) {
        let uncertain = match outcome {
            Outcome::Failed | Outcome::InvalidHandle => return,
            Outcome::Ok | Outcome::Partial => interference,
            Outcome::SessionInvalid => Some(ObjectGap::SessionContradiction),
            Outcome::Pending | Outcome::Ambiguous => Some(ObjectGap::AmbiguousOutcome),
        };
        match session {
            Some(s) => self.close_session(s, uncertain, Some(token), effects),
            None => {
                // An unknown session may have closed: its scope is unknown.
                if outcome.may_affect() {
                    self.widen_unknown_session(call, SlotScope::Unknown, effects);
                }
            }
        }
    }

    fn apply_close_all(
        &mut self,
        token: CallToken,
        call: &PendingCall,
        outcome: Outcome,
        effects: &mut ObjectEffects,
    ) {
        if !outcome.may_affect() {
            return;
        }
        let definite = outcome == Outcome::Ok;
        let live: Vec<SessionIncarnation> = self.domains[&call.domain]
            .live_sessions
            .values()
            .copied()
            .collect();
        for s in live {
            let scope = self.sessions[&s].scope;
            let exact =
                matches!((scope, call.scope), (SlotScope::Known(a), SlotScope::Known(b)) if a == b);
            if definite && exact {
                self.end_own_views(s, None, Some(token), effects);
                self.end_session(s, SessionEnd::Closed, effects);
            } else if scope.compatible(call.scope) {
                for (_, binding) in self.session_bindings(call.domain, s) {
                    if let Binding::View(id) = binding {
                        self.end_view(id, Lifetime::Retired(ObjectGap::CloseAllUncertain), effects);
                    }
                }
                self.end_session(
                    s,
                    SessionEnd::Uncertain(ObjectGap::CloseAllUncertain),
                    effects,
                );
            }
        }
    }

    fn apply_logout(
        &mut self,
        call: &PendingCall,
        outcome: Outcome,
        session: Option<SessionIncarnation>,
        effects: &mut ObjectEffects,
    ) {
        if !outcome.may_affect() {
            return;
        }
        let scope = self.session_scope(session);
        self.retire_scope(call.domain, scope, ObjectGap::LogoutUncertain, effects);
    }

    fn apply_finalize(
        &mut self,
        call: &PendingCall,
        outcome: Outcome,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) {
        if !outcome.may_affect() {
            return;
        }
        let lifetime = if outcome == Outcome::Ok {
            Lifetime::AccessEnded(ObjectGap::Finalize)
        } else {
            Lifetime::Retired(ObjectGap::AmbiguousOutcome)
        };
        for id in self.live_views(call.domain) {
            self.end_view(id, lifetime, effects);
        }
        self.end_domain(call.domain, ObjectGap::Finalize, effects, ledger);
    }

    // -----------------------------------------------------------------------
    // boundaries
    // -----------------------------------------------------------------------

    /// End every live session/view of a domain. An ended domain admits
    /// nothing further, so its tickets are released: any late completion is
    /// a stale token and cannot join.
    fn end_domain(
        &mut self,
        domain: ObjectDomain,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) {
        self.clear_domain(domain, reason, effects);
        for token in self.domain_calls(domain) {
            self.remove_call(token, ledger);
        }
        let state = self.domains.get_mut(&domain).expect("domain");
        state.ended = Some(reason);
        state.bootstrap = None;
    }

    fn clear_domain(
        &mut self,
        domain: ObjectDomain,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
    ) {
        for id in self.live_views(domain) {
            self.end_view(id, Lifetime::Retired(reason), effects);
        }
        let live: Vec<SessionIncarnation> = self.domains[&domain]
            .live_sessions
            .values()
            .copied()
            .collect();
        for s in live {
            self.end_session(s, SessionEnd::Uncertain(reason), effects);
        }
        let leftovers: Vec<(SessionIncarnation, ObjectHandle)> =
            self.domains[&domain].bindings.keys().copied().collect();
        for (s, h) in leftovers {
            self.set_binding(domain, s, h, None);
        }
        for token in self.domain_calls(domain) {
            self.fence(token);
        }
    }

    fn fence(&mut self, token: CallToken) {
        let Some(call) = self.pending.get_mut(&token) else {
            return;
        };
        if call.fenced || call.end_applied {
            return;
        }
        call.fenced = true;
        let domain = call.domain;
        let floor = max_opt(Some(call.begin), call.end_cut());
        if let Some(state) = self.domains.get_mut(&domain) {
            state.fence_floor = max_opt(state.fence_floor, floor);
        }
    }

    /// Proof in a domain ends: live continuity is unknown from here on.
    fn void_bootstrap(
        &mut self,
        domain: ObjectDomain,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) {
        if !self.domains.contains_key(&domain) {
            return;
        }
        for id in self.live_views(domain) {
            self.end_view(id, Lifetime::Retired(reason), effects);
        }
        let live: Vec<SessionIncarnation> = self.domains[&domain]
            .live_sessions
            .values()
            .copied()
            .collect();
        for s in live {
            self.end_session(s, SessionEnd::Uncertain(reason), effects);
        }
        let leftovers: Vec<(SessionIncarnation, ObjectHandle)> =
            self.domains[&domain].bindings.keys().copied().collect();
        for (s, h) in leftovers {
            self.set_binding(domain, s, h, None);
        }
        let max_cut = self.domains[&domain].cuts.iter().next_back().copied();
        let state = self.domains.get_mut(&domain).expect("domain");
        state.bootstrap = None;
        state.fence_floor = max_opt(
            max_opt(state.fence_floor, state.covered),
            max_opt(state.applied, max_cut),
        );
        // Never wrap: a reused generation could revive a stale snapshot.
        let Some(next) = state.generation.checked_add(1) else {
            self.gap(ObjectGap::IdExhausted);
            self.end_domain(domain, ObjectGap::IdExhausted, effects, ledger);
            return;
        };
        state.generation = next;
    }

    /// A contradicted or unrepresentable history (`reason`): downgrade every
    /// published join in the domain,
    /// retire live continuity, fence pending tickets and require a new
    /// bootstrap above everything seen.
    fn contradict(
        &mut self,
        domain: ObjectDomain,
        reason: ObjectGap,
        cut: Option<u64>,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) {
        self.gap(reason);
        let ids: Vec<ObjectId> = self
            .objects
            .iter()
            .filter(|(_, v)| v.domain == domain && v.attribution == Attribution::Valid)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some(view) = self.objects.get_mut(&id) {
                view.attribution = Attribution::Downgraded(reason);
            }
            effects.push(ObjectEffect::Downgraded { object: id, reason });
        }
        for token in self.domain_calls(domain) {
            self.fence(token);
        }
        self.void_bootstrap(domain, reason, effects, ledger);
        let state = self.domains.get_mut(&domain).expect("domain");
        state.fence_floor = max_opt(state.fence_floor, cut);
    }

    pub(super) fn invalidate(
        &mut self,
        scope: AffectedScope,
        reason: ObjectGap,
        ledger: &mut super::journal::StagingLedger,
    ) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        self.gap(reason);
        match scope {
            AffectedScope::Capture => {
                let domains: Vec<ObjectDomain> = self.domains.keys().copied().collect();
                for domain in domains {
                    self.invalidate_domain(domain, reason, &mut effects, ledger);
                }
            }
            AffectedScope::Domain(domain) => match self.held(domain) {
                Ok(()) => self.invalidate_domain(domain, reason, &mut effects, ledger),
                Err(unheld) => self.gap_effect(&mut effects, unheld),
            },
            AffectedScope::Session(domain, handle) => {
                if let Err(unheld) = self.held(domain) {
                    self.gap_effect(&mut effects, unheld);
                    return effects;
                }
                // One rule, with or without pending tickets: a session loss is
                // an uncertain close plus an uncertain destroy over its
                // compatible scope.
                let live = self.domains[&domain].live_sessions.get(&handle).copied();
                let scope = self.session_scope(live);
                if let Some(s) = live {
                    self.end_session_uncertain(s, reason, &mut effects);
                }
                self.close_other_views(domain, live, scope, false, reason, &mut effects);
                let affected: Vec<CallToken> = self
                    .domain_calls(domain)
                    .into_iter()
                    .filter(|t| {
                        let c = &self.pending[t];
                        !c.end_applied
                            && (c.session_handle() == Some(handle)
                                || c.completion
                                    .as_ref()
                                    .is_some_and(|d| d.session_out == HandleInput::Value(handle)))
                    })
                    .collect();
                self.fence_and_void(domain, affected, reason, &mut effects, ledger);
            }
            AffectedScope::Slot(domain, slot_scope) => {
                if let Err(unheld) = self.held(domain) {
                    self.gap_effect(&mut effects, unheld);
                    return effects;
                }
                let handles = self.end_scope_sessions(domain, slot_scope, reason, &mut effects);
                let affected: Vec<CallToken> = self
                    .domain_calls(domain)
                    .into_iter()
                    .filter(|t| {
                        let c = &self.pending[t];
                        !c.end_applied
                            && (c.session_handle().is_none_or(|h| handles.contains(&h))
                                || c.scope.compatible(slot_scope))
                    })
                    .collect();
                self.fence_and_void(domain, affected, reason, &mut effects, ledger);
            }
        }
        effects
    }

    fn fence_and_void(
        &mut self,
        domain: ObjectDomain,
        affected: Vec<CallToken>,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) {
        if affected.is_empty() {
            return;
        }
        for token in affected {
            self.fence(token);
        }
        // A lost ticket may have affected any compatible scope at an unknown
        // time: proof in the whole domain ends until a new bootstrap.
        self.void_bootstrap(domain, reason, effects, ledger);
    }

    fn invalidate_domain(
        &mut self,
        domain: ObjectDomain,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
        ledger: &mut super::journal::StagingLedger,
    ) {
        match reason {
            ObjectGap::Exec | ObjectGap::Fork | ObjectGap::Unload | ObjectGap::Finalize => {
                self.end_domain(domain, reason, effects, ledger);
            }
            _ => {
                self.clear_domain(domain, reason, effects);
                self.void_bootstrap(domain, reason, effects, ledger);
            }
        }
    }

    /// Unbounded-abandonment disposal for one domain: the specified
    /// abandonment-disposal path (S2). Conservative fencing is retained
    /// (every pending ticket fenced, views/sessions retired, bootstrap
    /// voided) and call storage is then released — unlike plain
    /// invalidation, which keeps fenced tickets against late terminals
    /// the abandoned frame will never deliver. Emits no disposal-bound
    /// effect: the incarnation stays refused, never rebootstrap'd above
    /// an invented cut. The journal's permanent-refusal paths call this
    /// wherever adapter custody is deleted with the refusal.
    pub(super) fn abandon_domain(
        &mut self,
        domain: ObjectDomain,
        ledger: &mut super::journal::StagingLedger,
    ) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        self.gap(ObjectGap::Loss);
        if let Err(unheld) = self.held(domain) {
            self.gap_effect(&mut effects, unheld);
            return effects;
        }
        self.clear_domain(domain, ObjectGap::Loss, &mut effects);
        for token in self.domain_calls(domain) {
            self.remove_call(token, ledger);
        }
        self.void_bootstrap(domain, ObjectGap::Loss, &mut effects, ledger);
        effects
    }

    // -----------------------------------------------------------------------
    // projection and cost
    // -----------------------------------------------------------------------

    /// A terminal outcome the producer lost, bounded by an upper cut. A
    /// lost ticket is released (freeing its pending slot) and its possible
    /// scope invalidated; an unfenced one also ends proof, since its effect
    /// time is unknown. A bound on refused begins lifts their in-flight
    /// fence. Either way a new bootstrap must lie above the bound.
    #[cfg(test)]
    pub(super) fn exhaust_generation(&mut self, domain: ObjectDomain) {
        if let Some(state) = self.domains.get_mut(&domain) {
            state.generation = u64::MAX;
        }
    }

    pub(super) fn outcome_lost(
        &mut self,
        lost: LostOutcome,
        ledger: &mut super::journal::StagingLedger,
    ) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        let (domain, upper) = match lost {
            LostOutcome::Ticket(token, upper) => {
                let Some(call) = self.pending.get(&token) else {
                    self.gap_effect(&mut effects, ObjectGap::StaleToken);
                    return effects;
                };
                // The bound must cover the ticket's own cuts.
                let own = max_opt(Some(call.begin), call.end_cut()).unwrap_or(call.begin);
                if upper.0 < own {
                    self.gap_effect(&mut effects, ObjectGap::MalformedFact);
                    return effects;
                }
                let (domain, fenced) = (call.domain, call.fenced);
                let scope = self.call_scope(call);
                if !fenced {
                    self.void_bootstrap(domain, ObjectGap::OutcomeLost, &mut effects, ledger);
                }
                self.remove_call(token, ledger);
                self.retire_scope(domain, scope, ObjectGap::OutcomeLost, &mut effects);
                (domain, upper.0)
            }
            LostOutcome::Refused(domain, upper) => {
                if let Err(unheld) = self.held(domain) {
                    self.gap_effect(&mut effects, unheld);
                    return effects;
                }
                let state = self.domains.get_mut(&domain).expect("held domain");
                if state.refused_in_flight.is_some_and(|cut| upper.0 >= cut) {
                    state.refused_in_flight = None;
                }
                (domain, upper.0)
            }
            LostOutcome::Voided(domain, upper) => {
                if let Err(unheld) = self.held(domain) {
                    self.gap_effect(&mut effects, unheld);
                    return effects;
                }
                // The void proves the interval lost, not over: in-flight
                // refusals stay until a covering bound arrives.
                self.void_bootstrap(domain, ObjectGap::OutcomeLost, &mut effects, ledger);
                (domain, upper.0)
            }
        };
        self.gap(ObjectGap::OutcomeLost);
        if let Some(state) = self.domains.get_mut(&domain) {
            state.fence_floor = max_opt(state.fence_floor, Some(upper));
        }
        effects
    }

    /// H9 metadata-at-use snapshot for one qualified key: presence
    /// bitmaps only, read by reference. Values never cross to H9
    /// (only discriminants are matched; nothing is copied out).
    /// `None` when the view is gone (a reference implies a live view
    /// at settle, so callers treat absence as unavailable metadata,
    /// never as proof of no metadata).
    pub(super) fn key_metadata_flags(&self, key: ObjectId) -> Option<super::KeyMetadataFlags> {
        self.objects.get(&key).map(Self::metadata_flags_of)
    }

    /// Presence bitmaps for one view: the shared computation behind
    /// the current-state read above and the join-time snapshot in
    /// [`Self::reference`].
    fn metadata_flags_of(view: &ViewRecord) -> super::KeyMetadataFlags {
        let mut requested = 0u8;
        let mut established = 0u8;
        let mut conflicted = 0u8;
        for index in 0..super::METADATA_FIELDS {
            let asked = !matches!(view.requested[index], FieldState::Unknown)
                || !matches!(view.queries[index], QueryStatus::NotQueried);
            let kept = matches!(
                view.established[index],
                FieldState::Value(_)
                    | FieldState::Conflict(Some(_))
                    | FieldState::Invalidated(Some(_))
            );
            let clash = matches!(
                view.requested[index],
                FieldState::Conflict(_) | FieldState::Invalidated(_)
            ) || matches!(
                view.established[index],
                FieldState::Conflict(_) | FieldState::Invalidated(_)
            );
            if asked {
                requested |= 1 << index;
            }
            if kept {
                established |= 1 << index;
            }
            if clash {
                conflicted |= 1 << index;
            }
        }
        super::KeyMetadataFlags {
            requested,
            established,
            conflicted,
        }
    }

    pub(super) fn receipt_snapshot(&self, key: ObjectId) -> Option<super::ReceiptSnapshot> {
        let view = self.objects.get(&key)?;
        Some(super::ReceiptSnapshot {
            label: view.label(),
            attribution_valid: view.attribution == super::Attribution::Valid,
            session: view.session,
        })
    }

    // -----------------------------------------------------------------------
    // 6.07b deferred async custody: seal-path (Q2) primitives. The completion
    // control quantum calls these once the journal P1 packet lands; until
    // then only tests drive them. Each refuses instead of overwriting.
    // -----------------------------------------------------------------------

    /// Move one deferred origin pending→detached (GetID mint): the
    /// record keeps its origin ticket, frozen inputs and position;
    /// custody opens under the origin session as holder. The
    /// shared-budget charge follows the origin ticket — no recharge.
    /// Refuses when no record is live, when the detached key already
    /// names a live origin (first wins), or when the origin session's
    /// slot scope is Unknown (U-4: no exact detached key exists).
    #[cfg_attr(not(test), allow(dead_code))] // First Q2 seal-path caller lands with journal P1.
    pub(super) fn detach_deferred(
        &mut self,
        session: SessionIncarnation,
        target: u32,
        value: u64,
    ) -> Result<(), DeferredRefusal> {
        let Some(record) = self.deferred_pending.get(&(session, target)).copied() else {
            return Err(DeferredRefusal::NoRecord);
        };
        if self.session_scope(Some(session)) == SlotScope::Unknown {
            return Err(DeferredRefusal::UnknownSlot);
        }
        let key = (record.domain, target, value);
        if self.deferred_detached.contains_key(&key) {
            return Err(DeferredRefusal::Occupied);
        }
        // Successful detach re-queues the record behind still-pending
        // elders (§3.1, S1 GetID order): the sequence advances only
        // here — refused detaches change nothing.
        self.deferred_sequence = self.deferred_sequence.wrapping_add(1);
        let mut record = record;
        record.sequence = self.deferred_sequence;
        self.deferred_pending.remove(&(session, target));
        self.deferred_detached.insert(
            key,
            DetachedDeferred {
                origin: record,
                holder: Some(session),
            },
        );
        Ok(())
    }

    /// Move whole detached custody to the joiner (Join transfer):
    /// origin, frozen inputs and position unchanged; the
    /// shared-budget charge follows the origin ticket. Join acquires
    /// no destination key; a missing record mutates nothing.
    #[cfg_attr(not(test), allow(dead_code))] // First Q2 seal-path caller lands with journal P1.
    pub(super) fn join_deferred_holder(
        &mut self,
        domain: ObjectDomain,
        target: u32,
        value: u64,
        joiner: SessionIncarnation,
    ) -> bool {
        match self.deferred_detached.get_mut(&(domain, target, value)) {
            Some(detached) => {
                detached.holder = Some(joiner);
                true
            }
            None => false,
        }
    }

    /// Consume one live deferred origin exactly once (Complete): emits
    /// `Referenced` effects with the ORIGIN ticket and the frozen
    /// input ordinals/objects/metadata — current view state is never
    /// consulted. Lost/absent/unproven inputs yield nothing. Removal
    /// is the once-token; a second redeem finds no record. Refuses
    /// (consuming nothing) when the origin session is not Live or the
    /// domain's generation moved on.
    #[cfg_attr(not(test), allow(dead_code))] // First Q2 seal-path caller lands with journal P1.
    pub(super) fn redeem_deferred(&mut self, ticket: CallToken) -> Option<ObjectEffects> {
        let pending_key = self
            .deferred_pending
            .iter()
            .find_map(|(key, record)| (record.ticket == ticket).then_some(*key));
        if let Some(key) = pending_key {
            if !self.redeem_legal(&self.deferred_pending[&key]) {
                return None;
            }
            let record = self.deferred_pending.remove(&key).expect("legal record");
            // Consumption has no ledger access: the charge releases
            // at the next mint or prune.
            self.deferred_releases.push(record.ticket.0);
            return Some(self.redeem_effects(&record));
        }
        let detached_key = self
            .deferred_detached
            .iter()
            .find_map(|(key, detached)| (detached.origin.ticket == ticket).then_some(*key));
        if let Some(key) = detached_key {
            if !self.redeem_legal(&self.deferred_detached[&key].origin) {
                return None;
            }
            let detached = self.deferred_detached.remove(&key).expect("legal record");
            self.deferred_releases.push(detached.origin.ticket.0);
            return Some(self.redeem_effects(&detached.origin));
        }
        None
    }

    /// A record redeems only while its frozen origin session is Live
    /// and its domain generation is current on a live domain.
    fn redeem_legal(&self, record: &DeferredOrigin) -> bool {
        let session_live = record.session.is_some_and(|s| {
            self.sessions
                .get(&s)
                .is_some_and(|record| record.state == SessionState::Live)
        });
        let domain_current = self
            .domains
            .get(&record.domain)
            .is_some_and(|state| state.ended.is_none() && state.generation == record.generation);
        session_live && domain_current
    }

    /// The completion's `Referenced` effects: origin ticket, frozen
    /// input ordinal, frozen object id, frozen metadata/label/
    /// attribution. Reference counters bump like `reference` (key
    /// history retention), but no current value is read — a redeemed
    /// reference can only repeat what the origin END froze.
    fn redeem_effects(&mut self, record: &DeferredOrigin) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        for (index, input) in record.inputs.iter().enumerate() {
            let DeferredInput::Frozen {
                object,
                key_use,
                metadata,
                label,
                attribution_valid,
                lost: false,
            } = input
            else {
                continue;
            };
            if let Some(view) = self.objects.get_mut(object) {
                view.references = view.references.saturating_add(1);
                if *key_use {
                    view.key_uses = view.key_uses.saturating_add(1);
                    view.key_retained = true;
                }
            }
            effects.push(ObjectEffect::Referenced {
                call: record.ticket,
                object: *object,
                key_use: *key_use,
                input: u8::try_from(index).ok(),
                metadata: *metadata,
                label: *label,
                attribution_valid: *attribution_valid,
            });
        }
        effects
    }

    pub(super) fn project(&self) -> ObjectProjection {
        // Access relations are derived from live bindings, not assumed.
        let mut relations: BTreeMap<ObjectId, usize> = BTreeMap::new();
        for state in self.domains.values() {
            for binding in state.bindings.values() {
                if let Binding::View(id) = binding {
                    *relations.entry(*id).or_insert(0) += 1;
                }
            }
        }
        let sessions = self
            .sessions
            .iter()
            .map(|(id, r)| SessionView {
                id: *id,
                origin: r.origin,
                scope_known: matches!(r.scope, SlotScope::Known(_)),
                state: r.state,
            })
            .collect();
        let objects = self
            .objects
            .iter()
            .map(|(id, v)| ObjectView {
                id: *id,
                session: v.session,
                origin: v.origin,
                creator: v.creator,
                birth: v.birth,
                lifetime: v.lifetime,
                attribution: v.attribution,
                references: v.references,
                key_uses: v.key_uses,
                requested: MetadataView {
                    fields: v.requested,
                },
                established: MetadataView {
                    fields: v.established,
                },
                queries: v.queries,
                label: v.label(),
                accessing_sessions: relations.get(id).copied().unwrap_or(0),
            })
            .collect();
        ObjectProjection {
            sessions,
            objects,
            gaps: self.gaps.iter().map(|(g, c)| (*g, *c)).collect(),
            usage: self.usage(),
        }
    }

    pub(super) fn audit_loss_record_counts(&self) -> (usize, usize) {
        (self.objects.len(), self.sessions.len())
    }

    pub(super) fn replay_pending_count(&self) -> usize {
        self.pending.len()
    }

    fn usage(&self) -> StateUsage {
        let live_bindings = self
            .domains
            .values()
            .map(|d| {
                d.bindings
                    .values()
                    .filter(|b| matches!(b, Binding::View(_)))
                    .count()
            })
            .sum();
        StateUsage {
            domains: self.domains.len(),
            instances: self.instances.len(),
            live_sessions: self.domains.values().map(|d| d.live_sessions.len()).sum(),
            session_records: self.sessions.len(),
            object_records: self.objects.len(),
            live_bindings,
            tombstones: self.tombstones,
            pending_calls: self.pending.len(),
            deferred_origins: self.deferred_pending.len() + self.deferred_detached.len(),
            lifetime_objects: self.next_object,
            lifetime_sessions: self.next_session,
            pruned_objects: self.pruned_objects,
            pruned_sessions: self.pruned_sessions,
            refunded_tombstones: self.refunded_tombstones,
            pruned_domains: self.pruned_domains,
        }
    }

    pub(super) fn estimate(&self) -> StateEstimate {
        let usage = self.usage();
        let object_records = usage.object_records * size_of::<(ObjectId, ViewRecord)>();
        let session_records = usage.session_records
            * size_of::<(SessionIncarnation, SessionRecord)>()
            + usage.live_sessions * size_of::<(SessionHandle, SessionIncarnation)>();
        let live_bindings = (usage.live_bindings + usage.tombstones)
            * size_of::<((SessionIncarnation, ObjectHandle), Binding)>();
        let pending_calls = usage.pending_calls
            * (size_of::<(CallToken, PendingCall)>()
                + size_of::<(CallKey, CallToken)>()
                + 2 * size_of::<u64>());
        let deferred_origins = self.deferred_pending.len()
            * size_of::<((SessionIncarnation, u32), DeferredOrigin)>()
            + self.deferred_detached.len()
                * size_of::<((ObjectDomain, u32, u64), DetachedDeferred)>();
        let prune_lists: usize = self
            .domains
            .values()
            .map(|d| {
                d.retired_views.len() * size_of::<(ObjectId, u64)>()
                    + d.ended_sessions.len() * size_of::<(SessionIncarnation, u64)>()
                    + d.cleared_tombstones.len() * size_of::<u64>()
            })
            .sum();
        let fixed = prune_lists
            + self.recently_pruned.len() * 2 * size_of::<ObjectDomain>()
            + usage.domains * size_of::<(ObjectDomain, DomainState)>()
            + usage.instances * size_of::<(InstanceKey, InstanceUsage)>()
            + self.gaps.len() * size_of::<(ObjectGap, u64)>();
        StateEstimate {
            occupied_bytes: object_records
                + session_records
                + live_bindings
                + pending_calls
                + deferred_origins
                + fixed,
            object_records,
            session_records,
            live_bindings,
            pending_calls,
            deferred_origins,
        }
    }
}

impl std::fmt::Debug for ModelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelState")
            .field("usage", &self.usage())
            .field("gaps", &self.gaps)
            .finish_non_exhaustive()
    }
}

enum SessionRes {
    Live(SessionIncarnation),
    NoSession,
    /// The acting session is unknown (unreadable, unseen with a non-success
    /// outcome, stale, or unrepresentable); carries its possible scope.
    Unknown(SlotScope),
}

fn is_function(function: u32, name: &str) -> bool {
    pkcs11_module::function_name(function as usize) == Some(name)
}

/// The existing descriptor rule: only Init slots carrying
/// `NULL_MECHANISM_CANCEL` treat a successful null mechanism as a cancel.
fn is_null_cancel_init(function: u32) -> bool {
    pkcs11_module::function_name(function as usize)
        .and_then(crate::kinds::descriptor)
        .is_some_and(|d| {
            d.transition == transition::INITIALIZE
                && d.semantic_flags & semantic_flags::NULL_MECHANISM_CANCEL != 0
        })
}

fn requested_fields(list: Option<&AttributeList>) -> [FieldState; METADATA_FIELDS] {
    let mut fields = [FieldState::Unknown; METADATA_FIELDS];
    let Some(list) = list else {
        return fields;
    };
    for observation in list.observations() {
        let (Some(kind), Some(value)) = (observation.kind, observation.value) else {
            continue;
        };
        let index = field_index(kind);
        fields[index] = match fields[index] {
            FieldState::Unknown => FieldState::Value(value),
            FieldState::Value(old) if old == value => FieldState::Value(old),
            FieldState::Value(old) => FieldState::Conflict(Some(old)),
            FieldState::Conflict(earlier) => FieldState::Conflict(earlier),
            FieldState::Invalidated(_) => FieldState::Value(value),
        };
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_ebpf_common::object_policy::SafeCurve;

    fn scalar(value: u16) -> FieldState {
        FieldState::Value(FieldValue::Scalar(value))
    }

    fn established_with(pairs: &[(SafeAttributeKind, FieldState)]) -> ViewRecord {
        let mut established = [FieldState::Unknown; METADATA_FIELDS];
        for (kind, state) in pairs {
            established[field_index(*kind)] = *state;
        }
        ViewRecord {
            domain: ObjectDomain::reference(1, 1, 1, 1, 1),
            session: SessionIncarnation(7),
            handle: ObjectHandle::new(9).unwrap(),
            origin: ViewOrigin::FirstObserved,
            creator: None,
            birth: Birth::Unknown,
            lifetime: Lifetime::Live,
            attribution: Attribution::Valid,
            references: 0,
            key_uses: 0,
            key_retained: false,
            requested: [FieldState::Unknown; METADATA_FIELDS],
            established,
            queries: [QueryStatus::NotQueried; METADATA_FIELDS],
        }
    }

    // Healthy twins: an established compatible class keeps the combined
    // label, and an unknown class does not block it.
    #[test]
    fn combined_label_healthy_class_key_pairs() {
        use SafeAttributeKind::*;
        let aes = established_with(&[
            (Class, scalar(4)),
            (KeyType, scalar(0x1f)),
            (ValueLen, scalar(16)),
        ]);
        assert_eq!(aes.label(), Some(KeyLabel::Aes { value_len: 16 }));
        let rsa = established_with(&[
            (Class, scalar(3)),
            (KeyType, scalar(0x00)),
            (ModulusBits, scalar(2048)),
        ]);
        assert_eq!(rsa.label(), Some(KeyLabel::Rsa { modulus_bits: 2048 }));
        let rsa_public = established_with(&[
            (Class, scalar(2)),
            (KeyType, scalar(0x00)),
            (ModulusBits, scalar(4096)),
        ]);
        assert_eq!(
            rsa_public.label(),
            Some(KeyLabel::Rsa { modulus_bits: 4096 })
        );
        let ec = established_with(&[
            (Class, scalar(2)),
            (KeyType, scalar(0x03)),
            (
                EcParams,
                FieldState::Value(FieldValue::Curve(SafeCurve::Secp256r1)),
            ),
        ]);
        assert_eq!(
            ec.label(),
            Some(KeyLabel::Ec {
                curve: SafeCurve::Secp256r1
            })
        );
        let unknown_class = established_with(&[(KeyType, scalar(0x1f)), (ValueLen, scalar(32))]);
        assert_eq!(unknown_class.label(), Some(KeyLabel::Aes { value_len: 32 }));
    }

    // Failure twin: a conflicting class withholds the combined label.
    #[test]
    fn combined_label_withheld_on_class_conflict() {
        use SafeAttributeKind::*;
        let conflicted = established_with(&[
            (Class, FieldState::Conflict(Some(FieldValue::Scalar(4)))),
            (KeyType, scalar(0x1f)),
            (ValueLen, scalar(16)),
        ]);
        assert_eq!(conflicted.label(), None);
    }

    // Failure twins: an established class incompatible with the key
    // type withholds the combined label (AES needs secret_key; RSA/EC
    // need public_key/private_key).
    #[test]
    fn combined_label_withheld_on_incompatible_class() {
        use SafeAttributeKind::*;
        let curve = FieldState::Value(FieldValue::Curve(SafeCurve::Secp384r1));
        for (key_type, size_kind, size, class, name) in [
            (0x1f, ValueLen, 16, 2, "aes under public_key"),
            (0x1f, ValueLen, 24, 0, "aes under data"),
            (0x00, ModulusBits, 2048, 4, "rsa under secret_key"),
            (0x00, ModulusBits, 1024, 1, "rsa under certificate"),
            (0x00, ModulusBits, 3072, 0, "rsa under data"),
        ] {
            let view = established_with(&[
                (Class, scalar(class)),
                (KeyType, scalar(key_type)),
                (size_kind, scalar(size)),
            ]);
            assert_eq!(view.label(), None, "{name}");
        }
        for (class, name) in [
            (4, "ec under secret_key"),
            (1, "ec under certificate"),
            (0, "ec under data"),
        ] {
            let view = established_with(&[
                (Class, scalar(class)),
                (KeyType, scalar(0x03)),
                (EcParams, curve),
            ]);
            assert_eq!(view.label(), None, "{name}");
        }
    }

    // ==================== 6.07b deferred-mint (userspace) ====================

    const DSESSION: u64 = 7;
    const DKEY: u64 = 9;

    struct DeferredFixture {
        state: ModelState,
        domain: ObjectDomain,
        session: SessionIncarnation,
        object: ObjectId,
        next_key: u64,
        next_token: u64,
    }

    impl DeferredFixture {
        fn new() -> Self {
            let mut state = ModelState::new(ObjectLimits::policy());
            let domain = ObjectDomain::reference(1, 1, 1, 1, 1);
            state.register_domain(domain).expect("domain registers");
            state.domains.get_mut(&domain).expect("domain").bootstrap = Some(0);
            let session = state
                .alloc_session(
                    domain,
                    SessionHandle::new(DSESSION).unwrap(),
                    SessionOrigin::Opened,
                    SlotScope::reference_known(0, 0),
                )
                .expect("session opens");
            let object = state
                .alloc_view(
                    domain,
                    session,
                    ObjectHandle::new(DKEY).unwrap(),
                    ViewOrigin::FirstObserved,
                    Birth::Unknown,
                    [FieldState::Unknown; METADATA_FIELDS],
                    Lifetime::Live,
                )
                .expect("view binds");
            // Establish an AES-128 label with valid attribution, plus
            // one requested field, so the frozen triple is nontrivial.
            let view = state.objects.get_mut(&object).expect("view");
            view.established[field_index(SafeAttributeKind::Class)] = scalar(4);
            view.established[field_index(SafeAttributeKind::KeyType)] = scalar(0x1f);
            view.established[field_index(SafeAttributeKind::ValueLen)] = scalar(16);
            view.requested[field_index(SafeAttributeKind::ValueLen)] = scalar(16);
            Self {
                state,
                domain,
                session,
                object,
                next_key: 100,
                next_token: 100,
            }
        }

        fn target(&mut self, name: &str) -> u32 {
            crate::kinds::function_id(name).expect("catalog function")
        }

        /// Drive one PENDING Access END through begin+end replay.
        fn pending_access(
            &mut self,
            session: HandleInput<SessionHandle>,
            input0: HandleInput<ObjectHandle>,
            function: u32,
        ) -> (CallToken, ObjectEffects) {
            let mut ledger = super::super::journal::StagingLedger::new();
            self.pending_access_with_ledger(session, input0, function, &mut ledger)
        }

        /// Drive one PENDING Access END through begin+end replay
        /// against a caller-held ledger, so deferred charges
        /// accumulate in it across mints.
        fn pending_access_with_ledger(
            &mut self,
            session: HandleInput<SessionHandle>,
            input0: HandleInput<ObjectHandle>,
            function: u32,
            ledger: &mut super::super::journal::StagingLedger,
        ) -> (CallToken, ObjectEffects) {
            self.next_key += 1;
            self.next_token += 1;
            let token = CallToken(self.next_token);
            let call = PendingCall {
                domain: self.domain,
                key: CallKey::reference(self.next_key),
                begin: 10,
                entry_ns: 100,
                function,
                kind: CallKind::Object(ObjectAction::Access),
                session,
                inputs: [input0, HandleInput::Absent],
                requested: [None, None],
                derive_protocol: DeriveResultProtocol::Unavailable,
                entry_mechanism: MechClass::Value,
                scope: SlotScope::Unknown,
                completion: Some(Completion {
                    cut: 11,
                    end_ns: 110,
                    rv: CkRv::PENDING.0,
                    return_mechanism: MechanismEvidence::NotCaptured,
                    results: [ResultSlot::NotCaptured, ResultSlot::NotCaptured],
                    session_out: HandleInput::Absent,
                    found: FindResult::NotCaptured,
                    attributes: None,
                    malformed: false,
                }),
                fenced: false,
                begin_applied: false,
                end_applied: false,
                snapshot: EMPTY_SNAPSHOT,
            };
            self.state.pending.insert(token, call);
            self.state.apply_begin(token);
            let mut effects = ObjectEffects::default();
            self.state.apply_end(token, &mut effects, ledger);
            (token, effects)
        }

        fn minted(effects: &ObjectEffects, token: CallToken) -> bool {
            effects
                .effects
                .contains(&ObjectEffect::DeferredMinted { call: token })
        }
    }

    // F1–F4: a qualified PENDING END with a settled input freezes the
    // origin ticket, position, function, domain, generation, session
    // and the reference-grade metadata/label/attribution triple.
    #[test]
    fn deferred_mint_freezes_qualified_inputs() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let before = fx.state.objects.len();
        let (token, effects) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        assert!(DeferredFixture::minted(&effects, token), "mint effect");
        let record = fx
            .state
            .deferred_pending
            .get(&(fx.session, target))
            .expect("record stored under (origin session, target)");
        assert_eq!(record.ticket, token);
        assert_eq!(record.position, fx.state.pending[&token].key.admission());
        assert_eq!(record.function, target);
        assert_eq!(record.domain, fx.domain);
        assert_eq!(record.generation, fx.state.domains[&fx.domain].generation);
        assert_eq!(record.session, Some(fx.session));
        let view = fx.state.objects[&fx.object].clone();
        match record.inputs[0] {
            DeferredInput::Frozen {
                object,
                key_use,
                metadata,
                label,
                attribution_valid,
                lost,
            } => {
                assert_eq!(object, fx.object);
                assert!(key_use, "access input is a key use");
                assert_eq!(metadata, ModelState::metadata_flags_of(&view));
                assert_eq!(label, view.label());
                assert_eq!(label, Some(super::KeyLabel::Aes { value_len: 16 }));
                assert!(attribution_valid);
                assert!(!lost);
            }
            other => panic!("input 0 freezes, got {other:?}"),
        }
        assert_eq!(record.inputs[1], DeferredInput::Absent);
        assert_eq!(fx.state.objects.len(), before, "mint allocates nothing");
        assert_eq!(fx.state.usage().deferred_origins, 1);
    }

    // F6: the deferred mint NEVER first-observes: a Deferred (unbound
    // at cut) input freezes Unproven, and no view is allocated.
    #[test]
    fn deferred_mint_never_first_observes() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let before = fx.state.objects.len();
        let (token, effects) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(0xBEEF).unwrap()),
            target,
        );
        assert!(DeferredFixture::minted(&effects, token), "mint effect");
        let record = fx
            .state
            .deferred_pending
            .get(&(fx.session, target))
            .expect("record stored");
        assert_eq!(
            record.inputs[0],
            DeferredInput::Unproven(ObjectGap::PendingResultUnavailable)
        );
        assert_eq!(fx.state.objects.len(), before, "no first-observed view");
    }

    // F6: a Settled snapshot whose binding changed before the END
    // freezes Unproven(StaleOrigin), never the replacement.
    #[test]
    fn deferred_mint_stale_binding_yields_unproven() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        fx.next_key += 1;
        fx.next_token += 1;
        let token = CallToken(fx.next_token);
        let call = PendingCall {
            domain: fx.domain,
            key: CallKey::reference(fx.next_key),
            begin: 10,
            entry_ns: 100,
            function: target,
            kind: CallKind::Object(ObjectAction::Access),
            session: HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            inputs: [
                HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
                HandleInput::Absent,
            ],
            requested: [None, None],
            derive_protocol: DeriveResultProtocol::Unavailable,
            entry_mechanism: MechClass::Value,
            scope: SlotScope::Unknown,
            completion: Some(Completion {
                cut: 11,
                end_ns: 110,
                rv: CkRv::PENDING.0,
                return_mechanism: MechanismEvidence::NotCaptured,
                results: [ResultSlot::NotCaptured, ResultSlot::NotCaptured],
                session_out: HandleInput::Absent,
                found: FindResult::NotCaptured,
                attributes: None,
                malformed: false,
            }),
            fenced: false,
            begin_applied: false,
            end_applied: false,
            snapshot: EMPTY_SNAPSHOT,
        };
        fx.state.pending.insert(token, call);
        fx.state.apply_begin(token);
        assert_eq!(
            fx.state.pending[&token].snapshot.inputs[0],
            OriginState::Settled(fx.object),
            "begin settles the input"
        );
        // The binding changes before the END (close/destroy/recreate).
        fx.state.set_binding(
            fx.domain,
            fx.session,
            ObjectHandle::new(DKEY).unwrap(),
            None,
        );
        let mut effects = ObjectEffects::default();
        let mut ledger = super::super::journal::StagingLedger::new();
        fx.state.apply_end(token, &mut effects, &mut ledger);
        assert!(DeferredFixture::minted(&effects, token), "mint effect");
        let record = fx
            .state
            .deferred_pending
            .get(&(fx.session, target))
            .expect("record stored");
        assert_eq!(
            record.inputs[0],
            DeferredInput::Unproven(ObjectGap::StaleOrigin)
        );
    }

    // F3: an Unknown/NoSession resolution mints the effect but stores
    // no record (no incarnation key exists): permanently unknown.
    #[test]
    fn deferred_mint_unknown_session_stores_nothing() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (token, effects) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(0x0BAD).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        assert!(DeferredFixture::minted(&effects, token), "mint effect");
        assert!(
            fx.state.deferred_pending.is_empty(),
            "no incarnation, no record"
        );
        assert_eq!(fx.state.usage().deferred_origins, 0);
        assert!(
            fx.state.redeem_deferred(token).is_none(),
            "nothing to redeem"
        );
    }

    // Duplicate PENDING for a live (session, target): first wins, the
    // second joins nothing (AmbiguousOutcome), no second record.
    #[test]
    fn deferred_mint_duplicate_key_keeps_first() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let session = HandleInput::Value(SessionHandle::new(DSESSION).unwrap());
        let input = HandleInput::Value(ObjectHandle::new(DKEY).unwrap());
        let (first, _) = fx.pending_access(session, input, target);
        let (second, effects) = fx.pending_access(session, input, target);
        assert!(!DeferredFixture::minted(&effects, second), "no second mint");
        assert!(
            effects.effects.contains(&ObjectEffect::Unresolved {
                call: second,
                reason: ObjectGap::AmbiguousOutcome,
            }),
            "second join stays unknown"
        );
        assert_eq!(fx.state.deferred_pending.len(), 1);
        assert_eq!(
            fx.state.deferred_pending[&(fx.session, target)].ticket,
            first
        );
    }

    // D1: object death marks frozen inputs lost; redeem skips them.
    #[test]
    fn deferred_death_object_marks_lost() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (token, _) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        let mut effects = ObjectEffects::default();
        fx.state.destroy_view(token, fx.object, &mut effects);
        let record = fx
            .state
            .deferred_pending
            .get(&(fx.session, target))
            .expect("record survives object death");
        assert!(
            matches!(record.inputs[0], DeferredInput::Frozen { lost: true, .. }),
            "frozen input lost"
        );
        let redeemed = fx
            .state
            .redeem_deferred(token)
            .expect("consumption still runs once");
        assert!(
            !redeemed
                .effects
                .iter()
                .any(|e| matches!(e, ObjectEffect::Referenced { .. })),
            "lost inputs yield no receipt"
        );
        assert!(fx.state.deferred_pending.is_empty());
    }

    // D2: acting-session death disposes the record on both tables.
    #[test]
    fn deferred_death_session_disposes() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (token, _) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        fx.state
            .detach_deferred(fx.session, target, 42)
            .expect("detaches while live");
        assert_eq!(fx.state.usage().deferred_origins, 1);
        let mut effects = ObjectEffects::default();
        fx.state
            .close_session(fx.session, None, Some(token), &mut effects);
        assert!(
            fx.state.deferred_pending.is_empty() && fx.state.deferred_detached.is_empty(),
            "acting-session death disposes deferred custody"
        );
        assert!(
            fx.state.redeem_deferred(token).is_none(),
            "no redeem after session death"
        );
    }

    // D2 (holder): a non-origin holder's death floats the id (holder
    // None, joinable); the origin record survives.
    #[test]
    fn deferred_death_holder_floats() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (token, _) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        fx.state
            .detach_deferred(fx.session, target, 42)
            .expect("detaches while live");
        let joiner = fx
            .state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 1).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("joiner session opens");
        assert!(fx.state.join_deferred_holder(fx.domain, target, 42, joiner));
        let mut effects = ObjectEffects::default();
        fx.state
            .close_session(joiner, None, Some(token), &mut effects);
        let detached = fx
            .state
            .deferred_detached
            .get(&(fx.domain, target, 42))
            .expect("record survives holder death");
        assert_eq!(detached.holder, None, "holder floats, still joinable");
        assert_eq!(detached.origin.ticket, token);
    }

    // D3: domain end disposes every deferred record of the domain.
    #[test]
    fn deferred_death_domain_disposes() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (token, _) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        assert_eq!(fx.state.usage().deferred_origins, 1);
        let mut effects = ObjectEffects::default();
        let mut ledger = super::super::journal::StagingLedger::new();
        fx.state
            .end_domain(fx.domain, ObjectGap::Finalize, &mut effects, &mut ledger);
        assert!(
            fx.state.deferred_pending.is_empty() && fx.state.deferred_detached.is_empty(),
            "domain end disposes deferred custody"
        );
        assert!(
            fx.state.redeem_deferred(token).is_none(),
            "no redeem after domain end"
        );
    }

    // R2-D3-7: one domain holds at most 256 deferred records;
    // oldest-first eviction disposes the rest with evidence.
    #[test]
    fn deferred_pressure_evicts_oldest_first() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let mut first_session = None;
        for index in 0..257u64 {
            let word = 1000 + index;
            let session = fx
                .state
                .alloc_session(
                    fx.domain,
                    SessionHandle::new(word).unwrap(),
                    SessionOrigin::Opened,
                    SlotScope::reference_known(0, 0),
                )
                .expect("session opens");
            if index == 0 {
                first_session = Some(session);
            }
            fx.pending_access(
                HandleInput::Value(SessionHandle::new(word).unwrap()),
                HandleInput::Absent,
                target,
            );
        }
        assert_eq!(fx.state.deferred_pending.len(), 256);
        assert_eq!(fx.state.usage().deferred_origins, 256);
        assert!(
            !fx.state
                .deferred_pending
                .contains_key(&(first_session.unwrap(), target)),
            "oldest evicted first"
        );
        assert_eq!(fx.state.gaps.get(&ObjectGap::PendingCapacity), Some(&1));
    }

    // Mixed pending/detached oldest-first order (§§2.2/3.8): detach
    // re-queues the record behind still-pending elders, exactly like
    // S1 — queue A, queue B, detach A, then 255 pendings evicts B on
    // both sides, never the detached A.
    #[test]
    fn deferred_mixed_pending_detached_eviction_matches_s1_order() {
        use crate::semantics_edge::{EdgeSemantics, SemanticCall};

        // S1 reference: the same trace on the real edge reducer.
        let mut edge = EdgeSemantics::default();
        let s1_target = crate::kinds::function_id("C_SignInit").unwrap();
        let s1_call = |function: &str, session: u64, rv: u64| SemanticCall {
            function: function.into(),
            session,
            rv,
            ..SemanticCall::default()
        };
        edge.observe(&s1_call("C_OpenSession", 7, CkRv::OK.0));
        edge.observe(&s1_call("C_SignInit", 7, CkRv::PENDING.0));
        edge.observe(&s1_call("C_SignInit", 8, CkRv::PENDING.0));
        let mut get_id = s1_call("C_AsyncGetID", 7, CkRv::OK.0);
        get_id.target_function = s1_target;
        get_id.async_value = 42;
        edge.observe(&get_id);
        for index in 0..255u64 {
            edge.observe(&s1_call("C_SignInit", 1000 + index, CkRv::PENDING.0));
        }
        // S1 evicts the still-pending B (255 new pendings survive, the
        // detached A survives): the order the model must match.
        assert_eq!(edge.resource_usage().pending_calls, 255);
        assert_eq!(edge.resource_usage().detached_calls, 1);
        assert_eq!(edge.evidence().async_evictions, 1);

        // Model twin: A on the fixture session, B on a second session.
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (token_a, effects_a) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Absent,
            target,
        );
        assert!(DeferredFixture::minted(&effects_a, token_a));
        let session_b = fx
            .state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 1).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("B session opens");
        let (token_b, effects_b) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION + 1).unwrap()),
            HandleInput::Absent,
            target,
        );
        assert!(DeferredFixture::minted(&effects_b, token_b));
        fx.state
            .detach_deferred(fx.session, target, 42)
            .expect("A detaches");
        let seq_a = fx.state.deferred_detached[&(fx.domain, target, 42)]
            .origin
            .sequence;
        let seq_b = fx.state.deferred_pending[&(session_b, target)].sequence;
        assert!(
            seq_a > seq_b,
            "detached A re-queues behind still-pending B (S1 GetID order)"
        );
        for index in 0..255u64 {
            let word = 1000 + index;
            fx.state
                .alloc_session(
                    fx.domain,
                    SessionHandle::new(word).unwrap(),
                    SessionOrigin::Opened,
                    SlotScope::reference_known(0, 0),
                )
                .expect("session opens");
            fx.pending_access(
                HandleInput::Value(SessionHandle::new(word).unwrap()),
                HandleInput::Absent,
                target,
            );
        }
        assert_eq!(fx.state.deferred_pending.len(), 255);
        assert_eq!(fx.state.deferred_detached.len(), 1);
        assert!(
            !fx.state.deferred_pending.contains_key(&(session_b, target)),
            "model evicts B, the oldest still-pending record"
        );
        assert!(
            fx.state
                .deferred_detached
                .contains_key(&(fx.domain, target, 42)),
            "model keeps the detached A"
        );
        assert_eq!(fx.state.gaps.get(&ObjectGap::PendingCapacity), Some(&1));
        assert_eq!(
            (
                edge.resource_usage().pending_calls,
                edge.resource_usage().detached_calls
            ),
            (
                fx.state.deferred_pending.len(),
                fx.state.deferred_detached.len()
            ),
            "model and S1 retain the same survivor shape"
        );
    }

    // Charge-before-insert (§§2.2/3.8): each deferred record holds
    // a real shared-budget charge for its whole lifetime. An
    // exhausted budget refuses the mint with counted evidence —
    // no record, no sequence advance, no growth.
    #[test]
    fn deferred_mint_exhausted_budget_refuses_without_growth() {
        let mut fx = DeferredFixture::new();
        let mut ledger = super::super::journal::StagingLedger::new();
        let target = fx.target("C_SignInit");
        let (token_a, effects_a) = fx.pending_access_with_ledger(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
            &mut ledger,
        );
        assert!(DeferredFixture::minted(&effects_a, token_a));
        fx.state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 1).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("B session opens");
        let (token_b, effects_b) = fx.pending_access_with_ledger(
            HandleInput::Value(SessionHandle::new(DSESSION + 1).unwrap()),
            HandleInput::Absent,
            target,
            &mut ledger,
        );
        assert!(DeferredFixture::minted(&effects_b, token_b));
        assert_eq!(fx.state.usage().deferred_origins, 2);
        let full = ledger.charged_bytes();
        assert!(full > 0, "two mints hold real shared-budget charges");
        ledger.set_byte_limit(full);
        fx.state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 2).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("C session opens");
        let sequence_before = fx.state.deferred_sequence;
        let (token_c, effects_c) = fx.pending_access_with_ledger(
            HandleInput::Value(SessionHandle::new(DSESSION + 2).unwrap()),
            HandleInput::Absent,
            target,
            &mut ledger,
        );
        assert!(
            !DeferredFixture::minted(&effects_c, token_c),
            "exhausted mint stores no record"
        );
        assert!(
            effects_c.effects.contains(&ObjectEffect::Unresolved {
                call: token_c,
                reason: ObjectGap::PendingCapacity,
            }),
            "exhausted mint counts capacity evidence"
        );
        assert_eq!(fx.state.usage().deferred_origins, 2);
        assert_eq!(ledger.charged_bytes(), full, "refused mint grows nothing");
        assert_eq!(
            fx.state.deferred_sequence, sequence_before,
            "refused mint advances nothing"
        );
        assert_eq!(fx.state.gaps.get(&ObjectGap::PendingCapacity), Some(&1));
    }

    // The charge moves with the record across detach/Join (same
    // origin ticket, no recharge) and releases on consumption,
    // readmitting one remint under a capped budget.
    #[test]
    fn deferred_charge_moves_with_record_and_releases_on_consume() {
        let mut fx = DeferredFixture::new();
        let mut ledger = super::super::journal::StagingLedger::new();
        let target = fx.target("C_SignInit");
        let (token_a, effects_a) = fx.pending_access_with_ledger(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
            &mut ledger,
        );
        assert!(DeferredFixture::minted(&effects_a, token_a));
        fx.state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 1).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("B session opens");
        let (token_b, effects_b) = fx.pending_access_with_ledger(
            HandleInput::Value(SessionHandle::new(DSESSION + 1).unwrap()),
            HandleInput::Absent,
            target,
            &mut ledger,
        );
        assert!(DeferredFixture::minted(&effects_b, token_b));
        let full = ledger.charged_bytes();
        assert!(full > 0, "two mints hold real shared-budget charges");
        assert_eq!(
            ledger.roles_for_test()[2],
            2,
            "both charges sit in the Model role"
        );
        ledger.set_byte_limit(full);
        fx.state
            .detach_deferred(fx.session, target, 42)
            .expect("A detaches");
        assert_eq!(
            ledger.charged_bytes(),
            full,
            "detach moves the charge, never doubles it"
        );
        assert_eq!(ledger.roles_for_test()[2], 2);
        let joiner = fx
            .state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 2).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("joiner session opens");
        assert!(fx.state.join_deferred_holder(fx.domain, target, 42, joiner));
        assert_eq!(
            ledger.charged_bytes(),
            full,
            "join moves the charge, never doubles it"
        );
        assert!(fx.state.redeem_deferred(token_a).is_some());
        fx.state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 3).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("C session opens");
        let (token_c, effects_c) = fx.pending_access_with_ledger(
            HandleInput::Value(SessionHandle::new(DSESSION + 3).unwrap()),
            HandleInput::Absent,
            target,
            &mut ledger,
        );
        assert!(
            DeferredFixture::minted(&effects_c, token_c),
            "consuming A frees its charge for one remint"
        );
        assert_eq!(fx.state.usage().deferred_origins, 2);
        assert_eq!(ledger.charged_bytes(), full);
        assert_eq!(ledger.roles_for_test()[2], 2);
    }

    // Session-death disposal releases the record's charge: a remint
    // fits under the same cap the disposed record filled.
    #[test]
    fn deferred_disposal_releases_budget_for_remint() {
        let mut fx = DeferredFixture::new();
        let mut ledger = super::super::journal::StagingLedger::new();
        let target = fx.target("C_SignInit");
        let (token_a, effects_a) = fx.pending_access_with_ledger(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
            &mut ledger,
        );
        assert!(DeferredFixture::minted(&effects_a, token_a));
        let one = ledger.charged_bytes();
        assert!(one > 0, "the mint holds a real shared-budget charge");
        ledger.set_byte_limit(one);
        let mut effects = ObjectEffects::default();
        fx.state
            .close_session(fx.session, None, Some(token_a), &mut effects);
        assert_eq!(fx.state.usage().deferred_origins, 0);
        fx.state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 1).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("B session opens");
        let (token_b, effects_b) = fx.pending_access_with_ledger(
            HandleInput::Value(SessionHandle::new(DSESSION + 1).unwrap()),
            HandleInput::Absent,
            target,
            &mut ledger,
        );
        assert!(
            DeferredFixture::minted(&effects_b, token_b),
            "disposing A frees its charge for one remint"
        );
        assert_eq!(fx.state.usage().deferred_origins, 1);
        assert_eq!(ledger.charged_bytes(), one);
    }

    // Oldest-first eviction releases the evicted record's charge:
    // 258 mints under a 257-charge cap hold exactly 256 live charges.
    #[test]
    fn deferred_eviction_releases_its_charge() {
        let mut fx = DeferredFixture::new();
        let mut ledger = super::super::journal::StagingLedger::new();
        let target = fx.target("C_SignInit");
        let (token_first, effects_first) = fx.pending_access_with_ledger(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Absent,
            target,
            &mut ledger,
        );
        assert!(DeferredFixture::minted(&effects_first, token_first));
        let one = ledger.charged_bytes();
        assert!(one > 0, "the mint holds a real shared-budget charge");
        ledger.set_byte_limit(257 * one);
        let mut first_loop_session = None;
        for index in 0..257u64 {
            let word = 1000 + index;
            let session = fx
                .state
                .alloc_session(
                    fx.domain,
                    SessionHandle::new(word).unwrap(),
                    SessionOrigin::Opened,
                    SlotScope::reference_known(0, 0),
                )
                .expect("session opens");
            if index == 0 {
                first_loop_session = Some(session);
            }
            let (token, effects) = fx.pending_access_with_ledger(
                HandleInput::Value(SessionHandle::new(word).unwrap()),
                HandleInput::Absent,
                target,
                &mut ledger,
            );
            assert!(
                DeferredFixture::minted(&effects, token),
                "mint {index} fits: eviction frees each overflow charge"
            );
        }
        assert_eq!(fx.state.usage().deferred_origins, 256);
        assert_eq!(
            ledger.charged_bytes(),
            256 * one,
            "every evicted record released its charge"
        );
        assert_eq!(ledger.roles_for_test()[2], 256);
        assert!(
            !fx.state
                .deferred_pending
                .contains_key(&(fx.session, target)),
            "oldest (fixture session) evicted first"
        );
        assert!(
            !fx.state
                .deferred_pending
                .contains_key(&(first_loop_session.unwrap(), target)),
            "second-oldest evicted second"
        );
        assert_eq!(fx.state.gaps.get(&ObjectGap::PendingCapacity), Some(&2));
    }

    // The occupancy estimate counts both deferred maps, like every
    // other retained structure. Measured across consumption (which
    // removes exactly one entry per map and touches no other
    // counted structure), so setup growth cannot leak into the delta.
    #[test]
    fn deferred_state_estimate_counts_deferred_maps() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (token_a, effects_a) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Absent,
            target,
        );
        assert!(DeferredFixture::minted(&effects_a, token_a));
        fx.state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 1).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("B session opens");
        let (token_b, effects_b) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION + 1).unwrap()),
            HandleInput::Absent,
            target,
        );
        assert!(DeferredFixture::minted(&effects_b, token_b));
        fx.state
            .detach_deferred(fx.session, target, 42)
            .expect("A detaches");
        let pending_entry = size_of::<((SessionIncarnation, u32), DeferredOrigin)>();
        let detached_entry = size_of::<((ObjectDomain, u32, u64), DetachedDeferred)>();
        let live = fx.state.estimate();
        assert_eq!(
            live.deferred_origins,
            pending_entry + detached_entry,
            "the deferred component names its bytes"
        );
        assert!(fx.state.redeem_deferred(token_a).is_some());
        assert!(fx.state.redeem_deferred(token_b).is_some());
        let consumed = fx.state.estimate();
        assert_eq!(consumed.deferred_origins, 0);
        assert_eq!(
            live.occupied_bytes - consumed.occupied_bytes,
            pending_entry + detached_entry,
            "occupied_bytes counts both deferred maps"
        );
    }

    // Full custody chain: mint → detach → join → redeem once with the
    // origin ticket and frozen inputs; no second redeem.
    #[test]
    fn deferred_detach_join_redeem_chain() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (token, _) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        fx.state
            .detach_deferred(fx.session, target, 42)
            .expect("detaches while live");
        assert!(fx.state.deferred_pending.is_empty());
        let joiner = fx
            .state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 1).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("joiner session opens");
        assert!(fx.state.join_deferred_holder(fx.domain, target, 42, joiner));
        let detached = fx.state.deferred_detached[&(fx.domain, target, 42)];
        assert_eq!(detached.holder, Some(joiner));
        assert_eq!(detached.origin.ticket, token);
        assert_eq!(detached.origin.session, Some(fx.session));
        let redeemed = fx
            .state
            .redeem_deferred(token)
            .expect("live record redeems once");
        let refs: Vec<_> = redeemed
            .effects
            .iter()
            .filter_map(|effect| match effect {
                ObjectEffect::Referenced {
                    call,
                    object,
                    key_use,
                    input,
                    metadata,
                    label,
                    attribution_valid,
                } => Some((
                    *call,
                    *object,
                    *key_use,
                    *input,
                    *metadata,
                    *label,
                    *attribution_valid,
                )),
                _ => None,
            })
            .collect();
        assert_eq!(refs.len(), 1, "one frozen input redeems one reference");
        let (call, object, key_use, input, metadata, label, valid) = refs[0];
        assert_eq!(call, token, "origin ticket, never the completion's");
        assert_eq!(object, fx.object);
        assert!(key_use);
        assert_eq!(input, Some(0), "holes stay holes");
        let view = fx.state.objects[&fx.object].clone();
        assert_eq!(metadata, ModelState::metadata_flags_of(&view));
        assert_eq!(label, Some(super::KeyLabel::Aes { value_len: 16 }));
        assert!(valid);
        assert!(fx.state.deferred_detached.is_empty());
        assert!(
            fx.state.redeem_deferred(token).is_none(),
            "removal is the once-token"
        );
    }

    // U-4 + first-wins: an occupied detached key refuses the second
    // mint, and an Unknown slot scope refuses to detach at all.
    #[test]
    fn deferred_detach_refuses_occupied_and_unknown_slot() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (first, _) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        fx.state
            .detach_deferred(fx.session, target, 42)
            .expect("first detaches");
        let other = fx
            .state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 1).unwrap(),
                SessionOrigin::Opened,
                SlotScope::reference_known(0, 0),
            )
            .expect("second session opens");
        let (second, _) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION + 1).unwrap()),
            HandleInput::Absent,
            target,
        );
        let sequence_before_refusals = fx.state.deferred_sequence;
        assert_eq!(
            fx.state.detach_deferred(other, target, 42),
            Err(DeferredRefusal::Occupied),
            "same-key remint refuses, first intact"
        );
        assert_eq!(
            fx.state.deferred_sequence, sequence_before_refusals,
            "refused detach advances no sequence"
        );
        assert_eq!(
            fx.state.deferred_detached[&(fx.domain, target, 42)]
                .origin
                .ticket,
            first
        );
        assert!(
            fx.state.deferred_pending.contains_key(&(other, target)),
            "refused mint keeps its pending"
        );
        assert!(fx.state.redeem_deferred(second).is_some());
        // Unknown slot scope: no exact detached key exists.
        let floating = fx
            .state
            .alloc_session(
                fx.domain,
                SessionHandle::new(DSESSION + 2).unwrap(),
                SessionOrigin::FirstObserved,
                SlotScope::Unknown,
            )
            .expect("unknown-scope session opens");
        fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION + 2).unwrap()),
            HandleInput::Absent,
            target,
        );
        // The floating mint above advanced the sequence; the refused
        // detach below must not.
        let sequence_before_unknown_slot = fx.state.deferred_sequence;
        assert_eq!(
            fx.state.detach_deferred(floating, target, 43),
            Err(DeferredRefusal::UnknownSlot)
        );
        assert_eq!(
            fx.state.deferred_sequence, sequence_before_unknown_slot,
            "refused detach advances no sequence"
        );
    }

    // Mint-before-dispatch ordering: a destroy-PENDING freezes its
    // target first, then the existing Pending arm retires it — the
    // record survives with the input lost (D1), never rebound.
    #[test]
    fn deferred_mint_destroy_pending_freezes_then_loses() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_DestroyObject");
        fx.next_key += 1;
        fx.next_token += 1;
        let token = CallToken(fx.next_token);
        let call = PendingCall {
            domain: fx.domain,
            key: CallKey::reference(fx.next_key),
            begin: 10,
            entry_ns: 100,
            function: target,
            kind: CallKind::Object(ObjectAction::Destroy),
            session: HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            inputs: [
                HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
                HandleInput::Absent,
            ],
            requested: [None, None],
            derive_protocol: DeriveResultProtocol::Unavailable,
            entry_mechanism: MechClass::Value,
            scope: SlotScope::Unknown,
            completion: Some(Completion {
                cut: 11,
                end_ns: 110,
                rv: CkRv::PENDING.0,
                return_mechanism: MechanismEvidence::NotCaptured,
                results: [ResultSlot::NotCaptured, ResultSlot::NotCaptured],
                session_out: HandleInput::Absent,
                found: FindResult::NotCaptured,
                attributes: None,
                malformed: false,
            }),
            fenced: false,
            begin_applied: false,
            end_applied: false,
            snapshot: EMPTY_SNAPSHOT,
        };
        fx.state.pending.insert(token, call);
        fx.state.apply_begin(token);
        let mut effects = ObjectEffects::default();
        let mut ledger = super::super::journal::StagingLedger::new();
        fx.state.apply_end(token, &mut effects, &mut ledger);
        assert!(DeferredFixture::minted(&effects, token), "mint effect");
        let record = fx
            .state
            .deferred_pending
            .get(&(fx.session, target))
            .expect("record stored");
        assert!(
            matches!(
                record.inputs[0],
                DeferredInput::Frozen {
                    lost: true,
                    key_use: false,
                    ..
                }
            ),
            "destroy freezes no key use and loses immediately"
        );
    }

    // F5: an overlapping same-session call voids the frozen inputs
    // with its interference gap; Absent stays Absent.
    #[test]
    fn deferred_mint_interference_voids_inputs() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        // An overlapping same-session call the mint must void against.
        fx.next_key += 1;
        fx.next_token += 1;
        let other = CallToken(fx.next_token);
        let other_key = CallKey::reference(fx.next_key);
        fx.state.pending.insert(
            other,
            PendingCall {
                domain: fx.domain,
                key: other_key,
                begin: 5,
                entry_ns: 50,
                function: target,
                kind: CallKind::Object(ObjectAction::Access),
                session: HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
                inputs: [HandleInput::Absent, HandleInput::Absent],
                requested: [None, None],
                derive_protocol: DeriveResultProtocol::Unavailable,
                entry_mechanism: MechClass::Value,
                scope: SlotScope::Unknown,
                completion: Some(Completion {
                    cut: 50,
                    end_ns: 150,
                    rv: CkRv::PENDING.0,
                    return_mechanism: MechanismEvidence::NotCaptured,
                    results: [ResultSlot::NotCaptured, ResultSlot::NotCaptured],
                    session_out: HandleInput::Absent,
                    found: FindResult::NotCaptured,
                    attributes: None,
                    malformed: false,
                }),
                fenced: false,
                begin_applied: false,
                end_applied: false,
                snapshot: EMPTY_SNAPSHOT,
            },
        );
        fx.state
            .domains
            .get_mut(&fx.domain)
            .expect("domain")
            .keys
            .insert(other_key, other);
        let (token, effects) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        assert!(DeferredFixture::minted(&effects, token), "mint effect");
        let record = fx
            .state
            .deferred_pending
            .get(&(fx.session, target))
            .expect("record stored");
        assert_eq!(
            record.inputs[0],
            DeferredInput::Unproven(ObjectGap::SameSessionOverlap)
        );
        assert_eq!(record.inputs[1], DeferredInput::Absent);
    }

    // Redeem refuses a dead origin session and a voided generation.
    #[test]
    fn deferred_redeem_refuses_dead_session_and_voided_generation() {
        let mut fx = DeferredFixture::new();
        let target = fx.target("C_SignInit");
        let (token, _) = fx.pending_access(
            HandleInput::Value(SessionHandle::new(DSESSION).unwrap()),
            HandleInput::Value(ObjectHandle::new(DKEY).unwrap()),
            target,
        );
        fx.state.exhaust_generation(fx.domain);
        assert!(
            fx.state.redeem_deferred(token).is_none(),
            "voided generation refuses"
        );
        // The record is still live custody (refusal consumes nothing).
        assert_eq!(fx.state.usage().deferred_origins, 1);
    }
}
