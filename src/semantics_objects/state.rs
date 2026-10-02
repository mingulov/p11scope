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

/// The finite call vocabulary the model accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallKind {
    Object(ObjectAction),
    Lifecycle(u8),
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

fn call_kind(function: u32) -> Option<CallKind> {
    if let Some(descriptor) = object_descriptor(function) {
        return Some(CallKind::Object(descriptor.action));
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

/// Mechanism evidence class without the raw word.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MechClass {
    NotCaptured,
    Null,
    Unreadable,
    Value,
}

impl MechClass {
    fn of(evidence: MechanismEvidence) -> Self {
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
            CallKind::Lifecycle(_) => None,
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
        match scalar(SafeAttributeKind::KeyType)? {
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

    pub(super) fn begin(&mut self, origin: OriginFact) -> Result<CallToken, ObjectGap> {
        let (domain, cut) = (origin.domain, origin.cut.0);
        let result = self.admit(origin);
        match result {
            Err(reason @ (ObjectGap::ClosedFrontier | ObjectGap::MalformedFact)) => {
                // Unrepresentable history: a begin the model can no longer
                // order. Proof ends and the fence floor rises above it.
                // It is still a real call that may be running: like a
                // capacity refusal, it blocks bootstrap until bounded.
                let mut effects = ObjectEffects::default();
                self.contradict(domain, reason, Some(cut), &mut effects);
                if let Some(state) = self.domains.get_mut(&domain) {
                    state.refused_in_flight = max_opt(state.refused_in_flight, Some(cut));
                }
            }
            Err(reason) => self.gap(reason),
            Ok(_) => {}
        }
        result
    }

    fn admit(&mut self, origin: OriginFact) -> Result<CallToken, ObjectGap> {
        let domain = origin.domain;
        self.held(domain)?;
        if self.domains[&domain].ended.is_some() {
            return Err(ObjectGap::DomainEnded);
        }
        let kind = call_kind(origin.function).ok_or(ObjectGap::UnsupportedFunction)?;
        let cut = origin.cut.0;
        let state = &self.domains[&domain];
        if let Some(token) = state.keys.get(&origin.key) {
            // An exact re-delivery of an admitted begin is a no-op; the same
            // key at another cut is malformed.
            return if self.pending[token].begin == cut {
                Err(ObjectGap::DuplicateCall)
            } else {
                Err(ObjectGap::MalformedFact)
            };
        }
        if state.covered.is_some_and(|covered| cut <= covered) {
            return Err(ObjectGap::ClosedFrontier);
        }
        if state.cuts.contains(&cut) {
            return Err(ObjectGap::MalformedFact);
        }
        if self.pending.len() >= self.limits.pending_calls {
            self.refuse_unrepresented(domain, cut);
            return Err(ObjectGap::PendingCapacity);
        }
        let Some(next) = self
            .next_token
            .checked_add(1)
            .filter(|next| *next <= self.limits.max_call_token)
        else {
            self.refuse_unrepresented(domain, cut);
            return Err(ObjectGap::IdExhausted);
        };
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
        Ok(token)
    }

    /// A refused call is unrepresented history that may still be running:
    /// proof in its domain ends, and no bootstrap is accepted until a
    /// lost-outcome fact bounds it. Existing tickets stay as fences.
    fn refuse_unrepresented(&mut self, domain: ObjectDomain, cut: u64) {
        let mut effects = ObjectEffects::default();
        self.void_bootstrap(domain, ObjectGap::PendingCapacity, &mut effects);
        if let Some(state) = self.domains.get_mut(&domain) {
            state.fence_floor = max_opt(state.fence_floor, Some(cut));
            state.refused_in_flight = max_opt(state.refused_in_flight, Some(cut));
        }
    }

    pub(super) fn complete(&mut self, token: CallToken, result: CompletedFact) -> ObjectEffects {
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
            self.remove_call(token);
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
            self.remove_call(token);
            self.contradict(domain, reason, Some(cut), &mut effects);
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

    fn remove_call(&mut self, token: CallToken) {
        if let Some(call) = self.pending.remove(&token)
            && let Some(state) = self.domains.get_mut(&call.domain)
        {
            state.keys.remove(&call.key);
            state.cuts.remove(&call.begin);
            if let Some(end) = call.end_cut() {
                state.cuts.remove(&end);
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

    pub(super) fn settle(&mut self, prefix: CompleteInputPrefix) -> ObjectEffects {
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
            self.contradict(domain, ObjectGap::PrefixContradiction, None, &mut effects);
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
            for (_, is_end, token) in events {
                // A contradiction inside this replay fences or releases the
                // remaining calls: their events no longer apply.
                if self.pending.get(&token).is_none_or(|c| c.fenced) {
                    continue;
                }
                if is_end {
                    self.apply_end(token, &mut effects);
                } else {
                    self.apply_begin(token);
                }
                if self.domains[&domain].ended.is_some() {
                    break;
                }
            }
            let state = self.domains.get_mut(&domain).expect("registered domain");
            state.applied = max_opt(state.applied, Some(watermark));
        }
        self.prune(domain);
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

    fn prune(&mut self, domain: ObjectDomain) {
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
            self.remove_call(token);
        }
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

    fn apply_end(&mut self, token: CallToken, effects: &mut ObjectEffects) {
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
            self.contradict(call.domain, ObjectGap::UnseenFinalize, None, effects);
            return;
        }
        let scope = self.call_scope(&call);

        // A proof void after this call's begin replay rejects its snapshot,
        // even when a newer bootstrap is in force.
        if !call.snapshot.qualified
            || call.snapshot.generation != self.domains[&call.domain].generation
        {
            self.gap_effect(effects, ObjectGap::BootstrapUnproven);
        } else if !self.apply_qualified_end(token, &call, &completion, outcome, effects) {
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
        self.apply_action(token, call, outcome, effects);
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
                lifecycle::FINALIZE => self.apply_finalize(call, outcome, effects),
                _ => {}
            },
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
    /// that may alter what this call's joins rely on.
    fn interference(&self, token: CallToken) -> (Option<ObjectGap>, bool) {
        let x = &self.pending[&token];
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
    /// no unsettled ticket began at or before that position, and no pending
    /// origin snapshot references it. Live views, live sessions and live
    /// tombstones are never pruned. Every record of an ended domain is
    /// eligible. Pruning runs lazily, only under capacity pressure, so the
    /// projection keeps retired history until a budget needs the room. IDs
    /// are never reused.
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
            if !eligible(at) || views_ref.contains(&id) {
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
        effects: &mut ObjectEffects,
    ) {
        if let Some(view) = self.objects.get_mut(&id) {
            view.references = view.references.saturating_add(1);
            if key_use {
                view.key_uses = view.key_uses.saturating_add(1);
            }
            effects.push(ObjectEffect::Referenced {
                call: token,
                object: id,
                key_use,
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
                Ok(Some(id)) => self.reference(token, id, key_use, effects),
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
                    self.reference(token, id, key_use, effects);
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
                self.reference(token, id, false, effects);
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
                Some(Binding::View(id)) => self.reference(token, id, false, effects),
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
                        self.reference(token, id, false, effects);
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
        self.end_domain(call.domain, ObjectGap::Finalize, effects);
    }

    // -----------------------------------------------------------------------
    // boundaries
    // -----------------------------------------------------------------------

    /// End every live session/view of a domain. An ended domain admits
    /// nothing further, so its tickets are released: any late completion is
    /// a stale token and cannot join.
    fn end_domain(&mut self, domain: ObjectDomain, reason: ObjectGap, effects: &mut ObjectEffects) {
        self.clear_domain(domain, reason, effects);
        for token in self.domain_calls(domain) {
            self.remove_call(token);
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
            self.end_domain(domain, ObjectGap::IdExhausted, effects);
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
        self.void_bootstrap(domain, reason, effects);
        let state = self.domains.get_mut(&domain).expect("domain");
        state.fence_floor = max_opt(state.fence_floor, cut);
    }

    pub(super) fn invalidate(&mut self, scope: AffectedScope, reason: ObjectGap) -> ObjectEffects {
        let mut effects = ObjectEffects::default();
        self.gap(reason);
        match scope {
            AffectedScope::Capture => {
                let domains: Vec<ObjectDomain> = self.domains.keys().copied().collect();
                for domain in domains {
                    self.invalidate_domain(domain, reason, &mut effects);
                }
            }
            AffectedScope::Domain(domain) => match self.held(domain) {
                Ok(()) => self.invalidate_domain(domain, reason, &mut effects),
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
                self.fence_and_void(domain, affected, reason, &mut effects);
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
                self.fence_and_void(domain, affected, reason, &mut effects);
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
    ) {
        if affected.is_empty() {
            return;
        }
        for token in affected {
            self.fence(token);
        }
        // A lost ticket may have affected any compatible scope at an unknown
        // time: proof in the whole domain ends until a new bootstrap.
        self.void_bootstrap(domain, reason, effects);
    }

    fn invalidate_domain(
        &mut self,
        domain: ObjectDomain,
        reason: ObjectGap,
        effects: &mut ObjectEffects,
    ) {
        match reason {
            ObjectGap::Exec | ObjectGap::Fork | ObjectGap::Unload | ObjectGap::Finalize => {
                self.end_domain(domain, reason, effects);
            }
            _ => {
                self.clear_domain(domain, reason, effects);
                self.void_bootstrap(domain, reason, effects);
            }
        }
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

    pub(super) fn outcome_lost(&mut self, lost: LostOutcome) -> ObjectEffects {
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
                    self.void_bootstrap(domain, ObjectGap::OutcomeLost, &mut effects);
                }
                self.remove_call(token);
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
        };
        self.gap(ObjectGap::OutcomeLost);
        if let Some(state) = self.domains.get_mut(&domain) {
            state.fence_floor = max_opt(state.fence_floor, Some(upper));
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
                + fixed,
            object_records,
            session_records,
            live_bindings,
            pending_calls,
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
